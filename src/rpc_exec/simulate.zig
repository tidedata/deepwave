//! SimulateTransaction (CONTRACTS 6.7): sui-rpc-api `simulate_transaction` (request, read mask,
//! transaction parse, mock-gas decision, rendering) around sui-core
//! `transaction_simulation::simulate_transaction` (checks, input loading, execution without
//! commit, unchanged loaded runtime objects, the transaction's object set).
//!
//! One `Engine` per node is shared read-only by every worker thread; each request runs in its own
//! arena and reads the pre-state through `State` (zero-copy views of the snapshot).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const exec = @import("exec");
const serve = @import("serve");

const root = @import("root.zig");
const state_mod = @import("state.zig");
const reply = @import("reply.zig");
const checks = @import("checks.zig");
const deny = @import("deny.zig");
const txdeny = @import("txdeny.zig");
const render = @import("render.zig");
const resolve = @import("resolve.zig");
const failure = @import("failure.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const ObjectView = exec.objects.ObjectView;
const ptb = exec.ptb;
const proto = serve.proto;
const State = state_mod.State;
const Reply = reply.Reply;
const Fail = checks.Fail;
const Loaded = checks.Loaded;

pub const EpochEnv = root.EpochEnv;

const code_invalid_argument = 3;
const code_not_found = 5;
const code_unimplemented = 12;
const code_internal = 13;
const code_unavailable = 14;

/// `DEV_INSPECT_GAS_COIN_VALUE`.
pub const mock_gas_value: u64 = 1_000_000_000_000_000_000;
/// `ObjectID::MAX`.
pub const mock_gas_id: Id = @splat(0xff);

pub const Engine = struct {
    /// Long-lived allocator for the per-thread package caches (exec-move `pkgs.cacheFor`).
    gpa: Allocator,
    pkgs: *const exec.packages.Store,
    /// Source of the random nonce gas selection puts in a ValidDuring expiration (Rust:
    /// `rand::random`); without one the nonce comes from a process-wide counter.
    io: ?std.Io = null,
    /// `suggested_gas_price` source (the node's congestion tracker); null answers none.
    suggest: ?Suggest = null,
    /// Run with `track_results` (DevInspect command results); set on a copy by `simulate`.
    track_results: bool = false,
    /// Render `json` on objects, events and command outputs (sui-node always does; the serve
    /// service's `json` switch, off only in test harnesses whose truth had no packages).
    json: bool = true,
    /// Render `display` on the transaction's objects (the serve service's `display` switch).
    display: bool = true,
    /// `proposer_selector` (sui-node: the transaction driver's validator monitor): the proposer
    /// set gas selection restricts a transaction to. Null: none (a node without a driver).
    proposers: ?ProposerSelector = null,
    /// The request's `x-sui-client-protocol-version` header; set on a copy per request.
    client_protocol_version: ?u64 = null,
    /// What a request with checks disabled gets (`--dev-inspect-disabled`, fullnode.yaml
    /// `dev-inspect-disabled`).
    dev_inspect: DevInspect = default_dev_inspect,

    pub const DevInspect = enum {
        /// `dev-inspect-disabled: true`: sui-node's refusal (`AuthorityState::simulate_transaction`).
        refused,
        /// The operator did not say (deepwave's default for now): no DevInspect<true> execution. The
        /// transaction runs under the rules of execution with checks, and a request whose
        /// answer needs the relaxed rules (inputs that fail the signing checks, a failure
        /// DevInspect<true> would not raise) is UNIMPLEMENTED.
        guarded,
        /// `dev-inspect-disabled: false` (sui-node's default): executed as DevInspect<true>.
        enabled,
    };
    /// The state without `--dev-inspect-disabled` and without the fullnode.yaml key.
    pub const default_dev_inspect: DevInspect = .guarded;

    pub const ProposerSelector = struct {
        ctx: *anyopaque,
        /// `ProposerSelector::preferred_proposers(max)`: committee indices, strictly increasing,
        /// with the committee's epoch; null before any validator latency was observed.
        preferred: *const fn (ctx: *anyopaque, arena: Allocator, max: usize) Allocator.Error!?types.AllowedProposers,
    };

    pub const Suggest = struct {
        ctx: *const anyopaque,
        /// The clearing price over the transaction's exclusively accessed shared inputs.
        price: *const fn (ctx: *const anyopaque, ids: []const [32]u8) ?u64,
    };

    /// Handles one `SimulateTransactionRequest` (prost bytes); the reply is a
    /// `SimulateTransactionResponse` or a gRPC error. Everything is allocated in `arena`.
    pub fn simulate(e: *const Engine, arena: Allocator, env: *const EpochEnv, state: State, body: []const u8) Allocator.Error!Reply {
        return handle(e, arena, env, state, body) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                if (@import("builtin").mode == .debug) if (@errorReturnTrace()) |t| std.debug.dumpErrorReturnTrace(t);
                return errReply(arena, code_internal, @errorName(err));
            },
        };
    }
};

/// Packages for the deny checks: the engine's package store, then the snapshot.
const SimPkgs = struct {
    e: *const Engine,
    epoch: u64,
    state: State,

    fn lookup(p: *SimPkgs) txdeny.PackageLookup {
        return .{ .ctx = p, .get = get };
    }
    fn get(ctx: *anyopaque, _: Allocator, id: *const Id) ?[]const u8 {
        const p: *SimPkgs = @ptrCast(@alignCast(ctx));
        if (p.e.pkgs.get(id, p.epoch)) |raw| return raw;
        const r = p.state.latest(id) orelse return null;
        const v = ObjectView.parse(r) catch return null;
        return if (v.is_package) r else null;
    }
};

fn errReply(arena: Allocator, code: u8, message: []const u8) Allocator.Error!Reply {
    return .{ .err = .{ .code = code, .message = message, .details = serve.status.plain(arena, code, message) catch return error.OutOfMemory } };
}

fn badRequest(arena: Allocator, field: []const u8, description: []const u8, reason: serve.status.Reason) Allocator.Error!Reply {
    const det = serve.status.badRequest(arena, code_invalid_argument, field, description, reason) catch return error.OutOfMemory;
    return .{ .err = .{ .code = code_invalid_argument, .message = description, .details = det } };
}

fn failReply(arena: Allocator, f: Fail) Allocator.Error!Reply {
    return errReply(arena, f.code, f.message);
}

const sim_response_root = serve.schema.index("SimulateTransactionResponse");

/// The Rust `bcs` crate's `Error` Display for the decode failures deepwave's BCS reader reports.
fn bcsErrorText(err: anyerror) []const u8 {
    return switch (err) {
        error.EndOfInput => "unexpected end of input",
        error.TrailingBytes => "remaining input",
        error.InvalidBool => "expected boolean",
        error.InvalidUtf8 => "malformed utf8",
        error.InvalidUleb => "ULEB128 encoding was not minimal in size",
        error.LengthTooLarge => "exceeded max sequence length",
        else => "invalid value",
    };
}

fn handle(e: *const Engine, arena: Allocator, env: *const EpochEnv, state: State, body: []const u8) !Reply {
    // ---- request (prost merge: repeated occurrences of a message field concatenate)
    var tx_msg: std.ArrayList(u8) = .empty;
    var tx_present = false;
    var mask_paths: std.ArrayList([]const u8) = .empty;
    var mask_present = false;
    var checks_v: u64 = 0;
    var gas_sel = false;
    {
        var r = proto.Reader.init(body);
        while (r.next() catch return errReply(arena, code_internal, "failed to decode Protobuf message")) |f| switch (f.number) {
            1 => {
                tx_present = true;
                try tx_msg.appendSlice(arena, proto.Reader.bytesOf(f) catch return errReply(arena, code_internal, "failed to decode Protobuf message"));
            },
            2 => {
                mask_present = true;
                var mr = proto.Reader.init(proto.Reader.bytesOf(f) catch return errReply(arena, code_internal, "failed to decode Protobuf message"));
                while (mr.next() catch return errReply(arena, code_internal, "failed to decode Protobuf message")) |mf| {
                    if (mf.number == 1) try mask_paths.append(arena, proto.Reader.stringOf(mf) catch return errReply(arena, code_internal, "failed to decode Protobuf message"));
                }
            },
            3 => checks_v = proto.Reader.varintOf(f) catch return errReply(arena, code_internal, "failed to decode Protobuf message"),
            4 => gas_sel = (proto.Reader.varintOf(f) catch return errReply(arena, code_internal, "failed to decode Protobuf message")) != 0,
            else => {},
        };
    }

    // ---- read mask
    var tree: serve.mask.Tree = undefined;
    if (mask_present) {
        if (serve.status.invalidPath(sim_response_root, mask_paths.items)) |p| {
            return badRequest(arena, "read_mask", try std.fmt.allocPrint(arena, "invalid read_mask path: {s}", .{p}), .field_invalid);
        }
        tree = try serve.mask.Tree.fromPaths(arena, mask_paths.items);
    } else tree = try serve.mask.Tree.parse(arena, "*");
    const m = tree.mask();

    if (!tx_present) return badRequest(arena, "transaction", "", .field_missing);
    const checks_enabled = checks_v != 1;

    // ---- transaction: BCS, a fully formed proto, or resolution of a partial one
    var bcs_msg: std.ArrayList(u8) = .empty;
    var has_bcs = false;
    {
        var r = proto.Reader.init(tx_msg.items);
        while (r.next() catch return errReply(arena, code_internal, "failed to decode Protobuf message")) |f| {
            if (f.number == 1) {
                has_bcs = true;
                try bcs_msg.appendSlice(arena, proto.Reader.bytesOf(f) catch return errReply(arena, code_internal, "failed to decode Protobuf message"));
            }
        }
    }
    var tx_raw: []const u8 = &.{};
    var td: types.TransactionDataV1 = undefined;
    var req: resolve.Request = .{};
    if (has_bcs) {
        var r = proto.Reader.init(bcs_msg.items);
        while (r.next() catch return errReply(arena, code_internal, "failed to decode Protobuf message")) |f| {
            if (f.number == 2) tx_raw = proto.Reader.bytesOf(f) catch return errReply(arena, code_internal, "failed to decode Protobuf message");
        }
        const td_all = bcs.decode(types.TransactionData, arena, tx_raw) catch |err| {
            return badRequest(arena, "transaction", try std.fmt.allocPrint(arena, "invalid transaction: error converting from protobuf: field: bcs reason: FIELD_INVALID description: {s}", .{bcsErrorText(err)}), .field_invalid);
        };
        td = switch (td_all) {
            .V1 => |v| v,
        };
    } else {
        req = resolve.parse(arena, tx_msg.items) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return errReply(arena, code_internal, "failed to decode Protobuf message"),
        };
        const renv: resolve.Env = .{ .cfg = env.cfg, .rgp = env.rgp, .chain_id = env.chain_id, .pkgs = e.pkgs, .epoch = env.epoch };
        switch (try resolve.resolve(arena, &renv, state, &req)) {
            .ok => |x| td = x,
            .err => |re| return resolveErr(arena, re),
            .unimplemented => |why| return errReply(arena, code_unimplemented, why),
        }
        tx_raw = try bcs.encodeAlloc(types.TransactionData, arena, &types.TransactionData{ .V1 = td });
    }

    const cfg = env.cfg;
    const perform_gas_selection = gas_sel and checks_enabled;
    // sui-node always executes in DevInspect mode (`dev_inspect_transaction`, TRACK_EXECUTION):
    // the run whose effects are rendered also yields the command outputs; tracking leaves gas
    // and effects unchanged, so it is only switched on when the mask asks for the outputs.
    var et = e.*;
    et.track_results = m.contains("command_outputs");
    var out: Sim = undefined;
    if (perform_gas_selection and !(has_bcs and checks.gasPaidFromAddressBalance(&td) and td.gas_data.price == 0)) {
        switch (try gasSelection(e, arena, env, state, &req, has_bcs, &td)) {
            .ok => {},
            .reply => |r| return r,
        }
        tx_raw = try bcs.encodeAlloc(types.TransactionData, arena, &types.TransactionData{ .V1 = td });
        out = switch (try run(&et, arena, env, state, tx_raw, td, false, false)) {
            .ok => |o| o,
            .fail => |f| return failReply(arena, f),
            .unimplemented => |why| return errReply(arena, code_unimplemented, why),
        };
    } else {
        const allow_mock = !checks_enabled or !(try addressBalancePaysGas(arena, e, env, state, &td));
        out = switch (try run(&et, arena, env, state, tx_raw, td, allow_mock, !checks_enabled)) {
            .ok => |o| o,
            .fail => |f| return failReply(arena, f),
            .unimplemented => |why| return errReply(arena, code_unimplemented, why),
        };
    }
    const td_all: types.TransactionData = .{ .V1 = td };
    _ = cfg;

    // command outputs exist only for a successful execution (`execution_result` is Err otherwise)
    const success = switch (out.eff) {
        .V2 => |v| v.status == .Success,
        .V1 => |v| v.status == .Success,
    };
    // command outputs: `execution_result.into_iter().flatten()`, empty for a failed execution;
    // each value's `json` through the store's type layout (`get_type_layout`, no overlay of the
    // transaction's own packages)
    var outputs: []const u8 = &.{};
    if (success and m.contains("command_outputs")) {
        const results = out.command_results orelse return errReply(arena, code_unimplemented, "command_outputs are not supported");
        const jctx: ?*const serve.render_object.Ctx = if (e.json) try renderCtx(arena, e, env, state, &.{}, false) else null;
        outputs = try encodeCommandOutputsCtx(arena, results, jctx);
    }

    const resp = try render.response(arena, e, env, state, m, .{
        .tx_raw = tx_raw,
        .td = td_all,
        .tx_digest = types.digest.transactionDataDigest(tx_raw),
        .effects = out.effects,
        .eff = out.eff,
        .events = out.events,
        .objects = out.objects,
        .loaded = out.loaded,
        .render = if (e.json or e.display) try renderCtx(arena, e, env, state, out.objects, e.display) else null,
    });
    return switch (resp) {
        .ok => |b0| blk: {
            // SimulateTransactionResponse: transaction (1), command_outputs (2), suggested_gas_price (3)
            const b = if (outputs.len == 0) b0 else try std.mem.concat(arena, u8, &.{ b0, outputs });
            if (!m.contains("suggested_gas_price")) break :blk .{ .ok = b };
            const sg = e.suggest orelse break :blk .{ .ok = b };
            const price = sg.price(sg.ctx, try @import("congestion.zig").exclusiveShared(arena, &td)) orelse break :blk .{ .ok = b };
            var w: std.ArrayList(u8) = .empty;
            try w.appendSlice(arena, b);
            try w.append(arena, 3 << 3);
            var x = price;
            while (x >= 0x80) : (x >>= 7) try w.append(arena, @as(u8, @truncate(x)) | 0x80);
            try w.append(arena, @truncate(x));
            break :blk .{ .ok = w.items };
        },
        .unimplemented => |why| errReply(arena, code_unimplemented, why),
    };
}

// ---- address_balance_pays_gas ----------------------------------------------------------------

/// sui-rpc-api `address_balance_pays_gas` (checks enabled, no gas selection).
pub fn addressBalancePaysGas(arena: Allocator, e: *const Engine, env: *const EpochEnv, state: State, td: *const types.TransactionDataV1) Allocator.Error!bool {
    _ = e;
    const cfg = env.cfg;
    if (!cfg.feature_flags.enable_address_balance_gas_payments) return false;
    if (!checks.gasPaidFromAddressBalance(td)) return false;
    const pt = checks.ptbOf(td) orelse return false;
    if (checks.usesGasCoin(pt)) return false;
    // is_replay_protected_without_gas_coin: owned inputs at their latest version
    if (!checks.isReplayProtectedExpiration(td.expiration)) {
        var any = false;
        for (pt.inputs) |*a| switch (a.*) {
            .Object => |o| switch (o) {
                .ImmOrOwnedObject => |r| {
                    if (checks.isCoinReservation(&r[2].@"0".@"0")) continue;
                    const raw = state.latest(&r[0].@"0".@"0") orelse continue;
                    const v = ObjectView.parse(raw) catch continue;
                    if (v.is_package) continue;
                    if (raw[v.owner_at] == 0) { // Owner::AddressOwner
                        any = true;
                        break;
                    }
                },
                else => {},
            },
            else => {},
        };
        if (!any) return false;
    }
    // address_balance_available_for_gas: the gas owner's SUI address balance, less the explicit
    // SUI withdrawals (none here: explicit withdrawals are not modeled and answer UNIMPLEMENTED).
    const owner = &td.gas_data.owner.@"0";
    const raw = state.latest(&checks.accumulatorId(owner, &checks.sui_balance_tag)) orelse return false;
    const amount = checks.accumulatorAmount(raw) orelse return false;
    _ = arena;
    return @as(u64, @truncate(amount)) >= td.gas_data.budget;
}

// ---- transaction_simulation::simulate_transaction --------------------------------------------

pub const Ref = serve.objset.Ref;

pub const Sim = struct {
    effects: []const u8,
    eff: types.TransactionEffects,
    events: ?[]const u8,
    /// The object set (`get_transaction_object_set` keys found among inputs, writes and runtime
    /// loads), raw BCS objects.
    objects: []const []const u8,
    /// `unchanged_loaded_runtime_objects`, sorted by id.
    loaded: []const Ref,
    command_results: ?[]const ptb.CommandResult = null,
    /// The objects the transaction wrote (new versions, raw BCS), for chained simulations.
    written: []const exec.coin_ptb.Written = &.{},
};

pub const RunResult = union(enum) {
    ok: Sim,
    fail: Fail,
    unimplemented: []const u8,
};

/// The mock gas coin: `Object::new_move(MoveObject::new_gas_coin(1, ObjectID::MAX, value),
/// AddressOwner(gas owner), genesis marker)`.
fn mockGasObject(arena: Allocator, owner: *const Id) Allocator.Error![]const u8 {
    const buf = try arena.alloc(u8, 3 + 8 + 1 + 40 + 1 + 32 + 33 + 8);
    var at: usize = 0;
    buf[0] = 0; // Data::Move
    buf[1] = 1; // MoveObjectType_::GasCoin
    buf[2] = 1; // has_public_transfer
    at = 3;
    std.mem.writeInt(u64, buf[at..][0..8], 1, .little);
    at += 8;
    buf[at] = 40;
    at += 1;
    @memcpy(buf[at..][0..32], &mock_gas_id);
    at += 32;
    std.mem.writeInt(u64, buf[at..][0..8], mock_gas_value, .little);
    at += 8;
    buf[at] = 0; // Owner::AddressOwner
    at += 1;
    @memcpy(buf[at..][0..32], owner);
    at += 32;
    buf[at] = 32; // TransactionDigest::genesis_marker (a 32-byte vector of zeros)
    at += 1;
    @memset(buf[at..][0..32], 0);
    at += 32;
    std.mem.writeInt(u64, buf[at..][0..8], 0, .little);
    at += 8;
    std.debug.assert(at == buf.len);
    return buf;
}

/// What ptb.execute reads by (id, version): the mock gas coin, then the pre-state.
const Lookup = struct {
    state: State,
    mock: ?[]const u8,

    fn get(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const l: *const Lookup = @ptrCast(@alignCast(ctx));
        if (l.mock) |mk| if (version == 1 and std.mem.eql(u8, id, &mock_gas_id)) return mk;
        return l.state.at(id, version);
    }
};

/// exec-move's PreState over the request's `State`; address-balance reads are recorded as
/// runtime loads (Rust reads the accumulator field through the tracking store).
const Pre = struct {
    state: State,
    arena: Allocator,
    acc_reads: std.ArrayList(Ref) = .empty,
    /// The accumulator root version an object funds read loaded (the implicit system object read).
    root_read: ?u64 = null,
    oom: bool = false,

    fn of(ctx: *const anyopaque) *Pre {
        return @constCast(@as(*const Pre, @ptrCast(@alignCast(ctx))));
    }

    fn sharedLatest(ctx: *const anyopaque, id: *const Id) ?u64 {
        const p = of(ctx);
        const raw = p.state.latest(id) orelse return null;
        const v = ObjectView.parse(raw) catch return null;
        return v.version;
    }

    fn childAtMost(ctx: *const anyopaque, child: *const Id, upper: u64) ?[]const u8 {
        return of(ctx).state.childAtMost(child, upper);
    }

    fn addressBalance(ctx: *const anyopaque, owner: *const Id, ty: *const types.TypeTag) ?u128 {
        const p = of(ctx);
        const root_raw = p.state.latest(&checks.acc_root) orelse return null;
        const root_v = (ObjectView.parse(root_raw) catch return null).version;
        p.root_read = root_v;
        const ty_bcs = bcs.encodeAlloc(types.TypeTag, p.arena, ty) catch {
            p.oom = true;
            return null;
        };
        const id = checks.accumulatorId(owner, ty_bcs);
        const raw = p.state.childAtMost(&id, root_v) orelse return 0;
        const v = ObjectView.parse(raw) catch return null;
        p.acc_reads.append(p.arena, .{ .id = id, .version = v.version }) catch {
            p.oom = true;
            return null;
        };
        return checks.accumulatorAmount(raw);
    }

    const vtable: ptb.PreState.VTable = .{ .shared_latest = sharedLatest, .child_at_most = childAtMost, .address_balance = addressBalance };
};

/// `Engine.DevInspect.guarded`: failures DevInspect<true> does not raise (arbitrary calls and
/// values, no conservation checks). Its execution goes on where execution with checks stopped.
fn relaxedFailure(eff: *const types.TransactionEffects) ?[]const u8 {
    const status = switch (eff.*) {
        .V2 => |v| v.status,
        .V1 => |v| v.status,
    };
    const f = switch (status) {
        .Success => return null,
        .Failure => |f| f,
    };
    return switch (f.@"error") {
        .NonEntryFunctionInvoked, .CommandArgumentError, .UnusedValueWithoutDrop, .InvalidPublicFunctionReturnType, .InvariantViolation => "checks disabled: execution past a check DevInspect<true> skips is not supported",
        else => null,
    };
}

/// `get_latest_account_amount`: the live accumulator field's value, 0 when absent.
fn accountAmount(state: State, account: *const Id) u128 {
    const raw = state.latest(account) orelse return 0;
    return checks.accumulatorAmount(raw) orelse 0;
}

fn lessRef(_: void, a: Ref, b: Ref) bool {
    const o = std.mem.order(u8, &a.id, &b.id);
    return if (o == .eq) a.version < b.version else o == .lt;
}

fn ownerOf(arena: Allocator, raw: []const u8, v: *const ObjectView) !types.Owner {
    return bcs.decode(types.Owner, arena, raw[v.owner_at..v.prev_tx_at]);
}

fn loadedOf(arena: Allocator, kind: checks.InputKind, raw: []const u8) !Loaded {
    const v = try ObjectView.parse(raw);
    return .{ .kind = kind, .raw = raw, .view = v, .owner = try ownerOf(arena, raw, &v) };
}

/// `dev_inspect` is checks disabled: `check_dev_inspect_input` in place of
/// `check_transaction_input` (no ownership, replay protection or receiving checks; the gas checks
/// without the ownership pass) and execution as DevInspect<true> (`ptb.Inputs.skip_all_checks`),
/// when `Engine.dev_inspect` is `enabled`. `refused` answers sui-node's refusal; `guarded` never
/// runs DevInspect<true> (see `Engine.DevInspect`).
/// The simulation core (`transaction_simulation::simulate_transaction`): the gRPC handler above
/// and the native engine (`src/exec/simulate`) both run transactions through it.
pub fn run(e: *const Engine, arena: Allocator, env: *const EpochEnv, state: State, tx_raw: []const u8, td_in: types.TransactionDataV1, allow_mock: bool, dev_inspect: bool) !RunResult {
    const cfg = env.cfg;
    var td = td_in;
    // AuthorityState::simulate_transaction
    if (checks.isSystemKind(&td.kind)) return .{ .fail = try checks.unsupportedFeature(arena, "simulate does not support system transactions", .{}) };
    // `checks.disabled() && self.config.dev_inspect_disabled`
    if (dev_inspect and e.dev_inspect == .refused) return .{ .fail = try checks.unsupportedFeature(arena, "simulate with checks disabled is not allowed on this node", .{}) };
    const relaxed = dev_inspect and e.dev_inspect == .enabled;

    // coin reservations in gas payment
    if (!protocol.derived.enableCoinReservationObjRefs(cfg)) {
        for (td.gas_data.payment) |r| if (checks.isCoinReservation(&r[2].@"0".@"0")) {
            return .{ .fail = try checks.unsupportedFeature(arena, "coin reservations in gas payment are not supported at this protocol version", .{}) };
        };
    }
    if (checks.unsupportedWithdrawal(&td)) |why| return .{ .unimplemented = why };

    var kinds: std.ArrayList(checks.InputKind) = .empty;
    var recv: std.ArrayList(checks.Receiving) = .empty;
    if (try checks.inputKinds(arena, &td, &kinds, &recv)) |f| return .{ .fail = f };

    // mock gas coin
    var mock: ?[]const u8 = null;
    if (allow_mock and td.gas_data.payment.len == 0 and !checks.isGasless(cfg, &td)) {
        const raw = try mockGasObject(arena, &td.gas_data.owner.@"0");
        const v = try ObjectView.parse(raw);
        const pay = try arena.alloc(@typeInfo(@TypeOf(td.gas_data.payment)).pointer.child, 1);
        pay[0] = .{ .{ .@"0" = .{ .@"0" = mock_gas_id } }, .{ .@"0" = 1 }, .{ .@"0" = .{ .@"0" = v.digest() } } };
        td.gas_data.payment = pay;
        mock = raw;
    }

    const vctx: checks.ValidityCtx = .{ .cfg = cfg, .epoch = env.epoch, .chain_id = env.chain_id, .rgp = env.rgp, .committee_size = env.committee_size };
    if (try checks.validity(arena, &vctx, &td)) |f| return .{ .fail = f };

    // pre_object_load_checks: the transaction deny config first (no signatures in simulate; the
    // input kinds are the ones computed before the mock gas coin)
    {
        const deny_cfg = txdeny.current();
        if (deny_cfg.active()) {
            const deny_rules = &deny_cfg.rules;
            var pl: SimPkgs = .{ .e = e, .epoch = env.epoch, .state = state };
            if (try txdeny.check(arena, deny_rules, &td, &.{}, kinds.items, recv.items, pl.lookup())) |f| return .{ .fail = f };
        }
    }

    // pre_object_load_checks: declared withdrawals (FundsWithdrawal inputs and address-balance
    // gas) against the live address balances
    var withdraw_types: []types.TypeTag = &.{};
    switch (try checks.declaredWithdrawals(arena, &td, &env.chain_id, state)) {
        .fail => |f| return .{ .fail = f },
        .ok => |list| {
            // the coin reservations' types, resolved through the accumulator field (candidates
            // for exec's reservation typing, `Inputs.reservation_types`)
            withdraw_types = try arena.alloc(types.TypeTag, list.len);
            for (list, withdraw_types) |w, *t| t.* = w.coin;
            for (list) |w| {
                const actual = accountAmount(state, &w.account);
                if (actual < w.amount) return .{ .fail = try checks.userInput(arena, "Invalid withdraw reservation: Insufficient address balance of coin type {s} for address {s}: the transaction requires {d} but only {d} is available. Note that the address balance does not include funds held in Coin objects owned by the address; to spend those funds, use the Coin objects directly as transaction inputs.", .{ try checks.typeDisplay(arena, &w.coin), checks.hex(&w.owner).s(), w.amount, actual }) };
            }
            if (cfg.feature_flags.gasless_verify_remaining_balance and checks.isGasless(cfg, &td)) for (list) |w| {
                const remaining = accountAmount(state, &w.account) -| w.amount;
                if (remaining == 0) continue;
                const min = checks.gaslessMinAmount(cfg, &w.coin) orelse continue;
                if (min > 0 and remaining < min) return .{ .fail = try checks.userInput(arena, "Invalid withdraw reservation: Invalid gasless withdrawal of coin type {s} from address {s}. Gasless transactions must either use the entire address balance, or leave at least {d}. Remaining amount would be {d}", .{ try checks.typeDisplay(arena, &w.coin), checks.hex(&w.owner).s(), min, remaining }) };
            };
        },
    }

    const td_all: types.TransactionData = .{ .V1 = td };
    const sim_raw = if (mock == null) tx_raw else try bcs.encodeAlloc(types.TransactionData, arena, &td_all);

    // ---- read_objects_for_simulation (read_objects_for_signing)
    const loaded = try arena.alloc(Loaded, kinds.items.len + @intFromBool(mock != null));
    for (kinds.items, 0..) |k, i| switch (k) {
        .package => |pid| {
            const raw = e.pkgs.get(&pid, env.epoch) orelse blk: {
                const r = state.latest(&pid) orelse break :blk null;
                const v = ObjectView.parse(r) catch break :blk null;
                break :blk if (v.is_package) r else null;
            } orelse return .{ .fail = try checks.userInput(arena, "Dependent package not found on-chain: {s}", .{checks.hex(&pid).s()}) };
            loaded[i] = try loadedOf(arena, k, raw);
        },
        .shared => |s| {
            const raw = state.latest(&s.id) orelse return .{ .fail = try checks.userInput(arena, "Could not find the referenced object {s} at version None", .{checks.hex(&s.id).s()}) };
            const l = try loadedOf(arena, k, raw);
            const start: ?u64 = switch (l.owner) {
                .Shared => |x| x.initial_shared_version.@"0",
                .ConsensusAddressOwner => |x| x.start_version.@"0",
                .Party => |x| x.start_version.@"0",
                else => null,
            };
            if (start == null or start.? != s.isv) return .{ .fail = try checks.userInput(arena, "Could not find the referenced object {s} at version None", .{checks.hex(&s.id).s()}) };
            loaded[i] = l;
        },
        .owned => {},
    };
    for (kinds.items, 0..) |k, i| switch (k) {
        .owned => |o| {
            const raw = state.at(&o.id, o.version) orelse {
                const live = state.latest(&o.id) orelse return .{ .fail = try checks.userInput(arena, "Could not find the referenced object {s} at version None", .{checks.hex(&o.id).s()}) };
                const lv = try ObjectView.parse(live);
                if (lv.version >= o.version) {
                    return .{ .fail = try checks.userInput(arena, "Transaction needs to be rebuilt because object {s} version {d} ({s}) is unavailable for consumption, current version: {d}", .{ checks.hex(&o.id).s(), o.version, try checks.b58(arena, &o.digest), lv.version }) };
                }
                return .{ .fail = try checks.userInput(arena, "Could not find the referenced object {s} at version Some(SequenceNumber({d}))", .{ checks.hex(&o.id).s(), o.version }) };
            };
            loaded[i] = try loadedOf(arena, k, raw);
        },
        else => {},
    };
    const recv_objs = try arena.alloc(?[]const u8, recv.items.len);
    for (recv.items, recv_objs) |r, *o| {
        o.* = state.latest(&r.id) orelse return .{ .fail = try checks.userInput(arena, "Could not find the referenced object {s} at version Some(SequenceNumber({d}))", .{ checks.hex(&r.id).s(), r.version }) };
    }
    if (mock) |mk| loaded[kinds.items.len] = try loadedOf(arena, .{ .owned = .{ .id = mock_gas_id, .version = 1, .digest = td.gas_data.payment[0][2].@"0".@"0" } }, mk);

    // ---- check_transaction_input
    if (dev_inspect) {
        if (try checks.devInspectInput(arena, cfg, env.rgp, &td, loaded)) |f| return .{ .fail = f };
        // guarded: the ownership, replay and receiving checks are skipped there, and execution
        // with checks assumes them
        if (!relaxed) if (try checks.objectsInput(arena, cfg, &td, loaded, recv.items, recv_objs)) |_|
            return .{ .unimplemented = "checks disabled: inputs that fail the signing checks are not supported" };
    } else if (try checks.transactionInput(arena, cfg, env.rgp, &td, loaded, recv.items, recv_objs)) |f| return .{ .fail = f };

    // ---- execution (`dev_inspect_transaction(.., skip_all_checks = dev_inspect)`: DevInspect<false>
    // has the effects of normal execution, DevInspect<true> its relaxed rules)
    var lookup: Lookup = .{ .state = state, .mock = mock };
    var pre: Pre = .{ .state = state, .arena = arena };
    const res = ptb.execute(arena, .{
        .gpa = e.gpa,
        .cfg = cfg,
        .pv = env.pv,
        .epoch = env.epoch,
        .epoch_start_ms = env.epoch_start_ms,
        .rgp = env.rgp,
        .pkgs = e.pkgs,
        .authoritative_packages = true,
    }, sim_raw, &td, .{
        .objs = .{ .ctx = &lookup, .get = Lookup.get },
        .effects = null,
        .unchanged_loaded = null,
        .state = .{ .ctx = &pre, .vtable = &Pre.vtable },
        .reservation_types = withdraw_types,
        .track_results = e.track_results,
        .skip_all_checks = relaxed,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .unimplemented = try std.fmt.allocPrint(arena, "execution: {s}", .{@errorName(err)}) },
    };
    if (pre.oom) return error.OutOfMemory;
    const o = switch (res) {
        .done => |o| o,
        .unsupported => |why| return .{ .unimplemented = why },
    };
    const eff = try bcs.decode(types.TransactionEffects, arena, o.effects);
    if (dev_inspect and !relaxed) if (relaxedFailure(&eff)) |why| return .{ .unimplemented = why };

    // ---- unchanged_loaded_runtime_objects: runtime loads (packages excluded), one per id (the
    // highest version wins, as in an ObjectSet walk), minus every changed object.
    var all_loaded: std.ArrayList(Ref) = .empty;
    for (o.loaded) |r| try all_loaded.append(arena, .{ .id = r.id, .version = r.version });
    try all_loaded.appendSlice(arena, pre.acc_reads.items);
    // the implicit accumulator root read (tracked like any store read) unless it is an input
    if (pre.root_read) |rv| {
        const is_input = for (kinds.items) |k| switch (k) {
            .shared => |sh| if (std.mem.eql(u8, &sh.id, &checks.acc_root)) break true,
            .owned => |ow| if (std.mem.eql(u8, &ow.id, &checks.acc_root)) break true,
            .package => {},
        } else false;
        if (!is_input) try all_loaded.append(arena, .{ .id = checks.acc_root, .version = rv });
    }
    const changed = switch (eff) {
        .V2 => |v| v.changed_objects,
        .V1 => return .{ .unimplemented = "effects v1" },
    };
    // coin deny list v2 (context::finish), read through the tracking store, also when the
    // transaction reverts afterwards
    {
        const pairs = try deny.fromPtb(arena, o.deny_pairs);
        var reads: std.ArrayList(deny.Ref) = .empty;
        switch (try deny.check(arena, state, env.epoch, &pairs, &reads)) {
            .ok => {},
            .denied => |why| return .{ .unimplemented = why },
        }
        for (reads.items) |r| try all_loaded.append(arena, .{ .id = r.id, .version = r.version });
    }
    std.mem.sort(Ref, all_loaded.items, {}, lessRef);
    var unchanged: std.ArrayList(Ref) = .empty;
    for (all_loaded.items, 0..) |r, i| {
        if (i + 1 < all_loaded.items.len and std.mem.eql(u8, &all_loaded.items[i + 1].id, &r.id)) continue;
        // effects.object_changes(): accumulator writes are not object changes
        var is_changed = false;
        for (changed) |c| if (c[1].output_state != .AccumulatorWriteV1 and std.mem.eql(u8, &c[0].@"0".@"0", &r.id)) {
            is_changed = true;
            break;
        };
        if (!is_changed) try unchanged.append(arena, r);
    }

    // ---- the object set: get_transaction_object_set keys among inputs, writes and loads
    var pool: serve.objset.Map = .empty;
    for (loaded) |l| try pool.put(arena, serve.objset.key(&l.view.id, l.view.version), l.raw);
    for (o.written) |w| {
        const v = try ObjectView.parse(w.bytes);
        try pool.put(arena, serve.objset.key(&v.id, v.version), w.bytes);
    }
    for (all_loaded.items) |r| {
        const k = serve.objset.key(&r.id, r.version);
        if (pool.contains(k)) continue;
        if (state.at(&r.id, r.version)) |raw| try pool.put(arena, k, raw);
    }
    const keys = try serve.txobjects.keys(arena, td_all, eff, unchanged.items);
    var objs: std.ArrayList([]const u8) = .empty;
    for (keys) |k| if (pool.get(serve.objset.key(&k.id, k.version))) |raw| try objs.append(arena, raw);

    return .{ .ok = .{ .effects = o.effects, .eff = eff, .events = o.events, .objects = objs.items, .loaded = unchanged.items, .command_results = o.command_results, .written = o.written } };
}

// ---- transaction resolution errors, gas selection and budget estimation ------------------------

fn resolveErr(arena: Allocator, re: resolve.Error) Allocator.Error!Reply {
    return switch (re) {
        .bad => |b| badRequest(arena, b.field, b.description, b.reason),
        .status => |s| errReply(arena, s.code, s.message),
    };
}

const GasOutcome = union(enum) { ok, reply: Reply };

/// The nonce of a server-made expiration: random, as Rust's `rand::random()`.
var nonce_counter: std.atomic.Value(u32) = .init(0x5eed);

fn randomNonce(e: *const Engine) u32 {
    var nb: [4]u8 = undefined;
    if (e.io) |io| io.random(&nb) else std.mem.writeInt(u32, &nb, nonce_counter.fetchAdd(0x9e3779b9, .monotonic), .little);
    return std.mem.readInt(u32, &nb, .little);
}

/// The first protocol version every binary defines `TransactionExpiration::Validity` in.
const first_protocol_version_with_validity: u64 = 136;
/// `MAX_ALLOWED_PROPOSERS` = `MAX_UNPAID_ALLOWED_PROPOSERS`.
const max_allowed_proposers: usize = 3;

/// `can_offer_allowed_proposers`: the network accepts `Validity` and the client (its
/// `x-sui-client-protocol-version`) can decode it.
fn canOfferAllowedProposers(e: *const Engine, cfg: *const protocol.ProtocolConfig) bool {
    const v = e.client_protocol_version orelse return false;
    return cfg.feature_flags.allowed_proposers and v >= first_protocol_version_with_validity;
}

/// `select_allowed_proposers`: the selector's set, only when it names the current epoch.
fn selectAllowedProposers(e: *const Engine, arena: Allocator, env: *const EpochEnv) Allocator.Error!?types.AllowedProposers {
    if (!canOfferAllowedProposers(e, env.cfg)) return null;
    const sel = e.proposers orelse return null;
    const ap = (try sel.preferred(sel.ctx, arena, max_allowed_proposers)) orelse return null;
    if (ap.epoch != env.epoch or ap.proposers.len == 0) return null;
    return ap;
}

fn chainOf(env: *const EpochEnv) types.ChainIdentifier {
    return .{ .@"0" = .{ .@"0" = .{ .@"0" = env.chain_id } } };
}

/// `configure_transaction_validity`: the current epoch and the next one, a random nonce;
/// `Validity` with the allowed proposers when one is offered, `ValidDuring` otherwise. A
/// transaction that already has a validity window keeps it.
fn configureValidity(e: *const Engine, arena: Allocator, env: *const EpochEnv, td: *types.TransactionDataV1) Allocator.Error!void {
    switch (td.expiration) {
        .ValidDuring, .Validity => return,
        else => {},
    }
    const nonce = randomNonce(e);
    td.expiration = if (try selectAllowedProposers(e, arena, env)) |ap| .{ .Validity = .{
        .min_epoch = env.epoch,
        .max_epoch = env.epoch + 1,
        .min_timestamp = null,
        .max_timestamp = null,
        .chain = chainOf(env),
        .nonce = nonce,
        .allowed_proposers = ap,
    } } else .{ .ValidDuring = .{
        .min_epoch = env.epoch,
        .max_epoch = env.epoch + 1,
        .min_timestamp = null,
        .max_timestamp = null,
        .chain = chainOf(env),
        .nonce = nonce,
    } };
}

/// `restrict_transaction_proposers`: a coin-paid transaction without an expiration is
/// restricted to the proposer set when one is offered; otherwise returned as resolved.
fn restrictTransactionProposers(e: *const Engine, arena: Allocator, env: *const EpochEnv, td: *types.TransactionDataV1) Allocator.Error!void {
    if (td.expiration != .None) return;
    const ap = (try selectAllowedProposers(e, arena, env)) orelse return;
    td.expiration = .{ .Validity = .{
        .min_epoch = env.epoch,
        .max_epoch = env.epoch + 1,
        .min_timestamp = null,
        .max_timestamp = null,
        .chain = chainOf(env),
        .nonce = randomNonce(e),
        .allowed_proposers = ap,
    } };
}

/// `address_balance_available_for_gas`: the gas owner's live SUI address balance less the SUI the
/// transaction already withdraws from that account (FundsWithdrawal inputs, coin reservations).
fn addressBalanceForGas(arena: Allocator, env: *const EpochEnv, state: State, td: *const types.TransactionDataV1) Allocator.Error!?u64 {
    const owner = &td.gas_data.owner.@"0";
    const account = checks.accumulatorId(owner, &checks.sui_balance_tag);
    const raw = state.latest(&account) orelse return null;
    const amount: u64 = @truncate(checks.accumulatorAmount(raw) orelse return null);
    var est = td.*;
    est.gas_data.budget = 0; // include_gas_payment = false
    const reserved: u64 = switch (checks.declaredWithdrawals(arena, &est, &env.chain_id, state) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return amount,
    }) {
        .fail => 0,
        .ok => |list| blk: {
            for (list) |w| if (std.mem.eql(u8, &w.account, &account)) break :blk w.amount;
            break :blk 0;
        },
    };
    return amount -| reserved;
}

/// `compute_gas_loading_cost_mist`.
fn loadingCost(cfg: *const protocol.ProtocolConfig, extra: u64, rgp: u64) u64 {
    const units = extra *| 40 *| (cfg.obj_access_cost_read_per_byte orelse 0);
    const rounded = if (cfg.gas_rounding_step) |step| (if (step == 0 or units % step == 0) units else units +| (step - units % step)) else units;
    return rounded *| rgp;
}

/// The written mock gas coin's storage rebate (= its storage cost): the last u64 of the object.
fn mockStorageCost(objects: []const []const u8) u64 {
    var best: u64 = 0;
    for (objects) |raw| {
        const v = ObjectView.parse(raw) catch continue;
        if (!std.mem.eql(u8, &v.id, &mock_gas_id) or raw.len < 8) continue;
        best = @max(best, std.mem.readInt(u64, raw[raw.len - 8 ..][0..8], .little));
    }
    return best;
}

/// A struct type input without type arguments as a TypeTag (the allowlist names plain types).
fn plainTag(t: *const types.TypeInput) ?types.TypeTag {
    const st = switch (t.*) {
        .@"struct" => |x| x,
        else => return null,
    };
    if (st.type_args.len != 0) return null;
    if (!types.hand.Identifier.isValid(st.module.@"0") or !types.hand.Identifier.isValid(st.name.@"0")) return null;
    return .{ .@"struct" = .{ .address = st.address, .module = .{ .@"0" = st.module.@"0" }, .name = .{ .@"0" = st.name.@"0" }, .type_args = &.{} } };
}

fn gaslessAllowed(cfg: *const protocol.ProtocolConfig, t: ?types.TypeTag) bool {
    const x = t orelse return false;
    return checks.gaslessMinAmount(cfg, &x) != null;
}

/// `ProgrammableMoveCall::validate_gasless_transaction`: 0x2 fund functions only, each with one
/// type argument that is (or, for withdrawal_split, is the `Balance<T>` of) an allowlisted type.
fn gaslessMoveCall(cfg: *const protocol.ProtocolConfig, m: *const types.ProgrammableMoveCall) bool {
    const pkg = m.package.@"0".@"0";
    for (pkg[0..31]) |b| if (b != 0) return false;
    if (pkg[31] != 2) return false;
    const Fn = struct { []const u8, []const u8, bool }; // module, function, Balance<T> argument
    const fns = [_]Fn{
        .{ "balance", "send_funds", false }, .{ "balance", "redeem_funds", false }, .{ "balance", "split", false },
        .{ "balance", "zero", false },       .{ "funds_accumulator", "withdrawal_split", true }, .{ "coin", "into_balance", false },
        .{ "coin", "redeem_funds", false },  .{ "coin", "send_funds", false },                  .{ "coin", "put", false },
    };
    const f = for (fns) |f| {
        if (std.mem.eql(u8, f[0], m.module.@"0") and std.mem.eql(u8, f[1], m.function.@"0")) break f;
    } else return false;
    if (m.type_arguments.len != 1) return false;
    const t = &m.type_arguments[0];
    if (!f[2]) return gaslessAllowed(cfg, plainTag(t));
    // Balance::maybe_get_balance_type_param: 0x2::balance::Balance<T>
    const st = switch (t.*) {
        .@"struct" => |x| x,
        else => return false,
    };
    for (st.address.@"0"[0..31]) |b| if (b != 0) return false;
    if (st.address.@"0"[31] != 2 or !std.mem.eql(u8, st.module.@"0", "balance") or !std.mem.eql(u8, st.name.@"0", "Balance") or st.type_args.len != 1) return false;
    return gaslessAllowed(cfg, plainTag(&st.type_args[0]));
}

/// sui-rpc-api `is_gasless_candidate`: gasless on, no bcs, no non-zero price, no gas objects,
/// `validate_gasless_transaction` (commands, inputs, used inputs, pure sizes) and
/// `check_gasless_object_inputs` (every object input exists, is address or consensus-address
/// owned, and is a `Coin<T>` of an allowlisted T).
fn gaslessCandidate(arena: Allocator, cfg: *const protocol.ProtocolConfig, state: State, req: *const resolve.Request, has_bcs: bool, td: *const types.TransactionDataV1) Allocator.Error!bool {
    if (!cfg.feature_flags.enable_gasless or has_bcs) return false;
    if (req.gasPrice()) |p| if (p != 0) return false;
    if (req.gasObjects() != 0) return false;
    const pt = checks.ptbOf(td) orelse return false;
    if (pt.commands.len == 0) return false;
    for (pt.inputs) |*a| switch (a.*) {
        .Object => |o| if (o == .Receiving) return false,
        else => {},
    };
    for (pt.commands) |*c| switch (c.*) {
        .MoveCall => |*m| if (!gaslessMoveCall(cfg, m)) return false,
        .SplitCoins, .MergeCoins => {},
        else => return false,
    };
    // validate_gasless_inputs
    const used = try arena.alloc(bool, pt.inputs.len);
    @memset(used, false);
    for (pt.commands) |*c| {
        const args: []const types.Argument = switch (c.*) {
            .MoveCall => |m| m.arguments,
            .SplitCoins => |x| blk: {
                if (x[0] == .Input and x[0].Input < used.len) used[x[0].Input] = true;
                break :blk x[1];
            },
            .MergeCoins => |x| blk: {
                if (x[0] == .Input and x[0].Input < used.len) used[x[0].Input] = true;
                break :blk x[1];
            },
            else => &.{},
        };
        for (args) |a| if (a == .Input and a.Input < used.len) {
            used[a.Input] = true;
        };
    }
    const max_unused = protocol.derived.gaslessMaxUnusedInputs(cfg);
    const max_pure = protocol.derived.gaslessMaxPureInputBytes(cfg);
    var unused_pure: u64 = 0;
    for (pt.inputs, used) |*a, u| switch (a.*) {
        .Pure => |b| {
            if (b.len > max_pure) return false;
            if (!u) unused_pure += 1;
        },
        else => if (!u) return false,
    };
    if (unused_pure > max_unused) return false;
    // input_objects (duplicates fail) and check_gasless_object_inputs. A coin reservation (an
    // ImmOrOwnedObject ref whose digest is a reservation) is a withdrawal, not an input object
    // (`CallArg::input_objects`): no object is loaded for it and it is no duplicate of anything.
    for (pt.inputs, 0..) |*a, i| {
        const id: Id = switch (a.*) {
            .Object => |o| switch (o) {
                .ImmOrOwnedObject => |r| if (checks.isCoinReservation(&r[2].@"0".@"0")) continue else r[0].@"0".@"0",
                .SharedObject => |sh| sh.id.@"0".@"0",
                .Receiving => return false,
            },
            else => continue,
        };
        for (pt.inputs[0..i]) |*b| switch (b.*) {
            .Object => |o| switch (o) {
                .ImmOrOwnedObject => |r| if (!checks.isCoinReservation(&r[2].@"0".@"0") and std.mem.eql(u8, &r[0].@"0".@"0", &id)) return false,
                .SharedObject => |sh| if (std.mem.eql(u8, &sh.id.@"0".@"0", &id)) return false,
                .Receiving => {},
            },
            else => {},
        };
        const raw = state.latest(&id) orelse return false;
        const obj = bcs.decode(types.Object, arena, raw) catch return false;
        const mo = switch (obj.data) {
            .Move => |x| x,
            .Package => continue,
        };
        switch (obj.owner) {
            .AddressOwner, .ConsensusAddressOwner => {},
            else => return false,
        }
        const coin: types.TypeTag = switch (mo.type_.@"0") {
            .GasCoin => checks.sui_coin_tag,
            .Coin => |t| t,
            else => return false,
        };
        if (!gaslessAllowed(cfg, coin)) return false;
    }
    return true;
}

/// sui-rpc-api `simulate_transaction` with `do_gas_selection` and checks on: budget estimation
/// (when the request has no budget and no bcs), then `select_gas` when the payment is empty.
/// Leaves `td` ready for the final simulation.
fn gasSelection(e: *const Engine, arena: Allocator, env: *const EpochEnv, state: State, req: *const resolve.Request, has_bcs: bool, td: *types.TransactionDataV1) !GasOutcome {
    const cfg = env.cfg;
    const max_gas = cfg.max_tx_gas orelse 0;
    // a gasless simulation first; kept unless it fails for gas (post-execution gasless rules)
    if (try gaslessCandidate(arena, cfg, state, req, has_bcs, td)) {
        var g = td.*;
        g.gas_data.price = 0;
        g.gas_data.budget = 0;
        try configureValidity(e, arena, env, &g);
        const g_raw = try bcs.encodeAlloc(types.TransactionData, arena, &types.TransactionData{ .V1 = g });
        switch (try run(e, arena, env, state, g_raw, g, false, false)) {
            .ok => |o| {
                const insufficient_gas = switch (o.eff) {
                    .V2 => |v| v.status == .Failure and v.status.Failure.@"error" == .InsufficientGas,
                    .V1 => false,
                };
                if (!insufficient_gas) {
                    td.* = g;
                    return .ok;
                }
            },
            .fail => |f| return .{ .reply = try failReply(arena, f) },
            .unimplemented => |why| return .{ .reply = try errReply(arena, code_unimplemented, why) },
        }
    }

    const budget_was_estimated = req.gasBudget() == null and !has_bcs;
    var estimation_failed = false;
    var estimation_failure: ?types.ExecutionFailure = null;
    if (budget_was_estimated) {
        var est = td.*;
        est.gas_data.payment = &.{};
        est.gas_data.budget = max_gas;
        const est_raw = try bcs.encodeAlloc(types.TransactionData, arena, &types.TransactionData{ .V1 = est });
        const sim = switch (try run(e, arena, env, state, est_raw, est, true, false)) {
            .ok => |o| o,
            .fail => |f| return .{ .reply = try failReply(arena, f) },
            .unimplemented => |why| return .{ .reply = try errReply(arena, code_unimplemented, why) },
        };
        const v2 = switch (sim.eff) {
            .V2 => |v| v,
            .V1 => return .{ .reply = try errReply(arena, code_unimplemented, "effects v1") },
        };
        const g = v2.gas_used;
        // estimate_gas_budget_from_gas_cost
        const storage = g.storageCost -| mockStorageCost(sim.objects);
        const used = g.computationCost +| storage;
        const net: i64 = @as(i64, @bitCast(used)) -| @as(i64, @bitCast(g.storageRebate));
        const base = @max(g.computationCost, if (net < 0) 0 else @as(u64, @intCast(net)));
        const extra: u64 = @as(u64, req.gasObjects()) -| 1;
        const estimate = @min(base +| loadingCost(cfg, extra, env.rgp) +| (1000 *| env.rgp), max_gas);
        const balance = td.gas_data.budget;
        if (balance < estimate) return .{ .reply = try errReply(arena, code_invalid_argument, try std.fmt.allocPrint(arena, "Insufficient gas balance to cover estimated transaction cost. Available gas balance: {d} MIST. Estimated gas budget required: {d} MIST", .{ balance, estimate })) };
        td.gas_data.budget = estimate;
        estimation_failed = v2.status != .Success;
        if (v2.status == .Failure) estimation_failure = v2.status.Failure;
    }

    if (td.gas_data.payment.len == 0) {
        const owner = td.gas_data.owner.@"0";
        const budget = td.gas_data.budget;
        const pt = checks.ptbOf(td);
        const gas_coin_used = if (pt) |p| checks.usesGasCoin(p) else false;
        const ab = try addressBalanceForGas(arena, env, state, td);
        var selected_value: u64 = 0;
        var coin_balance: u64 = 0;
        if (!gas_coin_used and ab != null and ab.? >= budget) {
            td.gas_data.payment = &.{};
            if (td.expiration == .None) try configureValidity(e, arena, env, td);
            selected_value = budget;
        } else {
            const PayRef = @typeInfo(@TypeOf(td.gas_data.payment)).pointer.child;
            var pay: std.ArrayList(PayRef) = .empty;
            const limit: usize = cfg.max_gas_payment_objects orelse 256;
            // `owned_objects_iter(owner, Coin<SUI>)` filtered (inputs, unreadable, consensus,
            // not a gas coin), then `take(max_gas_payment_objects)`: the index is read in growing
            // windows until `limit` coins pass the filters or the owner's rows run out.
            var want: usize = limit + (if (pt) |p| p.inputs.len else 0);
            while (true) {
                const ids = (state.ownedGasCoins(arena, &owner, want) catch |err| return .{ .reply = switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.Unavailable => try errReply(arena, code_unavailable, "rpc indexes are being built"),
                    error.Internal => try errReply(arena, code_internal, "owner index read failed"),
                } }) orelse return .{ .reply = try errReply(arena, code_not_found, "") };
                pay.clearRetainingCapacity();
                coin_balance = 0;
                for (ids) |*id| {
                    if (pay.items.len >= limit) break;
                    const c = gasCandidate(state, pt, id) orelse continue;
                    try pay.append(arena, .{ .{ .@"0" = .{ .@"0" = c.v.id } }, .{ .@"0" = c.v.version }, .{ .@"0" = .{ .@"0" = c.v.digest() } } });
                    coin_balance +|= c.value;
                }
                if (pay.items.len >= limit or ids.len < want) break;
                want *|= 2;
            }
            selected_value = coin_balance;
            if (protocol.derived.enableCoinReservationObjRefs(cfg) and gas_coin_used and ab != null and ab.? > 0) {
                const account = checks.accumulatorId(&owner, &checks.sui_balance_tag);
                const r = resolve.encodeReservation(&account, env.epoch, ab.?, 0, &env.chain_id);
                try pay.insert(arena, 0, .{ r[0], r[1], r[2] });
                selected_value +|= ab.?;
                if (td.expiration == .None) try configureValidity(e, arena, env, td);
            }
            td.gas_data.payment = pay.items;
        }
        var final_budget = budget;
        if (budget_was_estimated) {
            var real: u64 = 0;
            for (td.gas_data.payment) |r| {
                if (!checks.isCoinReservation(&r[2].@"0".@"0")) real += 1;
            }
            final_budget = @min(budget +| loadingCost(cfg, real -| 1, env.rgp), max_gas);
            td.gas_data.budget = final_budget;
        }
        if (selected_value < final_budget) {
            // a failed estimation run reports the execution failure, not a funding quote
            if (estimation_failed) if (estimation_failure) |f| return .{ .reply = try simulationFailureReply(arena, e, env, state, f) };
            const ig = try failure.insufficientGas(arena, .{ .owner = owner, .required_budget = final_budget, .coin_balance = coin_balance, .address_balance = ab orelse 0 });
            return .{ .reply = .{ .err = .{ .code = code_invalid_argument, .message = ig.message, .details = ig.details } } };
        }
    }
    // coin-paid transactions get a proposer restriction too (a no-op on the address-balance
    // paths, which already set their expiration)
    try restrictTransactionProposers(e, arena, env, td);
    return .ok;
}

/// One owner-index row through `select_gas`'s filters: not an ImmOrOwned input of the
/// transaction, readable at its latest version, not consensus-owned, a `GasCoin`.
fn gasCandidate(state: State, pt: ?*const types.ProgrammableTransaction, id: *const Id) ?struct { v: ObjectView, value: u64 } {
    if (pt) |p| for (p.inputs) |*a| switch (a.*) {
        .Object => |o| switch (o) {
            .ImmOrOwnedObject => |r| if (std.mem.eql(u8, &r[0].@"0".@"0", id)) return null,
            else => {},
        },
        else => {},
    };
    const raw = state.latest(id) orelse return null;
    const v = ObjectView.parse(raw) catch return null;
    switch (raw[v.owner_at]) {
        2, 4, 5 => return null, // Shared, ConsensusAddressOwner, Party: `is_consensus`
        else => {},
    }
    const value = resolve.gasCoinValue(raw, &v) orelse return null;
    return .{ .v = v, .value = value };
}

// ---- render context ---------------------------------------------------------------------------

/// Package (and Display object) source of simulate's rendering: the transaction's own packages
/// first (`OverlayBackingPackageStore` over the output object set), then the live store, then
/// the system packages the executor loads.
const RenderSource = struct {
    overlay: []const []const u8,
    state: State,
    pkgs: *const exec.packages.Store,
    epoch: u64,

    fn get(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
        const s: *const RenderSource = @ptrCast(@alignCast(ctx));
        for (s.overlay) |raw| {
            // BCS Object: data enum tag 1 = Package, whose first field is its id
            if (raw.len > 33 and raw[0] == 1 and std.mem.eql(u8, raw[1..33], id)) return raw;
        }
        if (s.state.latest(id)) |raw| return raw;
        return s.pkgs.get(id, s.epoch);
    }

    fn packages(s: *const RenderSource) serve.movelayout.PackageSource {
        return .{ .ctx = s, .get = get };
    }
};

/// The json/display render context of one simulate request; `overlay` are the transaction's
/// objects (its published packages resolve types the store does not hold yet).
fn renderCtx(arena: Allocator, e: *const Engine, env: *const EpochEnv, state: State, overlay: []const []const u8, display: bool) Allocator.Error!*const serve.render_object.Ctx {
    const src = try arena.create(RenderSource);
    src.* = .{ .overlay = overlay, .state = state, .pkgs = e.pkgs, .epoch = env.epoch };
    const res = try arena.create(serve.movelayout.Resolver);
    res.* = serve.movelayout.Resolver.init(arena, src.packages());
    const c = try arena.create(serve.render_object.Ctx);
    c.* = .{
        .resolver = res,
        .display = if (display) try serve.objdisplay.Hook.create(arena, src.packages()) else null,
        .json_on = e.json,
    };
    return c;
}

// ---- command_outputs --------------------------------------------------------------------------

/// `SimulateTransactionResponse.command_outputs` (field 2, repeated `CommandResult`): per command
/// `return_values` (1) and `mutated_by_ref` (2), each a `CommandOutput { argument (1), value (2):
/// Bcs { name: canonical type string, value }, json (3) }`. Without a render context `json` is
/// left out.
pub fn encodeCommandOutputs(arena: Allocator, results: []const ptb.CommandResult) Allocator.Error![]const u8 {
    return encodeCommandOutputsCtx(arena, results, null);
}

/// As `encodeCommandOutputs`, with `json` rendered through `ctx` (`to_command_output`: the type
/// layout from the store, a fresh `max_json_move_value_size` budget per value; no layout or a
/// failed render leaves `json` out).
pub fn encodeCommandOutputsCtx(arena: Allocator, results: []const ptb.CommandResult, ctx: ?*const serve.render_object.Ctx) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (results) |r| {
        var cr: std.ArrayList(u8) = .empty;
        for (r.returns) |*v| try pbBytes(arena, &cr, 1, try commandOutput(arena, v, ctx));
        for (r.mutated) |*v| try pbBytes(arena, &cr, 2, try commandOutput(arena, v, ctx));
        try pbBytes(arena, &out, 2, cr.items);
    }
    return out.items;
}

/// `google.protobuf.Value` message body of `v`.
fn valueBody(arena: Allocator, v: *const serve.pbvalue.Value) Allocator.Error![]const u8 {
    var cap: usize = 256;
    while (true) : (cap *= 2) {
        const buf = try arena.alloc(u8, cap);
        var w = proto.Writer.init(buf);
        serve.pbvalue.writeBody(&w, v) catch |err| switch (err) {
            error.NoSpace => continue,
        };
        return w.bytesWritten();
    }
}

fn commandOutput(arena: Allocator, v: *const ptb.TrackedValue, ctx: ?*const serve.render_object.Ctx) Allocator.Error![]const u8 {
    var o: std.ArrayList(u8) = .empty;
    if (v.arg) |a| {
        // Argument { kind (1): GAS 1, INPUT 2, RESULT 3; input (2); result (3); subresult (4) }
        var ab: std.ArrayList(u8) = .empty;
        switch (a) {
            .GasCoin => try pbVarint(arena, &ab, 1, 1),
            .Input => |i| {
                try pbVarint(arena, &ab, 1, 2);
                try pbVarint(arena, &ab, 2, i);
            },
            .Result => |i| {
                try pbVarint(arena, &ab, 1, 3);
                try pbVarint(arena, &ab, 3, i);
            },
            .NestedResult => |x| {
                try pbVarint(arena, &ab, 1, 3);
                try pbVarint(arena, &ab, 3, x[0]);
                try pbVarint(arena, &ab, 4, x[1]);
            },
        }
        try pbBytes(arena, &o, 1, ab.items);
    }
    var ts = serve.typestr.scratch();
    var bb: std.ArrayList(u8) = .empty;
    if (serve.typestr.typeTag(&ts, v.ty)) |_| try pbBytes(arena, &bb, 1, ts.str()) else |_| {}
    try pbBytes(arena, &bb, 2, v.bytes);
    try pbBytes(arena, &o, 2, bb.items);
    if (ctx) |c| if (c.json_on) {
        if (try serve.jsonapi.typeJson(arena, c, &v.ty, v.bytes)) |jv| try pbBytes(arena, &o, 3, try valueBody(arena, &jv));
    };
    return o.items;
}

fn pbVarint(arena: Allocator, l: *std.ArrayList(u8), field: u32, v: u64) Allocator.Error!void {
    try varintRaw(arena, l, @as(u64, field) << 3);
    try varintRaw(arena, l, v);
}
fn pbBytes(arena: Allocator, l: *std.ArrayList(u8), field: u32, b: []const u8) Allocator.Error!void {
    try varintRaw(arena, l, (@as(u64, field) << 3) | 2);
    try varintRaw(arena, l, b.len);
    try l.appendSlice(arena, b);
}
fn varintRaw(arena: Allocator, l: *std.ArrayList(u8), v0: u64) Allocator.Error!void {
    var v = v0;
    while (v >= 0x80) : (v >>= 7) try l.append(arena, @as(u8, @truncate(v)) | 0x80);
    try l.append(arena, @truncate(v));
}

test "command outputs encode return values and mutated references" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const u64_tag: types.TypeTag = .u64;
    const res = [_]ptb.CommandResult{.{
        .returns = &.{.{ .bytes = &.{ 7, 0, 0, 0, 0, 0, 0, 0 }, .ty = u64_tag }},
        .mutated = &.{.{ .arg = .{ .Input = 1 }, .bytes = &.{ 9, 0, 0, 0, 0, 0, 0, 0 }, .ty = u64_tag }},
    }};
    const got = try encodeCommandOutputs(a.allocator(), &res);
    // CommandResult{ return_values: [{ value: { name: "u64", value: 07.. } }], mutated_by_ref: [{ argument: { kind: INPUT, input: 1 }, value: ... }] }
    const want = [_]u8{ 0x12, 0x2c, 0x0a, 0x11, 0x12, 0x0f, 0x0a, 0x03, 'u', '6', '4', 0x12, 0x08, 7, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x17, 0x0a, 0x04, 0x08, 0x02, 0x10, 0x01, 0x12, 0x0f, 0x0a, 0x03, 'u', '6', '4', 0x12, 0x08, 9, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectEqualSlices(u8, &want, got);
}

test "command outputs carry json rendered from the value's type layout" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const NoPkgs = struct {
        fn get(_: *const anyopaque, _: *const [32]u8) ?[]const u8 {
            return null;
        }
    };
    const res = try arena.create(serve.movelayout.Resolver);
    res.* = serve.movelayout.Resolver.init(arena, .{ .ctx = undefined, .get = NoPkgs.get });
    const ctx: serve.render_object.Ctx = .{ .resolver = res };
    const u64_tag: types.TypeTag = .u64;
    const results = [_]ptb.CommandResult{.{
        .returns = &.{.{ .bytes = &.{ 7, 0, 0, 0, 0, 0, 0, 0 }, .ty = u64_tag }},
        .mutated = &.{.{ .arg = .{ .Input = 1 }, .bytes = &.{ 9, 0, 0, 0, 0, 0, 0, 0 }, .ty = u64_tag }},
    }};
    const got = try encodeCommandOutputsCtx(arena, &results, &ctx);
    // as the test above, each CommandOutput followed by json (3): Value { string_value (3): "7" / "9" }
    const want = [_]u8{ 0x12, 0x36, 0x0a, 0x16, 0x12, 0x0f, 0x0a, 0x03, 'u', '6', '4', 0x12, 0x08, 7, 0, 0, 0, 0, 0, 0, 0, 0x1a, 0x03, 0x1a, 0x01, '7', 0x12, 0x1c, 0x0a, 0x04, 0x08, 0x02, 0x10, 0x01, 0x12, 0x0f, 0x0a, 0x03, 'u', '6', '4', 0x12, 0x08, 9, 0, 0, 0, 0, 0, 0, 0, 0x1a, 0x03, 0x1a, 0x01, '9' };
    try std.testing.expectEqualSlices(u8, &want, got);

    // a value that does not decode under its layout (trailing bytes) has no json, as in Rust
    const bad = [_]ptb.CommandResult{.{ .returns = &.{.{ .bytes = &.{ 7, 0, 0, 0, 0, 0, 0, 0, 1 }, .ty = u64_tag }}, .mutated = &.{} }};
    const got_bad = try encodeCommandOutputsCtx(arena, &bad, &ctx);
    const want_bad = [_]u8{ 0x12, 0x14, 0x0a, 0x12, 0x12, 0x10, 0x0a, 0x03, 'u', '6', '4', 0x12, 0x09, 7, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectEqualSlices(u8, &want_bad, got_bad);

    // json switched off: the plain encoding
    const off: serve.render_object.Ctx = .{ .resolver = res, .json_on = false };
    try std.testing.expectEqualSlices(u8, try encodeCommandOutputs(arena, &results), try encodeCommandOutputsCtx(arena, &results, &off));
}

// ---- checks disabled (DevInspect<true>) through the handler -------------------------------------
// The system packages come from the corpus (`ptb.devinspect_test.Fixture`): skipped without it.

/// A `SimulateTransactionRequest`: `transaction.bcs.value`, the read mask and `checks`.
fn testRequest(arena: Allocator, tx_raw: []const u8, mask: []const []const u8, checks_disabled: bool) ![]const u8 {
    var bcs_msg: std.ArrayList(u8) = .empty;
    try pbBytes(arena, &bcs_msg, 2, tx_raw);
    var tx: std.ArrayList(u8) = .empty;
    try pbBytes(arena, &tx, 1, bcs_msg.items);
    var fm: std.ArrayList(u8) = .empty;
    for (mask) |path| try pbBytes(arena, &fm, 1, path);
    var req: std.ArrayList(u8) = .empty;
    try pbBytes(arena, &req, 1, tx.items);
    try pbBytes(arena, &req, 2, fm.items);
    if (checks_disabled) try pbVarint(arena, &req, 3, 1); // TransactionChecks::DISABLED
    return req.items;
}

fn testEnv(f: *const ptb.devinspect_test.Fixture) EpochEnv {
    return .{ .chain_id = @splat(0), .epoch = f.epoch, .pv = f.pv, .cfg = f.cfg, .rgp = f.rgp, .epoch_start_ms = f.start_ms, .committee_size = 100 };
}

fn testState(arena: Allocator, f: *const ptb.devinspect_test.Fixture) !*state_mod.MapState {
    const ms = try arena.create(state_mod.MapState);
    ms.* = .{};
    var it = f.objs.iterator();
    while (it.next()) |kv| try ms.put(arena, kv.key_ptr.*, (try ObjectView.parse(kv.value_ptr.*)).version, kv.value_ptr.*);
    return ms;
}

/// One `CommandResult` holding one return value: `CommandOutput { value: Bcs { name, value },
/// json: Value { string_value } }`.
fn testReturnOutput(arena: Allocator, type_name: []const u8, value: []const u8, json_string: []const u8) ![]const u8 {
    var b: std.ArrayList(u8) = .empty;
    try pbBytes(arena, &b, 1, type_name);
    try pbBytes(arena, &b, 2, value);
    var j: std.ArrayList(u8) = .empty;
    try pbBytes(arena, &j, 3, json_string);
    var o: std.ArrayList(u8) = .empty;
    try pbBytes(arena, &o, 2, b.items);
    try pbBytes(arena, &o, 3, j.items);
    var cr: std.ArrayList(u8) = .empty;
    try pbBytes(arena, &cr, 1, o.items);
    var out: std.ArrayList(u8) = .empty;
    try pbBytes(arena, &out, 2, cr.items);
    return out.items;
}

// sui-core `simulate_transaction`: `check_dev_inspect_input` in place of `check_transaction_input`
// when checks are disabled (no `check_objects` ownership pass, `check_gas` with
// `gas_ownership_checks = false`), then `dev_inspect_transaction(.., skip_all_checks = true)`;
// sui-rpc-api renders `execution_result` as `command_outputs` with each value's `json`.
test "checks disabled: an object and a gas coin of another address execute; command outputs carry json" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const dt = ptb.devinspect_test;
    var f: dt.Fixture = undefined;
    try f.init(arena, std.testing.io);
    defer f.deinit();
    const other: types.Owner = .{ .AddressOwner = .{ .@"0" = dt.idOf(0x77) } };
    const coin = try dt.coinObject(arena, dt.idOf(0x71), 5, 5000, other);
    const gas = try dt.coinObject(arena, dt.idOf(0x72), 9, dt.gas_balance, other);
    try f.add(coin);
    try f.add(gas);
    var td = try f.data(.{
        .inputs = &.{ .{ .Pure = &.{ 2, 'h', 'i' } }, .{ .Object = .{ .ImmOrOwnedObject = try dt.refOf(coin) } } },
        .commands = &.{
            dt.moveCall(1, "string", "utf8", &.{}, &.{.{ .Input = 0 }}),
            dt.moveCall(2, "coin", "value", &.{dt.suiInput()}, &.{.{ .Input = 1 }}),
        },
    });
    const engine: Engine = .{ .gpa = std.heap.page_allocator, .pkgs = &f.pkgs, .dev_inspect = .enabled };
    const env = testEnv(&f);
    const ms = try testState(arena, &f);
    const mask: []const []const u8 = &.{"command_outputs"};

    var want: std.ArrayList(u8) = .empty;
    try want.appendSlice(arena, try testReturnOutput(arena, "0x0000000000000000000000000000000000000000000000000000000000000001::string::String", &.{ 2, 'h', 'i' }, "hi"));
    try want.appendSlice(arena, try testReturnOutput(arena, "u64", try dt.u64Bytes(arena, 5000), "5000"));

    // the sender's own gas coin, another address's object; then another address's gas coin too
    for (0..2) |round| {
        if (round == 1) {
            const pay = try arena.alloc(@typeInfo(@TypeOf(td.V1.gas_data.payment)).pointer.child, 1);
            const r = try dt.refOf(gas);
            pay[0] = .{ r[0], r[1], r[2] };
            td.V1.gas_data.payment = pay;
        }
        const tx_raw = try bcs.encodeAlloc(types.TransactionData, arena, &td);
        // checks on: check_one_object refuses an object of another address
        switch (try engine.simulate(arena, &env, ms.state(), try testRequest(arena, tx_raw, mask, false))) {
            .ok => return error.TestUnexpectedResult,
            .err => |e| {
                try std.testing.expectEqual(@as(u8, code_invalid_argument), e.code);
                try std.testing.expect(std.mem.indexOf(u8, e.message, "is owned by account address") != null);
            },
        }
        // checks off: it runs
        switch (try engine.simulate(arena, &env, ms.state(), try testRequest(arena, tx_raw, mask, true))) {
            .ok => |resp| try std.testing.expectEqualSlices(u8, want.items, resp),
            .err => |e| {
                std.debug.print("checks disabled: code {d}: {s}\n", .{ e.code, e.message });
                return error.TestUnexpectedResult;
            },
        }
    }
}

// `check_dev_inspect_input` still runs `check_gas` (SuiGasStatus::new and check_gas_balance): the
// gas price and budget rules hold with checks disabled.
test "checks disabled: the gas price and budget rules still hold" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const dt = ptb.devinspect_test;
    var f: dt.Fixture = undefined;
    try f.init(arena, std.testing.io);
    defer f.deinit();
    const engine: Engine = .{ .gpa = std.heap.page_allocator, .pkgs = &f.pkgs, .dev_inspect = .enabled };
    const env = testEnv(&f);
    const ms = try testState(arena, &f);
    const pt: types.ProgrammableTransaction = .{
        .inputs = &.{.{ .Pure = try dt.u64Bytes(arena, 7) }},
        .commands = &.{dt.moveCall(1, "u64", "max", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 0 } })},
    };
    const Case = struct { price: u64, budget: u64, message: []const u8 };
    const cases = [_]Case{
        .{ .price = f.rgp - 1, .budget = dt.budget, .message = "Error checking transaction input objects: Gas price 99 under reference gas price (RGP) 100" },
        .{ .price = f.rgp, .budget = dt.gas_balance + 1, .message = "Error checking transaction input objects: Balance of gas object 1000000000000 is lower than the needed amount: 1000000000001" },
    };
    for (cases) |c| {
        var td = try f.data(pt);
        td.V1.gas_data.price = c.price;
        td.V1.gas_data.budget = c.budget;
        const tx_raw = try bcs.encodeAlloc(types.TransactionData, arena, &td);
        switch (try engine.simulate(arena, &env, ms.state(), try testRequest(arena, tx_raw, &.{"command_outputs"}, true))) {
            .ok => return error.TestUnexpectedResult,
            .err => |e| {
                try std.testing.expectEqual(@as(u8, code_invalid_argument), e.code);
                try std.testing.expectEqualStrings(c.message, e.message);
            },
        }
    }
    try std.testing.expectEqual(@as(u64, 100), f.rgp);
}

// sui-node's own answers (`zui-truth-rpc-exec synth`: Mysten's SimulateTransaction handler over
// transaction_simulation, checks disabled, a mock gas coin) for natives whose result is not of
// its declared type, in every position sui-node consumes such a value, next to the same calls
// with a type that fits. 18 transactions, each with and without `command_outputs` in the mask:
// - `funds_accumulator::withdraw_from_accumulator_address<T>` (a struct of one u64 whatever `T`
//   is) from the PTB, through `withdraw_impl` and through `redeem`; `T` = u256, u64, ID,
//   vector<u64> (InvariantViolation in command 0) and Balance<SUI>, Supply<SUI> (success)
// - `config::read_setting_impl` with a `Value` that is not the stored one: a vector<u64> as
//   Option<u8>, Option<String>, also when it is empty (InvariantViolation: a vector of a
//   primitive keeps its element kind), an empty vector<ID> as Option<u8> (success: a generic
//   vector is checked element by element), a vector<ID> as Option<u64> and Option<address>
// The record has the rpc-simulate format (tools/truth/rpc-exec/README.md).
test "checks disabled: a native result that is not of its declared type answers as sui-node (Rust-made vectors)" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const dt = ptb.devinspect_test;
    const conformance = @import("conformance.zig");
    var f: dt.Fixture = undefined;
    try f.init(arena, std.testing.io);
    defer f.deinit();
    const data = try @import("harness").decompressZstd(arena, @embedFile("testdata/devinspect_ill_typed.rec.zst"), 1 << 24);
    const blocks = try conformance.parseRecord(arena, data);
    try std.testing.expectEqual(@as(usize, 1), blocks.len);
    const b = &blocks[0];
    // the fixture's system packages are the record's epoch
    try std.testing.expectEqual(f.epoch, b.epoch);
    try std.testing.expectEqual(f.pv, b.pv);
    try std.testing.expectEqual(@as(usize, 36), b.cases.len);
    const ms = try conformance.mapState(arena, b.objects);
    const env = try conformance.envOf(serve.b58.decode32(conformance.mainnet_chain_id_b58).?, b);
    const engine: Engine = .{ .gpa = std.heap.page_allocator, .pkgs = &f.pkgs, .dev_inspect = .enabled };
    var failures: usize = 0;
    for (b.cases) |*k| {
        switch (try engine.simulate(arena, &env, ms.state(), k.request)) {
            .ok => |resp| {
                if (k.code != 0 or !std.mem.eql(u8, resp, k.response)) {
                    std.debug.print("case {d}: zui answered OK with {d} bytes; sui-node code {d}, {d} bytes\n", .{ k.case, resp.len, k.code, k.response.len });
                    return error.TestUnexpectedResult;
                }
                // TransactionEffects.status.error (ExecutionError.kind = INVARIANT_VIOLATION is 20)
                if (std.mem.indexOf(u8, resp, "InvariantViolation in command 0") != null) failures += 1;
            },
            .err => |e| {
                std.debug.print("case {d}: zui code {d} \"{s}\"; sui-node code {d} \"{s}\"\n", .{ k.case, e.code, e.message, k.code, k.message });
                return error.TestUnexpectedResult;
            },
        }
    }
    // 12 of the 18 transactions fail that way, under both masks
    try std.testing.expectEqual(@as(usize, 24), failures);
}

// ---- gasless simulation with a coin reservation input --------------------------------------------

// sui-rpc-api simulate/mod.rs `is_gasless_candidate` loads `transaction.input_objects()`, and
// sui-types `CallArg::input_objects` yields nothing for an ImmOrOwnedObject ref whose digest is a
// coin reservation: the ref names the sender's balance, not an object, so no object is looked up
// for it. Every other object input must still be in the store.
test "gasless candidate: a coin reservation input is not an input object to load" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const dt = ptb.devinspect_test;
    const cfg = try protocol.get(141, .mainnet);
    var usdc_addr: Id = undefined;
    _ = try std.fmt.hexToBytes(&usdc_addr, "dba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7");
    const usdc: types.TypeInput = .{ .@"struct" = .{ .address = .{ .@"0" = usdc_addr }, .module = .{ .@"0" = "usdc" }, .name = .{ .@"0" = "USDC" }, .type_args = &.{} } };
    // a reservation digest: the amount, then 20 bytes of 0xac at the end
    var res_digest: Id = @splat(0);
    std.mem.writeInt(u64, res_digest[0..8], 1_000_000, .little);
    @memset(res_digest[12..32], 0xac);
    const ObjRef = @FieldType(types.ObjectArg, "ImmOrOwnedObject");
    const reservation: ObjRef = .{ .{ .@"0" = .{ .@"0" = dt.idOf(0x0d) } }, .{ .@"0" = 7 }, .{ .@"0" = .{ .@"0" = res_digest } } };
    const object: ObjRef = .{ .{ .@"0" = .{ .@"0" = dt.idOf(0x0d) } }, .{ .@"0" = 7 }, .{ .@"0" = .{ .@"0" = dt.idOf(0x33) } } };
    const empty: state_mod.MapState = .{};
    const req: resolve.Request = .{};
    const send = dt.moveCall(2, "coin", "send_funds", &.{usdc}, &.{ .{ .Input = 0 }, .{ .Input = 1 } });
    const send_second = dt.moveCall(2, "coin", "send_funds", &.{usdc}, &.{ .{ .Input = 2 }, .{ .Input = 1 } });
    const recipient: types.CallArg = .{ .Pure = &dt.idOf(0x44) };
    const data = struct {
        fn of(inputs: []const types.CallArg, commands: []const types.Command) types.TransactionDataV1 {
            return .{
                .kind = .{ .ProgrammableTransaction = .{ .inputs = inputs, .commands = commands } },
                .sender = .{ .@"0" = dt.sender },
                .gas_data = .{ .payment = &.{}, .owner = .{ .@"0" = dt.sender }, .price = 0, .budget = 0 },
                .expiration = .None,
            };
        }
    }.of;

    // the reservation names no object in the store: still a candidate
    const one = data(&.{ .{ .Object = .{ .ImmOrOwnedObject = reservation } }, recipient }, &.{send});
    try std.testing.expect(try gaslessCandidate(arena, cfg, empty.state(), &req, false, &one));
    // the same reservation twice is no duplicate object input either
    const two = data(&.{ .{ .Object = .{ .ImmOrOwnedObject = reservation } }, recipient, .{ .Object = .{ .ImmOrOwnedObject = reservation } } }, &.{ send, send_second });
    try std.testing.expect(try gaslessCandidate(arena, cfg, empty.state(), &req, false, &two));
    // an object ref under the same id is an input object: missing from the store, no candidate
    const missing = data(&.{ .{ .Object = .{ .ImmOrOwnedObject = object } }, recipient }, &.{send});
    try std.testing.expect(!try gaslessCandidate(arena, cfg, empty.state(), &req, false, &missing));
    // and next to a reservation the missing object still decides
    const mixed = data(&.{ .{ .Object = .{ .ImmOrOwnedObject = reservation } }, recipient, .{ .Object = .{ .ImmOrOwnedObject = object } } }, &.{ send, send_second });
    try std.testing.expect(!try gaslessCandidate(arena, cfg, empty.state(), &req, false, &mixed));
    // a transaction given as bcs, or with a gas price, is never one
    try std.testing.expect(!try gaslessCandidate(arena, cfg, empty.state(), &req, true, &one));
    const priced: resolve.Request = .{ .gas = .{ .price = 100 } };
    try std.testing.expect(!try gaslessCandidate(arena, cfg, empty.state(), &priced, false, &one));
}

// Mainnet checkpoint 342452733, transaction 11, answered by sui-node 1.83.1 (rpc-simulate record
// format, tools/truth/rpc-exec/README.md): `0x2::coin::send_funds<USDC>` of a coin reservation
// of the sender's USDC balance. Cases: 1 the signed bytes (gas from the address balance), 5 gas
// selection over the bytes, 6 gas selection with a budget the sender's SUI does not cover
// (INVALID_ARGUMENT), 7 the unresolved transaction with gas selection, which sui-node simulates
// gasless and keeps (all gas costs 0). The pre-state is the record's without the system state
// object, plus the USDC package.
test "gasless simulation of a coin reservation transfer answers as sui-node (mainnet 342452733/11)" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const dt = ptb.devinspect_test;
    const conformance = @import("conformance.zig");
    var f: dt.Fixture = undefined;
    try f.init(arena, std.testing.io);
    defer f.deinit();
    const data = try @import("harness").decompressZstd(arena, @embedFile("testdata/gasless_coin_reservation.rec.zst"), 1 << 24);
    const blocks = try conformance.parseRecord(arena, data);
    try std.testing.expectEqual(@as(usize, 1), blocks.len);
    const b = &blocks[0];
    // the fixture's system packages are the record's epoch
    try std.testing.expectEqual(f.epoch, b.epoch);
    try std.testing.expectEqual(f.pv, b.pv);
    try std.testing.expectEqual(@as(usize, 4), b.cases.len);
    for (b.objects) |raw| {
        const v = try ObjectView.parse(raw);
        if (v.is_package) try f.pkgs.user.put(arena, v.id, raw);
    }
    const ms = try conformance.mapState(arena, b.objects);
    const env = try conformance.envOf(serve.b58.decode32(conformance.mainnet_chain_id_b58).?, b);
    const engine: Engine = .{ .gpa = std.heap.page_allocator, .pkgs = &f.pkgs };
    for (b.cases) |*k| {
        switch (try engine.simulate(arena, &env, ms.state(), k.request)) {
            .ok => |resp| if (k.code != 0 or !std.mem.eql(u8, resp, k.response)) {
                std.debug.print("case {d}: zui answered OK with {d} bytes; sui-node code {d}, {d} bytes\n", .{ k.case, resp.len, k.code, k.response.len });
                return error.TestUnexpectedResult;
            },
            .err => |e| if (k.code != e.code or !std.mem.eql(u8, e.message, k.message)) {
                std.debug.print("case {d}: zui code {d} \"{s}\"; sui-node code {d} \"{s}\"\n", .{ k.case, e.code, e.message, k.code, k.message });
                return error.TestUnexpectedResult;
            },
        }
    }
}

// The executor gets the transaction with the reservation rewritten to a sender FundsWithdrawal
// (sui-core `rewrite_transaction_for_coin_reservations`), so the reservation is one of
// `compute_input_reservations` (temporary_store.rs) and `check_gasless_execution_requirements`
// holds it to the remainder rule: what the transaction leaves of the reserved amount is 0 or at
// least the token's minimum (USDC: 10000). A gasless simulation that breaks the rule ends in
// InsufficientGas, which simulate/mod.rs `is_gasless_post_execution_failure` answers with the
// priced flow. The pre-state is the record's above; the expectations follow the Rust source (the
// record has the whole reservation sent, a remainder of 0).
test "gasless simulation: a coin reservation's unused remainder is held to the token minimum" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const dt = ptb.devinspect_test;
    const conformance = @import("conformance.zig");
    var f: dt.Fixture = undefined;
    try f.init(arena, std.testing.io);
    defer f.deinit();
    const data = try @import("harness").decompressZstd(arena, @embedFile("testdata/gasless_coin_reservation.rec.zst"), 1 << 24);
    const b = &(try conformance.parseRecord(arena, data))[0];
    for (b.objects) |raw| {
        const v = try ObjectView.parse(raw);
        if (v.is_package) try f.pkgs.user.put(arena, v.id, raw);
    }
    const ms = try conformance.mapState(arena, b.objects);
    const env = try conformance.envOf(serve.b58.decode32(conformance.mainnet_chain_id_b58).?, b);
    const engine: Engine = .{ .gpa = std.heap.page_allocator, .pkgs = &f.pkgs };

    // the transaction's sender, reservation ref (21.34 USDC of the sender's balance) and recipient
    var tx_sender: Id = undefined;
    _ = try std.fmt.hexToBytes(&tx_sender, "1daff9e3ade7510db6e7152e8fa21495b70a33da4d09164b0ad4c3c93660a662");
    var res_id: Id = undefined;
    _ = try std.fmt.hexToBytes(&res_id, "0de54d7329b9cd224a03ab634967f964fe93d90bad11ad18567c32e6f460ad50");
    var recipient: Id = undefined;
    _ = try std.fmt.hexToBytes(&recipient, "149b3e2272d5eb0fc6218ae73a9c6342131955844dbaf17a067b55a0569ebaa4");
    var usdc_addr: Id = undefined;
    _ = try std.fmt.hexToBytes(&usdc_addr, "dba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7");
    const usdc: types.TypeInput = .{ .@"struct" = .{ .address = .{ .@"0" = usdc_addr }, .module = .{ .@"0" = "usdc" }, .name = .{ .@"0" = "USDC" }, .type_args = &.{} } };
    const res_digest = serve.b58.decode32("7WAzsXjhkSvrSjLzQcXAAyeTFsLWuyAJagCnsXkHPQMR").?;
    try std.testing.expect(checks.isCoinReservation(&res_digest));
    const reserved: u64 = std.mem.readInt(u64, res_digest[0..8], .little);
    try std.testing.expectEqual(@as(u64, 21_340_000), reserved);
    const req: resolve.Request = .{};

    // the amount sent back to the sender is what stays of the reservation
    const Run = struct { back: u64, gasless: bool };
    for ([_]Run{ .{ .back = 1, .gasless = false }, .{ .back = 9_999, .gasless = false }, .{ .back = 10_000, .gasless = true } }) |r| {
        var td: types.TransactionDataV1 = .{
            .kind = .{ .ProgrammableTransaction = .{
                .inputs = &.{
                    .{ .Object = .{ .ImmOrOwnedObject = .{ .{ .@"0" = .{ .@"0" = res_id } }, .{ .@"0" = 912306153 }, .{ .@"0" = .{ .@"0" = res_digest } } } } },
                    .{ .Pure = &recipient },
                    .{ .Pure = &tx_sender },
                    .{ .Pure = try dt.u64Bytes(arena, r.back) },
                },
                .commands = &.{
                    .{ .SplitCoins = .{ .{ .Input = 0 }, &.{.{ .Input = 3 }} } },
                    dt.moveCall(2, "coin", "send_funds", &.{usdc}, &.{ .{ .NestedResult = .{ 0, 0 } }, .{ .Input = 2 } }),
                    dt.moveCall(2, "coin", "send_funds", &.{usdc}, &.{ .{ .Input = 0 }, .{ .Input = 1 } }),
                },
            } },
            .sender = .{ .@"0" = tx_sender },
            .gas_data = .{ .payment = &.{}, .owner = .{ .@"0" = tx_sender }, .price = env.rgp, .budget = 50_000_000 },
            .expiration = .None,
        };
        try std.testing.expect(try gaslessCandidate(arena, env.cfg, ms.state(), &req, false, &td));
        const outcome = try gasSelection(&engine, arena, &env, ms.state(), &req, false, &td);
        if (r.gasless) {
            // kept: gas selection is over, the transaction is the gasless one
            try std.testing.expect(outcome == .ok);
            try std.testing.expectEqual(@as(u64, 0), td.gas_data.price);
            try std.testing.expectEqual(@as(u64, 0), td.gas_data.budget);
        } else {
            // not kept: the priced flow goes on with the reference gas price
            try std.testing.expectEqual(env.rgp, td.gas_data.price);
        }
    }
}

// sui-core authority.rs `simulate_transaction`: `checks.disabled() && config.dev_inspect_disabled`
// is `UnsupportedFeatureError { "simulate with checks disabled is not allowed on this node" }`,
// which sui-rpc-api's `simulation_error_to_rpc_error` answers as INVALID_ARGUMENT with the
// error's Display ("Use of disabled feature: ..").
test "dev-inspect-disabled: a checks-disabled request gets sui-node's refusal, a checks-enabled one is unaffected" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const dt = ptb.devinspect_test;
    var f: dt.Fixture = undefined;
    try f.init(arena, std.testing.io);
    defer f.deinit();
    const env = testEnv(&f);
    const ms = try testState(arena, &f);
    const td = try f.data(.{
        .inputs = &.{.{ .Pure = try dt.u64Bytes(arena, 7) }},
        .commands = &.{dt.moveCall(1, "u64", "max", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 0 } })},
    });
    const tx_raw = try bcs.encodeAlloc(types.TransactionData, arena, &td);
    const mask: []const []const u8 = &.{"command_outputs"};
    const want_ok = try testReturnOutput(arena, "u64", try dt.u64Bytes(arena, 7), "7");
    const refusal = "Use of disabled feature: simulate with checks disabled is not allowed on this node";

    for ([_]Engine.DevInspect{ .refused, .guarded, .enabled }) |mode| {
        const engine: Engine = .{ .gpa = std.heap.page_allocator, .pkgs = &f.pkgs, .dev_inspect = mode };
        // checks enabled: the same answer whatever the switch says
        switch (try engine.simulate(arena, &env, ms.state(), try testRequest(arena, tx_raw, mask, false))) {
            .ok => |resp| try std.testing.expectEqualSlices(u8, want_ok, resp),
            .err => return error.TestUnexpectedResult,
        }
        switch (try engine.simulate(arena, &env, ms.state(), try testRequest(arena, tx_raw, mask, true))) {
            .ok => |resp| {
                try std.testing.expect(mode != .refused);
                try std.testing.expectEqualSlices(u8, want_ok, resp);
            },
            .err => |e| {
                try std.testing.expect(mode == .refused);
                try std.testing.expectEqual(@as(u8, code_invalid_argument), e.code);
                try std.testing.expectEqualStrings(refusal, e.message);
                try std.testing.expectEqualSlices(u8, try serve.status.plain(arena, code_invalid_argument, refusal), e.details);
            },
        }
    }
    // without the switch the engine is in its default state
    const plain: Engine = .{ .gpa = std.heap.page_allocator, .pkgs = &f.pkgs };
    try std.testing.expectEqual(Engine.default_dev_inspect, plain.dev_inspect);
}

// `guarded`: DevInspect<true> never runs. A request that needs its rules is UNIMPLEMENTED: a
// friend function call fails as NonEntryFunctionInvoked under the rules with checks, and an
// object of another address fails the signing checks.
test "dev inspect guarded: a request that needs DevInspect<true> is UNIMPLEMENTED" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const dt = ptb.devinspect_test;
    var f: dt.Fixture = undefined;
    try f.init(arena, std.testing.io);
    defer f.deinit();
    const coin = try dt.coinObject(arena, dt.idOf(0x71), 5, 5000, .{ .AddressOwner = .{ .@"0" = dt.idOf(0x77) } });
    try f.add(coin);
    const env = testEnv(&f);
    const ms = try testState(arena, &f);
    const engine: Engine = .{ .gpa = std.heap.page_allocator, .pkgs = &f.pkgs, .dev_inspect = .guarded };
    const Case = struct { pt: types.ProgrammableTransaction, message: []const u8 };
    const cases = [_]Case{
        .{ .pt = .{
            .inputs = &.{ .{ .Pure = try arena.dupe(u8, &dt.idOf(0x11)) }, .{ .Pure = try dt.u64Bytes(arena, 7) } },
            .commands = &.{dt.moveCall(2, "dynamic_field", "hash_type_and_key", &.{.u64}, &.{ .{ .Input = 0 }, .{ .Input = 1 } })},
        }, .message = "checks disabled: execution past a check DevInspect<true> skips is not supported" },
        .{ .pt = .{
            .inputs = &.{.{ .Object = .{ .ImmOrOwnedObject = try dt.refOf(coin) } }},
            .commands = &.{dt.moveCall(2, "coin", "value", &.{dt.suiInput()}, &.{.{ .Input = 0 }})},
        }, .message = "checks disabled: inputs that fail the signing checks are not supported" },
    };
    for (cases) |c| {
        const td = try f.data(c.pt);
        const tx_raw = try bcs.encodeAlloc(types.TransactionData, arena, &td);
        switch (try engine.simulate(arena, &env, ms.state(), try testRequest(arena, tx_raw, &.{"command_outputs"}, true))) {
            .ok => return error.TestUnexpectedResult,
            .err => |e| {
                try std.testing.expectEqual(@as(u8, code_unimplemented), e.code);
                try std.testing.expectEqualStrings(c.message, e.message);
            },
        }
    }
}

/// sui-rpc-api `simulation_failure_error`: the failure's message, and details carrying the
/// TRANSACTION_EXECUTION_FAILED ErrorInfo and the ExecutionError as simulate's effects render it
/// (`render_clever_error` included).
fn simulationFailureReply(arena: Allocator, e: *const Engine, env: *const EpochEnv, state: State, f: types.ExecutionFailure) !Reply {
    const message = try failure.simulationFailureMessage(arena, f);
    var ee = try failure.executionError(arena, f);
    // render.clever reads the effects field: [4: TransactionEffects { 4: status { 2: error } }]
    var status_msg: std.ArrayList(u8) = .empty;
    try pbBytes(arena, &status_msg, 2, ee);
    var eff: std.ArrayList(u8) = .empty;
    try pbBytes(arena, &eff, 4, status_msg.items);
    var field: std.ArrayList(u8) = .empty;
    try pbBytes(arena, &field, 4, eff.items);
    const rendered = try render.clever(arena, e, env, state, field.items);
    if (rendered.ptr != field.items.ptr) {
        var r = proto.Reader.init(rendered);
        if (r.next() catch null) |top| if (render.sub(top.data, 4)) |st| if (render.sub(st, 2)) |x| {
            ee = x;
        };
    }
    return .{ .err = .{ .code = code_invalid_argument, .message = message, .details = try failure.simulationFailureDetails(arena, message, f, ee) } };
}

test "simulation failure message renders a Move abort like sui-node" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var addr: [32]u8 = @splat(0);
    addr[0] = 0xf9;
    addr[31] = 0xe9;
    const f: types.ExecutionFailure = .{ .@"error" = .{ .MoveAbort = .{ .{ .module = .{ .address = .{ .@"0" = addr }, .name = .{ .@"0" = "rip_station" } }, .function = 21, .instruction = 18, .function_name = .{ .@"0" = "sell_card" } }, 6 } }, .command = 1 };
    try std.testing.expectEqualStrings("Transaction fails in simulation: Move Runtime Abort. Location: f9000000000000000000000000000000000000000000000000000000000000e9::rip_station::sell_card (function index 21) at offset 18, Abort Code: 6 in command 1", try failure.simulationFailureMessage(a.allocator(), f));
}
