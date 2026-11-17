//! checkpoints.builder.Env over the exec store (sui-core CheckpointBuilder's reads of the
//! execution side):
//!   key_digest, effects, tx_class   the exec store (`tx_key_to_digest`, executed effects, kinds)
//!   user_signatures                 the authority's recorded signatures (`SigSource`); a system
//!                                   transaction carries the all-zero signature
//!   settlement_effects              `resolve_settlement_effects`: the accumulator settlement
//!                                   transactions (AccumulatorSettlementTxBuilder over the sorted
//!                                   root effects) and the barrier, executed here when they have
//!                                   not run (the role of sui-core's SettlementScheduler) and
//!                                   stored under the settlement key
//!   advance_epoch                   `create_and_execute_advance_epoch_tx`: the
//!                                   EndOfEpochTransaction (epoch/endofepoch.zig) executed through
//!                                   exec.system, idempotent, with the next committee read from
//!                                   the new system state
//! Event-stream accumulators (`EventDigest` values) and IntegerTuple balances are not built
//! (`error.Fatal`): Rust's merkle root of event commitments is not ported.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const exec = @import("exec");
const checkpoint = @import("checkpoint");
const builder = @import("../checkpoints/builder.zig");
const create = @import("../checkpoints/create.zig");
const iface = @import("../iface.zig");
const state_mod = @import("../authority/state.zig");
const endofepoch = @import("../epoch/endofepoch.zig");
const reconfig = @import("../epoch/reconfig.zig");
const packages = @import("../epoch/packages.zig");
const state_update = @import("../randomness/state_update.zig");
const store_mod = @import("exec_store.zig");
const runner_mod = @import("runner.zig");
const objects = @import("objects.zig");
const congestion = @import("../authority/congestion.zig");

const Allocator = std.mem.Allocator;
const ExecStore = store_mod.ExecStore;
const Runner = runner_mod.Runner;
const Id = [32]u8;
const objectId = runner_mod.objectId;
const acc_root_id = runner_mod.acc_root_id;
const system_state_id = objectId(5);
const framework = objectId(2);

/// The user signatures the authority recorded for a transaction (null for a system transaction).
pub const SigSource = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, arena: Allocator, digest: *const Id) ?state_mod.UserSigs,

    /// Reads `EpochState.sigs` directly: the caller serializes with the handler (its lock).
    pub fn fromEpochState(st: *state_mod.EpochState) SigSource {
        return .{ .ctx = st, .get = epochStateGet };
    }
    fn epochStateGet(ctx: *anyopaque, arena: Allocator, digest: *const Id) ?state_mod.UserSigs {
        _ = arena;
        const st: *state_mod.EpochState = @ptrCast(@alignCast(ctx));
        return st.sigs.get(digest.*);
    }
};

/// What the end of epoch needs beyond the store.
pub const AdvanceHooks = struct {
    /// The protocol-version vote at the end of the epoch
    /// (`choose_protocol_version_and_system_packages_v2` over the epoch's stored capabilities);
    /// null keeps the current version with no package upgrade.
    vote: ?struct { ctx: *anyopaque, f: *const fn (ctx: *anyopaque, arena: Allocator) anyerror!reconfig.Chosen } = null,
    /// This binary's built-in framework (`packages.builtIn`): the bytes of a winning vote's
    /// packages come from it (`get_system_package_bytes`).
    builtin: []const packages.Package = &.{},
    /// The estimator's observations at the final round, key sorted (`take_observations`,
    /// ExecutionTimeEstimate congestion mode); `advance` keeps the keys of the observation window
    /// (`filter_and_sort_v1`). The hook returning null is an error; no hook: an empty V1 list.
    observations: ?struct { ctx: *anyopaque, f: *const fn (ctx: *anyopaque, arena: Allocator) ?types.StoredExecutionTimeObservations } = null,
};

pub const CkptEnv = struct {
    runner: *Runner,
    sigs: ?SigSource = null,
    hooks: AdvanceHooks = .{},

    fn store(e: *CkptEnv) *ExecStore {
        return e.runner.store;
    }

    pub fn env(e: *CkptEnv) builder.Env {
        return .{ .ctx = e, .vtable = &vtable };
    }
    const vtable: builder.Env.VTable = .{
        .key_digest = keyDigest,
        .effects = effectsFn,
        .tx_class = txClass,
        .user_signatures = userSigs,
        .settlement_effects = settlementFn,
        .advance_epoch = advanceFn,
    };
    fn of(ctx: *anyopaque) *CkptEnv {
        return @ptrCast(@alignCast(ctx));
    }

    fn keyDigest(ctx: *anyopaque, key: *const iface.TransactionKey) ?Id {
        return of(ctx).store().keyDigest(fromIfaceKey(key.*));
    }

    fn effectsFn(ctx: *anyopaque, arena: Allocator, digest: *const Id) builder.Env.Err!?[]const u8 {
        _ = arena;
        return of(ctx).store().effects(digest);
    }

    fn txClass(ctx: *anyopaque, digest: *const Id) ?builder.TxClass {
        const e = of(ctx);
        const td_bcs = e.store().txData(digest) orelse return null;
        var arena = std.heap.ArenaAllocator.init(e.runner.gpa);
        defer arena.deinit();
        const td = bcs.decode(types.TransactionData, arena.allocator(), td_bcs) catch return .forbidden;
        return switch (td.V1.kind) {
            .ConsensusCommitPrologue, .ConsensusCommitPrologueV2, .ConsensusCommitPrologueV3, .ConsensusCommitPrologueV4 => .consensus_commit_prologue,
            .AuthenticatorStateUpdate => .authenticator_state_update,
            .RandomnessStateUpdate => |u| .{ .randomness_state_update = u.randomness_round.@"0" },
            .ProgrammableSystemTransaction => .programmable_system,
            .ProgrammableTransaction => .programmable,
            else => .forbidden,
        };
    }

    fn userSigs(ctx: *anyopaque, arena: Allocator, digest: *const Id) builder.Env.Err![]const create.SigEntry {
        const e = of(ctx);
        if (e.sigs) |src| if (src.get(src.ctx, arena, digest)) |u| {
            const out = try arena.alloc(create.SigEntry, u.sigs.len);
            for (out, u.sigs, 0..) |*o, s, i| o.* = .{ .{ .@"0" = s }, if (i < u.alias_versions.len) if (u.alias_versions[i]) |v| types.SequenceNumber{ .@"0" = v } else null else null };
            return out;
        };
        // a system transaction: one all-zero Ed25519 signature, no alias version
        const zero = try arena.alloc(u8, 97);
        @memset(zero, 0);
        const out = try arena.alloc(create.SigEntry, 1);
        out[0] = .{ .{ .@"0" = zero }, null };
        return out;
    }

    // ------------------------------------------------------------------ settlement

    fn settlementFn(ctx: *anyopaque, arena: Allocator, req: *const builder.SettlementRequest) builder.Env.Err!?[]const []const u8 {
        return of(ctx).settlement(arena, req) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.NotReady => null,
            else => blk: {
                std.log.err("settlement at height {d}: {s} ({s})", .{ req.height, @errorName(err), of(ctx).runner.lastError() });
                break :blk error.Fatal;
            },
        };
    }

    /// `resolve_settlement_effects` + the SettlementScheduler: settlement transactions and the
    /// barrier for one root group, executed when they have not run yet.
    pub fn settlement(e: *CkptEnv, arena: Allocator, req: *const builder.SettlementRequest) ![]const []const u8 {
        const st = e.store();
        const rctx = &e.runner.ctx;
        const key = fromIfaceKey(req.key);
        const sk = switch (key) {
            .accumulator_settlement => |x| x,
            else => return error.BadKey,
        };
        const root_raw = st.latest(&acc_root_id) orelse return error.NoAccumulatorRoot;
        const isv = objects.startVersion(root_raw) orelse return error.NoAccumulatorRoot;
        const root_version = (try exec.objects.ObjectView.parse(root_raw)).version;

        var effects: std.ArrayList([]const u8) = .empty;
        if (st.keyDigest(key)) |barrier| {
            // already settled: rebuild the digests from the stored settlement transactions
            const built = try buildSettlements(arena, rctx.cfg, st, req, sk.epoch, isv);
            for (built) |b| try effects.append(arena, st.effects(&b.digest) orelse return error.Missing);
            try effects.append(arena, st.effects(&barrier) orelse return error.Missing);
            return effects.items;
        }
        const pins = [_]objects.Pin{.{ .id = acc_root_id, .version = root_version }};
        const built = try buildSettlements(arena, rctx.cfg, st, req, sk.epoch, isv);
        var views: std.ArrayList(types.TransactionEffectsV2) = .empty;
        for (built) |b| {
            const ex = try e.runner.runSystem(arena, b.data, b.digest, &b.td, &pins, &.{});
            try effects.append(arena, ex.effects_bcs);
            try views.append(arena, (try bcs.decode(types.TransactionEffects, arena, ex.effects_bcs)).V2);
        }
        const barrier = try barrierTx(arena, sk.epoch, isv, sk.height, views.items);
        const ex = try e.runner.runSystem(arena, barrier.data, barrier.digest, &barrier.td, &pins, &.{key});
        try effects.append(arena, ex.effects_bcs);
        for (effects.items) |raw| {
            const fx = try bcs.decode(types.TransactionEffects, arena, raw);
            if (fx.V2.status != .Success) return error.SettlementFailed; // Rust asserts
        }
        return effects.items;
    }

    // ------------------------------------------------------------------ end of epoch

    fn advanceFn(ctx: *anyopaque, arena: Allocator, req: *const builder.AdvanceRequest) builder.Env.Err!?builder.EpochAdvance {
        return of(ctx).advance(arena, req) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            // Rust: CheckpointBuilderError::SystemPackagesMissing, the builder retries until this
            // binary has the packages or the certified checkpoint arrives from peers
            error.SystemPackagesMissing => blk: {
                std.log.err("advance epoch: the winning vote's system packages are not in this binary; waiting", .{});
                break :blk null;
            },
            else => blk: {
                std.log.err("advance epoch: {s} ({s})", .{ @errorName(err), of(ctx).runner.lastError() });
                break :blk error.Fatal;
            },
        };
    }

    /// `ExecutionTimeObservationKey::from_command` of every command of the programmable
    /// transactions among `lists` (canonical key bytes).
    fn observedKeys(arena: Allocator, st: *ExecStore, lists: []const []const [32]u8) !std.StringHashMapUnmanaged(void) {
        var keys: std.StringHashMapUnmanaged(void) = .empty;
        for (lists) |list| for (list) |*d| {
            const ex = st.executed(d) orelse return error.Missing;
            const td = (try bcs.decode(types.TransactionData, arena, ex.td_bcs)).V1;
            switch (td.kind) {
                .ProgrammableTransaction => |pt| for (pt.commands) |*c| try keys.put(arena, try congestion.keyOfCommand(arena, c), {}),
                else => {},
            }
        };
        return keys;
    }

    /// The local key the advance-epoch transaction of `epoch` is stored under (no TransactionKey
    /// names it in sui-core; this one never leaves the exec store).
    pub fn advanceKey(epoch: u64) store_mod.Key {
        return .{ .accumulator_settlement = .{ .epoch = epoch, .height = std.math.maxInt(u64) } };
    }

    pub fn advance(e: *CkptEnv, arena: Allocator, req: *const builder.AdvanceRequest) !builder.EpochAdvance {
        const st = e.store();
        const rctx = &e.runner.ctx;
        const cfg = rctx.cfg;
        const key = advanceKey(rctx.epoch);
        var digest: Id = undefined;
        if (st.keyDigest(key)) |d| {
            digest = d;
        } else {
            const facts = try factsOf(arena, st, rctx);
            const chosen: reconfig.Chosen = if (e.hooks.vote) |v| try v.f(v.ctx, arena) else .{ .protocol_version = cfg.version, .packages = &.{} };
            var bytes: packages.BytesSource = .{ .builtin = e.hooks.builtin, .src = objectSource(st) };
            var f2 = facts;
            if (cfg.feature_flags.per_object_congestion_control_mode == .ExecutionTimeEstimate) {
                f2.execution_time_observations = if (e.hooks.observations) |o| blk: {
                    const all = o.f(o.ctx, arena) orelse return error.MissingExecutionTimeObservations;
                    const params = cfg.feature_flags.per_object_congestion_control_mode.ExecutionTimeEstimate;
                    const included = try observedKeys(arena, st, &.{ req.window_tx_digests, req.tx_digests });
                    break :blk try congestion.filterStored(arena, all, &included, std.math.cast(usize, params.stored_observations_limit) orelse std.math.maxInt(usize));
                } else .{ .V1 = &.{} };
            }
            const built = try endofepoch.build(arena, cfg, f2, .{
                .current_epoch = rctx.epoch,
                .epoch_start_timestamp_ms = req.epoch_start_timestamp_ms,
                .gas = .{ .computation_cost = req.gas.computation_cost, .storage_cost = req.gas.storage_cost, .storage_rebate = req.gas.storage_rebate, .non_refundable_storage_fee = req.gas.non_refundable_storage_fee },
                .chosen = chosen,
            }, bytes.source());
            // shared inputs at their live versions: every transaction of the epoch ran before
            var pins: std.ArrayList(objects.Pin) = .empty;
            for ([_]Id{ system_state_id, runner_mod.authenticator_id, objectId(9) }) |id| {
                const raw = st.latest(&id) orelse continue;
                try pins.append(arena, .{ .id = id, .version = (try exec.objects.ObjectView.parse(raw)).version });
            }
            const td = (try bcs.decode(types.TransactionData, arena, built.data_bcs)).V1;
            const ex = try e.runner.runSystem(arena, built.data_bcs, built.digest, &td, pins.items, &.{key});
            const fx = try bcs.decode(types.TransactionEffects, arena, ex.effects_bcs);
            if (fx.V2.status != .Success) return error.AdvanceEpochFailed; // Rust: safe mode, not modeled
            digest = built.digest;
        }
        const ex = st.executed(&digest) orelse return error.Missing;
        const td = (try bcs.decode(types.TransactionData, arena, ex.td_bcs)).V1;
        const next_pv: u64 = switch (td.kind) {
            .EndOfEpochTransaction => |kinds| kinds[kinds.len - 1].ChangeEpoch.protocol_version.@"0",
            .ChangeEpoch => |ce| ce.protocol_version.@"0",
            else => return error.Missing,
        };
        return .{ .effects = ex.effects_bcs, .next_committee = try committeeOf(arena, st), .next_protocol_version = next_pv };
    }
};

/// `packages.Source` over the exec store (live objects and objects by version).
pub fn objectSource(st: *ExecStore) packages.Source {
    const S = struct {
        fn latest(ctx: *anyopaque, id: *const Id) ?[]const u8 {
            const s: *ExecStore = @ptrCast(@alignCast(ctx));
            return s.latest(id);
        }
        fn at(ctx: *anyopaque, id: *const Id, version: u64) ?[]const u8 {
            const s: *ExecStore = @ptrCast(@alignCast(ctx));
            return s.objectAt(id, version);
        }
    };
    return .{ .ctx = st, .latest = S.latest, .at = S.at };
}

pub fn fromIfaceKey(k: iface.TransactionKey) store_mod.Key {
    return switch (k) {
        .digest => |d| .{ .digest = d.@"0".@"0" },
        .randomness_round => |x| .{ .randomness_round = .{ .epoch = x.epoch, .round = x.round } },
        .accumulator_settlement => |x| .{ .accumulator_settlement = .{ .epoch = x.epoch, .height = x.height } },
        .consensus_commit_prologue => |x| .{ .consensus_commit_prologue = .{ .epoch = x.epoch, .round = x.round, .sub_dag_index = x.sub_dag_index } },
    };
}

/// `epoch_store.*_exists()` and the accumulator object count, from the live objects (the
/// system objects only change at epoch boundaries, so the live state is the epoch start's).
pub fn factsOf(arena: Allocator, st: *ExecStore, rctx: *const runner_mod.EpochCtx) !endofepoch.Facts {
    _ = arena;
    var f: endofepoch.Facts = .{ .chain_identifier = rctx.chain_id };
    if (st.latest(&runner_mod.authenticator_id)) |raw| {
        f.authenticator_state_exists = true;
        f.authenticator_obj_initial_shared_version = objects.startVersion(raw);
    }
    f.randomness_state_exists = st.latest(&runner_mod.randomness_id) != null;
    if (st.latest(&objectId(9))) |raw| {
        f.bridge_exists = true;
        f.bridge_obj_initial_shared_version = objects.startVersion(raw);
        f.bridge_committee_initiated = bridgeCommitteeInitiated(raw, objectSource(st));
    }
    f.coin_deny_list_state_exists = st.latest(&objectId(0x403)) != null;
    f.accumulator_root_exists = st.latest(&acc_root_id) != null;
    f.coin_registry_exists = st.latest(&objectId(0xc)) != null;
    f.display_registry_exists = st.latest(&objectId(0xd)) != null;
    f.address_alias_state_exists = st.latest(&objectId(0xa)) != null;
    f.forwarding_address_registry_exists = st.latest(&objectId(0xfa)) != null;
    if (f.accumulator_root_exists) {
        const id = accumulatorCountId();
        if (st.latest(&id)) |raw| {
            const v = try exec.objects.ObjectView.parse(raw);
            const c = v.contents();
            if (c.len >= 41) f.accumulator_object_count = std.mem.readInt(u64, c[33..41], .little);
        }
    }
    return f;
}

/// sui-types bridge.rs `is_bridge_committee_initiated` (read by sui-core at epoch start,
/// epoch_start_configuration.rs; the members only change in the end-of-epoch BridgeCommitteeInit,
/// so the live state before this epoch's advance is the epoch start's): `get_bridge` reads the
/// `BridgeWrapper` { id, version: Versioned { id, version } } of 0x9 and, at version 1, the
/// `Field<u64, BridgeInnerV1>` under the Versioned id; initiated when the inner
/// `committee.members` VecMap is non-empty. Every read error (`SuiBridgeReadError`: no wrapper,
/// a wrapper of another length, another version, no inner field, short bytes) is false. The
/// inner state is read up to the members count (BridgeInnerV1: bridge_version u64,
/// message_version u8, chain_id u8, sequence_nums VecMap<u8, u64>, committee { members, .. }).
pub fn bridgeCommitteeInitiated(wrapper_raw: []const u8, src: packages.Source) bool {
    const wv = exec.objects.ObjectView.parse(wrapper_raw) catch return false;
    const wc = wv.contents();
    if (wv.is_package or wc.len != 32 + 32 + 8) return false;
    const inner_uid = wc[32..64];
    const version = std.mem.readInt(u64, wc[64..72], .little);
    if (version != 1) return false;
    var k: [8]u8 = undefined;
    std.mem.writeInt(u64, &k, version, .little);
    var klen: [8]u8 = undefined;
    std.mem.writeInt(u64, &klen, 8, .little);
    const field_id = hash.blake2b256(&.{ &[_]u8{0xf0}, inner_uid, &klen, &k, &[_]u8{2} }); // TypeTag::U64
    const raw = src.latest(src.ctx, &field_id) orelse return false;
    const fv = exec.objects.ObjectView.parse(raw) catch return false;
    if (fv.is_package) return false;
    const c = fv.contents();
    // Field { id: UID, name: u64, value: BridgeInnerV1 }
    var at: usize = 32 + 8 + 8 + 1 + 1;
    const n_seq = uleb(c, &at) orelse return false;
    at = std.math.add(usize, at, std.math.mul(usize, n_seq, 9) catch return false) catch return false;
    const members = uleb(c, &at) orelse return false;
    return members != 0;
}

fn uleb(b: []const u8, at: *usize) ?usize {
    var v: u64 = 0;
    var shift: u6 = 0;
    while (at.* < b.len) {
        const byte = b[at.*];
        at.* += 1;
        v |= @as(u64, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) return std.math.cast(usize, v);
        if (shift >= 56) return null;
        shift += 7;
    }
    return null;
}

/// `DynamicFieldKey(0xacc, AccumulatorObjectCountKey(0), ..)`: Field<AccumulatorObjectCountKey, u64>.
pub fn accumulatorCountId() Id {
    const key_type = [_]u8{7} ++ framework ++ [_]u8{20} ++ "accumulator_metadata".* ++ [_]u8{25} ++ "AccumulatorObjectCountKey".* ++ [_]u8{0};
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, 1, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, &acc_root_id, &len_le, &[_]u8{0}, &key_type });
}

/// The committee of the system state in the store (`get_current_epoch_committee`), sorted by name.
pub fn committeeOf(arena: Allocator, st: *ExecStore) ![]const create.CommitteeEntry {
    const wrapper = st.latest(&system_state_id) orelse return error.NoSystemState;
    const wv = try exec.objects.ObjectView.parse(wrapper);
    const wc = wv.contents();
    if (wc.len < 40) return error.NoSystemState;
    const version = std.mem.readInt(u64, wc[32..40], .little);
    var k: [8]u8 = undefined;
    std.mem.writeInt(u64, &k, version, .little);
    var klen: [8]u8 = undefined;
    std.mem.writeInt(u64, &klen, 8, .little);
    const field = hash.blake2b256(&.{ &[_]u8{0xf0}, &system_state_id, &klen, &k, &[_]u8{2} });
    const inner = st.latest(&field) orelse return error.NoSystemState;
    const iv = try exec.objects.ObjectView.parse(inner);
    const members = try checkpoint.genesis.readValidators(arena, iv.contents());
    const out = try arena.alloc(create.CommitteeEntry, members.len);
    for (members, out) |m, *o| o.* = .{ .name = m.name, .stake = m.stake };
    std.mem.sort(create.CommitteeEntry, out, {}, struct {
        fn lt(_: void, a: create.CommitteeEntry, b: create.CommitteeEntry) bool {
            return std.mem.lessThan(u8, &a.name, &b.name);
        }
    }.lt);
    return out;
}

// ---------------------------------------------------------------------- settlement transactions

pub const BuiltTx = struct { td: types.TransactionDataV1, data: []const u8, digest: Id };

fn finishSystem(arena: Allocator, pt: types.ProgrammableTransaction) !BuiltTx {
    const td = state_update.systemTransactionData(.{ .ProgrammableSystemTransaction = pt });
    const data = try bcs.encodeAlloc(types.TransactionData, arena, &td);
    return .{ .td = td.V1, .data = data, .digest = types.digest.transactionDataDigest(data) };
}

/// sui-types ProgrammableTransactionBuilder: identical pure inputs and the same object share one
/// input (`IndexMap` keyed by the bytes or the object id).
pub const PtBuilder = struct {
    a: Allocator,
    inputs: std.ArrayList(types.CallArg) = .empty,
    commands: std.ArrayList(types.Command) = .empty,

    pub fn pureBytes(b: *PtBuilder, bytes: []const u8) !types.Argument {
        for (b.inputs.items, 0..) |in, i| switch (in) {
            .Pure => |p| if (std.mem.eql(u8, p, bytes)) return .{ .Input = @intCast(i) },
            else => {},
        };
        try b.inputs.append(b.a, .{ .Pure = try b.a.dupe(u8, bytes) });
        return .{ .Input = @intCast(b.inputs.items.len - 1) };
    }
    pub fn pure(b: *PtBuilder, comptime T: type, v: T) !types.Argument {
        return b.pureBytes(try bcs.encodeAlloc(T, b.a, &v));
    }
    pub fn shared(b: *PtBuilder, id: Id, isv: u64, mutability: types.SharedObjectMutability) !types.Argument {
        for (b.inputs.items, 0..) |in, i| switch (in) {
            .Object => |o| switch (o) {
                .SharedObject => |s| if (std.mem.eql(u8, &s.id.@"0".@"0", &id)) {
                    // IndexMap::insert_full replaces the value under the same key
                    b.inputs.items[i] = .{ .Object = .{ .SharedObject = .{ .id = .{ .@"0" = .{ .@"0" = id } }, .initial_shared_version = .{ .@"0" = isv }, .mutability = mutability } } };
                    return .{ .Input = @intCast(i) };
                },
                else => {},
            },
            else => {},
        };
        try b.inputs.append(b.a, .{ .Object = .{ .SharedObject = .{ .id = .{ .@"0" = .{ .@"0" = id } }, .initial_shared_version = .{ .@"0" = isv }, .mutability = mutability } } });
        return .{ .Input = @intCast(b.inputs.items.len - 1) };
    }
    pub fn call(b: *PtBuilder, module: []const u8, function: []const u8, ty: []const types.TypeInput, args: []const types.Argument) !void {
        try b.commands.append(b.a, .{ .MoveCall = .{
            .package = .{ .@"0" = .{ .@"0" = framework } },
            .module = .{ .@"0" = module },
            .function = .{ .@"0" = function },
            .type_arguments = try b.a.dupe(types.TypeInput, ty),
            .arguments = try b.a.dupe(types.Argument, args),
        } });
    }
    pub fn finish(b: *const PtBuilder) types.ProgrammableTransaction {
        return .{ .inputs = b.inputs.items, .commands = b.commands.items };
    }
};

fn addPrologue(b: *PtBuilder, root: types.Argument, epoch: u64, height: u64, idx: u64, input_sui: u64, output_sui: u64) !void {
    const e = try b.pure(u64, epoch);
    const h = try b.pure(u64, height);
    const i = try b.pure(u64, idx);
    const in = try b.pure(u64, input_sui);
    const out = try b.pure(u64, output_sui);
    try b.call("accumulator_settlement", "settlement_prologue", &.{}, &.{ root, e, h, i, in, out });
}

const Update = struct {
    id: Id,
    address: types.AccumulatorAddress,
    /// `MergedValueIntermediate`: SumU128 (`merge`, `split`) or Events (the commitments' merkle
    /// leaves, in order).
    events: bool = false,
    merge: u128 = 0,
    split: u128 = 0,
    merge_leaves: std.ArrayList([32]u8) = .empty,
    split_leaves: std.ArrayList([32]u8) = .empty,
    input_sui: u64 = 0,
    output_sui: u64 = 0,
};

/// The merkle leaf of `EventCommitment { checkpoint_seq, transaction_idx, event_idx, digest }`:
/// Blake2b-256 of 0x00 then its BCS (fastcrypto `MerkleTree::build_from_unserialized`).
pub fn eventLeaf(checkpoint_seq: u64, transaction_idx: u64, event_idx: u64, digest: *const [32]u8) [32]u8 {
    var b: [1 + 24 + 1 + 32]u8 = undefined;
    b[0] = 0;
    std.mem.writeInt(u64, b[1..9], checkpoint_seq, .little);
    std.mem.writeInt(u64, b[9..17], transaction_idx, .little);
    std.mem.writeInt(u64, b[17..25], event_idx, .little);
    b[25] = 32;
    @memcpy(b[26..58], digest);
    return hash.blake2b256(&.{&b});
}

/// `build_event_merkle_root`: fastcrypto's MerkleTree root over the leaves. Each level pairs
/// nodes as Blake2b-256(0x01 || left || right), an odd level gets an all-zero sibling; no
/// leaves is the all-zero node. Overwrites `leaves`.
pub fn eventMerkleRoot(leaves: [][32]u8) [32]u8 {
    if (leaves.len == 0) return @splat(0);
    var n = leaves.len;
    const zero: [32]u8 = @splat(0);
    while (n > 1) {
        var i: usize = 0;
        while (i < n) : (i += 2) {
            const r: *const [32]u8 = if (i + 1 < n) &leaves[i + 1] else &zero;
            leaves[i / 2] = hash.blake2b256(&.{ &[_]u8{1}, &leaves[i], r });
        }
        n = (n + 1) / 2;
    }
    return leaves[0];
}

fn isFramework(a: *const [32]u8) bool {
    return std.mem.eql(u8, a, &framework);
}

/// `Balance<T>` (ClassifiedType::Balance).
fn isBalance(t: *const types.TypeTag) bool {
    return switch (t.*) {
        .@"struct" => |s| isFramework(&s.address.@"0") and std.mem.eql(u8, s.module.@"0", "balance") and std.mem.eql(u8, s.name.@"0", "Balance"),
        else => false,
    };
}

/// `GasCoin::is_gas_balance`: `Balance<0x2::sui::SUI>`.
fn isGasBalance(t: *const types.TypeTag) bool {
    if (!isBalance(t)) return false;
    const args = t.@"struct".type_args;
    if (args.len != 1) return false;
    return switch (args[0]) {
        .@"struct" => |s| isFramework(&s.address.@"0") and std.mem.eql(u8, s.module.@"0", "sui") and std.mem.eql(u8, s.name.@"0", "SUI") and s.type_args.len == 0,
        else => false,
    };
}

/// One update of `build_tx`: the address input is added first, then an update whose merges and
/// splits cancel is skipped (its address stays an input of the transaction, as in Rust).
fn addSettle(b: *PtBuilder, root: types.Argument, u: *const Update, checkpoint_seq: u64) !void {
    const addr = try b.pure([32]u8, u.address.address.@"0");
    if (u.events) {
        // settle_events(root, stream, new_root: u256 (the merkle root's bytes, little-endian),
        // event_count_delta, checkpoint_seq)
        const leaves = try b.a.dupe([32]u8, u.merge_leaves.items);
        const mroot = try b.pure([32]u8, eventMerkleRoot(leaves));
        const count = try b.pure(u64, u.merge_leaves.items.len);
        const seq = try b.pure(u64, checkpoint_seq);
        try b.call("accumulator_settlement", "settle_events", &.{}, &.{ root, addr, mroot, count, seq });
        return;
    }
    const merge = if (u.merge >= u.split) u.merge - u.split else 0;
    const split = if (u.merge >= u.split) 0 else u.split - u.merge;
    if (merge == 0 and split == 0) return;
    const m = try b.pure(u128, merge);
    const s = try b.pure(u128, split);
    const ty_bytes = try bcs.encodeAlloc(types.TypeTag, b.a, &u.address.ty);
    const ty = try bcs.decode(types.TypeInput, b.a, ty_bytes);
    try b.call("accumulator_settlement", "settle_u128", &.{ty}, &.{ root, addr, m, s });
}

/// AccumulatorSettlementTxBuilder::new + build_tx over the effects of `req.sorted_root_digests`.
pub fn accRootId() Id {
    return acc_root_id;
}

/// What `AccumulatorSettlementTxBuilder::new` + `build_tx` take besides the effects.
pub const SettleParams = struct {
    epoch: u64,
    /// The accumulator root's initial shared version.
    isv: u64,
    checkpoint_height: u64,
    checkpoint_seq: u64,
    tx_index_offset: u64,
    max_updates_per_settlement_txn: ?u32,
};

/// AccumulatorSettlementTxBuilder::new + build_tx over the effects of `req.sorted_root_digests`.
pub fn buildSettlements(arena: Allocator, cfg: anytype, st: *ExecStore, req: *const builder.SettlementRequest, epoch: u64, isv: u64) ![]const BuiltTx {
    const fxs = try arena.alloc(types.TransactionEffectsV2, req.sorted_root_digests.len);
    for (req.sorted_root_digests, fxs) |*d, *fx| {
        const raw = st.effects(d) orelse return error.NotReady;
        fx.* = (try bcs.decode(types.TransactionEffects, arena, raw)).V2;
    }
    return buildSettlementsOf(arena, fxs, .{
        .epoch = epoch,
        .isv = isv,
        .checkpoint_height = req.height,
        .checkpoint_seq = req.seq,
        .tx_index_offset = req.tx_index_offset,
        .max_updates_per_settlement_txn = cfg.max_updates_per_settlement_txn,
    });
}

/// `AccumulatorSettlementTxBuilder::new(None, effects, checkpoint_seq, tx_index_offset)` then
/// `build_tx(cfg, epoch, isv, checkpoint_height, checkpoint_seq)`.
pub fn buildSettlementsOf(arena: Allocator, effects: []const types.TransactionEffectsV2, p: SettleParams) ![]const BuiltTx {
    var updates: std.AutoArrayHashMapUnmanaged(Id, Update) = .empty;
    for (effects, 0..) |*fx, tx_index| {
        for (fx.changed_objects) |c| switch (c[1].output_state) {
            .AccumulatorWriteV1 => |w| {
                const id = c[0].@"0".@"0";
                const gop = try updates.getOrPut(arena, id);
                if (!gop.found_existing) gop.value_ptr.* = .{ .id = id, .address = w.address, .events = w.value == .EventDigest };
                const u = gop.value_ptr;
                if (u.events != (w.value == .EventDigest)) return error.UnsupportedAccumulatorValue; // Rust: fatal
                const v: u64 = switch (w.value) {
                    .Integer => |x| x,
                    // SumU128U128 is todo!() in Rust
                    .IntegerTuple => return error.UnsupportedAccumulatorValue,
                    .EventDigest => |evs| {
                        const leaves = if (w.operation == .Merge) &u.merge_leaves else &u.split_leaves;
                        for (evs) |e| try leaves.append(arena, eventLeaf(p.checkpoint_seq, tx_index + p.tx_index_offset, e.@"0", &e.@"1".@"0"));
                        continue;
                    },
                };
                if (!isBalance(&w.address.ty)) return error.UnsupportedAccumulatorValue; // Rust: fatal
                const sui: u64 = if (isGasBalance(&w.address.ty)) v else 0;
                switch (w.operation) {
                    .Merge => {
                        u.merge += v;
                        u.input_sui += sui; // the event's output is the settlement's input
                    },
                    .Split => {
                        u.split += v;
                        u.output_sui += sui;
                    },
                }
            },
            else => {},
        };
    }
    // BTreeMap order
    const ids = try arena.alloc(Id, updates.count());
    @memcpy(ids, updates.keys());
    std.mem.sort(Id, ids, {}, struct {
        fn lt(_: void, a: Id, b: Id) bool {
            return std.mem.lessThan(u8, &a, &b);
        }
    }.lt);
    const chunk: usize = if (p.max_updates_per_settlement_txn) |m| @max(m, 1) else std.math.maxInt(u32);
    var out: std.ArrayList(BuiltTx) = .empty;
    var i: usize = 0;
    var idx: u64 = 0;
    while (i < ids.len) : (idx += 1) {
        const end = @min(i + chunk, ids.len);
        var b: PtBuilder = .{ .a = arena };
        const root = try b.shared(acc_root_id, p.isv, .NonExclusiveWrite);
        var tin: u64 = 0;
        var tout: u64 = 0;
        for (ids[i..end]) |id| {
            const u = updates.get(id).?;
            tin += u.input_sui;
            tout += u.output_sui;
        }
        try addPrologue(&b, root, p.epoch, p.checkpoint_height, idx, tin, tout);
        for (ids[i..end]) |id| try addSettle(&b, root, &updates.get(id).?, p.checkpoint_seq);
        try out.append(arena, try finishSystem(arena, b.finish()));
        i = end;
    }
    return out.items;
}

/// `build_accumulator_barrier_tx`.
pub fn barrierTx(arena: Allocator, epoch: u64, isv: u64, height: u64, settlement_effects: []const types.TransactionEffectsV2) !BuiltTx {
    var created: u64 = 0;
    var destroyed: u64 = 0;
    for (settlement_effects) |fx| for (fx.changed_objects) |c| switch (c[1].id_operation) {
        .Created => created += 1,
        .Deleted => destroyed += 1,
        .None => {},
    };
    var b: PtBuilder = .{ .a = arena };
    const root = try b.shared(acc_root_id, isv, .Mutable);
    try addPrologue(&b, root, epoch, height, settlement_effects.len, 0, 0);
    const c = try b.pure(u64, created);
    const d = try b.pure(u64, destroyed);
    try b.call("accumulator_metadata", "record_accumulator_object_changes", &.{}, &.{ root, c, d });
    return finishSystem(arena, b.finish());
}

// ---------------------------------------------------------------------- tests

const testing = std.testing;

test "ckpt env: the barrier transaction shares identical pure inputs" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // epoch 0, height 0, no settlements: every u64 argument is 0 and shares one input
    const t = try barrierTx(a, 0, 1, 0, &.{});
    const pt = t.td.kind.ProgrammableSystemTransaction;
    try testing.expectEqual(@as(usize, 2), pt.inputs.len);
    try testing.expectEqual(@as(usize, 2), pt.commands.len);
    try testing.expectEqual(types.SharedObjectMutability.Mutable, pt.inputs[0].Object.SharedObject.mutability);
    // epoch 3, height 7: inputs root, 3, 7, 0
    const t2 = try barrierTx(a, 3, 1, 7, &.{});
    try testing.expectEqual(@as(usize, 4), t2.td.kind.ProgrammableSystemTransaction.inputs.len);
    try testing.expectEqual(@as(u64, 1), t2.td.gas_data.price);
}

test "ckpt env: accumulator count field id and key conversion" {
    const id = accumulatorCountId();
    try testing.expect(!std.mem.eql(u8, &id, &acc_root_id));
    const k = fromIfaceKey(.{ .accumulator_settlement = .{ .epoch = 2, .height = 9 } });
    try testing.expectEqual(@as(u64, 9), k.accumulator_settlement.height);
}

test "ckpt env: a settlement update that cancels out keeps its address input" {
    // sui-node's settlement at height 58 of a mixed localnet: a MERGE 0 for 0x24d0.. then SPLIT
    // 1000 for 0xd0cc.. and 0x43b1..: inputs root, prologue args, 0x24d0, 0xd0cc, 0u128,
    // 1000u128, 0x43b1, and two settle_u128 calls
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const sui_args = try a.alloc(types.TypeTag, 1);
    sui_args[0] = .{ .@"struct" = .{ .address = .{ .@"0" = framework }, .module = .{ .@"0" = "sui" }, .name = .{ .@"0" = "SUI" }, .type_args = &.{} } };
    const bal: types.TypeTag = .{ .@"struct" = .{ .address = .{ .@"0" = framework }, .module = .{ .@"0" = "balance" }, .name = .{ .@"0" = "Balance" }, .type_args = sui_args } };
    const owners = [_]Id{ @splat(0x24), @splat(0xd0), @splat(0x43) };
    const ups = [_]Update{
        .{ .id = @splat(1), .address = .{ .address = .{ .@"0" = owners[0] }, .ty = bal }, .merge = 0 },
        .{ .id = @splat(2), .address = .{ .address = .{ .@"0" = owners[1] }, .ty = bal }, .split = 1000 },
        .{ .id = @splat(3), .address = .{ .address = .{ .@"0" = owners[2] }, .ty = bal }, .split = 1000 },
    };
    var b: PtBuilder = .{ .a = a };
    const root = try b.shared(acc_root_id, 1, .NonExclusiveWrite);
    try addPrologue(&b, root, 1, 58, 0, 0, 2000);
    for (&ups) |*u| try addSettle(&b, root, u, 0);
    const pt = b.finish();
    // root, 1, 58, 0, 2000, then 0x24.., 0xd0.., 0u128, 1000u128, 0x43..
    try testing.expectEqual(@as(usize, 10), pt.inputs.len);
    try testing.expectEqualSlices(u8, &owners[0], pt.inputs[5].Pure);
    try testing.expectEqualSlices(u8, &owners[1], pt.inputs[6].Pure);
    try testing.expectEqualSlices(u8, &owners[2], pt.inputs[9].Pure);
    try testing.expectEqual(@as(usize, 3), pt.commands.len);
}

test "ckpt env: bridge committee initiated equals Rust's is_bridge_committee_initiated" {
    // tools/truth/validator-epoch `upgrade` (1.84) over the mainnet bridge 0x9 and its inner
    // Field<u64, BridgeInnerV1> (epoch 1313), the same with no members, and partial stores
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const Objs = struct {
        list: []const []const u8,
        fn latest(ctx: *anyopaque, id: *const Id) ?[]const u8 {
            const o: *@This() = @ptrCast(@alignCast(ctx));
            for (o.list) |raw| {
                const v = exec.objects.ObjectView.parse(raw) catch continue;
                if (std.mem.eql(u8, &v.id, id)) return raw;
            }
            return null;
        }
        fn at(ctx: *anyopaque, id: *const Id, version: u64) ?[]const u8 {
            _ = version;
            return latest(ctx, id);
        }
    };
    var n: usize = 0;
    var lines = std.mem.splitScalar(u8, @embedFile("../epoch/testdata/upgrade/v142/bridge-committee.jsonl"), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const o = (try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{})).object;
        const js = o.get("objects").?.array.items;
        const raws = try a.alloc([]const u8, js.len);
        for (js, raws) |j, *r| {
            const b = try a.alloc(u8, j.string.len / 2);
            _ = try std.fmt.hexToBytes(b, j.string);
            r.* = b;
        }
        var objs: Objs = .{ .list = raws };
        const src: packages.Source = .{ .ctx = &objs, .latest = Objs.latest, .at = Objs.at };
        const have = if (Objs.latest(&objs, &objectId(9))) |w| bridgeCommitteeInitiated(w, src) else false;
        std.testing.expectEqual(o.get("want").?.bool, have) catch |e| {
            std.debug.print("bridge case {s}\n", .{o.get("name").?.string});
            return e;
        };
        n += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), n);
}

test "ckpt env: event stream merkle root (fastcrypto MerkleTree over BCS EventCommitment leaves)" {
    const one: [32]u8 = @splat(1);
    const two: [32]u8 = @splat(2);
    const three: [32]u8 = @splat(3);
    var leaves = [_][32]u8{ eventLeaf(7, 2, 0, &one), eventLeaf(7, 2, 1, &two), eventLeaf(7, 5, 0, &three) };
    const all = leaves;
    var h: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&h, "6b5a180ca0886ade36733466985b1c0bd0702a334cbd8240bb0e8b60824f04d5");
    try testing.expectEqualSlices(u8, &h, &leaves[0]);
    try testing.expectEqualSlices(u8, &h, &eventMerkleRoot(leaves[0..1]));
    leaves = all;
    _ = try std.fmt.hexToBytes(&h, "dbcc6d624d9e81e1cf117a52d18a964d94e82df727c7fe5f02bf4c539aeaec17");
    try testing.expectEqualSlices(u8, &h, &eventMerkleRoot(leaves[0..2]));
    leaves = all;
    _ = try std.fmt.hexToBytes(&h, "fcf99c247bfce80b98848854878825397f77f8375fed2d636b2c56dbf03056b6");
    try testing.expectEqualSlices(u8, &h, &eventMerkleRoot(leaves[0..]));
    const zero: [32]u8 = @splat(0);
    try testing.expectEqualSlices(u8, &zero, &eventMerkleRoot(leaves[0..0]));
}
