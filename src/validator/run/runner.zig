//! The validator's executor (authority.exec_bridge.Runner) over the exec store, for every item
//! kind the consensus handler schedules:
//!
//!   user                        rpc_exec.simulate.run (deepwave's PTB engine with sui-core's input
//!                               checks) reading shared inputs and the accumulator root at the
//!                               versions consensus assigned; a transaction consensus cancelled
//!                               (congestion, DKG failure) runs exec.ptb.execute with the
//!                               cancellation sentinels, which fails it early exactly as
//!                               sui-core's `get_early_execution_error` does
//!   consensus_commit_prologue   exec.ccp
//!   authenticator_state_update  exec.system
//!   randomness_state_update     exec.system; the transaction is built at run time from the
//!                               round's bytes (`RandomnessSource`), not ready before them
//!   accumulator_settlement      ready once the checkpoint builder's Env ran the settlement and
//!                               barrier transactions (ckpt_env.zig, `resolve_settlement_effects`
//!                               and sui-core's SettlementScheduler build them from the same
//!                               sorted root effects); the item then answers the barrier
//!
//! Every execution is one durable exec store record (objects, removals, effects, events, data,
//! keys) written before the effects are visible. Running an item whose transaction already ran
//! returns the stored outcome (restart, retry).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const exec = @import("exec");
const rpc_exec = @import("rpc_exec");
const exec_bridge = @import("../authority/exec_bridge.zig");
const versions = @import("../authority/versions.zig");
const state_update = @import("../randomness/state_update.zig");
const store_mod = @import("exec_store.zig");
const objects = @import("objects.zig");

const Allocator = std.mem.Allocator;
const ExecStore = store_mod.ExecStore;
const Id = [32]u8;
pub const Key = store_mod.Key;
pub const RunError = exec_bridge.RunError;

/// What execution needs of the current epoch.
pub const EpochCtx = struct {
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    epoch_start_ms: u64,
    /// Reference gas price of the epoch.
    rgp: u64,
    /// Genesis checkpoint digest.
    chain_id: [32]u8,
    /// Committee size (transaction validity checks).
    committee_size: u32 = 1,
};

/// `random_bytes` of a randomness round (BCS of the round's full threshold signature), null
/// until the round completed. `arena` owns the result.
pub const RandomnessSource = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, arena: Allocator, epoch: u64, round: u64) ?[]const u8,
};

pub const AuthHook = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, u: *const types.AuthenticatorStateUpdate) void,
};

pub fn objectId(n: u16) Id {
    var a: Id = @splat(0);
    std.mem.writeInt(u16, a[30..32], n, .big);
    return a;
}
pub const clock_id = objectId(6);
pub const authenticator_id = objectId(7);
pub const randomness_id = objectId(8);
pub const acc_root_id = objectId(0xacc);

pub const Runner = struct {
    gpa: Allocator,
    store: *ExecStore,
    ctx: EpochCtx,
    pkgs: exec.packages.Store = .{},
    engine: rpc_exec.simulate.Engine = undefined,
    env: rpc_exec.EpochEnv = undefined,
    randomness: ?RandomnessSource = null,
    executed: u64 = 0,
    failed: u64 = 0,
    last_error: [200]u8 = undefined,
    last_error_len: usize = 0,
    /// Called after an AuthenticatorStateUpdate executed (`update_authenticator_state`: the
    /// signature verifier's JWK map takes its new active JWKs). Set per epoch under the lock.
    auth_hook: ?AuthHook = null,
    auth_hook_lock: @import("../authority/sync.zig").Spin = .{},
    funds: Funds = .{},

    /// In place: the engine points at `r.pkgs`.
    pub fn init(r: *Runner, gpa: Allocator, store: *ExecStore, ctx: EpochCtx) void {
        r.* = .{ .gpa = gpa, .store = store, .ctx = ctx };
        r.pkgs = .{ .lookup = store.packageLookup() };
        r.engine = .{ .gpa = gpa, .pkgs = &r.pkgs, .json = false, .display = false, .certificate = true };
        r.setEpoch(ctx);
    }

    /// Also frees this thread's PTB package caches (they point into this runner's package
    /// store; a runner per thread, torn down with its store).
    pub fn deinit(r: *Runner) void {
        r.funds.deinit(r.gpa);
        exec.ptb.pkgs.releaseThreadCaches();
        r.pkgs.user.deinit(r.gpa);
        r.pkgs.system.deinit(r.gpa);
    }

    /// A new epoch (after reconfiguration).
    pub fn setEpoch(r: *Runner, ctx: EpochCtx) void {
        r.ctx = ctx;
        r.env = .{ .chain_id = ctx.chain_id, .epoch = ctx.epoch, .pv = ctx.cfg.version, .cfg = ctx.cfg, .rgp = ctx.rgp, .epoch_start_ms = ctx.epoch_start_ms, .committee_size = ctx.committee_size };
    }

    pub fn runner(r: *Runner) exec_bridge.Runner {
        return .{ .ctx = r, .vtable = &vt };
    }
    const vt: exec_bridge.Runner.VTable = .{ .ready = readyFn, .run = runFn, .enqueued = enqueuedFn };

    // ------------------------------------------------------------------ funds withdraw scheduling

    fn enqueuedFn(ctx: *anyopaque, item: *const exec_bridge.Item) Allocator.Error!void {
        const r: *Runner = @ptrCast(@alignCast(ctx));
        return r.enqueued(item);
    }

    /// `collect_withdraw_reservations`: a user transaction with funds withdrawals joins the
    /// batch of the accumulator version consensus assigned it, in consensus order.
    pub fn enqueued(r: *Runner, item: *const exec_bridge.Item) Allocator.Error!void {
        if (item.kind != .user) return;
        const td_bcs = item.td_bcs orelse return;
        const version = for (item.system) |s| {
            if (std.mem.eql(u8, &s.id, &acc_root_id)) break s.version;
        } else return;
        var scratch = std.heap.ArenaAllocator.init(r.gpa);
        defer scratch.deinit();
        const td = switch (bcs.decode(types.TransactionData, scratch.allocator(), td_bcs) catch return) {
            .V1 => |v| v,
        };
        if (!rpc_exec.checks.hasFundsWithdrawals(&td)) return;
        const reserves = try rpc_exec.checks.executionWithdrawals(scratch.allocator(), &td, &r.ctx.chain_id);
        if (reserves.len == 0) return;
        const digest = item.digest orelse types.digest.transactionDataDigest(td_bcs);
        try r.funds.add(r.gpa, version, digest, reserves);
    }

    fn accVersion(item: *const exec_bridge.Item) ?u64 {
        for (item.system) |s| if (std.mem.eql(u8, &s.id, &acc_root_id)) return s.version;
        return null;
    }

    /// The scheduler's verdict for a transaction about to run: true when its reservations do
    /// not fit (`ScheduleStatus::InsufficientFunds`).
    fn insufficientFunds(r: *Runner, item: *const exec_bridge.Item, digest: *const Id) Allocator.Error!bool {
        const version = accVersion(item) orelse return false;
        return r.funds.decide(r.gpa, r.store, version, digest);
    }

    pub fn lastError(r: *const Runner) []const u8 {
        return r.last_error[0..r.last_error_len];
    }
    fn noteError(r: *Runner, msg: []const u8) void {
        const n = @min(msg.len, r.last_error.len);
        @memcpy(r.last_error[0..n], msg[0..n]);
        r.last_error_len = n;
    }

    // ------------------------------------------------------------------ readiness

    fn readyFn(ctx: *anyopaque, item: *const exec_bridge.Item) bool {
        const r: *Runner = @ptrCast(@alignCast(ctx));
        return r.ready(item);
    }

    pub fn ready(r: *Runner, item: *const exec_bridge.Item) bool {
        switch (item.kind) {
            .accumulator_settlement => return r.store.keyDigest(item.key) != null,
            .randomness_state_update => {
                if (r.store.keyDigest(item.key) != null) return true;
                const src = r.randomness orelse return false;
                const rr = switch (item.key) {
                    .randomness_round => |x| x,
                    else => return false,
                };
                var arena = std.heap.ArenaAllocator.init(r.gpa);
                defer arena.deinit();
                if (src.get(src.ctx, arena.allocator(), rr.epoch, rr.round) == null) return false;
            },
            else => if (item.digest) |d| if (r.store.executed(&d) != null) return true,
        }
        for (item.owned) |o| if (r.store.objectAt(&o.id, o.version) == null) return false;
        for (item.shared) |s| {
            if (versions.isCancelled(s.version)) continue;
            // a deleted (tombstoned) consensus input: ready once the ending transaction's marker is
            if (r.store.objectAt(&s.id, s.version) == null and
                r.store.streamEndDigest(r.ctx.epoch, &s.id, s.isv, s.version) == null) return false;
        }
        for (item.system) |s| if (r.store.objectAt(&s.id, s.version) == null) return false;
        return true;
    }

    // ------------------------------------------------------------------ execution

    fn runFn(ctx: *anyopaque, arena: Allocator, item: *const exec_bridge.Item) RunError!exec_bridge.Outcome {
        const r: *Runner = @ptrCast(@alignCast(ctx));
        const e = try r.run(arena, item);
        return outcomeOf(e);
    }

    pub fn outcomeOf(e: store_mod.Executed) exec_bridge.Outcome {
        return .{ .effects_digest = e.effects_digest, .effects_bcs = e.effects_bcs };
    }

    pub fn run(r: *Runner, arena: Allocator, item: *const exec_bridge.Item) RunError!store_mod.Executed {
        switch (item.kind) {
            .accumulator_settlement => {
                const d = r.store.keyDigest(item.key) orelse return error.Unsupported;
                return r.store.executed(&d) orelse error.Failed;
            },
            .randomness_state_update => return r.runRandomness(arena, item),
            else => {},
        }
        const td_bcs = item.td_bcs orelse return error.Failed;
        const digest = item.digest orelse types.digest.transactionDataDigest(td_bcs);
        if (r.store.executed(&digest)) |e| {
            // executed before a restart and re-enqueued with its unsettled group (the bridge
            // holds its ack until the settlement at its accumulator version): sui-core
            // re-executes it, so its object withdrawals count as unsettled again
            if (item.kind == .user) if (accVersion(item)) |v| {
                const td = (bcs.decode(types.TransactionData, arena, td_bcs) catch return e).V1;
                try r.funds.recordObjectWithdraws(r.gpa, arena, v, &td, e.effects_bcs, &r.ctx.chain_id);
            };
            return e;
        }
        const td_all = bcs.decode(types.TransactionData, arena, td_bcs) catch return error.Failed;
        const td = switch (td_all) {
            .V1 => |v| v,
        };
        const keys: []const Key = if (item.key == .digest) &.{} else &.{item.key};
        return switch (item.kind) {
            .user => r.runUser(arena, item, td_bcs, digest, &td),
            .consensus_commit_prologue => r.runPrologue(arena, item, td_bcs, digest, &td, keys),
            .authenticator_state_update => blk: {
                const ex = try r.runSystem(arena, td_bcs, digest, &td, try pinsOf(arena, item), keys);
                switch (td.kind) {
                    .AuthenticatorStateUpdate => |*u| {
                        r.auth_hook_lock.lock();
                        defer r.auth_hook_lock.unlock();
                        if (r.auth_hook) |h| h.f(h.ctx, u);
                    },
                    else => {},
                }
                break :blk ex;
            },
            .randomness_state_update, .accumulator_settlement => unreachable,
        };
    }

    /// Installs (or with null removes) the AuthenticatorStateUpdate hook.
    pub fn setAuthHook(r: *Runner, h: ?AuthHook) void {
        r.auth_hook_lock.lock();
        defer r.auth_hook_lock.unlock();
        r.auth_hook = h;
    }

    /// sui-core's checkpoint executor for one transaction of a certified checkpoint (state sync
    /// catch-up, run/catchup.zig): its consensus inputs are read at the versions the certified
    /// effects name (`input_consensus_objects`: mutated shared and consensus-owned inputs,
    /// read-only roots, cancellation sentinels), not at versions assigned here. The caller
    /// compares the effects with the certified ones before it trusts the result.
    pub fn runCertified(r: *Runner, arena: Allocator, td_bcs: []const u8, digest: Id, fx: *const types.TransactionEffectsV2) RunError!store_mod.Executed {
        if (r.store.executed(&digest)) |e| return e;
        const td_all = bcs.decode(types.TransactionData, arena, td_bcs) catch return error.Failed;
        const td = switch (td_all) {
            .V1 => |v| v,
        };
        const shared = try certifiedInputs(arena, r.store, fx);
        const kind: exec_bridge.ItemKind = switch (td.kind) {
            .ProgrammableTransaction => .user,
            .ConsensusCommitPrologue, .ConsensusCommitPrologueV2, .ConsensusCommitPrologueV3, .ConsensusCommitPrologueV4 => .consensus_commit_prologue,
            .Genesis => return error.Unsupported,
            else => .authenticator_state_update, // any system transaction: exec.system
        };
        const item: exec_bridge.Item = .{ .key = .{ .digest = digest }, .kind = kind, .td_bcs = td_bcs, .digest = digest, .shared = shared, .system = &.{} };
        return switch (kind) {
            .user => r.runUser(arena, &item, td_bcs, digest, &td),
            .consensus_commit_prologue => r.runPrologue(arena, &item, td_bcs, digest, &td, &.{}),
            else => r.runSystem(arena, td_bcs, digest, &td, try pinsOf(arena, &item), &.{}),
        };
    }

    fn pinsOf(arena: Allocator, item: *const exec_bridge.Item) Allocator.Error![]const objects.Pin {
        var l: std.ArrayList(objects.Pin) = .empty;
        for (item.shared) |s| if (!versions.isCancelled(s.version)) try l.append(arena, .{ .id = s.id, .version = s.version });
        for (item.system) |s| try l.append(arena, .{ .id = s.id, .version = s.version });
        return l.items;
    }

    fn runUser(r: *Runner, arena: Allocator, item: *const exec_bridge.Item, td_bcs: []const u8, digest: Id, td: *const types.TransactionDataV1) RunError!store_mod.Executed {
        for (item.shared) |s| if (versions.isCancelled(s.version)) return r.runCancelled(arena, item, td_bcs, digest, td);
        // `ObjectConsensusStreamEnded` (read_objects_for_execution): the object at the assigned
        // version is not this consensus object (deleted or taken out of consensus by an earlier
        // transaction); the transaction fails early with InputObjectDeleted
        for (item.shared) |s| if (streamEndedAt(r.store, r.ctx.epoch, &s.id, s.isv, s.version) != null)
            return r.runCancelled(arena, item, td_bcs, digest, td);
        const st: objects.State = .{ .store = r.store, .pins = try pinsOf(arena, item) };
        const insufficient = try r.insufficientFunds(item, &digest);
        const version = accVersion(item);
        var view: Funds.View = .{ .funds = &r.funds, .version = version orelse 0 };
        const res = rpc_exec.simulate.runOpts(&r.engine, arena, &r.env, st.state(), td_bcs, td.*, false, false, .{
            .insufficient_funds = insufficient,
            .unsettled = if (version != null) view.unsettled() else null,
        }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                r.noteError(@errorName(e));
                r.failed += 1;
                return error.Failed;
            },
        };
        switch (res) {
            .ok => |sim| {
                const raws = try arena.alloc([]const u8, sim.written.len);
                for (sim.written, raws) |w, *o| o.* = w.bytes;
                const out = try r.commit(arena, digest, &.{}, td_bcs, sim.effects, sim.events, raws);
                if (version) |v| try r.funds.recordObjectWithdraws(r.gpa, arena, v, td, sim.effects, &r.ctx.chain_id);
                return out;
            },
            .fail => |f| {
                r.noteError(f.message);
                r.failed += 1;
                return error.Failed;
            },
            .unimplemented => |why| {
                r.noteError(why);
                r.failed += 1;
                return error.Unsupported;
            },
        }
    }

    /// A transaction with a cancelled shared input (exec.ptb with the sentinel versions) or one
    /// whose consensus stream ended: both fail early, without the signing-style input load.
    fn runCancelled(r: *Runner, arena: Allocator, item: *const exec_bridge.Item, td_bcs: []const u8, digest: Id, td: *const types.TransactionDataV1) RunError!store_mod.Executed {
        const pre: CancelPre = .{ .store = r.store, .item = item, .epoch = r.ctx.epoch };
        const lk: Lookup = .{ .store = r.store };
        const insufficient = try r.insufficientFunds(item, &digest);
        const res = exec.ptb.execute(arena, .{
            .gpa = r.gpa,
            .cfg = r.ctx.cfg,
            .pv = r.ctx.cfg.version,
            .epoch = r.ctx.epoch,
            .epoch_start_ms = r.ctx.epoch_start_ms,
            .rgp = r.ctx.rgp,
            .pkgs = &r.pkgs,
            .authoritative_packages = true,
            .tx_digest = digest,
            .chain_id = r.ctx.chain_id,
        }, td_bcs, td, .{
            .objs = lk.lookup(),
            .effects = null,
            .unchanged_loaded = null,
            .state = .{ .ctx = &pre, .vtable = &CancelPre.vtable },
            .insufficient_funds = insufficient,
        }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                r.noteError(@errorName(e));
                r.failed += 1;
                return error.Failed;
            },
        };
        switch (res) {
            .done => |o| {
                const raws = try arena.alloc([]const u8, o.written.len);
                for (o.written, raws) |w, *x| x.* = w.bytes;
                return r.commit(arena, digest, &.{}, td_bcs, o.effects, o.events, raws);
            },
            .unsupported => |why| {
                r.noteError(why);
                r.failed += 1;
                return error.Unsupported;
            },
        }
    }

    fn runPrologue(r: *Runner, arena: Allocator, item: *const exec_bridge.Item, td_bcs: []const u8, digest: Id, td: *const types.TransactionDataV1, keys: []const Key) RunError!store_mod.Executed {
        var clock_v: ?u64 = null;
        for (item.shared) |s| if (std.mem.eql(u8, &s.id, &clock_id)) {
            clock_v = s.version;
        };
        const raw = r.store.objectAt(&clock_id, clock_v orelse return error.Failed) orelse return error.Failed;
        const res = exec.ccp.execute(arena, r.ctx.cfg, r.ctx.epoch, td_bcs, td, &.{raw}) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                r.noteError(@errorName(e));
                return error.Failed;
            },
        };
        switch (res) {
            .done => |o| {
                const raws = try arena.alloc([]const u8, o.written.len);
                for (o.written, raws) |w, *x| x.* = w.bytes;
                return r.commit(arena, digest, keys, td_bcs, o.effects, null, raws);
            },
            .unsupported => |why| {
                r.noteError(why);
                return error.Unsupported;
            },
        }
    }

    fn runRandomness(r: *Runner, arena: Allocator, item: *const exec_bridge.Item) RunError!store_mod.Executed {
        if (r.store.keyDigest(item.key)) |d| return r.store.executed(&d) orelse error.Failed;
        const rr = switch (item.key) {
            .randomness_round => |x| x,
            else => return error.Failed,
        };
        const src = r.randomness orelse return error.Unsupported;
        const bytes = src.get(src.ctx, arena, rr.epoch, rr.round) orelse return error.Unsupported;
        var isv: ?u64 = null;
        for (item.shared) |s| if (std.mem.eql(u8, &s.id, &randomness_id)) {
            isv = s.isv;
        };
        const built = state_update.build(arena, rr.epoch, rr.round, bytes, isv orelse return error.Failed) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Failed,
        };
        if (r.store.executed(&built.digest)) |e| return e;
        const td = (bcs.decode(types.TransactionData, arena, built.data) catch return error.Failed).V1;
        return r.runSystem(arena, built.data, built.digest, &td, try pinsOf(arena, item), &.{item.key});
    }

    /// Runs a system transaction through exec.system (authenticator and randomness updates,
    /// settlement and barrier, end of epoch) with its shared inputs at `pins`, and stores it.
    pub fn runSystem(r: *Runner, arena: Allocator, td_bcs: []const u8, digest: Id, td: *const types.TransactionDataV1, pins: []const objects.Pin, keys: []const Key) RunError!store_mod.Executed {
        if (r.store.executed(&digest)) |e| {
            // a key learned now for a transaction stored before (idempotent retry)
            for (keys) |k| if (r.store.keyDigest(k) == null) r.store.putKey(k, digest) catch |e2| fatalStore(e2);
            return e;
        }
        const iv = try arena.alloc(exec.system.InputVersion, pins.len);
        for (pins, iv) |p, *o| o.* = .{ .id = p.id, .version = p.version };
        const src: SysSource = .{ .r = r };
        const env: exec.system.Env = .{ .cfg = r.ctx.cfg, .epoch = r.ctx.epoch, .epoch_start_ms = r.ctx.epoch_start_ms, .rgp = r.ctx.rgp, .tx_digest = digest };
        const res = exec.system.execute(arena, &env, td_bcs, td, iv, src.source()) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                r.noteError(@errorName(e));
                return error.Failed;
            },
        };
        switch (res) {
            .done => |o| {
                const raws = try arena.alloc([]const u8, o.written.len);
                for (o.written, raws) |w, *x| x.* = w.bytes;
                return r.commit(arena, digest, keys, td_bcs, o.effects, o.events, raws);
            },
            .unsupported => |why| {
                r.noteError(why);
                return error.Unsupported;
            },
        }
    }

    fn commit(r: *Runner, arena: Allocator, digest: Id, keys: []const Key, td_bcs: []const u8, effects: []const u8, events: ?[]const u8, written: []const []const u8) RunError!store_mod.Executed {
        const removed = store_mod.removalsOf(arena, effects) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Failed,
        };
        r.store.commitTx(&.{ .digest = digest, .keys = keys, .td_bcs = td_bcs, .effects_bcs = effects, .events_bcs = events, .written = written, .removed = removed }) catch |e| fatalStore(e);
        r.executed += 1;
        return r.store.executed(&digest).?;
    }
};

/// The consensus inputs of a certified transaction with their versions, from its effects
/// (sui-types `TransactionEffectsAPI::input_consensus_objects`): changed objects whose input was
/// shared or consensus-owned at that version, and the unchanged ones (read-only roots and the
/// sentinel versions of cancelled or ended streams).
pub fn certifiedInputs(arena: Allocator, st: *ExecStore, fx: *const types.TransactionEffectsV2) Allocator.Error![]const versions.SharedVersion {
    var out: std.ArrayList(versions.SharedVersion) = .empty;
    for (fx.changed_objects) |c| switch (c[1].input_state) {
        .Exist => |ex| {
            const isv: ?u64 = switch (ex[1]) {
                .Shared => |sh| sh.initial_shared_version.@"0",
                .ConsensusAddressOwner => |co| co.start_version.@"0",
                .Party => |p| p.start_version.@"0",
                else => null,
            };
            if (isv) |v| try out.append(arena, .{ .id = c[0].@"0".@"0", .isv = v, .version = ex[0][0].@"0" });
        },
        .NotExist => {},
    };
    for (fx.unchanged_consensus_objects) |u| {
        const id = u[1];
        const version: u64 = switch (id) {
            .ReadOnlyRoot => |x| x[0].@"0",
            .MutateConsensusStreamEnded, .ReadConsensusStreamEnded, .Cancelled => |v| v.@"0",
            .PerEpochConfig => continue,
        };
        const oid = u[0].@"0".@"0";
        const isv: u64 = if (st.objectAt(&oid, version)) |raw| objects.startVersion(raw) orelse 0 else 0;
        try out.append(arena, .{ .id = oid, .isv = isv, .version = version });
    }
    return out.items;
}

/// A failed exec store write: the executed state can no longer be made durable. sui-core panics
/// on a database error; so does the validator (it restarts from the log).
fn fatalStore(e: anyerror) noreturn {
    std.debug.panic("exec store write failed: {s}", .{@errorName(e)});
}

const Lookup = struct {
    store: *ExecStore,
    fn self(ctx: *const anyopaque) *ExecStore {
        const l: *const Lookup = @ptrCast(@alignCast(ctx));
        return l.store;
    }
    fn get(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        return self(ctx).objectAt(id, version);
    }
    fn latest(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
        return self(ctx).latest(id);
    }
    fn lookup(l: *const Lookup) exec.coin_ptb.ObjectLookup {
        return .{ .ctx = l, .get = get, .latest = latest };
    }
};

/// sui-core's address funds withdraw scheduler, with `NaiveFundsWithdrawScheduler`'s results
/// (the eager scheduler's are the same): every withdrawing transaction of one accumulator
/// version (one consensus commit) in consensus order; when the first of them runs, the root is
/// at that version and its settlement has not run, so the stored balances are the settled ones.
/// Each account then covers the transactions' declared maxima in order: a transaction whose
/// reservation does not fit some account is InsufficientFunds (the accounts that did fit keep
/// their deduction, as in Rust); a root already past the version skips the batch (all
/// sufficient: `SkipSchedule`).
pub const Funds = struct {
    batches: std.AutoArrayHashMapUnmanaged(u64, *Batch) = .empty,

    const Entry = struct { digest: Id, reserves: []const rpc_exec.checks.Reserve };
    const Batch = struct {
        arena: std.heap.ArenaAllocator,
        entries: std.ArrayList(Entry) = .empty,
        /// Entries decided so far (a prefix: consensus order makes the decision prefix-stable,
        /// so entries enqueued after a decision are decided on their turn).
        decided: usize = 0,
        /// Remaining balance per account after the decided entries' reservations.
        balances: std.AutoArrayHashMapUnmanaged(Id, u128) = .empty,
        /// The root was past the version: SkipSchedule, every entry sufficient.
        skip: bool = false,
        /// digest -> insufficient
        results: std.AutoHashMapUnmanaged(Id, bool) = .empty,
        /// `UnsettledObjectWithdrawals` at this version: the net withdrawals of the commit's
        /// successful transactions from accounts they did not reserve (object-owned accounts).
        object_withdraws: std.AutoArrayHashMapUnmanaged(Id, u128) = .empty,
        /// Transactions whose object withdrawals are in `object_withdraws` (a transaction
        /// executed before a restart is recorded again when its group is re-enqueued).
        recorded: std.AutoHashMapUnmanaged(Id, void) = .empty,
    };

    fn batchFor(f: *Funds, gpa: Allocator, version: u64) Allocator.Error!*Batch {
        const gop = try f.batches.getOrPut(gpa, version);
        if (!gop.found_existing) {
            const b = gpa.create(Batch) catch |e| {
                f.batches.swapRemoveAt(gop.index);
                return e;
            };
            b.* = .{ .arena = .init(gpa) };
            gop.value_ptr.* = b;
        }
        return gop.value_ptr.*;
    }

    /// `UnsettledObjectFundsRead` at one accumulator version, for exec.ptb.
    pub const View = struct {
        funds: *const Funds,
        version: u64,
        pub fn unsettled(v: *const View) exec.ptb.Unsettled {
            return .{ .ctx = v, .get = get };
        }
        fn get(ctx: *const anyopaque, _: Allocator, field: *const Id) anyerror!u128 {
            const v: *const View = @ptrCast(@alignCast(ctx));
            const b = v.funds.batches.get(v.version) orelse return 0;
            return b.object_withdraws.get(field.*) orelse 0;
        }
    };

    /// `record_object_funds_withdraws` after a successful execution: every Split of an account
    /// the transaction did not reserve, by its net amount.
    pub fn recordObjectWithdraws(f: *Funds, gpa: Allocator, arena: Allocator, version: u64, td: *const types.TransactionDataV1, effects_bcs: []const u8, chain_id: *const Id) Allocator.Error!void {
        const fx = (bcs.decode(types.TransactionEffects, arena, effects_bcs) catch return).V2;
        if (fx.status != .Success) return;
        {
            f.prune(gpa, version);
            const b = try f.batchFor(gpa, version);
            const gop = try b.recorded.getOrPut(b.arena.allocator(), fx.transaction_digest.@"0".@"0");
            if (gop.found_existing) return;
        }
        var reserved: ?[]const rpc_exec.checks.Reserve = null;
        for (fx.changed_objects) |c| switch (c[1].output_state) {
            .AccumulatorWriteV1 => |w| {
                if (w.operation != .Split) continue;
                const amount: u64 = switch (w.value) {
                    .Integer => |x| x,
                    else => continue,
                };
                if (amount == 0) continue;
                const id = c[0].@"0".@"0";
                if (reserved == null) reserved = try rpc_exec.checks.executionWithdrawals(arena, td, chain_id);
                const is_reserved = for (reserved.?) |*rv| {
                    if (std.mem.eql(u8, &rv.account, &id)) break true;
                } else false;
                if (is_reserved) continue;
                f.prune(gpa, version);
                const b = try f.batchFor(gpa, version);
                const gop = try b.object_withdraws.getOrPut(b.arena.allocator(), id);
                if (!gop.found_existing) gop.value_ptr.* = 0;
                gop.value_ptr.* +|= amount;
            },
            else => {},
        };
    }

    pub fn deinit(f: *Funds, gpa: Allocator) void {
        for (f.batches.values()) |b| {
            b.arena.deinit();
            gpa.destroy(b);
        }
        f.batches.deinit(gpa);
    }

    pub fn add(f: *Funds, gpa: Allocator, version: u64, digest: Id, reserves: []const rpc_exec.checks.Reserve) Allocator.Error!void {
        const b = try f.batchFor(gpa, version);
        // a transaction enqueued again (restart, retry) keeps its first place
        for (b.entries.items) |*x| if (std.mem.eql(u8, &x.digest, &digest)) return;
        const a = b.arena.allocator();
        try b.entries.append(a, .{ .digest = digest, .reserves = try a.dupe(rpc_exec.checks.Reserve, reserves) });
    }

    pub fn decide(f: *Funds, gpa: Allocator, store: *ExecStore, version: u64, digest: *const Id) Allocator.Error!bool {
        f.prune(gpa, version);
        const b = f.batches.get(version) orelse return false;
        const a = b.arena.allocator();
        // the consistent read's version is the accumulator root's
        if (b.decided < b.entries.items.len) if (store.latest(&acc_root_id)) |raw| {
            const rv = exec.objects.ObjectView.parse(raw) catch null;
            if (rv) |v| if (v.version > version) {
                b.skip = true;
            };
        };
        while (b.decided < b.entries.items.len) : (b.decided += 1) {
            const x = &b.entries.items[b.decided];
            // get_consistent_latest_account_amount_and_version for accounts not seen yet
            for (x.reserves) |*rv| {
                const gop = try b.balances.getOrPut(a, rv.account);
                if (gop.found_existing) continue;
                gop.value_ptr.* = 0;
                const raw = store.latest(&rv.account) orelse continue;
                gop.value_ptr.* = rpc_exec.checks.accumulatorAmount(raw) orelse 0;
            }
            var ok = true;
            if (!b.skip) for (x.reserves) |*rv| {
                const bal = b.balances.getPtr(rv.account).?;
                if (bal.* < rv.amount) ok = false else bal.* -= rv.amount;
            };
            try b.results.put(a, x.digest, !ok);
        }
        return b.results.get(digest.*) orelse false;
    }

    /// Batches below `version` are settled: their transactions all ran.
    fn prune(f: *Funds, gpa: Allocator, version: u64) void {
        var i: usize = 0;
        while (i < f.batches.count()) {
            if (f.batches.keys()[i] < version) {
                const b = f.batches.values()[i];
                b.arena.deinit();
                gpa.destroy(b);
                f.batches.swapRemoveAt(i);
            } else i += 1;
        }
    }
};

/// exec.ptb's pre-state for a cancelled transaction: shared inputs answer the version consensus
/// assigned (a sentinel for the cancelled ones).
const CancelPre = struct {
    store: *ExecStore,
    item: *const exec_bridge.Item,
    epoch: u64,
    fn of(ctx: *const anyopaque) *const CancelPre {
        return @ptrCast(@alignCast(ctx));
    }
    fn sharedLatest(ctx: *const anyopaque, id: *const Id) ?u64 {
        const p = of(ctx);
        for (p.item.shared) |s| if (std.mem.eql(u8, &s.id, id)) return s.version;
        for (p.item.system) |s| if (std.mem.eql(u8, &s.id, id)) return s.version;
        const raw = p.store.latest(id) orelse return null;
        return (exec.objects.ObjectView.parse(raw) catch return null).version;
    }
    fn childAtMost(ctx: *const anyopaque, child: *const Id, upper: u64) ?[]const u8 {
        return of(ctx).store.atMost(child, upper);
    }
    fn addressBalance(ctx: *const anyopaque, owner: *const Id, ty: *const types.TypeTag) ?u128 {
        _ = .{ ctx, owner, ty };
        return null;
    }
    fn streamEnded(ctx: *const anyopaque, id: *const [32]u8, start: u64, version: u64) ?[32]u8 {
        const p = of(ctx);
        return streamEndedAt(p.store, p.epoch, id, start, version);
    }
    const vtable: exec.ptb.PreState.VTable = .{ .shared_latest = sharedLatest, .child_at_most = childAtMost, .address_balance = addressBalance, .stream_ended = streamEnded };
};

/// read_objects_for_execution's shared input at its assigned version: when the stored object
/// there is not the consensus object `(id, start)` (`obj.full_id() != input.full_object_id()`),
/// the digest of the transaction whose ConsensusStreamEnded marker is at that version; null for
/// the live object, a cancellation sentinel, or no marker.
fn streamEndedAt(store: *ExecStore, epoch: u64, id: *const Id, start: u64, version: u64) ?Id {
    if (versions.isCancelled(version)) return null;
    if (store.objectAt(id, version)) |raw| {
        const v = exec.objects.ObjectView.parse(raw) catch return null;
        var buf: [256]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buf);
        const owner = bcs.decode(types.Owner, fba.allocator(), raw[v.owner_at..v.prev_tx_at]) catch return null;
        if (store_mod.consensusStart(owner)) |st| if (st == start) return null;
    }
    return store.streamEndDigest(epoch, id, start, version);
}

const SysSource = struct {
    r: *Runner,
    fn of(ctx: *const anyopaque) *const SysSource {
        return @ptrCast(@alignCast(ctx));
    }
    fn input(ctx: *const anyopaque, id: *const [32]u8, version: u64) ?[]const u8 {
        return of(ctx).r.store.objectAt(id, version);
    }
    fn child(ctx: *const anyopaque, parent: *const [32]u8, c: *const [32]u8, bound: u64) error{NotAvailable}!?[]const u8 {
        _ = parent;
        return of(ctx).r.store.atMost(c, bound);
    }
    fn package(ctx: *const anyopaque, id: *const [32]u8) ?[]const u8 {
        const r = of(ctx).r;
        return r.pkgs.get(id, r.ctx.epoch);
    }
    fn source(s: *const SysSource) exec.system.Source {
        return .{ .ctx = s, .input = input, .child = child, .package = package };
    }
};

// ---------------------------------------------------------------------- tests

const testing = std.testing;

test "runner: settlement items wait for the builder's barrier, digests are idempotent" {
    const gpa = testing.allocator;
    var s = ExecStore.openMem(gpa, testing.io);
    defer s.close();
    const cfg = try protocol.get(141, .mainnet);
    var r: Runner = undefined;
    r.init(gpa, &s, .{ .cfg = cfg, .epoch = 0, .epoch_start_ms = 0, .rgp = 1000, .chain_id = @splat(0) });
    defer r.deinit();
    const key: Key = .{ .accumulator_settlement = .{ .epoch = 0, .height = 1 } };
    const item: exec_bridge.Item = .{ .key = key, .kind = .accumulator_settlement, .td_bcs = null, .digest = null, .shared = &.{}, .system = &.{} };
    try testing.expect(!r.ready(&item));
    try s.commitTx(&.{ .digest = @splat(5), .keys = &.{key}, .td_bcs = "td", .effects_bcs = "fx", .written = &.{} });
    try testing.expect(r.ready(&item));
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const e = try r.run(arena.allocator(), &item);
    try testing.expectEqualStrings("fx", e.effects_bcs);
    // a user item whose digest already ran is ready and answers the stored effects
    const u: exec_bridge.Item = .{ .key = .{ .digest = @splat(5) }, .kind = .user, .td_bcs = "td", .digest = @splat(5), .shared = &.{.{ .id = @splat(1), .isv = 1, .version = 9 }}, .system = &.{} };
    try testing.expect(r.ready(&u));
    try testing.expectEqualStrings("fx", (try r.run(arena.allocator(), &u)).effects_bcs);
    // randomness without a source is not ready
    const rnd: exec_bridge.Item = .{ .key = .{ .randomness_round = .{ .epoch = 0, .round = 1 } }, .kind = .randomness_state_update, .td_bcs = null, .digest = null, .shared = &.{}, .system = &.{} };
    try testing.expect(!r.ready(&rnd));
}

fn testObject(arena: Allocator, id: Id, version: u64, amount: u128) ![]const u8 {
    var two: Id = @splat(0);
    two[31] = 2;
    var c: std.ArrayList(u8) = .empty;
    try c.appendSlice(arena, &id);
    var v: [16]u8 = undefined;
    std.mem.writeInt(u128, &v, amount, .little);
    try c.appendSlice(arena, &v);
    const obj: types.Object = .{
        .data = .{ .Move = .{
            .type_ = .{ .@"0" = .{ .Other = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "t" }, .name = .{ .@"0" = "T" }, .type_args = &.{} } } },
            .has_public_transfer = false,
            .version = .{ .@"0" = version },
            .contents = c.items,
        } },
        .owner = .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 1 } } },
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(0) } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, arena, &obj);
}

test "runner: funds withdraw scheduling in consensus order (NaiveFundsWithdrawScheduler)" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var s = ExecStore.openMem(gpa, testing.io);
    defer s.close();
    const acct_a: Id = @splat(0xaa);
    const acct_b: Id = @splat(0xbb);
    // the root at version 10, account A holds 1000, B does not exist
    try s.commitTx(&.{ .digest = @splat(1), .keys = &.{}, .td_bcs = "td", .effects_bcs = "fx", .written = &.{ try testObject(a, acc_root_id, 10, 0), try testObject(a, acct_a, 9, 1000) } });
    var f: Funds = .{};
    defer f.deinit(gpa);
    const R = rpc_exec.checks.Reserve;
    const d = struct {
        fn of(n: u8) Id {
            return @splat(n);
        }
    }.of;
    // the design doc's example: 400, 300 fit, 500 does not
    try f.add(gpa, 10, d(1), &.{R{ .account = acct_a, .amount = 400 }});
    try f.add(gpa, 10, d(2), &.{R{ .account = acct_a, .amount = 300 }});
    try f.add(gpa, 10, d(3), &.{R{ .account = acct_a, .amount = 500 }});
    // A fits (300 left, 200 taken), B (absent: 0) does not: insufficient, A keeps the deduction
    try f.add(gpa, 10, d(4), &.{ R{ .account = acct_a, .amount = 200 }, R{ .account = acct_b, .amount = 1 } });
    try f.add(gpa, 10, d(1), &.{R{ .account = acct_a, .amount = 999 }}); // enqueued again: ignored
    try testing.expect(try f.decide(gpa, &s, 10, &d(3)));
    try testing.expect(!try f.decide(gpa, &s, 10, &d(1)));
    try testing.expect(!try f.decide(gpa, &s, 10, &d(2)));
    try testing.expect(try f.decide(gpa, &s, 10, &d(4)));
    // enqueued after the first decision: decided on its turn (100 left)
    try f.add(gpa, 10, d(5), &.{R{ .account = acct_a, .amount = 100 }});
    try f.add(gpa, 10, d(6), &.{R{ .account = acct_a, .amount = 1 }});
    try testing.expect(try f.decide(gpa, &s, 10, &d(6)));
    try testing.expect(!try f.decide(gpa, &s, 10, &d(5)));
    // unknown transaction or version: sufficient
    try testing.expect(!try f.decide(gpa, &s, 10, &d(9)));
    // a root past the version: SkipSchedule
    try f.add(gpa, 11, d(7), &.{R{ .account = acct_b, .amount = 5 }});
    try s.commitTx(&.{ .digest = @splat(2), .keys = &.{}, .td_bcs = "td", .effects_bcs = "fx", .written = &.{try testObject(a, acc_root_id, 12, 0)} });
    try testing.expect(!try f.decide(gpa, &s, 11, &d(7)));
    // deciding version 11 pruned version 10
    try testing.expectEqual(@as(usize, 1), f.batches.count());
}

test "runner: unsettled object withdrawals are read per accumulator version" {
    const gpa = testing.allocator;
    var f: Funds = .{};
    defer f.deinit(gpa);
    const acct: Id = @splat(0xcc);
    const b = try f.batchFor(gpa, 7);
    try b.object_withdraws.put(b.arena.allocator(), acct, 40);
    var v7: Funds.View = .{ .funds = &f, .version = 7 };
    var v8: Funds.View = .{ .funds = &f, .version = 8 };
    const at7 = v7.unsettled();
    const at8 = v8.unsettled();
    try testing.expectEqual(@as(u128, 40), try at7.get(at7.ctx, gpa, &acct));
    try testing.expectEqual(@as(u128, 0), try at8.get(at8.ctx, gpa, &acct));
    const other: Id = @splat(0xdd);
    try testing.expectEqual(@as(u128, 0), try at7.get(at7.ctx, gpa, &other));
}
