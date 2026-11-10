//! deepwave simulation engine: execute a transaction without committing it. This is
//! the plain Zig interface that the native QUIC protocol (lane native-proto), gRPC
//! SimulateTransaction and tools bind to.
//!
//!   var eng: Engine = .{ .core = .{ .gpa = gpa, .pkgs = &pkgs }, .tip = .{ .store = st, .env = env_src } };
//!   var snap = st.snapshot(); defer snap.release(); // held while `r` is used
//!   const r = try eng.simulate(arena, &snap, .{ .tx = .{ .kind = .{ .kind = kind_bcs, .sender = me } } });
//!   switch (r) { .executed => |x| x.status, x.gas, x.object_changes, x.balance_changes, .rejected => |e| e.message }
//!
//! - Threads: call from any number of threads at once. Every call reads one RCU store snapshot
//!   (zero copy, no write-path lock) and allocates only in the caller's `arena`. Keep a fixed
//!   set of worker threads (`rpc_exec.pool.Pool`, or your own), each reusing one arena
//!   (`reset(.retain_capacity)`), so each worker's package cache stays warm. Call
//!   `releaseThreadCaches` when a worker exits.
//! - Packages: each worker deserializes a package once per epoch. The bytecode verifier runs
//!   once per package per protocol version for the whole process (`move_vm.loader.verified`).
//!   `setCacheBudget` splits `--exec-cache-mb` over the workers.
//! - Results: `Executed` carries what sui-node's simulate_transaction and the old JSON-RPC
//!   dry_run_transaction_block return: the effects (BCS and decoded), the events, the object
//!   changes, the balance changes, the gas breakdown and the execution error with its command
//!   index. `grpcResponse` renders it byte for byte as sui-node's SimulateTransactionResponse.
//!   An execution failure is `.executed` with `status = .failure`. `.rejected` means the
//!   transaction never ran: input checks failed (sui-node's gRPC error), or the transaction is
//!   outside what deepwave models (code 12, UNIMPLEMENTED).
//! - Overrides: replacement or extra input objects, gas budget and price, the Clock's
//!   timestamp, skip-checks DevInspect mode. An override must decode as a BCS `Object`; its Move
//!   contents are not checked against the type's layout, so take overrides only from callers
//!   you trust (an agent's own process), not from a public endpoint. `simulateChain` runs B on A's outputs within one
//!   snapshot. Owned inputs whose id an override or an earlier step wrote are rebased to that
//!   version, so an agent can build every step against the chain tip.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const exec = @import("exec");
const serve = @import("serve");
const rpc_exec = @import("rpc_exec");
const overlay_mod = @import("overlay.zig");

const Allocator = std.mem.Allocator;
pub const Id = [32]u8;
pub const State = rpc_exec.State;
pub const EpochEnv = rpc_exec.EpochEnv;
pub const Overlay = overlay_mod.Overlay;
const core = rpc_exec.simulate;
const ObjectView = exec.objects.ObjectView;

pub const ObjectRef = struct { id: Id, version: u64, digest: Id };

/// What to run.
pub const Tx = union(enum) {
    /// An unsigned BCS `TransactionData`, run as given (gas coins, budget, price, expiration).
    data: []const u8,
    /// A BCS `TransactionKind` with its sender. Without `gas.payment`, a mock gas coin pays
    /// (sui-node's simulate without gas). Budget defaults to the protocol maximum, price to the
    /// reference gas price.
    kind: struct { kind: []const u8, sender: Id, gas: Gas = .{} },
};

pub const Gas = struct {
    payment: []const ObjectRef = &.{},
    /// Defaults to the sender.
    owner: ?Id = null,
    budget: ?u64 = null,
    price: ?u64 = null,
};

pub const Mode = enum {
    /// sui-node simulate with checks on: the effects mainnet would certify.
    simulate,
    /// checks off (`DevInspect<true>`, `check_dev_inspect_input`): arbitrary calls, no ownership,
    /// replay or gas checks.
    dev_inspect,
};

/// "What if" inputs for one simulation (all optional).
pub const Overrides = struct {
    /// Raw BCS `Object`s that replace the id's live version or add an object that does not
    /// exist. Owned inputs that name one of them are rebased to it.
    objects: []const []const u8 = &.{},
    /// Ids to hide from the pre-state.
    hidden: []const Id = &.{},
    gas_budget: ?u64 = null,
    gas_price: ?u64 = null,
    /// The Clock's (0x6) `timestamp_ms` as the transaction reads it.
    clock_ms: ?u64 = null,
};

pub const Request = struct {
    tx: Tx,
    mode: Mode = .simulate,
    overrides: Overrides = .{},
    /// Rebase owned and receiving input refs (and gas coins) to the overlay's versions.
    rebase: bool = true,
};

pub const Result = union(enum) {
    executed: Executed,
    rejected: Rejected,
};

/// The transaction did not run. `code` is the gRPC status sui-node answers (3 invalid
/// argument, 9 failed precondition, 13 internal; 12 is zui-only: not modeled yet).
pub const Rejected = struct { code: u8, message: []const u8 };

pub const Status = union(enum) {
    success,
    failure: Failure,
};

pub const Failure = struct {
    kind: types.ExecutionErrorKind,
    /// The PTB command index that failed (null: the failure is not a command's).
    command: ?u64,
    /// sui-node's message (`ExecutionFailureStatus` Display plus the command, as simulate
    /// reports it).
    message: []const u8,
    /// The variant name, e.g. `MoveAbort`, `InsufficientCoinBalance`.
    name: []const u8,
};

pub const GasBreakdown = struct {
    computation: u64,
    storage: u64,
    rebate: u64,
    non_refundable: u64,
    budget: u64,
    price: u64,
    /// computation + storage - rebate (what the gas owner pays, negative when the rebate wins).
    pub fn net(g: GasBreakdown) i128 {
        return @as(i128, g.computation) + g.storage - g.rebate;
    }
};

pub const ChangeKind = enum { created, mutated, unwrapped, deleted, wrapped, unwrapped_then_deleted, published };

pub const ObjectChange = struct {
    kind: ChangeKind,
    id: Id,
    /// The version after the transaction (the lamport version), or before it for deletions.
    version: u64,
    /// The object after the transaction (raw BCS), when written.
    object: ?[]const u8 = null,
    /// The object before the transaction (raw BCS), when it was an input or a runtime load.
    previous: ?[]const u8 = null,
};

pub const BalanceChange = serve.balance.Change;

pub const Executed = struct {
    /// The TransactionData as run (after overrides and rebasing), BCS.
    tx_data: []const u8,
    td: types.TransactionDataV1,
    digest: Id,
    status: Status,
    gas: GasBreakdown,
    effects: []const u8,
    eff: types.TransactionEffects,
    events: ?[]const u8,
    object_changes: []const ObjectChange,
    balance_changes: []const BalanceChange,
    /// The objects written (new versions), raw BCS.
    written: []const exec.coin_ptb.Written,
    /// sui-node's transaction object set (inputs, writes and runtime loads), for rendering.
    objects: []const []const u8,
    loaded: []const core.Ref,
    /// The state the simulation read (the overlay), for rendering.
    state: State,
};

/// Where `simulate` reads the tip: the store and the epoch the node is in.
pub const Tip = struct {
    store: *store.Store,
    env: rpc_exec.service.EnvSource,
};

pub const Engine = struct {
    /// The shared simulation core (package store, gas-selection randomness, congestion price).
    core: core.Engine,
    /// Null: only `simulateAt` / `simulateChainAt` (an explicit pre-state).
    tip: ?Tip = null,

    /// One simulation at the tip, read through `snap`: the caller's snapshot, held until it is
    /// done with the Result (`objects`, `state`, object-change bytes borrow from it).
    pub fn simulate(e: *const Engine, arena: Allocator, snap: *const store.Snapshot, req: Request) !Result {
        const r = try e.simulateChain(arena, snap, &.{req});
        return r[0];
    }

    /// Steps in order on one snapshot: each step sees every earlier step's writes and
    /// deletions (as if they had committed). A rejected step is answered and the chain goes on
    /// without its writes; a failed step's gas charge and rebates still apply, as on chain.
    /// `snap`: as for `simulate` (a snapshot taken and released in here left `state` and the
    /// borrowed object bytes of every Result dangling).
    pub fn simulateChain(e: *const Engine, arena: Allocator, snap: *const store.Snapshot, reqs: []const Request) ![]Result {
        const tip = e.tip orelse return error.NoTip;
        const env = tip.env.get(tip.env.ctx) orelse return error.EpochUnavailable;
        return e.simulateChainAt(arena, &env, State.fromSnapshot(snap), reqs);
    }

    pub fn simulateAt(e: *const Engine, arena: Allocator, env: *const EpochEnv, base: State, req: Request) !Result {
        var ov = Overlay.init(base);
        return e.step(arena, env, &ov, req);
    }

    pub fn simulateChainAt(e: *const Engine, arena: Allocator, env: *const EpochEnv, base: State, reqs: []const Request) ![]Result {
        const out = try arena.alloc(Result, reqs.len);
        var ov = Overlay.init(base);
        for (reqs, out) |r, *o| {
            o.* = try e.step(arena, env, &ov, r);
            switch (o.*) {
                .executed => |x| try applyOutputs(arena, &ov, &x),
                .rejected => {},
            }
        }
        return out;
    }

    fn step(e: *const Engine, arena: Allocator, env: *const EpochEnv, ov: *Overlay, req: Request) !Result {
        // per-step overrides layer over the chain's overlay (a copy: they do not outlive the step)
        const local = try arena.create(Overlay);
        local.* = .{ .base = ov.base, .map = try ov.map.clone(arena) };
        for (req.overrides.objects) |raw| {
            // the whole Object must decode (framing, owner, digests); Move contents are the caller's
            _ = bcs.decode(types.Object, arena, raw) catch return reject(3, "override object: not a BCS Object");
            local.put(arena, raw) catch return reject(3, "override object: not a BCS Object");
        }
        for (req.overrides.hidden) |id| try local.remove(arena, &id);
        if (req.overrides.clock_ms) |ms| {
            const clock_id = comptime blk: {
                var a: Id = @splat(0);
                a[31] = 6;
                break :blk a;
            };
            const raw = local.state().latest(&clock_id) orelse return reject(13, "the Clock object is not in the pre-state");
            const v = ObjectView.parse(raw) catch return reject(13, "Clock: bad object");
            if (v.contents_len != 40) return reject(13, "Clock: unexpected layout");
            const copy = try arena.dupe(u8, raw);
            std.mem.writeInt(u64, copy[v.contents_at + 32 ..][0..8], ms, .little);
            try local.map.put(arena, clock_id, .{ .version = v.version, .raw = copy });
        }
        const state = local.state();

        // ---- the TransactionData
        var td: types.TransactionDataV1 = undefined;
        var tx_raw: []const u8 = undefined;
        var reencode = false;
        switch (req.tx) {
            .data => |raw| {
                const all = bcs.decode(types.TransactionData, arena, raw) catch return reject(3, "invalid transaction: bad BCS TransactionData");
                td = switch (all) {
                    .V1 => |v| v,
                };
                tx_raw = raw;
            },
            .kind => |k| {
                const kind = bcs.decode(types.TransactionKind, arena, k.kind) catch return reject(3, "invalid transaction: bad BCS TransactionKind");
                const pay = try arena.alloc(@typeInfo(@TypeOf(td.gas_data.payment)).pointer.child, k.gas.payment.len);
                for (k.gas.payment, pay) |p, *q| q.* = .{ .{ .@"0" = .{ .@"0" = p.id } }, .{ .@"0" = p.version }, .{ .@"0" = .{ .@"0" = p.digest } } };
                td = .{
                    .kind = kind,
                    .sender = .{ .@"0" = k.sender },
                    .gas_data = .{
                        .payment = pay,
                        .owner = .{ .@"0" = k.gas.owner orelse k.sender },
                        .price = k.gas.price orelse env.rgp,
                        .budget = k.gas.budget orelse (env.cfg.max_tx_gas orelse 50_000_000_000),
                    },
                    .expiration = .None,
                };
                reencode = true;
            },
        }
        if (req.overrides.gas_budget) |b| {
            td.gas_data.budget = b;
            reencode = true;
        }
        if (req.overrides.gas_price) |p| {
            td.gas_data.price = p;
            reencode = true;
        }
        if (req.rebase and local.map.count() > 0 and try rebaseInputs(arena, local, &td)) reencode = true;
        if (reencode) tx_raw = try bcs.encodeAlloc(types.TransactionData, arena, &types.TransactionData{ .V1 = td });

        // ---- run (the same core as gRPC SimulateTransaction)
        const dev = req.mode == .dev_inspect;
        const allow_mock = dev or !(try core.addressBalancePaysGas(arena, &e.core, env, state, &td));
        const sim = switch (try core.run(&e.core, arena, env, state, tx_raw, td, allow_mock, dev)) {
            .ok => |s| s,
            .fail => |f| return reject(f.code, f.message),
            .unimplemented => |why| return reject(12, why),
        };
        const v2 = switch (sim.eff) {
            .V2 => |v| v,
            .V1 => return reject(12, "effects v1"),
        };
        const status: Status = switch (v2.status) {
            .Success => .success,
            .Failure => |f| .{ .failure = .{
                .kind = f.@"error",
                .command = f.command,
                .message = try rpc_exec.failure.simulationFailureMessage(arena, f),
                .name = rpc_exec.failure.kindName(f.@"error"),
            } },
        };
        var pool: serve.objset.Map = .empty;
        for (sim.objects) |raw| {
            const v = ObjectView.parse(raw) catch continue;
            try pool.put(arena, serve.objset.key(&v.id, v.version), raw);
        }
        return .{ .executed = .{
            .tx_data = tx_raw,
            .td = td,
            .digest = v2.transaction_digest.@"0".@"0",
            .status = status,
            .gas = .{
                .computation = v2.gas_used.computationCost,
                .storage = v2.gas_used.storageCost,
                .rebate = v2.gas_used.storageRebate,
                .non_refundable = v2.gas_used.nonRefundableStorageFee,
                .budget = td.gas_data.budget,
                .price = td.gas_data.price,
            },
            .effects = sim.effects,
            .eff = sim.eff,
            .events = sim.events,
            .object_changes = try objectChanges(arena, &v2, sim.written, &pool, state),
            .balance_changes = try serve.balance.derive(arena, sim.eff, &pool),
            .written = sim.written,
            .objects = sim.objects,
            .loaded = sim.loaded,
            .state = state,
        } };
    }
};

fn reject(code: u8, message: []const u8) Result {
    return .{ .rejected = .{ .code = code, .message = message } };
}

/// Owned and receiving inputs and gas coins whose id the overlay holds take its version and
/// digest. True when anything changed.
fn rebaseInputs(arena: Allocator, ov: *const Overlay, td: *types.TransactionDataV1) !bool {
    var changed = false;
    switch (td.kind) {
        .ProgrammableTransaction => |pt| {
            var inputs: ?[]types.CallArg = null;
            for (pt.inputs, 0..) |in, i| {
                const obj = switch (in) {
                    .Object => |o| o,
                    else => continue,
                };
                const ref = switch (obj) {
                    .ImmOrOwnedObject => |r| r,
                    .Receiving => |r| r,
                    .SharedObject => continue,
                };
                const e = switch (ov.own(&ref[0].@"0".@"0") orelse continue) {
                    .obj => |x| x,
                    .gone => continue,
                };
                const d = types.digest.objectDigest(e.raw);
                if (e.version == ref[1].@"0" and std.mem.eql(u8, &d, &ref[2].@"0".@"0")) continue;
                const nr: @TypeOf(ref) = .{ ref[0], .{ .@"0" = e.version }, .{ .@"0" = .{ .@"0" = d } } };
                if (inputs == null) inputs = try arena.dupe(types.CallArg, pt.inputs);
                inputs.?[i] = .{ .Object = switch (obj) {
                    .ImmOrOwnedObject => .{ .ImmOrOwnedObject = nr },
                    .Receiving => .{ .Receiving = nr },
                    .SharedObject => unreachable,
                } };
            }
            if (inputs) |ins| {
                td.kind = .{ .ProgrammableTransaction = .{ .inputs = ins, .commands = pt.commands } };
                changed = true;
            }
        },
        else => {},
    }
    var pay: ?[]@typeInfo(@TypeOf(td.gas_data.payment)).pointer.child = null;
    for (td.gas_data.payment, 0..) |r, i| {
        const e = switch (ov.own(&r[0].@"0".@"0") orelse continue) {
            .obj => |x| x,
            .gone => continue,
        };
        const d = types.digest.objectDigest(e.raw);
        if (e.version == r[1].@"0" and std.mem.eql(u8, &d, &r[2].@"0".@"0")) continue;
        if (pay == null) pay = try arena.dupe(@typeInfo(@TypeOf(td.gas_data.payment)).pointer.child, td.gas_data.payment);
        pay.?[i] = .{ r[0], .{ .@"0" = e.version }, .{ .@"0" = .{ .@"0" = d } } };
    }
    if (pay) |p| {
        td.gas_data.payment = p;
        changed = true;
    }
    return changed;
}

/// effects.object_changes() as the JSON-RPC ObjectChange list classifies them (accumulator
/// writes are not object changes).
fn objectChanges(arena: Allocator, v2: *const types.TransactionEffectsV2, written: []const exec.coin_ptb.Written, pool: *const serve.objset.Map, state: State) ![]const ObjectChange {
    var out: std.ArrayList(ObjectChange) = .empty;
    const lamport = v2.lamport_version.@"0";
    for (v2.changed_objects) |c| {
        const id = c[0].@"0".@"0";
        const ch = c[1];
        const in_v: ?u64 = switch (ch.input_state) {
            .NotExist => null,
            .Exist => |x| x[0][0].@"0",
        };
        const kind: ChangeKind = switch (ch.output_state) {
            .AccumulatorWriteV1 => continue,
            .PackageWrite => .published,
            .ObjectWrite => if (in_v != null) .mutated else switch (ch.id_operation) {
                .Created => .created,
                else => .unwrapped,
            },
            .NotExist => if (in_v != null) switch (ch.id_operation) {
                .Deleted => .deleted,
                else => .wrapped,
            } else .unwrapped_then_deleted,
        };
        var after: ?[]const u8 = null;
        for (written) |w| if (std.mem.eql(u8, &w.id, &id)) {
            after = w.bytes;
            break;
        };
        const before: ?[]const u8 = if (in_v) |v| pool.get(serve.objset.key(&id, v)) orelse state.at(&id, v) else null;
        const version: u64 = switch (ch.output_state) {
            .PackageWrite => |p| p[0].@"0",
            .NotExist => in_v orelse lamport,
            else => lamport,
        };
        try out.append(arena, .{ .kind = kind, .id = id, .version = version, .object = after, .previous = before });
    }
    return out.items;
}

/// A later chain step sees this step's writes; deleted and wrapped objects disappear.
fn applyOutputs(arena: Allocator, ov: *Overlay, x: *const Executed) !void {
    for (x.written) |w| try ov.put(arena, w.bytes);
    for (x.object_changes) |c| switch (c.kind) {
        .deleted, .wrapped, .unwrapped_then_deleted => try ov.remove(arena, &c.id),
        else => {},
    };
}

/// sui-node's SimulateTransactionResponse for an executed simulation, byte for byte, under a
/// read mask (`"*"` for everything). Command outputs and suggested_gas_price are not included.
pub fn grpcResponse(e: *const Engine, arena: Allocator, env: *const EpochEnv, x: *const Executed, mask: []const u8) ![]const u8 {
    var tree = try serve.mask.Tree.parse(arena, mask);
    const td_all: types.TransactionData = .{ .V1 = x.td };
    const r = try rpc_exec.render.response(arena, &e.core, env, x.state, tree.mask(), .{
        .tx_raw = x.tx_data,
        .td = td_all,
        .tx_digest = types.digest.transactionDataDigest(x.tx_data),
        .effects = x.effects,
        .eff = x.eff,
        .events = x.events,
        .objects = x.objects,
        .loaded = x.loaded,
    });
    return switch (r) {
        .ok => |b| b,
        .unimplemented => error.Unimplemented,
    };
}

/// Splits the package-cache budget (`--exec-cache-mb`) over every thread that holds package
/// caches (simulation workers plus, in execute mode, the executor's threads), two epochs' caches
/// per thread, as execute mode does: a thread's cache is dropped and rebuilt when it outgrows its
/// share (exec `pkgs.max_cache_bytes`). The process-wide parsed-package table, when on, is one
/// table for all of them: its part comes out of the budget once (exec `pkgs.setBudget`).
pub fn setCacheBudget(cache_mb: u32, threads: usize) void {
    const total: usize = @as(usize, cache_mb) << 20;
    exec.ptb.pkgs.setBudget(total, @max(threads, 1) * 2);
}

test "the cache budget is shared by every caching thread" {
    const pkgs = exec.ptb.pkgs;
    pkgs.readEnv();
    const saved = .{ pkgs.max_cache_bytes, pkgs.shared_enabled, pkgs.shared.max_bytes, pkgs.shared_budget };
    defer {
        pkgs.max_cache_bytes = saved[0];
        pkgs.shared_enabled = saved[1];
        pkgs.shared.max_bytes = saved[2];
        pkgs.shared_budget = saved[3];
    }
    pkgs.shared_enabled = false;
    setCacheBudget(3072, 12);
    try std.testing.expectEqual(@as(usize, 128) << 20, pkgs.max_cache_bytes);
    setCacheBudget(64, 16);
    try std.testing.expectEqual(@as(usize, 32) << 20, pkgs.max_cache_bytes);
    // With the parsed-package table on, its part (512 MiB here) is counted once and the
    // thread caches share the rest: 24 caches of 2560 MiB.
    pkgs.shared_enabled = true;
    pkgs.shared_budget = 512 << 20;
    setCacheBudget(3072, 12);
    try std.testing.expectEqual(@as(usize, 512) << 20, pkgs.shared.max_bytes);
    try std.testing.expectEqual((@as(usize, 2560) << 20) / 24, pkgs.max_cache_bytes);
    try std.testing.expect(pkgs.shared.max_bytes + 24 * pkgs.max_cache_bytes <= @as(usize, 3072) << 20);
}

/// Frees this thread's package caches and VM runtimes (call as a worker exits).
pub fn releaseThreadCaches() void {
    exec.ptb.pkgs.releaseThreadCaches();
    exec.system.movecall.releaseThreadCaches();
}

/// Process-wide verifier sharing: packages verified once, and how often a load skipped it.
pub fn verifiedStats() struct { packages: usize, hits: u64, misses: u64 } {
    const v = &@import("move_vm").loader.verified;
    return .{ .packages = v.count(), .hits = v.hits.load(.monotonic), .misses = v.misses.load(.monotonic) };
}

fn testGasCoin(arena: Allocator, id: Id, version: u64, owner: Id) ![]const u8 {
    const buf = try arena.alloc(u8, 3 + 8 + 1 + 40 + 1 + 32 + 33 + 8);
    @memset(buf, 0);
    buf[1] = 1;
    buf[2] = 1;
    std.mem.writeInt(u64, buf[3..11], version, .little);
    buf[11] = 40;
    @memcpy(buf[12..44], &id);
    std.mem.writeInt(u64, buf[44..52], 1000, .little);
    @memcpy(buf[53..85], &owner);
    buf[85] = 32;
    return buf;
}

test "rebase moves owned inputs and gas coins to the overlay's versions" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var m: rpc_exec.state.MapState = .{};
    const coin: Id = @splat(0x11);
    const other: Id = @splat(0x22);
    const me: Id = @splat(0x33);
    var ov = Overlay.init(m.state());
    const raw = try testGasCoin(a, coin, 7, me);
    try ov.put(a, raw);
    const zero: Id = @splat(0);
    const inputs = [_]types.CallArg{
        .{ .Object = .{ .ImmOrOwnedObject = .{ .{ .@"0" = .{ .@"0" = coin } }, .{ .@"0" = 3 }, .{ .@"0" = .{ .@"0" = zero } } } } },
        .{ .Object = .{ .ImmOrOwnedObject = .{ .{ .@"0" = .{ .@"0" = other } }, .{ .@"0" = 5 }, .{ .@"0" = .{ .@"0" = zero } } } } },
    };
    const pay = [_]@typeInfo(@TypeOf(@as(types.GasData, undefined).payment)).pointer.child{.{ .{ .@"0" = .{ .@"0" = coin } }, .{ .@"0" = 3 }, .{ .@"0" = .{ .@"0" = zero } } }};
    var td: types.TransactionDataV1 = .{
        .kind = .{ .ProgrammableTransaction = .{ .inputs = &inputs, .commands = &.{} } },
        .sender = .{ .@"0" = me },
        .gas_data = .{ .payment = &pay, .owner = .{ .@"0" = me }, .price = 1000, .budget = 1 },
        .expiration = .None,
    };
    try std.testing.expect(try rebaseInputs(a, &ov, &td));
    const ins = td.kind.ProgrammableTransaction.inputs;
    try std.testing.expectEqual(@as(u64, 7), ins[0].Object.ImmOrOwnedObject[1].@"0");
    try std.testing.expectEqualSlices(u8, &types.digest.objectDigest(raw), &ins[0].Object.ImmOrOwnedObject[2].@"0".@"0");
    try std.testing.expectEqual(@as(u64, 5), ins[1].Object.ImmOrOwnedObject[1].@"0");
    try std.testing.expectEqual(@as(u64, 7), td.gas_data.payment[0][1].@"0");
    // the caller's input array is not modified
    try std.testing.expectEqual(@as(u64, 3), inputs[0].Object.ImmOrOwnedObject[1].@"0");
    try std.testing.expect(!try rebaseInputs(a, &ov, &td));
    // an override at the same version with other contents takes the override's digest
    const raw2 = try a.dupe(u8, raw);
    raw2[44] ^= 1;
    try ov.put(a, raw2);
    try std.testing.expect(try rebaseInputs(a, &ov, &td));
    try std.testing.expectEqualSlices(u8, &types.digest.objectDigest(raw2), &td.kind.ProgrammableTransaction.inputs[0].Object.ImmOrOwnedObject[2].@"0".@"0");
}

test "a chain step's deletions and writes reach the next step" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var m: rpc_exec.state.MapState = .{};
    const me: Id = @splat(0x33);
    const x: Id = @splat(1);
    const y: Id = @splat(2);
    var ov = Overlay.init(m.state());
    const wx = try testGasCoin(a, x, 9, me);
    var ex: Executed = undefined;
    ex.written = &.{.{ .id = x, .bytes = wx }};
    ex.object_changes = &.{ .{ .kind = .mutated, .id = x, .version = 9 }, .{ .kind = .deleted, .id = y, .version = 4 } };
    try applyOutputs(a, &ov, &ex);
    const s = ov.state();
    try std.testing.expectEqualSlices(u8, wx, s.latest(&x).?);
    try std.testing.expect(s.latest(&y) == null);
    try std.testing.expect(ov.own(&y).? == .gone);
}
