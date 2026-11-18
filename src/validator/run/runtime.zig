//! `deepwave-validator run --config validator.yaml`: the integrated validator on a committee that
//! Mysten's `sui genesis` described (the same inputs `seat` reads: the seat's validator.yaml and
//! genesis.blob). One process holds the signer, the execution store, the checkpoint store and the
//! randomness network; everything epoch-bound is built per epoch by `Epoch.create` and torn down
//! at the switch (`epoch.manager.EpochManager` drives `start`/`stop` through `Components`, the
//! certified last checkpoint of an epoch triggers it through `epoch.driver.Driver`).
//!
//! Per epoch:
//!   consensus (ConsensusAuthority: real Mysticeti core, net, LogStore under <db>/consensus)
//!     -> authority (TxValidator votes, adapter = TransactionSource, handler = CommitSink, the
//!        commit group log <db>/validator/epoch-N/authority.log)
//!     -> execution (run/runner.zig over the exec store, pumped on the handler thread)
//!     -> checkpoints (builder over run/ckpt_env.zig, Output signs through the Signer, Aggregator
//!        certifies from sequenced CheckpointSignatureV2, the driver switches on the last one)
//!   randomness (Manager restored from the commit group, DKG through consensus, partial
//!   signatures over anemo: run/randomness_net.zig), JWK (aggregator restored from the group;
//!   no fetching on a local committee), the reconfig state (run/epoch_control.zig).
//!
//! Threads per epoch: the consensus authority's own; `handler` (Authority.step: commits, then
//! execution; then the randomness bookkeeping); `checkpoints` (builder + aggregator).
//!
//! Safety: the gate decides first (local committees only, or `--sign-network` naming this chain);
//! every block and checkpoint signature goes through the Signer's watermarks.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const consensus = @import("consensus");
const consensus_net = @import("consensus_net");
const checkpoint = @import("checkpoint");
const serve = @import("serve");
const iface = @import("../iface.zig");
const gate = @import("../gate.zig");
const signer_mod = @import("../signer.zig");
const keys = @import("../keys/root.zig");
const seat = @import("../seat.zig");
const vnode = @import("../node.zig");
const authority = @import("../authority/root.zig");
const env_mod = authority.env;
const state_mod = authority.state;
const checkpoints = @import("../checkpoints/root.zig");
const randomness = @import("../randomness/root.zig");
const jwk = @import("../jwk/root.zig");
const zklogin = @import("zklogin.zig");
const epoch_mod = @import("../epoch/root.zig");
const reconfig = epoch_mod.reconfig;
const emanager = epoch_mod.manager;
const driver_mod = epoch_mod.driver;
const genesis_mod = @import("genesis.zig");
const exec_store = @import("exec_store.zig");
const objects = @import("objects.zig");
const runner_mod = @import("runner.zig");
const ckpt_env = @import("ckpt_env.zig");
const ckpt_store = @import("ckpt_store.zig");
const randomness_net = @import("randomness_net.zig");
const epoch_control = @import("epoch_control.zig");
const catchup = @import("catchup.zig");
const p2p_mod = @import("p2p.zig");
const state_sync = @import("state_sync.zig");
const rpc_exec = @import("rpc_exec");
const net = @import("net");
const api = @import("../api/root.zig");
const submit_mod = authority.submit;
const deny_manager = authority.deny_manager;
const SuiErrorKind = api.backend.SuiErrorKind;
const dwire = api.wire.driver_wire;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const log = std.log.scoped(.validator);

pub const usage =
    \\deepwave-validator run --config FILE [--genesis FILE] [--db DIR] [--duration-s N] [--sign-network NET]
    \\  --config FILE      the validator.yaml Mysten's `sui genesis` wrote for this seat
    \\  --genesis FILE     genesis.blob (default: the yaml's genesis-file-location)
    \\  --db DIR           zui stores, signer watermarks (default: <db-path>-zui)
    \\  --duration-s N     stop after N seconds (default: until SIGINT/SIGTERM)
    \\  --no-randomness    do not start the randomness network (DKG still runs through consensus)
    \\  --sign-network NET mainnet|testnet|<8-hex chain id>: sign on that public network (must match genesis)
    \\  --no-catchup       do not catch up through state sync (StateSync is still served)
    \\  --zui-catchup      accepted for older scripts (catch-up over StateSync is on by default)
    \\
;

pub const Error = error{ BadArguments, BadConfig, BadGenesis, Refused, NotAMember, Io, OutOfMemory, Startup };

/// True when `args` are for this runtime (a Mysten validator.yaml without `--chain-id`); the
/// scaffold of node.zig keeps `--localnet` and `--config --chain-id --node-store`.
pub fn wants(args: []const []const u8) bool {
    var has_config = false;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--chain-id") or std.mem.eql(u8, a, "--localnet")) return false;
        if (std.mem.eql(u8, a, "--config")) has_config = true;
    }
    return has_config;
}

// ------------------------------------------------------------------ process level

var stop_flag: Atomic(bool) = .init(false);
fn onSignal(_: std.posix.SIG) callconv(.c) void {
    stop_flag.store(true, .release);
}

fn monoMs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}
fn wallMs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}
fn wallUs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.us_per_s + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_us;
}
fn sleepMs(ms: u64) void {
    var ts: std.c.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = std.c.nanosleep(&ts, &ts);
}

/// A blocking lock for the runtime's coarse sections (epoch switch, FIFO): spins briefly, then
/// sleeps in 50 us steps, so a long epoch build does not burn a core in every waiter.
const Lock = struct {
    m: std.atomic.Mutex = .unlocked,
    fn lock(l: *Lock) void {
        var i: u32 = 0;
        while (!l.m.tryLock()) : (i += 1) {
            if (i < 64) {
                std.atomic.spinLoopHint();
            } else {
                var ts: std.c.timespec = .{ .sec = 0, .nsec = 50_000 };
                _ = std.c.nanosleep(&ts, &ts);
            }
        }
    }
    fn unlock(l: *Lock) void {
        l.m.unlock();
    }
};

pub const Runtime = struct {
    gpa: Allocator,
    io: Io,
    arena: std.heap.ArenaAllocator,
    db: []const u8,
    genesis: genesis_mod.Genesis,
    own_index_genesis: u32,
    own_name: [96]u8,
    license: gate.License,
    signer: *signer_mod.Signer,
    exec: exec_store.ExecStore,
    ckpt: ckpt_store.CkptStore,
    runner: runner_mod.Runner,
    /// The seat's one anemo endpoint (run/p2p.zig) and its StateSync/Discovery services.
    p2p: ?*p2p_mod.P2p = null,
    ssvc: ?*state_sync.Service = null,
    randnet: ?*randomness_net.RandomnessNet = null,
    emgr: emanager.EpochManager,
    driver: driver_mod.Driver,
    clock: consensus_net.testkit.RealClock,
    /// The epoch running now (written by the driver thread under `epoch_mu`).
    epoch_mu: Lock = .{},
    current: ?*Epoch = null,
    boots: u64 = 0,
    failed: Atomic(bool) = .init(false),
    api_epoch: Atomic(u64) = .init(0),
    tracer: ?*@import("../latency/root.zig").tracer.StageTracer = null,
    /// This binary's built-in framework (`epoch.packages.builtIn` at the max supported version).
    builtin: []const epoch_mod.packages.Package = &.{},
    api_server: ?*api.Server = null,
    metrics: api.metrics.Registry = undefined,
    node_backend: api.NodeBackend = undefined,
    /// Catch-up over state sync (run/catchup.zig, on unless `--no-catchup`), and the highest
    /// epoch whose checkpoint builder is frozen because catch-up applied that epoch from
    /// certified checkpoints (-1: none).
    catchup_on: bool = true,
    ckpt_frozen: Atomic(i64) = .init(-1),
    /// A certified summary `syncLoop` fetched from a peer, for the ckpt thread (gpa-owned).
    pulled_mu: Lock = .{},
    pulled: ?[]u8 = null,
    /// `start_jwk_updater`: provider names of this chain (`zklogin-oauth-providers`, defaults
    /// when absent) and `jwk-fetch-interval-seconds` in ms.
    jwk_providers: []const []const u8 = &.{},
    jwk_interval_ms: u64 = jwk.updater.default_fetch_interval_ms,
    /// The transaction-deny config shared through consensus (process-wide, as the AuthorityState's
    /// TransactionDenyConfigManager): publishes the effective config to `txdeny.effective_slot`.
    deny: ?*deny_manager.Manager = null,
    /// sui-node's `broadcast_on_startup`: the first epoch this process runs as a member with
    /// `share_transaction_deny_config_in_consensus` on is the startup one.
    deny_startup: bool = true,

    fn putPulled(rt: *Runtime, bytes: []const u8) void {
        const own = rt.gpa.dupe(u8, bytes) catch return;
        rt.pulled_mu.lock();
        defer rt.pulled_mu.unlock();
        if (rt.pulled) |old| rt.gpa.free(old);
        rt.pulled = own;
    }

    fn takePulled(rt: *Runtime) ?[]u8 {
        rt.pulled_mu.lock();
        defer rt.pulled_mu.unlock();
        defer rt.pulled = null;
        return rt.pulled;
    }

    fn genesisValidator(rt: *const Runtime, name: *const [96]u8) ?*const seat.GenesisValidator {
        for (rt.genesis.validators) |*v| if (std.mem.eql(u8, &v.protocol_pubkey, name)) return v;
        return null;
    }

    // ---- RandomnessSource for the runner: the round's full signature from the network

    fn randomBytes(ctx: *anyopaque, arena: Allocator, epoch: u64, round: u64) ?[]const u8 {
        const rt: *Runtime = @ptrCast(@alignCast(ctx));
        const rn = rt.randnet orelse return null;
        const sig = rn.fullSig(epoch, round) orelse return null;
        return arena.dupe(u8, &sig) catch null;
    }

    fn fullSigSink(ctx: *anyopaque, epoch: u64, round: u64, sig: []const u8) void {
        _ = .{ ctx, sig };
        log.debug("randomness epoch {d} round {d} aggregated", .{ epoch, round });
    }

    /// The running epoch, pinned for an API call (unpin with `e.api_users.fetchSub(1)`), or null
    /// between epochs.
    fn pin(rt: *Runtime) ?*Epoch {
        rt.epoch_mu.lock();
        defer rt.epoch_mu.unlock();
        const e = rt.current orelse return null;
        if (e.stop.load(.acquire)) return null;
        _ = e.api_users.fetchAdd(1, .acq_rel);
        return e;
    }
    fn unpin(e: *Epoch) void {
        _ = e.api_users.fetchSub(1, .acq_rel);
    }

    // ---- epoch.manager Components

    fn compStart(ctx: *anyopaque, es: *reconfig.EpochState, t: *const emanager.Transition) error{ComponentFailed}!void {
        const rt: *Runtime = @ptrCast(@alignCast(ctx));
        const e = Epoch.create(rt, es, t.*) catch |err| {
            log.err("epoch {d}: start failed: {s} (runner: {s})", .{ es.info.epoch, @errorName(err), rt.runner.lastError() });
            rt.failed.store(true, .release);
            return error.ComponentFailed;
        };
        rt.epoch_mu.lock();
        rt.current = e;
        rt.epoch_mu.unlock();
        rt.api_epoch.store(es.info.epoch, .release);
        rt.boots += 1;
        std.debug.print("deepwave-validator: epoch {d} started (protocol {d}, committee {d}, own index {?d})\n", .{ es.info.epoch, es.info.protocol_version, es.info.committee.len, es.info.own_index });
    }
    fn compStop(ctx: *anyopaque, epoch: u64) void {
        const rt: *Runtime = @ptrCast(@alignCast(ctx));
        rt.epoch_mu.lock();
        const e = rt.current;
        rt.current = null;
        rt.epoch_mu.unlock();
        if (e) |x| {
            // API calls that pinned this epoch finish their current poll step first
            x.stop.store(true, .release);
            while (x.api_users.load(.acquire) != 0) sleepMs(1);
            x.destroy();
            std.debug.print("deepwave-validator: epoch {d} stopped\n", .{epoch});
        }
    }
    const comp_vt: emanager.Components.VTable = .{ .start = compStart, .stop = compStop };

    /// driver.ParamsSource: the next epoch's system parameters from the executed ChangeEpoch.
    fn paramsGet(ctx: *anyopaque, next_epoch: u64) ?driver_mod.Params {
        const rt: *Runtime = @ptrCast(@alignCast(ctx));
        const st = systemState(&rt.exec) orelse return null;
        const sum = serve.sysstate.summary(st) catch return null;
        if (sum.epoch != next_epoch) return null;
        const p = serve.sysstate.epochParams(st) catch return null;
        return .{ .epoch_duration_ms = p.epoch_duration_ms, .safe_mode = p.safe_mode };
    }
};

// ------------------------------------------------------------------ Validator API backend

/// SubmitTransaction's `get_executed_effects` step over the exec store (every epoch): a
/// transaction that already executed answers `Executed`, before its consumed inputs are checked.
/// Without it a client whose WaitForEffects was cut (that seat killed) after the transaction
/// executed is rejected on the spent gas version by every seat and never asks for the effects.
pub fn submitHooks(exec: *exec_store.ExecStore) submit_mod.Hooks {
    const H = struct {
        fn executedEffects(ctx: *anyopaque, digest: *const [32]u8) ?[32]u8 {
            const st: *exec_store.ExecStore = @ptrCast(@alignCast(ctx));
            return if (st.executed(digest)) |x| x.effects_digest else null;
        }
    };
    return .{ .ctx = exec, .executed_effects = H.executedEffects };
}


/// `api.backend.Authority` over the running epoch: SubmitTransaction and WaitForEffects go to the
/// epoch's `authority.Submit` / `WaitForEffects`; reads are answered by the exec store. The epoch
/// lock is held only for one non-blocking step at a time, so an epoch switch is never held up by
/// a waiting client (it then sees ValidatorHaltedAtEpochEnd or an expired position).
const ApiBackend = struct {
    fn rtOf(ctx: *anyopaque) *Runtime {
        return @ptrCast(@alignCast(ctx));
    }
    fn halted() SuiErrorKind {
        return .ValidatorHaltedAtEpochEnd;
    }
    fn rejectedBytes(arena: Allocator, text: []const u8) ?[]const u8 {
        const k: SuiErrorKind = .{ .GenericAuthorityError = .{ .@"error" = .{ .@"0" = text } } };
        return bcs.encodeAlloc(SuiErrorKind, arena, &k) catch null;
    }
    fn details(rt: *Runtime, arena: Allocator, digest: *const [32]u8) ?dwire.ExecutedData {
        const fx = rt.exec.effects(digest) orelse return null;
        return .{ .effects = arena.dupe(u8, fx) catch return null, .events = if (rt.exec.events(digest)) |ev| arena.dupe(u8, ev) catch null else null };
    }

    fn submit(ctx: *anyopaque, arena: Allocator, req: api.backend.SubmitRequest) api.backend.Result([]const dwire.RawSubmitResult) {
        const rt = rtOf(ctx);
        if (req.invalid_submit_type) |v| return .{ .err = .{ .GrpcMessageDeserializeError = .{
            .type_info = .{ .@"0" = "SubmitTxRequest" },
            .@"error" = .{ .@"0" = std.fmt.allocPrint(arena, "unknown enumeration value {d}", .{v}) catch "unknown enumeration value" },
        } } };
        const e = rt.pin() orelse return .{ .err = halted() };
        defer Runtime.unpin(e);
        var failure: submit_mod.Failure = undefined;
        const st: submit_mod.SubmitType = if (req.ping) .ping else if (req.soft_bundle) .soft_bundle else .default;
        const resp = e.auth.submit.handle(arena, .{ .submit_type = st, .transactions = req.transactions }, &failure) catch |err| switch (err) {
            error.OutOfMemory => return .{ .err = api.backend.storageError("out of memory") },
            error.Failed => return .{ .err = switch (failure.kind) {
                error.ValidatorHalted => halted(),
                else => .{ .GenericAuthorityError = .{ .@"error" = .{ .@"0" = failure.message } } },
            } },
        };
        const out = arena.alloc(dwire.RawSubmitResult, resp.results.len) catch return .{ .err = api.backend.storageError("out of memory") };
        for (resp.results, out) |r, *o| o.* = switch (r) {
            .submitted => |ticket| blk: {
                // the position exists once the next proposal carried the transaction
                const t0 = monoMs();
                while (true) {
                    if (e.auth.adapter.positionOf(ticket)) |pos| {
                        const buf = arena.create([50]u8) catch return .{ .err = api.backend.storageError("out of memory") };
                        break :blk .{ .Submitted = submit_mod.encodePosition(buf, e.epoch, pos) };
                    }
                    if (monoMs() - t0 > 5_000 or e.stop.load(.acquire)) break :blk .{ .Rejected = rejectedBytes(arena, "not proposed in time") orelse "" };
                    sleepMs(2);
                }
            },
            .executed => |x| .{ .Executed = .{ .effects_digest = x.effects_digest, .details = null } },
            .rejected => |text| .{ .Rejected = rejectedBytes(arena, text) orelse "" },
        };
        return .{ .ok = out };
    }

    fn waitForEffects(ctx: *anyopaque, arena: Allocator, req: api.backend.WaitRequest) api.backend.Result(dwire.RawWaitResponse) {
        const rt = rtOf(ctx);
        const t0 = monoMs();
        var first_epoch: ?u64 = null;
        while (true) {
            {
                // executed in any epoch: the effects are in the exec store
                if (req.transaction_digest) |d| if (!req.ping) if (rt.exec.executed(&d)) |ed| {
                    return .{ .ok = .{ .Executed = .{ .effects_digest = ed.effects_digest, .details = if (req.include_details) details(rt, arena, &d) else null } } };
                };
                const e = rt.pin() orelse {
                    if (first_epoch) |fe| return .{ .ok = .{ .Expired = .{ .epoch = fe, .round = null } } };
                    return .{ .err = halted() };
                };
                defer Runtime.unpin(e);
                if (first_epoch == null) first_epoch = e.epoch;
                if (first_epoch.? != e.epoch) return .{ .ok = .{ .Expired = .{ .epoch = first_epoch.?, .round = null } } };
                switch (e.auth.wait.poll(arena, .{ .digest = req.transaction_digest, .consensus_position = req.consensus_position, .include_details = req.include_details, .ping = req.ping })) {
                    .ready => |r| switch (r) {
                        .executed => |x| {
                            var det: ?dwire.ExecutedData = null;
                            if (x.include_details) {
                                if (req.transaction_digest) |d| det = details(rt, arena, &d);
                            }
                            return .{ .ok = .{ .Executed = .{ .effects_digest = x.effects_digest, .details = det } } };
                        },
                        .rejected => |reason| return .{ .ok = .{ .Rejected = if (reason) |t| rejectedBytes(arena, t) else null } },
                        .expired => |x| return .{ .ok = .{ .Expired = .{ .epoch = x.epoch, .round = x.round } } },
                    },
                    .invalid => |text| return .{ .err = .{ .GenericAuthorityError = .{ .@"error" = .{ .@"0" = text } } } },
                    .lagging => |l| if (monoMs() - t0 >= req.deadline_ms) return .{ .err = .{ .ValidatorConsensusLagging = .{ .round = l.round, .last_committed_round = @intCast(@min(l.last_committed_round, std.math.maxInt(u32))) } } },
                    .pending => {},
                }
            }
            if (monoMs() - t0 >= req.deadline_ms) return .{ .err = .{ .TimeoutError = {} } };
            sleepMs(5);
        }
    }

    fn health(ctx: *anyopaque) api.wire.Health {
        const rt = rtOf(ctx);
        const e = rt.pin() orelse return .{};
        defer Runtime.unpin(e);
        return .{
            .pending_certificates = e.auth.adapter.pendingUser(),
            .consensus_round = if (e.cons) |c| c.lastProposedRound() else 0,
            .checkpoint_sequence = rt.ckpt.highestCertified() orelse 0,
        };
    }

    fn authority_(rt: *Runtime) api.backend.Authority {
        return .{ .ctx = rt, .submit = submit, .wait_for_effects = waitForEffects, .health = health };
    }
};

/// `get_stored_execution_time_observations`: the BCS StoredExecutionTimeObservations chunks the
/// previous epoch's end stored in the system state's `extra_fields` (key 1: the chunk count,
/// `ExecutionTimeObservationChunkKey { chunk_index }`: each chunk as vector<u8>), in chunk
/// order. None when the state is V1 or the count is missing (Rust logs and loads nothing).
pub fn storedObservationChunks(arena: Allocator, st: *exec_store.ExecStore) Allocator.Error![]const []const u8 {
    const exec = @import("exec");
    const s = systemState(st) orelse return &.{};
    if (s.version != 2) return &.{};
    const bag = serve.sysstate.extraFieldsId(s) catch return &.{};
    const count_raw = st.latest(&serve.sysstate.u64FieldId(&bag, 1)) orelse return &.{};
    const count_c = (exec.objects.ObjectView.parse(count_raw) catch return &.{}).contents();
    if (count_c.len < 48) return &.{};
    const count = std.mem.readInt(u64, count_c[40..48], .little);
    var out: std.ArrayList([]const u8) = .empty;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const id = chunkFieldId(&bag, i);
        const raw = st.latest(&id) orelse return &.{};
        const c = (exec.objects.ObjectView.parse(raw) catch return &.{}).contents();
        // Field<ExecutionTimeObservationChunkKey, vector<u8>>: id, chunk_index, value
        if (c.len < 40) return &.{};
        var r = bcs.Reader.init(c[40..]);
        const bytes = r.bytes(r.length() catch return &.{}) catch return &.{};
        try out.append(arena, try arena.dupe(u8, bytes));
    }
    return out.items;
}

/// `derive_dynamic_field_id(bag, 0x3::sui_system_state_inner::ExecutionTimeObservationChunkKey,
/// bcs(chunk_index))`.
pub fn chunkFieldId(bag: *const [32]u8, chunk_index: u64) [32]u8 {
    const hash = @import("hash");
    const module = "sui_system_state_inner";
    const name = "ExecutionTimeObservationChunkKey";
    var k: [8]u8 = undefined;
    std.mem.writeInt(u64, &k, chunk_index, .little);
    var klen: [8]u8 = undefined;
    std.mem.writeInt(u64, &klen, 8, .little);
    var sys: [32]u8 = @splat(0);
    sys[31] = 3;
    // TypeTag::Struct (7), address, module, name, no type params
    return hash.blake2b256(&.{ &[_]u8{0xf0}, bag, &klen, &k, &[_]u8{7}, &sys, &[_]u8{module.len}, module, &[_]u8{name.len}, name, &[_]u8{0} });
}

/// The live system state of the exec store (`0x5` wrapper and its versioned inner field).
pub fn systemState(st: *exec_store.ExecStore) ?serve.sysstate.State {
    const hash = @import("hash");
    const exec = @import("exec");
    const sys_id: [32]u8 = runner_mod.objectId(5);
    const wrapper = st.latest(&sys_id) orelse return null;
    const wv = exec.objects.ObjectView.parse(wrapper) catch return null;
    const version = serve.sysstate.wrapperVersion(wv.contents()) orelse return null;
    var k: [8]u8 = undefined;
    std.mem.writeInt(u64, &k, version, .little);
    var klen: [8]u8 = undefined;
    std.mem.writeInt(u64, &klen, 8, .little);
    const field = hash.blake2b256(&.{ &[_]u8{0xf0}, &sys_id, &klen, &k, &[_]u8{2} });
    const inner = st.latest(&field) orelse return null;
    const iv = exec.objects.ObjectView.parse(inner) catch return null;
    return .{ .version = version, .inner = serve.sysstate.innerOfField(iv.contents()) orelse return null };
}

// ------------------------------------------------------------------ one epoch

const Epoch = struct {
    rt: *Runtime,
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    es: *reconfig.EpochState,
    epoch: u64,
    cfg: *const protocol.ProtocolConfig,
    ectx: runner_mod.EpochCtx,
    control: epoch_control.Control,
    names: []iface.AuthorityName,
    stakes: []u64,
    own_index: ?u32,
    obj_state: objects.State,
    sig_env: @import("sig").user.UserSigEnv,
    check_env: authority.checker.Env,
    /// `SignatureVerifier.jwks` of the epoch (zkLogin): epoch-start active set, then every
    /// executed AuthenticatorStateUpdate.
    jwk_map: zklogin.JwkMap,
    rmgr: ?*randomness.Manager = null,
    radapter: randomness.hooks.Adapter = undefined,
    jagg: jwk.aggregator.Aggregator,
    jadapter: jwk.hooks.Adapter = undefined,
    /// `node_role.is_validator() && authenticator_state_enabled()`: the JWK updater submits.
    jwk_enabled: bool = false,
    ccommittee: checkpoint.Committee,
    vsigner: checkpoints.output.ValidatorSigner,
    output: checkpoints.Output = undefined,
    cenv: ckpt_env.CkptEnv = undefined,
    /// Sequenced CapabilityNotificationV2 / deny-config messages into the epoch store.
    ehooks: epoch_mod.hooks.Hooks = undefined,
    builder: checkpoints.Builder = undefined,
    aggregator: checkpoints.Aggregator = undefined,
    pending_fifo: Fifo = .{},
    auth: *authority.authority.Authority = undefined,
    context: consensus.Context = undefined,
    cons: ?*consensus_net.authority_node.ConsensusAuthority = null,
    stop: Atomic(bool) = .init(false),
    /// Validator API calls holding this epoch (`Runtime.pin`); destroy waits for zero.
    api_users: Atomic(u32) = .init(0),
    handler_thread: ?std.Thread = null,
    ckpt_thread: ?std.Thread = null,
    // randomness bookkeeping (handler thread)
    randnet_epoch_set: bool = false,
    partials_sent_through: u64 = 0,
    completed_through: u64 = 0,
    // checkpoint log lines (ckpt thread): highest seq already printed
    logged_built: u64 = 0,
    logged_certified: u64 = 0,
    stats: struct { steps: Atomic(u64) = .init(0), built: Atomic(u64) = .init(0), certified: Atomic(u64) = .init(0) } = .{},

    /// Checkpoint seqs pushed to the builder, in order: built ones are acknowledged to the handler.
    const Fifo = struct {
        mu: Lock = .{},
        seqs: std.ArrayList(u64) = .empty,
    };

    fn create(rt: *Runtime, es: *reconfig.EpochState, t: emanager.Transition) !*Epoch {
        const gpa = rt.gpa;
        const info = es.info;
        const e = try gpa.create(Epoch);
        errdefer gpa.destroy(e);
        e.* = .{
            .rt = rt,
            .gpa = gpa,
            .arena = .init(gpa),
            .es = es,
            .epoch = info.epoch,
            .cfg = undefined,
            .ectx = undefined,
            .control = epoch_control.Control.init(es, t.epoch_duration_ms),
            .names = undefined,
            .stakes = undefined,
            .own_index = info.own_index,
            .obj_state = .{ .store = &rt.exec },
            .sig_env = undefined,
            .check_env = undefined,
            .jwk_map = zklogin.JwkMap.init(gpa),
            .jagg = undefined,
            .ccommittee = undefined,
            .vsigner = try checkpoints.output.ValidatorSigner.init(rt.signer),
        };
        errdefer e.arena.deinit();
        const a = e.arena.allocator();
        e.cfg = protocol.get(info.protocol_version, .unknown) catch return error.UnsupportedProtocol;
        const sum = serve.sysstate.summary(systemState(&rt.exec) orelse return error.NoSystemState) catch return error.NoSystemState;
        // The epoch's reference gas price is kept next to its authority log: after a crash between
        // executing the epoch's ChangeEpoch and certifying its last checkpoint, the exec store
        // already shows the next epoch's system state while this epoch must still finish.
        var rgp_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const rgp_path = try std.fmt.bufPrint(&rgp_path_buf, "{s}/validator/epoch-{d}/rgp", .{ rt.db, info.epoch });
        const rgp: u64 = if (sum.epoch == info.epoch) blk: {
            writeRgp(rt, info.epoch, sum.reference_gas_price) catch return error.Io;
            break :blk sum.reference_gas_price;
        } else if (sum.epoch == info.epoch + 1) blk: {
            const raw = (keys.fsutil.readAll(gpa, rt.io, rgp_path, 64) catch return error.Io) orelse {
                log.err("exec store is at the end of epoch {d} and its gas price record is missing", .{info.epoch});
                return error.EpochMismatch;
            };
            defer gpa.free(raw);
            if (raw.len != 8) return error.Corrupt;
            log.info("epoch {d}: ChangeEpoch already executed; finishing the epoch (last checkpoint certification)", .{info.epoch});
            break :blk std.mem.readInt(u64, raw[0..8], .little);
        } else {
            log.err("exec store system state is at epoch {d}, starting epoch {d}", .{ sum.epoch, info.epoch });
            return error.EpochMismatch;
        };
        e.ectx = .{ .cfg = e.cfg, .epoch = info.epoch, .epoch_start_ms = info.epoch_start_timestamp_ms, .rgp = rgp, .chain_id = rt.genesis.chain_id, .committee_size = @intCast(info.committee.len) };
        rt.runner.setEpoch(e.ectx);
        e.sig_env = objects.sigEnv(&e.ectx);
        e.check_env = objects.checkerEnv(&e.ectx, &e.obj_state, &e.sig_env);

        e.names = try a.alloc(iface.AuthorityName, info.committee.len);
        e.stakes = try a.alloc(u64, info.committee.len);
        const rmembers = try a.alloc(randomness.manager.Member, info.committee.len);
        const jmembers = try a.alloc(jwk.aggregator.Member, info.committee.len);
        const cmembers = try a.alloc(checkpoint.committee.Member, info.committee.len);
        for (info.committee, 0..) |m, i| {
            e.names[i] = .{ .@"0" = m.name };
            e.stakes[i] = m.stake;
            rmembers[i] = .{ .name = m.name, .stake = m.stake };
            jmembers[i] = .{ .name = m.name, .stake = m.stake };
            cmembers[i] = .{ .name = m.name, .stake = m.stake };
        }
        e.ccommittee = try checkpoint.Committee.init(a, info.epoch, cmembers);
        if (rt.deny) |dm| {
            // reconfigure: the new committee's stakes, rows of members that left dropped
            const dmembers = try a.alloc(deny_manager.Member, info.committee.len);
            for (info.committee, dmembers) |m, *d| d.* = .{ .name = m.name, .stake = m.stake };
            try dm.updateForCommittee(dmembers);
        }

        // ---- authority params: the system objects' initial shared versions
        var params = env_mod.Params.fromProtocol(e.cfg, info.epoch, info.epoch_start_timestamp_ms, rgp);
        if (rt.exec.latest(&runner_mod.authenticator_id)) |raw| params.authenticator_isv = objects.startVersion(raw);
        if (rt.exec.latest(&runner_mod.randomness_id)) |raw| params.randomness_isv = objects.startVersion(raw);
        if (rt.exec.latest(&runner_mod.acc_root_id)) |raw| params.implicit.accumulator_root = objects.startVersion(raw);
        if (rt.exec.latest(&authority.versions.Implicit.fwd_id)) |raw| params.implicit.forwarding_registry = objects.startVersion(raw);
        if (params.randomness_state_enabled and params.randomness_isv == null) params.randomness_state_enabled = false;

        // ---- zkLogin: the JWK map (authenticator state at epoch start when enabled) and env
        errdefer e.jwk_map.deinit();
        if (params.authenticator_isv != null and e.cfg.feature_flags.enable_jwk_consensus_updates) {
            const n_jwks = try zklogin.loadEpochStart(&e.jwk_map, &rt.exec);
            log.info("epoch {d}: {d} active JWKs from the authenticator state", .{ info.epoch, n_jwks });
        }
        e.sig_env.zklogin = zklogin.env(&e.jwk_map, &rt.genesis.chain_id, e.cfg);
        rt.runner.setAuthHook(.{ .ctx = e, .f = authStateUpdated });
        errdefer rt.runner.setAuthHook(null);

        // ---- randomness manager (DKG key = the authority BLS key, as Rust)
        if (params.randomness_state_enabled) {
            var secret = try rt.signer.randomnessSecret();
            defer std.crypto.secureZero(u8, &secret);
            e.rmgr = try randomness.Manager.create(gpa, rt.io, .{
                .epoch = info.epoch,
                .chain_id = rt.genesis.chain_id,
                .members = rmembers,
                .protocol = randomness.manager.protocolParams(e.cfg),
            }, if (e.own_index != null) &secret else null);
            e.radapter = randomness.hooks.Adapter.init(gpa, e.rmgr.?, null, rt.own_name);
        }
        errdefer if (e.rmgr) |m| {
            e.radapter.deinit();
            m.destroy();
        };

        // ---- JWK (no fetching on a local committee; votes from peers are still aggregated)
        e.jagg = try jwk.aggregator.Aggregator.init(gpa, .{
            .epoch = info.epoch,
            .members = jmembers,
            .max_votes_per_validator = jwk.aggregator.maxVotesFromConfig(e.cfg),
            .enabled = params.authenticator_isv != null,
        });
        errdefer e.jagg.deinit();
        e.jadapter = jwk.hooks.Adapter.init(gpa, &e.jagg);
        errdefer e.jadapter.deinit();

        // ---- checkpoints
        e.cenv = .{ .runner = &rt.runner, .sigs = .{ .ctx = e, .get = sigsGet } };
        e.ehooks = epoch_mod.hooks.Hooks.init(es);
        e.builder = checkpoints.Builder.init(gpa, e.cfg, info.epoch, e.cenv.env(), rt.ckpt.store(), &e.output);
        errdefer e.builder.deinit();
        e.aggregator = checkpoints.Aggregator.init(gpa, &e.ccommittee, rt.ckpt.store(), rt.driver.certifiedSink());
        if (rt.ckpt.store().lastBuilt()) |lb| e.logged_built = lb.seq;
        if (rt.ckpt.store().highestCertified()) |h| e.logged_certified = h;
        errdefer e.aggregator.deinit();

        // ---- authority (replays its commit group log)
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        const log_path = try std.fmt.bufPrint(&pb, "{s}/validator/epoch-{d}/authority.log", .{ rt.db, info.epoch });
        keys.fsutil.makePath(rt.io, std.fs.path.dirname(log_path).?) catch return error.Io;
        e.auth = try authority.authority.Authority.create(gpa, .{
            .params = params,
            .cfg = e.cfg,
            .committee = e.names,
            .stakes = e.stakes,
            .own_index = e.own_index,
            .epoch_ctl = e.control.control(),
            .check_env = &e.check_env,
            .reader = objects.objectReader(&rt.exec),
            .runner = rt.runner.runner(),
            .router = .{
                .checkpoint_signature = e.aggregator.signatureSink(),
                .randomness = if (e.rmgr != null) e.radapter.hooks() else null,
                .jwk = e.jadapter.hooks(),
                .epoch = e.ehooks.epochHooks(),
                .deny_config = if (rt.deny) |dm| .{ .ctx = dm, .apply = denyBackstop } else null,
            },
            .pending_sink = .{ .ctx = e, .vtable = &pending_vt },
            .jwks = .{ .ctx = e.jadapter.source().ctx, .get = e.jadapter.source().get },
            .now_ms = wallMs,
            .commit_log_us = wallUs,
            .stored_observation_chunks = try storedObservationChunks(e.arena.allocator(), &rt.exec),
        }, .{ .io = rt.io, .path = log_path });
        errdefer e.auth.destroy();
        if (rt.tracer) |tr| {
            const vt = tr.validatorTracer();
            e.auth.submit.tracer = vt;
            e.auth.bridge.tracer = vt;
            e.auth.handler.d.tracer = vt;
            e.builder.tracer = vt;
        }
        e.cenv.hooks.observations = .{ .ctx = e, .f = eoeObservations };
        e.cenv.hooks.vote = .{ .ctx = e, .f = protocolVote };
        e.cenv.hooks.builtin = rt.builtin;
        e.auth.validator.hooks.ctx = e;
        e.auth.validator.hooks.checkpoint_signatures = verifyCkptSigs;
        e.auth.validator.hooks.recently_executed = voteRecentlyExecuted;
        e.auth.validator.hooks.executed_last_epoch = executedLastEpoch;
        if (rt.deny != null) e.auth.validator.hooks.apply_deny_updates = applyDenyUpdates;
        e.auth.submit.hooks = submitHooks(&rt.exec);
        e.auth.submit.hooks.ctx = e;
        e.auth.submit.hooks.executed_effects = submitExecutedEffects;
        e.auth.submit.hooks.executed_in_last_epoch = executedLastEpoch;
        e.output = .{ .gpa = gpa, .signer = e.vsigner.checkpointSigner(), .submit = e.auth.consensusSubmit(), .store = rt.ckpt.store() };
        e.jwk_enabled = e.own_index != null and params.authenticator_isv != null and e.cfg.feature_flags.enable_jwk_consensus_updates;
        if (e.rmgr != null) e.radapter.submit = e.auth.consensusSubmit();

        // ---- restore the side-records of the durable commits, in group order
        var rrestore = randomness.persist.Restore.init(gpa);
        defer rrestore.deinit();
        var n_ext: usize = 0;
        for (e.auth.state.ext.items) |x| {
            n_ext += 1;
            switch (x.tag) {
                state_mod.ext_randomness => try rrestore.add(x.bytes),
                state_mod.ext_jwk => try jwk.hooks.restore(&e.jagg, x.bytes),
                state_mod.ext_epoch => try e.control.restore(x.bytes),
                else => return error.Corrupt,
            }
        }
        if (e.rmgr) |m| try rrestore.apply(m, null);
        // checkpoint sequence numbers run across epochs: an epoch whose log has not assigned one
        // yet starts after the last built checkpoint (genesis 0, else the previous epoch's last)
        if (e.auth.state.queue_seq == 0) {
            const lb = rt.ckpt.store().lastBuilt() orelse return error.Corrupt;
            e.auth.state.queue_seq = lb.seq + 1;
        }
        const repushed = blk: {
            var ar = std.heap.ArenaAllocator.init(gpa);
            defer ar.deinit();
            break :blk try e.auth.handler.repushPending(ar.allocator());
        };
        if (n_ext != 0 or repushed != 0) std.debug.print("deepwave-validator: epoch {d} restored {d} side-records, {d} pending checkpoints, through commit {d}\n", .{ info.epoch, n_ext, repushed, e.auth.state.indices.sub_dag_index });
        e.partials_sent_through = e.auth.state.randomness_last orelse 0;

        // ---- consensus
        const auths = try a.alloc(consensus.committee.Authority, info.committee.len);
        for (info.committee, auths) |m, *au| {
            const v = rt.genesisValidator(&m.name) orelse return error.UnknownMember;
            au.* = .{ .stake = m.stake, .address = v.primary_address, .hostname = v.name, .authority_name = &v.protocol_pubkey, .protocol_key = v.worker_pubkey, .network_key = v.network_pubkey };
        }
        var cparams: consensus.config.Parameters = .{};
        cparams.db_path = try std.fmt.allocPrint(a, "{s}/consensus", .{rt.db});
        e.context = .{
            .epoch_start_timestamp_ms = info.epoch_start_timestamp_ms,
            .own_index = if (e.own_index) |i| @intCast(i) else null,
            .committee = consensus.Committee.init(info.epoch, auths) catch return error.BadCommittee,
            .parameters = cparams,
            .protocol_config = consensus.config.ProtocolConfig.fromProtocol(info.protocol_version, .unknown) catch return error.UnsupportedProtocol,
            .clock = rt.clock.clock(),
            .tracer = if (rt.tracer) |tr| tr.consensusTracer() else .{},
        };

        // DKG: our message (or the persisted confirmation) goes out before consensus starts
        if (e.rmgr != null and e.own_index != null) try e.radapter.start();

        var seed = rt.signer.networkSeed();
        defer std.crypto.secureZero(u8, &seed);
        e.cons = try consensus_net.authority_node.ConsensusAuthority.start(gpa, rt.io, .{
            .context = &e.context,
            .db_dir = cparams.db_path,
            .network_key_seed = &seed,
            .signer = vnode.blockSigner(rt.signer),
            .tx_verifier = e.auth.txVerifier(),
            .tx_source = e.auth.txSource(),
            .commit_sink = e.auth.commitSink(),
            .allow_non_local = rt.license.mode == .network,
            .boot_counter = rt.boots,
            .min_known_proposed_round = blk: {
                const w = rt.signer.watermarks.block orelse break :blk 0;
                break :blk if (w.epoch == info.epoch) w.round else 0;
            },
        });
        errdefer e.cons.?.stop();
        // sui-node monitor_reconfiguration: a committee member announces its capabilities at
        // every epoch start (before this epoch's commits are handled)
        if (e.own_index != null) e.announceCapabilities() catch |err| log.err("epoch {d}: capability notification not sent: {s}", .{ info.epoch, @errorName(err) });
        // sui-node, after the epoch's capability notification: reconcile this validator's shared
        // deny config vote with the (possibly restart-edited) local config
        if (rt.deny) |dm| if (e.own_index != null and e.cfg.feature_flags.share_transaction_deny_config_in_consensus) {
            const is_startup = rt.deny_startup;
            rt.deny_startup = false;
            var tracking: [8]u8 = undefined;
            rt.io.random(&tracking);
            dm.reconcile(e.auth.consensusSubmit(), tracking, is_startup);
        };
        e.handler_thread = try std.Thread.spawn(.{}, handlerLoop, .{e});
        e.ckpt_thread = try std.Thread.spawn(.{}, ckptLoop, .{e});
        return e;
    }

    fn destroy(e: *Epoch) void {
        e.stop.store(true, .release);
        if (e.cons) |c| c.stop();
        if (e.handler_thread) |t| t.join();
        if (e.ckpt_thread) |t| t.join();
        e.rt.runner.setAuthHook(null);
        e.auth.destroy();
        e.aggregator.deinit();
        e.builder.deinit();
        e.jadapter.deinit();
        e.jagg.deinit();
        e.jwk_map.deinit();
        if (e.rmgr) |m| {
            e.radapter.deinit();
            m.destroy();
        }
        e.pending_fifo.seqs.deinit(e.gpa);
        e.arena.deinit();
        e.gpa.destroy(e);
    }

    // ---- hooks

    /// The checkpoint builder's view of the recorded user signatures (under the state's lock: the
    /// handler thread applies commits concurrently).
    fn sigsGet(ctx: *anyopaque, arena: Allocator, digest: *const [32]u8) ?state_mod.UserSigs {
        _ = arena;
        const e: *Epoch = @ptrCast(@alignCast(ctx));
        e.auth.state.shared_lock.lock();
        defer e.auth.state.shared_lock.unlock();
        return e.auth.state.sigs.get(digest.*);
    }

    /// sui-node `monitor_reconfiguration`: this validator's CapabilityNotificationV2, the
    /// versions from the epoch's own up to this binary's max (lowered while the proposed config
    /// enables accumulators and the accumulator root does not exist) with Mysten's config
    /// digests, and the system packages this binary would install (`get_available_system_packages`
    /// with the epoch's binary config).
    fn announceCapabilities(e: *Epoch) !void {
        const rt = e.rt;
        var arena = std.heap.ArenaAllocator.init(e.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const bin = try @import("exec").system.movecall.binaryConfig(e.cfg);
        const pkgs = try epoch_mod.packages.availableSystemPackages(a, rt.builtin, ckpt_env.objectSource(&rt.exec), &bin);
        var an: epoch_mod.announce.Announcer = .{
            .authority = rt.own_name,
            .chain = vnode.chainOf(&rt.genesis.chain_id8),
            .system_packages = pkgs,
            .accumulator_root_exists = rt.exec.latest(&runner_mod.acc_root_id) != null,
        };
        var tracking: [8]u8 = undefined;
        rt.io.random(&tracking);
        try an.announce(a, e.auth.consensusSubmit(), tracking, wallMs(), e.es.info.protocol_version);
        log.info("epoch {d}: capabilities sent (protocol {d}..{d}, {d} system packages)", .{ e.epoch, e.es.info.protocol_version, an.announced_max, pkgs.len });
    }

    /// `choose_protocol_version_and_system_packages_v2` over the epoch's stored capabilities
    /// (`get_effective_buffer_stake_bps`: no operator override, the protocol's buffer).
    fn protocolVote(ctx: *anyopaque, arena: Allocator) anyerror!reconfig.Chosen {
        const e: *Epoch = @ptrCast(@alignCast(ctx));
        const caps = try e.es.capabilitiesCopy(arena);
        const chosen = try reconfig.chooseProtocolVersion(arena, e.es, e.cfg.feature_flags.advance_to_highest_supported_protocol_version, e.cfg.buffer_stake_for_protocol_upgrade_bps orelse 0, caps);
        log.info("epoch {d}: protocol vote over {d} capabilities: next version {d}, {d} system packages", .{ e.epoch, caps.len, chosen.protocol_version, chosen.packages.len });
        return chosen;
    }

    /// The handler's final-round estimator snapshot (StoreExecutionTimeObservations).
    fn eoeObservations(ctx: *anyopaque, arena: Allocator) ?types.StoredExecutionTimeObservations {
        const e: *Epoch = @ptrCast(@alignCast(ctx));
        return e.auth.handler.endOfEpochObservations(arena);
    }

    /// `update_authenticator_state`: the executed update's new active JWKs join the map.
    fn authStateUpdated(ctx: *anyopaque, u: *const types.AuthenticatorStateUpdate) void {
        const e: *Epoch = @ptrCast(@alignCast(ctx));
        e.jwk_map.insertActive(u.new_active_jwks) catch log.err("JWK map: out of memory", .{});
    }

    /// `handle_vote_transaction`: `is_recently_finalized` (sequenced this epoch) or
    /// `transactions_executed_in_cur_epoch` accepts without the input checks.
    fn voteRecentlyExecuted(ctx: *anyopaque, digest: *const [32]u8) bool {
        const e: *Epoch = @ptrCast(@alignCast(ctx));
        return e.auth.handler.finalized.contains(digest) or objects.executedInEpoch(&e.rt.exec, digest, e.epoch);
    }

    /// `transaction_executed_in_last_epoch` (vote: reject; submit: rejected).
    fn executedLastEpoch(ctx: *anyopaque, digest: *const [32]u8) bool {
        const e: *Epoch = @ptrCast(@alignCast(ctx));
        return objects.executedInLastEpoch(&e.rt.exec, digest, e.epoch);
    }

    /// SubmitTransaction's `get_executed_effects` (any epoch), as `submitHooks`.
    fn submitExecutedEffects(ctx: *anyopaque, digest: *const [32]u8) ?[32]u8 {
        const e: *Epoch = @ptrCast(@alignCast(ctx));
        return if (e.rt.exec.executed(digest)) |x| x.effects_digest else null;
    }

    /// consensus_validator `apply_deny_config_updates`: a validated block's deny config messages,
    /// with the block author's name.
    fn applyDenyUpdates(ctx: *anyopaque, author_index: u32, updates: []const @import("../messages.zig").SharedTransactionDenyConfig) void {
        const e: *Epoch = @ptrCast(@alignCast(ctx));
        const dm = e.rt.deny orelse return;
        if (author_index >= e.names.len) return;
        dm.applyUpdates(&e.names[author_index].@"0", updates);
    }

    /// consensus_handler `process_transaction_deny_config_updates`: one message at a time.
    fn denyBackstop(ctx: *anyopaque, author: *const [96]u8, update: *const @import("../messages.zig").SharedTransactionDenyConfig) void {
        const dm: *deny_manager.Manager = @ptrCast(@alignCast(ctx));
        const one: *const [1]@import("../messages.zig").SharedTransactionDenyConfig = update;
        dm.applyUpdates(author, one);
    }

    /// `batch_verify_checkpoints` for the block votes: BLS over the epoch committee.
    fn verifyCkptSigs(ctx: *anyopaque, msgs: []const *const @import("../messages.zig").CheckpointSignatureMessage) bool {
        const e: *Epoch = @ptrCast(@alignCast(ctx));
        return checkpoints.aggregator.verifySignatureMessages(e.gpa, &e.ccommittee, msgs) catch false;
    }

    fn pendingPush(ctx: *anyopaque, p: *const iface.PendingCheckpoint) error{ Full, Unimplemented }!void {
        const e: *Epoch = @ptrCast(@alignCast(ctx));
        e.pending_fifo.mu.lock();
        defer e.pending_fifo.mu.unlock();
        e.builder.push(p) catch return error.Full;
        e.pending_fifo.seqs.append(e.gpa, p.details.checkpoint_seq) catch {};
    }
    const pending_vt: iface.PendingCheckpointSink.VTable = .{ .push = pendingPush };

    // ---- threads

    fn handlerLoop(e: *Epoch) void {
        var scratch = std.heap.ArenaAllocator.init(e.gpa);
        defer scratch.deinit();
        while (!e.stop.load(.acquire)) {
            _ = scratch.reset(.retain_capacity);
            const n = e.auth.step(scratch.allocator()) catch |err| {
                log.err("epoch {d}: handler failed: {s}; exiting so a restart replays from the durable commit", .{ e.epoch, @errorName(err) });
                e.rt.failed.store(true, .release);
                stop_flag.store(true, .release);
                return;
            };
            _ = e.stats.steps.fetchAdd(1, .monotonic);
            e.randomnessStep();
            if (n == 0) sleepMs(2);
        }
    }

    /// After each step: install the DKG output in the network once there is one, send partial
    /// signatures for the rounds durable commits reserved, complete the rounds that executed.
    fn randomnessStep(e: *Epoch) void {
        const m = e.rmgr orelse return;
        const rn = e.rt.randnet orelse return;
        if (!e.randnet_epoch_set) {
            if (m.dkgStatus() != .successful) return;
            rn.setEpoch(e.epoch, m) catch |err| {
                log.err("randomness: setEpoch {d}: {s}", .{ e.epoch, @errorName(err) });
                return;
            };
            e.randnet_epoch_set = true;
            var n_msgs: usize = 0;
            var n_confs: usize = 0;
            for (m.processed) |p| n_msgs += @intFromBool(p != null);
            for (m.confirmations) |c| n_confs += @intFromBool(c != null);
            std.debug.print("deepwave-validator: epoch {d} DKG complete, randomness on (num_messages={d} num_confirmations={d} used={d} through commit {d})\n", .{ e.epoch, n_msgs, n_confs, if (m.used) |u| u.value.items.len else 0, e.auth.state.indices.sub_dag_index });
            e.partials_sent_through = 0;
        }
        const last = e.auth.state.randomness_last orelse return;
        if (last > e.partials_sent_through or (e.partials_sent_through == 0 and last > 0)) {
            rn.sendPartials(e.epoch, last) catch |err| log.warn("randomness: send partials {d}: {s}", .{ last, @errorName(err) });
            e.partials_sent_through = last;
        }
        var r = e.completed_through + 1;
        while (r <= last) : (r += 1) {
            const k: exec_store.Key = .{ .randomness_round = .{ .epoch = e.epoch, .round = r } };
            if (e.rt.exec.keyDigest(k) == null) break;
            e.completed_through = r;
        }
        if (e.completed_through > 0) rn.completeRound(e.epoch, e.completed_through);
    }

    fn ckptLoop(e: *Epoch) void {
        var svc: checkpoints.Service = .{ .builder = &e.builder, .aggregator = &e.aggregator };
        while (!e.stop.load(.acquire)) {
            // catch-up applied this epoch from certified checkpoints: nothing left to build here
            if (@as(i64, @intCast(e.epoch)) <= e.rt.ckpt_frozen.load(.acquire)) {
                sleepMs(20);
                continue;
            }
            const t = svc.tick(e.gpa) catch |err| {
                log.err("epoch {d}: checkpoints failed: {s} (builder: {s}; exec: {s})", .{ e.epoch, @errorName(err), e.builder.fatal_reason, e.rt.runner.lastError() });
                e.rt.failed.store(true, .release);
                stop_flag.store(true, .release);
                return;
            };
            if (t.built > 0) {
                _ = e.stats.built.fetchAdd(t.built, .monotonic);
                e.pending_fifo.mu.lock();
                const k = @min(t.built, e.pending_fifo.seqs.items.len);
                const through = if (k > 0) e.pending_fifo.seqs.items[k - 1] else 0;
                e.pending_fifo.seqs.replaceRangeAssumeCapacity(0, k, &.{});
                e.pending_fifo.mu.unlock();
                if (k > 0) e.auth.handler.ackPendingThrough(through);
            }
            var certified = t.certified;
            if (e.rt.takePulled()) |cb| {
                defer e.gpa.free(cb);
                var scratch = std.heap.ArenaAllocator.init(e.gpa);
                defer scratch.deinit();
                const seq = e.rt.ckpt.store().nextToCertify();
                if (e.aggregator.addCertified(scratch.allocator(), cb) catch false) {
                    std.debug.print("deepwave-validator: checkpoint {d} certified by a peer's certificate (state sync)\n", .{seq});
                    certified += 1;
                }
            }
            if (certified > 0) _ = e.stats.certified.fetchAdd(certified, .monotonic);
            if (t.built > 0 or certified > 0) e.logCheckpoints();
            if (t.built == 0 and certified == 0) sleepMs(5);
        }
    }

    /// One line per checkpoint built and certified, in sui-core's CheckpointBuilder text
    /// ("Made new checkpoint seq=N digest=<base58>"), so a mixed committee's tooling compares
    /// deepwave's summaries with the Mysten validators' at every sequence number.
    fn logCheckpoints(e: *Epoch) void {
        const st = e.rt.ckpt.store();
        var b58: [serve.b58.max_len_32]u8 = undefined;
        if (st.lastBuilt()) |lb| {
            var s = @max(e.logged_built + 1, lb.seq -| 1000);
            while (s <= lb.seq) : (s += 1) {
                const d = st.locallyComputedDigest(s) orelse continue;
                std.debug.print("deepwave-validator: Made new checkpoint seq={d} digest={s} epoch={d}\n", .{ s, serve.b58.encode32(&b58, &d), e.epoch });
            }
            e.logged_built = lb.seq;
        }
        if (st.highestCertified()) |h| {
            var s = @max(e.logged_certified + 1, h -| 1000);
            while (s <= h) : (s += 1) {
                const d = st.certifiedDigest(s) orelse continue;
                std.debug.print("deepwave-validator: certified checkpoint seq={d} digest={s} epoch={d}\n", .{ s, serve.b58.encode32(&b58, &d), e.epoch });
            }
            e.logged_certified = h;
        }
    }
};

// ------------------------------------------------------------------ entry

pub fn run(gpa: Allocator, io: Io, args: []const []const u8) u8 {
    return runInner(gpa, io, args) catch |e| {
        std.debug.print("deepwave-validator run: {s}\n", .{@errorName(e)});
        return switch (e) {
            error.BadArguments => 2,
            error.Refused, error.NotAMember => 3,
            else => 1,
        };
    };
}

fn runInner(gpa: Allocator, io: Io, args: []const []const u8) !u8 {
    var config_path: ?[]const u8 = null;
    var genesis_path: ?[]const u8 = null;
    var db_opt: ?[]const u8 = null;
    var duration_s: u64 = 0;
    var sign_network: ?gate.SignNetwork = null;
    var with_randomness = true;
    var catchup_on = true;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--no-randomness")) {
            with_randomness = false;
            continue;
        }
        if (std.mem.eql(u8, a, "--zui-catchup")) continue;
        if (std.mem.eql(u8, a, "--no-catchup")) {
            catchup_on = false;
            continue;
        }
        if (i + 1 >= args.len) {
            std.debug.print("{s}", .{usage});
            return error.BadArguments;
        }
        i += 1;
        const v = args[i];
        if (std.mem.eql(u8, a, "--config")) config_path = v else if (std.mem.eql(u8, a, "--genesis")) genesis_path = v else if (std.mem.eql(u8, a, "--db")) db_opt = v else if (std.mem.eql(u8, a, "--duration-s")) {
            duration_s = std.fmt.parseInt(u64, v, 10) catch return error.BadArguments;
        } else if (std.mem.eql(u8, a, gate.sign_network_flag)) {
            sign_network = gate.SignNetwork.parse(v) orelse return error.BadArguments;
        } else {
            std.debug.print("{s}", .{usage});
            return error.BadArguments;
        }
    }
    const cfg_path = config_path orelse {
        std.debug.print("{s}", .{usage});
        return error.BadArguments;
    };

    const rt = try gpa.create(Runtime);
    defer gpa.destroy(rt);
    rt.* = .{
        .gpa = gpa,
        .io = io,
        .arena = .init(gpa),
        .db = undefined,
        .genesis = undefined,
        .own_index_genesis = 0,
        .own_name = undefined,
        .license = undefined,
        .signer = undefined,
        .exec = undefined,
        .ckpt = undefined,
        .runner = undefined,
        .emgr = undefined,
        .driver = undefined,
        .clock = .{ .io = io },
    };
    defer rt.arena.deinit();
    const arena = rt.arena.allocator();

    var loaded = keys.config.load(gpa, io, cfg_path) catch return error.BadConfig;
    defer loaded.deinit();
    const c = &loaded.cfg;
    const gpath = genesis_path orelse c.genesis_path orelse return error.BadConfig;
    const blob = (keys.fsutil.readAll(arena, io, gpath, 256 << 20) catch return error.Io) orelse return error.BadConfig;
    rt.genesis = genesis_mod.load(arena, blob) catch return error.BadGenesis;
    const g = &rt.genesis;

    // the gate: chain id and every address of the genesis committee and of this yaml
    var addrs: std.ArrayList([]const u8) = .empty;
    for (g.validators) |v| {
        try seat.appendAddr(arena, &addrs, v.primary_address);
        try seat.appendAddr(arena, &addrs, v.net_address);
        try seat.appendAddr(arena, &addrs, v.p2p_address);
    }
    for (c.addresses(arena) catch return error.OutOfMemory) |ad| try seat.appendAddr(arena, &addrs, ad);
    rt.license = switch (gate.decide(.{ .chain_id = &g.chain_id8, .addresses = addrs.items, .key_source = .localnet_config, .sign_network = sign_network })) {
        .allowed => |l| l,
        .refused => |r| {
            std.debug.print("deepwave-validator run: {s}\n", .{r.text()});
            return error.Refused;
        },
    };

    var ks = try seat.loadKeys(gpa, io, c);
    defer ks.wipe();
    var own: ?u32 = null;
    for (g.validators, 0..) |v, idx| {
        if (std.mem.eql(u8, &v.protocol_pubkey, &ks.authority_pk)) own = @intCast(idx);
    }
    rt.own_index_genesis = own orelse return error.NotAMember;
    rt.own_name = ks.authority_pk;
    const me = g.validators[rt.own_index_genesis];
    if (!std.mem.eql(u8, &me.worker_pubkey, &ks.worker.public_key.toBytes()) or !std.mem.eql(u8, &me.network_pubkey, &ks.network.public_key.toBytes())) return error.NotAMember;

    rt.db = if (db_opt) |d| d else try std.fmt.allocPrint(arena, "{s}-zui", .{std.mem.trimEnd(u8, c.db_path, "/")});
    keys.fsutil.makePath(io, rt.db) catch return error.Io;
    rt.signer = signer_mod.Signer.open(gpa, io, &rt.license, rt.db, .{ .localnet_config = ks }) catch |e| {
        std.debug.print("deepwave-validator run: signer: {s}\n", .{@errorName(e)});
        return if (e == error.Locked) error.Io else error.Refused;
    };
    defer rt.signer.close();

    // ---- process-level stores (seeded with genesis; idempotent)
    rt.exec = exec_store.ExecStore.open(gpa, io, rt.db) catch return error.Io;
    defer rt.exec.close();
    try rt.exec.seedGenesis(g);
    rt.ckpt = ckpt_store.CkptStore.open(gpa, io, rt.db) catch return error.Io;
    defer rt.ckpt.close();
    rt.ckpt.seedGenesis(g) catch return error.Io;
    const cfg0 = protocol.get(g.protocol_version, .unknown) catch return error.BadGenesis;
    rt.builtin = epoch_mod.packages.builtIn(arena, epoch_mod.capabilities.supported_max) catch return error.BadGenesis;
    rt.runner.init(gpa, &rt.exec, .{ .cfg = cfg0, .epoch = g.epoch, .epoch_start_ms = g.epoch_start_timestamp_ms, .rgp = g.reference_gas_price, .chain_id = g.chain_id, .committee_size = @intCast(g.validators.len) });
    defer rt.runner.deinit();
    rt.runner.randomness = .{ .ctx = rt, .get = Runtime.randomBytes };
    rt.catchup_on = catchup_on;

    // ---- the seat's anemo endpoint (p2p address): StateSync, Discovery, Randomness
    {
        const peers = try arena.alloc(p2p_mod.Peer, g.validators.len);
        for (g.validators, peers) |v, *p| p.* = .{ .network_pubkey = v.network_pubkey, .p2p_address = v.p2p_address };
        var seed = ks.network.secret_key.seed();
        defer std.crypto.secureZero(u8, &seed);
        rt.p2p = p2p_mod.P2p.start(gpa, io, .{ .listen = me.p2p_address, .peers = peers, .own_index = rt.own_index_genesis, .network_seed = &seed, .chain_id = g.chain_id }) catch |e| {
            std.debug.print("deepwave-validator run: p2p endpoint on {s}: {s}\n", .{ me.p2p_address, @errorName(e) });
            return error.Startup;
        };
        rt.ssvc = state_sync.Service.start(gpa, io, .{ .p2p = rt.p2p.?, .ckpt = &rt.ckpt, .exec = &rt.exec, .genesis_digest = g.chain_id, .network_seed = &seed, .external = me.p2p_address }) catch |e| {
            std.debug.print("deepwave-validator run: state sync: {s}\n", .{@errorName(e)});
            return error.Startup;
        };
    }
    defer rt.p2p.?.stop();
    defer rt.ssvc.?.stop();

    // ---- randomness on the endpoint
    if (with_randomness and cfg0.feature_flags.random_beacon) {
        const peers = try arena.alloc(randomness_net.Peer, g.validators.len);
        for (g.validators, peers, 0..) |v, *p, idx| p.* = .{ .index = @intCast(idx), .name = v.protocol_pubkey, .network_pubkey = v.network_pubkey, .p2p_address = v.p2p_address };
        rt.randnet = randomness_net.RandomnessNet.start(gpa, io, .{
            .p2p = rt.p2p.?,
            .peers = peers,
            .own_index = @intCast(rt.own_index_genesis),
        }, .{ .ctx = rt, .f = Runtime.fullSigSink }) catch |e| {
            std.debug.print("deepwave-validator run: randomness network: {s}\n", .{@errorName(e)});
            return error.Startup;
        };
    }
    defer if (rt.randnet) |rn| rn.stop();

    // ---- JWK updater parameters (sui-node `start_jwk_updater`): the chain's providers
    rt.jwk_providers = jwkProviders(c, &g.chain_id);
    rt.jwk_interval_ms = c.jwk_fetch_interval_seconds *| 1000;

    // ---- latency tracer (val-fast-finality stages; `deepwave-validator budget` reads the report)
    const latency = @import("../latency/root.zig");
    rt.tracer = latency.tracer.StageTracer.create(gpa, 1 << 14) catch null;

    // ---- epochs
    rt.emgr = emanager.EpochManager.init(gpa, io, rt.db, rt.own_name, g.chain_id8, .{ .ctx = rt, .vtable = &Runtime.comp_vt });
    rt.driver = .{ .gpa = gpa, .io = io, .mgr = &rt.emgr, .params = .{ .ctx = rt, .get = Runtime.paramsGet } };
    var start_info: emanager.SystemStateInfo = emanager.loadPersisted(arena, io, rt.db, rt.own_name, g.chain_id8) orelse
        try emanager.infoFromState(arena, rt.own_name, g.chain_id8, systemState(&rt.exec) orelse return error.BadGenesis);
    // a restart after the epoch's last checkpoint was certified but before the switch persisted
    if (rt.ckpt.highestCertified()) |h| if (rt.ckpt.certifiedBytes(h)) |cb| {
        if (rt.driver.nextFromSummary(arena, cb, start_info.info.epoch, start_info.transition.epoch_duration_ms) catch null) |next| {
            std.debug.print("deepwave-validator: epoch {d} ended at certified checkpoint {d}: starting epoch {d}\n", .{ start_info.info.epoch, h, next.info.epoch });
            var tr = next.transition;
            if (Runtime.paramsGet(rt, next.info.epoch)) |p| tr.epoch_duration_ms = p.epoch_duration_ms;
            start_info = .{ .info = next.info, .transition = tr };
        }
    };
    if (start_info.transition.epoch_duration_ms == 0) {
        if (systemState(&rt.exec)) |st| if (serve.sysstate.epochParams(st)) |p| {
            start_info.transition.epoch_duration_ms = p.epoch_duration_ms;
        } else |_| {};
    }
    if (rt.catchup_on) try startupCatchup(rt, arena, &start_info);

    // ---- transaction deny config: the local one, and the manager sharing it through consensus
    const deny_local = try arena.create(rpc_exec.txdeny.Config);
    deny_local.* = rpc_exec.txdeny.parseItems(arena, c.tx_deny) catch return error.BadConfig;
    rpc_exec.txdeny.install(deny_local.*);
    {
        const dmembers = try arena.alloc(deny_manager.Member, start_info.info.committee.len);
        for (start_info.info.committee, dmembers) |m, *d| d.* = .{ .name = m.name, .stake = m.stake };
        const vdir = try std.fmt.allocPrint(arena, "{s}/validator", .{rt.db});
        keys.fsutil.makePath(io, vdir) catch return error.Io;
        rt.deny = deny_manager.Manager.create(gpa, .{
            .self_name = rt.own_name,
            .local = deny_local,
            .sync = c.peer_deny_sync,
            .committee = dmembers,
            .slot = &rpc_exec.txdeny.effective_slot,
            .path = try std.fmt.allocPrint(arena, "{s}/deny-sync", .{vdir}),
            .io = io,
            .now_ms = wallMs,
        }) catch |e| {
            std.debug.print("deepwave-validator run: transaction deny config: {s}\n", .{@errorName(e)});
            return error.BadConfig;
        };
    }
    defer if (rt.deny) |dm| {
        rpc_exec.txdeny.effective_slot.publish(null);
        dm.destroy();
    };
    rt.driver.reach = start_info.info.epoch;
    rt.driver.duration_ms = start_info.transition.epoch_duration_ms;
    std.debug.print("deepwave-validator run: chain {s}, own index {d} ({s}), gate {s}, db {s}, starting epoch {d} (duration {d} ms)\n", .{ &g.chain_id8, rt.own_index_genesis, me.name, @tagName(rt.license.mode), rt.db, start_info.info.epoch, start_info.transition.epoch_duration_ms });
    rt.emgr.start(start_info.info, start_info.transition) catch |e| {
        std.debug.print("deepwave-validator run: epoch start: {s}\n", .{@errorName(e)});
        return error.Startup;
    };
    rt.driver.start() catch return error.Startup;

    // ---- Validator API (SubmitTransaction / WaitForEffects) on the seat's network address
    rt.metrics = api.metrics.Registry.init(io);
    rt.node_backend = .{ .authority = ApiBackend.authority_(rt), .signer = rt.signer, .epoch = &rt.api_epoch };
    rt.api_server = api.Server.start(gpa, io, me.net_address, rt.node_backend.asBackend(), &rt.metrics, &rt.api_epoch, .{ .tls_seed = rt.signer.networkSeed() }) catch |e| blk: {
        std.debug.print("deepwave-validator run: validator API on {s}: {s} (continuing without it)\n", .{ me.net_address, @errorName(e) });
        break :blk null;
    };

    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onSignal }, .mask = std.posix.sigemptyset(), .flags = std.posix.SA.RESTART };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
    const cu_thread: ?std.Thread = if (rt.catchup_on) std.Thread.spawn(.{ .stack_size = 16 << 20 }, catchupLoop, .{rt}) catch null else null;
    const sync_thread: ?std.Thread = std.Thread.spawn(.{}, syncLoop, .{rt}) catch null;
    const jwk_thread: ?std.Thread = if (rt.jwk_providers.len != 0) std.Thread.spawn(.{}, jwkLoop, .{rt}) catch null else null;
    const t0 = monoMs();
    var last_report = t0;
    while (!stop_flag.load(.acquire)) {
        sleepMs(200);
        const now = monoMs();
        if (now - last_report >= 5000) {
            last_report = now;
            report(rt, now - t0);
        }
        if (duration_s != 0 and now - t0 >= duration_s * 1000) break;
    }
    report(rt, monoMs() - t0);
    stop_flag.store(true, .release);
    // outbound p2p calls (the certificate pull below, state sync's pushes and polls) would wait
    // out their dial and request timeouts against peers that already stopped: end them now
    if (rt.p2p) |p| p.cancelCalls();
    if (cu_thread) |t| t.join();
    if (sync_thread) |t| t.join();
    if (jwk_thread) |t| t.join();
    if (rt.takePulled()) |b| gpa.free(b);
    if (rt.api_server) |sv| _ = sv.stop();
    rt.driver.stop();
    rt.emgr.deinit();
    if (rt.tracer) |tr| {
        // the latency budget of this run: <db>/latency.txt (render) and latency.budget (encode)
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        const report_mod = @import("../latency/root.zig").report;
        const targets: report_mod.Targets = .{};
        if (report_mod.render(&out, gpa, &tr.budget, &targets)) |_| {
            const path = try std.fmt.allocPrint(arena, "{s}/latency.txt", .{rt.db});
            keys.fsutil.writeAtomic(io, path, out.items) catch {};
        } else |_| {}
        out.clearRetainingCapacity();
        if (report_mod.encode(&out, gpa, &tr.budget)) |_| {
            const path = try std.fmt.allocPrint(arena, "{s}/latency.budget", .{rt.db});
            keys.fsutil.writeAtomic(io, path, out.items) catch {};
        } else |_| {}
        tr.destroy();
    }
    std.debug.print("deepwave-validator run: stopped\n", .{});
    return if (rt.failed.load(.acquire)) 1 else 0;
}

// ------------------------------------------------------------------ JWK updater

/// The provider names `start_jwk_updater` runs for this chain: the yaml's set for the chain
/// ("Mainnet", "Testnet", "Unknown"; a chain the map does not list has none), or
/// `default_zklogin_oauth_providers` when the key is absent.
fn jwkProviders(c: *const keys.config.ValidatorConfig, chain_id: *const [32]u8) []const []const u8 {
    const chain = jwkChain(chain_id);
    const name = switch (chain) {
        .mainnet => "Mainnet",
        .testnet => "Testnet",
        .unknown => "Unknown",
    };
    const map = c.zklogin_oauth_providers orelse return jwk.providers.defaultProviderNames(chain);
    for (map) |cp| if (std.mem.eql(u8, cp.chain, name)) return cp.names;
    return &.{};
}

fn jwkChain(chain_id: *const [32]u8) jwk.providers.Chain {
    const us = rpc_exec.live.usersig;
    if (std.mem.eql(u8, chain_id, &us.mainnet_chain_id)) return .mainnet;
    if (std.mem.eql(u8, chain_id, &us.testnet_chain_id)) return .testnet;
    return .unknown;
}

/// `start_jwk_updater`, one thread for the process: Rust spawns one task per provider per epoch
/// (`within_alive_epoch`), each with a fresh `seen`; here the updater's `seen` is reset when the
/// epoch changes. Runs only while the running epoch has the authenticator state enabled and this
/// node is in its committee. The HTTPS fetches hold no epoch; the active check and the
/// NewJWKFetched submission pin the running epoch for a moment.
fn jwkLoop(rt: *Runtime) void {
    var upd = jwk.Updater.init(rt.gpa, rt.jwk_providers, rt.jwk_interval_ms) catch |e| {
        log.err("JWK updater: {s} (providers {d})", .{ @errorName(e), rt.jwk_providers.len });
        return;
    };
    defer upd.deinit();
    var https: jwk.https.Https = undefined;
    https.init(rt.gpa, rt.io);
    defer https.deinit();
    log.info("JWK updater: {d} providers, every {d} s", .{ rt.jwk_providers.len, rt.jwk_interval_ms / 1000 });
    var epoch: ?u64 = null;
    var next: u64 = 0;
    while (!stop_flag.load(.acquire)) {
        sleepMs(200);
        const e = rt.pin() orelse continue;
        const enabled = e.jwk_enabled;
        const ep = e.epoch;
        Runtime.unpin(e);
        if (!enabled) continue;
        if (epoch != ep) {
            upd.resetEpoch();
            epoch = ep;
            next = 0;
        }
        const now = wallMs();
        if (now < next) continue;
        next = upd.poll(now, https.transport(), .{ .ctx = rt, .f = jwkActive }, .{ .ctx = rt, .vote = jwkVote }) catch now + 1000;
        const s = upd.stats;
        log.info("JWK updater: epoch {d}: requests {d}, errors {d}, invalid {d}, submitted {d}", .{ ep, s.requests, s.errors, s.invalid_jwks, s.submitted });
    }
}

fn jwkActive(ctx: *anyopaque, id: types.JwkId, jwk_: types.JWK) bool {
    const rt: *Runtime = @ptrCast(@alignCast(ctx));
    const e = rt.pin() orelse return false;
    defer Runtime.unpin(e);
    const a = e.jadapter.active();
    return a.f(a.ctx, id, jwk_);
}

/// `ConsensusTransaction::new_jwk_fetched(authority, id, jwk)` through the running epoch's
/// consensus adapter.
fn jwkVote(ctx: *anyopaque, id: types.JwkId, jwk_: types.JWK) anyerror!void {
    const rt: *Runtime = @ptrCast(@alignCast(ctx));
    const e = rt.pin() orelse return error.EpochEnding;
    defer Runtime.unpin(e);
    if (!e.jwk_enabled) return error.EpochEnding;
    const bytes = try jwk.txs.newJwkFetchedTx(rt.gpa, &rt.own_name, id, jwk_);
    defer rt.gpa.free(bytes);
    try e.auth.consensusSubmit().submit(&.{bytes}, .system);
}

// ------------------------------------------------------------------ certificates from peers

/// A checkpoint built here and still uncertified after this long is asked of the peers.
const pull_after_ms: u64 = 1_000;
const pull_timeout_ms: u64 = 2_000;

/// sui-node's StateSync (`GetCheckpointSummary`), for the one thing a validator needs it for
/// while its consensus runs: the certificate of a checkpoint it built but never saw a quorum of
/// signatures for. At an epoch end the validators that certified the last checkpoint reconfigure
/// and drop the epoch's DAG, so the commits carrying the remaining signatures can stop short of
/// this seat (a 2 deepwave + 2 sui-node committee then halts: neither half has a quorum for the next
/// epoch). The ckpt thread checks the certificate against what this seat built
/// (`Aggregator.addCertified`).
fn syncLoop(rt: *Runtime) void {
    const svc = rt.ssvc orelse return;
    const n = svc.opts.p2p.peerCount();
    if (n <= 1) return;
    var arena = std.heap.ArenaAllocator.init(rt.gpa);
    defer arena.deinit();
    var waiting: u64 = std.math.maxInt(u64);
    var since: u64 = 0;
    var last_try: u64 = 0;
    var first: usize = 0;
    while (!stop_flag.load(.acquire)) {
        sleepMs(250);
        const st = rt.ckpt.store();
        const next = st.nextToCertify();
        if (st.locallyComputedDigest(next) == null) {
            waiting = std.math.maxInt(u64);
            continue;
        }
        const now = monoMs();
        if (next != waiting) {
            waiting = next;
            since = now;
            continue;
        }
        if (now - since < pull_after_ms or now - last_try < pull_after_ms) continue;
        last_try = now;
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        const body = net.state_sync.encodeSummaryRequest(a, .{ .seq = next }) catch continue;
        for (0..n) |k| {
            if (stop_flag.load(.acquire)) return;
            const i = (first + k) % n;
            if (svc.opts.p2p.isSelf(i)) continue;
            const raw = svc.call(a, i, net.state_sync.Route.get_checkpoint_summary, body, pull_timeout_ms) orelse continue;
            const cert = (net.state_sync.optionPayload(raw) catch continue) orelse continue;
            rt.putPulled(cert);
            first = i;
            break;
        }
    }
}

// ------------------------------------------------------------------ zui-only catch-up

const stall_ms: u64 = 10_000;

fn knownOf(arena: Allocator, epoch: u64, members: anytype, cfg: *const protocol.ProtocolConfig) !catchup.Applier.Known {
    const out = try arena.alloc(checkpoint.Member, members.len);
    for (members, out) |m, *o| o.* = .{ .name = m.name, .stake = m.stake };
    return .{ .epoch = epoch, .members = out, .cfg = cfg };
}

/// `<db>/validator/epoch-N/rgp`: epoch N's reference gas price (read when the exec store is
/// already past N's ChangeEpoch as N starts).
fn writeRgp(rt: *Runtime, epoch: u64, rgp: u64) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&buf, "{s}/validator/epoch-{d}/rgp", .{ rt.db, epoch });
    var b8: [8]u8 = undefined;
    std.mem.writeInt(u64, &b8, rgp, .little);
    try keys.fsutil.makePath(rt.io, std.fs.path.dirname(path).?);
    try keys.fsutil.writeAtomic(rt.io, path, &b8);
}

fn rgpSinkFn(ctx: *anyopaque, epoch: u64, rgp: u64) anyerror!void {
    return writeRgp(@ptrCast(@alignCast(ctx)), epoch, rgp);
}

fn printCatchup(ap: *const catchup.Applier, ms: u64) void {
    std.debug.print("deepwave-validator: catch-up: state sync applied {d} checkpoints ({?d}..{d}), {d} tx executed, {d} already executed, {d} epoch ends, {d} ms\n", .{ ap.applied, ap.first_seq, ap.prev.seq, ap.executed_txs, ap.skipped_txs, ap.eoes.items.len, ms });
}

/// A runner for the catch-up thread (its own package caches), in the epoch context of the
/// process runner; the applier moves it from epoch to epoch.
fn catchupRunner(rt: *Runtime, r: *runner_mod.Runner) void {
    r.init(rt.gpa, &rt.exec, rt.runner.ctx);
}

/// Before the persisted epoch starts: apply the epochs the peers finished while this seat was
/// down, then start the epoch after the last one applied.
fn startupCatchup(rt: *Runtime, arena: Allocator, start: *emanager.SystemStateInfo) !void {
    var cl = catchup.Client.init(rt.ssvc.?);
    var probe = std.heap.ArenaAllocator.init(rt.gpa);
    defer probe.deinit();
    const b = cl.best(probe.allocator()) orelse {
        std.debug.print("deepwave-validator: catch-up: no peer answered at startup\n", .{});
        return;
    };
    const fin = catchup.Client.finishedEpoch(b);
    const mine = rt.ckpt.highestCertified() orelse 0;
    if (b.seq <= mine or fin == null or fin.? < start.info.epoch) {
        std.debug.print("deepwave-validator: catch-up: up to date at startup (own certified {d}, epoch {d}; best peer {d} epoch {d})\n", .{ mine, start.info.epoch, b.seq, b.epoch });
        return;
    }
    std.debug.print("deepwave-validator: catch-up: at startup own certified {d} (epoch {d}), peer {d} certified {d} (epoch {d}): fetching through the end of epoch {d}\n", .{ mine, start.info.epoch, b.peer, b.seq, b.epoch, fin.? });
    const cfg = protocol.get(start.info.protocol_version, .unknown) catch return error.Startup;
    var crun: runner_mod.Runner = undefined;
    catchupRunner(rt, &crun);
    defer crun.deinit();
    var ap = catchup.Applier.init(rt.gpa, &rt.ckpt, &rt.exec, &crun, try knownOf(arena, start.info.epoch, start.info.committee, cfg)) catch |e| {
        std.debug.print("deepwave-validator: catch-up: cannot start: {s}\n", .{@errorName(e)});
        return;
    };
    defer ap.deinit();
    ap.rgp_sink = .{ .ctx = rt, .f = rgpSinkFn };
    const t0 = monoMs();
    cl.run(&ap, b, &stop_flag) catch |e| {
        std.debug.print("deepwave-validator: catch-up: stopped: {s}\n", .{@errorName(e)});
        if (e == error.Fork or e == error.Execution) return error.Startup;
    };
    printCatchup(&ap, monoMs() - t0);
    const last = ap.eoes.getLastOrNull() orelse return;
    const cb = rt.ckpt.certifiedBytes(last) orelse return;
    const sp = catchup.split(arena, cb) catch return;
    if (rt.driver.nextFromSummary(arena, cb, sp.summary.epoch, start.transition.epoch_duration_ms) catch null) |next| {
        var tr = next.transition;
        if (Runtime.paramsGet(rt, next.info.epoch)) |p| tr.epoch_duration_ms = p.epoch_duration_ms;
        start.* = .{ .info = next.info, .transition = tr };
        std.debug.print("deepwave-validator: catch-up: epoch {d} ended at certified checkpoint {d}: starting epoch {d}\n", .{ sp.summary.epoch, last, next.info.epoch });
    }
}

/// What moves while the running epoch makes progress.
fn progressSig(rt: *Runtime) [5]u64 {
    rt.epoch_mu.lock();
    defer rt.epoch_mu.unlock();
    const e = rt.current orelse return .{ std.math.maxInt(u64), 0, 0, 0, 0 };
    const commit: u64 = if (e.cons) |c| @intCast(c.lastCommitIndex()) else 0;
    return .{ e.epoch, commit, @intCast(e.auth.handler.stats.commits), @intCast(rt.runner.executed), rt.ckpt.highestCertified() orelse 0 };
}

/// The running epoch made no progress for `stall_ms`: when a peer has certified the end of it,
/// apply the missing checkpoints and hand each epoch end to the driver.
fn catchupLoop(rt: *Runtime) void {
    var cl = catchup.Client.init(rt.ssvc orelse return);
    var last_sig: [5]u64 = @splat(0);
    var last_change = monoMs();
    var last_try: u64 = 0;
    while (!stop_flag.load(.acquire)) {
        sleepMs(500);
        const now = monoMs();
        const sig = progressSig(rt);
        if (!std.mem.eql(u64, &sig, &last_sig)) {
            last_sig = sig;
            last_change = now;
            continue;
        }
        if (now - last_change < stall_ms or now - last_try < stall_ms) continue;
        last_try = now;
        catchUpRunning(rt, &cl, (now - last_change) / 1000);
    }
}

fn catchUpRunning(rt: *Runtime, cl: *catchup.Client, stalled_s: u64) void {
    var probe = std.heap.ArenaAllocator.init(rt.gpa);
    defer probe.deinit();
    const pa = probe.allocator();
    const b = cl.best(pa) orelse return;
    const fin = catchup.Client.finishedEpoch(b) orelse return;
    const e = rt.pin() orelse return;
    const cur = e.epoch;
    const known = knownOf(pa, cur, e.ccommittee.members, e.cfg) catch {
        Runtime.unpin(e);
        return;
    };
    Runtime.unpin(e);
    if (fin < cur) return;
    std.debug.print("deepwave-validator: catch-up: epoch {d} stalled {d} s; peer {d} certified {d} (epoch {d}{s}): fetching through the end of epoch {d}\n", .{ cur, stalled_s, b.peer, b.seq, b.epoch, if (b.eoe) ", its end" else "", fin });
    // this epoch's builder stops: what it would still build is applied from certified checkpoints
    rt.ckpt_frozen.store(@intCast(fin), .release);
    var crun: runner_mod.Runner = undefined;
    catchupRunner(rt, &crun);
    defer crun.deinit();
    var ap = catchup.Applier.init(rt.gpa, &rt.ckpt, &rt.exec, &crun, known) catch |err| {
        std.debug.print("deepwave-validator: catch-up: cannot start: {s}\n", .{@errorName(err)});
        return;
    };
    defer ap.deinit();
    ap.rgp_sink = .{ .ctx = rt, .f = rgpSinkFn };
    const t0 = monoMs();
    cl.run(&ap, b, &stop_flag) catch |err| {
        std.debug.print("deepwave-validator: catch-up: stopped: {s}\n", .{@errorName(err)});
        if (err == error.Fork or err == error.Execution) {
            rt.failed.store(true, .release);
            stop_flag.store(true, .release);
            return;
        }
    };
    printCatchup(&ap, monoMs() - t0);
    const sink = rt.driver.certifiedSink();
    for (ap.eoes.items) |seq| {
        const cb = rt.ckpt.certifiedBytes(seq) orelse break;
        const contents = (rt.ckpt.store().builtContents(pa, seq) catch null) orelse "";
        sink.certified(seq, cb, contents) catch |err| {
            std.debug.print("deepwave-validator: catch-up: epoch switch at checkpoint {d}: {s}\n", .{ seq, @errorName(err) });
            break;
        };
    }
}

fn report(rt: *Runtime, elapsed_ms: u64) void {
    rt.epoch_mu.lock();
    defer rt.epoch_mu.unlock();
    const e = rt.current orelse {
        std.debug.print("deepwave-validator: t={d}s no epoch running\n", .{elapsed_ms / 1000});
        return;
    };
    if (e.cons) |c| if (c.coreFailed()) {
        // a dead consensus core leaves the seat silent: exit so a restart recovers from the store
        log.err("epoch {d}: consensus core failed; stopping", .{e.epoch});
        rt.failed.store(true, .release);
        stop_flag.store(true, .release);
    };
    const cons_commits: u64 = if (e.cons) |c| c.lastCommitIndex() else 0;
    const hs = &e.auth.handler.stats;
    std.debug.print("deepwave-validator: t={d}s epoch {d} consensus commit {d} delivered {d} handled {d} pending-ckpt {d} built {d} certified-through {?d} executed {d} failed-exec {d} exec-queue {d} exec-dropped {d} dkg {s} randomness-round {?d} completed {d}{s}{s}\n", .{
        elapsed_ms / 1000,
        e.epoch,
        cons_commits,
        if (e.cons) |c| c.deliveredThrough() else 0,
        hs.commits,
        hs.pending_checkpoints,
        e.stats.built.load(.monotonic),
        rt.ckpt.highestCertified(),
        rt.runner.executed,
        rt.runner.failed,
        e.auth.bridge.queue.items.len,
        e.auth.bridge.unsupported,
        if (e.rmgr) |m| @tagName(m.dkgStatus()) else "off",
        e.auth.state.randomness_last,
        e.completed_through,
        if (rt.runner.lastError().len != 0) " last-exec-error: " else "",
        rt.runner.lastError(),
    });
}

fn testNowMs() u64 {
    return 1_000_000;
}

test "submit: a retry of a transaction that already executed answers Executed, not a rejection on its spent gas" {
    // Under kill -9 chaos a load lane's transaction executed while its
    // WaitForEffects ran on the seat that died; every retry was rejected on the spent gas version
    // and the lane never got its effects.
    const gpa = std.testing.allocator;
    const fixture = authority.preverify_fixture;
    const f = try fixture.Fixture.create(gpa);
    defer f.destroy();
    // the gas coin is not live at the signed version any more (the transaction consumed it)
    const made = try f.makeTx(.{ .signer = fixture.Signer.edSeed(1), .coin = 1, .put_coin = false });
    const tx = try bcs.decode(@import("../messages.zig").Transaction, f.arena(), made.raw);
    const td_bcs = try bcs.encodeAlloc(types.TransactionData, f.arena(), &tx.data.@"0".items[0].intent_message.value);
    const digest = types.digest.transactionDataDigest(td_bcs);

    var exec = exec_store.ExecStore.openMem(gpa, std.testing.io);
    defer exec.close();
    try exec.commitTx(&.{ .digest = digest, .td_bcs = td_bcs, .effects_bcs = "effects", .written = &.{} });
    const want = exec.executed(&digest).?.effects_digest;

    var ctl = try env_mod.LocalEpochControl.init(gpa, &f.stakes);
    defer ctl.deinit();
    var state = state_mod.EpochState.init(gpa);
    defer state.deinit();
    var adapter = authority.adapter.Adapter.init(gpa, .{});
    defer adapter.deinit();
    var s: submit_mod.Submit = .{
        .gpa = gpa,
        .params = f.params,
        .cfg = f.cfg,
        .check_env = &f.env,
        .state = &state,
        .epoch_ctl = ctl.control(),
        .adapter = &adapter,
        .own_index = 0,
        .own_name = .{ .@"0" = @splat(0) },
        .now_ms = testNowMs,
        .hooks = submitHooks(&exec),
    };
    defer s.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    var failure: submit_mod.Failure = undefined;
    const resp = try s.handle(ar.allocator(), .{ .transactions = &.{made.raw} }, &failure);
    try std.testing.expectEqual(@as(usize, 1), resp.results.len);
    switch (resp.results[0]) {
        .executed => |x| try std.testing.expectEqualSlices(u8, &want, &x.effects_digest),
        .submitted => return error.TestUnexpectedResult,
        .rejected => |m| {
            std.debug.print("rejected: {s}\n", .{m});
            return error.TestUnexpectedResult;
        },
    }
    try std.testing.expectEqual(@as(usize, 0), adapter.pendingUser());

    // without the hook (the runtime before this fix) the same retry is rejected
    s.hooks = .{};
    const again = try s.handle(ar.allocator(), .{ .transactions = &.{made.raw} }, &failure);
    try std.testing.expect(again.results[0] == .rejected);
}

test "stored execution time observation fields: chunk count and chunk ids of a localnet's extra_fields bag" {
    // ids read from a 1.83.1 localnet (sui-node created them in store_execution_time_estimates_v2)
    var bag: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bag, "9b12f6031f7976bcc6d80083ab839f44e45f45b8a9b43e606a42c85ae88125f5");
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "5543199301f075ce60cf8b4140b2fbf2300624109edb795c946b4eec1e0f5492");
    try std.testing.expectEqual(want, serve.sysstate.u64FieldId(&bag, 1));
    _ = try std.fmt.hexToBytes(&want, "bedd615e905019c57bb473f8c5592469d37ec6da6ef371d17d649c71dd9a1560");
    try std.testing.expectEqual(want, chunkFieldId(&bag, 0));
}
