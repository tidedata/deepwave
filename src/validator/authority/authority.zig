//! The composition root of val-authority: wires the epoch state and its durable log, the
//! consensus adapter, the block transaction validator, the consensus handler, the execution
//! bridge, the status and reject-reason caches, and SubmitTransaction / WaitForEffects around one
//! epoch. The epoch lane builds one per epoch (and drops it at reconfiguration); the local
//! committee harness builds four.
//!
//! Threads (docs/VALIDATOR-DESIGN 7): the consensus core calls `commitSink()`/`txSource()`/
//! `txVerifier()`; the handler thread calls `step()` in a loop (drain commits, then run
//! executable transactions); API threads call `submit` and `waitForEffects`.
const std = @import("std");
const protocol = @import("protocol");
const consensus = @import("consensus");
const iface = @import("../iface.zig");
const state_mod = @import("state.zig");
const epoch_log = @import("epoch_log.zig");
const env_mod = @import("env.zig");
const congestion = @import("congestion.zig");
const exec_bridge = @import("exec_bridge.zig");
const adapter_mod = @import("adapter.zig");
const status_mod = @import("status.zig");
const tx_validator = @import("tx_validator.zig");
const handler_mod = @import("handler.zig");
const submit_mod = @import("submit.zig");
const checker = @import("checker.zig");
const versions = @import("versions.zig");
const preverify = @import("preverify.zig");

const Allocator = std.mem.Allocator;

pub const Config = struct {
    params: env_mod.Params,
    cfg: *const protocol.ProtocolConfig,
    /// Committee in consensus AuthorityIndex order, with stakes.
    committee: []const iface.AuthorityName,
    stakes: []const u64,
    own_index: ?u32,
    epoch_ctl: env_mod.EpochControl,
    check_env: *const checker.Env,
    reader: versions.ObjectReader,
    runner: exec_bridge.Runner,
    router: handler_mod.Router = .{},
    pending_sink: ?iface.PendingCheckpointSink = null,
    jwks: ?handler_mod.JwkSource = null,
    adapter_limits: adapter_mod.Limits = .{},
    /// Wall clock in ms (required: in-flight suppression and retry windows depend on it).
    now_ms: *const fn () u64,
    tracer: iface.Tracer = .{},
    /// BCS `StoredExecutionTimeObservations` chunks of the previous epoch's end-of-epoch
    /// observations (system state extra_fields, chunk order), loaded by the epoch lane.
    /// Required for exact congestion estimates when the previous epoch stored any.
    stored_observation_chunks: []const []const u8 = &.{},
    /// Signature pre-verification on both intake paths (block votes and SubmitTransaction):
    /// zui-only, results unchanged; `--sig-preverify` of deepwave-validator.
    sig_preverify: preverify.Config = .{},
};

pub const Authority = struct {
    gpa: Allocator,
    state: state_mod.EpochState,
    mem_log: epoch_log.MemLog,
    file_log: ?epoch_log.FileLog = null,
    adapter: adapter_mod.Adapter,
    reasons: tx_validator.ReasonCache,
    statuses: status_mod.StatusCache,
    estimator: congestion.Estimator,
    bridge: exec_bridge.Bridge,
    validator: tx_validator.TxValidator,
    handler: handler_mod.Handler,
    submit: submit_mod.Submit,
    wait: submit_mod.WaitForEffects,

    /// Heap-allocated: the parts hold pointers to each other.
    pub fn create(gpa: Allocator, c: Config, file_log_path: ?struct { io: std.Io, path: []const u8 }) !*Authority {
        const a = try gpa.create(Authority);
        errdefer gpa.destroy(a);
        a.gpa = gpa;
        a.state = state_mod.EpochState.init(gpa);
        errdefer a.state.deinit();
        a.state.window = c.params.commit_rate_window;
        a.mem_log = epoch_log.MemLog.init(gpa);
        errdefer a.mem_log.deinit();
        a.file_log = null;
        if (file_log_path) |fp| {
            a.file_log = try epoch_log.FileLog.open(gpa, fp.io, fp.path, state_mod.Replay{ .state = &a.state }, state_mod.Replay.visit);
        }
        errdefer if (a.file_log) |*f| f.close();
        const log: handler_mod.DurableLog = if (a.file_log) |*f| handler_mod.DurableLog.fromFile(f) else handler_mod.DurableLog.fromMem(&a.mem_log);

        a.adapter = adapter_mod.Adapter.init(gpa, c.adapter_limits);
        errdefer a.adapter.deinit();
        a.reasons = .{ .gpa = gpa };
        errdefer a.reasons.deinit();
        a.statuses = .{ .gpa = gpa };
        errdefer a.statuses.deinit();
        a.estimator = congestion.Estimator.init(gpa, c.stakes, c.params.congestion);
        errdefer a.estimator.deinit();
        a.bridge = exec_bridge.Bridge.init(gpa, c.runner);
        errdefer a.bridge.deinit();
        a.validator = tx_validator.TxValidator.init(gpa, c.params, c.cfg, c.check_env, c.epoch_ctl, &a.reasons);
        errdefer a.validator.deinit();
        a.validator.preverify = c.sig_preverify;
        a.handler = try handler_mod.Handler.init(gpa, .{
            .params = c.params,
            .committee = c.committee,
            .state = &a.state,
            .log = log,
            .epoch_ctl = c.epoch_ctl,
            .router = c.router,
            .exec = &a.bridge,
            .reader = c.reader,
            .estimator = &a.estimator,
            .pending_sink = c.pending_sink,
            .jwks = c.jwks,
            .adapter = &a.adapter,
            .statuses = &a.statuses,
            .reasons = &a.reasons,
            .tracer = c.tracer,
        });
        errdefer a.handler.deinit();
        {
            var ar: std.heap.ArenaAllocator = .init(gpa);
            defer ar.deinit();
            // previous epoch's stored observations first, then this epoch's sequenced ones
            try a.handler.seedEstimator(ar.allocator(), c.stored_observation_chunks);
            try a.handler.restoreEstimator(ar.allocator());
        }
        a.handler.attachBridge(&a.bridge);
        // a randomness reservation that was durable survives the restart; one that was not is made again
        if (c.router.randomness) |rh| if (rh.vtable.restore_last_round) |f| if (a.state.randomness_last) |last| f(rh.ctx, last);
        try a.reenqueueUnexecuted();
        a.submit = .{
            .gpa = gpa,
            .params = c.params,
            .cfg = c.cfg,
            .check_env = c.check_env,
            .state = &a.state,
            .epoch_ctl = c.epoch_ctl,
            .adapter = &a.adapter,
            .own_index = c.own_index,
            .own_name = if (c.own_index) |i| c.committee[i] else .{ .@"0" = @splat(0) },
            .now_ms = c.now_ms,
            .preverify = c.sig_preverify,
        };
        a.wait = .{ .epoch = c.params.epoch, .statuses = &a.statuses, .exec = &a.bridge, .reasons = &a.reasons };
        return a;
    }

    /// After a restart: scheduled items that were durable but not acknowledged as executed go
    /// back to the executor in their original order.
    fn reenqueueUnexecuted(a: *Authority) !void {
        const Rec = state_mod.AssignedRecord;
        var list: std.ArrayList(Rec) = .empty;
        defer list.deinit(a.gpa);
        var it = a.state.assigned.valueIterator();
        while (it.next()) |r| if (r.exec != null) try list.append(a.gpa, r.*);
        std.mem.sort(Rec, list.items, {}, struct {
            fn less(_: void, x: Rec, y: Rec) bool {
                return x.seq < y.seq;
            }
        }.less);
        for (list.items) |r| {
            const x = r.exec.?;
            try a.bridge.enqueue(.{
                .key = r.key,
                .kind = @enumFromInt(x.kind),
                .td_bcs = x.td_bcs,
                .digest = x.digest,
                .shared = r.shared,
                .system = r.system,
                .owned = x.owned,
            });
        }
    }

    pub fn destroy(a: *Authority) void {
        const gpa = a.gpa;
        a.submit.deinit();
        a.handler.deinit();
        a.validator.deinit();
        a.bridge.deinit();
        a.estimator.deinit();
        a.statuses.deinit();
        a.reasons.deinit();
        a.adapter.deinit();
        if (a.file_log) |*f| f.close();
        a.mem_log.deinit();
        a.state.deinit();
        gpa.destroy(a);
    }

    pub fn commitSink(a: *Authority) consensus.iface.CommitSink {
        return a.handler.commitSink();
    }
    pub fn txSource(a: *Authority) consensus.iface.TransactionSource {
        return a.adapter.source();
    }
    pub fn txVerifier(a: *Authority) consensus.iface.TransactionVerifier {
        return a.validator.verifier();
    }
    pub fn consensusSubmit(a: *Authority) iface.ConsensusSubmit {
        return a.adapter.submitter();
    }
    pub fn txExecutor(a: *Authority) iface.TxExecutor {
        return a.bridge.txExecutor();
    }

    /// One handler-thread iteration: process queued commits, then run executable transactions.
    pub fn step(a: *Authority, scratch: Allocator) !usize {
        const n = try a.handler.drain();
        _ = try a.bridge.pump(scratch);
        return n;
    }
};

const Clock = struct {
    fn now() u64 {
        return 1_000;
    }
};

test "authority wires up and tears down" {
    const gpa = std.testing.allocator;
    const cfg = try protocol.get(141, .mainnet);
    var stakes = [_]u64{ 2500, 2500, 2500, 2500 };
    var ctl = try env_mod.LocalEpochControl.init(gpa, &stakes);
    defer ctl.deinit();
    var committee: [4]iface.AuthorityName = undefined;
    for (&committee, 0..) |*c, i| c.* = .{ .@"0" = @splat(@intCast(i + 1)) };
    var mem: exec_bridge.MemRunner = .{ .gpa = gpa };
    defer mem.deinit();
    const Dummy = struct {
        fn current(_: *anyopaque, _: *const [32]u8) ?versions.ObjectReader.Current {
            return null;
        }
        const vt: versions.ObjectReader.VTable = .{ .current = current };
    };
    var dummy: u8 = 0;
    var params = env_mod.Params.fromProtocol(cfg, 1, 0, 1000);
    params.commit_rate_window = 4;
    params.randomness_isv = 1;
    params.authenticator_isv = 1;
    params.implicit.accumulator_root = 1;
    const a = try Authority.create(gpa, .{
        .params = params,
        .cfg = cfg,
        .committee = &committee,
        .stakes = &stakes,
        .own_index = 0,
        .epoch_ctl = ctl.control(),
        .check_env = undefined,
        .reader = .{ .ctx = &dummy, .vtable = &Dummy.vt },
        .runner = mem.runner(),
        .now_ms = Clock.now,
    }, null);
    defer a.destroy();
    try std.testing.expectEqual(@as(usize, 0), try a.step(gpa));
    // a non-user submission goes through the adapter
    try a.consensusSubmit().submit(&.{"x"}, .system);
    var out: [2]consensus.types.Transaction = undefined;
    try std.testing.expectEqual(@as(usize, 1), a.txSource().next(&out, 100));
}
