//! ExecuteTransaction in deepwave (DROP-IN G10): the live executor over the node's own store.
//!
//!   deepwave run ... --serve ADDR --execute-epoch-from HOST:PORT[/plain]
//!
//! - The committee (validator network keys, addresses, voting power) and the reference gas price
//!   come from a `GetEpoch` call to HOST:PORT, refreshed every 60 s and within 5 s after a drive
//!   fails (`EpochRefresher`); the connection to HOST:PORT reconnects (`Upstream`). On the box that is sui-node (127.0.0.1:9000/plain) during the
//!   shadow; once deepwave serves GetEpoch itself (G6) it is deepwave's own --serve address, with no code
//!   change here.
//! - Already-executed transactions are answered from the node's store (`local.StoreLocal`).
//! - User signatures are verified before submission, with AddressAliases read from the store.
//! - A retriable failure keeps the transaction going in the background (sui-node's retry).
//! - The pending-tx log (`pending_log.zig`, sui-node's `fullnode_pending_transactions`) under
//!   `pending_dir`: what a killed node was submitting is submitted again after the restart.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const serve = @import("serve");
const store = @import("store");
const bcs = @import("bcs");
const types = @import("types");
const h2 = serve.h2;
const grpc = @import("grpc_client.zig");
const validators = @import("validators.zig");
const local = @import("local.zig");
const usersig = @import("usersig.zig");
const early = @import("early.zig");
const handler = @import("../driver/handler.zig");
const errors = @import("../driver/errors.zig");
const Upstream = @import("upstream.zig").Upstream;
const pending_log = @import("pending_log.zig");
const simulate = @import("../simulate.zig");

const path_get_epoch = "/sui.rpc.v2.LedgerService/GetEpoch";
pub const path_execute = "/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction";
pub const prefix = "/sui.rpc.v2.TransactionExecutionService/";

/// `ExecuteTransaction` over an executor as an h2 handler (sui-rpc-api's tonic service).
/// Other TransactionExecutionService methods answer UNIMPLEMENTED (SimulateTransaction is G9's).
pub const ExecuteService = struct {
    gpa: Allocator,
    ex: handler.Executor,

    pub fn handler_(self: *ExecuteService) h2.Handler {
        return .{ .ctx = self, .call = call };
    }

    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const self: *ExecuteService = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, req.path, path_execute)) return .unimplemented;
        var a = std.heap.ArenaAllocator.init(self.gpa);
        defer a.deinit();
        // the server deadline (sui-node: grpc-timeout-ms 60 s or the client's grpc-timeout)
        validators.deadline_hit = false;
        validators.server_budget_ns = if (req.deadline_ns) |d| d -| h2.meta.monoNs() else null;
        validators.handler_start_ns = h2.meta.monoNs();
        defer validators.server_budget_ns = null;
        const r = handler.executeTransaction(a.allocator(), self.ex, req.body) catch {
            rs.setMessage("out of memory");
            return .resource_exhausted;
        };
        if (validators.deadline_hit) return rs.deadlineExceeded();
        switch (r) {
            .ok => |b| {
                rs.message(b) catch return .internal;
                return .ok;
            },
            .err => |e| {
                rs.setMessage(e.message);
                if (e.details.len > 0) rs.details(e.details);
                return if (e.code == 0 or e.code > 16) .internal else @enumFromInt(e.code);
            },
        }
    }
};

/// `HOST:PORT` (TLS against the system CAs) or `HOST:PORT/plain` (h2c).
pub fn parseUpstream(s: []const u8) ?grpc.Endpoint {
    var text = s;
    var plain = false;
    if (std.mem.endsWith(u8, text, "/plain")) {
        plain = true;
        text = text[0 .. text.len - 6];
    }
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return null;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return null;
    if (colon == 0) return null;
    return .{ .host = text[0..colon], .port = port, .security = if (plain) .plain else .ca };
}

/// One `GetEpoch` with the committee mask; the reply is allocated in `arena`.
pub fn fetchEpoch(arena: Allocator, up: *Upstream) ![]const u8 {
    const req = try validators.getEpochRequest(arena);
    return switch (try up.call(arena, path_get_epoch, req, 15_000)) {
        .ok => |b| b,
        .status => |s| {
            std.log.err("execute: GetEpoch from the epoch source failed: {d} {s}", .{ s.code, s.message });
            return error.Upstream;
        },
    };
}

/// Keeps the executor's committee current: a `GetEpoch` at start (retried every `retry_ms` until
/// one succeeds), then every `refresh_ms`, and at once (at most every `min_gap_ms`) after a drive
/// failed (`kick`): at reconfiguration the old committee answers wrong-epoch / halted-at-epoch-end
/// errors, and sui-node swaps its aggregator at that moment rather than a minute later. The
/// upstream reconnects by itself (`Upstream`).
pub const EpochRefresher = struct {
    gpa: Allocator,
    io: Io,
    ex: *validators.LiveExecutor,
    up: *Upstream,
    label: []const u8 = "",
    refresh_ms: u64 = 60_000,
    retry_ms: u64 = 2_000,
    min_gap_ms: u64 = 5_000,
    mu: Io.Mutex = .init,
    cond: Io.Condition = .init,
    kicked: bool = false,
    last_fetch_ns: u64 = 0,
    fetches: std.atomic.Value(u64) = .init(0),

    pub fn start(r: *EpochRefresher) !void {
        (try std.Thread.spawn(.{}, loop, .{r})).detach();
    }

    /// A drive failed: refresh soon.
    pub fn kick(r: *EpochRefresher) void {
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        r.kicked = true;
        r.cond.signal(r.io);
    }

    pub fn hook(r: *EpochRefresher) validators.DriveErrorHook {
        return .{ .ctx = r, .f = onDriveError };
    }

    fn onDriveError(ctx: *anyopaque, _: *const errors.SubmissionError) void {
        const r: *EpochRefresher = @ptrCast(@alignCast(ctx));
        r.kick();
    }

    /// One refresh now. True when a committee is installed.
    pub fn once(r: *EpochRefresher) bool {
        var a = std.heap.ArenaAllocator.init(r.gpa);
        defer a.deinit();
        _ = r.fetches.fetchAdd(1, .monotonic);
        const body = fetchEpoch(a.allocator(), r.up) catch return false;
        const before = r.ex.epoch();
        const e = r.ex.setEpoch(body) catch |err| {
            std.log.err("execute: committee refresh: {s}", .{@errorName(err)});
            return false;
        };
        if (before == null or before.? != e) std.log.info("execute: committee of epoch {d}{s}{s}", .{ e, if (r.label.len > 0) " from " else "", r.label });
        return true;
    }

    fn loop(r: *EpochRefresher) void {
        while (true) {
            const ok = r.once();
            r.mu.lockUncancelable(r.io);
            r.last_fetch_ns = validators.monotonicNs(r.io);
            r.kicked = false;
            // no committee yet: retry soon; otherwise wait for the period or a kick
            const wait_ms = if (!ok and r.ex.epoch() == null) r.retry_ms else r.refresh_ms;
            const until = r.last_fetch_ns + wait_ms * std.time.ns_per_ms;
            while (true) {
                const now = validators.monotonicNs(r.io);
                if (now >= until) break;
                if (r.kicked and now -| r.last_fetch_ns >= r.min_gap_ms * std.time.ns_per_ms) break;
                const next = if (r.kicked) @min(until, r.last_fetch_ns + r.min_gap_ms * std.time.ns_per_ms) else until;
                r.cond.waitTimeout(r.io, &r.mu, .{ .duration = .{ .raw = .fromNanoseconds(@intCast(next -| now)), .clock = .awake } }) catch {};
            }
            r.mu.unlock(r.io);
        }
    }
};

/// Everything the node keeps for ExecuteTransaction. Lives as long as the node.
pub const NodeExec = struct {
    gpa: Allocator,
    io: Io,
    st: *store.Store,
    up: *Upstream,
    ex: validators.LiveExecutor,
    local_src: local.StoreLocal,
    svc: ExecuteService,
    refresher: EpochRefresher,

    /// How deepwave drives a transaction through the validators (`--exec-driver`).
    pub const Driver = enum {
        /// deepwave's default: submission to the 3 best-ranked proposers at once and full effects
        /// with the 4 fastest acknowledgments (same responses; about half sui-node's latency).
        zui,
        /// sui-node 1.83.1 exactly: amplification gas price / RGP (1 at the reference price),
        /// acknowledgments without details, full effects from one validator with fallbacks.
        @"sui-node",
    };

    /// Starts the committee refresh against the epoch source. Never fails on the network: until
    /// the first committee arrives, ExecuteTransaction answers "no committee yet" (the node's
    /// sync and reads start regardless, so a sui-node down at boot does not keep deepwave down).
    pub fn start(gpa: Allocator, io: Io, st: *store.Store, epoch_from: []const u8, pending_dir: ?[]const u8) !*NodeExec {
        return startWith(gpa, io, st, epoch_from, pending_dir, .zui);
    }

    /// `start` with the validator driver chosen (`--exec-driver`).
    pub fn startWith(gpa: Allocator, io: Io, st: *store.Store, epoch_from: []const u8, pending_dir: ?[]const u8, driver: Driver) !*NodeExec {
        const ep = parseUpstream(epoch_from) orelse return error.BadEpochSource;
        const self = try gpa.create(NodeExec);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .st = st,
            .up = try Upstream.init(gpa, io, ep),
            .ex = validators.LiveExecutor.init(gpa, io),
            .local_src = .{ .st = st },
            .svc = undefined,
            .refresher = undefined,
        };
        self.ex.local = self.local_src.localEffects();
        // the store answers by digest in microseconds: race it every 50 ms
        self.ex.local_race_ms = 50;
        self.ex.sig_env = .{ .aliases = .{ .ctx = self, .get = aliasesFromStore } };
        self.ex.live_objects = .{ .ctx = self, .get = liveFromStore, .at = objectFromStore, .latest = latestFromStore };
        self.ex.latency_checks = true;
        if (driver == .@"sui-node") {
            self.ex.min_amplification = 1;
            self.ex.detail_acks = 0;
        }
        self.ex.render = .{ .ctx = self, .make = makeRender };
        self.svc = .{ .gpa = gpa, .ex = self.ex.executor() };
        self.refresher = .{ .gpa = gpa, .io = io, .ex = &self.ex, .up = self.up, .label = epoch_from };
        self.ex.on_drive_error = self.refresher.hook();
        if (pending_dir) |d| {
            const l = try pending_log.PendingLog.open(gpa, io, d);
            self.ex.pending = l;
            if (l.torn_bytes > 0) std.log.warn("execute: pending-tx log {s}: {d} bytes of a torn tail dropped", .{ d, l.torn_bytes });
            std.log.info("execute: pending-tx log {s}: {d} pending transactions", .{ d, l.count() });
        }
        try self.refresher.start();
        // after the first committee (the thread waits for it)
        try self.ex.recoverPending();
        return self;
    }

    /// The h2 handler for `/sui.rpc.v2.TransactionExecutionService/*`.
    /// Simulate's proposer selector (sui-node: `with_proposer_selector(transaction_driver)`).
    pub fn proposerSelector(self: *NodeExec) simulate.Engine.ProposerSelector {
        return .{ .ctx = &self.ex, .preferred = preferred };
    }

    fn preferred(ctx: *anyopaque, arena: Allocator, max: usize) Allocator.Error!?types.AllowedProposers {
        const ex: *validators.LiveExecutor = @ptrCast(@alignCast(ctx));
        return ex.preferredProposers(arena, max);
    }

    pub fn handler(self: *NodeExec) h2.Handler {
        return self.svc.handler_();
    }

    fn liveFromStore(ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?early.Live {
        const self: *NodeExec = @ptrCast(@alignCast(ctx));
        var snap = self.st.snapshot();
        defer snap.release();
        const o = snap.liveObject(id) orelse return null;
        return early.liveOf(o.bytes, o.digest, arena);
    }

    fn makeRender(ctx: *anyopaque, arena: Allocator, objects: []const []const u8) ?*const serve.render_object.Ctx {
        return validators.RenderSource.make(arena, objects, ctx, latestFromStore);
    }

    fn latestFromStore(ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?[]const u8 {
        const self: *NodeExec = @ptrCast(@alignCast(ctx));
        var snap = self.st.snapshot();
        defer snap.release();
        const o = snap.liveObject(id) orelse return null;
        return arena.dupe(u8, o.bytes) catch null;
    }

    /// Early validation's epoch environment (protocol config, reference gas price, chain): the
    /// node's system-state cache (`rpc_exec.epoch_env.Cache`).
    pub fn setEnv(self: *NodeExec, src: early.EnvFn) void {
        if (self.ex.live_objects) |*lo| lo.env = src;
    }

    fn objectFromStore(ctx: *anyopaque, arena: Allocator, id: *const [32]u8, version: u64) ?[]const u8 {
        const self: *NodeExec = @ptrCast(@alignCast(ctx));
        var snap = self.st.snapshot();
        defer snap.release();
        const b = snap.objectAt(id, version) orelse return null;
        return arena.dupe(u8, b) catch null;
    }

    fn aliasesFromStore(ctx: *anyopaque, arena: Allocator, signer: *const [32]u8, _: bool) usersig.Aliases {
        const self: *NodeExec = @ptrCast(@alignCast(ctx));
        var snap = self.st.snapshot();
        defer snap.release();
        const id = usersig.aliasesObjectId(signer);
        const o = snap.liveObject(&id) orelse return .none;
        const obj = bcs.decode(types.Object, arena, o.bytes) catch return .unknown;
        return switch (obj.data) {
            .Move => |mo| if (usersig.parseAliases(arena, mo.contents)) |al| .{ .set = al } else .unknown,
            else => .unknown,
        };
    }
};
