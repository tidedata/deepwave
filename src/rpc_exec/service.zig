//! sui.rpc.v2 TransactionExecutionService over HTTP/2 (serve's h2 server): SimulateTransaction
//! runs on a store snapshot of the latest state; ExecuteTransaction goes to the driver (see
//! driver/). The node mounts `handler()` next to serve's: `routes(path)` tells the two apart.
const std = @import("std");
const store = @import("store");
const serve = @import("serve");

const root = @import("root.zig");
const state_mod = @import("state.zig");
const simulate = @import("simulate.zig");
const driver = @import("driver/root.zig");

const Allocator = std.mem.Allocator;
const h2 = serve.h2;

pub const prefix = "/sui.rpc.v2.TransactionExecutionService/";

/// True for the paths this service answers.
pub fn routes(path: []const u8) bool {
    return std.mem.startsWith(u8, path, prefix);
}

/// The epoch the node is in: protocol config, reference gas price, start time, committee size.
pub const EnvSource = struct {
    ctx: *const anyopaque,
    get: *const fn (ctx: *const anyopaque) ?root.EpochEnv,
};

/// ExecuteTransaction entry (the driver's handler); null validates the request and then answers
/// UNIMPLEMENTED "no transaction executor" (`driver.handler.noExecutor`).
pub const ExecuteFn = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, arena: Allocator, body: []const u8) Allocator.Error!root.Reply,
};

/// ExecuteFn over the driver's handler: `executor` (a DriverExecutor over a real transport, or a
/// fixed one in tests) must outlive the service.
pub fn driverExecute(executor: *const driver.handler.Executor) ExecuteFn {
    return .{ .ctx = @constCast(executor), .call = struct {
        fn call(ctx: *anyopaque, arena: Allocator, body: []const u8) Allocator.Error!root.Reply {
            const ex: *const driver.handler.Executor = @ptrCast(@alignCast(ctx));
            return driver.handler.executeTransaction(arena, ex.*, body);
        }
    }.call };
}

pub const Service = struct {
    gpa: Allocator,
    store: *store.Store,
    engine: simulate.Engine,
    env: EnvSource,
    execute: ?ExecuteFn = null,
    /// suggested_gas_price's tracker (fed by its own thread, see `Congestion.follow`).
    congestion: ?*Congestion = null,
    /// The owner index gas selection reads (deepwave with `--indexes`); null: gas selection
    /// answers NOT_FOUND, as sui-node without rpc indexes does. Set before requests are served.
    gas_coins: ?state_mod.GasCoinSource = null,

    /// The pre-state of one request at `snap`: the snapshot, plus the owner index when there is one.
    pub fn stateAt(self: *const Service, snap: *const store.Snapshot, holder: *state_mod.IndexedSnapshot) state_mod.State {
        const coins = self.gas_coins orelse return state_mod.State.fromSnapshot(snap);
        holder.* = .{ .snap = snap, .coins = coins };
        return holder.state();
    }

    pub fn handler(self: *Service) h2.Handler {
        return .{ .ctx = self, .call = call };
    }
};

fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    const self: *Service = @ptrCast(@alignCast(ctx));
    if (!routes(req.path)) return .unimplemented;
    var arena_state = std.heap.ArenaAllocator.init(self.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const method = req.path[prefix.len..];
    const r: root.Reply = if (std.mem.eql(u8, method, "SimulateTransaction")) blk: {
        const env = self.env.get(self.env.ctx) orelse {
            rs.setMessage("epoch state unavailable");
            return .unavailable;
        };
        var snap = self.store.snapshot();
        defer snap.release();
        var indexed: state_mod.IndexedSnapshot = undefined;
        var engine = self.engine;
        engine.client_protocol_version = req.client_protocol_version;
        break :blk engine.simulate(arena, &env, self.stateAt(&snap, &indexed), req.body) catch {
            rs.setMessage("out of memory");
            return .resource_exhausted;
        };
    } else if (std.mem.eql(u8, method, "ExecuteTransaction")) blk: {
        // no executor: the request is validated first, as a sui-node full node does
        const ex = self.execute orelse break :blk driver.handler.noExecutor(arena, req.body) catch {
            rs.setMessage("out of memory");
            return .resource_exhausted;
        };
        break :blk ex.call(ex.ctx, arena, req.body) catch {
            rs.setMessage("out of memory");
            return .resource_exhausted;
        };
    } else return .unimplemented;
    switch (r) {
        .ok => |bytes| {
            rs.message(bytes) catch return .internal;
            return .ok;
        },
        .err => |e| {
            rs.setMessage(e.message);
            if (e.details.len > 0) rs.details(e.details);
            return if (e.code == 0 or e.code > 16) .internal else @enumFromInt(e.code);
        },
    }
}

/// The congestion tracker behind a mutex: `price` (the request path, through `Engine.suggest`)
/// reads it; one background thread feeds it from the store's committed checkpoints (`follow`),
/// holding the mutex only while it applies a decoded checkpoint.
pub const Congestion = struct {
    io: std.Io,
    mu: std.Io.Mutex = .init,
    t: root.congestion.Tracker,

    /// Feeds every checkpoint committed since the last call (one snapshot, its own tip). Only one
    /// thread may call it. Returns how many checkpoints were read.
    pub fn feed(c: *Congestion, st: *store.Store) usize {
        var snap = st.snapshot();
        defer snap.release();
        return c.t.catchUpLocked(root.congestion.SnapshotSource{ .snap = &snap }, .{ .mu = &c.mu, .io = c.io });
    }

    /// Follows the store until `stop`: feeds, then waits `poll_ms` when there was nothing new.
    pub fn follow(c: *Congestion, st: *store.Store, stop: *const std.atomic.Value(bool), poll_ms: u32) void {
        while (!stop.load(.acquire)) {
            if (c.feed(st) == 0) c.io.sleep(.fromMilliseconds(poll_ms), .awake) catch {};
        }
    }

    pub fn suggest(c: *Congestion) simulate.Engine.Suggest {
        return .{ .ctx = c, .price = price };
    }

    fn price(ctx: *const anyopaque, ids: []const [32]u8) ?u64 {
        const c: *Congestion = @ptrCast(@alignCast(@constCast(ctx)));
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        return c.t.suggested(ids);
    }
};
