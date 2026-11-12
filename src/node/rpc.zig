//! sui.rpc.v2 TransactionExecutionService on the node (G9, docs/DROP-IN.md): SimulateTransaction
//! runs `rpc_exec` on the live store, next to serve's read methods on the same h2c port.
//! - requests: a fixed pool of worker threads (`rpc_exec.pool`), so the per-thread package caches
//!   and Move VM runtimes are bounded by the pool size and stay warm across connections; a full
//!   queue answers RESOURCE_EXHAUSTED;
//! - packages: `exec.packages.Store.lookup` over store snapshots. Only package objects are
//!   copied (a Move object id named as a MoveCall package answers null, as sui-node's package
//!   store does, and costs no memory); a user package is copied once per id (immutable), a system
//!   package once per version (exec's caches keep the bytes they were given for the process);
//! - suggested_gas_price: a background thread feeds the congestion tracker from every committed
//!   checkpoint, as sui-node's checkpoint executor does;
//! - epoch: `rpc_exec.epoch_env.Cache` decodes the live `0x5` system state (protocol version,
//!   reference gas price, epoch start, committee size);
//! - gas selection: `do_gas_selection` reads the StateService owner index (`--indexes`,
//!   src/index) through `setIndex`: `owned_objects_iter(owner, Coin<SUI>)` in index order
//!   (balance descending, then id). Without `--indexes` it answers NOT_FOUND, as sui-node
//!   without rpc indexes; while a fast start still builds the index, UNAVAILABLE.
//! - routing: one path. deepwave installs `handler()` as serve's `Service.execution`, behind
//!   the transport router (reflection, 404s, compression, x-sui-* and /health stay the
//!   router's); this handler only answers TransactionExecutionService paths.
//! - native simulation: `simulator()` is the src/exec/simulate API over the same store and core.
//! ExecuteTransaction goes to `execute` (G10, `--execute-epoch-from`); without it the request is
//! validated as sui-node's full node does, then answered UNIMPLEMENTED "no transaction executor".
const std = @import("std");
const Io = std.Io;
const store = @import("store");
const serve = @import("serve");
const exec = @import("exec");
const protocol = @import("protocol");
const rpc_exec = @import("rpc_exec");
const simulate = @import("simulate");
const index = @import("index");

const h2 = serve.h2;
const Id = [32]u8;

/// Package copies: user packages by id, system packages by (id, version).
const PkgKey = struct { Id, u64 };

/// The cache key of a live object, or null when it is not a package (nothing is cached).
fn packageKey(id: *const Id, bytes: []const u8) ?PkgKey {
    const v = exec.objects.ObjectView.parse(bytes) catch return null;
    if (!v.is_package) return null;
    return .{ id.*, if (exec.packages.isSystemPackage(id)) v.version else 0 };
}

pub const Rpc = struct {
    gpa: std.mem.Allocator,
    io: Io,
    st: *store.Store,
    pkg_mu: Io.Mutex = .init,
    pkg_cache: std.AutoHashMapUnmanaged(PkgKey, []const u8) = .empty,
    pkgs: exec.packages.Store = .{ .loaded = true },
    env: rpc_exec.epoch_env.Cache,
    svc: rpc_exec.service.Service,
    congestion: rpc_exec.service.Congestion,
    pool: rpc_exec.pool.Pool = undefined,
    pool_started: bool = false,
    feeder: ?std.Thread = null,
    stop: std.atomic.Value(bool) = .init(false),
    /// The StateService owner index (gas selection); null without `--indexes`.
    ix: ?*index.Index = null,
    /// ExecuteTransaction (rpc_exec.live.node_exec, `--execute-epoch-from`, G10); null: validated,
    /// then UNIMPLEMENTED "no transaction executor".
    execute: ?h2.Handler = null,

    /// Initialises in place (the service, the pool and the feeder keep pointers into `r`).
    pub fn init(r: *Rpc, gpa: std.mem.Allocator, io: Io, st: *store.Store, chain_id: Id) !void {
        r.* = .{
            .gpa = gpa,
            .io = io,
            .st = st,
            .env = .{ .gpa = gpa, .io = io, .st = st, .chain_id = chain_id, .layout_cfg = try protocol.get(protocol.max_protocol_version, .mainnet) },
            .svc = undefined,
            .congestion = .{ .io = io, .t = .{ .gpa = gpa } },
        };
        r.pkgs.lookup = .{ .ctx = r, .get = lookup };
        r.svc = .{ .gpa = gpa, .store = st, .engine = .{ .gpa = gpa, .pkgs = &r.pkgs, .io = io, .suggest = r.congestion.suggest() }, .env = r.env.source(), .congestion = &r.congestion };
        try r.pool.init(gpa, io, r.svc.handler(), .{ .on_exit = releaseWorkerCaches });
        r.pool_started = true;
        // start at the current tip (a fresh sui-node's tracker starts empty), then follow
        _ = r.congestion.feed(st);
        r.feeder = try std.Thread.spawn(.{}, feed, .{r});
    }

    /// The native simulation API at the tip (src/exec/simulate/api.zig), on the same package
    /// store, epoch source and congestion price as gRPC SimulateTransaction. Lane native-proto
    /// calls it from its own worker threads.
    pub fn simulator(r: *Rpc) simulate.api.Engine {
        return .{ .core = r.svc.engine, .tip = .{ .store = r.st, .env = r.env.source() } };
    }

    /// Simulate's proposer selector (the live execute path's validator monitor). Called before
    /// serving starts; the native API's engine copies it too.
    pub fn setProposers(r: *Rpc, sel: rpc_exec.simulate.Engine.ProposerSelector) void {
        r.svc.engine.proposers = sel;
    }

    /// Gas selection reads `ix` (the node's StateService index). Called before serving starts.
    pub fn setIndex(r: *Rpc, ix: *index.Index) void {
        r.ix = ix;
        r.svc.gas_coins = .{ .ctx = r, .get = gasCoins };
    }

    /// `owned_objects_iter(owner, Some(GasCoin::type_()))`: the owner's `Coin<SUI>` rows of the
    /// address-owner set, in key order (`!balance` big endian, then id), at most `limit` ids.
    /// The shared lock is held only while the rows are copied out.
    fn gasCoins(ctx: *const anyopaque, arena: std.mem.Allocator, owner: *const Id, limit: usize) rpc_exec.state.OwnedError![]const Id {
        const r: *const Rpc = @ptrCast(@alignCast(ctx));
        const ix = r.ix orelse return error.Internal;
        if (!ix.ready.load(.acquire)) return error.Unavailable;
        const prefix = gas_coin_type_bcs;
        var out: std.ArrayList(Id) = .empty;
        try out.ensureTotalCapacity(arena, @min(limit, 1024));
        ix.lock.lockShared();
        defer ix.lock.unlockShared();
        var it = ix.ownedIter(arena, .address, owner, prefix) catch |e| return mapIndexError(e);
        while (out.items.len < limit) {
            const row = (it.next() catch |e| return mapIndexError(e)) orelse break;
            if (!std.mem.startsWith(u8, row.key, prefix)) break;
            const parts = index.splitOwnerSuffix(row.key) catch return error.Internal;
            try out.append(arena, parts.id.*);
        }
        return out.items;
    }

    fn mapIndexError(e: anyerror) rpc_exec.state.OwnedError {
        return if (e == error.OutOfMemory) error.OutOfMemory else error.Internal;
    }

    /// The simulate pool's worker count (threads that hold package caches).
    pub fn simulateWorkers(r: *const Rpc) usize {
        return if (r.pool_started) r.pool.threads.len else 0;
    }

    fn feed(r: *Rpc) void {
        r.congestion.follow(r.st, &r.stop, 50);
    }

    /// A simulate worker exits: its package caches go back to the allocator the engine made
    /// them with (`gpa`, kept in each cache), its framework snapshots to theirs.
    fn releaseWorkerCaches() void {
        exec.ptb.pkgs.releaseThreadCaches();
        exec.system.movecall.releaseThreadCaches();
    }

    pub fn deinit(r: *Rpc) void {
        r.stop.store(true, .release);
        if (r.feeder) |t| t.join();
        if (r.pool_started) r.pool.deinit();
        r.congestion.t.deinit();
        var it = r.pkg_cache.valueIterator();
        while (it.next()) |v| r.gpa.free(v.*);
        r.pkg_cache.deinit(r.gpa);
    }

    fn lookup(ctx: *const anyopaque, id: *const Id, epoch: u64) ?[]const u8 {
        _ = epoch; // the live store holds the current epoch's system packages, which simulate runs in
        const r: *Rpc = @ptrCast(@alignCast(@constCast(ctx)));
        var snap = r.st.snapshot();
        defer snap.release();
        const live = snap.liveObject(id) orelse return null;
        const key = packageKey(id, live.bytes) orelse return null;
        r.pkg_mu.lockUncancelable(r.io);
        defer r.pkg_mu.unlock(r.io);
        if (r.pkg_cache.get(key)) |b| return b;
        const owned = r.gpa.dupe(u8, live.bytes) catch return null;
        r.pkg_cache.put(r.gpa, key, owned) catch {
            r.gpa.free(owned);
            return null;
        };
        return owned;
    }

    const execute_path = rpc_exec.service.prefix ++ "ExecuteTransaction";

    const Route = enum { pool, execute, none };

    /// TransactionExecutionService: ExecuteTransaction to `execute`, the rest (SimulateTransaction
    /// and unknown methods, which the service answers UNIMPLEMENTED) to the simulate pool.
    /// Anything else never reaches here (serve's router only hands this service's paths over).
    fn route(path: []const u8) Route {
        if (!rpc_exec.service.routes(path)) return .none;
        return if (std.mem.eql(u8, path, execute_path)) .execute else .pool;
    }

    /// The `Service.execution` hook of serve's router.
    pub fn handler(r: *Rpc) h2.Handler {
        return .{ .ctx = r, .call = call };
    }

    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const r: *Rpc = @ptrCast(@alignCast(ctx));
        switch (route(req.path)) {
            .pool => return rpc_exec.pool.Pool.call(&r.pool, req, rs),
            .execute => {
                // without --execute-epoch-from the service validates the request, then answers
                // UNIMPLEMENTED "no transaction executor" (rpc_exec driver.handler.noExecutor)
                const x = r.execute orelse return rpc_exec.pool.Pool.call(&r.pool, req, rs);
                return x.call(x.ctx, req, rs);
            },
            .none => return .unimplemented,
        }
    }
};

/// `bcs(StructTag 0x2::coin::Coin<0x2::sui::SUI>)`: the type part of an owner-index key.
const gas_coin_type_bcs: []const u8 = blk: {
    var b: []const u8 = &.{};
    const two: [32]u8 = @as([31]u8, @splat(0)) ++ [_]u8{2};
    b = b ++ two ++ [_]u8{4} ++ "coin" ++ [_]u8{4} ++ "Coin" ++ [_]u8{1}; // address, module, name, 1 type arg
    b = b ++ [_]u8{7} ++ two ++ [_]u8{3} ++ "sui" ++ [_]u8{3} ++ "SUI" ++ [_]u8{0}; // TypeTag::Struct(0x2::sui::SUI)
    break :blk b;
};

test "SimulateTransaction to the pool, ExecuteTransaction to execute, nothing else" {
    try std.testing.expectEqual(Rpc.Route.pool, Rpc.route("/sui.rpc.v2.TransactionExecutionService/SimulateTransaction"));
    try std.testing.expectEqual(Rpc.Route.execute, Rpc.route("/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction"));
    try std.testing.expectEqual(Rpc.Route.none, Rpc.route("/sui.rpc.v2.LedgerService/GetObject"));
}

test "gas coin owner-index prefix is bcs(Coin<SUI>) as the index writes it" {
    const types = @import("types");
    const bcs = @import("bcs");
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const tag = try index.objectStructTag(a.allocator(), .{ .@"0" = .GasCoin });
    const want = try bcs.encodeAlloc(types.StructTag, a.allocator(), &tag);
    try std.testing.expectEqualSlices(u8, want, gas_coin_type_bcs);
}

test "gas selection reads the owner index: Coin<SUI> rows, richest first, at most limit" {
    const types = @import("types");
    const bcs = @import("bcs");
    const gpa = std.testing.allocator;
    var a: std.heap.ArenaAllocator = .init(gpa);
    defer a.deinit();
    const al = a.allocator();
    var ix = try index.Index.init(gpa);
    defer ix.deinit();
    const owner: Id = @splat(0xab);
    const other: Id = @splat(0xcd);
    const Coin = struct { id: u8, owner: Id, bal: u64, sui: bool };
    const coins = [_]Coin{
        .{ .id = 1, .owner = owner, .bal = 5, .sui = true },
        .{ .id = 2, .owner = owner, .bal = 900, .sui = true },
        .{ .id = 3, .owner = other, .bal = 1000, .sui = true },
        .{ .id = 4, .owner = owner, .bal = 900, .sui = true },
        .{ .id = 5, .owner = owner, .bal = 7777, .sui = false },
        .{ .id = 6, .owner = owner, .bal = 50, .sui = true },
    };
    const usdc: types.TypeTag = .{ .@"struct" = .{ .address = .{ .@"0" = @splat(0x77) }, .module = .{ .@"0" = "usdc" }, .name = .{ .@"0" = "USDC" }, .type_args = &.{} } };
    for (coins) |c| {
        var contents: [40]u8 = @splat(0);
        contents[31] = c.id;
        std.mem.writeInt(u64, contents[32..40], c.bal, .little);
        const o: types.Object = .{
            .data = .{ .Move = .{ .type_ = .{ .@"0" = if (c.sui) .GasCoin else .{ .Coin = usdc } }, .has_public_transfer = true, .version = .{ .@"0" = 3 }, .contents = try al.dupe(u8, &contents) } },
            .owner = .{ .AddressOwner = .{ .@"0" = c.owner } },
            .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(0) } },
            .storage_rebate = 0,
        };
        try ix.insert(try bcs.encodeAlloc(types.Object, al, &o));
    }
    var r: Rpc = undefined;
    r.ix = &ix;
    const ids = try Rpc.gasCoins(&r, al, &owner, 3);
    try std.testing.expectEqual(@as(usize, 3), ids.len);
    try std.testing.expectEqual(@as(u8, 2), ids[0][31]); // 900, lower id first
    try std.testing.expectEqual(@as(u8, 4), ids[1][31]);
    try std.testing.expectEqual(@as(u8, 6), ids[2][31]); // 50
    const all = try Rpc.gasCoins(&r, al, &owner, 100);
    try std.testing.expectEqual(@as(usize, 4), all.len);
    try std.testing.expectEqual(@as(u8, 1), all[3][31]);
    ix.ready.store(false, .release);
    try std.testing.expectError(error.Unavailable, Rpc.gasCoins(&r, al, &owner, 3));
}

test "only package objects are cached, user packages once per id" {
    // ObjectView-shaped bytes come from exec's own encoder in its tests; here the decision is
    // exercised on the two shapes the lookup sees: a Move object and a package.
    const types = @import("types");
    const bcs = @import("bcs");
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    var id: Id = @splat(0x11);
    const owner: types.Owner = .{ .Immutable = {} };
    var contents: [40]u8 = @splat(0x11);
    const move_obj: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = .GasCoin }, .has_public_transfer = true, .version = .{ .@"0" = 9 }, .contents = &contents } },
        .owner = owner,
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(0) } },
        .storage_rebate = 0,
    };
    const raw_move = try bcs.encodeAlloc(types.Object, al, &move_obj);
    try std.testing.expect(packageKey(&id, raw_move) == null);
    const pkg_obj: types.Object = .{
        .data = .{ .Package = .{ .id = .{ .@"0" = .{ .@"0" = id } }, .version = .{ .@"0" = 3 }, .module_map = .{ .entries = &.{} }, .type_origin_table = &.{}, .linkage_table = .{ .entries = &.{} } } },
        .owner = owner,
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(0) } },
        .storage_rebate = 0,
    };
    const raw_pkg = try bcs.encodeAlloc(types.Object, al, &pkg_obj);
    try std.testing.expectEqual(PkgKey{ id, 0 }, packageKey(&id, raw_pkg).?);
    id = @splat(0);
    id[31] = 2;
    var sys = pkg_obj;
    sys.data.Package.id = .{ .@"0" = .{ .@"0" = id } };
    const raw_sys = try bcs.encodeAlloc(types.Object, al, &sys);
    try std.testing.expectEqual(PkgKey{ id, 3 }, packageKey(&id, raw_sys).?);
}

test "the native simulation API binds to the node's store and core" {
    _ = &Rpc.simulator;
    _ = &Rpc.simulateWorkers;
    const E = @TypeOf(@as(*Rpc, undefined).simulator());
    try std.testing.expect(E == simulate.api.Engine);
}
