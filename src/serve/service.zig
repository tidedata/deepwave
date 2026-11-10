//! sui.rpc.v2 LedgerService on a `store.Store`: GetServiceInfo, GetObject, GetTransaction and
//! GetCheckpoint (the remaining Ledger, State, Subscription and package services are listed in
//! BENCH.md/CONTRACTS.md as open). One arena per request; reads go through one snapshot.
//! Error replies carry the gRPC code, message and `grpc-status-details-bin` payload tonic sends for
//! sui-rpc-api's `RpcError` (`Status { code, message, details }`, details = BadRequest for request
//! validation errors). Request bytes are read with prost's rules where they matter: the last value
//! of a scalar or oneof wins, and a message field seen twice is merged (`read_mask` paths add up).
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const h2 = @import("h2/root.zig");
const proto = @import("proto.zig");
const mask = @import("mask.zig");
const b58 = @import("b58.zig");
const ledger = @import("ledger.zig");
const render_tx = @import("render_tx.zig");
const render_object = @import("render_object.zig");
const objdisplay = @import("objdisplay.zig");
const render_checkpoint = @import("render_checkpoint.zig");
const balance = @import("balance.zig");
const txobjects = @import("txobjects.zig");
const status = @import("status.zig");
const typestr = @import("typestr.zig");
const schema = @import("schema.zig");
const router = @import("router.zig");
const history = @import("history");
const lh_service = @import("lh_service.zig");
const clever = @import("clever.zig");
const exec_error = @import("exec_error.zig");
const mf = @import("move_format");
const movelayout = @import("movelayout.zig");
const render_json = @import("render_json.zig");
const cpcache = @import("cpcache.zig");

/// sui-node 1.83.1's `server` header (`sui-node/<version>-<git rev>`, captured from a production node).
pub const sui_node_server = "sui-node/1.83.1-6a567faf6de1";

pub const Service = struct {
    gpa: Allocator,
    store: *store.Store,
    /// Digest of checkpoint 0 (the chain identifier).
    chain_id: [32]u8,
    chain_name: []const u8 = "mainnet",
    server_name: []const u8 = "zui",
    /// The `server` response header: sui-node 1.83.1's exactly (`sui_node_server`), so a drop-in
    /// answers with sui-node's headers byte for byte. GetServiceInfo `server` stays `server_name`
    /// (DROP-IN 5.5).
    server_header: []const u8 = sui_node_server,
    /// Lowest checkpoint the store serves (reported by GetServiceInfo), when `lowest` is null.
    lowest_checkpoint: u64 = 0,
    /// Live value of the same (the node refreshes it after each prune; CONTRACTS 6.8).
    lowest: ?*const std.atomic.Value(u64) = null,
    /// Where each transaction's `unchanged_loaded_runtime_objects` come from (CONTRACTS 6.6): the
    /// store lane's per-transaction list once it exists. Null serves an empty list.
    loaded: ?LoadedSource = null,
    /// Parsed packages by object digest (a package object never changes). Call `deinit`.
    pkg_cache: PkgCache = .{},
    /// Pre-encoded GetCheckpoint responses by (checkpoint, read_mask) (cpcache.zig); budget 0: off.
    cp_cache: cpcache.Cache = .{},
    /// x-sui-* header values (router.zig).
    info_cache: router.InfoCache = .{},
    /// StateService (DROP-IN G4), served by the `index` module when the node has built its indexes.
    /// Null: StateService calls answer UNIMPLEMENTED.
    state: ?StateHook = null,
    /// Ledger-history index (ListCheckpoints/ListTransactions/ListEvents); null answers them UNIMPLEMENTED.
    history: ?*history.Index = null,
    /// rpc.ledger-history limits for the List* methods.
    lh_cfg: lh_service.Config = .{},
    /// SubscriptionService fan-out (subscribe.zig); null answers UNIMPLEMENTED like a node
    /// without the subscription service.
    hub: ?*subscribe.Hub = null,
    /// `/sui.rpc.v2.TransactionExecutionService/*` (rpc_exec: ExecuteTransaction, DROP-IN G10;
    /// SimulateTransaction, G9). Null: UNIMPLEMENTED.
    execution: ?h2.Handler = null,
    /// Epoch records and the package-version index (epoch-pkg lane, `rpcindex.zig`). Null: GetEpoch
    /// answers only the current epoch, version selectors and ListPackageVersions are UNAVAILABLE
    /// `rpc indexes are disabled` (sui-node with indexing off).
    rpc: ?*rpcindex.Index = null,
    /// Chain for protocol configs and SuiNS (`NameServiceConfig::mainnet`/`testnet`; null: UNIMPLEMENTED).
    chain: protocol.Chain = .mainnet,
    /// Protocol configs render as a sui-node whose release tops out at this protocol version:
    /// fields of newer releases are left out (`protocol.release_fields`). The epoch-pkg suite
    /// replays sui-node 1.83.1 captures at 141.
    protocol_release_max: u64 = protocol.max_protocol_version,
    /// Display v2 rendering for `display` (objdisplay.zig); false leaves the field out.
    display: bool = true,
    /// Move value `json` on objects and events; false leaves it out (the grpc-v2 suite's truth
    /// was recorded without a package store, so it has no `json`).
    json: bool = true,

    pub fn deinit(self: *Service) void {
        self.pkg_cache.deinit(self.gpa);
        self.cp_cache.deinit(self.gpa);
    }


    /// The full :9000 handler: sui.rpc services plus health, reflection, path and compression
    /// rules and response metadata (router.zig).
    pub fn handler(self: *Service) h2.Handler {
        return router.handler(self);
    }
};

/// Handler of `/sui.rpc.v2.StateService/*` (installed by the index module; see src/index/state.zig).
pub const StateHook = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, svc: *Service, arena: Allocator, method: []const u8, body: []const u8, rs: *h2.ResponseStream) h2.Status,
    /// The live-object index's committed checkpoint (sui-node `highest_live_committed_checkpoint`):
    /// bounds the served tip (`latestOf`) and gates /health (`indexCaughtUp`). Null: no bound.
    live: ?*const fn (ctx: *anyopaque) Live = null,

    pub const Live = struct {
        /// False while a fast-start build or replay owns the index (StateService UNAVAILABLE).
        ready: bool,
        checkpoint: ?u64,
    };
};

/// sui-rpc-api health.rs `MAX_HEALTHY_INDEX_LAG`.
pub const max_healthy_index_lag = 60;

/// The tip the node serves as "latest" (sui-node `RpcStoreReadStore::get_latest_checkpoint`):
/// with the live-object index on, the store's tip bounded by the index's committed checkpoint,
/// so a client that reads checkpoint N also reads the owned objects and balances of N. sui-node
/// fails closed while the index has no checkpoint; deepwave does too once the index is ready, and
/// serves the store's tip while a fast-start build owns it (StateService answers UNAVAILABLE
/// then, and /health reports down through `indexCaughtUp`).
pub fn latestOf(svc: *const Service, snap: *const store.Snapshot) ?u64 {
    const hi = snap.highestCommitted() orelse return null;
    return boundByIndex(svc, hi);
}

/// `latestOf` for a store tip read elsewhere.
pub fn boundByIndex(svc: *const Service, hi: u64) ?u64 {
    const st = svc.state orelse return hi;
    const f = st.live orelse return hi;
    const l = f(st.ctx);
    if (!l.ready) return hi;
    const ix = l.checkpoint orelse return null;
    return @min(hi, ix);
}

/// health.rs `index_caught_up`: with the index on, healthy only while its committed checkpoint
/// trails the store's tip by at most `max_healthy_index_lag` (never before its first commit).
/// The ledger-history index is excluded, as in sui-node.
///
/// While an index build owns the indexes (a fast start after a restore without an image, a
/// live-set scan, a replay: the state index or the rpc package floors not `ready`) /health is
/// down whatever the watermark says. sui-node restores its live cohort (owner, type, balance
/// indexes and the package-version floors) in `EmbeddedRpcStore::bootstrap` before it listens,
/// so no sui-node ever answers /health 200 before those are built; deepwave serves the other calls
/// during the build (index calls UNAVAILABLE) and reports down until it ends.
pub fn indexCaughtUp(svc: *const Service, executed: u64) bool {
    const st = svc.state orelse return true;
    const f = st.live orelse return true;
    const l = f(st.ctx);
    if (!l.ready) return false;
    if (svc.rpc) |x| if (!x.ready.load(.acquire)) return false;
    const ix = l.checkpoint orelse return false;
    return executed -| ix <= max_healthy_index_lag;
}

test "latestOf and indexCaughtUp follow the live index" {
    const Fake = struct {
        var cur: StateHook.Live = .{ .ready = true, .checkpoint = null };
        fn live(_: *anyopaque) StateHook.Live {
            return cur;
        }
        fn call(_: *anyopaque, _: *Service, _: Allocator, _: []const u8, _: []const u8, _: *h2.ResponseStream) h2.Status {
            return .ok;
        }
    };
    var dummy: u8 = 0;
    var svc: Service = undefined;
    svc.state = null;
    svc.rpc = null;
    try std.testing.expectEqual(@as(?u64, 100), boundByIndex(&svc, 100));
    try std.testing.expect(indexCaughtUp(&svc, 100));
    svc.state = .{ .ctx = &dummy, .call = Fake.call, .live = Fake.live };
    // ready, nothing committed yet: fail closed, unhealthy
    try std.testing.expectEqual(@as(?u64, null), boundByIndex(&svc, 100));
    try std.testing.expect(!indexCaughtUp(&svc, 100));
    Fake.cur = .{ .ready = true, .checkpoint = 40 };
    try std.testing.expectEqual(@as(?u64, 40), boundByIndex(&svc, 100));
    try std.testing.expect(indexCaughtUp(&svc, 100)); // exactly at the bound
    try std.testing.expect(!indexCaughtUp(&svc, 101));
    Fake.cur = .{ .ready = true, .checkpoint = 100 };
    try std.testing.expectEqual(@as(?u64, 100), boundByIndex(&svc, 100));
    // a fast-start build: the store's tip is served, health is down
    Fake.cur = .{ .ready = false, .checkpoint = 10 };
    try std.testing.expectEqual(@as(?u64, 100), boundByIndex(&svc, 100));
    try std.testing.expect(!indexCaughtUp(&svc, 100));
    // ... even with a watermark within the lag (a build resumed near the tip)
    Fake.cur = .{ .ready = false, .checkpoint = 99 };
    try std.testing.expect(!indexCaughtUp(&svc, 100));
    // the rpc package floors still being written: down; once ready: up
    Fake.cur = .{ .ready = true, .checkpoint = 99 };
    var rx: rpcindex.Index = undefined;
    rx.ready = .init(false);
    svc.rpc = &rx;
    try std.testing.expect(!indexCaughtUp(&svc, 100));
    rx.ready.store(true, .release);
    try std.testing.expect(indexCaughtUp(&svc, 100));
}
pub const state_prefix = "/sui.rpc.v2.StateService/";

/// A package object parsed once and kept in the service's cache (null when it does not parse).
/// `obj` is the live package object; the result lives as long as the service.
pub fn cachedPackage(svc: *Service, obj: store.ObjectRef) ?*const movepkg.Package {
    if (svc.pkg_cache.get(&obj.digest)) |hit| return hit;
    const e = svc.gpa.create(PkgCache.Entry) catch return null;
    e.arena = std.heap.ArenaAllocator.init(svc.gpa);
    movepkg.read(e.arena.allocator(), obj.bytes, &e.pkg) catch {
        e.arena.deinit();
        svc.gpa.destroy(e);
        return null;
    };
    return svc.pkg_cache.put(svc.gpa, &obj.digest, e);
}

/// Source of a transaction's unchanged loaded runtime objects (ObjectKey list, sorted as the node
/// stores it). Read through the request's snapshot `snap`: the slice may point into a decoded
/// chunk, which stays valid only while that snapshot lives (a snapshot of its own, released
/// before the render, let the chunk cache free it under the render: SIGSEGV in writeEffects).
pub const LoadedSource = struct {
    ctx: *const anyopaque,
    /// `at`: the transaction record's location (`TransactionRecord.loc`, a lookup hint; 0 = none).
    get: *const fn (ctx: *const anyopaque, snap: *const store.Snapshot, digest: *const [32]u8, at: u64) []const objset.Ref,
};

pub fn lowestOf(svc: *const Service) u64 {
    return if (svc.lowest) |l| l.load(.acquire) else svc.lowest_checkpoint;
}

fn loadedOf(svc: *const Service, snap: *const store.Snapshot, digest: *const [32]u8, at: u64) []const objset.Ref {
    const src = svc.loaded orelse return &.{};
    return src.get(src.ctx, snap, digest, at);
}

const objset = @import("objset.zig");

/// Read-mostly cache of parsed packages, so GetDatatype and GetFunction stop deserializing every
/// module of the package on each request. Entries are never freed while the service lives (so
/// readers need no reference count); once `max_entries` are held, further packages are parsed
/// per request. An entry outlives the snapshot that read it, so it must not borrow store memory:
/// movepkg.read copies the object bytes into the entry's arena.
const PkgCache = struct {
    const max_entries = 256;
    const Entry = struct { arena: std.heap.ArenaAllocator, pkg: movepkg.Package };
    lock: std.atomic.Value(u32) = .init(0),
    map: std.AutoHashMapUnmanaged([32]u8, *Entry) = .empty,

    fn acquire(c: *PkgCache) void {
        while (c.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn release(c: *PkgCache) void {
        c.lock.store(0, .release);
    }
    fn get(c: *PkgCache, digest: *const [32]u8) ?*const movepkg.Package {
        c.acquire();
        defer c.release();
        const e = c.map.get(digest.*) orelse return null;
        return &e.pkg;
    }
    /// Takes ownership of `e`. Returns the cached package (`e`'s, or the entry another request
    /// inserted first), or null when the cache is full (`e` is freed).
    fn put(c: *PkgCache, gpa: Allocator, digest: *const [32]u8, e: *Entry) ?*const movepkg.Package {
        c.acquire();
        defer c.release();
        if (c.map.get(digest.*)) |other| {
            e.arena.deinit();
            gpa.destroy(e);
            return &other.pkg;
        }
        if (c.map.count() < max_entries) if (c.map.put(gpa, digest.*, e)) |_| return &e.pkg else |_| {};
        e.arena.deinit();
        gpa.destroy(e);
        return null;
    }
    fn deinit(c: *PkgCache, gpa: Allocator) void {
        var it = c.map.valueIterator();
        while (it.next()) |e| {
            e.*.arena.deinit();
            gpa.destroy(e.*);
        }
        c.map.deinit(gpa);
    }
};
const reqdecode = @import("reqdecode.zig");
const movepkg = @import("movepkg.zig");
const protocol = @import("protocol");
const rpcindex = @import("rpcindex.zig");
const epoch_mod = @import("epoch.zig");
const names = @import("names.zig");
const verifysig = @import("verifysig.zig");
const proof = @import("proof.zig");

/// SignatureVerificationService: chain state (0x7 JWKs, AddressAliases) from one store snapshot.
fn callVerify(self: *Service, arena: Allocator, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    var snap = self.store.snapshot();
    defer snap.release();
    const Live = struct {
        fn get(ctx: *anyopaque, id: *const [32]u8) ?[]const u8 {
            const sn: *store.Snapshot = @ptrCast(@alignCast(ctx));
            return if (sn.liveObject(id)) |l| l.bytes else null;
        }
    };
    const env: verifysig.Env = .{ .chain_name = self.chain_name, .ctx = &snap, .liveObject = Live.get };
    return verifysig.call(arena, &env, req, rs);
}
const ledger_prefix = "/sui.rpc.v2.LedgerService/";
const package_prefix = "/sui.rpc.v2.MovePackageService/";
const subscribe = @import("subscribe.zig");
pub const execution_prefix = "/sui.rpc.v2.TransactionExecutionService/";
const name_prefix = "/sui.rpc.v2.NameService/";

pub fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    const self: *Service = @ptrCast(@alignCast(ctx));
    var arena_state = std.heap.ArenaAllocator.init(self.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    if (std.mem.startsWith(u8, req.path, package_prefix)) return callPackage(self, arena, req, rs);
    if (std.mem.startsWith(u8, req.path, state_prefix)) {
        const hook = self.state orelse return .unimplemented;
        return hook.call(hook.ctx, self, arena, req.path[state_prefix.len..], req.body, rs);
    }
    if (std.mem.startsWith(u8, req.path, subscribe.prefix)) return subscribe.call(self, arena, req, rs);
    if (std.mem.startsWith(u8, req.path, execution_prefix)) {
        const hook = self.execution orelse return .unimplemented;
        return hook.call(hook.ctx, req, rs);
    }
    if (std.mem.startsWith(u8, req.path, name_prefix)) return callNames(self, arena, req, rs);
    if (std.mem.startsWith(u8, req.path, verifysig.prefix)) return callVerify(self, arena, req, rs);
    if (std.mem.startsWith(u8, req.path, proof.prefix)) return proof.call(self, arena, req, rs);
    if (!std.mem.startsWith(u8, req.path, ledger_prefix)) return .unimplemented;
    const method = req.path[ledger_prefix.len..];
    if (lh_service.methodOf(method)) |m| return lh_service.callStream(self, &self.lh_cfg, arena, m, req, rs);
    if (requestMessage(method)) |m| if (reqdecode.check(arena, m, req.body)) |text| {
        rs.setMessage(text);
        return .internal; // tonic: Status::internal(DecodeError), no details
    };
    var snap = self.store.snapshot();
    defer snap.release();
    var cctx: clever.Ctx = .{ .svc = self, .snap = &snap, .arena = arena };
    exec_error.clever_hook = cctx.hook();
    defer exec_error.clever_hook = null;
    const res = if (std.mem.eql(u8, method, "GetCheckpoint"))
        getCheckpoint(self, arena, &snap, req.body, rs)
    else if (std.mem.eql(u8, method, "GetObject"))
        getObject(self, arena, &snap, req.body, rs)
    else if (std.mem.eql(u8, method, "GetTransaction"))
        getTransaction(self, arena, &snap, req.body, rs)
    else if (std.mem.eql(u8, method, "BatchGetObjects"))
        batchGetObjects(self, arena, &snap, req.body, rs)
    else if (std.mem.eql(u8, method, "BatchGetTransactions"))
        batchGetTransactions(self, arena, &snap, req.body, rs)
    else if (std.mem.eql(u8, method, "GetServiceInfo"))
        getServiceInfo(self, arena, &snap, rs)
    else if (std.mem.eql(u8, method, "GetEpoch"))
        getEpoch(self, arena, &snap, req.body, rs)
    else
        return .unimplemented;
    res catch |e| return fail(arena, rs, e);
    return .ok;
}

fn requestMessage(method: []const u8) ?*const reqdecode.Msg {
    const eql = std.mem.eql;
    if (eql(u8, method, "GetCheckpoint")) return &reqdecode.get_checkpoint_request;
    if (eql(u8, method, "GetObject")) return &reqdecode.get_object_request;
    if (eql(u8, method, "GetTransaction")) return &reqdecode.get_transaction_request;
    if (eql(u8, method, "BatchGetObjects")) return &reqdecode.batch_get_objects_request;
    if (eql(u8, method, "BatchGetTransactions")) return &reqdecode.batch_get_transactions_request;
    if (eql(u8, method, "GetServiceInfo")) return &reqdecode.empty_request;
    if (eql(u8, method, "GetEpoch")) return &reqdecode.get_epoch_request;
    return null;
}

pub const Err = error{ NotFoundBare, NotFound, Invalid, Unsupported, OutOfMemory, Internal, NoSpace, Malformed, Reported, Unavailable };

/// tonic sends every `RpcError` with `grpc-status-details-bin` = `Status { code, message,
/// details }`; a BadRequest reply has set its own (badField).
pub fn withDetails(arena: Allocator, rs: *h2.ResponseStream, code: h2.Status) h2.Status {
    if (rs.details_bin.len == 0) {
        if (status.plain(arena, @intFromEnum(code), rs.msg)) |bin| rs.details(bin) else |_| {}
    }
    return code;
}

pub fn fail(arena: Allocator, rs: *h2.ResponseStream, e: anyerror) h2.Status {
    switch (e) {
        error.Reported => return withDetails(arena, rs, .invalid_argument), // message already set
        error.NotFound => {
            if (rs.msg.len == 0) rs.setMessage("not found");
            return withDetails(arena, rs, .not_found);
        },
        error.NotFoundBare => return withDetails(arena, rs, .not_found), // RpcError::not_found(): no message
        error.Unavailable => return withDetails(arena, rs, .unavailable), // message already set
        error.Internal => {
            if (rs.msg.len == 0) rs.setMessage("internal error");
            return withDetails(arena, rs, .internal);
        },
        error.Malformed => {
            // tonic's prost decoder rejects the request before the handler: INTERNAL, no details
            rs.setMessage("failed to decode Protobuf message");
            return .internal;
        },
        error.Invalid => {
            rs.setMessage("invalid argument");
            return .invalid_argument;
        },
        error.Unsupported => {
            rs.setMessage("read_mask selects a field this server does not render yet");
            return .unimplemented;
        },
        else => {
            rs.setMessage("internal error");
            return .internal;
        },
    }
}

// ---- request parsing ----

pub const Mask = struct {
    tree: mask.Tree,
    pub fn m(self: *const Mask) mask.Mask {
        return self.tree.mask();
    }
};

/// Sets an INVALID_ARGUMENT reply carrying a `BadRequest` detail for one field violation.
pub fn badField(arena: Allocator, rs: *h2.ResponseStream, field: []const u8, description: []const u8, reason: status.Reason) Err {
    const bin = status.badRequest(arena, 3, field, description, reason) catch return error.OutOfMemory;
    rs.setMessage(description);
    rs.details(bin);
    return error.Reported;
}

/// Every occurrence of a request's `read_mask` field: prost merges a message field that appears
/// more than once, so their paths add up.
pub const MaskField = struct {
    parts: std.ArrayList([]const u8) = .empty,
    pub fn add(self: *MaskField, arena: Allocator, data: []const u8) Err!void {
        self.parts.append(arena, data) catch return error.OutOfMemory;
    }
    fn present(self: *const MaskField) bool {
        return self.parts.items.len > 0;
    }
};

/// FieldMask { repeated string paths = 1 } to a validated tree; `default` when the request has
/// none (`FieldMaskUtil::validate::<M>`: an unknown path is INVALID_ARGUMENT).
pub fn parseMask(arena: Allocator, rs: *h2.ResponseStream, field: *const MaskField, default: []const u8, root: i16) Err!Mask {
    if (!field.present()) return .{ .tree = mask.Tree.parse(arena, default) catch return error.OutOfMemory };
    var paths: std.ArrayList([]const u8) = .empty;
    for (field.parts.items) |data| {
        var r = proto.Reader.init(data);
        while (r.next() catch return error.Malformed) |f| {
            if (f.number == 1) paths.append(arena, proto.Reader.stringOf(f) catch return error.Malformed) catch return error.OutOfMemory;
        }
    }
    if (status.invalidPath(root, paths.items)) |p| {
        const text = std.fmt.allocPrint(arena, "invalid read_mask path: {s}", .{p}) catch return error.OutOfMemory;
        return badField(arena, rs, "read_mask", text, .field_invalid);
    }
    return .{ .tree = mask.Tree.fromPaths(arena, paths.items) catch return error.OutOfMemory };
}

/// Runs `render` with a growing output buffer until it fits; the message bytes (in `arena`).
fn renderBytes(arena: Allocator, hint: usize, ctx: anytype, comptime render: anytype) ![]const u8 {
    var cap: usize = @max(hint, 4096);
    while (true) {
        const buf = try arena.alloc(u8, cap);
        var w = proto.Writer.init(buf);
        render(ctx, &w) catch |e| switch (e) {
            error.NoSpace => {
                cap = w.retryCap() orelse return error.Internal;
                continue;
            },
            else => return e,
        };
        return w.bytesWritten();
    }
}

/// Runs `render` with a growing output buffer until it fits, then sends the message.
fn respond(arena: Allocator, rs: *h2.ResponseStream, hint: usize, ctx: anytype, comptime render: anytype) !void {
    var cap: usize = @max(hint, 4096);
    while (true) {
        const buf = try arena.alloc(u8, cap);
        var w = proto.Writer.init(buf);
        render(ctx, &w) catch |e| switch (e) {
            error.NoSpace => {
                cap = w.retryCap() orelse return error.Internal;
                continue;
            },
            else => return e,
        };
        return rs.message(w.bytesWritten());
    }
}

// ---- GetCheckpoint ----

pub const CheckpointData = struct {
    cert: []const u8,
    contents: []const u8,
    txs: []render_tx.Input,
    objects: []const []const u8,
};

pub fn splitEnvelope(arena: Allocator, bytes: []const u8) !struct { data: []const u8, sigs: []const []const u8 } {
    var r = bcs.Reader.init(bytes);
    if ((try r.length()) != 1) return error.Malformed;
    _ = try r.bytes(3); // intent
    const start = r.pos();
    try bcs.skip(types.TransactionData, &r);
    const data = bytes[start..r.pos()];
    const n = try r.length();
    const sigs = try arena.alloc([]const u8, n);
    for (sigs) |*s| s.* = try r.bytes(try r.length());
    return .{ .data = data, .sigs = sigs };
}

pub fn txInput(svc: *const Service, arena: Allocator, snap: *const store.Snapshot, rec: store.TransactionRecord) !render_tx.Input {
    const sp = try splitEnvelope(arena, rec.tx);
    return .{ .transaction = sp.data, .signatures = sp.sigs, .effects = rec.effects, .events = rec.events, .effects_digest = rec.effects_digest, .loaded = loadedOf(svc, snap, rec.digest, rec.loc), .clever = cleverResolver(svc) };
}

/// `clever_error` lookups for this service's renders (render.rs `render_clever_error`).
pub fn cleverResolver(svc: *const Service) exec_error.CleverResolver {
    return .{ .ctx = @constCast(svc), .module = cleverModule };
}

/// `reader.get_object(package_id)` then `Package::read_from_object` and `package.module(name)`:
/// the live object at the abort location's package id, parsed through the package cache.
fn cleverModule(ctx: *anyopaque, arena: Allocator, pkg_id: *const [32]u8, module: []const u8) ?*const mf.file_format.CompiledModule {
    const svc: *Service = @ptrCast(@alignCast(ctx));
    var snap = svc.store.snapshot();
    defer snap.release();
    const obj = snap.liveObject(pkg_id) orelse return null;
    const pkg: *const movepkg.Package = svc.pkg_cache.get(&obj.digest) orelse blk: {
        const e = svc.gpa.create(PkgCache.Entry) catch return null;
        e.arena = std.heap.ArenaAllocator.init(svc.gpa);
        movepkg.read(e.arena.allocator(), obj.bytes, &e.pkg) catch {
            e.arena.deinit();
            svc.gpa.destroy(e);
            return null;
        };
        if (svc.pkg_cache.put(svc.gpa, &obj.digest, e)) |cached| break :blk cached;
        // cache full: parse into the request's arena
        const p = arena.create(movepkg.Package) catch return null;
        movepkg.read(arena, obj.bytes, p) catch return null;
        break :blk p;
    };
    for (pkg.mods) |*m| if (std.mem.eql(u8, m.name, module)) return &m.cm;
    return null;
}

/// The (id, version) keys of a transaction's object set, in `get_transaction_object_set` order.
pub fn objectKeys(svc: *const Service, arena: Allocator, snap: *const store.Snapshot, rec: store.TransactionRecord) ![]const objset.Ref {
    const sp = try splitEnvelope(arena, rec.tx);
    const td = try bcs.decode(types.TransactionData, arena, sp.data);
    const eff = try bcs.decode(types.TransactionEffects, arena, rec.effects);
    return txobjects.keys(arena, td, eff, loadedOf(svc, snap, rec.digest, rec.loc));
}

/// Time this thread spent in the store reads of the List*/Get* item paths (lh_service logs it
/// per request with ZUI_LH_PROF=1). Plain counters: one request per thread at a time.
pub const Prof = struct {
    tx_ns: u64 = 0,
    txs: u64 = 0,
    obj_ns: u64 = 0,
    objs: u64 = 0,
    wait_ns: u64 = 0,
    pre_objs: u64 = 0,
    /// The read-ahead workers' store index probes (store.ProbeStats, summed at Job.finish).
    w_runs: u64 = 0,
    w_live: u64 = 0,
    w_hits: u64 = 0,
    w_falls: u64 = 0,
    w_skips: u64 = 0,
};
pub threadlocal var prof: Prof = .{};
pub fn profNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// The objects a transaction read or wrote (`get_transaction_object_set`), read from the store.
/// A missing object is INTERNAL with object_set.rs `build_object_sets`' message (the first
/// missing key in ObjectKey order); `missing` receives it.
pub fn collectObjects(svc: *const Service, arena: Allocator, snap: *store.Snapshot, rec: store.TransactionRecord, out: *std.ArrayList([]const u8), missing: *[]const u8) !void {
    for (try objectKeys(svc, arena, snap, rec)) |k| {
        const t0 = profNs();
        const found = snap.objectNear(&k.id, k.version, rec.loc);
        prof.obj_ns += profNs() - t0;
        prof.objs += 1;
        const raw = found orelse {
            var dbuf: [b58.max_len_32]u8 = undefined;
            var idbuf: [66]u8 = undefined;
            var o: typestr.Out = .{ .buf = &idbuf };
            try o.address(&k.id);
            missing.* = try std.fmt.allocPrint(arena, "unable to fetch object ObjectKey({s}, SequenceNumber({d})) for transaction {s}", .{ o.str(), k.version, b58.encode32(&dbuf, rec.digest) });
            return error.Internal;
        };
        try out.append(arena, raw);
    }
}

/// `TransactionNotFoundError` text: the digest as parsed, in its canonical base58 form.
fn txNotFound(arena: Allocator, dg: *const [32]u8) []const u8 {
    var dbuf: [b58.max_len_32]u8 = undefined;
    return std.fmt.allocPrint(arena, "Transaction {s} not found", .{b58.encode32(&dbuf, dg)}) catch "Transaction not found";
}

/// GetTransaction's lookup: a transaction is served only when its checkpoint is inside
/// lowest_available..=latest (get_transaction.rs).
fn findTransaction(svc: *const Service, snap: *store.Snapshot, dg: *const [32]u8, cp: ?u64) ?store.TransactionRecord {
    const t0 = profNs();
    const found = if (cp) |c| snap.transactionNear(dg, c) else snap.transaction(dg);
    prof.tx_ns += profNs() - t0;
    prof.txs += 1;
    const rec = found orelse return null;
    const latest = latestOf(svc, snap) orelse return null;
    if (rec.checkpoint < lowestOf(svc) or rec.checkpoint > latest) return null;
    return rec;
}

/// object_set.rs `mask_requests_object_set`: masks of an ExecutedTransaction that fetch the
/// transaction's object set (and fail when an object is missing).
pub fn needsObjectSet(t: mask.Mask) bool {
    return t.contains("balance_changes") or t.contains("effects") or t.contains("objects");
}

/// Object sets read ahead by another thread (lh_service's read-ahead workers): `get` returns
/// transaction `base + k`'s object bytes in key order once they are read (blocking until then),
/// or null when the caller must read them itself (not read ahead, or an object is missing: the
/// caller's own read produces the error).
pub const PreObjects = struct {
    ctx: ?*anyopaque = null,
    base: usize = 0,
    get: *const fn (ctx: *anyopaque, i: usize, digest: *const [32]u8) ?[]const []const u8 = undefined,
    pub fn of(p: PreObjects, k: usize, digest: *const [32]u8) ?[]const []const u8 {
        const c = p.ctx orelse return null;
        return p.get(c, p.base + k, digest);
    }
};

pub fn loadCheckpointData(svc: *const Service, arena: Allocator, snap: *store.Snapshot, rec: store.CheckpointRecord, want_txs: bool, want_objects: bool) !CheckpointData {
    return loadCheckpointDataPre(svc, arena, snap, rec, want_txs, want_objects, .{});
}

pub fn loadCheckpointDataPre(svc: *const Service, arena: Allocator, snap: *store.Snapshot, rec: store.CheckpointRecord, want_txs: bool, want_objects: bool, pre: PreObjects) !CheckpointData {
    var d: CheckpointData = .{ .cert = rec.summary_cert, .contents = rec.contents, .txs = &.{}, .objects = &.{} };
    if (!want_txs and !want_objects) return d;
    const contents = try bcs.decode(types.CheckpointContents, arena, rec.contents);
    const digests: []const types.ExecutionDigests = switch (contents) {
        .V1 => |v| v.transactions,
        .V2 => |v| blk: {
            const out = try arena.alloc(types.ExecutionDigests, v.transactions.len);
            for (v.transactions, out) |t, *o| o.* = t.digest;
            break :blk out;
        },
    };
    const txs = try arena.alloc(render_tx.Input, digests.len);
    var objs: std.ArrayList([]const u8) = .empty;
    var missing: []const u8 = "";
    for (digests, txs, 0..) |dg, *t, k| {
        const t0 = profNs();
        const found = snap.transactionNear(&dg.transaction.@"0".@"0", rec.seq);
        prof.tx_ns += profNs() - t0;
        prof.txs += 1;
        const r = found orelse return error.Internal;
        t.* = try txInput(svc, arena, snap, r);
        if (want_objects) {
            if (pre.of(k, r.digest)) |got| try objs.appendSlice(arena, got) else try collectObjects(svc, arena, snap, r, &objs, &missing);
        }
    }
    d.txs = txs;
    d.objects = objs.items;
    return d;
}

const CpCtx = struct { arena: Allocator, m: mask.Mask, d: CheckpointData, budget: *usize };

fn renderCheckpoint(c: CpCtx, w: *proto.Writer) !void {
    // one JSON budget for every event of the checkpoint, fresh on each render attempt
    c.budget.* = render_json.default_response_budget;
    try ledger.getCheckpoint(c.arena, w, c.m, c.d.cert, c.d.contents, c.d.objects, c.d.txs);
}

fn getCheckpoint(svc: *Service, arena: Allocator, snap: *store.Snapshot, body: []const u8, rs: *h2.ResponseStream) !void {
    // checkpoint_id is a oneof { sequence_number = 1, digest = 2 }: the last one seen wins
    var seq: ?u64 = null;
    var digest: ?[]const u8 = null;
    var mask_field: MaskField = .{};
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => {
            seq = proto.Reader.varintOf(f) catch return error.Malformed;
            digest = null;
        },
        2 => {
            digest = proto.Reader.stringOf(f) catch return error.Malformed;
            seq = null;
        },
        3 => try mask_field.add(arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        else => {},
    };
    var mk = try parseMask(arena, rs, &mask_field, "sequence_number,digest", comptime schema.index("Checkpoint"));
    const m = mk.m();
    const want_txs = m.subtree("transactions") != null;
    const want_objects = m.subtree("objects") != null or (if (m.subtree("transactions")) |t| needsObjectSet(t) else false);
    if (digest) |text| {
        const dg = b58.decode32(text) orelse return badField(arena, rs, "digest", "invalid digest: Unable to parse Digest (must be Base58 string of length 32)", .field_invalid);
        // get_checkpoint.rs: by digest, then the same lowest..=latest check as by sequence number.
        seq = snap.checkpointByDigest(&dg) orelse {
            var dbuf: [b58.max_len_32]u8 = undefined;
            rs.setMessage(std.fmt.allocPrint(arena, "Checkpoint {s} not found", .{b58.encode32(&dbuf, &dg)}) catch "Checkpoint not found");
            return error.NotFound;
        };
    }
    const latest_opt = latestOf(svc, snap);
    const want_seq = seq orelse latest_opt orelse return error.NotFound;
    const latest = latest_opt orelse want_seq;
    const rec = if (latest_opt != null and want_seq >= lowestOf(svc) and want_seq <= latest) snap.checkpoint(want_seq) else null;
    const found = rec orelse {
        rs.setMessage(std.fmt.allocPrint(arena, "Checkpoint {d} not found", .{want_seq}) catch "Checkpoint not found");
        return error.NotFound;
    };
    // A committed checkpoint's response is fixed: serve repeated calls from the encoded bytes.
    // `display` renders from live Display objects, so masks selecting it are rendered each time.
    const key: ?[]const u8 = if (svc.cp_cache.enabled() and !m.containsDyn("transactions.objects.objects.display"))
        try cpcache.maskKey(arena, mask_field.parts.items)
    else
        null;
    // A transaction of this checkpoint whose submitted signature order was learned after the
    // response was cached (store txfix.zig) makes the cached bytes stale. The generation is read
    // before the transactions are, so a fix landing during the render only marks this entry stale.
    const fixes = &snap.store.tx_fix;
    const fix_gen = fixes.generation();
    if (key) |k| if (svc.cp_cache.get(want_seq, k)) |e| {
        defer cpcache.release(svc.gpa, e);
        if (!fixes.changedSince(want_seq, e.gen)) return sendCached(svc, rs, e);
        svc.cp_cache.drop(svc.gpa, want_seq, k);
    };
    const d = try loadCheckpointData(svc, arena, snap, found, want_txs, want_objects);
    const budget = try arena.create(usize);
    budget.* = render_json.default_response_budget;
    if (want_txs) {
        const src = try arena.create(ObjSource);
        src.* = .{ .snap = snap, .overlay = d.objects };
        const rctx = try renderCtx(svc, arena, src);
        rctx.json_budget = budget;
        for (d.txs) |*t| t.render = rctx;
    }
    const bytes = try renderBytes(arena, 4096 + found.contents.len * 2, CpCtx{ .arena = arena, .m = m, .d = d, .budget = budget }, renderCheckpoint);
    if (key) |k| svc.cp_cache.putGen(svc.gpa, want_seq, k, bytes, fix_gen);
    return rs.message(bytes);
}

/// A cached response: its encoded bytes, or its compressed frame (made once per entry).
fn sendCached(svc: *Service, rs: *h2.ResponseStream, e: *cpcache.Entry) !void {
    const C = struct {
        fn zstd(gpa: Allocator, p: []const u8) anyerror![]u8 {
            return h2.codec.compress(gpa, .zstd, p);
        }
        fn gzip(gpa: Allocator, p: []const u8) anyerror![]u8 {
            return h2.codec.compress(gpa, .gzip, p);
        }
    };
    const z = switch (rs.encoding) {
        .identity => return rs.message(e.bytes),
        .zstd => cpcache.compressed(svc.gpa, e, .zstd, C.zstd),
        .gzip => cpcache.compressed(svc.gpa, e, .gzip, C.gzip),
    } orelse return rs.message(e.bytes);
    return rs.messageCompressed(z);
}

// ---- GetObject ----

/// sui-sdk-types `Address::from_str`: an optional lowercase "0x" prefix, then 1 to 64 hex digits
/// (left-padded with zeros).
pub fn parseObjectId(text: []const u8) ?[32]u8 {
    var s = text;
    if (std.mem.startsWith(u8, s, "0x")) s = s[2..];
    if (s.len == 0 or s.len > 64) return null;
    var out: [32]u8 = @splat(0);
    var padded: [64]u8 = @splat('0');
    @memcpy(padded[64 - s.len ..], s);
    _ = std.fmt.hexToBytes(&out, &padded) catch return null;
    return out;
}

/// Package and object reads for `json`/`display`: the request's overlay objects first (raw
/// BCS(Object); render.rs passes the checkpoint's object set), then the store's live objects.
pub const ObjSource = struct {
    snap: *const store.Snapshot,
    overlay: []const []const u8 = &.{},

    fn get(ctx: *const anyopaque, id: *const [32]u8) ?[]const u8 {
        const s: *const ObjSource = @ptrCast(@alignCast(ctx));
        for (s.overlay) |raw| {
            // BCS Object: data enum tag 1 = Package, whose first field is its id
            if (raw.len > 33 and raw[0] == 1 and std.mem.eql(u8, raw[1..33], id)) return raw;
        }
        return if (s.snap.liveObject(id)) |l| l.bytes else null;
    }

    pub fn packages(s: *const ObjSource) movelayout.PackageSource {
        return .{ .ctx = s, .get = get };
    }
};

/// The render context of one request: resolver over `src`, the Display hook, no shared budget.
pub fn renderCtx(svc: *const Service, arena: Allocator, src: *const ObjSource) !*render_object.Ctx {
    const res = try arena.create(movelayout.Resolver);
    res.* = movelayout.Resolver.init(arena, src.packages());
    const c = try arena.create(render_object.Ctx);
    c.* = .{ .resolver = res, .display = if (svc.display) try objdisplay.Hook.create(arena, src.packages()) else null, .json_on = svc.json };
    return c;
}

const ObjCtx = struct { arena: Allocator, m: mask.Mask, raw: []const u8, ctx: ?*const render_object.Ctx = null };

fn renderObject(c: ObjCtx, w: *proto.Writer) !void {
    const mm = try w.begin(1, c.raw.len + 128);
    try render_object.writeObjectCtx(c.arena, w, c.m, c.raw, c.ctx);
    try w.end(mm);
}

fn getObject(svc: *const Service, arena: Allocator, snap: *store.Snapshot, body: []const u8, rs: *h2.ResponseStream) !void {
    var id_text: ?[]const u8 = null;
    var version: ?u64 = null;
    var mask_field: MaskField = .{};
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => id_text = proto.Reader.stringOf(f) catch return error.Malformed,
        2 => version = proto.Reader.varintOf(f) catch return error.Malformed,
        3 => try mask_field.add(arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        else => {},
    };
    var mk = try parseMask(arena, rs, &mask_field, "object_id,version,digest", comptime schema.index("Object"));
    const text = id_text orelse return badField(arena, rs, "requests[0].object_id", "", .field_missing);
    const id = parseObjectId(text) orelse return badField(arena, rs, "requests[0].object_id", "invalid object_id: Unable to parse Address (must be hex string of length 32)", .field_invalid);
    const raw = findObject(snap, &id, version) orelse {
        rs.setMessage(objectNotFound(arena, &id, version));
        return error.NotFound;
    };
    const src = try arena.create(ObjSource);
    src.* = .{ .snap = snap };
    try respond(arena, rs, raw.len + 512, ObjCtx{ .arena = arena, .m = mk.m(), .raw = raw, .ctx = try renderCtx(svc, arena, src) }, renderObject);
}

fn findObject(snap: *store.Snapshot, id: *const [32]u8, version: ?u64) ?[]const u8 {
    return if (version) |v| snap.objectAt(id, v) else if (snap.liveObject(id)) |l| l.bytes else null;
}

/// `ObjectNotFoundError` text.
fn objectNotFound(arena: Allocator, id: *const [32]u8, version: ?u64) []const u8 {
    var idbuf: [66]u8 = undefined;
    var o: typestr.Out = .{ .buf = &idbuf };
    o.address(id) catch unreachable;
    return (if (version) |v|
        std.fmt.allocPrint(arena, "Object {s} with version {d} not found", .{ o.str(), v })
    else
        std.fmt.allocPrint(arena, "Object {s} not found", .{o.str()})) catch "Object not found";
}

const max_batch_objects = 1000;
const max_batch_transactions = 200;

/// BatchGetObjects: `requests` (1, GetObjectRequest) and `read_mask` (2); one GetObjectResult
/// `{ object = 1 | error = 2 }` per request. A bad request fails the whole call, a missing
/// object only its own result.
fn batchGetObjects(svc: *const Service, arena: Allocator, snap: *store.Snapshot, body: []const u8, rs: *h2.ResponseStream) !void {
    const Req = struct { id: ?[]const u8, version: ?u64 };
    var reqs: std.ArrayList(Req) = .empty;
    var mask_field: MaskField = .{};
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => {
            var q: Req = .{ .id = null, .version = null };
            var qr = proto.Reader.init(proto.Reader.bytesOf(f) catch return error.Malformed);
            while (qr.next() catch return error.Malformed) |g| switch (g.number) {
                1 => q.id = proto.Reader.stringOf(g) catch return error.Malformed,
                2 => q.version = proto.Reader.varintOf(g) catch return error.Malformed,
                else => {},
            };
            try reqs.append(arena, q);
        },
        2 => try mask_field.add(arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        else => {},
    };
    if (reqs.items.len > max_batch_objects) {
        rs.setMessage("number of batch requests exceed limit of 1000");
        return error.Reported;
    }
    var mk = try parseMask(arena, rs, &mask_field, "object_id,version,digest", comptime schema.index("Object"));
    const ids = try arena.alloc([32]u8, reqs.items.len);
    for (reqs.items, ids, 0..) |q, *id, i| {
        var fb: [48]u8 = undefined;
        const field = std.fmt.bufPrint(&fb, "requests[{d}].object_id", .{i}) catch unreachable;
        const text = q.id orelse return badField(arena, rs, try arena.dupe(u8, field), "", .field_missing);
        id.* = parseObjectId(text) orelse return badField(arena, rs, try arena.dupe(u8, field), "invalid object_id: Unable to parse Address (must be hex string of length 32)", .field_invalid);
    }
    const src = try arena.create(ObjSource);
    src.* = .{ .snap = snap };
    const rctx = try renderCtx(svc, arena, src);
    // Look every object up once (a retry with a bigger buffer re-renders, it does not re-read),
    // and size the buffer from what was found, so a 500-id batch renders once, not ~8 times
    // over doubling buffers (lane serve-tail).
    const raws = try arena.alloc(?[]const u8, reqs.items.len);
    var cap: usize = 4096;
    for (reqs.items, ids, raws) |q, *id, *raw| {
        raw.* = findObject(snap, id, q.version);
        cap += if (raw.*) |x| x.len + x.len / 2 + 256 else 160;
    }
    while (true) {
        const buf = try arena.alloc(u8, cap);
        var w = proto.Writer.init(buf);
        batchObjectsInto(arena, &w, mk.m(), raws, ids, reqs.items, rctx) catch |e| switch (e) {
            error.NoSpace => {
                cap = w.retryCap() orelse return error.Internal;
                continue;
            },
            else => return e,
        };
        return rs.message(w.bytesWritten());
    }
}

fn batchObjectsInto(arena: Allocator, w: *proto.Writer, m: mask.Mask, raws: []const ?[]const u8, ids: []const [32]u8, reqs: anytype, rctx: *const render_object.Ctx) !void {
    for (reqs, ids, raws) |q, *id, found| {
        const item = try w.begin(1, 256);
        if (found) |raw| {
            const om = try w.begin(1, raw.len + 128);
            try render_object.writeObjectCtx(arena, w, m, raw, rctx);
            try w.end(om);
        } else {
            try w.bytes(2, try status.plain(arena, 5, objectNotFound(arena, id, q.version)));
        }
        try w.end(item);
    }
}

/// BatchGetTransactions: `digests` (1, repeated string) and `read_mask` (2); one
/// GetTransactionResult `{ transaction = 1 | error = 2 }` per digest.
fn batchGetTransactions(svc: *const Service, arena: Allocator, snap: *store.Snapshot, body: []const u8, rs: *h2.ResponseStream) !void {
    var digests: std.ArrayList([]const u8) = .empty;
    var mask_field: MaskField = .{};
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => try digests.append(arena, proto.Reader.stringOf(f) catch return error.Malformed),
        2 => try mask_field.add(arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        else => {},
    };
    var mk = try parseMask(arena, rs, &mask_field, "digest", comptime schema.index("ExecutedTransaction"));
    if (digests.items.len > max_batch_transactions) {
        rs.setMessage("number of batch requests exceed limit of 200");
        return error.Reported;
    }
    var cap: usize = 4096;
    while (true) {
        const buf = try arena.alloc(u8, cap);
        var w = proto.Writer.init(buf);
        batchTxInto(svc, arena, &w, snap, mk.m(), digests.items) catch |e| switch (e) {
            error.NoSpace => {
                cap = w.retryCap() orelse return error.Internal;
                continue;
            },
            else => return e,
        };
        return rs.message(w.bytesWritten());
    }
}

fn batchTxInto(svc: *const Service, arena: Allocator, w: *proto.Writer, snap: *store.Snapshot, m: mask.Mask, digests: []const []const u8) !void {
    for (digests, 0..) |dtext, i| {
        const item = try w.begin(1, 1024);
        const dg = b58.decode32(dtext) orelse {
            const field = try std.fmt.allocPrint(arena, "digests[{d}]", .{i});
            const st = try status.badRequest(arena, 3, field, "invalid digest: Unable to parse Digest (must be Base58 string of length 32)", .field_invalid);
            try w.bytes(2, st);
            try w.end(item);
            continue;
        };
        const start = w.len;
        const mm = try w.begin(1, 1024);
        var missing: []const u8 = "";
        txBody(svc, arena, w, snap, m, &dg, &missing) catch |e| switch (e) {
            error.NotFound => {
                w.len = start;
                try w.bytes(2, try status.plain(arena, 5, txNotFound(arena, &dg)));
                try w.end(item);
                continue;
            },
            error.Internal => {
                w.len = start;
                try w.bytes(2, try status.plain(arena, 13, if (missing.len > 0) missing else "internal error"));
                try w.end(item);
                continue;
            },
            else => return e,
        };
        try w.end(mm);
        try w.end(item);
    }
}

/// The ExecutedTransaction body of GetTransaction for `dg` (also ListTransactions' items).
/// `pre`: the object set read ahead (PreObjects), or null to read it here.
/// `cp`: the checkpoint holding it, when an index named it (a lookup hint).
pub fn txBodyPub(svc: *const Service, arena: Allocator, w: *proto.Writer, snap: *store.Snapshot, m: mask.Mask, dg: *const [32]u8, missing: *[]const u8, pre: ?[]const []const u8, cp_hint: ?u64) !void {
    return txBodyPre(svc, arena, w, snap, m, dg, missing, pre, cp_hint);
}
fn txBody(svc: *const Service, arena: Allocator, w: *proto.Writer, snap: *store.Snapshot, m: mask.Mask, dg: *const [32]u8, missing: *[]const u8) !void {
    return txBodyPre(svc, arena, w, snap, m, dg, missing, null, null);
}
fn txBodyPre(svc: *const Service, arena: Allocator, w: *proto.Writer, snap: *store.Snapshot, m: mask.Mask, dg: *const [32]u8, missing: *[]const u8, pre: ?[]const []const u8, cp_hint: ?u64) !void {
    const rec = findTransaction(svc, snap, dg, cp_hint) orelse return error.NotFound;
    const cp = snap.checkpoint(rec.checkpoint) orelse return error.Internal;
    const cert = try render_checkpoint.Cert.parse(arena, cp.summary_cert);
    var objs: std.ArrayList([]const u8) = .empty;
    if (needsObjectSet(m)) {
        if (pre) |got| try objs.appendSlice(arena, got) else try collectObjects(svc, arena, snap, rec, &objs, missing);
    }
    var input = try txInput(svc, arena, snap, rec);
    const src = try arena.create(ObjSource);
    src.* = .{ .snap = snap, .overlay = objs.items };
    input.render = try renderCtx(svc, arena, src);
    try ledger.writeExecutedBody(arena, w, m, input, rec.checkpoint, cert.summary.timestamp_ms, objs.items);
}

// ---- GetTransaction ----

const TxCtx = struct { arena: Allocator, m: mask.Mask, input: render_tx.Input, seq: u64, ts_ms: u64, objects: []const []const u8 };

fn renderTx(c: TxCtx, w: *proto.Writer) !void {
    const mm = try w.begin(1, c.input.transaction.len + c.input.effects.len + 256);
    try ledger.writeExecutedBody(c.arena, w, c.m, c.input, c.seq, c.ts_ms, c.objects);
    try w.end(mm);
}

fn getTransaction(svc: *const Service, arena: Allocator, snap: *store.Snapshot, body: []const u8, rs: *h2.ResponseStream) !void {
    var digest_text: ?[]const u8 = null;
    var mask_field: MaskField = .{};
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => digest_text = proto.Reader.stringOf(f) catch return error.Malformed,
        2 => try mask_field.add(arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        else => {},
    };
    const dtext = digest_text orelse return badField(arena, rs, "digest", "missing digest", .field_missing);
    const dg = b58.decode32(dtext) orelse return badField(arena, rs, "digest", "invalid digest: Unable to parse Digest (must be Base58 string of length 32)", .field_invalid);
    var mk = try parseMask(arena, rs, &mask_field, "digest", comptime schema.index("ExecutedTransaction"));
    const m = mk.m();
    const rec = findTransaction(svc, snap, &dg, null) orelse {
        rs.setMessage(txNotFound(arena, &dg));
        return error.NotFound;
    };
    const cp = snap.checkpoint(rec.checkpoint) orelse return error.Internal;
    const cert = try render_checkpoint.Cert.parse(arena, cp.summary_cert);
    var objs: std.ArrayList([]const u8) = .empty;
    var missing: []const u8 = "";
    if (needsObjectSet(m)) collectObjects(svc, arena, snap, rec, &objs, &missing) catch |e| {
        if (e == error.Internal) rs.setMessage(missing);
        return e;
    };
    var input = try txInput(svc, arena, snap, rec);
    const src = try arena.create(ObjSource);
    src.* = .{ .snap = snap, .overlay = objs.items };
    input.render = try renderCtx(svc, arena, src);
    try respond(arena, rs, input.transaction.len + input.effects.len + 1024, TxCtx{ .arena = arena, .m = m, .input = input, .seq = rec.checkpoint, .ts_ms = cert.summary.timestamp_ms, .objects = objs.items }, renderTx);
}

// ---- GetServiceInfo ----

fn getServiceInfo(svc: *Service, arena: Allocator, snap: *store.Snapshot, rs: *h2.ResponseStream) !void {
    const hi = latestOf(svc, snap) orelse return error.NotFound;
    const rec = snap.checkpoint(hi) orelse return error.NotFound;
    const cert = try render_checkpoint.Cert.parse(arena, rec.summary_cert);
    const buf = try arena.alloc(u8, 512);
    var w = proto.Writer.init(buf);
    var cid: [b58.max_len_32]u8 = undefined;
    try w.string(1, b58.encode32(&cid, &svc.chain_id));
    try w.string(2, svc.chain_name);
    try w.uint(3, cert.summary.epoch);
    try w.uint(4, cert.summary.sequence_number);
    {
        const ts = try w.begin(5, 12);
        const ms = cert.summary.timestamp_ms;
        if (ms / 1000 != 0) try w.uint(1, ms / 1000);
        if (ms % 1000 != 0) try w.uint(2, (ms % 1000) * 1_000_000);
        try w.end(ts);
    }
    const lowest = lowestOf(svc);
    try w.uint(6, lowest);
    // Deprecated lowest_available_checkpoint_objects: get_service_info.rs still sets it to the same value.
    try w.uint(7, lowest);
    try w.string(8, svc.server_name);
    try rs.message(w.bytesWritten());
}


// ---- MovePackageService ----

fn callPackage(self: *Service, arena: Allocator, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    const method = req.path[package_prefix.len..];
    const Which = enum { package, datatype, function, versions };
    const which: Which = if (std.mem.eql(u8, method, "GetPackage")) .package else if (std.mem.eql(u8, method, "GetDatatype")) .datatype else if (std.mem.eql(u8, method, "GetFunction")) .function else if (std.mem.eql(u8, method, "ListPackageVersions")) .versions else return .unimplemented;
    const msg: *const reqdecode.Msg = switch (which) {
        .package => &reqdecode.get_package_request,
        .datatype => &reqdecode.get_datatype_request,
        .function => &reqdecode.get_function_request,
        .versions => &reqdecode.list_package_versions_request,
    };
    if (reqdecode.check(arena, msg, req.body)) |text| {
        rs.setMessage(text);
        return .internal;
    }
    var snap = self.store.snapshot();
    defer snap.release();
    const res = switch (which) {
        .package => getPackage(self, arena, &snap, req.body, rs),
        .datatype, .function => getMember(self, arena, &snap, req.body, rs, which == .datatype),
        .versions => listPackageVersions(self, arena, &snap, req.body, rs),
    };
    res catch |e| return fail(arena, rs, e);
    return .ok;
}

/// `ObjectID::from_str`: `decode_bytes_hex` (optional 0x, exactly 32 bytes of hex), else
/// `from_hex_literal` (0x required; short literals are zero-padded on the left, then parsed with
/// `from_str` again; longer ones drop the 0x and go round again). The only error text that can
/// surface is the missing-prefix one. A loop, not Rust's mutual recursion: a 4 MB "0x0x0x..."
/// id would otherwise recurse two million deep.
fn parseSuiObjectId(text_in: []const u8) ?[32]u8 {
    var text = text_in;
    var padded: [64]u8 = undefined;
    while (true) {
        const h = if (std.mem.startsWith(u8, text, "0x")) text[2..] else text;
        var out: [32]u8 = undefined;
        if (h.len == 64) if (std.fmt.hexToBytes(&out, h)) |_| return out else |_| {};
        if (!std.mem.startsWith(u8, text, "0x")) return null;
        const hex_len = text.len - 2;
        if (hex_len < 64) {
            // text may be `padded` itself ("0x" + "x" + 62 hex pads to "0x"...): copy first
            var tmp: [64]u8 = undefined;
            @memcpy(tmp[0..hex_len], text[2..]);
            @memset(padded[0 .. 64 - hex_len], '0');
            @memcpy(padded[64 - hex_len ..], tmp[0..hex_len]);
            text = &padded;
        } else text = text[2..];
    }
}

test "parseSuiObjectId: ObjectID::from_str forms" {
    const full = "00000000000000000000000000000000000000000000000000000000000000ab";
    var want: [32]u8 = @splat(0);
    want[31] = 0xab;
    try std.testing.expectEqual(want, parseSuiObjectId(full).?);
    try std.testing.expectEqual(want, parseSuiObjectId("0x" ++ full).?);
    try std.testing.expectEqual(want, parseSuiObjectId("0xAB").?);
    try std.testing.expectEqual(want, parseSuiObjectId("0x0x" ++ full).?);
    try std.testing.expectEqual(want, parseSuiObjectId("0x0x0x" ++ full).?);
    try std.testing.expect(parseSuiObjectId("ab") == null);
    try std.testing.expect(parseSuiObjectId("0x0xab") == null); // padded "0..0x0xab" has no 0x prefix
    try std.testing.expect(parseSuiObjectId("0x" ++ full ++ "00") == null);
    // "0xx" + 62 hex: padded to "0x" + 62 hex, padded again to 64 (from_hex_literal twice)
    try std.testing.expectEqual(want, parseSuiObjectId("0xx" ++ full[2..]).?);
    // deep "0x" chains end without recursion
    const gpa = std.testing.allocator;
    const long = try gpa.alloc(u8, 4 << 20);
    defer gpa.free(long);
    for (0..long.len / 2) |i| @memcpy(long[2 * i ..][0..2], "0x");
    try std.testing.expect(parseSuiObjectId(long) == null);
}

/// The live package object `id`, parsed (and cached like GetPackage), for clever_error:
/// `get_object` + `Package::read_from_object`, any failure is null.
pub fn packageForClever(svc: *Service, arena: Allocator, snap: *store.Snapshot, id: *const [32]u8) ?*const movepkg.Package {
    const obj: store.ObjectRef = snap.liveObject(id) orelse blk: {
        // A store started mid-chain (no snapshot) holds packages a transaction read only as
        // historical versions (read sets, CONTRACTS 6.8). A package id has exactly one version
        // (its upgrade number), so probe the low versions; the bytes are the same package.
        var v: u64 = 1;
        while (v <= 128) : (v += 1) if (snap.objectAt(id, v)) |raw| break :blk .{ .version = v, .digest = id.*, .bytes = raw };
        return null;
    };
    if (svc.pkg_cache.get(&obj.digest)) |hit| return hit;
    const e = svc.gpa.create(PkgCache.Entry) catch return null;
    e.arena = std.heap.ArenaAllocator.init(svc.gpa);
    movepkg.read(e.arena.allocator(), obj.bytes, &e.pkg) catch {
        e.arena.deinit();
        svc.gpa.destroy(e);
        return null;
    };
    if (svc.pkg_cache.put(svc.gpa, &obj.digest, e)) |cached| return cached;
    const p = arena.create(movepkg.Package) catch return null;
    movepkg.read(arena, obj.bytes, p) catch return null;
    return p;
}

fn loadPackage(svc: *Service, arena: Allocator, snap: *store.Snapshot, text: []const u8, rs: *h2.ResponseStream, pkg: *movepkg.Package) Err!void {
    const id = parseSuiObjectId(text) orelse
        return badField(arena, rs, "package_id", "invalid package_id: ObjectID hex literal must start with 0x", .field_invalid);
    const obj = snap.liveObject(&id) orelse return error.NotFoundBare;
    if (svc.pkg_cache.get(&obj.digest)) |hit| {
        pkg.* = hit.*;
        return;
    }
    const e = try svc.gpa.create(PkgCache.Entry);
    e.arena = std.heap.ArenaAllocator.init(svc.gpa);
    movepkg.read(e.arena.allocator(), obj.bytes, &e.pkg) catch |err| {
        const msg: ?[]const u8 = if (err == error.Resolver) arena.dupe(u8, e.pkg.message) catch null else null;
        e.arena.deinit();
        svc.gpa.destroy(e);
        switch (err) {
            error.NotAPackage => {
                rs.setMessage("object is not a package");
                return error.Reported; // RpcError::new(InvalidArgument, ..): Status details only
            },
            error.Resolver => {
                rs.setMessage(msg orelse "package could not be read");
                return error.Internal;
            },
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                rs.setMessage("package could not be read");
                return error.Internal;
            },
        }
    };
    if (svc.pkg_cache.put(svc.gpa, &obj.digest, e)) |cached| {
        pkg.* = cached.*;
        return;
    }
    // cache full: parse into the request's arena (this read succeeded just above)
    movepkg.read(arena, obj.bytes, pkg) catch return error.Internal;
}

fn getPackage(svc: *Service, arena: Allocator, snap: *store.Snapshot, body: []const u8, rs: *h2.ResponseStream) !void {
    var id_text: ?[]const u8 = null;
    var version: ?u64 = null;
    var at_checkpoint: ?u64 = null;
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => id_text = proto.Reader.stringOf(f) catch return error.Malformed,
        2 => {
            version = proto.Reader.varintOf(f) catch return error.Malformed;
            at_checkpoint = null;
        },
        3 => {
            at_checkpoint = proto.Reader.varintOf(f) catch return error.Malformed;
            version = null;
        },
        else => {},
    };
    const text = id_text orelse return badField(arena, rs, "package_id", "missing package_id", .field_missing);
    var pkg: movepkg.Package = undefined;
    if (version != null or at_checkpoint != null) {
        // load_package_at_version / load_package_at_checkpoint (package-version index)
        const target = try selectPackage(svc, arena, snap, text, rs, version, at_checkpoint);
        try loadPackage(svc, arena, snap, target, rs, &pkg);
    } else try loadPackage(svc, arena, snap, text, rs, &pkg);
    try respond(arena, rs, 4096, PkgCtx{ .arena = arena, .pkg = &pkg, .module = "", .name = "" }, renderPackage);
}

const PkgCtx = struct { arena: Allocator, pkg: *movepkg.Package, module: []const u8, name: []const u8 };

fn renderPackage(c: PkgCtx, w: *proto.Writer) !void {
    return movepkg.writePackage(c.arena, w, c.pkg);
}
fn renderDatatype(c: PkgCtx, w: *proto.Writer) !void {
    return movepkg.writeDatatypeResponse(c.arena, w, c.pkg, c.module, c.name);
}
fn renderFunction(c: PkgCtx, w: *proto.Writer) !void {
    return movepkg.writeFunctionResponse(c.arena, w, c.pkg, c.module, c.name);
}

fn getMember(svc: *Service, arena: Allocator, snap: *store.Snapshot, body: []const u8, rs: *h2.ResponseStream, datatype: bool) !void {
    var id_text: ?[]const u8 = null;
    var module_name: ?[]const u8 = null;
    var name: ?[]const u8 = null;
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => id_text = proto.Reader.stringOf(f) catch return error.Malformed,
        2 => module_name = proto.Reader.stringOf(f) catch return error.Malformed,
        3 => name = proto.Reader.stringOf(f) catch return error.Malformed,
        else => {},
    };
    const text = id_text orelse return badField(arena, rs, "package_id", "missing package_id", .field_missing);
    const mname = module_name orelse return badField(arena, rs, "module_name", "missing module_name", .field_missing);
    const n = name orelse return badField(arena, rs, "name", "missing name", .field_missing);
    var pkg: movepkg.Package = undefined;
    try loadPackage(svc, arena, snap, text, rs, &pkg);
    const c: PkgCtx = .{ .arena = arena, .pkg = &pkg, .module = mname, .name = n };
    const res = if (datatype) respond(arena, rs, 1024, c, renderDatatype) else respond(arena, rs, 512, c, renderFunction);
    res catch |e| switch (e) {
        error.Resolver => {
            rs.setMessage(pkg.message);
            return error.Internal;
        },
        error.NoSpace => unreachable,
        else => |o| return o,
    };
}


// ---- epoch-pkg lane: GetEpoch, package versions, NameService (DROP-IN G6, G8) ----

fn getEpoch(svc: *Service, arena: Allocator, snap: *store.Snapshot, body: []const u8, rs: *h2.ResponseStream) !void {
    var requested: ?u64 = null;
    var mask_field: MaskField = .{};
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => requested = proto.Reader.varintOf(f) catch return error.Malformed,
        2 => try mask_field.add(arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        else => {},
    };
    var mk = try parseMask(arena, rs, &mask_field, epoch_mod.default_mask, comptime schema.index("Epoch"));
    switch (try epoch_mod.getEpoch(arena, snap, svc.rpc, svc.chain, svc.protocol_release_max, requested, mk.m())) {
        .ok => |bytes| try rs.message(bytes),
        .not_found => |m| {
            rs.setMessage(m);
            return error.NotFound;
        },
        .internal => |m| {
            rs.setMessage(m);
            return error.Internal;
        },
    }
}

/// The light part of `load_package`: id parse, live object, `try_into_package`, original id.
const LightPkg = struct { id: [32]u8, original: [32]u8, version: u64 };
fn lightPackage(arena: Allocator, snap: *store.Snapshot, text: []const u8, rs: *h2.ResponseStream) Err!LightPkg {
    const id = parseSuiObjectId(text) orelse
        return badField(arena, rs, "package_id", "invalid package_id: ObjectID hex literal must start with 0x", .field_invalid);
    const obj = snap.liveObject(&id) orelse return error.NotFoundBare;
    if (obj.bytes.len < 41 or obj.bytes[0] != 1) {
        rs.setMessage("object is not a package");
        return error.Reported;
    }
    const original = rpcindex.originalId(obj.bytes) orelse {
        rs.setMessage("package could not be read");
        return error.Internal;
    };
    return .{ .id = id, .original = original, .version = std.mem.readInt(u64, obj.bytes[33..41], .little) };
}

fn indexOrUnavailable(svc: *Service, rs: *h2.ResponseStream) Err!*rpcindex.Index {
    const x = svc.rpc orelse {
        rs.setMessage("rpc indexes are disabled");
        return error.Unavailable;
    };
    if (!x.ready.load(.acquire)) {
        // fast start: package floors from the restored live set are still being written
        rs.setMessage("rpc indexes are being built");
        return error.Unavailable;
    }
    return x;
}

/// GetPackage's `version` / `at_checkpoint` selector: the storage id (as text) of the package to load.
fn selectPackage(svc: *Service, arena: Allocator, snap: *store.Snapshot, text: []const u8, rs: *h2.ResponseStream, version: ?u64, at_checkpoint: ?u64) Err![]const u8 {
    const p = try lightPackage(arena, snap, text, rs);
    var b: [66]u8 = undefined;
    if (version) |v| {
        if (p.version == v) return text;
        const x = try indexOrUnavailable(svc, rs);
        const tok = x.enter();
        defer x.exit(tok);
        for (x.lineage(&p.original)) |e| if (e.version == v) return try arena.dupe(u8, sysstateHex(&b, &e.storage_id));
        return error.NotFoundBare;
    }
    const at = at_checkpoint.?;
    const x = try indexOrUnavailable(svc, rs);
    const lowest = lowestOf(svc);
    if (at < lowest) {
        rs.setMessage(try std.fmt.allocPrint(arena, "requested checkpoint {d} has been pruned; lowest available checkpoint is {d}", .{ at, lowest }));
        return error.NotFound;
    }
    const hi = x.highestIndexed() orelse {
        rs.setMessage("rpc index is empty");
        return error.Unavailable;
    };
    if (at > hi) {
        rs.setMessage(try std.fmt.allocPrint(arena, "requested checkpoint {d} is not yet indexed; highest indexed checkpoint is {d}", .{ at, hi }));
        return error.NotFound;
    }
    const tok = x.enter();
    defer x.exit(tok);
    const v = rpcindex.atCheckpoint(x.lineage(&p.original), at) orelse return error.NotFoundBare;
    return try arena.dupe(u8, sysstateHex(&b, &v.storage_id));
}

fn sysstateHex(b: *[66]u8, a: *const [32]u8) []const u8 {
    return @import("sysstate.zig").hexAddr(b, a);
}

fn listPackageVersions(svc: *Service, arena: Allocator, snap: *store.Snapshot, body: []const u8, rs: *h2.ResponseStream) !void {
    var id_text: ?[]const u8 = null;
    var page_size: ?u32 = null;
    var token: ?[]const u8 = null;
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => id_text = proto.Reader.stringOf(f) catch return error.Malformed,
        2 => page_size = @truncate(proto.Reader.varintOf(f) catch return error.Malformed),
        3 => token = proto.Reader.bytesOf(f) catch return error.Malformed,
        else => {},
    };
    const text = id_text orelse return badField(arena, rs, "package_id", "missing package_id", .field_missing);
    const p = try lightPackage(arena, snap, text, rs);
    const size: usize = if (page_size) |n| std.math.clamp(@as(usize, n), 1, 10000) else 1000;
    var from: u64 = 0;
    if (token) |t| {
        // bcs::from_bytes::<PageToken { original_package_id: ObjectID, version: u64 }>
        if (t.len < 40) return badField(arena, rs, "page_token", "invalid page token encoding: unexpected end of input", .field_invalid);
        if (t.len > 40) return badField(arena, rs, "page_token", "invalid page token encoding: remaining input", .field_invalid);
        if (!std.mem.eql(u8, t[0..32], &p.original))
            return badField(arena, rs, "page_token", "page token package ID does not match request package ID", .field_invalid);
        from = std.mem.readInt(u64, t[32..40], .little);
    }
    const x = try indexOrUnavailable(svc, rs);
    const rd = x.enter();
    defer x.exit(rd);
    const l = x.lineage(&p.original);
    var start: usize = 0;
    while (start < l.len and l[start].version < from) start += 1;
    const take = @min(l.len - start, size + 1);
    const page = l[start..][0..@min(take, size)];
    const buf = try arena.alloc(u8, page.len * 90 + 64);
    var w = proto.Writer.init(buf);
    var b: [66]u8 = undefined;
    for (page) |e| {
        const m = try w.begin(1, 80);
        try w.string(1, sysstateHex(&b, &e.storage_id));
        try w.uint(2, e.version);
        try w.end(m);
    }
    if (take > size) {
        var tok: [40]u8 = undefined;
        @memcpy(tok[0..32], &p.original);
        std.mem.writeInt(u64, tok[32..40], l[start + size].version, .little);
        try w.bytes(2, &tok);
    }
    try rs.message(w.bytesWritten());
}

fn callNames(self: *Service, arena: Allocator, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    const method = req.path[name_prefix.len..];
    const reverse = if (std.mem.eql(u8, method, "LookupName")) false else if (std.mem.eql(u8, method, "ReverseLookupName")) true else return .unimplemented;
    const msg = if (reverse) &reqdecode.reverse_lookup_name_request else &reqdecode.lookup_name_request;
    if (reqdecode.check(arena, msg, req.body)) |text| {
        rs.setMessage(text);
        return .internal;
    }
    const cfg: names.Config = switch (self.chain) {
        .mainnet => names.Config.mainnet,
        .testnet => names.Config.testnet,
        else => {
            rs.setMessage("SuiNS not configured for this network");
            return withDetails(arena, rs, .unimplemented);
        },
    };
    var text: ?[]const u8 = null;
    var r = proto.Reader.init(req.body);
    while (r.next() catch return fail(arena, rs, error.Malformed)) |f| if (f.number == 1) {
        text = proto.Reader.stringOf(f) catch return fail(arena, rs, error.Malformed);
    };
    var snap = self.store.snapshot();
    defer snap.release();
    const out = (if (reverse)
        names.reverseLookupName(arena, &snap, &cfg, text, if (text) |t| parseObjectId(t) else null)
    else
        names.lookupName(arena, &snap, &cfg, text)) catch |e| return fail(arena, rs, e);
    switch (out) {
        .ok => |bytes| {
            rs.message(bytes) catch |e| return fail(arena, rs, e);
            return .ok;
        },
        .bad_field => |bf| {
            badFieldReason(arena, rs, bf.field, bf.description, if (bf.missing) .field_missing else .field_invalid);
            return .invalid_argument;
        },
        .not_found_bare => return withDetails(arena, rs, .not_found),
        .internal => |m| {
            rs.setMessage(m);
            return withDetails(arena, rs, .internal);
        },
        .expired => {
            rs.setMessage("name has expired");
            return withDetails(arena, rs, .resource_exhausted);
        },
    }
}

fn badFieldReason(arena: Allocator, rs: *h2.ResponseStream, field: []const u8, description: []const u8, reason: status.Reason) void {
    _ = badField(arena, rs, field, description, reason) catch {};
}
