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
    /// An edge that passes what it does not hold to its core (src/edge/forward.zig) reports the
    /// core's lowest available checkpoint in GetServiceInfo and `x-sui-lowest-available-*`: with
    /// forwarding, that is what a client can ask this node for. Null: the node's own (`lowestOf`).
    /// What the node itself serves from its store is bounded by `lowestOf` either way.
    reported_lowest: ?*const std.atomic.Value(u64) = null,
    /// An edge with a core upstream: the checkpoints whose certificate is not the core's yet.
    foreign_cert: ?ForeignCert = null,
    /// Where each transaction's `unchanged_loaded_runtime_objects` come from (CONTRACTS 6.6): the
    /// store lane's per-transaction list once it exists. Null serves an empty list.
    loaded: ?LoadedSource = null,
    /// Parsed packages by object digest (a package object never changes). Call `deinit`.
    pkg_cache: PkgCache = .{},
    /// Pre-encoded GetCheckpoint responses by (checkpoint, read_mask) (cpcache.zig); budget 0: off.
    cp_cache: cpcache.Cache = .{},
    /// GetCheckpoint calls answered from `cp_cache` before any store read (`getCheckpointCached`).
    cp_fast_hits: std.atomic.Value(u64) = .init(0),
    /// How long a cached GetCheckpoint response is served without its checkpoint's record being
    /// read again (`getCheckpointCached`). After that the next call for it takes the store path,
    /// which reads and checks the record: a record that went bad on disk answers NotFound and
    /// counts in the store's `corrupt_reads` from then on, as it did before the cache was
    /// looked up first.
    cp_recheck_ns: u64 = 60 * std.time.ns_per_s,
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

/// The lowest available checkpoint the node tells clients about (`Service.reported_lowest`).
pub fn reportedLowest(svc: *const Service) u64 {
    if (svc.reported_lowest) |l| {
        const v = l.load(.acquire);
        // not read from the core yet: the node's own
        if (v != std.math.maxInt(u64)) return v;
    }
    return lowestOf(svc);
}

/// A gap in this node's store that its core does not have, met while answering (an edge:
/// src/edge/route.zig `Gap`, same values). Only looked for while `gap_watch` is set on the
/// calling thread, which only an edge's forwarding handler does, around its local attempt: the
/// call then ends with `error.LocalGap` before any response byte is written, and the handler
/// passes the request to the core. Off (every other node, every other thread): nothing changes.
pub const LocalGap = enum(u8) { none, item_missing, sig_order, object_missing, foreign_cert };
pub threadlocal var gap_watch: bool = false;
pub threadlocal var gap: LocalGap = .none;
/// Set with `gap_watch` when the request's mask renders a checkpoint's quorum certificate
/// (`Checkpoint.signature`): GetCheckpoint then asks `Service.foreign_cert` about the checkpoint
/// it is about to answer, and ends with `foreign_cert` when its certificate is not the core's.
pub threadlocal var gap_cert: bool = false;

/// The quorum certificate this node holds for a checkpoint, as an edge with a core upstream
/// may hand it out (src/edge/certs.zig, docs/EDGE.md section 13).
pub const CertState = enum {
    /// The core's (or the node tracks none): answered here.
    core,
    /// Not the core's yet, and the core can be asked: not this node's to answer.
    withhold,
    /// Not the core's yet, and no core can be reached: answered here with the certificate the
    /// node holds (valid for the committee; replaced once a core is back).
    held,
};

/// Set by an edge's forwarding handler; null on every other node, and nothing changes.
pub const ForeignCert = struct {
    ctx: *anyopaque,
    state: *const fn (ctx: *anyopaque, seq: u64) CertState,
    /// An answer is going out with a `held` certificate.
    served_held: *const fn (ctx: *anyopaque) void,
};

pub fn certState(svc: *const Service, seq: u64) CertState {
    const fc = svc.foreign_cert orelse return .core;
    return fc.state(fc.ctx, seq);
}

fn servedHeld(svc: *const Service) void {
    if (svc.foreign_cert) |fc| fc.served_held(fc.ctx);
}

pub fn foreignCert(svc: *const Service, seq: u64) bool {
    return certState(svc, seq) == .withhold;
}
/// Set with `gap_watch` when the request's mask renders transaction signatures: GetCheckpoint
/// then skips its response cache, whose entries were rendered without the signature check.
pub threadlocal var gap_sigs: bool = false;

fn gapHit(g: LocalGap) error{LocalGap}!void {
    if (!gap_watch) return;
    gap = g;
    return error.LocalGap;
}

/// A transaction with two or more signatures, under a mask that renders them: the order an edge
/// stored can differ from its core's until the signature-order sweep has passed (docs/EDGE.md
/// 10.3), so an edge does not answer it.
fn gapSigOrder(m: mask.Mask, signatures: usize) error{LocalGap}!void {
    if (gap_watch and signatures > 1 and m.contains("signatures")) return gapHit(.sig_order);
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
    // A repeated GetCheckpoint is answered from the response cache before the snapshot.
    if (std.mem.eql(u8, method, "GetCheckpoint")) {
        const sent = getCheckpointCached(self, arena, req.body, rs) catch |e| return fail(arena, rs, e);
        if (sent) return .ok;
    }
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
            try gapHit(.object_missing);
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

const CheckpointRequest = struct { seq: ?u64 = null, digest: ?[]const u8 = null, mask_field: MaskField = .{} };

/// The fields of a GetCheckpointRequest.
fn scanCheckpointRequest(arena: Allocator, body: []const u8) Err!CheckpointRequest {
    // checkpoint_id is a oneof { sequence_number = 1, digest = 2 }: the last one seen wins
    var q: CheckpointRequest = .{};
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => {
            q.seq = proto.Reader.varintOf(f) catch return error.Malformed;
            q.digest = null;
        },
        2 => {
            q.digest = proto.Reader.stringOf(f) catch return error.Malformed;
            q.seq = null;
        },
        3 => try q.mask_field.add(arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        else => {},
    };
    return q;
}

/// GetCheckpoint by sequence number (or latest) from the response cache alone: no mask parse, no
/// record read, and no snapshot unless a fix was installed since the entry was rendered
/// (`fixedSince`). True when the reply was sent; false leaves everything to `getCheckpoint`,
/// which has had no effect of this call to undo.
///
/// The reply is the one `getCheckpoint` sends for the same request at the same moment. That
/// function serves the cached entry when (1) the request parses and names no digest, (2) the
/// mask is valid and does not select `display`, (3) the sequence number is within
/// lowest..=latest, (4) the checkpoint's record is readable, (5) an entry for (sequence number,
/// raw mask bytes) is cached and (6) no transaction fix touched the checkpoint since. Here:
/// - (1) is the same scan; anything else, and every error reply, goes to `getCheckpoint`.
/// - (2) follows from (5): an entry is only ever inserted under a key whose mask passed both
///   tests, and both depend on the raw mask bytes alone.
/// - (3) reads the same values: the store's committed tip (what a snapshot taken now holds),
///   bounded by the live index, and the lowest available checkpoint.
/// - (4): a committed record at or above the store's floors is never removed, so it is readable
///   exactly while its sequence number is at or above the checkpoint floor and its segment's
///   epoch is in the history window. Both are checked here on the store's own atomics (they move
///   before the node refreshes `lowest`), the epoch being the one recorded with the entry.
///   What those cannot show is a record that fails its checks (damage on disk): `getCheckpoint`
///   answers NotFound for it and the store counts it (`stats.corrupt_reads`). So an entry is
///   served here only for `cp_recheck_ns` after its record was last read: the next call then
///   goes through `getCheckpoint`, which reads the record and, if it is good, serves the entry
///   and renews it. A damaged record is therefore answered from memory for at most that long,
///   then NotFound on every call, and counted.
/// - (5) and (6) are the same lookup and the same test.
fn getCheckpointCached(svc: *Service, arena: Allocator, body: []const u8, rs: *h2.ResponseStream) !bool {
    if (!svc.cp_cache.enabled() or gap_sigs) return false;
    const q = scanCheckpointRequest(arena, body) catch return false;
    if (q.digest != null) return false;
    const latest = boundByIndex(svc, svc.store.committed() orelse return false) orelse return false;
    const want_seq = q.seq orelse latest;
    if (want_seq < lowestOf(svc) or want_seq > latest) return false;
    if (want_seq < svc.store.cp_floor.load(.acquire)) return false;
    // (`getCheckpoint` ends the call there: nothing of a withheld certificate is served from here)
    const cert_state: CertState = if (gap_cert) certState(svc, want_seq) else .core;
    if (cert_state == .withhold) return false;
    const key = cpcache.maskKey(arena, q.mask_field.parts.items) catch return false;
    const e = svc.cp_cache.peek(want_seq, key) orelse return false;
    defer cpcache.release(svc.gpa, e);
    const epoch = e.epoch orelse return false;
    if (epoch < svc.store.oldest_epoch.load(.acquire)) return false;
    if (h2.meta.monoNs() -| e.checked_ns.load(.monotonic) >= svc.cp_recheck_ns) return false;
    if (fixedSince(svc.store, want_seq, e)) return false;
    if (cert_state == .held) servedHeld(svc);
    _ = svc.cp_cache.stats.hits.fetchAdd(1, .monotonic);
    _ = svc.cp_fast_hits.fetchAdd(1, .monotonic);
    try sendCached(svc, rs, e);
    return true;
}

/// Whether a transaction fix or a loaded-list fix installed after `e` was rendered touches its
/// checkpoint (`changedSince` on both of the store's fix tables), for a caller that holds no
/// snapshot. The tables free a merged-away index once no snapshot from before the merge is
/// live, so the index is read under a snapshot. With no fix installed since the render (the
/// common case) there is nothing to read: two atomic loads, no snapshot.
fn fixedSince(st: *store.Store, seq: u64, e: *const cpcache.Entry) bool {
    if (st.tx_fix.generation() <= e.gen and st.list_fix.generation() <= e.gen_lists and st.cert_fix.generation() <= e.gen_certs) return false;
    var snap = st.snapshot();
    defer snap.release();
    return st.tx_fix.changedSince(seq, e.gen) or st.list_fix.changedSince(seq, e.gen_lists) or st.cert_fix.changedSince(seq, e.gen_certs);
}

fn getCheckpoint(svc: *Service, arena: Allocator, snap: *store.Snapshot, body: []const u8, rs: *h2.ResponseStream) !void {
    const q = try scanCheckpointRequest(arena, body);
    var seq = q.seq;
    const digest = q.digest;
    var mask_field = q.mask_field;
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
    // An edge: this checkpoint's certificate is not its core's yet and the mask renders it.
    // Asked before the record is read: a mark is set before its checkpoint is committed and
    // cleared after the core's certificate is installed, so a record read after a "no" here
    // carries the core's certificate.
    // With no core reachable (`held`) the certificate the edge holds is the answer: it verifies.
    if (gap_cert) switch (certState(svc, want_seq)) {
        .core => {},
        .withhold => try gapHit(.foreign_cert),
        .held => servedHeld(svc),
    };
    // The certificate-fix generation, before the record is read (see the response cache below).
    const certs = &snap.store.cert_fix;
    const cert_gen = certs.generation();
    const rec = if (latest_opt != null and want_seq >= lowestOf(svc) and want_seq <= latest) snap.checkpoint(want_seq) else null;
    const found = rec orelse {
        rs.setMessage(std.fmt.allocPrint(arena, "Checkpoint {d} not found", .{want_seq}) catch "Checkpoint not found");
        return error.NotFound;
    };
    // A committed checkpoint's response is fixed: serve repeated calls from the encoded bytes.
    // `display` renders from live Display objects, so masks selecting it are rendered each time.
    const key: ?[]const u8 = if (svc.cp_cache.enabled() and !gap_sigs and !m.containsDyn("transactions.objects.objects.display"))
        try cpcache.maskKey(arena, mask_field.parts.items)
    else
        null;
    // A transaction of this checkpoint whose submitted signature order was learned after the
    // response was cached (store txfix.zig) makes the cached bytes stale. The generation is read
    // before the transactions are, so a fix landing during the render only marks this entry stale.
    // The same holds for a loaded runtime object list replaced since (store `list_fix`).
    const fixes = &snap.store.tx_fix;
    const fix_gen = fixes.generation();
    const lists = &snap.store.list_fix;
    const list_gen = lists.generation();
    // And for the checkpoint's own certificate, replaced by an edge with its core's (store
    // `cert_fix`): `cert_gen` was read before the record, so an entry rendered from the older
    // certificate is never kept under the newer generation.
    if (key) |k| if (svc.cp_cache.get(want_seq, k)) |e| {
        defer cpcache.release(svc.gpa, e);
        if (!fixes.changedSince(want_seq, e.gen) and !lists.changedSince(want_seq, e.gen_lists) and !certs.changedSince(want_seq, e.gen_certs)) {
            // the record was read just above: the entry may be served ahead of it again
            e.checked_ns.store(h2.meta.monoNs(), .monotonic);
            return sendCached(svc, rs, e);
        }
        svc.cp_cache.drop(svc.gpa, want_seq, k);
    };
    const d = try loadCheckpointData(svc, arena, snap, found, want_txs, want_objects);
    if (gap_watch) if (m.subtree("transactions")) |tm| for (d.txs) |*t| try gapSigOrder(tm, t.signatures.len);
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
    if (key) |k| svc.cp_cache.putAll(svc.gpa, want_seq, found.epoch, h2.meta.monoNs(), k, bytes, fix_gen, list_gen, cert_gen);
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
            try gapHit(.item_missing);
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
                try gapHit(.item_missing);
                w.len = start;
                try w.bytes(2, try status.plain(arena, 5, txNotFound(arena, &dg)));
                try w.end(item);
                continue;
            },
            error.Internal => {
                try gapHit(.item_missing);
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
    try gapSigOrder(m, input.signatures.len);
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
    try gapSigOrder(m, input.signatures.len);
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
    const lowest = reportedLowest(svc);
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

test "GetCheckpoint: a cached reply is sent before any store read, and every boundary answers as the store path does" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const loopback = @import("loopback.zig");
    var cfg: store.Config = .{ .max_live_objects = 1 << 10, .max_object_versions = 1 << 12, .max_transactions = 1 << 10, .max_checkpoints = 1 << 10, .max_batch_bytes = 4 << 20, .max_batch_objects = 64, .max_segments = 16, .segment_reserve = 8 << 20, .seed = 3 };
    const sim = try store.SimIo.init(gpa, 7, .{}, 64 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    const T = struct {
        fn commit(s: *store.Store, a: Allocator, seq: u64, epoch: u64) !void {
            const summary: types.CheckpointSummary = .{
                .epoch = epoch,
                .sequence_number = seq,
                .network_total_transactions = seq,
                .content_digest = .{ .@"0" = .{ .@"0" = @splat(0) } },
                .previous_digest = null,
                .epoch_rolling_gas_cost_summary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
                .timestamp_ms = 1_700_000_000_000 + seq,
                .checkpoint_commitments = &.{},
                .end_of_epoch_data = null,
                .version_specific_data = &.{},
            };
            const empty_bitmap = [_]u8{ 0x3a, 0x30, 0, 0, 0, 0, 0, 0 };
            const sig: types.AuthorityQuorumSignInfo = .{ .epoch = epoch, .signature = @splat(0), .signers_map = .{ .@"0" = &empty_bitmap } };
            const x = try bcs.encodeAlloc(types.CheckpointSummary, a, &summary);
            const y = try bcs.encodeAlloc(types.AuthorityQuorumSignInfo, a, &sig);
            const b = try s.begin(seq, epoch);
            try b.checkpoint(try std.mem.concat(a, u8, &.{ x, y }), &.{ 0, 0, 0 });
            try s.commit(b);
        }
        /// GetCheckpointRequest: `seq` (absent: latest) and a read mask.
        fn request(a: Allocator, seq: ?u64, paths: []const []const u8) ![]const u8 {
            const buf = try a.alloc(u8, 256);
            var w = proto.Writer.init(buf);
            if (seq) |n| try w.uint(1, n);
            const m = try w.begin(3, 64);
            for (paths) |p| try w.string(1, p);
            try w.end(m);
            return w.bytesWritten();
        }
        var live: StateHook.Live = .{ .ready = false, .checkpoint = null };
        fn liveFn(_: *anyopaque) StateHook.Live {
            return live;
        }
        fn stateCall(_: *anyopaque, _: *Service, _: Allocator, _: []const u8, _: []const u8, _: *h2.ResponseStream) h2.Status {
            return .unimplemented;
        }
    };
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // epoch 0: checkpoints 0..5, epoch 1: 6..11, epoch 2: 12..14
    for (0..15) |i| try T.commit(st, a, i, if (i < 6) 0 else if (i < 12) 1 else 2);

    // `svc` has the response cache; `ref` never caches, so every one of its replies is rendered
    // from the store: the reference for each case below.
    var svc: Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    var ref: Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0), .cp_cache = .{ .budget = 0 } };
    defer ref.deinit();
    var dummy: u8 = 0;
    T.live = .{ .ready = false, .checkpoint = null };
    svc.state = .{ .ctx = &dummy, .call = T.stateCall, .live = T.liveFn };
    ref.state = svc.state;
    const path = "/sui.rpc.v2.LedgerService/GetCheckpoint";
    const mask_paths = [_][]const u8{ "sequence_number", "digest", "summary", "signature", "contents" };
    const Same = struct {
        /// Asks both services; the replies must be equal. Returns the gRPC status.
        fn ask(al: Allocator, s: *Service, r: *Service, body: []const u8) !u8 {
            const got = try loopback.unary(al, s.handler(), path, body);
            const want = try loopback.unary(al, r.handler(), path, body);
            try testing.expectEqual(want.status, got.status);
            try testing.expectEqualSlices(u8, want.message, got.message);
            try testing.expectEqualStrings(want.grpc_message, got.grpc_message);
            try testing.expectEqualSlices(u8, want.details, got.details);
            return got.status;
        }
    };
    const fast = &svc.cp_fast_hits;
    // First asks render and cache (by number, and "latest"); the same asks again never reach the store.
    for ([_]?u64{ 2, 5, 7, 9, 13, 14, null }) |seq| try testing.expectEqual(@as(u8, 0), try Same.ask(a, &svc, &ref, try T.request(a, seq, &mask_paths)));
    try testing.expectEqual(@as(u64, 1), fast.load(.monotonic)); // "latest" is 14, cached by the ask before it
    for ([_]?u64{ 2, 5, 7, 9, 13, 14, null }) |seq| try testing.expectEqual(@as(u8, 0), try Same.ask(a, &svc, &ref, try T.request(a, seq, &mask_paths)));
    try testing.expectEqual(@as(u64, 8), fast.load(.monotonic));
    try testing.expectEqual(@as(u64, 8), svc.cp_cache.stats.hits.load(.monotonic));
    try testing.expectEqual(@as(u64, 6), svc.cp_cache.stats.misses.load(.monotonic));
    // Another mask, the same paths in another order, a digest: not the cached key, the store path.
    try testing.expectEqual(@as(u8, 0), try Same.ask(a, &svc, &ref, try T.request(a, 9, &.{ "digest", "sequence_number" })));
    try testing.expectEqual(@as(u64, 8), fast.load(.monotonic));
    // An invalid mask is the same INVALID_ARGUMENT whether or not the checkpoint is cached.
    try testing.expectEqual(@as(u8, 3), try Same.ask(a, &svc, &ref, try T.request(a, 9, &.{"nope"})));
    // Not yet available: NOT_FOUND; once committed it is served (failures are never cached).
    try testing.expectEqual(@as(u8, 5), try Same.ask(a, &svc, &ref, try T.request(a, 15, &mask_paths)));
    try T.commit(st, a, 15, 2);
    try testing.expectEqual(@as(u8, 0), try Same.ask(a, &svc, &ref, try T.request(a, 15, &mask_paths)));
    // "latest" follows the tip: 15 now (cached by the ask just above), not the 14 cached for it before.
    const f0 = fast.load(.monotonic);
    try testing.expectEqual(@as(u8, 0), try Same.ask(a, &svc, &ref, try T.request(a, null, &mask_paths)));
    try testing.expectEqual(f0 + 1, fast.load(.monotonic));

    // The live index bounds the tip at 13: 14 and 15 are cached and no longer served.
    T.live = .{ .ready = true, .checkpoint = 13 };
    const f1 = fast.load(.monotonic);
    try testing.expectEqual(@as(u8, 5), try Same.ask(a, &svc, &ref, try T.request(a, 14, &mask_paths)));
    try testing.expectEqual(@as(u8, 5), try Same.ask(a, &svc, &ref, try T.request(a, 15, &mask_paths)));
    try testing.expectEqual(f1, fast.load(.monotonic));
    try testing.expectEqual(@as(u8, 0), try Same.ask(a, &svc, &ref, try T.request(a, null, &mask_paths))); // latest is 13, cached
    try testing.expectEqual(f1 + 1, fast.load(.monotonic));
    T.live = .{ .ready = false, .checkpoint = null };

    // Pruned by the checkpoint floor, before the node has refreshed `lowest`: 2 is cached, and gone.
    _ = try st.setFloors(.{ .cp_pruned = 3 });
    const f2 = fast.load(.monotonic);
    try testing.expectEqual(@as(u8, 5), try Same.ask(a, &svc, &ref, try T.request(a, 2, &mask_paths)));
    try testing.expectEqual(f2, fast.load(.monotonic));
    try testing.expectEqual(@as(u8, 0), try Same.ask(a, &svc, &ref, try T.request(a, 5, &mask_paths)));
    try testing.expectEqual(f2 + 1, fast.load(.monotonic));
    // Aged out by epoch (segment 0 leaves the window): 5 is above the checkpoint floor, cached, and gone.
    _ = try st.ageOut(1);
    try testing.expectEqual(@as(u8, 5), try Same.ask(a, &svc, &ref, try T.request(a, 5, &mask_paths)));
    try testing.expectEqual(f2 + 1, fast.load(.monotonic));
    try testing.expectEqual(@as(u8, 0), try Same.ask(a, &svc, &ref, try T.request(a, 7, &mask_paths)));
    try testing.expectEqual(f2 + 2, fast.load(.monotonic));
    // The lowest available checkpoint moves above 7: cached, readable in the store, not served.
    svc.lowest_checkpoint = 8;
    ref.lowest_checkpoint = 8;
    try testing.expectEqual(@as(u8, 5), try Same.ask(a, &svc, &ref, try T.request(a, 7, &mask_paths)));
    try testing.expectEqual(f2 + 2, fast.load(.monotonic));
    try testing.expectEqual(@as(u8, 0), try Same.ask(a, &svc, &ref, try T.request(a, 9, &mask_paths)));
    try testing.expectEqual(f2 + 3, fast.load(.monotonic));
    // A transaction fix for checkpoint 9 makes its entry stale: rendered again, then cached again.
    const d9: [32]u8 = @splat(9);
    _ = try st.tx_fix.put(9, &d9, "fix");
    try testing.expectEqual(@as(u8, 0), try Same.ask(a, &svc, &ref, try T.request(a, 9, &mask_paths)));
    try testing.expectEqual(f2 + 3, fast.load(.monotonic));
    try testing.expectEqual(@as(u8, 0), try Same.ask(a, &svc, &ref, try T.request(a, 9, &mask_paths)));
    try testing.expectEqual(f2 + 4, fast.load(.monotonic));
    // An entry put without its epoch (`put`) is never served ahead of the record read.
    const raw_key = try cpcache.maskKey(a, &.{"x"});
    svc.cp_cache.put(gpa, 13, raw_key, "not a response");
    const Noop = struct {
        fn write(_: *anyopaque, _: *const [5]u8, _: []const u8) anyerror!void {}
        fn cancelled(_: *anyopaque) bool {
            return false;
        }
    };
    var dummy_rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &dummy, .vt = &.{ .write = Noop.write, .cancelled = Noop.cancelled } };
    var raw_req: [16]u8 = undefined;
    var rw = proto.Writer.init(&raw_req);
    try rw.uint(1, 13);
    try rw.bytes(3, "x");
    try testing.expect(!(try getCheckpointCached(&svc, a, rw.bytesWritten(), &dummy_rs)));
}

/// A small chain in a simulated store, for tests of the GetCheckpoint paths.
const CpTest = struct {
    fn commit(s: *store.Store, a: Allocator, seq: u64, epoch: u64) !void {
        const summary: types.CheckpointSummary = .{
            .epoch = epoch,
            .sequence_number = seq,
            .network_total_transactions = seq,
            .content_digest = .{ .@"0" = .{ .@"0" = @splat(0) } },
            .previous_digest = null,
            .epoch_rolling_gas_cost_summary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
            .timestamp_ms = 1_700_000_000_000 + seq,
            .checkpoint_commitments = &.{},
            .end_of_epoch_data = null,
            .version_specific_data = &.{},
        };
        const empty_bitmap = [_]u8{ 0x3a, 0x30, 0, 0, 0, 0, 0, 0 };
        const sig: types.AuthorityQuorumSignInfo = .{ .epoch = epoch, .signature = @splat(0), .signers_map = .{ .@"0" = &empty_bitmap } };
        const x = try bcs.encodeAlloc(types.CheckpointSummary, a, &summary);
        const y = try bcs.encodeAlloc(types.AuthorityQuorumSignInfo, a, &sig);
        const b = try s.begin(seq, epoch);
        try b.checkpoint(try std.mem.concat(a, u8, &.{ x, y }), &.{ 0, 0, 0 });
        try s.commit(b);
    }
    /// GetCheckpointRequest: `seq` (absent: latest) and a read mask.
    fn request(a: Allocator, seq: ?u64, paths: []const []const u8) ![]const u8 {
        const buf = try a.alloc(u8, 256);
        var w = proto.Writer.init(buf);
        if (seq) |n| try w.uint(1, n);
        const m = try w.begin(3, 64);
        for (paths) |p| try w.string(1, p);
        try w.end(m);
        return w.bytesWritten();
    }
    const path = "/sui.rpc.v2.LedgerService/GetCheckpoint";
    const masks = [_][]const []const u8{
        &.{ "sequence_number", "digest", "summary", "signature", "contents" },
        &.{ "sequence_number", "summary" },
    };
};

test "GetCheckpoint over sockets: cached replies (borrowed, zstd, gRPC-web text) stay whole under eviction, re-render and clients that leave" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const io = testing.io;
    const loopback = @import("loopback.zig");
    var cfg: store.Config = .{ .max_live_objects = 1 << 10, .max_object_versions = 1 << 12, .max_transactions = 1 << 10, .max_checkpoints = 1 << 10, .max_batch_bytes = 4 << 20, .max_batch_objects = 64, .max_segments = 16, .segment_reserve = 8 << 20, .seed = 3 };
    const sim = try store.SimIo.init(gpa, 7, .{}, 64 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const nseq = 24;
    for (0..nseq) |i| try CpTest.commit(st, a, i, 0);

    // What every reply must be: rendered by a service that never caches.
    var ref: Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0), .cp_cache = .{ .budget = 0 } };
    defer ref.deinit();
    var want: [nseq][CpTest.masks.len][]const u8 = undefined;
    var largest: usize = 0;
    for (0..nseq) |i| for (CpTest.masks, 0..) |m, j| {
        const r = try loopback.unary(a, ref.handler(), CpTest.path, try CpTest.request(a, i, m));
        try testing.expectEqual(@as(u8, 0), r.status);
        want[i][j] = r.message;
        largest = @max(largest, r.message.len);
    };
    // A cache that holds about five responses per shard: derived frames (zstd, base64) push
    // entries out all the time, also while a worker still holds one for the transport.
    var svc: Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0), .cp_cache = .{ .budget = cpcache.nshards * 5 * (largest + 64 + @sizeOf(cpcache.Entry)) } };
    defer svc.deinit();

    const Srv = struct {
        io: std.Io,
        handler: h2.Handler,
        server: std.Io.net.Server,
        stopping: std.atomic.Value(bool) = .init(false),
        live: std.atomic.Value(u32) = .init(0),
        fn loop(s: *@This()) void {
            while (!s.stopping.load(.acquire)) {
                const c = s.server.accept(s.io) catch return;
                if (s.stopping.load(.acquire)) return c.close(s.io);
                _ = s.live.fetchAdd(1, .acq_rel);
                const t = std.Thread.spawn(.{}, conn, .{ s, c }) catch {
                    _ = s.live.fetchSub(1, .acq_rel);
                    c.close(s.io);
                    continue;
                };
                t.detach();
            }
        }
        fn conn(s: *@This(), c: std.Io.net.Stream) void {
            h2.server.serveStreamOpts(testing.allocator, s.io, c, .{}, s.handler);
            _ = s.live.fetchSub(1, .acq_rel);
        }
    };
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var srv: Srv = .{ .io = io, .handler = svc.handler(), .server = try addr.listen(io, .{ .reuse_address = true }) };
    const port = srv.server.socket.address.getPort();
    const accept_thread = try std.Thread.spawn(.{}, Srv.loop, .{&srv});

    const Shared = struct {
        port: u16,
        io: std.Io,
        want: *const [nseq][CpTest.masks.len][]const u8,
        st: *store.Store,
        stop: std.atomic.Value(bool) = .init(false),
        calls: std.atomic.Value(u32) = .init(0),
        left: std.atomic.Value(u32) = .init(0),
        bad: std.atomic.Value(u32) = .init(0),
        fn fail(sh: *@This(), comptime fmt: []const u8, args: anytype) void {
            if (sh.bad.fetchAdd(1, .monotonic) < 8) std.debug.print("cp socket stress: " ++ fmt ++ "\n", args);
        }
        fn unzstd(al: Allocator, z: []const u8) ![]u8 {
            var in: std.Io.Reader = .fixed(z);
            const dbuf = try al.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
            var dz: std.compress.zstd.Decompress = .init(&in, dbuf, .{});
            return dz.reader.allocRemaining(al, .unlimited);
        }
        fn client(sh: *@This(), idx: usize) void {
            var ar = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer ar.deinit();
            var rng = std.Random.DefaultPrng.init(0xc11e + idx);
            const r = rng.random();
            const bin = [_][2][]const u8{ .{ "content-type", "application/grpc" }, .{ "te", "trailers" } };
            const bin_z = [_][2][]const u8{ .{ "content-type", "application/grpc" }, .{ "te", "trailers" }, .{ "grpc-accept-encoding", "zstd" } };
            const text = [_][2][]const u8{ .{ "content-type", "application/grpc-web-text" }, .{ "accept", "application/grpc-web-text" } };
            const text_z = [_][2][]const u8{ .{ "content-type", "application/grpc-web-text" }, .{ "accept", "application/grpc-web-text" }, .{ "grpc-accept-encoding", "zstd" } };
            while (!sh.stop.load(.acquire)) {
                _ = ar.reset(.retain_capacity);
                const al = ar.allocator();
                const seq = r.uintLessThan(usize, nseq);
                const mi = r.uintLessThan(usize, CpTest.masks.len);
                const mode = r.uintLessThan(u8, 4);
                const leave = r.uintLessThan(u8, 8) == 0;
                const req = CpTest.request(al, seq, CpTest.masks[mi]) catch return;
                const hdrs: []const [2][]const u8 = switch (mode) {
                    0 => &bin,
                    1 => &bin_z,
                    2 => &text,
                    else => &text_z,
                };
                // a client that leaves closes at the first DATA frame, the rest of the reply unread
                const rep = loopback.call(al, sh.io, sh.port, CpTest.path, hdrs, &.{req}, .{ .text_body = mode >= 2, .max_messages = if (leave) 0 else null }) catch |e| {
                    sh.fail("call: {s}", .{@errorName(e)});
                    continue;
                };
                if (leave) {
                    _ = sh.left.fetchAdd(1, .monotonic);
                    continue;
                }
                _ = sh.calls.fetchAdd(1, .monotonic);
                const expected = sh.want[seq][mi];
                var flag: u8 = 0;
                var body: []const u8 = "";
                if (mode < 2) {
                    if (rep.messages.items.len != 1) {
                        sh.fail("seq {d} mode {d}: {d} messages", .{ seq, mode, rep.messages.items.len });
                        continue;
                    }
                    flag = @intFromBool(rep.messages.items[0].compressed);
                    body = rep.messages.items[0].payload;
                } else {
                    const raw = h2.codec.base64DecodeChunks(al, rep.data.items) catch {
                        sh.fail("seq {d} mode {d}: reply is not base64", .{ seq, mode });
                        continue;
                    };
                    if (raw.len < 5 or raw.len - 5 < std.mem.readInt(u32, raw[1..5], .big)) {
                        sh.fail("seq {d} mode {d}: short text reply ({d} bytes)", .{ seq, mode, raw.len });
                        continue;
                    }
                    flag = raw[0];
                    body = raw[5..][0..std.mem.readInt(u32, raw[1..5], .big)];
                }
                const got = if (flag & 1 != 0) unzstd(al, body) catch {
                    sh.fail("seq {d} mode {d}: reply does not zstd-decode", .{ seq, mode });
                    continue;
                } else body;
                if (!std.mem.eql(u8, expected, got)) sh.fail("seq {d} mask {d} mode {d}: reply differs ({d} bytes, want {d})", .{ seq, mi, mode, got.len, expected.len });
            }
        }
        /// Transaction fixes for random checkpoints: their cached responses turn stale, are
        /// dropped and rendered again (to the same bytes: no transaction has these digests).
        fn fixer(sh: *@This()) void {
            var n: u64 = 0;
            while (!sh.stop.load(.acquire)) : (n += 1) {
                var d: [32]u8 = @splat(0xf1);
                std.mem.writeInt(u64, d[0..8], n, .little);
                _ = sh.st.tx_fix.put(n % nseq, &d, "x") catch {};
                h2.sock.sleepMs(2);
            }
        }
    };
    var sh: Shared = .{ .port = port, .io = io, .want = &want, .st = st };
    var clients: [4]std.Thread = undefined;
    for (&clients, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Shared.client, .{ &sh, i });
    const fix_thread = try std.Thread.spawn(.{}, Shared.fixer, .{&sh});
    h2.sock.sleepMs(1500);
    sh.stop.store(true, .release);
    for (clients) |t| t.join();
    fix_thread.join();
    srv.stopping.store(true, .release);
    {
        // wake the accept loop
        var wake = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
        if (wake.connect(io, .{ .mode = .stream })) |c| c.close(io) else |_| {}
    }
    accept_thread.join();
    while (srv.live.load(.acquire) != 0) h2.sock.sleepMs(1);
    srv.server.deinit(io);
    try testing.expect(h2.server.waitDrained(5 * std.time.ns_per_s));

    try testing.expectEqual(@as(u32, 0), sh.bad.load(.monotonic));
    try testing.expect(sh.calls.load(.monotonic) > 100);
    try testing.expect(sh.left.load(.monotonic) > 5);
    const cs = &svc.cp_cache.stats;
    try testing.expect(cs.hits.load(.monotonic) > 0);
    try testing.expect(cs.evictions.load(.monotonic) > 0);
    // `svc.deinit` (deferred) frees every entry: a reference never given back, or given back
    // twice, is the test allocator's leak or double free.
}

test "GetCheckpoint: a record damaged on disk under a cached reply is read again within the recheck time, then NotFound and counted" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const loopback = @import("loopback.zig");
    var cfg: store.Config = .{ .max_live_objects = 1 << 10, .max_object_versions = 1 << 12, .max_transactions = 1 << 10, .max_checkpoints = 1 << 10, .max_batch_bytes = 4 << 20, .max_batch_objects = 64, .max_segments = 16, .segment_reserve = 8 << 20, .seed = 3, .compress = false };
    // (uncompressed segments: a read goes to the file's bytes, not to a decoded chunk kept in memory)
    const sim = try store.SimIo.init(gpa, 7, .{}, 64 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // epoch 0: checkpoints 0..3 (the segment that will be damaged), epoch 1: 4..7
    for (0..8) |i| try CpTest.commit(st, a, i, if (i < 4) 0 else 1);
    var svc: Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    const req2 = try CpTest.request(a, 2, CpTest.masks[0]);
    const req6 = try CpTest.request(a, 6, CpTest.masks[0]);
    const first = try loopback.unary(a, svc.handler(), CpTest.path, req2);
    try testing.expectEqual(@as(u8, 0), first.status);
    try testing.expectEqual(@as(u8, 0), (try loopback.unary(a, svc.handler(), CpTest.path, req6)).status);
    // Served from the cache, no store read (the default recheck time is a minute).
    try testing.expectEqual(@as(u8, 0), (try loopback.unary(a, svc.handler(), CpTest.path, req2)).status);
    try testing.expectEqual(@as(u64, 1), svc.cp_fast_hits.load(.monotonic));

    // The recheck: once the time is up a hit takes the store path, reads the record, serves the
    // entry and renews it, so the call after that is fast again.
    svc.cp_recheck_ns = 0;
    const slow = try loopback.unary(a, svc.handler(), CpTest.path, req2);
    try testing.expectEqualSlices(u8, first.message, slow.message);
    try testing.expectEqual(@as(u64, 1), svc.cp_fast_hits.load(.monotonic));
    svc.cp_recheck_ns = 60 * std.time.ns_per_s;
    try testing.expectEqual(@as(u8, 0), (try loopback.unary(a, svc.handler(), CpTest.path, req2)).status);
    try testing.expectEqual(@as(u64, 2), svc.cp_fast_hits.load(.monotonic));

    // Damage on disk: the records of segment 0 read back as zeros.
    var nb: [96]u8 = undefined;
    const name = store.io.segName(&nb, 0);
    const fd = try sim.openFile(name, false);
    const size = try sim.size(fd);
    sim.closeFile(fd);
    try testing.expect(size > 0);
    try testing.expect(sim.zeroAt(name, 0, size));
    const corrupt0 = st.stats.corrupt_reads.load(.monotonic);
    // Within the recheck time the cached reply still goes out, with no store read.
    const during = try loopback.unary(a, svc.handler(), CpTest.path, req2);
    try testing.expectEqual(@as(u8, 0), during.status);
    try testing.expectEqualSlices(u8, first.message, during.message);
    try testing.expectEqual(@as(u64, 3), svc.cp_fast_hits.load(.monotonic));
    try testing.expectEqual(corrupt0, st.stats.corrupt_reads.load(.monotonic));
    // Once the recheck time has passed (here: set to nothing) the call reads the record:
    // NotFound, and the store counts the damaged read. The entry is never renewed, so every
    // later call does the same, as every call did before the cache was looked up first.
    svc.cp_recheck_ns = 0;
    for (0..3) |i| {
        const after = try loopback.unary(a, svc.handler(), CpTest.path, req2);
        try testing.expectEqual(@as(u8, 5), after.status);
        try testing.expectEqualStrings("Checkpoint 2 not found", after.grpc_message);
        try testing.expect(st.stats.corrupt_reads.load(.monotonic) >= corrupt0 + 1 + i);
    }
    try testing.expectEqual(@as(u64, 3), svc.cp_fast_hits.load(.monotonic));
    // A checkpoint of the undamaged segment is unaffected.
    try testing.expectEqual(@as(u8, 0), (try loopback.unary(a, svc.handler(), CpTest.path, req6)).status);
}

test "GetCheckpoint: a signature-order fix or a loaded-list fix of the checkpoint keeps its cached reply off the lookup before the store read; a fix of another checkpoint does not" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const loopback = @import("loopback.zig");
    var cfg: store.Config = .{ .max_live_objects = 1 << 10, .max_object_versions = 1 << 12, .max_transactions = 1 << 10, .max_checkpoints = 1 << 10, .max_batch_bytes = 4 << 20, .max_batch_objects = 64, .max_segments = 16, .segment_reserve = 8 << 20, .seed = 3 };
    const sim = try store.SimIo.init(gpa, 7, .{}, 64 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for (0..8) |i| try CpTest.commit(st, a, i, 0);
    var svc: Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    // Every call below is within the recheck time, however slow the machine.
    svc.cp_recheck_ns = std.time.ns_per_hour;
    const req2 = try CpTest.request(a, 2, CpTest.masks[0]);
    const req5 = try CpTest.request(a, 5, CpTest.masks[0]);
    const fast = &svc.cp_fast_hits;
    const inserts = &svc.cp_cache.stats.inserts;
    const want2 = (try loopback.unary(a, svc.handler(), CpTest.path, req2)).message;
    const want5 = (try loopback.unary(a, svc.handler(), CpTest.path, req5)).message;
    try testing.expectEqual(@as(u64, 2), inserts.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), fast.load(.monotonic));
    var f: u64 = 0; // the fast hits so far
    var n: u64 = 2; // the inserts so far
    // Both of the store's fix tables, in turn: a fix of checkpoint 5 alone (no transaction has
    // the digest, so the reply's bytes stay).
    for ([_]*store.txfix.Table{ &st.tx_fix, &st.list_fix }, 0..) |table, k| {
        var d: [32]u8 = @splat(0xd0);
        d[0] = @intCast(k);
        try testing.expect(try table.put(5, &d, "x"));
        // Checkpoint 2 was not touched: still answered before any store read, the entry kept.
        try testing.expectEqualSlices(u8, want2, (try loopback.unary(a, svc.handler(), CpTest.path, req2)).message);
        f += 1;
        try testing.expectEqual(f, fast.load(.monotonic));
        try testing.expectEqual(n, inserts.load(.monotonic));
        // Checkpoint 5 is stale: not answered ahead of the store; dropped, rendered and cached again.
        try testing.expectEqualSlices(u8, want5, (try loopback.unary(a, svc.handler(), CpTest.path, req5)).message);
        n += 1;
        try testing.expectEqual(f, fast.load(.monotonic));
        try testing.expectEqual(n, inserts.load(.monotonic));
        try testing.expectEqual(@as(u64, 2), svc.cp_cache.entries());
        // The new entry carries the new generation: answered before the store read again.
        try testing.expectEqualSlices(u8, want5, (try loopback.unary(a, svc.handler(), CpTest.path, req5)).message);
        f += 1;
        try testing.expectEqual(f, fast.load(.monotonic));
        try testing.expectEqual(n, inserts.load(.monotonic));
    }
}

test "GetCheckpoint: a certificate fix of the checkpoint (an edge installing its core's) is in the next reply, not the cached one; and with an edge's marks, a reply that would render a marked checkpoint's certificate ends as the foreign_cert gap before any byte" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const loopback = @import("loopback.zig");
    var cfg: store.Config = .{ .max_live_objects = 1 << 10, .max_object_versions = 1 << 12, .max_transactions = 1 << 10, .max_checkpoints = 1 << 10, .max_batch_bytes = 4 << 20, .max_batch_objects = 64, .max_segments = 16, .segment_reserve = 8 << 20, .seed = 3 };
    const sim = try store.SimIo.init(gpa, 7, .{}, 64 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for (0..8) |i| try CpTest.commit(st, a, i, 0);
    var svc: Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    svc.cp_recheck_ns = std.time.ns_per_hour;
    const with_cert = CpTest.masks[0];
    const without = CpTest.masks[1];
    const req2 = try CpTest.request(a, 2, with_cert);
    const req5 = try CpTest.request(a, 5, with_cert);
    const req5_plain = try CpTest.request(a, 5, without);
    const fast = &svc.cp_fast_hits;
    const old2 = (try loopback.unary(a, svc.handler(), CpTest.path, req2)).message;
    const old5 = (try loopback.unary(a, svc.handler(), CpTest.path, req5)).message;
    const plain5 = (try loopback.unary(a, svc.handler(), CpTest.path, req5_plain)).message;
    try testing.expectEqualSlices(u8, old5, (try loopback.unary(a, svc.handler(), CpTest.path, req5)).message);
    try testing.expectEqual(@as(u64, 1), fast.load(.monotonic));

    // Checkpoint 5 gets another certificate over the same summary (the core's, on an edge).
    const other: []const u8 = blk: {
        var snap = st.snapshot();
        defer snap.release();
        const stored = snap.checkpoint(5).?.summary_cert;
        const cert = try render_checkpoint.Cert.parse(a, stored);
        const bitmap = [_]u8{ 0x3a, 0x30, 0, 0, 0, 0, 0, 0 };
        const sig: types.AuthorityQuorumSignInfo = .{ .epoch = 0, .signature = @splat(0x77), .signers_map = .{ .@"0" = &bitmap } };
        break :blk try std.mem.concat(a, u8, &.{ cert.summary_bcs, try bcs.encodeAlloc(types.AuthorityQuorumSignInfo, a, &sig) });
    };
    try testing.expect(try st.cert_fix.put(5, &store.certFixKey(5), other));
    // not the cached reply: rendered again, with the installed certificate, and cached again
    const new5 = (try loopback.unary(a, svc.handler(), CpTest.path, req5)).message;
    try testing.expect(!std.mem.eql(u8, old5, new5));
    try testing.expect(std.mem.indexOf(u8, new5, &@as([48]u8, @splat(0x77))) != null);
    try testing.expectEqual(@as(u64, 1), fast.load(.monotonic));
    try testing.expectEqualSlices(u8, new5, (try loopback.unary(a, svc.handler(), CpTest.path, req5)).message);
    try testing.expectEqual(@as(u64, 2), fast.load(.monotonic));
    // a mask without the certificate renders the same bytes as before; another checkpoint's
    // cached reply is still served ahead of the store
    try testing.expectEqualSlices(u8, plain5, (try loopback.unary(a, svc.handler(), CpTest.path, req5_plain)).message);
    try testing.expectEqualSlices(u8, old2, (try loopback.unary(a, svc.handler(), CpTest.path, req2)).message);

    // An edge with a core upstream: checkpoints 3 and 7 (the latest) hold a certificate that is
    // not the core's. Its forwarding handler sets the watch around the local attempt.
    // `held`: no core is reachable (the node answers with what it holds); else `withhold`.
    const Marks = struct {
        var no_core: bool = false;
        var served: u32 = 0;
        fn state(_: *anyopaque, seq: u64) CertState {
            if (seq != 3 and seq != 7) return .core;
            return if (no_core) .held else .withhold;
        }
        fn servedHeldFn(_: *anyopaque) void {
            served += 1;
        }
    };
    Marks.no_core = false;
    Marks.served = 0;
    var ctx: u8 = 0;
    svc.foreign_cert = .{ .ctx = &ctx, .state = Marks.state, .served_held = Marks.servedHeldFn };
    defer {
        gap_watch = false;
        gap_cert = false;
        gap = .none;
    }
    const Ask = struct {
        fn gapOf(s: *Service, arena: Allocator, body: []const u8, cert: bool) !struct { gap: LocalGap, bytes: usize, status: u8 } {
            gap = .none;
            gap_watch = true;
            gap_cert = cert;
            defer gap_watch = false;
            defer gap_cert = false;
            const r = try loopback.unary(arena, s.handler(), CpTest.path, body);
            return .{ .gap = gap, .bytes = r.message.len, .status = r.status };
        }
    };
    // marked, the mask renders the certificate: the gap, nothing sent
    inline for (.{ @as(?u64, 3), @as(?u64, 7), @as(?u64, null) }) |seq| {
        const r = try Ask.gapOf(&svc, a, try CpTest.request(a, seq, with_cert), true);
        try testing.expectEqual(LocalGap.foreign_cert, r.gap);
        try testing.expectEqual(@as(usize, 0), r.bytes);
    }
    // the same checkpoints under a mask without it, and unmarked ones with it: answered here
    for ([_]?u64{ 3, 7, null }) |seq| {
        const r = try Ask.gapOf(&svc, a, try CpTest.request(a, seq, without), false);
        try testing.expectEqual(LocalGap.none, r.gap);
        try testing.expectEqual(@as(u8, 0), r.status);
    }
    for ([_]?u64{ 2, 5, 6 }) |seq| {
        const r = try Ask.gapOf(&svc, a, try CpTest.request(a, seq, with_cert), true);
        try testing.expectEqual(LocalGap.none, r.gap);
        try testing.expectEqual(@as(u8, 0), r.status);
        try testing.expect(r.bytes > 0);
    }
    // a reply of a marked checkpoint cached earlier (before it was marked here) is not served
    // from the cache either
    svc.foreign_cert = null;
    const cached3 = (try loopback.unary(a, svc.handler(), CpTest.path, try CpTest.request(a, 3, with_cert))).message;
    try testing.expect(cached3.len > 0);
    svc.foreign_cert = .{ .ctx = &ctx, .state = Marks.state, .served_held = Marks.servedHeldFn };
    const r = try Ask.gapOf(&svc, a, try CpTest.request(a, 3, with_cert), true);
    try testing.expectEqual(LocalGap.foreign_cert, r.gap);
    try testing.expectEqual(@as(usize, 0), r.bytes);
    try testing.expectEqual(@as(u32, 0), Marks.served);
    // No core reachable: the same requests are answered here with the certificate the node
    // holds, from the cache and rendered, and each such answer is counted; one that does not
    // render the certificate is not.
    Marks.no_core = true;
    inline for (.{ @as(?u64, 3), @as(?u64, 7), @as(?u64, null), @as(?u64, 3) }, 0..) |seq, i| {
        const h = try Ask.gapOf(&svc, a, try CpTest.request(a, seq, with_cert), true);
        try testing.expectEqual(LocalGap.none, h.gap);
        try testing.expectEqual(@as(u8, 0), h.status);
        try testing.expect(h.bytes > 0);
        try testing.expectEqual(@as(u32, i + 1), Marks.served);
    }
    _ = try Ask.gapOf(&svc, a, try CpTest.request(a, 3, without), false);
    _ = try Ask.gapOf(&svc, a, try CpTest.request(a, 5, with_cert), true);
    try testing.expectEqual(@as(u32, 4), Marks.served);
    // a core is back: withheld again, the cached reply included
    Marks.no_core = false;
    const back = try Ask.gapOf(&svc, a, try CpTest.request(a, 3, with_cert), true);
    try testing.expectEqual(LocalGap.foreign_cert, back.gap);
    try testing.expectEqual(@as(usize, 0), back.bytes);
    // without the watch (no forwarding handler in front): the node's own answer, as ever
    try testing.expectEqualSlices(u8, cached3, (try loopback.unary(a, svc.handler(), CpTest.path, try CpTest.request(a, 3, with_cert))).message);
}

test "GetCheckpoint: the lookup before the store read reads the fix tables under a snapshot, and takes none while no fix was installed since the render" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const loopback = @import("loopback.zig");
    var cfg: store.Config = .{ .max_live_objects = 1 << 10, .max_object_versions = 1 << 12, .max_transactions = 1 << 10, .max_checkpoints = 1 << 10, .max_batch_bytes = 4 << 20, .max_batch_objects = 64, .max_segments = 16, .segment_reserve = 8 << 20, .seed = 3 };
    const sim = try store.SimIo.init(gpa, 7, .{}, 64 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for (0..8) |i| try CpTest.commit(st, a, i, 0);
    var svc: Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    svc.cp_recheck_ns = std.time.ns_per_hour;

    const Shared = struct {
        svc: *Service,
        req: []const u8 = "",
        calls: std.atomic.Value(u64) = .init(0),
        refused: std.atomic.Value(u64) = .init(0),
        fn write(_: *anyopaque, _: *const [5]u8, _: []const u8) anyerror!void {}
        fn cancelled(_: *anyopaque) bool {
            return false;
        }
        /// One call of the lookup; a call that does not send the cached reply is counted.
        fn ask(sh: *@This()) void {
            var buf: [2048]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&buf);
            var dummy: u8 = 0;
            var rs: h2.ResponseStream = .{ .gpa = testing.allocator, .impl = &dummy, .vt = &.{ .write = write, .cancelled = cancelled } };
            const sent = getCheckpointCached(sh.svc, fba.allocator(), sh.req, &rs) catch false;
            if (!sent) _ = sh.refused.fetchAdd(1, .monotonic);
            _ = sh.calls.fetchAdd(1, .release);
        }
        /// Whether `n` calls have finished, waiting up to `ms`.
        fn waitCalls(sh: *@This(), n: u64, ms: u32) bool {
            var waited: u32 = 0;
            while (sh.calls.load(.acquire) < n and waited < ms) : (waited += 1) h2.sock.sleepMs(1);
            return sh.calls.load(.acquire) >= n;
        }
    };
    var sh: Shared = .{ .svc = &svc };
    var calls: u64 = 0;
    // Each of the store's two fix tables in turn, on an entry rendered after every earlier fix.
    // Snapshots register under `creaders.lock`: while the test holds it, a call that takes a
    // snapshot cannot finish.
    for ([_]*store.txfix.Table{ &st.tx_fix, &st.list_fix }, 0..) |table, k| {
        sh.req = try CpTest.request(a, 2 + k, CpTest.masks[0]);
        try testing.expectEqual(@as(u8, 0), (try loopback.unary(a, svc.handler(), CpTest.path, sh.req)).status);
        // No fix was installed since the render: the call takes no snapshot, and finishes.
        {
            st.creaders.lock.lock();
            const t = try std.Thread.spawn(.{}, Shared.ask, .{&sh});
            const finished = sh.waitCalls(calls + 1, 10_000);
            st.creaders.lock.unlock();
            t.join();
            calls += 1;
            try testing.expect(finished);
        }
        // A fix of another checkpoint: the table's index has to be read, which a merge may free
        // as soon as no snapshot from before it is live. The call waits for the lock, so it is
        // registered as a snapshot before it reads the index; then the entry is still served.
        const d: [32]u8 = @splat(0xf1);
        try testing.expect(try table.put(7, &d, "x"));
        {
            st.creaders.lock.lock();
            const t = try std.Thread.spawn(.{}, Shared.ask, .{&sh});
            const finished = sh.waitCalls(calls + 1, 100);
            st.creaders.lock.unlock();
            t.join();
            calls += 1;
            try testing.expect(!finished);
        }
        try testing.expectEqual(calls, sh.calls.load(.acquire));
        try testing.expectEqual(@as(u64, 0), sh.refused.load(.monotonic));
    }
    try testing.expectEqual(@as(u64, 4), svc.cp_fast_hits.load(.monotonic));
}
