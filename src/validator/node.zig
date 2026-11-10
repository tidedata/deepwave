//! Validator mode: `deepwave-validator run` (and `deepwave validator ...`, which hands over to it).
//! Wires the lanes of docs/VALIDATOR-DESIGN.md around the epoch lifecycle of this lane:
//!
//!   1. load the committee: a local test committee (`--localnet DIR --index N`, keys generated from
//!      the committee seed) or a validator.yaml (`--config FILE`, keys from files);
//!   2. the safety gate (gate.zig) decides before any key is opened, socket bound or peer dialed;
//!   3. the signer opens (lock file, watermarks), the metrics registry and overload state are built;
//!   4. the epoch manager opens the epoch store and starts the lane hooks (`Lanes`): val-authority's
//!      adapter and transaction validator, consensus, randomness. A lane whose entry point still
//!      returns `error.Unimplemented` is reported as a stub and skipped, so this binary runs the
//!      epoch lifecycle and the Validator API today and lights lanes up as they merge;
//!   5. the Validator gRPC server and the metrics endpoint start (`api`);
//!   6. a driver thread turns certified end-of-epoch checkpoints (iface.CertifiedSink) into epoch
//!      switches;
//!   7. SIGINT/SIGTERM stop everything in reverse order.
//!
//! This module never signs anything by itself: every signature goes through `Signer`, which only
//! opens with a license from the gate.
const std = @import("std");
const Io = std.Io;
const gate = @import("gate.zig");
const signer_mod = @import("signer.zig");
const iface = @import("iface.zig");
const keys = @import("keys/root.zig");
const epoch = @import("epoch/root.zig");
const api = @import("api/root.zig");
const authority = @import("authority/root.zig");
const randomness = @import("randomness/root.zig");
const consensus = @import("consensus");
const consensus_net = @import("consensus_net");
const protocol = @import("protocol");
const store = @import("store");
const serve = @import("serve");
const zui_node = @import("node");
const exec = @import("exec");
const core = @import("core");
const gpu = @import("gpu");
const reconfig = epoch.reconfig;
const manager = epoch.manager;
const Atomic = std.atomic.Value;

pub const Error = error{
    BadArguments,
    Refused,
    BadConfig,
    Io,
    OutOfMemory,
    Locked,
    NoCommittee,
    Startup,
};

pub const usage =
    \\deepwave-validator run (--localnet DIR --index N | --config FILE --chain-id HEX8) [options]
    \\  --localnet DIR         local test committee made by `deepwave-validator localnet` (keys generated from its seed)
    \\  --index N              this validator's member index in the committee (default 0)
    \\  --config FILE          validator.yaml (key files; allowed only with an unaudited build and flag)
    \\  --chain-id HEX8        chain identifier for --config (the gate refuses mainnet and testnet)
    \\  --db DIR               validator database (default: <localnet>/db-<index>, or db-path of the config)
    \\  --node-store DIR       a deepwave data directory (the one holding store/) to answer ObjectInfo,
    \\                         TransactionInfo, Checkpoint and system state from; its node/LOCK is taken, so a
    \\                         running deepwave must be stopped (use `deepwave-tool db-checkpoint` for a copy)
    \\  --protocol-digests FILE  Rust protocol config digests (tools/truth/validator-epoch protocol-digests.txt)
    \\  --exit-after-start     start, print the listening ports and exit cleanly (smoke test)
    \\  --sig-preverify MODE   on|off|auto: verify the user signatures of a block's or a submit request's
    \\                         transactions in parallel before the serial checks (same verdicts; default
    \\                         auto = on when the CPU pool has more than one lane and the batch has 2+)
    \\  --pool-threads N       lanes of the shared CPU worker pool (default 0: the hw plan's cores, cgroup quota and
    \\                         affinity counted; 1: no threads)
    \\  --sig-parallel MODE    auto|on|off: the signature engine (CPU pool, and the GPU when one passes its startup
    \\                         self-check) for --sig-preverify and its pre-steps; auto = on with more than 2 cores or
    \\                         such a GPU; off = --sig-preverify off and no GPU (default auto; verdicts identical)
    \\  --gpu MODE             off|auto|metal|cuda: accelerator for the Ed25519 and zkLogin pre-steps
    \\                         (default: $ZUI_GPU, unset = auto; verdicts identical either way)
    \\  --unaudited-validator-i-accept-the-risk
    \\
    \\deepwave-validator localnet DIR --validators N [--seed HEX64] [--base-port P] [--epoch-ms MS]
    \\                           writes localnet.json and validator-<i>.yaml
    \\
;

pub const Options = struct {
    localnet_dir: ?[]const u8 = null,
    index: u32 = 0,
    config_path: ?[]const u8 = null,
    chain_id: ?[]const u8 = null,
    db_path: ?[]const u8 = null,
    node_store: ?[]const u8 = null,
    protocol_digests: ?[]const u8 = null,
    exit_after_start: bool = false,
    unaudited_flag: bool = false,
    sig_preverify: authority.preverify.Mode = .auto,
    /// Lanes of the shared CPU pool (`core.pool`); 0 = one per CPU.
    pool_threads: u32 = 0,
    /// `--gpu`; null: ZUI_GPU, unset = auto (gpu.engine).
    gpu: ?gpu.Mode = null,
    /// `--sig-parallel`.
    sig_parallel: gpu.engine.Parallel = .auto,
};

pub fn parseOptions(args: []const []const u8) Error!Options {
    var o: Options = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const has_next = i + 1 < args.len;
        if (std.mem.eql(u8, a, "--localnet") and has_next) {
            i += 1;
            o.localnet_dir = args[i];
        } else if (std.mem.eql(u8, a, "--index") and has_next) {
            i += 1;
            o.index = std.fmt.parseInt(u32, args[i], 10) catch return error.BadArguments;
        } else if (std.mem.eql(u8, a, "--config") and has_next) {
            i += 1;
            o.config_path = args[i];
        } else if (std.mem.eql(u8, a, "--chain-id") and has_next) {
            i += 1;
            o.chain_id = args[i];
        } else if (std.mem.eql(u8, a, "--db") and has_next) {
            i += 1;
            o.db_path = args[i];
        } else if (std.mem.eql(u8, a, "--node-store") and has_next) {
            i += 1;
            o.node_store = args[i];
        } else if (std.mem.eql(u8, a, "--protocol-digests") and has_next) {
            i += 1;
            o.protocol_digests = args[i];
        } else if (std.mem.eql(u8, a, "--exit-after-start")) {
            o.exit_after_start = true;
        } else if (std.mem.eql(u8, a, "--sig-preverify") and has_next) {
            i += 1;
            o.sig_preverify = authority.preverify.Mode.parse(args[i]) orelse return error.BadArguments;
        } else if (std.mem.eql(u8, a, "--pool-threads") and has_next) {
            i += 1;
            o.pool_threads = std.fmt.parseInt(u32, args[i], 10) catch return error.BadArguments;
        } else if (std.mem.eql(u8, a, "--sig-parallel") and has_next) {
            i += 1;
            o.sig_parallel = gpu.engine.Parallel.parse(args[i]) orelse return error.BadArguments;
        } else if (std.mem.eql(u8, a, "--gpu") and has_next) {
            i += 1;
            o.gpu = gpu.Mode.parse(args[i]) orelse return error.BadArguments;
        } else if (std.mem.eql(u8, a, gate.unaudited_runtime_flag)) {
            o.unaudited_flag = true;
        } else return error.BadArguments;
    }
    if ((o.localnet_dir == null) == (o.config_path == null)) return error.BadArguments;
    if (o.config_path != null and o.chain_id == null) return error.BadArguments;
    return o;
}

// ------------------------------------------------------------------ the committee to run

/// Everything `prepare` decides before a key is opened.
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    license: gate.License,
    key_spec: signer_mod.KeySpec,
    db_dir: []const u8,
    chain_id: [8]u8,
    info: reconfig.EpochInfo,
    transition: manager.Transition,
    api_listen: []const u8,
    metrics_listen: []const u8,
    overload: keys.config.Overload = .{},
    unknown_keys: []const []const u8 = &.{},
    own_name: [96]u8,
    /// The node store behind `--node-store`, opened once by `prepare` (with the node's directory
    /// lock) and handed to the node by `create`.
    node_store: ?NodeStore = null,
    /// Rust's protocol config digests for the capability notification (`--protocol-digests`).
    digests: ?epoch.capabilities.DigestTable = null,

    pub fn deinit(p: *Prepared) void {
        if (p.node_store) |*n| n.close();
        p.node_store = null;
        if (p.digests) |*d| d.deinit();
        p.digests = null;
        p.arena.deinit();
    }
};

/// A deepwave node directory's store, opened under `<dir>/node/LOCK` (the lock deepwave and deepwave-tool
/// take), so it never has a second writer.
pub const NodeStore = struct {
    gpa: std.mem.Allocator,
    store: *store.Store,
    io: *store.RealIo,
    cfg: *store.Config,
    lock_fd: std.c.fd_t,
    path: []u8,

    pub fn close(n: *NodeStore) void {
        n.store.close() catch {};
        n.io.deinit();
        zui_node.dbcheckpoint.unlock(n.lock_fd);
        n.gpa.free(n.path);
        n.gpa.destroy(n.cfg);
    }
};

/// `Chain` of a chain identifier (the genesis checkpoint digest's first 4 bytes in hex).
pub fn chainOf(chain_id: *const [8]u8) protocol.Chain {
    if (std.mem.eql(u8, chain_id, gate.mainnet_chain_id)) return .mainnet;
    if (std.mem.eql(u8, chain_id, gate.testnet_chain_id)) return .testnet;
    return .unknown;
}

pub const StoreChain = enum { match, mismatch, unknown };

/// Whether the store's genesis checkpoint (sequence 0) is the one `chain_id` names. Unknown when
/// the store does not hold checkpoint 0 (restored from a snapshot, pruned).
pub fn storeChain(arena: std.mem.Allocator, st: *store.Store, chain_id: *const [8]u8) StoreChain {
    var snap = st.snapshot();
    defer snap.release();
    const rec = snap.checkpoint(0) orelse return .unknown;
    const cert = serve.render_checkpoint.Cert.parse(arena, rec.summary_cert) catch return .unknown;
    const d = cert.digest();
    const hex = std.fmt.bytesToHex(d[0..4], .lower);
    return if (std.mem.eql(u8, &hex, chain_id)) .match else .mismatch;
}

/// Opens `dir`'s store behind the node directory lock and checks that it belongs to `chain_id`.
/// `strict` (local test committees) also refuses a store whose chain cannot be established.
fn openNodeStore(gpa: std.mem.Allocator, io: Io, dir: []const u8, chain_id: *const [8]u8, strict: bool) Error!NodeStore {
    const lock_fd = zui_node.dbcheckpoint.lock(dir) catch |e| {
        if (e == error.NodeRunning) std.debug.print("deepwave-validator: {s} is in use by a deepwave or deepwave-tool (node/LOCK); stop it or use a db-checkpoint copy\n", .{dir});
        return if (e == error.NodeRunning) error.Locked else error.Io;
    };
    errdefer zui_node.dbcheckpoint.unlock(lock_fd);
    const path = std.fs.path.join(gpa, &.{ dir, "store" }) catch return error.OutOfMemory;
    errdefer gpa.free(path);
    Io.Dir.cwd().access(io, path, .{}) catch {
        std.debug.print("deepwave-validator: {s} has no store directory (--node-store takes a deepwave data directory)\n", .{dir});
        return error.BadConfig;
    };
    const cfg = gpa.create(store.Config) catch return error.OutOfMemory;
    errdefer gpa.destroy(cfg);
    cfg.* = .{ .dir = path, .codec = exec.objects.store_codec };
    const opened = store.openDir(gpa, io, cfg, .{}) catch return error.Io;
    var ns: NodeStore = .{ .gpa = gpa, .store = opened.store, .io = opened.io, .cfg = cfg, .lock_fd = lock_fd, .path = path };
    errdefer ns.close();
    var tmp = std.heap.ArenaAllocator.init(gpa);
    defer tmp.deinit();
    switch (storeChain(tmp.allocator(), ns.store, chain_id)) {
        .match => {},
        .mismatch => {
            std.debug.print("deepwave-validator: refused: the node store is not chain {s}\n", .{chain_id});
            return error.Refused;
        },
        .unknown => if (strict) {
            std.debug.print("deepwave-validator: refused: cannot establish which chain the node store belongs to (no checkpoint 0)\n", .{});
            return error.Refused;
        } else std.debug.print("deepwave-validator: warning: the node store holds no checkpoint 0; its chain is not checked\n", .{}),
    }
    return ns;
}

fn loadDigests(gpa: std.mem.Allocator, io: Io, path: ?[]const u8) Error!?epoch.capabilities.DigestTable {
    const p = path orelse return null;
    const text = (keys.fsutil.readAll(gpa, io, p, 1 << 20) catch return error.Io) orelse return error.BadConfig;
    defer gpa.free(text);
    return epoch.capabilities.DigestTable.parse(gpa, text) catch error.BadConfig;
}

fn sortedCommittee(arena: std.mem.Allocator, members: []const keys.localnet.Member) ![]reconfig.CommitteeMember {
    const out = try arena.alloc(reconfig.CommitteeMember, members.len);
    for (members, out) |m, *o| o.* = .{ .name = m.authority_pk, .stake = m.stake };
    std.mem.sort(reconfig.CommitteeMember, out, {}, struct {
        fn lt(_: void, a: reconfig.CommitteeMember, b: reconfig.CommitteeMember) bool {
            return std.mem.lessThan(u8, &a.name, &b.name);
        }
    }.lt);
    return out;
}

/// Reads the committee and runs the gate. Nothing is opened, bound or dialed here.
pub fn prepare(gpa: std.mem.Allocator, io: Io, o: Options) Error!Prepared {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();
    if (o.localnet_dir) |dir| {
        var ln = keys.localnet.Localnet.load(gpa, io, dir) catch return error.BadConfig;
        defer ln.deinit();
        const d = ln.desc;
        if (o.index >= d.members.len) return error.BadArguments;
        var addrs: std.ArrayList([]const u8) = .empty;
        for (d.members) |m| {
            try addrs.append(arena, try arena.dupe(u8, m.network_address));
            try addrs.append(arena, try arena.dupe(u8, m.consensus_address));
            try addrs.append(arena, try arena.dupe(u8, m.p2p_address));
            try addrs.append(arena, try arena.dupe(u8, m.metrics_address));
        }
        const decision = gate.decide(.{ .chain_id = &d.chain_id, .addresses = addrs.items, .key_source = .generated, .unaudited_flag = o.unaudited_flag });
        const lic = switch (decision) {
            .allowed => |l| l,
            .refused => |r| {
                std.debug.print("deepwave-validator: {s}\n", .{r.text()});
                return error.Refused;
            },
        };
        const me = d.members[o.index];
        const committee = try sortedCommittee(arena, d.members);
        var own: ?u32 = null;
        for (committee, 0..) |c, i| {
            if (std.mem.eql(u8, &c.name, &me.authority_pk)) own = @intCast(i);
        }
        const db = if (o.db_path) |p| try arena.dupe(u8, p) else try std.fmt.allocPrint(arena, "{s}/db-{d}", .{ dir, o.index });
        // a validator that switched epochs resumes in the epoch it reached, not epoch 0
        var info: reconfig.EpochInfo = .{ .epoch = 0, .protocol_version = d.protocol_version, .chain_id = d.chain_id, .epoch_start_timestamp_ms = 0, .committee = committee, .own_index = own };
        var transition: manager.Transition = .{ .epoch_duration_ms = d.epoch_duration_ms, .safe_mode = false, .from_epoch = 0 };
        if (manager.loadPersisted(arena, io, db, me.authority_pk, d.chain_id)) |p| {
            info = p.info;
            transition = p.transition;
        }
        var digests = try loadDigests(gpa, io, o.protocol_digests);
        errdefer if (digests) |*t| t.deinit();
        var ns: ?NodeStore = null;
        errdefer if (ns) |*n| n.close();
        if (o.node_store) |dir_path| ns = try openNodeStore(gpa, io, dir_path, &d.chain_id, true);
        return .{
            .arena = arena_state,
            .license = lic,
            .key_spec = .{ .generated = .{ .seed = d.seed, .index = o.index } },
            .db_dir = db,
            .chain_id = d.chain_id,
            .info = info,
            .transition = transition,
            .api_listen = try arena.dupe(u8, me.network_address),
            .metrics_listen = try arena.dupe(u8, me.metrics_address),
            .own_name = me.authority_pk,
            .node_store = ns,
            .digests = digests,
        };
    }
    // validator.yaml with key files: only an unaudited build with the runtime flag gets past the gate
    var cfg = keys.config.load(gpa, io, o.config_path.?) catch return error.BadConfig;
    defer cfg.deinit();
    const c = cfg.cfg;
    const addrs = c.addresses(arena) catch return error.OutOfMemory;
    const decision = gate.decide(.{ .chain_id = o.chain_id.?, .addresses = addrs, .key_source = .file, .unaudited_flag = o.unaudited_flag });
    const lic = switch (decision) {
        .allowed => |l| l,
        .refused => |r| {
            std.debug.print("deepwave-validator: {s}\n", .{r.text()});
            return error.Refused;
        },
    };
    // protocol, network, worker (the account key is never read by a validator, as in sui-node)
    const ktexts = [3]signer_mod.KeyText{
        try keyText(arena, c.protocol_key),
        try keyText(arena, c.network_key),
        try keyText(arena, c.worker_key),
    };
    // The epoch, committee and chain come from the node store's system state (`--node-store`).
    const store_dir = o.node_store orelse return error.NoCommittee;
    var chain: [8]u8 = undefined;
    for (o.chain_id.?, 0..) |ch, i| chain[i] = std.ascii.toLower(ch);
    const own = blk: {
        const text = switch (ktexts[0]) {
            .path => |p| (keys.fsutil.readAll(gpa, io, p, 4096) catch return error.Io) orelse return error.BadConfig,
            .value => |v| gpa.dupe(u8, v) catch return error.OutOfMemory,
        };
        defer {
            std.crypto.secureZero(u8, text);
            gpa.free(text);
        }
        var sk = keys.material.decodeAuthorityFile(text) catch return error.BadConfig;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&sk));
        break :blk sk.publicKey().toBytes();
    };
    var ns = try openNodeStore(gpa, io, store_dir, &chain, false);
    errdefer ns.close();
    var digests = try loadDigests(gpa, io, o.protocol_digests);
    errdefer if (digests) |*t| t.deinit();
    const st = blk: {
        var snap = ns.store.snapshot();
        defer snap.release();
        const live = serve.rpcindex.liveState(&snap) orelse return error.NoCommittee;
        // `infoFromState` copies the committee into the arena; the snapshot is released after it
        break :blk manager.infoFromState(arena, own, chain, live) catch return error.NoCommittee;
    };
    const derived = st;
    return .{
        .arena = arena_state,
        .license = lic,
        .key_spec = .{ .file = .{ .protocol = ktexts[0], .network = ktexts[1], .worker = ktexts[2] } },
        .db_dir = if (o.db_path) |p| try arena.dupe(u8, p) else try arena.dupe(u8, c.db_path),
        .chain_id = chain,
        .info = derived.info,
        .transition = derived.transition,
        .api_listen = try arena.dupe(u8, c.network_address),
        .metrics_listen = try arena.dupe(u8, c.metrics_address),
        .overload = c.overload,
        .unknown_keys = &.{},
        .own_name = own,
        .node_store = ns,
        .digests = digests,
    };
}

/// A key pair of validator.yaml, by path or in place. A missing protocol, network or worker key
/// is refused (sui-node would generate a random one, which can never match the on-chain keys).
fn keyText(arena: std.mem.Allocator, loc: ?keys.config.KeyLocation) Error!signer_mod.KeyText {
    const l = loc orelse return error.BadConfig;
    return switch (l) {
        .path => |p| .{ .path = arena.dupe(u8, p) catch return error.OutOfMemory },
        .value => |v| .{ .value = arena.dupe(u8, v) catch return error.OutOfMemory },
    };
}

// ------------------------------------------------------------------ lanes

pub const LaneStatus = enum { not_started, running, stub, failed };

pub const Lanes = struct {
    authority: LaneStatus = .not_started,
    consensus: LaneStatus = .not_started,
    randomness: LaneStatus = .not_started,
    checkpoints: LaneStatus = .not_started,
    jwk: LaneStatus = .not_started,
    /// val-authority's submitter once the adapter is real.
    submit: ?iface.ConsensusSubmit = null,
    verifier: ?consensus.iface.TransactionVerifier = null,
    /// val-authority's consensus adapter for the running epoch (owned; freed by `stop`).
    adapter: ?*authority.Adapter = null,

    fn mapStub(e: anyerror) LaneStatus {
        return if (e == error.Unimplemented) .stub else .failed;
    }

    /// Starts every lane that has a real entry point for the epoch in `st`.
    pub fn start(l: *Lanes, n: *ValidatorNode, st: *reconfig.EpochState) void {
        _ = st;
        // val-authority: the consensus adapter (ConsensusSubmit and TransactionSource) is real and
        // owned here for the epoch. The block transaction validator (TxValidator.init) needs the
        // epoch's params, protocol config, checker env, EpochControl and the Authority's reason
        // cache; those are built by the integration step, so the lane
        // reports .stub until then and `verifier` stays null.
        if (l.adapter == null) {
            if (n.gpa.create(authority.Adapter)) |a| {
                a.* = authority.Adapter.init(n.gpa, .{});
                l.adapter = a;
            } else |_| l.authority = .failed;
        }
        if (l.adapter) |a| {
            l.submit = a.submitter();
            l.authority = .stub;
        }
        // consensus: needs the adapter and the verifier; the lane's start() takes everything
        // through consensus.iface seams (the options are built where their pieces exist)
        l.consensus = .stub;
        // randomness: randomness.Manager.create needs the epoch committee's DKG params and the
        // validator's BLS secret; wired with the consensus integration, .stub until then.
        l.randomness = .stub;
        // checkpoints and JWK are driven by the handler and a timer, not at epoch start
        l.checkpoints = .stub;
        l.jwk = .stub;
        n.lane_report_dirty = true;
    }

    pub fn stop(l: *Lanes) void {
        if (l.adapter) |a| {
            const gpa = a.gpa;
            a.deinit();
            gpa.destroy(a);
        }
        l.* = .{};
    }

    pub fn write(l: *const Lanes, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("lanes: authority={s} consensus={s} randomness={s} checkpoints={s} jwk={s}\n", .{ @tagName(l.authority), @tagName(l.consensus), @tagName(l.randomness), @tagName(l.checkpoints), @tagName(l.jwk) });
    }
};

/// `consensus.iface.BlockSigner` over the signer: the only way consensus signs a block.
pub fn blockSigner(sg: *signer_mod.Signer) consensus.iface.BlockSigner {
    const V = struct {
        fn sign(ctx: *anyopaque, ep: u64, round: u32, message: []const u8) consensus.iface.BlockSigner.SignError![64]u8 {
            const s: *signer_mod.Signer = @ptrCast(@alignCast(ctx));
            return s.signBlock(ep, round, message) catch |e| switch (e) {
                error.AlreadySigned => error.AlreadySigned,
                error.Io => error.Io,
                error.Unimplemented => error.Unimplemented,
                error.NoLicense, error.Locked, error.Refused => error.Refused,
            };
        }
        const vt: consensus.iface.BlockSigner.VTable = .{ .sign_block = sign };
    };
    return .{ .ctx = sg, .vtable = &V.vt };
}

// ------------------------------------------------------------------ the node

pub const ValidatorNode = struct {
    gpa: std.mem.Allocator,
    io: Io,
    prep: Prepared,
    signer: *signer_mod.Signer,
    reg: *api.metrics.Registry,
    overload: api.overload.Info = .{},
    epoch_now: Atomic(u64) = .init(0),
    mgr: manager.EpochManager,
    driver: epoch.driver.Driver,
    lanes: Lanes = .{},
    lane_report_dirty: bool = false,
    backend: api.NodeBackend,
    api_server: ?*api.Server = null,
    metrics_server: ?*api.MetricsServer = null,
    announcer: epoch.announce.Announcer,
    stopping: Atomic(bool) = .init(false),
    /// Start of the previous epoch (for the measured `epoch_total_duration`).
    last_epoch_start_ms: u64 = 0,
    /// The API server could not drain at shutdown: connection threads may still use the backend,
    /// so the store, signer and registry are left open until the process exits.
    api_leaked: bool = false,
    /// Signature pre-verification for the Authority's intake paths (`--sig-preverify`); the
    /// integration step that builds the Authority per epoch passes it as `Config.sig_preverify`.
    sig_preverify: authority.preverify.Config = .{},
    /// The stage's batch pre-steps (`installPresteps`): zkLogin Groth16 batch and Ed25519 batch
    /// through `accel` (the signature engine's, owned by it). Null / undefined until installed.
    accel: ?*gpu.Accel = null,
    presteps: authority.presteps.Set = undefined,

    const Self = @This();

    /// Takes over `prepared` (its node store included) on success; on failure the caller still owns it.
    pub fn create(gpa: std.mem.Allocator, io: Io, prepared: Prepared) Error!*Self {
        const self = gpa.create(Self) catch return error.OutOfMemory;
        errdefer gpa.destroy(self);
        self.* = undefined;
        self.gpa = gpa;
        self.io = io;
        self.prep = prepared;
        self.overload = .{};
        self.epoch_now = .init(prepared.info.epoch);
        self.lanes = .{};
        self.lane_report_dirty = false;
        self.api_server = null;
        self.last_epoch_start_ms = 0;
        self.api_leaked = false;
        self.sig_preverify = .{};
        self.accel = null;
        self.metrics_server = null;
        self.stopping = .init(false);
        // gate passed: now the keys open
        self.signer = signer_mod.Signer.open(gpa, io, &self.prep.license, self.prep.db_dir, self.prep.key_spec) catch |e| return switch (e) {
            error.Locked => error.Locked,
            error.Refused, error.NoLicense => error.Refused,
            else => error.Io,
        };
        errdefer self.signer.close();
        const pubs = self.signer.publicKeys() catch return error.Io;
        if (!std.mem.eql(u8, &pubs.authority, &self.prep.own_name)) return error.Refused;
        self.reg = gpa.create(api.metrics.Registry) catch return error.OutOfMemory;
        errdefer gpa.destroy(self.reg);
        self.reg.* = api.metrics.Registry.init(io);
        self.backend = .{ .store = if (self.prep.node_store) |h| h.store else null, .signer = self.signer, .epoch = &self.epoch_now };
        self.announcer = .{ .authority = self.prep.own_name, .chain = chainOf(&self.prep.chain_id), .table = if (self.prep.digests) |*t| t else null };
        self.mgr = manager.EpochManager.init(gpa, io, self.prep.db_dir, self.prep.own_name, self.prep.chain_id, .{ .ctx = self, .vtable = &components_vt });
        self.driver = .{ .gpa = gpa, .io = io, .mgr = &self.mgr };
        // after a switch the next epoch's parameters come from the node store's system state
        if (self.prep.node_store != null) self.driver.params = .{ .ctx = self, .get = paramsGet };
        return self;
    }

    pub fn destroy(self: *Self) void {
        self.shutdown();
        self.mgr.deinit();
        if (self.api_leaked) {
            // a call outlived the drain wait: it may still read the store, signer and registry
            std.debug.print("deepwave-validator: a Validator API call did not finish at shutdown; leaving the store and keys open until exit\n", .{});
            return;
        }
        self.signer.close();
        self.gpa.destroy(self.reg);
        self.prep.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// With the stage not off: installs the zkLogin and Ed25519 pre-steps on the signature
    /// engine's accelerator (`gpu.engine`: its pool, its self-checked GPU and dispatch table) and
    /// turns on the zk proof cache and, when the Ed25519 step can run, the Ed25519 verified-
    /// signature cache (both verdict-neutral). Without an engine (or one that is off) the stage
    /// runs without pre-steps. Call after setting `sig_preverify.mode`, before `start`.
    pub fn installPresteps(self: *Self, eng: ?*gpu.engine.Engine) void {
        if (self.sig_preverify.mode == .off or self.accel != null) return;
        const e = eng orelse return;
        if (!e.on) return;
        self.accel = &e.accel;
        self.presteps.init(self.io, self.gpa, &e.accel);
        self.presteps.enableUsed();
        self.sig_preverify.pre_steps = self.presteps.slice();
    }

    pub fn certifiedSink(self: *Self) iface.CertifiedSink {
        return self.driver.certifiedSink();
    }

    /// Opens the first epoch, then the API, the metrics endpoint and the epoch driver.
    pub fn start(self: *Self) Error!void {
        self.mgr.start(self.prep.info, self.prep.transition) catch |e| {
            std.debug.print("deepwave-validator: epoch start failed: {s}\n", .{@errorName(e)});
            return error.Startup;
        };
        self.api_server = api.Server.start(self.gpa, self.io, self.prep.api_listen, self.backend.asBackend(), self.reg, &self.epoch_now, .{ .tls_seed = self.signer.networkSeed() }) catch return error.Startup;
        self.metrics_server = api.MetricsServer.start(self.gpa, self.io, self.prep.metrics_listen, self.reg) catch return error.Startup;
        self.driver.start() catch return error.Startup;
    }

    pub fn shutdown(self: *Self) void {
        if (self.stopping.swap(true, .acq_rel)) return;
        self.driver.stop();
        if (self.metrics_server) |m| m.stop();
        self.metrics_server = null;
        if (self.api_server) |a| {
            if (!a.stop()) self.api_leaked = true;
        }
        self.api_server = null;
    }

    // -------------------------------------------------------------- epoch components

    fn stopComponents(ctx: *anyopaque, ep: u64) void {
        _ = ep;
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.lanes.stop();
    }

    fn startComponents(ctx: *anyopaque, st: *reconfig.EpochState, t: *const manager.Transition) error{ComponentFailed}!void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.epoch_now.store(st.info.epoch, .release);
        self.reg.gauge("current_epoch").set(@intCast(st.info.epoch));
        self.reg.gauge("sui_current_protocol_version").set(@intCast(st.info.protocol_version));
        self.reg.gauge("zui_epoch_start_timestamp_ms").set(@intCast(st.info.epoch_start_timestamp_ms));
        // Rust sets the measured duration of the epoch that just ended
        if (self.last_epoch_start_ms != 0 and st.info.epoch_start_timestamp_ms >= self.last_epoch_start_ms) {
            self.reg.gauge("epoch_total_duration").set(@intCast(st.info.epoch_start_timestamp_ms - self.last_epoch_start_ms));
        }
        self.last_epoch_start_ms = st.info.epoch_start_timestamp_ms;
        self.reg.gauge("zui_epoch_reconfig_state").set(@intFromEnum(st.reconfig));
        self.reg.gauge("zui_epoch_end_of_publish_stake").set(@intCast(st.eop_stake));
        self.reg.gauge("zui_epoch_safe_mode").set(@intFromBool(t.safe_mode));
        if (t.from_epoch != 0 or st.info.epoch != 0) self.reg.counter("zui_epoch_switches_total").inc();
        self.lanes.start(self, st);
        // vote for the protocol version this binary supports, once the adapter is real
        if (self.lanes.submit) |sub| {
            var arena = std.heap.ArenaAllocator.init(self.gpa);
            defer arena.deinit();
            var tracking: [8]u8 = undefined;
            self.io.random(&tracking);
            const now_ms: u64 = @intCast(@divTrunc(Io.Clock.real.now(self.io).toNanoseconds(), std.time.ns_per_ms));
            self.announcer.announce(arena.allocator(), sub, tracking, now_ms, st.info.protocol_version) catch {};
        }
    }

    /// `driver.ParamsSource`: waits (up to 10 s, on the driver thread) for the node store to execute
    /// the epoch's ChangeEpoch, then reads the new system parameters.
    fn paramsGet(ctx: *anyopaque, next_epoch: u64) ?epoch.driver.Params {
        const self: *Self = @ptrCast(@alignCast(ctx));
        const h = self.prep.node_store orelse return null;
        var waited: u32 = 0;
        while (waited < 200 and !self.stopping.load(.acquire)) : (waited += 1) {
            {
                var snap = h.store.snapshot();
                defer snap.release();
                if (serve.rpcindex.liveState(&snap)) |live| {
                    if (serve.sysstate.summary(live)) |sum| {
                        if (sum.epoch >= next_epoch) {
                            const p = serve.sysstate.epochParams(live) catch return null;
                            return .{ .epoch_duration_ms = p.epoch_duration_ms, .safe_mode = p.safe_mode };
                        }
                    } else |_| {}
                }
            }
            serve.h2.sock.sleepMs(50);
        }
        return null;
    }

    const components_vt: manager.Components.VTable = .{ .stop = stopComponents, .start = startComponents };

    // -------------------------------------------------------------- reporting

    pub fn describe(self: *const Self, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const cur = self.mgr.current;
        try w.print("deepwave-validator: chain {s}, {s} mode, epoch {d}, protocol {d}, committee {d}", .{
            &self.prep.chain_id,
            @tagName(self.prep.license.mode),
            if (cur) |c| c.info.epoch else 0,
            if (cur) |c| c.info.protocol_version else 0,
            if (cur) |c| c.info.committee.len else 0,
        });
        if (cur) |c| if (c.info.own_index) |i| try w.print(", index {d}", .{i});
        try w.writeAll("\n");
        if (self.api_server) |a| try w.print("validator api: 127.0.0.1:{d}\n", .{a.port()});
        if (self.metrics_server) |m| try w.print("metrics: 127.0.0.1:{d}\n", .{m.port()});
        try w.print("sig preverify: {s}, cpu pool lanes {d}\n", .{ @tagName(self.sig_preverify.mode), if (self.sig_preverify.poolOf()) |p| p.lanes() else 1 });
        if (self.accel) |a| {
            try w.print("sig pre-steps: zklogin, ed25519; gpu {s} ({d} devices)\n", .{ a.name(), a.deviceCount() });
        } else try w.writeAll("sig pre-steps: none\n");
        try self.lanes.write(w);
    }
};

// ------------------------------------------------------------------ signals and the main loop

var stop_flag: Atomic(bool) = .init(false);

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    stop_flag.store(true, .release);
}

fn installSignals() void {
    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onSignal }, .mask = std.posix.sigemptyset(), .flags = std.posix.SA.RESTART };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
}

pub fn run(gpa: std.mem.Allocator, io: Io, args: []const []const u8) u8 {
    const opts = parseOptions(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const prep = prepare(gpa, io, opts) catch |e| {
        std.debug.print("deepwave-validator: {s}\n", .{@errorName(e)});
        return if (e == error.Refused) 1 else 2;
    };
    // The signature engine: the shared CPU pool from the hw plan (ZUI_HW; --pool-threads wins),
    // the GPU when one passes its self-check, the dispatch table between them.
    var spec: core.hw.Spec = .{};
    core.hw.parseEnv(&spec, null) catch {};
    if (opts.pool_threads != 0) spec.threads = opts.pool_threads;
    const machine = core.hw.detect(null);
    const plan = core.hw.plan(&machine, &spec);
    const eng = gpu.engine.install(io, gpa, .{ .parallel = opts.sig_parallel, .gpu = opts.gpu, .plan = &plan });
    defer gpu.engine.uninstall();
    var prep_mut = prep;
    const node = ValidatorNode.create(gpa, io, prep_mut) catch |e| {
        std.debug.print("deepwave-validator: cannot open: {s}\n", .{@errorName(e)});
        prep_mut.deinit();
        return 2;
    };
    defer node.destroy();
    node.sig_preverify.mode = if (opts.sig_parallel == .off) .off else opts.sig_preverify;
    node.installPresteps(eng);
    node.start() catch |e| {
        std.debug.print("deepwave-validator: start failed: {s}\n", .{@errorName(e)});
        return 2;
    };
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    node.describe(&w) catch {};
    std.debug.print("{s}", .{w.buffered()});
    if (opts.exit_after_start) return 0;
    installSignals();
    while (!stop_flag.load(.acquire)) {
        var ts: std.c.timespec = .{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&ts, &ts);
    }
    std.debug.print("deepwave-validator: stopping\n", .{});
    return 0;
}

// ------------------------------------------------------------------ tests

test "options require exactly one committee source" {
    try std.testing.expectError(error.BadArguments, parseOptions(&.{}));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "--localnet", "d", "--config", "c" }));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "--config", "c" }));
    const o = try parseOptions(&.{ "--localnet", "d", "--index", "2", "--exit-after-start" });
    try std.testing.expectEqual(@as(u32, 2), o.index);
    try std.testing.expect(o.exit_after_start);
    try std.testing.expectEqual(authority.preverify.Mode.auto, o.sig_preverify);
    const o2 = try parseOptions(&.{ "--localnet", "d", "--sig-preverify", "off", "--pool-threads", "4" });
    try std.testing.expectEqual(authority.preverify.Mode.off, o2.sig_preverify);
    try std.testing.expectEqual(@as(u32, 4), o2.pool_threads);
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "--localnet", "d", "--sig-preverify", "maybe" }));
    try std.testing.expect(o2.gpu == null);
    const o3 = try parseOptions(&.{ "--localnet", "d", "--gpu", "auto" });
    try std.testing.expectEqual(gpu.Mode.auto, o3.gpu.?);
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "--localnet", "d", "--gpu", "vulkan" }));
    const o4 = try parseOptions(&.{ "--localnet", "d", "--sig-parallel", "off" });
    try std.testing.expectEqual(gpu.engine.Parallel.off, o4.sig_parallel);
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "--localnet", "d", "--sig-parallel", "maybe" }));
}

fn tmpDirPath(tmp: *std.testing.TmpDir, buf: []u8) ![]const u8 {
    return buf[0..try tmp.dir.realPath(std.testing.io, buf)];
}

test "a local test committee starts, answers the API and the metrics endpoint, and stops" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&tmp, &pb);
    const seed: [32]u8 = @splat(5);
    // ports of a localnet come from its description: pick a free-ish base per test run
    try keys.localnet.Localnet.generate(std.testing.allocator, std.testing.io, dir, 4, seed, .{ .base_port = 0 });
    var prep = try prepare(std.testing.allocator, std.testing.io, .{ .localnet_dir = dir, .index = 1 });
    // point the listeners at port 0 so the test never collides with another process
    prep.api_listen = "127.0.0.1:0";
    prep.metrics_listen = "127.0.0.1:0";
    try std.testing.expectEqual(gate.Mode.local_test, prep.license.mode);
    try std.testing.expectEqual(@as(usize, 4), prep.info.committee.len);
    try std.testing.expect(prep.info.own_index != null);
    const n = try ValidatorNode.create(std.testing.allocator, std.testing.io, prep);
    defer n.destroy();
    try n.start();
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try n.describe(&out.writer);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "local_test mode, epoch 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "authority=stub") != null);
    // the epoch metrics were set by the component start
    var m: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer m.deinit();
    try n.reg.render(&m.writer);
    try std.testing.expect(std.mem.indexOf(u8, m.written(), "sui_current_protocol_version 141\n") != null);
    // a second process on the same database is refused by the signer lock
    var prep2 = try prepare(std.testing.allocator, std.testing.io, .{ .localnet_dir = dir, .index = 1 });
    defer prep2.deinit();
    try std.testing.expectError(error.Locked, ValidatorNode.create(std.testing.allocator, std.testing.io, prep2));
}

test "a localnet on mainnet's chain id is refused before any key opens" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&tmp, &pb);
    try keys.localnet.Localnet.generate(std.testing.allocator, std.testing.io, dir, 4, @splat(1), .{});
    // rewrite the committee file with a public address: the gate refuses
    var ln = try keys.localnet.Localnet.load(std.testing.allocator, std.testing.io, dir);
    defer ln.deinit();
    var members = try std.testing.allocator.dupe(keys.localnet.Member, ln.desc.members);
    defer std.testing.allocator.free(members);
    members[2].network_address = "/ip4/8.8.8.8/tcp/8080";
    var d = ln.desc;
    d.members = members;
    const json = try keys.localnet.renderJson(std.testing.allocator, &d);
    defer std.testing.allocator.free(json);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    try keys.fsutil.writeAtomic(std.testing.io, try std.fmt.bufPrint(&path_buf, "{s}/localnet.json", .{dir}), json);
    try std.testing.expectError(error.Refused, prepare(std.testing.allocator, std.testing.io, .{ .localnet_dir = dir, .index = 0 }));
}

test "a validator that switched epochs resumes in that epoch after a restart" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&tmp, &pb);
    try keys.localnet.Localnet.generate(std.testing.allocator, std.testing.io, dir, 4, @splat(6), .{ .base_port = 0 });
    {
        var prep = try prepare(std.testing.allocator, std.testing.io, .{ .localnet_dir = dir, .index = 2 });
        prep.api_listen = "127.0.0.1:0";
        prep.metrics_listen = "127.0.0.1:0";
        const n = try ValidatorNode.create(std.testing.allocator, std.testing.io, prep);
        defer n.destroy();
        try n.start();
        var info = n.mgr.current.?.info;
        // the committee slice belongs to the epoch being closed: switch with a copy
        const members = try std.testing.allocator.dupe(reconfig.CommitteeMember, info.committee);
        defer std.testing.allocator.free(members);
        info.committee = members;
        info.epoch = 1;
        info.epoch_start_timestamp_ms = 5_000;
        try n.mgr.switchEpoch(info, .{ .epoch_duration_ms = 77_000, .safe_mode = false, .from_epoch = 0 });
        try std.testing.expectEqual(@as(u64, 1), n.epoch_now.load(.acquire));
        // epoch 1's blocks are signed from round 0
        _ = try n.signer.signBlock(1, 0, "block");
    }
    var prep2 = try prepare(std.testing.allocator, std.testing.io, .{ .localnet_dir = dir, .index = 2 });
    prep2.api_listen = "127.0.0.1:0";
    prep2.metrics_listen = "127.0.0.1:0";
    try std.testing.expectEqual(@as(u64, 1), prep2.info.epoch);
    try std.testing.expectEqual(@as(u64, 77_000), prep2.transition.epoch_duration_ms);
    const n2 = try ValidatorNode.create(std.testing.allocator, std.testing.io, prep2);
    defer n2.destroy();
    try n2.start();
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try n2.describe(&out.writer);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "local_test mode, epoch 1") != null);
    _ = try n2.signer.signBlock(1, 1, "block 2");
}

test "an unknown chain on the node store is refused for local committees, mismatches always" {
    const chain: [8]u8 = "0badc0de".*;
    try std.testing.expectEqual(protocol.Chain.mainnet, chainOf(gate.mainnet_chain_id));
    try std.testing.expectEqual(protocol.Chain.unknown, chainOf(&chain));
}
