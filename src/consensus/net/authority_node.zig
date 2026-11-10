//! consensus_core::ConsensusAuthority at mainnet-v1.83.1 (`authority_node.rs` + `core_thread.rs`
//! + `leader_timeout.rs` + `commit_observer.rs`): one consensus instance for one epoch.
//! Owner lane: val-consensus-net.
//!
//! Threads (docs/VALIDATOR-DESIGN.md 7):
//! - the core thread owns the Core (through `CoreDriver`), DagState and all consensus store
//!   writes. Its input is a bounded queue of events (verified block batches, certified commits,
//!   new-transaction signals, propagation delay, the own-block-sync result); after every event
//!   it flushes the store, publishes a round snapshot, streams a newly proposed block to the
//!   broadcast ring, hands the missing ancestors to the synchronizer and pushes committed
//!   sub-dags to the CommitSink (retrying when the sink is full). A timer wakes it for the
//!   leader timeout and for the min-round-delay proposal retry.
//! - ingress verification runs on the threads that receive blocks (one subscriber per peer,
//!   the synchronizer's fetch workers, the commit syncer), see shared.zig.
//! - the gRPC server (grpc.zig) has one thread per connection and per call, serving from the
//!   store and the published snapshot, never from DagState.
//! - the synchronizer, commit syncer, subscriber and round prober (sync.zig).
//!
//! The core is reached only through `CoreDriver`, so the network side is testable without the
//! consensus core and the real `consensus.Core` plugs in through `consensusCoreDriver`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const types = consensus.types;
const iface = consensus.iface;
const Store = consensus.store.Store;
const grpc = @import("grpc.zig");
const tls = @import("tls.zig");
const addr = @import("addr.zig");
const service = @import("service.zig");
const sync = @import("sync.zig");
const shared_mod = @import("shared.zig");
const peers_mod = @import("peers.zig");
const mon = @import("mon.zig");
const bc = @import("broadcast.zig");
const Shared = shared_mod.Shared;

const log = std.log.scoped(.consensus_node);

pub const Error = error{ Unimplemented, Refused, Io, OutOfMemory, StoreFailure, BadConfig };

/// What the node needs from the consensus core. All calls come from the core thread.
pub const CoreDriver = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const CoreError = consensus.errors.Error;

    pub const VTable = struct {
        /// `Core::new` + recovery; re-emitted commits after the sink's processed index come in `out`.
        recover: *const fn (ctx: *anyopaque, arena: Allocator, out: *consensus.core.Output) CoreError!void,
        /// Verified peer blocks with our own fast-path reject votes per block.
        add_blocks: *const fn (ctx: *anyopaque, arena: Allocator, blocks: []const types.VerifiedBlock, rejects: []const []const types.TransactionIndex, out: *consensus.core.Output) CoreError!void,
        /// The first `certifier_rejects.len` blocks are the certifying blocks, with our reject votes.
        add_certified_commits: *const fn (ctx: *anyopaque, arena: Allocator, commits: []const types.TrustedCommit, blocks: []const types.VerifiedBlock, certifier_rejects: []const []const types.TransactionIndex, out: *consensus.core.Output) CoreError!void,
        try_propose: *const fn (ctx: *anyopaque, arena: Allocator, force: bool, signals: consensus.core.Signals, out: *consensus.core.Output) CoreError!void,
        set_last_known_proposed_round: *const fn (ctx: *anyopaque, round: types.Round) void,
        /// Writes buffered blocks, commits and commit info to the store (one group).
        flush: *const fn (ctx: *anyopaque) CoreError!void,
        /// Highest accepted round per authority, our last proposed round, last commit index.
        snapshot: *const fn (ctx: *anyopaque, accepted: []types.Round, last_proposed: *types.Round, commit_index: *types.CommitIndex) void,
        /// DagState's GC round (optional; 0 when the driver does not track it).
        gc_round: ?*const fn (ctx: *anyopaque) types.Round = null,
        /// Refs the block manager still waits for.
        missing_blocks: *const fn (ctx: *anyopaque, out: []types.BlockRef) usize,
        deinit: *const fn (ctx: *anyopaque) void,
    };
};

pub const Options = struct {
    context: *const consensus.Context,
    /// `<db>/consensus` (the per-epoch subdirectory is chosen here).
    db_dir: []const u8,
    /// Overrides the committee address of our own authority (tests with ephemeral ports).
    listen_address: ?[]const u8 = null,
    /// Ed25519 network key seed for TLS (from validator/keys; network key only, never the
    /// protocol key).
    network_key_seed: *const [32]u8,
    signer: iface.BlockSigner,
    tx_verifier: iface.TransactionVerifier,
    tx_source: iface.TransactionSource,
    commit_sink: iface.CommitSink,
    /// Start in observe-only mode: follow and commit, never propose or sign (shadow validator).
    observe_only: bool = false,
    /// Safety: by default the authority refuses a committee (or listen address) that is not
    /// loopback/private, so it cannot reach a real network by accident. The validator sets this
    /// only when its gate (validator/gate.zig) returned `Mode.unaudited`; never otherwise.
    allow_non_local: bool = false,
    /// Authorities this process started before this one (0 on the first boot). Rust syncs the
    /// last known own block only when it is 0; later boots (epoch changes) propose at once.
    boot_counter: u64 = 0,
    verify_tiles: u8 = 2,
    /// Tests: an in-memory store and a driver replace LogStore and consensus.Core.
    store_override: ?Store = null,
    driver_override: ?CoreDriver = null,
    verifier_override: ?shared_mod.VerifierHook = null,
    grpc_config: ?grpc.Config = null,
};

/// The store behind one lock, so the network handlers can read while the core thread writes
/// regardless of the engine's own concurrency rules.
const LockedStore = struct {
    inner: Store,
    mu: mon.Monitor,
    /// The LogStore behind `inner` (not set for a test store): evicted blocks are read from disk.
    log: ?*consensus.store.LogStore = null,

    const E = consensus.errors.Error;

    fn store(l: *LockedStore) Store {
        return .{ .ctx = l, .vtable = &vt };
    }
    const vt: Store.VTable = .{
        .write = write,
        .read_blocks = readBlocks,
        .contains_blocks = containsBlocks,
        .scan_blocks_by_author = scanByAuthor,
        .scan_last_blocks_by_author = scanLast,
        .read_last_commit = readLastCommit,
        .scan_commits = scanCommits,
        .read_commit_votes = readCommitVotes,
        .read_last_commit_info = readLastCommitInfo,
        .read_last_finalized_commit = readLastFinalized,
        .read_rejected_transactions = readRejected,
    };
    fn self(ctx: *anyopaque) *LockedStore {
        return @ptrCast(@alignCast(ctx));
    }
    fn write(ctx: *anyopaque, b: *const consensus.store.WriteBatch) E!void {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        return l.inner.vtable.write(l.inner.ctx, b);
    }
    fn readBlocks(ctx: *anyopaque, refs: []const types.BlockRef, out: []?types.VerifiedBlock) E!void {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        return l.inner.vtable.read_blocks(l.inner.ctx, refs, out);
    }
    /// For the network handlers: blocks deep-copied into `arena` under the lock, so a later
    /// eviction (LogStore frees blocks below its retained rounds on write) cannot free them while
    /// a response is being written. Blocks already evicted from memory come from the log on disk.
    fn readBlocksCopy(ctx: *anyopaque, arena: Allocator, refs: []const types.BlockRef, out: []?types.VerifiedBlock) E!void {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        try l.inner.vtable.read_blocks(l.inner.ctx, refs, out);
        for (out, refs) |*o, ref| {
            if (o.*) |*b| {
                o.* = try consensus.digest.cloneVerified(arena, b);
            } else if (l.log) |ls| {
                o.* = try ls.readBlockFromDisk(arena, ref);
            }
        }
    }
    fn cloneAll(a: Allocator, blocks: []types.VerifiedBlock) E![]types.VerifiedBlock {
        for (blocks) |*b| b.* = try consensus.digest.cloneVerified(a, b);
        return blocks;
    }
    fn containsBlocks(ctx: *anyopaque, refs: []const types.BlockRef, out: []bool) E!void {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        return l.inner.vtable.contains_blocks(l.inner.ctx, refs, out);
    }
    fn scanByAuthor(ctx: *anyopaque, a: Allocator, author: types.AuthorityIndex, s: types.Round, e: types.Round, limit: usize) E![]types.VerifiedBlock {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        return cloneAll(a, try l.inner.vtable.scan_blocks_by_author(l.inner.ctx, a, author, s, e, limit));
    }
    fn scanLast(ctx: *anyopaque, a: Allocator, author: types.AuthorityIndex, n: u64, before: ?types.Round) E![]types.VerifiedBlock {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        return cloneAll(a, try l.inner.vtable.scan_last_blocks_by_author(l.inner.ctx, a, author, n, before));
    }
    fn readLastCommit(ctx: *anyopaque) E!?types.TrustedCommit {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        return l.inner.vtable.read_last_commit(l.inner.ctx);
    }
    fn scanCommits(ctx: *anyopaque, a: Allocator, r: types.CommitRange) E![]types.TrustedCommit {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        return l.inner.vtable.scan_commits(l.inner.ctx, a, r);
    }
    fn readCommitVotes(ctx: *anyopaque, a: Allocator, i: types.CommitIndex) E![]types.BlockRef {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        return l.inner.vtable.read_commit_votes(l.inner.ctx, a, i);
    }
    fn readLastCommitInfo(ctx: *anyopaque) E!?consensus.store.CommitInfoEntry {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        return l.inner.vtable.read_last_commit_info(l.inner.ctx);
    }
    fn readLastFinalized(ctx: *anyopaque) E!?types.CommitRef {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        return l.inner.vtable.read_last_finalized_commit(l.inner.ctx);
    }
    fn readRejected(ctx: *anyopaque, c: types.CommitRef) E!?[]const types.RejectedInBlock {
        const l = self(ctx);
        l.mu.lock();
        defer l.mu.unlock();
        return l.inner.vtable.read_rejected_transactions(l.inner.ctx, c);
    }
};

/// Finalized sub-dags waiting for the CommitSink (it was full). Each item owns its memory
/// (`Finalized.arena`) and is freed once the sink took it; `items` itself is a gpa slice.
const PendingCommits = struct {
    items: []consensus.commit_finalizer.Finalized,
    next: usize = 0,
};

pub const ConsensusAuthority = struct {
    gpa: Allocator,
    io: Io,
    options: Options,
    shared: *Shared,
    peers: *peers_mod.Peers,
    handlers: *service.Handlers,
    locked: *LockedStore,
    log_store: ?*consensus.store.LogStore = null,
    identity: *tls.Identity,
    peer_keys: []const [32]u8,
    server: ?*grpc.Server = null,
    driver: CoreDriver,
    core_thread: ?std.Thread = null,
    own_sync_thread: ?std.Thread = null,
    subscriber: ?*sync.Subscriber = null,
    synchronizer: ?*sync.Synchronizer = null,
    commit_syncer: ?*sync.CommitSyncer = null,
    prober: ?*sync.RoundProber = null,
    pending: std.ArrayList(PendingCommits) = .empty,
    /// This epoch's genesis block refs (the block verifier borrows them).
    genesis_refs: []types.BlockRef = &.{},
    /// Written by the core thread before `startup_failed` is set (release); read after (acquire).
    startup_error: ?anyerror = null,
    startup_failed: std.atomic.Value(bool) = .init(false),
    started: std.atomic.Value(bool) = .init(false),

    /// Recovers state, starts the server and the core thread. Returns after the listener is up
    /// and the core has recovered.
    pub fn start(gpa: Allocator, io: Io, options: Options) Error!*ConsensusAuthority {
        const ctx = options.context;
        // Refuse real-network committees before anything is opened (see Options.allow_non_local).
        if (!options.allow_non_local) {
            for (ctx.committee.authorities) |au| {
                const hp = addr.parse(au.address) catch return error.BadConfig;
                if (!addr.isLocalOrPrivate(hp.host)) return error.Refused;
            }
            if (options.listen_address) |t| {
                const hp = addr.parse(t) catch return error.BadConfig;
                if (!addr.isLocalOrPrivate(hp.host)) return error.Refused;
            }
        }
        // Until everything is built the errdefers below free; afterwards `shutdown` does.
        var armed = true;
        const a = try gpa.create(ConsensusAuthority);
        errdefer if (armed) gpa.destroy(a);
        a.* = .{ .gpa = gpa, .io = io, .options = options, .shared = undefined, .peers = undefined, .handlers = undefined, .locked = undefined, .identity = undefined, .peer_keys = undefined, .driver = undefined };

        // Store (one lock around the engine).
        a.locked = try gpa.create(LockedStore);
        errdefer if (armed) gpa.destroy(a.locked);
        if (options.store_override) |s| {
            a.locked.* = .{ .inner = s, .mu = mon.Monitor.init(io) };
        } else {
            var dir_buf: [512]u8 = undefined;
            const dir = std.fmt.bufPrint(&dir_buf, "{s}/{d}", .{ options.db_dir, ctx.committee.epoch }) catch return error.BadConfig;
            const ls = consensus.store.LogStore.open(gpa, io, .{ .dir_path = dir, .epoch = ctx.committee.epoch }) catch return error.StoreFailure;
            a.log_store = ls;
            a.locked.* = .{ .inner = ls.store(), .mu = mon.Monitor.init(io), .log = ls };
        }
        errdefer if (armed) if (a.log_store) |ls| ls.close();

        // Peers and verification.
        const grpc_cfg: grpc.Config = options.grpc_config orelse .{
            .message_limit = ctx.parameters.tonic.message_size_limit,
            .keepalive_ns = ctx.parameters.tonic.keepalive_interval_ns,
            // tonic_network.rs hardcodes the HTTP/2 windows (64 MiB connection, 32 MiB stream),
            // the Config defaults; connection_buffer_size does not set them.
        };
        a.peers = peers_mod.Peers.init(gpa, io, ctx, options.network_key_seed, grpc_cfg) catch return error.BadConfig;
        errdefer if (armed) a.peers.deinit();
        // Genesis refs of this epoch for the verifier (borrowed by it; freed by `shutdown`).
        {
            var tmp = std.heap.ArenaAllocator.init(gpa);
            defer tmp.deinit();
            const gen = consensus.digest.genesisBlocks(tmp.allocator(), &ctx.committee, ctx.epoch_start_timestamp_ms, &ctx.protocol_config) catch return error.OutOfMemory;
            const refs = try gpa.alloc(types.BlockRef, gen.len);
            for (gen, refs) |*g, *r| r.* = g.reference();
            a.genesis_refs = refs;
        }
        errdefer if (armed) gpa.free(a.genesis_refs);
        const verifier = consensus.verifier.SignedBlockVerifier.init(ctx, options.tx_verifier, a.genesis_refs);
        a.shared = Shared.init(gpa, io, ctx, a.peers, verifier) catch return error.OutOfMemory;
        errdefer if (armed) a.shared.deinit();
        const s = a.shared;
        s.verifier_hook = options.verifier_override;

        a.handlers = try gpa.create(service.Handlers);
        errdefer if (armed) gpa.destroy(a.handlers);
        a.handlers.* = service.Handlers.init(gpa, io, ctx, a.locked.store(), &s.broadcaster, &s.rounds, &s.published, .{ .ctx = a, .submit = ingressSubmit }, &s.stats, &s.stopping);
        a.handlers.read_copy = .{ .ctx = a.locked, .read = LockedStore.readBlocksCopy };

        // Core (recovered on the core thread; start waits for it).
        a.driver = options.driver_override orelse (consensusCoreDriver(gpa, ctx, a.locked.store(), options) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Unimplemented => error.Unimplemented,
            else => error.StoreFailure,
        });
        errdefer if (armed) a.driver.vtable.deinit(a.driver.ctx);

        // Server (validators only: observers have no committee address).
        a.identity = try gpa.create(tls.Identity);
        errdefer if (armed) gpa.destroy(a.identity);
        var name_buf: [48]u8 = undefined;
        const name = tls.serverName(&name_buf, ctx.committee.epoch) catch return error.BadConfig;
        a.identity.* = tls.Identity.init(options.network_key_seed, name) catch return error.BadConfig;
        const keys = try gpa.alloc([32]u8, ctx.committee.size());
        errdefer if (armed) gpa.free(keys);
        for (ctx.committee.authorities, 0..) |au, i| keys[i] = au.network_key;
        a.peer_keys = keys;
        // Every resource exists now: from here a failure runs the full `shutdown`, which stops
        // the threads that are already running before it frees what they use.
        armed = false;
        errdefer a.shutdown();

        // The synchronizer first: the server's ingress hook and the core thread reach it.
        a.synchronizer = sync.Synchronizer.start(s) catch return error.Io;
        s.excluded_hook = .{ .ctx = a, .check = excludedCheck };
        if (ctx.own_index) |own| {
            const text = options.listen_address orelse ctx.committee.authorities[own].address;
            const hp = addr.parse(text) catch return error.BadConfig;
            if (!options.allow_non_local and !addr.isLocalOrPrivate(hp.host)) return error.Refused;
            a.server = grpc.Server.start(gpa, io, .{
                .listen_host = addr.bindHost(hp.host),
                .listen_port = hp.port,
                .server_name = a.peers.server_name,
                .identity = a.identity,
                .check = .{ .ctx = a, .lookup = peerLookup },
                .cfg = grpc_cfg,
                .handler = a.handlers.grpcHandler(),
            }) catch return error.Io;
        }

        a.core_thread = std.Thread.spawn(.{ .stack_size = 16 << 20 }, coreMain, .{a}) catch return error.Io;
        // Wait for recovery.
        while (!a.started.load(.acquire) and !a.startup_failed.load(.acquire)) shared_mod.sleepMs(2);
        if (a.startup_failed.load(.acquire)) {
            return switch (a.startup_error orelse error.StoreFailure) {
                error.Unimplemented => error.Unimplemented,
                error.OutOfMemory => error.OutOfMemory,
                else => error.StoreFailure,
            };
        }

        const multi = ctx.committee.size() > 1;
        if (multi) {
            a.subscriber = sync.Subscriber.start(s) catch return error.Io;
            a.commit_syncer = sync.CommitSyncer.start(s) catch return error.Io;
            a.prober = sync.RoundProber.start(s) catch return error.Io;
        }
        if (!options.observe_only and ctx.own_index != null) {
            const do_sync = multi and options.boot_counter == 0 and ctx.parameters.sync_last_known_own_block_timeout_ns != 0;
            if (do_sync) {
                a.own_sync_thread = std.Thread.spawn(.{ .stack_size = 8 << 20 }, ownSyncMain, .{a}) catch return error.Io;
            } else {
                _ = s.core_q.push(.{ .last_known_round = 0 });
            }
        }
        return a;
    }

    fn peerLookup(ctx: *anyopaque, key: *const [32]u8) ?u32 {
        const a: *ConsensusAuthority = @ptrCast(@alignCast(ctx));
        for (a.peer_keys, 0..) |k, i| if (std.mem.eql(u8, &k, key)) return @intCast(i);
        return null;
    }

    /// `handle_send_block`: verify on the caller's thread, then queue for the core.
    fn ingressSubmit(ctx: *anyopaque, peer: types.AuthorityIndex, serialized: []const u8, excluded: []const types.BlockRef) bool {
        const a: *ConsensusAuthority = @ptrCast(@alignCast(ctx));
        const n = a.shared.submitBlocks(peer, &.{serialized}, excluded, true) catch return false;
        return n > 0;
    }

    /// `check_block_refs`: excluded ancestors of a streamed block that we do not have are fetched
    /// from the sender.
    fn excludedCheck(ctx: *anyopaque, refs: []const types.BlockRef, peer: types.AuthorityIndex) void {
        const a: *ConsensusAuthority = @ptrCast(@alignCast(ctx));
        const sy = a.synchronizer orelse return;
        var buf: [2 * shared_mod.max_peers]types.BlockRef = undefined;
        var have: [2 * shared_mod.max_peers]bool = undefined;
        const n = @min(refs.len, buf.len);
        @memcpy(buf[0..n], refs[0..n]);
        a.locked.store().vtable.contains_blocks(a.locked.store().ctx, buf[0..n], have[0..n]) catch return;
        var unknown: [2 * shared_mod.max_peers]types.BlockRef = undefined;
        var k: usize = 0;
        for (buf[0..n], have[0..n]) |r, h| {
            if (!h) {
                unknown[k] = r;
                k += 1;
            }
        }
        if (k > 0) sy.fetchMissing(unknown[0..k], peer);
    }

    fn ownSyncMain(a: *ConsensusAuthority) void {
        if (sync.syncLastKnownOwnBlock(a.shared)) |round| {
            _ = a.shared.pushCore(.{ .last_known_round = round });
        }
    }

    /// Stops proposing, drains the commit observer, closes connections, flushes the store.
    pub fn stop(a: *ConsensusAuthority) void {
        a.shutdown();
    }

    fn shutdown(a: *ConsensusAuthority) void {
        const s = a.shared;
        s.stopping.store(true, .release);
        s.broadcaster.close();
        a.peers.close();
        if (a.server) |srv| {
            srv.stop();
            a.server = null;
        }
        if (a.own_sync_thread) |t| t.join();
        if (a.subscriber) |x| x.stop();
        if (a.commit_syncer) |x| x.stop();
        if (a.prober) |x| x.stop();
        // The core thread uses the synchronizer: it ends first (it also sees `stopping`).
        _ = s.core_q.push(.stop);
        if (a.core_thread) |t| t.join();
        a.core_thread = null;
        if (a.synchronizer) |x| x.stop();
        a.synchronizer = null;
        for (a.pending.items) |p| {
            for (p.items[p.next..]) |*f| f.deinit();
            a.gpa.free(p.items);
        }
        a.pending.deinit(a.gpa);
        a.driver.vtable.deinit(a.driver.ctx);
        a.gpa.free(a.genesis_refs);
        if (a.log_store) |ls| ls.close();
        a.peers.deinit();
        s.deinit();
        a.gpa.free(a.peer_keys);
        std.crypto.secureZero(u8, std.mem.asBytes(&a.identity.key));
        a.gpa.destroy(a.identity);
        a.gpa.destroy(a.handlers);
        a.gpa.destroy(a.locked);
        const gpa = a.gpa;
        gpa.destroy(a);
    }

    /// Highest committed index (for the epoch store and health).
    pub fn lastCommitIndex(a: *const ConsensusAuthority) types.CommitIndex {
        return a.shared.published.commit_index.load(.acquire);
    }

    pub fn lastProposedRound(a: *const ConsensusAuthority) types.Round {
        return a.shared.published.last_proposed.load(.acquire);
    }

    pub fn stats(a: *const ConsensusAuthority) *const service.Stats {
        return &a.shared.stats;
    }

    /// The TCP port the consensus server listens on (0 for observers).
    pub fn listenPort(a: *const ConsensusAuthority) u16 {
        return if (a.server) |s| s.port else 0;
    }

    /// Wakes the core to propose when new transactions arrived (TransactionClient notify).
    pub fn notifyNewTransactions(a: *ConsensusAuthority) void {
        _ = a.shared.core_q.push(.new_txs);
    }

    // ------------------------------------------------------------ core thread

    fn coreMain(a: *ConsensusAuthority) void {
        coreLoop(a) catch |e| {
            if (!a.started.load(.acquire)) {
                log.err("consensus startup failed: {s}", .{@errorName(e)});
                if (@errorReturnTrace()) |t| std.debug.dumpErrorReturnTrace(t);
                a.startup_error = e;
                a.startup_failed.store(true, .release);
            } else {
                log.err("core thread failed: {s}", .{@errorName(e)});
                if (@errorReturnTrace()) |t| std.debug.dumpErrorReturnTrace(t);
            }
            // A failed core must not leave the node half alive.
            a.shared.stopping.store(true, .release);
        };
    }

    fn coreLoop(a: *ConsensusAuthority) !void {
        const s = a.shared;
        const ctx = a.options.context;
        const d = a.driver;
        const min_delay = @max(ctx.parameters.min_round_delay_ns, std.time.ns_per_ms);
        var step_arena = std.heap.ArenaAllocator.init(a.gpa);
        defer step_arena.deinit();
        var out: consensus.core.Output = .{};
        try d.vtable.recover(d.ctx, step_arena.allocator(), &out);
        try a.afterStep(&step_arena, &out, 0);
        a.started.store(true, .release);

        var propagation_delay: types.Round = 0;
        var leader_timeout_at: u64 = if (out.new_round != null) mon.monoNs(s.io) + ctx.parameters.leader_timeout_ns else 0;
        var last_tick_ns: u64 = mon.monoNs(s.io);
        while (true) {
            if (s.isStopping()) return;
            const now = mon.monoNs(s.io);
            var wait = min_delay -| (now -| last_tick_ns);
            if (leader_timeout_at != 0) wait = @min(wait, leader_timeout_at -| now);
            if (a.pending.items.len > 0) wait = @min(wait, 2 * std.time.ns_per_ms);
            const ev = s.core_q.pop(wait);
            _ = step_arena.reset(.retain_capacity);
            out = .{};
            var step_peer: types.AuthorityIndex = ctx.own_index orelse 0;
            if (ev) |e| {
                switch (e) {
                    .stop => return,
                    .blocks => |b| {
                        defer b.destroy();
                        step_peer = b.peer;
                        try d.vtable.add_blocks(d.ctx, step_arena.allocator(), b.blocks, b.rejects, &out);
                    },
                    .commits => |c| {
                        defer c.destroy();
                        try d.vtable.add_certified_commits(d.ctx, step_arena.allocator(), c.commits, c.blocks, c.certifier_rejects, &out);
                    },
                    .propagation_delay => |p| propagation_delay = p,
                    .last_known_round => |r| {
                        d.vtable.set_last_known_proposed_round(d.ctx, r);
                        s.may_propose.store(true, .release);
                        try d.vtable.try_propose(d.ctx, step_arena.allocator(), true, .{ .propagation_delay = propagation_delay }, &out);
                    },
                    .new_txs => if (s.may_propose.load(.acquire) and !a.options.observe_only) {
                        try d.vtable.try_propose(d.ctx, step_arena.allocator(), false, .{ .propagation_delay = propagation_delay }, &out);
                    },
                }
            }
            try a.afterStep(&step_arena, &out, step_peer);
            // LeaderTimeoutTask: a new threshold-clock round arms the leader timeout.
            if (out.new_round != null) leader_timeout_at = mon.monoNs(s.io) + ctx.parameters.leader_timeout_ns;
            // Timers run after every event, so a steady stream of blocks cannot starve them.
            const now2 = mon.monoNs(s.io);
            if (s.may_propose.load(.acquire) and !a.options.observe_only) {
                var force: ?bool = null;
                if (leader_timeout_at != 0 and now2 >= leader_timeout_at) {
                    leader_timeout_at = 0;
                    force = true;
                } else if (now2 -| last_tick_ns >= min_delay) {
                    last_tick_ns = now2;
                    force = false;
                }
                if (force) |f| {
                    out = .{};
                    try d.vtable.try_propose(d.ctx, step_arena.allocator(), f, .{ .propagation_delay = propagation_delay }, &out);
                    try a.afterStep(&step_arena, &out, step_peer);
                    if (out.new_round != null) leader_timeout_at = mon.monoNs(s.io) + ctx.parameters.leader_timeout_ns;
                }
            }
        }
    }

    /// Everything the core thread does after the core returned: persist, publish, stream the
    /// proposed block, queue the missing ancestors, push committed sub-dags.
    fn afterStep(a: *ConsensusAuthority, step_arena: *std.heap.ArenaAllocator, out: *consensus.core.Output, from: types.AuthorityIndex) !void {
        const s = a.shared;
        const d = a.driver;
        const ctx = a.options.context;
        const own = ctx.own_index;
        try d.vtable.flush(d.ctx);
        // Publish the round snapshot before the block reaches subscribers.
        var accepted: [shared_mod.max_peers]types.Round = undefined;
        var last_proposed: types.Round = 0;
        var commit_index: types.CommitIndex = 0;
        const n = ctx.committee.size();
        d.vtable.snapshot(d.ctx, accepted[0..n], &last_proposed, &commit_index);
        s.published.publish(accepted[0..n], last_proposed, commit_index);
        if (d.vtable.gc_round) |f| s.published.gc_round.store(f(d.ctx), .release);
        for (out.proposed.items) |p| {
            const blk = p.block;
            s.broadcaster.append(blk.serialized, p.excluded_ancestors) catch {};
            if (own) |o| s.rounds.updateFromVerifiedBlock(o, blk.block.inner.round(), blk.block.inner.ancestors(), p.excluded_ancestors);
            a.options.tx_source.ack(blk.reference());
        }
        // Missing ancestors: live sync from the sender, and the periodic work list.
        var missing_buf: [shared_mod.Shared.max_missing]types.BlockRef = undefined;
        const nm = d.vtable.missing_blocks(d.ctx, &missing_buf);
        s.setMissing(missing_buf[0..nm]);
        if (a.synchronizer) |sy| if (out.missing.len > 0) sy.fetchMissing(out.missing, from);
        // Committed sub-dags, in order, to the sink; a full sink keeps them for the next pass.
        _ = step_arena;
        if (out.committed.items.len > 0) {
            // Each Finalized owns its sub-dag (its own arena); the list itself is in the step
            // arena, so copy the entries to a gpa slice that lives until the sink took them all.
            const items = a.gpa.dupe(consensus.commit_finalizer.Finalized, out.committed.items) catch |e| {
                for (out.committed.items) |*f| f.deinit();
                out.committed = .empty;
                return e;
            };
            out.committed = .empty;
            a.pending.append(a.gpa, .{ .items = items }) catch |e| {
                for (items) |*f| f.deinit();
                a.gpa.free(items);
                return e;
            };
        }
        a.drainPending();
        s.handled_commit.store(a.options.commit_sink.processedThrough(), .release);
    }

    fn drainPending(a: *ConsensusAuthority) void {
        while (a.pending.items.len > 0) {
            const p = &a.pending.items[0];
            while (p.next < p.items.len) {
                if (!a.options.commit_sink.push(&p.items[p.next].sub_dag)) return;
                p.items[p.next].deinit();
                p.next += 1;
            }
            a.gpa.free(p.items);
            _ = a.pending.orderedRemove(0);
        }
    }
};

// ---------------------------------------------------------------- the real core

/// The consensus core (`consensus.Core`, val-consensus-core) behind the driver interface.
const RealCore = struct {
    gpa: Allocator,
    context: *const consensus.Context,
    dag: *consensus.dag_state.DagState,
    schedule: consensus.leader_schedule.LeaderSchedule,
    votes: consensus.transaction_vote_tracker.TransactionVoteTracker,
    finalizer: consensus.commit_finalizer.CommitFinalizer,
    core: ?consensus.Core = null,
    signer: iface.BlockSigner,
    tx_source: iface.TransactionSource,
    commit_sink: iface.CommitSink,

    const E = CoreDriver.CoreError;

    fn self(ctx: *anyopaque) *RealCore {
        return @ptrCast(@alignCast(ctx));
    }

    const vt: CoreDriver.VTable = .{
        .recover = recover,
        .add_blocks = addBlocks,
        .add_certified_commits = addCommits,
        .try_propose = tryPropose,
        .set_last_known_proposed_round = setLast,
        .flush = flush,
        .snapshot = snapshot,
        .gc_round = gcRound,
        .missing_blocks = missingBlocks,
        .deinit = deinit,
    };

    fn gcRound(ctx: *anyopaque) types.Round {
        return self(ctx).dag.gcRound();
    }

    fn recover(ctx: *anyopaque, arena: Allocator, out: *consensus.core.Output) E!void {
        const r = self(ctx);
        r.core = try consensus.Core.recover(r.gpa, arena, .{
            .context = r.context,
            .dag = r.dag,
            .schedule = &r.schedule,
            .tracker = &r.votes,
            .finalizer = &r.finalizer,
            .signer = r.signer,
            .tx_source = r.tx_source,
            // The network lane always sends `last_known_round` (0 when no own-block sync runs).
            .sync_last_known_own_block = true,
            .replay_after_commit_index = r.commit_sink.processedThrough(),
        }, out);
    }
    fn addBlocks(ctx: *anyopaque, arena: Allocator, blocks: []const types.VerifiedBlock, rejects: []const []const types.TransactionIndex, out: *consensus.core.Output) E!void {
        const r = self(ctx);
        // Our own reject votes on these blocks' transactions feed the vote tracker before the
        // core accepts them (Rust: `add_voted_blocks` ahead of `add_blocks`).
        for (blocks, 0..) |*b, i| try r.votes.addVotedBlock(b, if (i < rejects.len) rejects[i] else &.{});
        return r.core.?.addBlocks(arena, blocks, out);
    }
    /// The commit syncer hands over commits plus one block list (commit blocks and the certifying
    /// vote blocks); the core wants each commit with its blocks and the votes apart.
    fn addCommits(ctx: *anyopaque, arena: Allocator, commits: []const types.TrustedCommit, blocks: []const types.VerifiedBlock, certifier_rejects: []const []const types.TransactionIndex, out: *consensus.core.Output) E!void {
        const r = self(ctx);
        // commit_syncer.rs fetch_once: `transaction_vote_tracker.add_voted_blocks` with the
        // certifying blocks and our reject votes, before the commits go to the core.
        for (blocks[0..@min(blocks.len, certifier_rejects.len)], certifier_rejects[0..@min(blocks.len, certifier_rejects.len)]) |*b, rej| try r.votes.addVotedBlock(b, rej);
        var by_ref: std.AutoHashMapUnmanaged(types.BlockRef, usize) = .empty;
        for (blocks, 0..) |*b, i| by_ref.put(arena, b.reference(), i) catch return error.OutOfMemory;
        const used = arena.alloc(bool, blocks.len) catch return error.OutOfMemory;
        @memset(used, false);
        const certified = arena.alloc(types.CertifiedCommit, commits.len) catch return error.OutOfMemory;
        for (commits, certified) |c, *cc| {
            const refs = c.commit.V1.blocks;
            const cb = arena.alloc(types.VerifiedBlock, refs.len) catch return error.OutOfMemory;
            for (refs, cb) |ref, *dst| {
                const i = by_ref.get(ref) orelse return error.MissingBlock;
                dst.* = blocks[i];
                used[i] = true;
            }
            cc.* = .{ .commit = c, .blocks = cb };
        }
        // fetch_once step 10: every block of the certified commits enters the vote tracker too
        // (with no own reject votes: only the reject votes it carries count). The finalizer reads
        // vote info for each committed block; without this a node that caught up through commit
        // sync with transaction voting on failed `MissingBlock` in tryDirectFinalizeCommit.
        if (r.context.protocol_config.transaction_voting_enabled) {
            for (blocks, used) |*b, u| if (u) try r.votes.addVotedBlock(b, &.{});
        }
        var votes: std.ArrayList(types.VerifiedBlock) = .empty;
        for (blocks, used) |b, u| if (!u) votes.append(arena, b) catch return error.OutOfMemory;
        return r.core.?.addCertifiedCommits(arena, certified, votes.items, out);
    }
    fn tryPropose(ctx: *anyopaque, arena: Allocator, force: bool, signals: consensus.core.Signals, out: *consensus.core.Output) E!void {
        const c = &self(ctx).core.?;
        c.setSignals(signals);
        _ = try c.tryPropose(arena, force, out);
    }
    fn setLast(ctx: *anyopaque, round: types.Round) void {
        self(ctx).core.?.setLastKnownProposedRound(round) catch |e| log.err("set last known proposed round: {s}", .{@errorName(e)});
    }
    fn flush(ctx: *anyopaque) E!void {
        return self(ctx).dag.flush();
    }
    fn snapshot(ctx: *anyopaque, accepted: []types.Round, last_proposed: *types.Round, commit_index: *types.CommitIndex) void {
        const r = self(ctx);
        for (accepted, 0..) |*x, i| x.* = r.dag.getLastBlockForAuthority(@intCast(i)).block.inner.round();
        last_proposed.* = if (r.dag.getLastProposedBlock()) |b| b.block.inner.round() else 0;
        commit_index.* = r.dag.lastCommitIndex();
    }
    fn missingBlocks(ctx: *anyopaque, out: []types.BlockRef) usize {
        const r = self(ctx);
        const c = if (r.core) |*c| c else return 0;
        const m = c.missingBlocks();
        const n = @min(m.len, out.len);
        @memcpy(out[0..n], m[0..n]);
        return n;
    }
    fn deinit(ctx: *anyopaque) void {
        const r = self(ctx);
        if (r.core) |*c| c.deinit();
        r.finalizer.deinit();
        r.votes.deinit();
        r.schedule.deinit();
        r.dag.deinit();
        r.gpa.destroy(r);
    }
};

/// Builds the real core driver over `store` (the locked store the network also reads).
pub fn consensusCoreDriver(gpa: Allocator, context: *const consensus.Context, store: Store, options: Options) !CoreDriver {
    const r = try gpa.create(RealCore);
    errdefer gpa.destroy(r);
    const dag = try consensus.dag_state.DagState.init(gpa, context, store);
    errdefer dag.deinit();
    r.* = .{
        .gpa = gpa,
        .context = context,
        .dag = dag,
        .schedule = try consensus.leader_schedule.LeaderSchedule.fromStore(gpa, context, dag),
        .votes = consensus.transaction_vote_tracker.TransactionVoteTracker.init(gpa, context, dag, options.tx_verifier),
        .finalizer = undefined,
        .signer = options.signer,
        .tx_source = options.tx_source,
        .commit_sink = options.commit_sink,
    };
    r.finalizer = consensus.commit_finalizer.CommitFinalizer.init(gpa, context, dag, &r.votes);
    return .{ .ctx = r, .vtable = &RealCore.vt };
}
