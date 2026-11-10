//! The local multi-node test committee runner: N authorities on loopback in one process, each a
//! full `ConsensusAuthority` (TLS gRPC server, subscribers, synchronizer, commit syncer, round
//! prober, core thread) with generated keys, so a test machine can run a localnet and exercise the
//! whole network stack without touching any real validator. Owner lane: val-consensus-net.
//!
//! Modes:
//! - `toy`: the toy core of testcore.zig (not Mysticeti) so the network layer can be exercised
//!   before and independently of the consensus core.
//! - `real`: `consensus.Core` and the LogStore; works once val-consensus-core has landed (until
//!   then `ConsensusAuthority.start` returns `error.Unimplemented`).
//!
//! Safety: keys are generated from the seed, all addresses are loopback, nothing here can reach
//! a real validator, and the signer is the test signer (never a key file).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const types = consensus.types;
const testkit = @import("testkit.zig");
const testcore = @import("testcore.zig");
const node = @import("authority_node.zig");
const mon = @import("mon.zig");
const proxy = @import("localnet_proxy.zig");

pub const Mode = enum { toy, real };

pub const Config = struct {
    n: usize = 4,
    seed: u64 = 1,
    mode: Mode = .toy,
    /// Stop when every node committed at least this many commits.
    target_commits: u32 = 10,
    timeout_ms: u64 = 30_000,
    /// Toy mode: advance rounds only with every authority's block (deterministic commits).
    wait_all: bool = true,
    /// Refuse every Nth CommitSink push once, to exercise the retry path (0: never).
    sink_full_every: u32 = 0,
    /// Parent of real-mode stores: each run makes a fresh `run-<pid>-<time>` directory inside it
    /// (so a second run or another seed never recovers stale state) and deletes it at the end.
    db_dir: []const u8 = "/tmp/deepwave-consensus-localnet",
    min_round_delay_ms: u64 = 5,
    /// Consensus protocol config from this sui protocol version (chain unknown, as a local
    /// committee): GC depth, block V2 with transaction votes, linearizer and timestamp rules.
    /// Null keeps the testkit default (V1 blocks, GC depth 0).
    protocol_version: ?u64 = null,
    /// Bring this node up late (index), after `late_start_commits` commits elsewhere (exercises
    /// catch-up); needs `wait_all = false` with n >= 4.
    late_node: ?usize = null,
    late_start_commits: u32 = 5,
    /// Context parameters worth shrinking in catch-up tests.
    commit_sync_batch_size: u32 = 100,
    dag_state_cached_rounds: u32 = 500,
    /// Stop this node (clean shutdown: threads joined, sockets closed, store closed) once the
    /// committee's best node has `restart_after_commits` commits, keep it down `restart_down_ms`,
    /// then start it again on the same store, signer and commit sink.
    restart_node: ?usize = null,
    restart_after_commits: u32 = 500,
    restart_down_ms: u64 = 5_000,
    /// Real mode: before the restart, append a torn record (a valid-looking header and half a
    /// body) to the stopped node's consensus.log, as a kill in the middle of a write leaves it.
    restart_torn: bool = false,
    /// Cut this node off from every other node for `partition_ms` once the best node has
    /// `partition_after_commits` commits (each ordered pair talks through its own loopback relay,
    /// localnet_proxy.zig), then heal.
    partition_node: ?usize = null,
    partition_after_commits: u32 = 500,
    partition_ms: u64 = 30_000,
    partition_mode: proxy.CutMode = .blackhole,
};

pub const EventKind = enum { restart, partition };

/// What happened around a restart or a partition.
pub const EventReport = struct {
    kind: EventKind,
    node: usize,
    /// Commits of the slowest other node when the event started and when it ended.
    others_min_at_start: usize,
    others_min_at_end: usize,
    /// The affected node's commits when the event ended.
    node_at_end: usize,
    event_ms: u64,
    /// From the end of the event until the affected node had as many commits as the best other
    /// node had at the end of the event (null: never within the timeout).
    recover_ms: ?u64,
};

pub const NodeReport = struct {
    commits: usize,
    last_proposed: types.Round,
    blocks_received: u64,
    blocks_invalid: u64,
    blocks_streamed: u64,
    commit_batches_synced: u64,
    blocks_fetched: u64,
};

pub const Report = struct {
    ok: bool,
    elapsed_ms: u64,
    nodes: []NodeReport,
    /// All nodes agree on the commit sequence (leader refs by index) over their common prefix.
    consistent: bool,
    min_commits: usize,
    event: ?EventReport = null,

    pub fn deinit(r: *Report, gpa: Allocator) void {
        gpa.free(r.nodes);
    }
};

const Node = struct {
    gpa: Allocator,
    fs: testkit.FakeStore,
    signer: testcore.TestSigner,
    source: testcore.TestSource = .{},
    sink: testcore.TestSink,
    txv: testcore.AcceptAllTxs = .{},
    verifier: testcore.ToyVerifier,
    context: consensus.Context,
    core: ?*testcore.ToyCore = null,
    authority: ?*node.ConsensusAuthority = null,
    clock: testkit.RealClock,
    /// Committee copy whose addresses point at this node's relays (partition runs only).
    auths: []consensus.committee.Authority = &.{},
    addr_bufs: [testkit.max_test_authorities][48]u8 = undefined,
    /// Stats of earlier incarnations (restart runs).
    acc: NodeReport = .{ .commits = 0, .last_proposed = 0, .blocks_received = 0, .blocks_invalid = 0, .blocks_streamed = 0, .commit_batches_synced = 0, .blocks_fetched = 0 },
    listen: ?[]const u8 = null,

    fn stopAuthority(nd: *Node) void {
        const a = nd.authority orelse return;
        const st = a.stats();
        nd.acc.blocks_received += st.blocks_received.load(.monotonic);
        nd.acc.blocks_invalid += st.blocks_invalid.load(.monotonic);
        nd.acc.blocks_streamed += st.blocks_streamed.load(.monotonic);
        nd.acc.commit_batches_synced += st.commit_batches_synced.load(.monotonic);
        nd.acc.blocks_fetched += st.blocks_fetched.load(.monotonic);
        nd.acc.last_proposed = @max(nd.acc.last_proposed, a.lastProposedRound());
        a.stop();
        nd.authority = null;
    }
};

const Phase = enum { idle, active, recovering, done };

/// Runs a committee until every node reaches `target_commits` or the timeout; returns the report.
pub fn run(gpa: Allocator, io: Io, cfg_in: Config) !Report {
    var cfg = cfg_in;
    var run_dir_buf: [320]u8 = undefined;
    var run_dir: ?[]const u8 = null;
    if (cfg.mode == .real) {
        const now_ns: u64 = @intCast(Io.Clock.real.now(io).toNanoseconds());
        run_dir = std.fmt.bufPrint(&run_dir_buf, "{s}/run-{d}-{d}", .{ cfg.db_dir, std.c.getpid(), now_ns }) catch return error.BadConfig;
        cfg.db_dir = run_dir.?;
    }
    defer if (run_dir) |d| Io.Dir.cwd().deleteTree(io, d) catch {};
    if (cfg.restart_node) |r| if (r >= cfg.n) return error.BadConfig;
    if (cfg.partition_node) |p| if (p >= cfg.n) return error.BadConfig;
    const tc = try testkit.TestCommittee.init(gpa, io, cfg.n, cfg.seed, 0, 1);
    defer tc.deinit();
    var cuts: proxy.Cuts = .{ .mode = cfg.partition_mode };
    var relays: [testkit.max_test_authorities][testkit.max_test_authorities]?*proxy.Relay = @splat(@splat(null));
    defer for (&relays) |*row| for (row) |r| if (r) |x| x.stop();
    const nodes = try gpa.alloc(Node, cfg.n);
    defer gpa.free(nodes);
    var made: usize = 0;
    defer for (nodes[0..made]) |*nd| {
        nd.stopAuthority();
        nd.sink.deinit();
        nd.fs.deinit();
        if (nd.auths.len != 0) gpa.free(nd.auths);
    };
    for (nodes, 0..) |*nd, i| {
        nd.gpa = gpa;
        nd.clock = .{ .io = io };
        nd.fs = testkit.FakeStore.init(gpa, io);
        nd.signer = try testcore.TestSigner.init(&tc.protocol_seeds[i]);
        nd.source = .{};
        nd.sink = testcore.TestSink.init(gpa, io);
        nd.sink.full_every = cfg.sink_full_every;
        nd.txv = .{};
        nd.context = testkit.makeContext(tc, @intCast(i), nd.clock.clock());
        nd.context.parameters.min_round_delay_ns = cfg.min_round_delay_ms * std.time.ns_per_ms;
        if (cfg.protocol_version) |v| nd.context.protocol_config = consensus.config.ProtocolConfig.fromProtocol(v, .unknown) catch return error.BadConfig;
        nd.context.parameters.commit_sync_batch_size = cfg.commit_sync_batch_size;
        nd.context.parameters.dag_state_cached_rounds = cfg.dag_state_cached_rounds;
        nd.context.parameters.round_prober_interval_ms = 500;
        nd.context.parameters.round_prober_request_timeout_ms = 1000;
        nd.context.parameters.tonic.keepalive_interval_ns = 2 * std.time.ns_per_s;
        nd.verifier = .{ .context = &nd.context };
        nd.core = null;
        nd.authority = null;
        nd.auths = &.{};
        nd.acc = .{ .commits = 0, .last_proposed = 0, .blocks_received = 0, .blocks_invalid = 0, .blocks_streamed = 0, .commit_batches_synced = 0, .blocks_fetched = 0 };
        nd.listen = null;
        made += 1;
        if (cfg.partition_node != null) {
            // Node i dials node j through relay (i, j); it still listens on its committee port.
            nd.auths = try gpa.alloc(consensus.committee.Authority, cfg.n);
            @memcpy(nd.auths, tc.authorities);
            for (0..cfg.n) |j| {
                if (j == i) continue;
                const r = try proxy.Relay.start(gpa, io, i, j, tc.ports[j], &cuts);
                relays[i][j] = r;
                nd.auths[j].address = std.fmt.bufPrint(&nd.addr_bufs[j], "/ip4/127.0.0.1/udp/{d}", .{r.port}) catch return error.BadConfig;
            }
            nd.context.committee = try consensus.Committee.init(tc.committee.epoch, nd.auths);
            nd.listen = tc.addresses[i];
        }
    }
    const start_ns = mon.monoNs(io);
    for (nodes, 0..) |*nd, i| {
        if (cfg.late_node != null and cfg.late_node.? == i) continue;
        try startNode(gpa, io, tc, nd, i, cfg);
    }
    var late_started = cfg.late_node == null;
    const deadline = start_ns + cfg.timeout_ms * std.time.ns_per_ms;
    var ok = false;
    const ev_node: ?usize = cfg.restart_node orelse cfg.partition_node;
    const ev_kind: EventKind = if (cfg.restart_node != null) .restart else .partition;
    const ev_after: u32 = if (cfg.restart_node != null) cfg.restart_after_commits else cfg.partition_after_commits;
    const ev_len_ms: u64 = if (cfg.restart_node != null) cfg.restart_down_ms else cfg.partition_ms;
    var phase: Phase = if (ev_node == null) .done else .idle;
    var ev: EventReport = undefined;
    var ev_t0: u64 = 0;
    var ev_t1: u64 = 0;
    var ev_goal: usize = 0;
    while (mon.monoNs(io) < deadline) {
        var all = true;
        var most: usize = 0;
        for (nodes, 0..) |*nd, i| {
            if (nd.authority == null and !late_started) {
                most = @max(most, 0);
                continue;
            }
            const c = nd.sink.count();
            most = @max(most, c);
            if (c < cfg.target_commits) all = false;
            _ = i;
        }
        if (!late_started and most >= cfg.late_start_commits) {
            try startNode(gpa, io, tc, &nodes[cfg.late_node.?], cfg.late_node.?, cfg);
            late_started = true;
            all = false;
        }
        if (ev_node) |en| switch (phase) {
            .idle => if (most >= ev_after) {
                ev = .{ .kind = ev_kind, .node = en, .others_min_at_start = othersMin(nodes, en), .others_min_at_end = 0, .node_at_end = 0, .event_ms = 0, .recover_ms = null };
                if (ev_kind == .restart) {
                    nodes[en].stopAuthority();
                    if (cfg.restart_torn and cfg.mode == .real) try tearLog(io, cfg.db_dir, en, tc.committee.epoch);
                } else cuts.set(en, true);
                std.debug.print("localnet: {s} node {d} at {d} commits\n", .{ @tagName(ev_kind), en, most });
                ev_t0 = mon.monoNs(io);
                phase = .active;
            },
            .active => if (mon.monoNs(io) - ev_t0 >= ev_len_ms * std.time.ns_per_ms) {
                if (ev_kind == .restart) try startNode(gpa, io, tc, &nodes[en], en, cfg) else cuts.set(en, false);
                ev_t1 = mon.monoNs(io);
                ev.event_ms = (ev_t1 - ev_t0) / std.time.ns_per_ms;
                ev.others_min_at_end = othersMin(nodes, en);
                ev.node_at_end = nodes[en].sink.count();
                ev_goal = othersMax(nodes, en);
                std.debug.print("localnet: node {d} back after {d} ms: node {d} commits, others min {d} (from {d}), best {d}\n", .{ en, ev.event_ms, ev.node_at_end, ev.others_min_at_end, ev.others_min_at_start, ev_goal });
                phase = .recovering;
                all = false;
            },
            .recovering => if (nodes[en].sink.count() >= ev_goal) {
                ev.recover_ms = (mon.monoNs(io) - ev_t1) / std.time.ns_per_ms;
                std.debug.print("localnet: node {d} caught up in {d} ms\n", .{ en, ev.recover_ms.? });
                phase = .done;
            },
            .done => {},
        };
        if (all and late_started and phase == .done) {
            ok = true;
            break;
        }
        @import("serve").h2.sock.sleepMs(20);
    }
    const elapsed = (mon.monoNs(io) - start_ns) / std.time.ns_per_ms;
    const reports = try gpa.alloc(NodeReport, cfg.n);
    errdefer gpa.free(reports);
    var min_commits: usize = std.math.maxInt(usize);
    for (nodes, 0..) |*nd, i| {
        const st: *const @import("service.zig").Stats = if (nd.authority) |a| a.stats() else &empty_stats;
        reports[i] = .{
            .commits = nd.sink.count(),
            .last_proposed = @max(nd.acc.last_proposed, if (nd.authority) |a| a.lastProposedRound() else 0),
            .blocks_received = nd.acc.blocks_received + st.blocks_received.load(.monotonic),
            .blocks_invalid = nd.acc.blocks_invalid + st.blocks_invalid.load(.monotonic),
            .blocks_streamed = nd.acc.blocks_streamed + st.blocks_streamed.load(.monotonic),
            .commit_batches_synced = nd.acc.commit_batches_synced + st.commit_batches_synced.load(.monotonic),
            .blocks_fetched = nd.acc.blocks_fetched + st.blocks_fetched.load(.monotonic),
        };
        min_commits = @min(min_commits, reports[i].commits);
    }
    // Commit sequences agree over the common prefix.
    var consistent = true;
    // Every node saw each commit index exactly once, in order, from 1 (no gap, no replayed duplicate).
    for (nodes, 0..) |*nd, i| {
        for (nd.sink.commits.items, 0..) |cm, k| if (cm.index != k + 1) {
            std.debug.print("localnet: node {d} commit #{d} has index {d}\n", .{ i, k, cm.index });
            consistent = false;
            break;
        };
    }
    var idx: usize = 0;
    while (idx < min_commits) : (idx += 1) {
        const ref = nodes[0].sink.commits.items[idx];
        for (nodes[1..]) |*nd| {
            const o = nd.sink.commits.items[idx];
            if (o.index != ref.index or !o.leader.eql(ref.leader)) consistent = false;
        }
    }
    const event: ?EventReport = if (ev_node != null and phase != .idle) ev else null;
    return .{ .ok = ok and consistent, .elapsed_ms = elapsed, .nodes = reports, .consistent = consistent, .min_commits = min_commits, .event = event };
}

/// Appends a partial record to node `i`'s consensus log (what a kill mid-write leaves behind).
fn tearLog(io: Io, db_dir: []const u8, i: usize, epoch: types.Epoch) !void {
    var buf: [400]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "{s}/node{d}/{d}/consensus.log", .{ db_dir, i, epoch }) catch return error.BadConfig;
    const f = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer f.close(io);
    const end = try f.length(io);
    // Length 4096 and a checksum, then 100 bytes of a body that never finished.
    var torn: [112]u8 = @splat(0xa5);
    std.mem.writeInt(u32, torn[0..4], 4096, .little);
    try f.writePositionalAll(io, &torn, end);
    std.debug.print("localnet: tore node {d}'s consensus.log at {d} (+{d} bytes)\n", .{ i, end, torn.len });
}

fn othersMin(nodes: []Node, skip: usize) usize {
    var m: usize = std.math.maxInt(usize);
    for (nodes, 0..) |*nd, i| if (i != skip) {
        m = @min(m, nd.sink.count());
    };
    return m;
}

fn othersMax(nodes: []Node, skip: usize) usize {
    var m: usize = 0;
    for (nodes, 0..) |*nd, i| if (i != skip) {
        m = @max(m, nd.sink.count());
    };
    return m;
}

var empty_stats: @import("service.zig").Stats = .{};

fn startNode(gpa: Allocator, io: Io, tc: *testkit.TestCommittee, nd: *Node, i: usize, cfg: Config) !void {
    const toy = cfg.mode == .toy;
    if (toy) nd.core = try testcore.ToyCore.create(gpa, &nd.context, &nd.fs, nd.signer.blockSigner(), nd.source.txSource(), cfg.wait_all);
    var dir_buf: [256]u8 = undefined;
    const db = std.fmt.bufPrint(&dir_buf, "{s}/node{d}", .{ cfg.db_dir, i }) catch return error.BadConfig;
    nd.authority = node.ConsensusAuthority.start(gpa, io, .{
        .context = &nd.context,
        .db_dir = db,
        .network_key_seed = &tc.network_seeds[i],
        .signer = nd.signer.blockSigner(),
        .tx_verifier = nd.txv.verifier(),
        .tx_source = nd.source.txSource(),
        .commit_sink = nd.sink.commitSink(),
        .listen_address = nd.listen,
        // Real mode: LogStore, consensus.Core and SignedBlockVerifier (no overrides).
        .store_override = if (toy) nd.fs.store() else null,
        .driver_override = if (toy) nd.core.?.driver() else null,
        .verifier_override = if (toy) nd.verifier.hook() else null,
        // The late node only follows (observe-only): its own blocks would change the others' DAG.
        .observe_only = cfg.late_node != null and cfg.late_node.? == i,
    }) catch |e| return switch (e) {
        // The real core's pieces are stubs until val-consensus-core lands.
        error.Unimplemented, error.StoreFailure => if (toy) e else error.Unimplemented,
        else => e,
    };
}

test "toy committee of four commits identically over real TLS gRPC" {
    const gpa = std.testing.allocator;
    var rep = try run(gpa, std.testing.io, .{ .n = 4, .target_commits = 8, .timeout_ms = 30_000, .sink_full_every = 3 });
    defer rep.deinit(gpa);
    for (rep.nodes) |n| {
        std.debug.print("node commits={d} proposed={d} received={d} invalid={d} streamed={d} synced_batches={d} fetched={d}\n", .{ n.commits, n.last_proposed, n.blocks_received, n.blocks_invalid, n.blocks_streamed, n.commit_batches_synced, n.blocks_fetched });
    }
    try std.testing.expect(rep.consistent);
    try std.testing.expect(rep.ok);
    for (rep.nodes) |n| try std.testing.expectEqual(@as(u64, 0), n.blocks_invalid);
}

test "late observer catches up through the synchronizer and commit syncer" {
    const gpa = std.testing.allocator;
    var rep = try run(gpa, std.testing.io, .{ .n = 4, .wait_all = false, .late_node = 3, .late_start_commits = 25, .target_commits = 30, .timeout_ms = 60_000, .commit_sync_batch_size = 3, .dag_state_cached_rounds = 2 });
    defer rep.deinit(gpa);
    for (rep.nodes) |n| {
        std.debug.print("node commits={d} proposed={d} received={d} invalid={d} streamed={d} synced_batches={d} fetched={d}\n", .{ n.commits, n.last_proposed, n.blocks_received, n.blocks_invalid, n.blocks_streamed, n.commit_batches_synced, n.blocks_fetched });
    }
    try std.testing.expect(rep.consistent);
    try std.testing.expect(rep.ok);
}

test "real committee: a node stopped and restarted on its store rejoins without equivocating" {
    const gpa = std.testing.allocator;
    var rep = try run(gpa, std.testing.io, .{ .n = 4, .mode = .real, .wait_all = false, .target_commits = 80, .timeout_ms = 120_000, .restart_node = 2, .restart_after_commits = 20, .restart_down_ms = 1_000, .restart_torn = true, .protocol_version = 141 });
    defer rep.deinit(gpa);
    try std.testing.expect(rep.consistent);
    try std.testing.expect(rep.ok);
    try std.testing.expect(rep.event.?.recover_ms != null);
    for (rep.nodes) |n| try std.testing.expectEqual(@as(u64, 0), n.blocks_invalid);
}

test "real committee: a partitioned node (blackhole, then drop) catches up after healing" {
    const gpa = std.testing.allocator;
    for ([_]proxy.CutMode{ .blackhole, .drop }) |mode| {
        var rep = try run(gpa, std.testing.io, .{ .n = 4, .mode = .real, .wait_all = false, .target_commits = 80, .timeout_ms = 120_000, .partition_node = 1, .partition_after_commits = 20, .partition_ms = 3_000, .partition_mode = mode, .protocol_version = 141 });
        defer rep.deinit(gpa);
        try std.testing.expect(rep.consistent);
        try std.testing.expect(rep.ok);
        const e = rep.event.?;
        // The other three keep committing while node 1 is cut off (they hold 2f+1).
        try std.testing.expect(e.others_min_at_end > e.others_min_at_start);
        try std.testing.expect(e.recover_ms != null);
        for (rep.nodes) |n| try std.testing.expectEqual(@as(u64, 0), n.blocks_invalid);
    }
}

test {
    _ = proxy;
}

test "real committee at 141: a node partitioned past its cached rounds catches up through commit sync" {
    // Fails with MissingBlock in tryDirectFinalizeCommit unless commit sync puts the certified
    // commits' blocks into the vote tracker (commit_syncer.rs fetch_once step 10).
    const gpa = std.testing.allocator;
    var rep = try run(gpa, std.testing.io, .{ .n = 4, .mode = .real, .wait_all = false, .target_commits = 80, .timeout_ms = 60_000, .partition_node = 1, .partition_after_commits = 20, .partition_ms = 6_000, .protocol_version = 141, .dag_state_cached_rounds = 10, .commit_sync_batch_size = 5 });
    defer rep.deinit(gpa);
    try std.testing.expect(rep.consistent);
    try std.testing.expect(rep.ok);
    try std.testing.expect(rep.event.?.recover_ms != null);
}
