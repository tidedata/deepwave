//! The deepwave full node: one process, every stage wired over one store.
//!
//!   source (S3 archive | our node | local dir) --fetchers--> spool/<seq>.chk
//!        --> sync.Follower: index, digests, output objects vs effects (N workers), BLS
//!            certificate, chain link, epoch rule, committee hand-over (ordered stage)
//!        --> observer: persist the next epoch's committee at an epoch end; execute mode runs exec
//!        --> store: one durable commit group per checkpoint
//!        --> serve: sui.rpc.v2 from store snapshots;  metrics: Prometheus text on scrape
//!
//! Restart and crash recovery. The store recovers its durable prefix on open (one commit group
//! per checkpoint, so a crash mid-checkpoint loses that checkpoint and nothing else). The
//! follower's anchor is derived from the last committed checkpoint: its summary digest is the
//! next chain link, its epoch names the committee, and an end-of-epoch summary carries the next
//! committee itself. Committees are persisted before the end-of-epoch batch is committed
//! (trust.zig), so every committed checkpoint's epoch has a committee on disk. The spool is a
//! per-process cache and is emptied at start.
const std = @import("std");
const move_vm_aot = @import("move_vm").aot;
const core = @import("core");
const Io = std.Io;
const store = @import("store");
const sync = @import("sync");
const serve = @import("serve");
const native = @import("native");
const edge = @import("edge");
const index = @import("index");
const lhist = @import("history");
const lhfill = @import("lhfill.zig");
const types = @import("types");
const checkpoint = @import("checkpoint");
const source_mod = @import("source.zig");
const edge_certs = @import("edge_certs.zig");
const s3 = @import("s3.zig");
const http = @import("http.zig");
const stream_mod = @import("stream.zig");
const sigorder = @import("sigorder.zig");
const p2p_mod = @import("p2p.zig");
const reconcile_mod = @import("reconcile.zig");
const reask_mod = @import("reask.zig");
const p2p_serve = @import("p2p_serve.zig");
const p2p_config = @import("p2p_config.zig");
pub const ops = @import("ops.zig");
const trust = @import("trust.zig");
const execute = @import("execute.zig");
const memstat = @import("memstat.zig");
const stageprof = @import("stageprof.zig");
const convert = @import("convert.zig");
const exec = @import("exec");
const rpc = @import("rpc.zig");
const native_hooks = @import("native_hooks.zig");
const native_pass = @import("native_pass.zig");
const gate_mod = @import("gate.zig");
const simulate = @import("simulate");
const history = @import("history.zig");
const snapshot = @import("snapshot.zig");
const snapwrite = @import("snapwrite.zig");
const dbcheckpoint = @import("dbcheckpoint.zig");
pub const network = @import("network.zig");
pub const Network = network.Network;
pub const rpcmetrics = @import("rpcmetrics.zig");
/// sui-node's checkpoint executor, state sync and pruner families (lane ops-metrics).
pub const opsmetrics = @import("opsmetrics.zig");
pub const statehash = @import("statehash.zig");
pub const upgrade = @import("upgrade.zig");
pub const handoff = @import("handoff.zig");
pub const conservation = @import("conservation.zig");
pub const admin = @import("admin.zig");
const admin_store = @import("admin_store.zig");
pub const logfilter = @import("logfilter.zig");
/// RUST_LOG_JSON / RUST_LOG_FILE output (telemetry-subscribers).
pub const logout = @import("logout.zig");
/// Optional metrics push (sui-metrics-push-client).
pub const metricspush = @import("metricspush.zig");
const protocol = @import("protocol");
const retention = @import("retention.zig");
const fast_start = @import("fast_start.zig");
const restore_index = @import("restore_index.zig");
const Atomic = std.atomic.Value;

pub const Mode = enum { verify, execute };
pub const Start = union(enum) { auto, tip, seq: u64 };

/// `Config.age_out` (`--age-out on|off|defer`).
pub const AgeOut = enum {
    off,
    on,
    deferred,

    pub fn parse(text: []const u8) ?AgeOut {
        if (std.mem.eql(u8, text, "on")) return .on;
        if (std.mem.eql(u8, text, "off")) return .off;
        if (std.mem.eql(u8, text, "defer")) return .deferred;
        return null;
    }

    /// The mode after ZUI_AGE_OUT (`env`, null when unset): on, off or defer by name; 1 turns
    /// age-out on in the configured mode (always-on unless the configuration says defer), 0
    /// and anything else that is a number turn it off or on the same way.
    pub fn withEnv(configured: AgeOut, env: ?[]const u8) AgeOut {
        const v = env orelse return configured;
        if (parse(v)) |m| return m;
        const n = std.fmt.parseInt(u32, v, 10) catch return configured;
        if (n == 0) return .off;
        return if (configured == .off) .on else configured;
    }
};

test "age-out mode: the flag's values and ZUI_AGE_OUT" {
    const t = std.testing;
    try t.expectEqual(AgeOut.on, AgeOut.parse("on").?);
    try t.expectEqual(AgeOut.off, AgeOut.parse("off").?);
    try t.expectEqual(AgeOut.deferred, AgeOut.parse("defer").?);
    try t.expect(AgeOut.parse("--serve") == null);
    // Unset: what the flag or the profile said.
    try t.expectEqual(AgeOut.deferred, AgeOut.withEnv(.deferred, null));
    // 0 and off force it off; 1 keeps the configured mode, or turns a node without one on.
    try t.expectEqual(AgeOut.off, AgeOut.withEnv(.deferred, "0"));
    try t.expectEqual(AgeOut.off, AgeOut.withEnv(.on, "off"));
    try t.expectEqual(AgeOut.deferred, AgeOut.withEnv(.deferred, "1"));
    try t.expectEqual(AgeOut.on, AgeOut.withEnv(.off, "1"));
    // By name it overrides the profile either way.
    try t.expectEqual(AgeOut.on, AgeOut.withEnv(.deferred, "on"));
    try t.expectEqual(AgeOut.deferred, AgeOut.withEnv(.off, "defer"));
    try t.expectEqual(AgeOut.on, AgeOut.withEnv(.on, "junk"));
}

pub const SnapshotSpec = struct {
    epoch: ?u64 = null,
    /// `--snapshot retained` (epoch null): the newest snapshot old enough that following from it
    /// holds every checkpoint and object version a sui-node with the same retention holds
    /// (snapshot epoch <= current - retention epochs). `latest` starts with less history than
    /// sui-node for up to two epochs: its lowest available checkpoint is S + 1 while sui-node's
    /// smoothed floor is still inside the epochs before S.
    retained: bool = false,
    /// Null: the network's formal snapshot bucket (network.zig).
    origin: ?snapshot.Origin = null,
    threads: u32 = 8,
    /// Tests only: accept this root instead of the certified commitment.
    expect_root: ?[32]u8 = null,
};

/// `bucket` null: the network's archive (network.zig).
pub const S3Spec = struct { profile: []const u8 = "default", credentials: ?[]const u8 = null, budget_usd: f64 = 5, bucket: ?[]const u8 = null };

pub const SourceSpec = union(enum) {
    dir: []const u8,
    s3: S3Spec,
    /// Mysten's public bucket (http.zig). `fallback`: S3 for failed requests and checkpoints
    /// older than its 30-day window; used only when its credentials load (else a warning).
    /// `base` null: the network's public bucket (network.zig).
    http: struct { base: ?[]const u8 = null, fallback: ?S3Spec = .{} },
    /// Core (or other edge) nodes over zui/1 (`--source zui1:ADDR:PORT/KEYHEX[,...]`, docs/EDGE.md).
    zui1: Zui1Spec,
};

pub const Zui1Spec = struct {
    /// `ADDR:PORT/KEYHEX[,...]` (edge.client.parseSpecs).
    cores: []const u8,
    /// Connections kept to the cores (`--edge-conns`).
    max_conns: u32 = 4,
    /// Ask for zstd frames with the cores' dictionary (`--no-edge-zstd` turns it off).
    zstd: bool = true,
    /// The most feed requests in flight at the cores during catch-up (`--feed-max-inflight`;
    /// edge/inflight.zig sets the count from what the edge measures). 0: one per fetch thread,
    /// always, as before it existed. Keep it well under the core's feed queue (64 for all its
    /// clients together) divided by the number of edges: one edge at 64 could fill the queue.
    max_inflight: u32 = 16,
    /// Where checkpoints come from while no core can serve them (`--edge-fallback`).
    fallback: EdgeFallbackSpec = .off,
    /// The switch rules' numbers (edge/fallback.zig; tests shorten them).
    tuning: edge.fallback.Tuning = .{},
};

/// `--edge-fallback off | http[:URL] | dir:PATH` (docs/EDGE.md section 10).
pub const EdgeFallbackSpec = union(enum) {
    /// The cores are the only source: an outage of every core stalls the edge (as before).
    off,
    /// The public checkpoint bucket, the `--source http` path without S3 behind it (an edge
    /// holds no credentials and spends nothing). `base` null: the network's bucket.
    http: struct { base: ?[]const u8 = null },
    /// A directory of `<seq>.chk` or `<seq>.binpb.zst` files (a local mirror; tests).
    dir: []const u8,
};

/// `--rpc-release` value: `1.83`, `1.83.1`, `v1.84.0` or a max protocol version (serve protocfg).
pub const parseRpcRelease = serve.protocfg.parseRelease;

pub const Config = struct {
    /// Node directory: `store/`, `node/epochs/`, `node/spool/`, `node/spend.jsonl`.
    dir: []const u8,
    /// The chain followed (`--network`): chain id, protocol table, buckets, snapshot origin,
    /// stream full node and p2p server name default from it (network.zig).
    network: Network = .mainnet,
    mode: Mode = .verify,
    source: SourceSpec,
    /// Background age-out (store holes + punches, `--age-out on|off|defer` or ZUI_AGE_OUT). Off
    /// by default until the real-store proof; off, the store behaves
    /// as before. `deferred` (the edge and macmini profiles): on, but waiting while the node is
    /// far behind the tip (`noteLag`, store `AgeMode.deferred`).
    age_out: AgeOut = .off,
    /// Extra local directory tried first for end-of-epoch checkpoints during the trust walk.
    trust_dir: ?[]const u8 = null,
    /// Mainnet `genesis.blob` (the trust root) and an epoch index (hint for the walk).
    genesis: ?[]const u8 = null,
    epochs_index: ?[]const u8 = null,
    /// Past epochs whose GetEpoch records node start fills from their end-of-epoch checkpoints
    /// (verified by the trust walk) when the store did not follow them: sui-node answers GetEpoch
    /// for every epoch its rpc-store indexed (never pruned; the box: 1295 onward on 2026-11-08).
    /// 0 turns it off.
    epoch_records: u64 = 30,
    start: Start = .auto,
    /// Stop after applying this checkpoint (catch-up runs and tests); null follows forever.
    to: ?u64 = null,
    serve_addr: ?[]const u8 = null,
    /// sui.rpc.v2 over TLS 1.3 on a second TCP port (native/tcptls.zig), with --serve. sui-node's
    /// `rpc.https-address` (default 0.0.0.0:9443) when fullnode.yaml sets `rpc.tls`.
    serve_tls_addr: ?[]const u8 = null,
    /// `rpc.tls.cert` / `rpc.tls.key`: PEM certificate chain and private key for --serve-tls
    /// (loaded again on SIGHUP or a file change, native/certs.zig).
    /// Both null: a self-signed P-256 certificate for `localhost` (13 days, dev and bench).
    serve_tls_cert: ?[]const u8 = null,
    serve_tls_key: ?[]const u8 = null,
    /// `rpc.subscription-max-subscribers` / `rpc.subscription-watermark-interval` (subscribe.zig).
    sub_max_subscribers: ?usize = null,
    sub_watermark_interval: ?u32 = null,
    /// zui/1 native protocol (raw QUIC ALPN zui/1 + WebTransport, docs/NATIVE-PROTOCOL.md); off when null.
    native_listen: ?[]const u8 = null,
    /// Write the WebTransport certificate's SHA-256 (hex) here at startup (dev: serverCertificateHashes).
    native_cert_hash_file: ?[]const u8 = null,
    /// `--native-cert` and `--native-key`: a PEM chain and key the zui/1 listener presents instead
    /// of its self-signed certificate (native/certs.zig; reloaded on SIGHUP or a file change).
    native_cert: ?[]const u8 = null,
    native_key: ?[]const u8 = null,
    /// zui/1 Ed25519 identity seed (32 raw bytes, 0600; created on first start). Clients and
    /// edges pin the key it derives, so it must survive restarts. Null: `<dir>/node/native-identity.seed`.
    native_identity_file: ?[]const u8 = null,
    /// zui/1 API keys and the Agent Passes bound to them (`<key> <tier> [<pass hex>]` per line,
    /// docs/NATIVE-PROTOCOL.md 6.1). Null: everyone is anonymous, no pass.
    native_keys: ?[]const u8 = null,
    /// Where the passes keep their ledgers. Null: `<dir>/node/agent-pass`.
    native_pass_dir: ?[]const u8 = null,
    /// `--native-feed-workers`, `--native-feed-queue`: the zui/1 listener's edge feed pool, its
    /// threads and the feed requests it holds (queued or running) for all clients together.
    /// The queue is divided between the clients with requests in flight (native/fairq.zig).
    native_feed_workers: u32 = 4,
    native_feed_queue: u32 = 64,
    /// StateService indexes (lane indexes, DROP-IN G4): built in memory from the live set at start
    /// (needs RAM for every owned object), then fed per checkpoint. Off: StateService is UNIMPLEMENTED.
    indexes: bool = false,
    /// Serve the edge feed and its dictionary on the zui/1 listener (`--edge-feed`, docs/EDGE.md):
    /// what makes this node a feed for edges. Off by default.
    edge_feed: bool = false,
    /// `--core-upstream`: the core's sui.rpc.v2 gRPC address (edge/forward.zig `parseUpstream`).
    /// With `--serve`, the node then answers what it holds exactly and passes every other
    /// request to the core (docs/EDGE.md section 11). Null: every request is answered locally,
    /// as before.
    core_upstream: ?[]const u8 = null,
    /// `--core-upstream-pin`: SHA-256 of the core's TLS certificate (hex), when not in the address.
    core_upstream_pin: ?[]const u8 = null,
    /// `--edge-forward off`: keep the upstream configured and answer everything locally.
    edge_forward: bool = true,
    /// `--edge-execute-wait-ms`, `--edge-max-lag`, `--edge-ahead-wait-ms`, `--edge-raw`.
    edge_forward_cfg: edge.forward.Config = .{},
    /// `--edge-raw-waiters` was given (else the bound follows the serve worker pool).
    edge_raw_waiters_set: bool = false,
    /// `POST /zui1/rpc` on the native listen address over TCP (`--native-http-rpc`, certhttp.zig):
    /// zui/1 requests over plain HTTP for Workers and fetch callers, behind a TLS terminator.
    native_http_rpc: bool = false,
    /// `--gate` and its flags (docs/GATE.md): API keys, rate limits and usage metering for a
    /// node that serves the public, against an external gate service. Null: no gate, and
    /// serving is byte for byte what it is without this field.
    gate: ?gate_mod.Settings = null,
    metrics_addr: ?[]const u8 = null,
    /// sui-node `metrics.push-url`: POST the registry there (protobuf, snappy) every interval.
    metrics_push_url: ?[]const u8 = null,
    /// sui-node `metrics.push-interval-seconds` (default 60).
    metrics_push_interval_s: u64 = 60,
    workers: u32 = 0,
    /// Certificate pairing checks decided as randomized batches of up to this many checkpoints
    /// (sync.follower `Config.cert_batch`; same verdicts). 0: one check per worker, as before.
    cert_batch: u32 = 0,
    fetchers: u32 = 8,
    window: u32 = 64,
    /// `--net-max-mbps`: download cap in MiB per second for checkpoint fetches and the snapshot
    /// restore together (http.ByteBucket); 0: none.
    net_max_mbps: u32 = 0,
    /// Tip poll interval: one frontier request every poll_ms across all fetcher threads. Null:
    /// 25 for the public bucket (free requests), 100 for S3 (requester pays) and directories.
    poll_ms: ?u32 = null,
    /// At the tip: sequence numbers past the frontier that get one immediate request each time
    /// it moves (archive bursts; `Fetcher.lookahead`). Burst tries (4) on us-west-2, 2026-11-07,
    /// 8,091 checkpoints: arrival 26 ms earlier on mean, 133 ms at p10, for 2.15x the GETs; the
    /// per-frontier-move form at 2 ran both ops-live acceptance runs.
    lookahead: u32 = 2,
    /// Execute mode: stop at the first transaction whose result differs from the certified one.
    halt_on_mismatch: bool = true,
    status_every_s: u32 = 10,
    sync_mode: store.SyncMode = .data,
    /// Chain identifier (digest of checkpoint 0) GetServiceInfo reports; default the network's.
    chain_id: ?[32]u8 = null,
    /// Serve: GetEpoch `protocol_config` lists the fields of this sui-node release, given as its max
    /// protocol version (`--rpc-release`; default sui-node 1.83.1, the drop-in target). Raised to
    /// the chain's current protocol version when that is newer (serve `protocfg.effectiveRelease`).
    rpc_release_max: u64 = serve.protocfg.drop_in_release_max,
    /// Pre-encoded GetCheckpoint response cache budget (`--cp-cache-mb`; serve/cpcache.zig).
    cp_cache_bytes: u64 = 256 << 20,
    /// Keep fetched blobs (`<seq>.chk`, `<seq>.aux`) in the spool after commit, so `deepwave check
    /// --against DIR/node/spool` can compare the whole store after a live run.
    keep_spool: bool = false,
    /// Live checkpoint stream (stream.zig) racing the source's tip polling: a full node's base
    /// URL serving gRPC-web, or null for none. main.zig turns it on for the http source.
    stream: ?[]const u8 = null,
    /// Requests a second to the first stream's full node for the submitted signature order of
    /// bucket checkpoints with sponsored or multi-signer transactions (`--sig-order-rps`,
    /// sigorder.zig; 0: off, the contents order is stored).
    /// null: 20 for a remote node, `sigorder.loopback_rps` for one on this host (sui-node's
    /// standby in the shadow phase, no public limits to respect).
    sig_order_rps: ?u32 = null,
    /// The node asked (`--sig-order-from URL`); null: the first loopback `--stream` URL, else the
    /// first one (sigorder.pickBase).
    sig_order_from: ?[]const u8 = null,
    /// Sweep the committed checkpoints for transactions stored in the contents' signature order
    /// and serve the node's order instead (sigorder.Sweep; `--sig-order-sweep off`). Needs the
    /// signature-order node above.
    sig_order_sweep: bool = true,
    /// p2p state-sync peers (`host:port@peerid,...`, p2p.zig) racing the source and the streams.
    p2p: ?[]const u8 = null,
    /// Ed25519 network key seed file for p2p (random identity when null).
    p2p_key: ?[]const u8 = null,
    /// p2p: log each applied checkpoint's p2p timeline (`--p2p-trace`).
    p2p_trace: bool = false,
    /// p2p: peers asked for a checkpoint's contents at once (`--p2p-race`).
    p2p_race: u8 = 1,
    /// p2p: active set, the peers contents come from (`--p2p-push-peers`, 0: all; p2p.zig `push_peers`).
    p2p_push_peers: u8 = 8,
    /// p2p: peers to add from the seeds' known peers (`--p2p-discover`, 0: seeds only).
    p2p_discover: u8 = 32,
    /// p2p: threads executing a checkpoint's independent transactions (`--p2p-exec-threads`).
    p2p_exec_threads: u8 = 4,
    /// p2p tip path as a pipeline of pinned tiles on rings (`--tiles`, p2p_tiles.zig); off: the exec thread.
    tiles: bool = false,
    /// Cores for the tiles in pipeline order, comma separated (`--tile-cpus 2,3,4,5,6`).
    tile_cpus: ?[]const u8 = null,
    /// Tiles never sleep when idle (`--tile-spin`).
    tile_spin: bool = false,
    /// p2p: seconds a checkpoint built here waits for the stream's copy before the bucket's is
    /// fetched to compare its read sets with sui-node's (`--p2p-reconcile-wait S`, reconcile.zig;
    /// 0: no reconcile).
    p2p_reconcile_wait_s: u32 = 10,
    /// p2p only (`--p2p-only`, p2p_only.zig): no bucket, S3 or stream; needs a store to resume.
    p2p_only: bool = false,
    /// p2p `pinned-checkpoints` (`--p2p-pinned SEQ:DIGEST,...`).
    p2p_pinned: ?[]const u8 = null,
    /// Inbound anemo listener serving state sync and discovery (`--p2p-listen ADDR:PORT`, off).
    p2p_listen: ?[]const u8 = null,
    /// Address advertised in our signed node info (`--p2p-external`).
    p2p_external: ?[]const u8 = null,
    /// Advertised access type (`--p2p-access`; default public with an external address).
    p2p_access: ?@import("net").discovery.AccessType = null,
    /// Inbound request workers (`--p2p-listen-threads`, 0: auto).
    p2p_listen_threads: u16 = 0,
    /// sui-node `p2p-config` knobs (`--p2p-opt KEY=VALUE`, p2p_config.zig).
    p2p_tuning: p2p_config.Tuning = .{},
    /// Execute mode: threads running transactions (null: `Executor.defaultThreads`, half the
    /// CPUs; 0: on the follower's ordered thread, one at a time) and checkpoints in flight.
    exec_threads: ?u32 = null,
    exec_window: u32 = 64,
    /// Execute mode: memory all threads' Move package caches share (`--exec-cache-mb`).
    exec_cache_mb: u32 = 3072,
    /// Execute mode: checkpoint bytes in flight (`--exec-window-mb`), besides `exec_window`.
    exec_window_mb: u32 = 128,
    /// Start an empty store from a formal snapshot (snapshot.zig): the live object set at the end
    /// of `epoch` (null: the newest the origin has), then follow from the next epoch's first
    /// checkpoint. Ignored when the store already has data.
    snapshot: ?SnapshotSpec = null,
    /// Store each checkpoint's read set (input object versions and loaded runtime object lists) for
    /// serve's effects/objects masks (history.zig).
    read_sets: bool = true,
    /// Read sets through the edge feed (`--edge-read-sets on`, docs/EDGE.md section 12). On a
    /// node with read sets that serves the feed: checkpoints are marked as they are stored and
    /// their loaded runtime object lists go out with the feed to clients that ask. On a node
    /// with a zui1 source: it asks its cores for them, keeps read sets built from them and its
    /// own store, and answers effects, balance_changes and objects itself where it holds them.
    /// Off (the default): neither, and every byte stored and sent is as before.
    edge_read_sets: bool = false,
    /// Execute mode: a directory of `<id hex>.obj` package objects, tried before the store for
    /// packages the node has not seen in a followed checkpoint (`--packages`).
    packages_dir: ?[]const u8 = null,
    /// Execute mode: a full node (gRPC-web base URL) asked for packages found nowhere else
    /// (`--packages-from`, pkgfetch.zig); with `packages_dir` they are saved there.
    packages_from: ?[]const u8 = null,
    /// Execute mode: exec's deny-list state file (`deny/objects.bin.zst`) for a store that does
    /// not hold the full live set (`--deny-state`); see execute.zig `Lookup.latest`.
    deny_state: ?[]const u8 = null,
    /// `--dev-inspect-disabled true|false` (fullnode.yaml `dev-inspect-disabled`): true refuses
    /// SimulateTransaction with checks disabled as sui-node does, false runs it as DevInspect<true>;
    /// null (not given) is `rpc_exec.simulate.Engine.default_dev_inspect`.
    dev_inspect_disabled: ?bool = null,
    /// Execute mode: per-transaction verdicts (the `node-execute` suite).
    report: ?execute.Report = null,
    store_cfg: store.Config = .{},
    /// `uptime`'s version label (`<version>-<sha>`; main.zig fills in the build's sha).
    version_label: []const u8 = ops.version,
    /// Admin port on 127.0.0.1 (admin.zig); null: none. sui-node's default is 1337.
    admin_port: ?u16 = null,
    /// Per-epoch state-hash check (statehash.zig): what a mismatch does.
    state_hash: statehash.Policy = .verify_only,
    /// `--verify-fallback`: on a protocol this binary cannot execute, keep following and serving,
    /// pause execution and the state-hash halt (upgrade.zig). Alert lines are always on; the zui_protocol_* metrics only with this flag.
    verify_fallback: bool = false,
    /// `--handoff-sock PATH`: zero-downtime binary upgrade (handoff.zig); null: off.
    handoff_sock: ?[]const u8 = null,
    /// SUI conservation check at every end of epoch (conservation.zig): what a failure does.
    /// Off by default, as sui-node 1.83.1: `ExpensiveSafetyCheckConfig::default()` has
    /// `enable_epoch_sui_conservation_check` false, on only in debug builds (cfg!(debug_assertions))
    /// or by node config. It scans the whole live set (772M objects at epoch 1305).
    sui_conservation: conservation.Policy = .off,
    /// The :9000 transport limits (serve/h2/server.zig), set here to sui-node 1.83.1's values
    /// (sui-http 0.3.1 `Config::default`, tonic, sui-rpc-api `RpcConfig` defaults; a production node's
    /// fullnode.yaml sets none of them). Checked by the transport limit tests.
    serve_opts: serve.h2.ServerOptions = sui_node_limits,
    /// SIGTERM/SIGINT: how long open RPC connections get to finish their calls and streams
    /// (h2 GOAWAY grace, HTTP/1.1 response in flight) before the follower stops and the store
    /// flushes. A second signal skips what is left of it.
    drain_ms: u32 = 20_000,
    /// The whole shutdown (drain, follower stop, store flush) is cut at this many seconds, under
    /// the unit's TimeoutStopSec (120): past it the node exits without the flush (crash-safe).
    shutdown_timeout_s: u32 = 110,
    /// Ledger-history limits (`rpc.ledger-history.*` of fullnode.yaml); null: sui-node's defaults.
    lh_cfg: ?serve.lh_service.Config = null,
    /// Formal snapshot producer (`state-snapshot-write-config`): at the end of every epoch, write
    /// `<dir>/epoch_<E>/` from the store (snapwrite.zig).
    snapshot_write: ?[]const u8 = null,
    /// Where the rpc index and the ledger-history index live (with --serve); default DIR/rpc and
    /// DIR/ledger-history. Every path deepwave writes: DIR/store, DIR/node (LOCK, epochs, spool,
    /// snapshot marker, spend.jsonl), these two, and --snapshot-write.
    rpc_dir: ?[]const u8 = null,
    history_dir: ?[]const u8 = null,
    /// `--no-history-backfill` (also ZUI_LH_BACKFILL=0): never start the ledger-history backfill.
    /// The index serves what it holds; the node says which checkpoints are not indexed.
    lh_backfill: bool = true,
    /// 0: snapwrite.defaultThreads (half the cores, 4 to 16).
    snapshot_write_threads: u32 = 0,
};

/// sui-node 1.83.1's limits on its RPC port (docs/FULLNODE-PARITY.md task 9):
/// - 200 concurrent streams per h2 connection (sui-http DEFAULT_MAX_CONCURRENT_STREAMS);
/// - 4 MiB decoded request message (tonic's default max_decoding_message_size);
/// - 60 s server timeout per call, or a shorter `grpc-timeout` (`grpc-timeout-ms`, GrpcTimeout);
/// - 30 s HTTP/1.1 header read (DEFAULT_HTTP1_HEADER_READ_TIMEOUT_SECS);
/// - max connection age 4 h + 10 min grace (RpcConfig defaults);
/// - listen backlog 128 (Rust std's TcpListener; `ss -ltn` on the box shows 128 on :9000). The
///   4096 "pending connections" of sui-http bounds TLS handshakes only, and :9000 has no TLS;
/// - no keepalive PINGs.
pub const sui_node_limits: serve.h2.ServerOptions = .{
    .h2 = .{ .max_streams = 200, .max_request_bytes = 4 << 20, .default_timeout_ns = 60 * std.time.ns_per_s },
    .web = .{ .max_request_bytes = 4 << 20, .idle_ns = 30 * std.time.ns_per_s, .default_timeout_ns = 60 * std.time.ns_per_s },
    .max_age_ns = 4 * 3600 * std.time.ns_per_s,
    .age_grace_ns = 10 * 60 * std.time.ns_per_s,
    .keepalive_ns = null,
    .max_connections = 16384,
    .max_pumps = 2048,
    .workers = 0,
};
pub const listen_backlog: u31 = 128;

/// `--rpc KEY=VALUE` (fullnode.yaml `rpc.*` scalars, sui-config `RpcConfig`): sets one RPC port
/// option. `grpc-timeout-ms` (default 60000, 0 = no server timeout; a client `grpc-timeout`
/// still applies), `max-connection-age-secs` (default 14400, 0 = connections live forever),
/// `max-connection-age-grace-secs` (default 600), `subscription-watermark-interval` (default 25,
/// 0 counts as 1, as sui-node clamps it), `subscription-max-subscribers` (default 1024).
pub fn setRpc(c: *Config, kv: []const u8) !void {
    const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return error.BadRpcOption;
    const key = kv[0..eq];
    const v = std.fmt.parseInt(u64, kv[eq + 1 ..], 10) catch return error.BadRpcOption;
    const o = &c.serve_opts;
    const eql = std.mem.eql;
    if (eql(u8, key, "grpc-timeout-ms")) {
        const t: ?u64 = if (v == 0) null else std.math.mul(u64, v, std.time.ns_per_ms) catch std.math.maxInt(u64);
        o.h2.default_timeout_ns = t;
        o.web.default_timeout_ns = t;
    } else if (eql(u8, key, "max-connection-age-secs")) {
        o.max_age_ns = if (v == 0) null else std.math.mul(u64, v, std.time.ns_per_s) catch std.math.maxInt(u64);
    } else if (eql(u8, key, "max-connection-age-grace-secs")) {
        o.age_grace_ns = std.math.mul(u64, v, std.time.ns_per_s) catch std.math.maxInt(u64);
    } else if (eql(u8, key, "subscription-watermark-interval")) {
        c.sub_watermark_interval = @intCast(@max(1, @min(v, std.math.maxInt(u32))));
    } else if (eql(u8, key, "subscription-max-subscribers")) {
        c.sub_max_subscribers = std.math.cast(usize, v) orelse return error.BadRpcOption;
    } else return error.BadRpcOption;
}

test "setRpc: sui-node RpcConfig scalars" {
    var c: Config = .{ .dir = "", .source = .{ .dir = "" } };
    try setRpc(&c, "grpc-timeout-ms=1500");
    try std.testing.expectEqual(@as(?u64, 1500 * std.time.ns_per_ms), c.serve_opts.h2.default_timeout_ns);
    try std.testing.expectEqual(@as(?u64, 1500 * std.time.ns_per_ms), c.serve_opts.web.default_timeout_ns);
    try setRpc(&c, "grpc-timeout-ms=0");
    try std.testing.expectEqual(@as(?u64, null), c.serve_opts.h2.default_timeout_ns);
    try setRpc(&c, "max-connection-age-secs=0");
    try std.testing.expectEqual(@as(?u64, null), c.serve_opts.max_age_ns);
    try setRpc(&c, "max-connection-age-grace-secs=5");
    try std.testing.expectEqual(@as(u64, 5 * std.time.ns_per_s), c.serve_opts.age_grace_ns);
    try setRpc(&c, "subscription-watermark-interval=0");
    try std.testing.expectEqual(@as(?u32, 1), c.sub_watermark_interval);
    try setRpc(&c, "subscription-max-subscribers=7");
    try std.testing.expectEqual(@as(?usize, 7), c.sub_max_subscribers);
    try std.testing.expectError(error.BadRpcOption, setRpc(&c, "nope=1"));
    try std.testing.expectError(error.BadRpcOption, setRpc(&c, "grpc-timeout-ms=x"));
    try std.testing.expectError(error.BadRpcOption, setRpc(&c, "grpc-timeout-ms"));
}

/// `--ledger-history KEY=VALUE` (fullnode.yaml `rpc.ledger-history`): sets one limit.
pub fn setLedgerHistory(c: *serve.lh_service.Config, kv: []const u8) !void {
    const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return error.BadLedgerHistory;
    const key = kv[0..eq];
    const v = try std.fmt.parseInt(u64, kv[eq + 1 ..], 10);
    if (std.mem.eql(u8, key, "bitmap-bucket-scan-budget")) {
        c.bitmap_bucket_scan_budget = @intCast(v);
    } else if (std.mem.eql(u8, key, "chunk-bucket-scan-budget")) {
        c.chunk_bucket_scan_budget = @intCast(v);
    } else if (std.mem.eql(u8, key, "max-bitmap-filter-literals")) {
        c.max_filter_literals = @intCast(v);
    } else {
        const dot = std.mem.indexOfScalar(u8, key, '.') orelse return error.BadLedgerHistory;
        const list = key[0..dot];
        const field = key[dot + 1 ..];
        const lim = if (std.mem.eql(u8, list, "list-transactions")) &c.transactions else if (std.mem.eql(u8, list, "list-events")) &c.events else if (std.mem.eql(u8, list, "list-checkpoints")) &c.checkpoints else return error.BadLedgerHistory;
        if (std.mem.eql(u8, field, "timeout-ms")) {
            lim.timeout_ms = v;
        } else if (std.mem.eql(u8, field, "default-limit-items")) {
            lim.default_limit = @intCast(v);
        } else if (std.mem.eql(u8, field, "max-limit-items")) {
            lim.max_limit = @intCast(v);
        } else if (std.mem.eql(u8, field, "chunk-max")) {
            lim.chunk_max = @intCast(v);
        } else return error.BadLedgerHistory;
    }
}

/// Digest of mainnet checkpoint 0.
pub const mainnet_chain_id_b58 = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S";
pub const mainnet_chain_id: [32]u8 = blk: {
    @setEvalBranchQuota(100_000);
    break :blk serve.b58.decode32(mainnet_chain_id_b58).?;
};

/// Set by SIGINT/SIGTERM; `signals` counts them (a second one skips the RPC drain).
pub var stop_signal: Atomic(bool) = .init(false);
pub var signals: Atomic(u32) = .init(0);

/// Seconds from the first SIGINT/SIGTERM to a forced exit (`ZUI_STOP_DEADLINE_S`, default 8),
/// read at install time (getenv is not async-signal-safe).
var stop_deadline_s: c_uint = 8;
/// Added to the first deadline while the RPC server is up: its drain (`Config.drain_ms` + 2 s)
/// comes before the stop, and `gracefulStop` re-arms `stop_deadline_s` once it ends, so a stop
/// with no connections open still exits within the deadline.
var stop_drain_s: c_uint = 0;
/// While a successor takes the store (handoff.zig) the stop deadline is this long instead
/// (`ZUI_HANDOFF_RELEASE_DEADLINE_S`): an _exit of the old process mid-close would be the unit's
/// main process ending, and the store close of a big store takes longer than 8 s.
var release_deadline_s: c_uint = 120;

fn deadlineS() c_uint {
    return if (handoff.isReleasing()) @max(stop_deadline_s, release_deadline_s) else stop_deadline_s;
}

/// Seconds the store close may take once a stop reaches it (`ZUI_STOP_CLOSE_DEADLINE_S`, default
/// 60): `closeDeadline` re-arms the timer with it. The stop deadline bounds what must be quick
/// (threads to join, nothing that waits on the network); the close is the one step whose length
/// follows the work left, the live-table pages changed since the last flush written twice and
/// synced, after a background flush in progress ends. In catch-up on a slow volume that is more
/// than 8 s, and an exit in the middle of it saved seconds and cost minutes: the next start
/// checks every page of the live table (156 s for 19.6 GiB on an edge box, 2026-11-10).
var close_deadline_s: c_uint = 60;

/// What the stop is doing (`stopPhase`), for the deadline's last words: a stop that runs out of
/// time says where.
var stop_phase: Atomic(?[*:0]const u8) = .init(null);

fn stopPhase(name: [*:0]const u8) void {
    stop_phase.store(name, .release);
}

/// Seconds the timer is armed with when a stop reaches the store close.
pub fn closeDeadlineS() c_uint {
    return @max(deadlineS(), close_deadline_s);
}

/// Called when a stop reaches the store close: from here the deadline is the close's own. Only
/// after a signal (no timer runs on the other ways out: `--to`, a fatal error).
pub fn closeDeadline() void {
    stopPhase("store close (final flush of the live table)");
    if (signals.load(.acquire) == 0) return;
    _ = std.c.alarm(closeDeadlineS());
}

/// The first-signal part of onSignal, callable from a thread (handoff: a successor asked for the store).
pub fn requestStop() void {
    if (signals.fetchAdd(1, .acq_rel) == 0) _ = std.c.alarm(deadlineS() + @atomicLoad(c_uint, &stop_drain_s, .acquire));
    stop_signal.store(true, .release);
}

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    // The first signal arms the deadline: a kernel timer armed from the handler (alarm is
    // async-signal-safe), not a thread: round 2's watchdog thread (64 KiB stack, spawn error
    // ignored) never ran and one stop took 19.7 s (lane fast-start). A second signal skips the
    // RPC drain (statusLoop).
    if (signals.fetchAdd(1, .acq_rel) == 0) _ = std.c.alarm(stop_deadline_s + @atomicLoad(c_uint, &stop_drain_s, .acquire));
    stop_signal.store(true, .release);
}

/// Shutdown deadline (lane fast-start): every phase stops on its own within a second or two
/// (restore, image walk, index build and merge, follow), but a phase blocked in the kernel (a
/// store open replaying its journal, a disk at 100% util) must not hold SIGTERM for systemd's
/// 120 s. `ZUI_STOP_DEADLINE_S` after the signal the process exits without a clean close; the
/// store recovers from its journal and log, a build resumes from its manifest.
fn onDeadline(_: std.posix.SIG) callconv(.c) void {
    const msg = "warning: signal: not stopped within the stop deadline; exiting without a clean close (the next start recovers)\n";
    _ = std.c.write(2, msg, msg.len);
    // Where the stop was (write and a length loop only: async-signal-safe).
    if (stop_phase.load(.acquire)) |ph| {
        const pre = "warning: signal: the stop was in: ";
        _ = std.c.write(2, pre, pre.len);
        _ = std.c.write(2, ph, std.mem.len(ph));
        _ = std.c.write(2, "\n", 1);
    }
    std.c._exit(0);
}

fn envU32(name: [*:0]const u8, default: u32) u32 {
    const v = std.c.getenv(name) orelse return default;
    return std.fmt.parseInt(u32, std.mem.span(v), 10) catch default;
}

/// What the node is doing before `run` takes over signals (statusLoop): store open and replay,
/// snapshot restore, the rpc index seed (live-set scan for package floors), ledger history.
/// None of these polls for a stop, and each can run for tens of minutes, so `startupWatch`
/// ends the process when a signal arrives meanwhile instead of letting systemd kill it at
/// TimeoutStopSec. Nothing is lost that a crash would keep: the store is append-only with a
/// journal (reopen replays it), a restore keeps its `node/snapshot` marker and retries the same
/// epoch, the rpc index and ledger history level themselves with the store on the next start.
pub var startup_phase: Atomic(?[*:0]const u8) = .init("start");
pub var startup_done: Atomic(bool) = .init(false);
/// startupWatch's thread, joined by `run` once startup is done.
var startup_thread: ?std.Thread = null;
/// Grace for a phase that does stop on its own (snapshot restore checks between parts).
pub const startup_stop_grace_ms = 3000;

fn startupPhase(name: [*:0]const u8) void {
    startup_phase.store(name, .release);
}

fn startupWatch() void {
    while (!startup_done.load(.acquire)) {
        if (signals.load(.acquire) > 0) {
            var waited: u32 = 0;
            while (waited < startup_stop_grace_ms and !startup_done.load(.acquire)) : (waited += 50) sleepMs(50);
            if (startup_done.load(.acquire)) return;
            const ph = startup_phase.load(.acquire) orelse "start";
            std.log.warn("stop signal during startup ({s}): exiting now; the store reopens from its journal and the phase resumes on the next start", .{std.mem.span(ph)});
            std.c._exit(0);
        }
        sleepMs(50);
    }
}

fn sleepMs(ms: u64) void {
    var ts: std.c.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = std.c.nanosleep(&ts, &ts);
}

/// SIGHUP with `--native-cert`: the zui/1 certificate files are loaded again (native/certs.zig
/// reads the flag four times a second). With `--serve-tls-cert`: the gRPC TLS port's files, the
/// same way. Without either SIGHUP keeps its default action.
var native_reload: std.atomic.Value(bool) = .init(false);
var serve_tls_reload: std.atomic.Value(bool) = .init(false);

fn onReloadSignal(_: std.posix.SIG) callconv(.c) void {
    native_reload.store(true, .release);
    serve_tls_reload.store(true, .release);
}

fn installReloadSignal() void {
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onReloadSignal },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(.HUP, &act, null);
}

pub fn installSignalHandlers() void {
    if (std.c.getenv("ZUI_STOP_DEADLINE_S")) |v| {
        stop_deadline_s = std.fmt.parseInt(c_uint, std.mem.span(v), 10) catch 8;
        if (stop_deadline_s == 0) stop_deadline_s = 8;
    }
    if (std.c.getenv("ZUI_HANDOFF_RELEASE_DEADLINE_S")) |v| release_deadline_s = std.fmt.parseInt(c_uint, std.mem.span(v), 10) catch 120;
    if (std.c.getenv("ZUI_STOP_CLOSE_DEADLINE_S")) |v| close_deadline_s = std.fmt.parseInt(c_uint, std.mem.span(v), 10) catch 60;
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        // SA_RESTART: the signal lands on any thread; a syscall that thread is in restarts
        // instead of failing with EINTR in code that does not expect it.
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
    const dl: std.posix.Sigaction = .{
        .handler = .{ .handler = onDeadline },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.ALRM, &dl, null);
}

pub const Node = struct {
    gpa: std.mem.Allocator,
    io: Io,
    cfg: Config,
    root: Io.Dir,
    node_dir: Io.Dir,
    epochs_dir: Io.Dir,
    spool_dir: ?Io.Dir = null,
    st: *store.Store,
    rio: *store.RealIo,
    bucket: ?*s3.Bucket = null,
    public: ?*http.Public = null,
    /// `--source zui1:`: the cores this node follows.
    edge_pool: ?*edge.client.Pool = null,
    /// `--edge-fallback`: the fallback source and its switch, and the thread that probes the
    /// cores while the edge is on the fallback.
    edge_fb: ?*source_mod.EdgeFallback = null,
    edge_prober: ?*edge.fallback.Prober = null,
    /// `--edge-feed`: the zui/1 feed state.
    edge_feeder: ?*native.edgefeed.Feeder = null,
    /// zui/1 response dictionaries (`--native-listen`): hello, get_dictionary, ZSTD responses,
    /// and the edge feed's frames. Built once by `edge_warm`.
    native_dicts: ?*native.dicts.Dicts = null,
    /// The committed checkpoint whose timestamp the metrics last read, and that timestamp.
    compat_seq: Atomic(u64) = .init(std.math.maxInt(u64)),
    compat_ts: Atomic(u64) = .init(0),
    source: source_mod.Source,
    archive: sync.archive.Archive,
    fetcher: ?*source_mod.Fetcher = null,
    /// The forwarding handler of an edge with a core upstream (`--core-upstream`); null: the
    /// service's own handler answers everything.
    edge_fwd: ?*edge.forward.Forwarder = null,
    /// A zui1 source: the checkpoints whose quorum certificate did not come from a core, and
    /// the thread that replaces them with the core's (edge_certs.zig, docs/EDGE.md section 13).
    edge_certs: ?*edge_certs.Converger = null,
    edge_fwd_transport: edge.forward.GrpcTransport = undefined,
    /// Live streams racing each other and the source's tip polling (`--stream A,B`).
    streams: std.ArrayList(*stream_mod.Stream) = .empty,
    /// Signature-order overlay for bucket checkpoints (sigorder.zig), from the first stream URL.
    sig_order: ?*sigorder.Overlay = null,
    /// Its sweep over committed checkpoints (`node/sig-order.log`).
    sig_sweep: ?*sigorder.Sweep = null,
    /// Compares the read sets of p2p-built checkpoints with sui-node's and repairs them.
    reconcile: ?*reconcile_mod.Reconciler = null,
    /// An edge that keeps read sets: asks its core again for the lists of a checkpoint that
    /// came without them (reask.zig, docs/EDGE.md 12.7).
    reask: ?*reask_mod.ReAsk = null,
    /// p2p state-sync follower (`--p2p`).
    p2p: ?*p2p_mod.P2p = null,
    /// State-sync/discovery server (p2p_serve.zig): inbound listener and outbound connections.
    p2p_server: ?*p2p_serve.Server = null,
    p2p_listener: ?*@import("net").server.Listener = null,
    follower: *sync.Follower,
    executor: ?*execute.Executor = null,
    history: ?*history.History = null,
    anchor_arena: std.heap.ArenaAllocator,
    first_seq: u64,
    /// Protocol version of the epoch being applied, and of the next one once an epoch ends.
    cur_epoch: u64 = 0,
    cur_pv: u64 = 0,
    next_pv: ?u64 = null,
    /// Reference gas price and start of the epoch being applied, and of the next one.
    cur_params: trust.EpochParams = .{},
    next_params: ?trust.EpochParams = null,
    started_ns: u64,
    stopping: Atomic(bool) = .init(false),
    service: serve.service.Service = undefined,
    /// Ledger-history index (ListCheckpoints/ListTransactions/ListEvents), opened when serving.
    ledger_history: ?*lhist.Index = null,
    /// Ledger-history backfill in progress (lhfill.zig): the retained checkpoints the index has
    /// no rows for. Started at open and after the index restarts at a hole; swapped in by the
    /// commit path once ready (`adoptBackfill`).
    lh_fill: ?*lhfill.Backfill = null,
    lh_fill_tries: u8 = 0,
    /// The last failure of a backfill try, for the line that says the backfill gave up.
    lh_fill_err: ?anyerror = null,
    /// `zui_history_backfill_state`: 0 nothing to do, 1 building, 2 gave up, 3 switched off
    /// (`LhState`).
    lh_state: Atomic(u8) = .init(0),
    /// Unix ms of the newest committed checkpoint's timestamp (0: none yet in this run): the
    /// backfill waits while the node is behind the tip by it (lhfill.zig `behindTip`).
    lh_tip_ms: Atomic(u64) = .init(0),
    /// The backfill's heap and whether it is waiting for the node, copied here by the commit
    /// path for the metrics thread (`zui_history_backfill_bytes`, `_paused`).
    lh_mem: Atomic(u64) = .init(0),
    lh_paused: Atomic(bool) = .init(false),
    /// Bytes the backfill's staging directory holds on disk
    /// (`zui_history_backfill_staging_bytes`), read again by the metrics thread at most every
    /// 30 s (`lh_staging_read_ns`, under `render_lock`) and set to 0 when it is removed.
    lh_staging_bytes: Atomic(u64) = .init(0),
    lh_staging_read_ns: u64 = 0,
    /// The backfill's staging directory (`<ledger-history>/backfill`, lhfill.zig "Durability"),
    /// and the live index generation that must be on disk before it may go.
    lh_staging: ?[]const u8 = null,
    lh_staging_gen: ?u64 = null,
    /// Lowest checkpoint the store holds (sui-node's checkpoint store: state sync's
    /// GetCheckpointAvailability, and the low end of the ledger-history index); refreshed after
    /// each prune (CONTRACTS 6.8).
    lowest: Atomic(u64) = .init(0),
    /// Lowest checkpoint the RPC surface reports and serves from (GetServiceInfo
    /// `lowest_available_checkpoint`, the floor of GetCheckpoint, GetTransaction and List*):
    /// `lowest` and the object floor, whichever is higher, as sui-node's RPC reader takes them
    /// (`snapshot.lowestServed`). A node that writes no read sets promises no object sets at any
    /// height (an edge: those masks go to its core), so its own floor stays `lowest`.
    served_lowest: Atomic(u64) = .init(0),
    lowest_known: bool = false,
    /// The store's recorded highest pruned checkpoint (a snapshot restore's S), 0 when none:
    /// `last_pruned_checkpoint` until retention moves the checkpoint floor.
    store_pruned: Atomic(u64) = .init(0),
    /// Retention (writer thread only): the last pruning tick and the epoch boundaries found.
    ret_last_ns: u64 = 0,
    ret_ticks: u64 = 0,
    ret_last: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    clean_failed: bool = false,
    clean_carried: u64 = 0,
    /// Segment cleaning's share of the writer thread (ZUI_CLEAN_SHARE percent, default 20; 0
    /// off, 100 unpaced) and its progress for the status line (lane catchup-1306).
    clean_pace: retention.Pace = .{},
    clean_phase: Atomic(u8) = .init(0),
    clean_done: Atomic(u64) = .init(0),
    clean_total: Atomic(u64) = .init(0),
    clean_table_ahead: Atomic(u64) = .init(0),
    clean_cut: Atomic(u64) = .init(0),
    clean_steps: Atomic(u64) = .init(0),
    clean_skipped: Atomic(u64) = .init(0),
    /// Ordered-thread time and major faults per stage (lane catchup-io; status line).
    prof: stageprof.Prof = .{},
    /// The read-ahead thread's `<seq>.aux` buffer and parse arena (prefetchAux).
    pf_aux_buf: std.ArrayList(u8) = .empty,
    pf_aux_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator),
    /// SubscriptionService fan-out, started with `--serve`.
    hub: ?*serve.subscribe.Hub = null,
    /// TransactionExecutionService (rpc_exec) in front of `service` on the serve port.
    exec_rpc: rpc.Rpc = undefined,
    /// Epoch records and package-version index (GetEpoch, ListPackageVersions; serve/rpcindex.zig).
    rpc: ?*serve.rpcindex.Index = null,
    serve_server: ?Io.net.Server = null,
    serve_tls_server: ?Io.net.Server = null,
    serve_tls: native.tcptls.Server = undefined,
    /// `--serve-tls-cert/-key`: the chain and key the TLS port presents, loaded again on SIGHUP
    /// or when the files change. Lives until exit (connection threads may be in a handshake).
    serve_tls_certs: ?*native.certs.Certs = null,
    native_listener: ?*native.listener.Listener = null,
    /// `--gate`: lives until exit (like the hub: detached connection threads may still call it).
    gate: ?*gate_mod.NodeGate = null,
    gate_handler: serve.h2.Handler = undefined,
    native_disp: native.dispatch.Dispatcher = undefined,
    /// The WebTransport certificate and its rotation (native/certs.zig).
    native_certs: ?*native.certs.Certs = null,
    native_certhttp: ?*native.certhttp.Server = null,
    native_hooks: native_hooks.Hooks = undefined,
    /// `--native-keys`: API keys and Agent Passes (lives until exit, after the listener).
    native_policy: ?*native.agentpass.Policy = null,
    edge_warm: ?std.Thread = null,
    edge_stop: Atomic(bool) = .init(false),
    serve_stop: Atomic(bool) = .init(false),
    ix: ?*index.Index = null,
    ix_feed: ?*index.feed.Feed = null,
    /// Background index build and catch-up (lane fast-start); null when every index was level at start.
    fast: ?*fast_start.Job = null,
    metrics_server: ?Io.net.Server = null,
    /// sui-node's RPC metrics, fed by the transport (rpcmetrics.zig), installed with `--serve`.
    rpc_metrics: rpcmetrics.RpcMetrics = undefined,
    rpc_metrics_on: bool = false,
    /// Per-epoch state-hash check (writer thread), and the executor switch it turns off.
    state_hash: statehash.Checker = undefined,
    exec_off: bool = false,
    /// Unsupported-protocol alerting and the verify-only fallback (upgrade.zig).
    guard: upgrade.Guard = .{},
    /// Duration of the last epoch change seen (ms, `epoch_total_duration`).
    epoch_duration_ms: Atomic(u64) = .init(0),
    /// sui-node's checkpoint executor and state sync families (opsmetrics.zig).
    cp_metrics: opsmetrics.Checkpoints = .{},
    /// Disk bytes per data area (`rocksdb_total_sst_files_size{cf_name}`), walked once a minute.
    disk_usage: opsmetrics.DiskUsage = .{},
    metrics_pusher: ?*metricspush.Pusher = null,
    /// One render at a time (the scrape server and the push thread share the registry).
    render_lock: std.atomic.Mutex = .unlocked,
    /// Tombstones segment cleaning dropped (`num_pruned_tombstones`, with the ager's).
    clean_tombstones: Atomic(u64) = .init(0),
    admin_server: ?*admin.Server = null,
    /// The admin port's db-shell view of the store (admin_store.zig).
    admin_db: admin_store.AdminStore = undefined,
    threads: std.ArrayList(std.Thread) = .empty,
    resumed: bool = false,
    /// Epoch of the formal snapshot this run restored, if any.
    snapshot_epoch: ?u64 = null,
    /// Epoch of the formal snapshot the store was started from (this run or an earlier one).
    restored_epoch: ?u64 = null,
    /// Tip latency: wall clock at verification end minus the checkpoint's timestamp (ms), last 4096.
    lat_ring: [4096]Atomic(u32) = @splat(.init(0)),
    lat_n: Atomic(u64) = .init(0),
    /// Far behind the tip (catch-up), from the same lag (`noteLag`); `behind_set` once the
    /// store's ager was told.
    behind: Atomic(bool) = .init(false),
    behind_set: bool = false,
    /// Arrival age: wall clock when the checkpoint's bytes arrived minus its timestamp (ms), same
    /// ring layout. Tip latency minus this is decode, spool, verify and commit.
    arr_ring: [4096]Atomic(u32) = @splat(.init(0)),
    arr_n: Atomic(u64) = .init(0),
    /// Per source (source.SeenSrc): first sighting minus the checkpoint timestamp (ms), same ring
    /// layout; and how often each source had it first (any form, and full data only).
    src_ring: [source_mod.n_seen_src][4096]Atomic(u32) = @splat(@splat(.init(0))),
    src_n: [source_mod.n_seen_src]Atomic(u64) = @splat(.init(0)),
    first_any: [source_mod.n_seen_src]Atomic(u64) = @splat(.init(0)),
    first_data: [source_mod.n_seen_src]Atomic(u64) = @splat(.init(0)),
    failure: ?[]const u8 = null,
    /// `node/LOCK` (dbcheckpoint.lock): held for the process lifetime.
    lock_fd: ?std.c.fd_t = null,
    /// Graceful stop: open RPC connections did not finish within the drain (the store is then
    /// flushed without unmapping it under their threads).
    undrained: bool = false,
    /// `drainRpc` has run its drain (a later call only ends what is left).
    rpc_drained: bool = false,
    /// End-of-epoch snapshot the writer thread produces next (set on the writer thread before
    /// the checkpoint commits, started once it has).
    snap_pending: ?struct { seq: u64, epoch: u64, root: [32]u8 } = null,
    /// End-of-epoch SUI conservation check to run once the checkpoint commits (epoch thread).
    cons_pending: ?struct { seq: u64, epoch: u64 } = null,
    cons_stats: conservation.Stats = .{},
    /// Set by the epoch thread when the check fails; the writer thread turns execution off.
    cons_failed: Atomic(bool) = .init(false),
    snap_thread: ?std.Thread = null,
    snap_busy: Atomic(bool) = .init(false),
    snap_cancel: Atomic(bool) = .init(false),

    pub fn init(gpa: std.mem.Allocator, io: Io, cfg: Config) !*Node {
        const n = try gpa.create(Node);
        errdefer gpa.destroy(n);
        if (!startup_done.load(.acquire) and startup_thread == null) startup_thread = std.Thread.spawn(.{}, startupWatch, .{}) catch null;
        startupPhase("store open");
        const cwd = Io.Dir.cwd();
        try cwd.createDirPath(io, cfg.dir);
        // One process per node directory (deepwave-tool takes the same lock).
        const lock_fd = dbcheckpoint.lock(cfg.dir) catch |e| {
            if (e == error.NodeRunning) std.log.err("{s} is in use by another deepwave or deepwave-tool (node/LOCK)", .{cfg.dir});
            return e;
        };
        errdefer dbcheckpoint.unlock(lock_fd);
        const root = try cwd.openDir(io, cfg.dir, .{});
        try root.createDirPath(io, "node/epochs");
        try root.createDirPath(io, "store");
        // `.iterate`: a real descriptor (not O_PATH on Linux), so fsync of the directory works.
        const node_dir = try root.openDir(io, "node", .{ .iterate = true });
        const epochs_dir = try node_dir.openDir(io, "epochs", .{ .iterate = true });

        n.* = .{
            .gpa = gpa,
            .io = io,
            .cfg = cfg,
            .root = root,
            .node_dir = node_dir,
            .epochs_dir = epochs_dir,
            .st = undefined,
            .rio = undefined,
            .source = undefined,
            .archive = undefined,
            .follower = undefined,
            .anchor_arena = .init(gpa),
            .first_seq = 0,
            .started_ns = source_mod.nowNs(),
            .lock_fd = lock_fd,
        };
        // Before anything downloads (the snapshot restore below, the trust walk, the fetchers).
        http.net_cap.configure(cfg.net_max_mbps);
        if (cfg.net_max_mbps != 0) std.log.info("download cap: {d} MiB/s for checkpoint fetches and the snapshot restore together (--net-max-mbps)", .{cfg.net_max_mbps});

        // An interrupted snapshot restore leaves a partial live set: start it again from scratch.
        const marker = try snapshot.readMarker(io, node_dir);
        if (marker.state == .loading) {
            // Without --snapshot nothing would restore it again and the marker would stay
            // `loading`: every later start would wipe the store the node had followed into since.
            if (cfg.snapshot == null) {
                std.log.warn("snapshot restore of epoch {d} was interrupted; start again with --snapshot {d} (or remove {s}/node to start without one)", .{ marker.epoch, marker.epoch, cfg.dir });
                return error.SnapshotRestoreInterrupted;
            }
            std.log.warn("snapshot restore of epoch {d} was interrupted; wiping the store and restoring again", .{marker.epoch});
            try root.deleteTree(io, "store");
            try root.createDirPath(io, "store");
        }
        if (marker.state == .done) n.restored_epoch = marker.epoch;

        // Store (recovery happens in open).
        const store_path = try std.fs.path.join(n.anchor_arena.allocator(), &.{ cfg.dir, "store" });
        var scfg = cfg.store_cfg;
        scfg.dir = store_path;
        // Restored objects are compact records (CONTRACTS 6.8): the store parses their ids.
        if (scfg.codec == null) scfg.codec = @import("exec").objects.store_codec;
        // A/B switch for the cleaner's count read-ahead (lane catchup-io); on by default.
        if (envU32("ZUI_CLEAN_READAHEAD", 1) == 0) scfg.clean_readahead = false;
        // A/B switches for lane disk-fit's chunk codecs: record checksums elided (codec 2) and
        // history dictionaries (codec 3). On by default; off writes the older codecs (all read).
        if (envU32("ZUI_ELIDE_SUMS", 1) == 0) scfg.elide_sums = false;
        if (envU32("ZUI_HISTORY_DICTS", 1) == 0) scfg.history_dicts = false;
        // Age-out (lane ager-catchup). ZUI_AGE_SERIAL=1: the old path (no read-ahead, a lookup
        // per record under the lock). ZUI_AGE_QD: live-table reads in flight. ZUI_AGE_SHARE:
        // percent of the ager's time those reads may take. ZUI_AGE_DEFER_MB: what deferred
        // age-out lets the store append in catch-up before it catches up in one run.
        if (envU32("ZUI_AGE_SERIAL", 0) != 0) scfg.age_serial = true;
        // The ager's memory (`--age-mem-mb`, ZUI_AGE_MEM_MB): pending set, live set, buffers.
        scfg.age_mem_bytes = @as(u64, envU32("ZUI_AGE_MEM_MB", @intCast(scfg.age_mem_bytes >> 20))) << 20;
        // Segment pass with a live set (lane ager-segment-pass), off by default: one sequential
        // pass over the live table instead of a lookup per record of every aged segment.
        // ZUI_AGE_SET_MB: memory for its bits.
        if (envU32("ZUI_AGE_LIVE_SET", 0) != 0) scfg.age_live_set = true;
        if (envU32("ZUI_AGE_SET_VERIFY", 0) != 0) scfg.age_set_verify = true;
        scfg.age_set_bytes = @as(u64, envU32("ZUI_AGE_SET_MB", @intCast(scfg.age_set_bytes >> 20))) << 20;
        scfg.age_qd = envU32("ZUI_AGE_QD", scfg.age_qd);
        scfg.age_share_pct = envU32("ZUI_AGE_SHARE", @intCast(scfg.age_share_pct));
        scfg.age_defer_bytes = @as(u64, envU32("ZUI_AGE_DEFER_MB", @intCast(scfg.age_defer_bytes >> 20))) << 20;
        // Cleaning pace (lane catchup-1306): percent of the writer's time; 100 = unpaced (A/B).
        n.clean_pace.share_pct = envU32("ZUI_CLEAN_SHARE", 20);
        // State-index replay of stored checkpoints: readers in flight (1: one at a time, as before lane catchup-io).
        index.feed.replay_threads = envU32("ZUI_INDEX_REPLAY_THREADS", index.feed.replay_threads);
        const opened = try store.openDir(gpa, io, &scfg, .{ .sync = cfg.sync_mode });
        n.st = opened.store;
        n.rio = opened.io;
        errdefer {
            n.st.deinit();
            n.rio.deinit();
        }

        // Source (none in p2p-only mode: any read of it misses).
        if (cfg.p2p_only) {
            if (cfg.p2p == null) return error.P2pOnlyNeedsPeers;
            if (n.st.committed() == null) {
                std.log.err("--p2p-only resumes a store (restore a snapshot or catch up with a source first)", .{});
                return error.P2pOnlyNeedsStore;
            }
            n.source = .{ .gpa = gpa, .io = io, .kind = .none };
            std.log.info("source: none (p2p only: summaries and contents from peers, every checkpoint executed here)", .{});
        } else switch (cfg.source) {
            .zui1 => |spec| {
                const specs = try edge.client.parseSpecs(gpa, spec.cores);
                defer gpa.free(specs);
                const pool = try edge.client.Pool.init(gpa, io, specs, spec.max_conns);
                pool.chain_id = cfg.chain_id orelse cfg.network.params().chain_id;
                pool.use_zstd = spec.zstd;
                pool.read_sets = cfg.edge_read_sets;
                n.edge_pool = pool;
                n.source = .{ .gpa = gpa, .io = io, .kind = .{ .zui1 = pool }, .edge_read_sets = cfg.edge_read_sets };
                std.log.info("source: zui/1 from {d} core(s), {d} connection(s), zstd {s}", .{ specs.len, spec.max_conns, if (spec.zstd) "on" else "off" });
                try n.initEdgeFallback(spec, specs, pool);
            },
            .dir => |p| n.source = .{ .gpa = gpa, .io = io, .kind = .{ .dir = try cwd.openDir(io, p, .{}) } },
            .s3 => |spec| {
                const b = try loadBucket(n, spec);
                n.bucket = b;
                n.source = .{ .gpa = gpa, .io = io, .kind = .{ .s3 = b } };
            },
            .http => |spec| {
                const h = try gpa.create(http.Public);
                h.* = http.Public.init(gpa, io, spec.base orelse cfg.network.params().bucket_url);
                // The request pool follows --fetchers (it was a fixed 16).
                _ = h.setConcurrency(cfg.fetchers);
                n.public = h;
                if (spec.fallback) |fb| {
                    if (loadBucket(n, fb)) |b| {
                        n.bucket = b;
                        h.fallback = b;
                        std.log.info("source: {s}, S3 fallback (profile {s})", .{ h.base, fb.profile });
                    } else |e| std.log.warn("source: {s}, no S3 fallback ({s})", .{ h.base, @errorName(e) });
                } else std.log.info("source: {s}, no S3 fallback", .{h.base});
                n.source = .{ .gpa = gpa, .io = io, .kind = .{ .http = h } };
            },
        }

        // Formal snapshot start (empty store only).
        startupPhase("snapshot restore");
        if (cfg.snapshot) |spec| if (n.st.committed() == null) try n.restoreSnapshot(spec, if (marker.state == .loading) marker.epoch else null);

        // State-hash running root at the last committed checkpoint (written by a restore or by
        // the previous run's commits).
        n.state_hash = try statehash.Checker.init(gpa, cfg.state_hash);
        n.state_hash.lenient = cfg.verify_fallback;
        n.guard.enabled = cfg.verify_fallback;
        if (n.st.committed()) |last| {
            var snap = n.st.snapshot();
            defer snap.release();
            n.state_hash.load(&snap, last);
            if (cfg.state_hash != .off) {
                if (n.state_hash.running != null)
                    std.log.info("state hash: running root at checkpoint {d} loaded; checked at every end of epoch", .{last})
                else
                    std.log.warn("state hash: no running root at checkpoint {d} (the store was not started from a snapshot by this version); per-epoch check off until a restore", .{last});
            }
        }

        // Anchor: resume from the store, or start from trust.
        const anchor = try n.computeAnchor();
        n.first_seq = anchor.first_seq;

        // Where the follower reads: the dir source directly when it holds blobs, else the spool.
        const direct = switch (cfg.source) {
            .dir => |p| blk: {
                var nb: [48]u8 = undefined;
                const name = std.fmt.bufPrint(&nb, "{d}.chk", .{anchor.first_seq}) catch unreachable;
                const d = try cwd.openDir(io, p, .{});
                defer d.close(io);
                _ = d.statFile(io, name, .{}) catch break :blk false;
                break :blk true;
            },
            .s3, .http, .zui1 => false,
        };
        if (direct) {
            n.archive = try sync.archive.Archive.open(io, cfg.source.dir);
        } else {
            // A kept spool (--keep-spool) survives restarts so check can read every blob later;
            // its files are complete (temporary name, then rename) and verified like any source.
            if (!cfg.keep_spool) node_dir.deleteTree(io, "spool") catch {};
            try node_dir.createDirPath(io, "spool");
            n.spool_dir = try node_dir.openDir(io, "spool", .{});
            n.archive = .{ .dir = try node_dir.openDir(io, "spool", .{}) };
        }

        n.follower = try sync.Follower.init(gpa, io, n.st, .{ .archive = &n.archive }, .{
            .mode = .apply,
            .workers = cfg.workers,
            // Spool mode: every spool writer wakes the workers (Fetcher.on_spooled below), so they
            // block until their file is there; the timeout is a safety net only. Until lane
            // tip-cheap this was a 2 ms poll: one failed open per worker every 2 ms at the tip.
            .poll_ms = if (direct) n.pollMs() else spool_fallback_ms,
            // Store read-ahead (lane fast-start): inside a memory cap the live table and the
            // segments do not fit the page cache, and the apply would wait on one fault at a time.
            .prefetch_qd = envU32("ZUI_PREFETCH_QD", 64),
            .prefetch_ahead = @max(1, envU32("ZUI_PREFETCH_AHEAD", 32)),
            .cert_batch = cfg.cert_batch,
        }, anchor);
        n.follower.observer = .{ .ctx = n, .on_checkpoint = onCheckpoint, .on_batch = onBatch, .on_committed = onCommitted, .on_idle = onIdle };
        // What a core must still hold for the edge to return to it: the next checkpoint to apply.
        if (n.edge_fb) |fb| fb.applied_next = &n.follower.applied_next;
        if (cfg.read_sets) {
            const h = try gpa.create(history.History);
            h.* = try history.History.init(gpa, io, if (direct) try cwd.openDir(io, cfg.source.dir, .{}) else n.spool_dir.?);
            n.history = h;
            n.follower.prefetch_more = .{ .ctx = n, .add = prefetchAux };
            if (cfg.edge_read_sets) {
                // An edge: lists from its sources, every object from its own store. Any node:
                // the per-checkpoint mark, which is what an edge answers by and a feed sends by.
                h.edge = cfg.source == .zui1;
                h.mark_read_sets = true;
                std.log.info("read sets: {s}", .{if (h.edge) "kept by this edge (--edge-read-sets): loaded lists as its sources give them, every object from its own store; a checkpoint without its whole read set is answered by the core" else "marked per checkpoint (--edge-read-sets): sent with the edge feed to clients that ask"});
                if (h.edge) if (n.edge_pool) |pool| {
                    const r = try gpa.create(reask_mod.ReAsk);
                    r.* = .{ .gpa = gpa, .io = io, .pool = pool, .hist = h, .st = n.st };
                    n.reask = r;
                    n.source.reask = r;
                };
            }
        }
        if (cfg.mode == .execute) {
            const x = try gpa.create(execute.Executor);
            // Archive records (`<seq>.aux`) are where history.zig reads them.
            const aux_dir: Io.Dir = if (direct) try cwd.openDir(io, cfg.source.dir, .{}) else n.spool_dir.?;
            x.* = try execute.Executor.init(gpa, io, n.st, aux_dir);
            x.chain = cfg.network.params().chain;
            // System child reads above the bound keep working across restarts (removal_log.zig).
            x.openPriorLog(try std.fs.path.join(n.anchor_arena.allocator(), &.{ cfg.dir, "node", "removed-prior.log" })) catch |e|
                std.log.warn("execute: removal-prior index not durable ({s}); in memory only", .{@errorName(e)});
            if (cfg.packages_dir) |p| {
                if (cfg.packages_from != null) try cwd.createDirPath(io, p);
                x.pkg_dir = try cwd.openDir(io, p, .{});
            }
            if (cfg.packages_from) |url| {
                const f = try gpa.create(@import("pkgfetch.zig").Fetcher);
                f.* = .init(gpa, io, url);
                x.pkg_fetch = f;
                std.log.info("execute: packages not seen locally come from {s} (GetObject, 20 req/s)", .{f.base});
            }
            x.report = cfg.report;
            x.complete_from = try n.completeFrom();
            if (x.complete_from) |e| std.log.info("execute: the store holds the full live set from epoch {d}", .{e});
            if (cfg.deny_state) |p| {
                const k = try x.loadDenyState(p);
                std.log.info("execute: deny-list state for {d} objects from {s}", .{ k, p });
            }
            if (cfg.trust_dir) |td| if (cfg.epochs_index) |ei| {
                var tmp: std.heap.ArenaAllocator = .init(gpa);
                defer tmp.deinit();
                const idx = try trust.EpochIndex.load(tmp.allocator(), io, ei);
                var d = try cwd.openDir(io, td, .{});
                defer d.close(io);
                const got = x.seedSystemPackages(d, idx.last, n.cur_epoch + 1);
                std.log.info("execute: {d} system package writes up to epoch {d} from {s}", .{ got, n.cur_epoch, td });
            };
            const threads = cfg.exec_threads orelse execute.Executor.defaultThreads();
            x.cache_budget = @as(usize, cfg.exec_cache_mb) << 20;
            x.window_bytes = @as(u64, cfg.exec_window_mb) << 20;
            try x.start(threads, cfg.exec_window);
            std.log.info("execute: {d} executor threads, {d} checkpoints in flight", .{ threads, cfg.exec_window });
            n.executor = x;
        }
        if (!direct) {
            const f = try gpa.create(source_mod.Fetcher);
            f.* = .{
                .gpa = gpa,
                .io = io,
                .source = &n.source,
                .spool = n.spool_dir.?,
                .next = .init(anchor.first_seq),
                .applied_next = &n.follower.applied_next,
                .window = @min(cfg.window, 8192),
                .poll_ms = n.pollMs(),
                .lookahead = cfg.lookahead,
                .to = cfg.to orelse std.math.maxInt(u64),
                .keep = cfg.keep_spool,
                .on_spooled = .{ .ctx = n.follower, .call = spooled },
            };
            n.fetcher = f;
            // An edge: which checkpoints hold a certificate that is not a core's. Opened before
            // the follower commits anything (its log names the marks of earlier runs), with the
            // certificates it holds reinstalled.
            // (`ZUI_EDGE_CERTS=0`: off; the edge then serves whatever certificate each source gave.)
            if (n.edge_pool) |pool| if (envU32("ZUI_EDGE_CERTS", 1) != 0) {
                const cv = try edge_certs.Converger.open(gpa, io, n.node_dir, n.st, pool, .{ .ctx = n, .get = certCommittee }, .{ .max_lag = cfg.edge_forward_cfg.max_lag });
                cv.fetcher = f;
                cv.sw = if (n.edge_fb) |fb| &fb.sw else null;
                n.edge_certs = cv;
            };
            // A zui1 source in catch-up is bound by round trips: the fetch threads pipeline as
            // many requests as the apply stage can use (source.zig `InFlight`).
            if (cfg.source == .zui1 and cfg.source.zui1.max_inflight != 0 and !cfg.p2p_only) {
                const fl = try gpa.create(source_mod.InFlight);
                fl.* = source_mod.InFlight.init(@max(1, cfg.fetchers), cfg.source.zui1.max_inflight, @intCast(f.window));
                fl.stall_ns = &n.follower.metrics.stall_ns;
                f.inflight = fl;
                std.log.info("edge feed: {d} to {d} requests in flight at the cores in catch-up, set from the apply stage's waiting and the cores' answers (--feed-max-inflight {d}; never more than the fetch window, {d}); {d} at the tip", .{ fl.ctl.cfg.floor, fl.ctl.limit(), cfg.source.zui1.max_inflight, f.window, fl.ctl.cfg.floor });
            }
            if (cfg.stream) |urls| if (!cfg.p2p_only) {
                var it = std.mem.tokenizeScalar(u8, urls, ',');
                while (it.next()) |url| {
                    const st = try gpa.create(stream_mod.Stream);
                    st.* = .{ .gpa = gpa, .io = io, .base = std.mem.trimEnd(u8, std.mem.trim(u8, url, " "), "/"), .fetcher = f };
                    try n.streams.append(gpa, st);
                }
            };
            // An explicit `--sig-order-from` works without a stream (`--stream off`); else the
            // first loopback stream URL, else the first one.
            const sig_base: ?[]const u8 = sigOrderBase(&cfg, n.edge_fb != null);
            if (sig_base) |b| if (b.len > 0) {
                const rps = cfg.sig_order_rps orelse (if (sigorder.isLoopback(b)) sigorder.loopback_rps else sigorder.default_rps);
                if (rps > 0) {
                    const ov = try gpa.create(sigorder.Overlay);
                    ov.* = sigorder.Overlay.init(gpa, io, b, rps);
                    n.sig_order = ov;
                    f.sig_order = ov;
                    std.log.info("signature order for bucket checkpoints from {s}, {d} req/s", .{ b, rps });
                }
            };
            // The one thing a fallback checkpoint can store differently from a core's feed of it
            // (docs/EDGE.md section 10): said once, not papered over.
            if (n.edge_fb != null and n.sig_order == null)
                std.log.info("edge fallback: no signature-order node (--sig-order-from, or --sig-order-rps is 0): a checkpoint taken from the fallback stores sponsored and multi-signer transactions with their signatures in the contents' order, where a core's feed carries the order the core serves", .{});
        }
        // One network identity for the follower and the server (the same peer id both ways).
        var p2p_seed: [32]u8 = undefined;
        io.random(&p2p_seed);
        const p2p_key = if (cfg.p2p_key) |path| try p2p_mod.loadKey(io, path) else try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(p2p_seed);
        // sui-node's configured peers: seeds with an id and `allowlisted-peers` are trusted
        // (`is_trusted_peer`); `peer-address-overrides` are dialled at their given address and
        // kept connected (affinity High), like seeds.
        const tun = cfg.p2p_tuning;
        var trusted_ids: std.ArrayList([32]u8) = .empty;
        var overrides: []const p2p_config.Override = &.{};
        {
            const aa = n.anchor_arena.allocator();
            var bad: usize = 0;
            if (tun.allowlisted_peers) |t| for (try p2p_config.parseAllowlist(aa, t, &bad)) |al| try trusted_ids.append(aa, al.id);
            if (tun.peer_address_overrides) |t| overrides = try p2p_config.parseOverrides(aa, t, &bad);
            if (bad > 0) std.log.warn("p2p: {d} allowlisted-peers / peer-address-overrides entries without a peer id or a /dns|ip4|ip6/HOST/udp/PORT address; skipped", .{bad});
        }
        if (cfg.p2p) |text| if (n.fetcher) |f| p2p: {
            // fullnode.yaml seeds are DNS names; one that does not resolve is skipped, and with
            // none left the node follows without p2p rather than failing to start.
            var peers = try p2p_mod.parsePeersIo(n.anchor_arena.allocator(), io, text);
            if (overrides.len > 0) peers = try p2p_mod.applyOverrides(n.anchor_arena.allocator(), io, peers, overrides);
            if (peers.len == 0) {
                std.log.warn("p2p: no seed peer resolved; following without p2p", .{});
                break :p2p;
            }
            const key = p2p_key;
            const pp = try gpa.create(p2p_mod.P2p);
            pp.* = .{ .gpa = gpa, .io = io, .st = n.st, .fetcher = f, .peers = peers, .key = key, .hooks = .{ .ctx = n, .params = p2pParams }, .net = cfg.network.params(), .trace = cfg.p2p_trace, .race = cfg.p2p_race, .push_peers = cfg.p2p_push_peers, .discover = cfg.p2p_discover, .exec_threads = cfg.p2p_exec_threads };
            pp.p2p_only = cfg.p2p_only;
            {
                const aa = n.anchor_arena.allocator();
                for (peers) |sp| if (sp.id) |id| try trusted_ids.append(aa, id);
                pp.trusted = trusted_ids.items;
                if (tun.interval_period_ms) |ms| pp.query_ms = ms;
                if (tun.target_concurrent_connections) |t| pp.discover = t;
                pp.contents_v2 = tun.use_get_checkpoint_contents_v2;
                pp.known_peers_v3 = tun.use_get_known_peers_v3;
                const sc = &pp.scores.cfg;
                if (tun.peer_scoring_window_ms) |ms| sc.window_ns = ms * std.time.ns_per_ms;
                if (tun.peer_failure_rate) |r| sc.failure_rate = r;
                if (tun.exploration_probability) |x| sc.exploration = x;
                if (tun.peer_disconnect_threshold_ms) |ms| sc.disconnect_threshold_ns = ms * std.time.ns_per_ms;
                if (tun.min_peers_for_disconnect) |m| sc.min_peers_for_disconnect = m;
                if (tun.peer_failure_cooldown_ms) |ms| {
                    sc.cooldown_ns = ms * std.time.ns_per_ms;
                    pp.pool_cfg.silent_ms = ms;
                    pp.pool_cfg.wrong_peer_ms = ms;
                }
            }
            pp.tiles = cfg.tiles;
            pp.tile_spin = cfg.tile_spin;
            if (cfg.tile_cpus) |txt| {
                var cpus: std.ArrayList(u16) = .empty;
                var it = std.mem.splitScalar(u8, txt, ',');
                while (it.next()) |part| {
                    const t = std.mem.trim(u8, part, " ");
                    if (t.len == 0) continue;
                    try cpus.append(n.anchor_arena.allocator(), try std.fmt.parseInt(u16, t, 10));
                }
                pp.tile_cpus = cpus.items;
            }
            if (cfg.p2p_pinned) |pins| pp.pinned = .init(try @import("p2p_only.zig").parsePinned(n.anchor_arena.allocator(), pins));
            n.p2p = pp;
        };
        // The read sets of a checkpoint p2p built are deepwave's own word: they are compared with
        // sui-node's copy (the stream's duplicate, else the bucket's). p2p-only has no such copy.
        if (n.p2p != null and !cfg.p2p_only and cfg.p2p_reconcile_wait_s > 0) if (n.history) |h| {
            const r = try reconcile_mod.Reconciler.open(gpa, io, n.st, n.node_dir, if (n.source.kind == .none) null else &n.source, .{ .wait_ms = @as(u64, cfg.p2p_reconcile_wait_s) * 1000 });
            n.reconcile = r;
            h.mark_built = true;
            for (n.streams.items) |st| st.reconcile = r;
        };
        const np = cfg.network.params();
        n.service = .{ .gpa = gpa, .store = n.st, .chain_id = cfg.chain_id orelse np.chain_id, .chain = np.chain, .chain_name = np.name, .protocol_release_max = cfg.rpc_release_max, .loaded = .{ .ctx = n, .get = loadedOf }, .cp_cache = .{ .budget = cfg.cp_cache_bytes } };
        n.service.lowest = &n.served_lowest;
        if (cfg.edge_read_sets and n.history != null) n.service.read_sets = .{ .ctx = n, .has = readSetHeld };
        if (cfg.lh_cfg) |c| n.service.lh_cfg = c;
        n.refreshLowest();
        if (tun.excessive_message_size) |m| core.p2p_metrics.excessive_message_size = m;
        if (cfg.p2p_listen != null or n.p2p != null) {
            const aa = n.anchor_arena.allocator();
            const srv = try gpa.create(p2p_serve.Server);
            if (n.p2p == null) for (overrides) |o| try trusted_ids.append(aa, o.id);
            const trusted = trusted_ids;
            const cache_path: ?[]const u8 = if (tun.peer_addr_store_path) |pth|
                (if (std.mem.eql(u8, pth, "off")) null else pth)
            else
                try std.fs.path.join(aa, &.{ cfg.dir, "discovery_peer_cache.yaml" });
            srv.* = .{
                .gpa = gpa,
                .io = io,
                .st = n.st,
                .key = p2p_key,
                .p2p = n.p2p,
                .lowest = &n.lowest,
                .restored_epoch = n.restored_epoch,
                .external = if (cfg.p2p_external) |e| try p2p_serve.externalMultiaddr(aa, e) else null,
                // sui-node: `discovery.access-type`, default Public (with no external address our
                // info carries no address, so nobody dials it either way).
                .access = cfg.p2p_access orelse .public,
                .trusted = trusted.items,
                .peer_cache_path = cache_path,
                .limits = .{
                    .max_request_size = tun.max_checkpoint_summary_size orelse 256 * 1024,
                    .push_checkpoint_summary_rate = tun.push_checkpoint_summary_rate_limit,
                    .get_checkpoint_summary_rate = tun.get_checkpoint_summary_rate_limit,
                    .get_checkpoint_contents_rate = tun.get_checkpoint_contents_rate_limit,
                    .get_known_peers_rate = tun.get_known_peers_rate_limit,
                    .get_checkpoint_contents_inflight = tun.get_checkpoint_contents_inflight_limit,
                    .get_checkpoint_contents_per_checkpoint = tun.get_checkpoint_contents_per_checkpoint_limit,
                },
            };
            try srv.init();
            n.p2p_server = srv;
            if (n.p2p) |pp| {
                pp.server = srv.handler();
                pp.book = &srv.book;
                pp.srv = srv;
            }
        }
        if (cfg.serve_addr != null) {
            const rdir = cfg.rpc_dir orelse try std.fs.path.join(n.anchor_arena.allocator(), &.{ cfg.dir, "rpc" });
            const x = try serve.rpcindex.Index.open(gpa, io, rdir);
            errdefer x.deinit();
            x.committees = .{ .ctx = n, .get = committeeOf };
            // Before the follower runs: level the index with the store (live-set floors and a
            // replay of the stored checkpoints past its watermark). Failing here is fatal: a
            // partial index would answer OK with missing rows.
            startupPhase("rpc index seed");
            std.log.info("rpc index: levelling with the store at {s} (a full live-set scan after a restore)", .{rdir});
            var snap = n.st.snapshot();
            defer snap.release();
            const t0 = source_mod.nowNs();
            const img = n.restoreImage(&snap);
            const lag = if (snap.highestCommitted()) |tip| (if (x.watermark) |wm| tip -| wm else std.math.maxInt(u64)) else 0;
            // No image and no watermark on a large store (a db-checkpoint copy, an rpc dir lost,
            // --serve turned on later): the floors come from a live-set scan beside the follower
            // too (lane index-fast; it blocked RPC for 25 min on mainnet). Small stores seed here.
            const big = n.st.liveCount() >= liveScanMin();
            if (fastOn() and ((x.watermark == null and (img != null or big)) or (x.watermark != null and lag > 64))) {
                // fast start: floors from the image (or the live set) and the replay run in the background
                const j = try n.fastJob(img);
                j.rpc = x;
                j.floors = x.watermark == null;
                std.log.info("rpc index: watermark {?d}; package floors and stored-checkpoint replay in the background (fast start{s})", .{ x.watermark, if (img == null and x.watermark == null) ", live-set scan" else "" });
            } else {
                const rep = try x.seed(&snap);
                std.log.info("rpc index: watermark {?d}; {d} live objects walked ({d} package floors), {d} stored checkpoints replayed from {?d} in {d} ms", .{ rep.watermark, rep.live_objects, rep.floor_rows, rep.replayed, rep.replay_from, (source_mod.nowNs() - t0) / std.time.ns_per_ms });
            }
            n.rpc = x;
            n.service.rpc = x;
            n.backfillEpochRecords(x);
            const hdir = cfg.history_dir orelse try std.fs.path.join(n.anchor_arena.allocator(), &.{ cfg.dir, "ledger-history" });
            const h = try lhist.Index.init(gpa, io, hdir);
            var hsnap = n.st.snapshot();
            defer hsnap.release();
            if (hsnap.highestCommitted()) |tip| if (h.indexedHi()) |hi| h.publish(@min(hi, tip));
            n.ledger_history = h;
            n.service.history = h;
            n.lh_staging = try std.fs.path.join(n.anchor_arena.allocator(), &.{ hdir, "backfill" });
            if (hsnap.highestCommitted()) |tip| n.restoreFloor(h, tip);
            n.pruneHistory();
            if (hsnap.highestCommitted()) |tip| n.maybeBackfill(tip);
            // No build was started that would resume from it (the index covers the store, the
            // backfill is switched off, or it could not start): the staging directory of an
            // earlier build, adopted, killed or abandoned, goes now. Otherwise it stayed for
            // as long as nothing needed a backfill: up to a whole window of index files.
            if (n.lh_fill == null) n.dropStaging("no build resumes from it at this start");
        }
        try n.exec_rpc.init(gpa, n.io, n.st, n.service.chain_id);
        if (cfg.dev_inspect_disabled) |off| n.exec_rpc.svc.engine.dev_inspect = if (off) .refused else .enabled;
        // One `--exec-cache-mb` budget for every thread holding Move package caches: the
        // executor's threads (execute mode) and the simulate workers.
        {
            const exec_threads: usize = if (n.executor != null) (cfg.exec_threads orelse execute.Executor.defaultThreads()) else 0;
            simulate.api.setCacheBudget(cfg.exec_cache_mb, exec_threads + n.exec_rpc.simulateWorkers());
        }
        // TransactionExecutionService through the service router (transport lane), so reflection,
        // known paths, compression, x-sui-* headers and /health keep the router's handler fields.
        n.service.execution = n.exec_rpc.handler();
        try n.initEdgeForward();
        return n;
    }

    /// `--core-upstream` with `--serve`: the forwarding handler in front of the service
    /// (edge/forward.zig). Its memory lives until exit, like the hub's: detached connection
    /// threads may still be in it at shutdown.
    fn initEdgeForward(n: *Node) !void {
        const text = n.cfg.core_upstream orelse return;
        if (n.cfg.serve_addr == null) {
            std.log.warn("edge forwarding: --core-upstream without --serve does nothing", .{});
            return;
        }
        if (!n.cfg.edge_forward) {
            std.log.info("edge forwarding: off (--edge-forward off); every request is answered locally", .{});
            return;
        }
        const ep = edge.forward.parseUpstream(text, n.cfg.core_upstream_pin) catch |e| {
            std.log.err("--core-upstream {s}: {s} (HOST:PORT for TLS against the system CAs, HOST:PORT/pin=<sha256 hex of the core's certificate>, HOST:PORT/plain for cleartext)", .{ text, @errorName(e) });
            return error.BadCoreUpstream;
        };
        const a = std.heap.smp_allocator;
        n.edge_fwd_transport = try edge.forward.GrpcTransport.init(a, n.io, ep);
        var fcfg = n.cfg.edge_forward_cfg;
        // Reads waiting for read-after-write keep their serve worker: at most a quarter of the
        // pool waits, the rest of a burst is passed to the core (edge/forward.zig `pendingGate`).
        if (!n.cfg.edge_raw_waiters_set) {
            const workers: u32 = if (n.cfg.serve_opts.workers != 0) n.cfg.serve_opts.workers else serve.h2.pool.workersFor(serve.h2.pool.usableCpus());
            fcfg.raw_max_waiters = @max(1, workers / 4);
        }
        // The policy settings (docs/EDGE.md 11.8). `--edge-simulate local` asks for more than
        // the flag: the whole live set, else it stays on forward.
        var policy_line: [640]u8 = undefined;
        const policy_text = edge.forward.settlePolicies(&fcfg, .{ .indexes = n.cfg.indexes, .live_set = (n.completeFrom() catch null) != null }, &policy_line);
        const f = try edge.forward.Forwarder.create(a, n.io, &n.service, n.edge_fwd_transport.transport(), fcfg);
        f.source = .{ .ctx = n, .known_tip = fwdKnownTip, .silent_ns = fwdSilentNs, .on_fallback = fwdOnFallback };
        // reads of a certificate that is not the core's yet go to the core (route `foreign_cert`)
        if (n.edge_certs) |cv| f.setCerts(cv.certs);
        // an effects read of a tip checkpoint a re-ask is about to settle waits for its mark
        if (n.reask) |r| f.read_set_hold = r.holdHook();
        n.edge_fwd = f;
        const how: []const u8 = switch (ep.security) {
            .plain => "cleartext h2c",
            .ca => "TLS, system CAs",
            .pinned_cert => "TLS, pinned certificate",
            .pinned => "TLS, pinned key",
        };
        std.log.info("edge forwarding: on; core upstream {s}:{d} ({s}); read-after-write {s} {d} ms ({d} reads may wait at once), max lag {d} checkpoints, ahead wait {d} ms", .{ ep.host, ep.port, how, @tagName(f.cfg.execMode()), f.cfg.execute_wait_ms, f.cfg.raw_max_waiters, f.cfg.max_lag, f.cfg.ahead_wait_ms });
        std.log.info("{s}", .{policy_text});
        if (ep.security == .plain and !(std.mem.eql(u8, ep.host, "localhost") or std.mem.startsWith(u8, ep.host, "127.") or std.mem.eql(u8, ep.host, "::1")))
            std.log.warn("edge forwarding: the upstream {s}:{d} is cleartext and not loopback: its answers are relayed unauthenticated (use TLS with a name or /pin=)", .{ ep.host, ep.port });
    }

    fn fwdKnownTip(ctx: *anyopaque) ?u64 {
        const n: *Node = @ptrCast(@alignCast(ctx));
        return (n.fetcher orelse return null).tipKnown();
    }

    fn fwdSilentNs(ctx: *anyopaque) u64 {
        const n: *Node = @ptrCast(@alignCast(ctx));
        return (n.fetcher orelse return std.math.maxInt(u64)).silentNs();
    }

    fn fwdOnFallback(ctx: *anyopaque) bool {
        const n: *Node = @ptrCast(@alignCast(ctx));
        return if (n.edge_fb) |fb| fb.sw.mode() == .fallback else false;
    }

    /// edge_certs.zig `Committees`: the committee the node persisted for `epoch` (trust.save;
    /// every committed checkpoint's epoch has one).
    fn certCommittee(ctx: *anyopaque, arena: std.mem.Allocator, epoch: u64) ?sync.Committee {
        const n: *Node = @ptrCast(@alignCast(ctx));
        const info = (trust.load(arena, n.io, n.epochs_dir, epoch) catch return null) orelse return null;
        return info.syncCommittee(arena) catch null;
    }

    /// What the serve ports answer with: the forwarding handler of an edge with a core upstream,
    /// else the service's own.
    pub fn serveHandler(n: *Node) serve.h2.Handler {
        // With `--gate`, a forwarder asks the gate itself, before it routes (`gate_hook`); a
        // node without one has the gate as a wrapper around the service.
        if (n.edge_fwd) |f| return f.handler();
        return if (n.gate != null) n.gate_handler else n.service.handler();
    }

    /// The first epoch whose start the store's live set covers in full: the epoch after a
    /// restored formal snapshot, or 0 when the store holds checkpoint 0 (genesis writes every
    /// initial object). null: the store holds only what the node followed.
    fn completeFrom(n: *Node) !?u64 {
        const m = try snapshot.readMarker(n.io, n.node_dir);
        if (m.state == .done) return m.epoch + 1;
        var snap = n.st.snapshot();
        defer snap.release();
        if (snap.checkpoint(0) != null) return 0;
        // genesis sync: an empty store starting at checkpoint 0 will hold everything since genesis
        if (n.first_seq == 0 and n.st.committed() == null) return 0;
        return null;
    }

    fn loadBucket(n: *Node, spec: S3Spec) !*s3.Bucket {
        const a = n.anchor_arena.allocator();
        const home = std.c.getenv("HOME") orelse "";
        const path = spec.credentials orelse if (std.c.getenv("AWS_SHARED_CREDENTIALS_FILE")) |p| std.mem.span(p) else try std.fs.path.join(a, &.{ std.mem.span(home), ".aws", "credentials" });
        const creds = try s3.Credentials.load(a, n.io, path, spec.profile);
        const b = try n.gpa.create(s3.Bucket);
        b.* = s3.Bucket.init(n.gpa, n.io, creds);
        b.bucket = spec.bucket orelse n.cfg.network.params().s3_bucket;
        b.budget_usd = spec.budget_usd;
        return b;
    }

    /// The node asked for the submitted signature order of bucket checkpoints (sigorder.zig):
    /// an explicit `--sig-order-from` (works without a stream), else the first loopback
    /// `--stream` URL, else the first one. An edge whose fallback is the public bucket and that
    /// has neither gets the network's public full node, the node a `--source http` node asks by
    /// default (through its default stream): the bucket path stores the same signature order
    /// whether it is a node's source or an edge's fallback. `--sig-order-rps 0` turns it off.
    pub fn sigOrderBase(c: *const Config, edge_fallback_on: bool) ?[]const u8 {
        if (c.sig_order_from) |u| return std.mem.trimEnd(u8, std.mem.trim(u8, u, " "), "/");
        if (c.p2p_only) return null;
        if (c.stream) |urls| return sigorder.pickBase(urls);
        if (edge_fallback_on and c.source == .zui1 and c.source.zui1.fallback == .http) {
            const u = c.network.params().fullnode_url;
            if (u.len > 0) return u;
        }
        return null;
    }

    /// `--edge-fallback`: the zui1 source's second way to the same checkpoints (source.zig
    /// `EdgeFallback`, rules in edge/fallback.zig). Off: nothing is created and the source is
    /// the pool alone, as before.
    fn initEdgeFallback(n: *Node, spec: Zui1Spec, specs: []const edge.client.Spec, pool: *edge.client.Pool) !void {
        const gpa = n.gpa;
        const fsrc: source_mod.Source = switch (spec.fallback) {
            .off => {
                std.log.info("edge fallback: off (when no core serves the next checkpoint, this edge waits for one)", .{});
                return;
            },
            .http => |hs| blk: {
                const base = hs.base orelse n.cfg.network.params().bucket_url;
                if (base.len == 0) {
                    std.log.warn("edge fallback: off (this network has no public checkpoint bucket; give --edge-fallback http:URL or dir:PATH)", .{});
                    return;
                }
                const h = try gpa.create(http.Public);
                h.* = http.Public.init(gpa, n.io, base);
                _ = h.setConcurrency(n.cfg.fetchers);
                n.public = h;
                break :blk .{ .gpa = gpa, .io = n.io, .kind = .{ .http = h } };
            },
            .dir => |path| .{ .gpa = gpa, .io = n.io, .kind = .{ .dir = try Io.Dir.cwd().openDir(n.io, path, .{}) } },
        };
        var t = spec.tuning;
        t.fail_after_ms = envU32("ZUI_EDGE_FAIL_MS", t.fail_after_ms);
        t.behind_after_ms = envU32("ZUI_EDGE_BEHIND_MS", t.behind_after_ms);
        t.probe_ms = @max(1, envU32("ZUI_EDGE_PROBE_MS", t.probe_ms));
        t.back_after_ms = envU32("ZUI_EDGE_BACK_MS", t.back_after_ms);
        const fb = try gpa.create(source_mod.EdgeFallback);
        fb.* = .{ .src = fsrc, .sw = .{ .t = t } };
        fb.sw.since_ns.store(edge.fallback.nowNs(n.io), .monotonic);
        n.edge_fb = fb;
        n.source.edge_fb = fb;
        // A core call never outlives the grace: connects share it, a request that stops making
        // progress for as long fails (client.zig `fetchBlobBy`).
        pool.stall_ms = t.fail_after_ms;
        const pr = try edge.fallback.Prober.init(gpa, n.io, &fb.sw, specs, pool.chain_id);
        n.edge_prober = pr;
        try pr.start();
        switch (spec.fallback) {
            .off => unreachable,
            .http => std.log.info("edge fallback: {s} (no S3 behind it) when no core serves the next checkpoint for {d} ms; cores probed every {d} ms, back after {d} ms healthy", .{ n.public.?.base, t.fail_after_ms, t.probe_ms, t.back_after_ms }),
            .dir => |path| std.log.info("edge fallback: directory {s} when no core serves the next checkpoint for {d} ms; cores probed every {d} ms, back after {d} ms healthy", .{ path, t.fail_after_ms, t.probe_ms, t.back_after_ms }),
        }
    }

    fn snapshotOrigin(n: *const Node, spec: SnapshotSpec) snapshot.Origin {
        return spec.origin orelse .{ .https = n.cfg.network.params().formal_snapshot_url };
    }

    /// How long a follower worker waits for its spool file when no writer woke it: about one
    /// checkpoint interval, so a wake that was somehow lost costs one checkpoint of delay, not a
    /// stall, and a waiting worker looks 4 times a second, not 500.
    pub const spool_fallback_ms: u32 = 250;

    /// `Fetcher.on_spooled`: checkpoint `seq` is in the spool.
    fn spooled(ctx: *anyopaque, seq: u64) void {
        const f: *sync.Follower = @ptrCast(@alignCast(ctx));
        f.notify(seq);
    }

    pub fn pollMs(n: *const Node) u32 {
        return n.cfg.poll_ms orelse switch (n.cfg.source) {
            .http => 25,
            .zui1 => 50,
            .s3, .dir => 100,
        };
    }

    /// One line at start: how many checkpoint downloads can really be in flight. The public
    /// bucket's request pool follows `--fetchers` up to http.Public.max_clients; before, it
    /// was 16 whatever the flag said, and nothing told the operator.
    fn logFetchConcurrency(n: *Node, threads: u32) void {
        if (threads == 0) return;
        switch (n.source.kind) {
            .http => |h| {
                const pool = h.limit.load(.acquire);
                const eff = @min(threads, pool);
                std.log.info("fetch: {d} fetcher threads, at most {d} checkpoint requests in flight at the public bucket (pool of {d} with the tip search and stream-check, hard maximum {d}){s}", .{ threads, eff, pool, http.Public.max_clients, if (eff < threads) "; the fetchers above that wait for a slot" else "" });
            },
            .s3 => std.log.info("fetch: {d} fetcher threads, at most {d} checkpoint requests in flight at S3", .{ threads, threads }),
            .zui1 => std.log.info("fetch: {d} fetcher threads, at most {d} checkpoint requests in flight at the zui/1 cores", .{ threads, threads }),
            .dir => std.log.info("fetch: {d} fetcher threads reading the source directory", .{threads}),
            .none => {},
        }
    }

    /// The follower's starting point.
    fn computeAnchor(n: *Node) !sync.follower.Anchor {
        const a = n.anchor_arena.allocator();
        if (n.st.committed()) |last| {
            n.resumed = true;
            var snap = n.st.snapshot();
            defer snap.release();
            const rec = (try snap.checkpointChecked(last)) orelse return error.StoreMissingCommitted;
            const cert = try trust.splitCert(rec.summary_cert);
            const s = try checkpoint.Summary.parse(cert.summary);
            const digest = checkpoint.summaryDigest(cert.summary);
            if (s.next_committee != null) {
                var tmp: std.heap.ArenaAllocator = .init(n.gpa);
                defer tmp.deinit();
                const c = try checkpoint.nextCommittee(tmp.allocator(), s);
                var info = try trust.EpochInfo.fromCheckpoint(a, &c, s.next_protocol_version);
                const params = try paramsFromStore(&tmp, &snap, rec.contents);
                info.start_ms = params.start_ms;
                // Safe mode emits no SystemEpochInfoEvent and keeps the reference gas price.
                info.rgp = params.rgp orelse blk: {
                    const old = try trust.load(a, n.io, n.epochs_dir, s.epoch);
                    break :blk if (old) |o| o.rgp else null;
                };
                try trust.save(n.io, n.epochs_dir, &info);
                n.cur_epoch = info.epoch;
                n.cur_pv = info.protocol_version;
                n.cur_params = .{ .rgp = info.rgp, .start_ms = info.start_ms };
                std.log.info("resume: store has checkpoint {d} (end of epoch {d}); continuing at {d} in epoch {d}", .{ last, s.epoch, last + 1, info.epoch });
                return .{ .committee = try info.syncCommittee(a), .first_seq = last + 1, .prev_digest = digest, .prev_was_eoe = true };
            }
            const info = try n.epochInfo(s.epoch, last);
            n.cur_epoch = info.epoch;
            n.cur_pv = info.protocol_version;
            n.cur_params = .{ .rgp = info.rgp, .start_ms = info.start_ms };
            std.log.info("resume: store has checkpoint {d} (epoch {d}); continuing at {d}", .{ last, s.epoch, last + 1 });
            return .{ .committee = try info.syncCommittee(a), .first_seq = last + 1, .prev_digest = digest, .prev_was_eoe = false };
        }
        // Fresh store.
        const first = switch (n.cfg.start) {
            .seq => |q| q,
            .auto, .tip => blk: {
                const lo = try n.tipSearchFloor();
                const tip = try n.source.latest(lo);
                std.log.info("start: source tip is checkpoint {d}", .{tip});
                break :blk tip;
            },
        };
        // The epoch of the first checkpoint, read unverified; its certificate is verified by the
        // follower with the committee the walk derives.
        var sc = source_mod.Scratch.init(n.gpa);
        defer sc.deinit(n.gpa);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(n.gpa);
        if (try n.source.fetch(&sc, first, &buf) != .ok) return error.SourceMissing;
        const cert = try trust.blobCert(buf.items);
        const s = try checkpoint.Summary.parse(cert.summary);
        const info = try n.epochInfo(s.epoch, first);
        n.cur_epoch = info.epoch;
        n.cur_pv = info.protocol_version;
        n.cur_params = .{ .rgp = info.rgp, .start_ms = info.start_ms };
        std.log.info("start: checkpoint {d} in epoch {d} (protocol {d}, reference gas price {?d}), committee of {d}", .{ first, s.epoch, info.protocol_version, info.rgp, info.keys.len });
        return .{ .committee = try info.syncCommittee(a), .first_seq = first, .prev_digest = null, .prev_was_eoe = false };
    }

    fn restoreSnapshot(n: *Node, spec: SnapshotSpec, retry_epoch: ?u64) !void {
        const a = n.anchor_arena.allocator();
        const epoch = spec.epoch orelse retry_epoch orelse try n.newestSnapshotEpoch(spec);
        // Trust: committee of epoch + 1, and the fully verified end-of-epoch checkpoint of `epoch`.
        var eoe: std.ArrayList(u8) = .empty;
        defer eoe.deinit(n.gpa);
        const info = try n.walkToKeep(epoch + 1, &eoe);
        if (eoe.items.len == 0) return error.NoEndOfEpochCheckpoint;
        _ = info;
        try snapshot.writeMarker(n.io, n.node_dir, .loading, epoch);
        var stats: snapshot.Stats = .{};
        const t0 = source_mod.nowNs();
        // A restore inserts hundreds of millions of ids at random live-index pages: flushing at the
        // follow-time dirty-page cap would rewrite the table thousands of times. Flush once, at
        // the end (the dirty pages are private memory until then; a crash before the `done`
        // marker wipes the store anyway).
        const saved = .{ n.st.cfg.max_dirty_pages, n.st.cfg.index_flush_interval };
        n.st.cfg.max_dirty_pages = std.math.maxInt(u64);
        n.st.cfg.index_flush_interval = std.math.maxInt(u64);
        defer {
            n.st.cfg.max_dirty_pages = saved[0];
            n.st.cfg.index_flush_interval = saved[1];
        }
        const bulk = blk: {
            const v = std.c.getenv("ZUI_BULK_RESTORE") orelse break :blk true;
            break :blk !std.mem.eql(u8, std.mem.span(v), "0");
        };
        const sort = blk: {
            const v = std.c.getenv("ZUI_RESTORE_SORT") orelse break :blk true;
            break :blk !std.mem.eql(u8, std.mem.span(v), "0");
        };
        // Lane index-fast: the derived indexes are built from the download itself (rows on the
        // fetch threads, merged beside the live-table build), not by a walk of the restored
        // segment afterwards. Any failure there falls back to that walk.
        var rib: ?*restore_index.Build = null;
        defer if (rib) |b| b.destroy();
        if (fastOn() and restore_index.enabled()) {
            const arena = n.anchor_arena.allocator();
            rib = restore_index.Build.begin(n.gpa, n.io, n.st, .{
                .state_dir = if (n.cfg.indexes) try std.fs.path.join(arena, &.{ n.cfg.dir, "state-index" }) else null,
                .rpc_dir = if (n.cfg.serve_addr != null) (n.cfg.rpc_dir orelse try std.fs.path.join(arena, &.{ n.cfg.dir, "rpc" })) else null,
                .committees = .{ .ctx = n, .get = committeeOf },
                .lsm = indexBuildOptions(),
                .threads = spec.threads,
                .signal = &stop_signal,
            }) catch |e| blk: {
                std.log.warn("snapshot: indexes during the download: {s}; they are built after the restore instead", .{@errorName(e)});
                break :blk null;
            };
        }
        try snapshot.restore(n.gpa, n.io, n.st, .{
            .epoch = epoch,
            .origin = n.snapshotOrigin(spec),
            .threads = spec.threads,
            .eoe_blob = eoe.items,
            .expect_root = spec.expect_root,
            .bulk_live = bulk,
            .sort_by_type = sort,
            .stop = &stop_signal,
            .on_partition = if (rib) |b| b.partitionHook() else null,
            .after_objects = if (rib) |b| b.doneHook() else null,
        }, &stats);
        // The store is restored once its table is durable: `done` is written then, before the
        // derived indexes are waited for, so a stop or a kill while their tables are written
        // costs no download (restore_index.finishRestore; the next start finds the index build
        // pending and resumes it, StateService UNAVAILABLE until it is level).
        // The indexes level with the store before this returns, so the first start serves
        // everything at once: from the stream, else from the restore image now (lane
        // fast-start); skipped with ZUI_FAST_START=0 (node start builds).
        const indexed = try restore_index.finishRestore(n.io, n.node_dir, n.st, epoch, rib);
        n.snapshot_epoch = epoch;
        n.restored_epoch = epoch;
        if (rib) |b| {
            b.destroy();
            rib = null;
        }
        if (fastOn() and !indexed) try n.restoreIndexes(epoch);
        _ = a;
        std.log.info("snapshot: epoch {d} restored in {d} s ({d} objects, {d} MiB fetched); following from its end-of-epoch checkpoint", .{ epoch, (source_mod.nowNs() - t0) / std.time.ns_per_s, stats.objects.load(.monotonic), stats.bytes_fetched.load(.monotonic) >> 20 });
    }

    /// The newest epoch whose MANIFEST the origin serves, searching down from the source tip's epoch.
    fn newestSnapshotEpoch(n: *Node, spec: SnapshotSpec) !u64 {
        const lo = try n.tipSearchFloor();
        const tip = try n.source.latest(lo);
        var sc = source_mod.Scratch.init(n.gpa);
        defer sc.deinit(n.gpa);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(n.gpa);
        if (try n.source.fetch(&sc, tip, &buf) != .ok) return error.SourceMissing;
        const cur = (try checkpoint.Summary.parse((try trust.blobCert(buf.items)).summary)).epoch;
        var f: snapshot.Fetcher = .{ .gpa = n.gpa, .io = n.io, .origin = n.snapshotOrigin(spec) };
        defer f.deinit();
        // `retained`: at most current - retention epochs (the snapshot of epoch E ends at the
        // first checkpoint of E + 1, which must lie at or below sui-node's checkpoint floor)
        const keep: u64 = if (spec.retained) @max(n.st.cfg.retention_epochs, 1) else 0;
        var e = cur -| (keep -| 1);
        while (e > 0 and cur - e < 8 + keep) {
            e -= 1;
            f.get(e, "MANIFEST", &buf) catch continue;
            std.log.info("snapshot: newest formal snapshot is epoch {d} (tip is in epoch {d})", .{ e, cur });
            return e;
        }
        return error.NoSnapshot;
    }

    /// A sequence number known to exist, to start the tip search from: the epoch index's newest
    /// epoch start, or 0.
    fn tipSearchFloor(n: *Node) !u64 {
        const path = n.cfg.epochs_index orelse return 0;
        var tmp: std.heap.ArenaAllocator = .init(n.gpa);
        defer tmp.deinit();
        const idx = try trust.EpochIndex.load(tmp.allocator(), n.io, path);
        var e = idx.first.len;
        while (e > 0) {
            e -= 1;
            if (idx.first[e]) |f| return f;
        }
        return 0;
    }

    /// The saved committee of `epoch`, or a walk to it when none is saved or the saved one lacks
    /// the epoch parameters (the walk's periodic saves carry only the committee; execute mode
    /// needs the reference gas price and start). The walk resumes from the highest saved epoch
    /// below, so it verifies the end of `epoch - 1` in full and finds the parameters.
    fn epochInfo(n: *Node, epoch: u64, tip: u64) !trust.EpochInfo {
        if (try trust.load(n.anchor_arena.allocator(), n.io, n.epochs_dir, epoch)) |info| {
            if ((info.rgp != null and info.start_ms != null) or n.cfg.genesis == null) return info;
        }
        return n.walkTo(epoch, tip);
    }

    fn walkTo(n: *Node, epoch: u64, tip: u64) !trust.EpochInfo {
        return n.walkToOpts(epoch, tip, null);
    }

    /// Walks to `epoch` from genesis (never from a saved committee, so the walk itself verifies
    /// the end-of-epoch checkpoint of `epoch - 1` in full) and hands that checkpoint back.
    fn rpcRestoredObject(ctx: *anyopaque, id: *const [32]u8, version: u64, bytes: []const u8) anyerror!void {
        const x: *serve.rpcindex.Index = @ptrCast(@alignCast(ctx));
        try x.onRestoredObject(id, version, bytes);
    }

    /// GetEpoch records of the `cfg.epoch_records` epochs before the current one that the store
    /// did not follow (a snapshot start, a tip start): each comes from the epoch's end-of-epoch
    /// checkpoint, verified by the trust walk from the saved committee (one fetch per epoch), and
    /// gives the end record of its epoch plus the start record (state, first checkpoint) of the
    /// next. The oldest one only gives the start of the first epoch in range, so no epoch answers
    /// with an end and no start. Records persist, so a restart fetches nothing again. A failure
    /// stops the fill with a warning (those epochs stay NOT_FOUND, as on a node that never saw them).
    fn backfillEpochRecords(n: *Node, x: *serve.rpcindex.Index) void {
        const want = n.cfg.epoch_records;
        if (want == 0 or n.cfg.genesis == null) return;
        const cur = n.cur_epoch;
        if (cur == 0) return;
        const lo = cur -| want; // the first epoch to answer
        const t0 = source_mod.nowNs();
        var fed: u64 = 0;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(n.gpa);
        // the end-of-epoch checkpoint of e gives the end of e and the start of e + 1
        var e: u64 = if (lo > 0) lo - 1 else 0;
        while (e < cur) : (e += 1) {
            const want_end = e >= lo;
            if (!x.epochNeeds(e, want_end)) continue;
            buf.clearRetainingCapacity();
            _ = n.walkToKeep(e + 1, &buf) catch |err| {
                std.log.warn("rpc index: epoch records stop at epoch {d}: the trust walk to its end-of-epoch checkpoint failed ({s})", .{ e, @errorName(err) });
                break;
            };
            if (buf.items.len == 0) break;
            const seq = (checkpoint.Summary.parse((trust.blobCert(buf.items) catch break).summary) catch break).sequence_number;
            x.onEpochCheckpoint(seq, buf.items, want_end) catch |err| {
                std.log.warn("rpc index: end-of-epoch checkpoint {d} (epoch {d}) gave no epoch records ({s})", .{ seq, e, @errorName(err) });
                break;
            };
            fed += 1;
        }
        if (fed > 0) std.log.info("rpc index: epoch records for epochs {d}..{d} from {d} end-of-epoch checkpoints in {d} ms", .{ lo, cur, fed, (source_mod.nowNs() - t0) / std.time.ns_per_ms });
    }

    fn walkToKeep(n: *Node, epoch: u64, eoe: *std.ArrayList(u8)) !trust.EpochInfo {
        const hint = if (n.cfg.epochs_index) |p| blk: {
            var tmp: std.heap.ArenaAllocator = .init(n.gpa);
            defer tmp.deinit();
            const idx = try trust.EpochIndex.load(tmp.allocator(), n.io, p);
            break :blk if (epoch < idx.first.len) idx.first[@intCast(epoch)] else null;
        } else null;
        return n.walkToOpts(epoch, hint orelse try n.source.latest(try n.tipSearchFloor()), eoe);
    }

    fn walkToOpts(n: *Node, epoch: u64, tip: u64, keep: ?*std.ArrayList(u8)) !trust.EpochInfo {
        const a = n.anchor_arena.allocator();
        const gpath = n.cfg.genesis orelse return error.NoTrustRoot;
        const genesis_blob = try Io.Dir.cwd().readFileAlloc(n.io, gpath, a, .limited(1 << 30));
        var srcs: std.ArrayList(*const source_mod.Source) = .empty;
        if (n.cfg.trust_dir) |p| {
            const s = try a.create(source_mod.Source);
            s.* = .{ .gpa = n.gpa, .io = n.io, .kind = .{ .dir = try Io.Dir.cwd().openDir(n.io, p, .{}) } };
            try srcs.append(a, s);
        }
        // An edge (`--source zui1:`) follows cores that hold only their last couple of epochs, so
        // the committee chain from genesis comes from the network's public checkpoint bucket
        // (free, the same trust root a core walks; every certificate is still verified here).
        var trust_http: ?*http.Public = null;
        defer if (trust_http) |h| {
            h.deinit();
            n.gpa.destroy(h);
        };
        if (n.source.kind == .zui1) {
            const h = try n.gpa.create(http.Public);
            h.* = http.Public.init(n.gpa, n.io, n.cfg.network.params().bucket_url);
            trust_http = h;
            const s = try a.create(source_mod.Source);
            s.* = .{ .gpa = n.gpa, .io = n.io, .kind = .{ .http = h } };
            try srcs.append(a, s);
            std.log.info("trust walk: end-of-epoch checkpoints from {s}, then the zui/1 cores", .{h.base});
        }
        try srcs.append(a, &n.source);
        var w: trust.Walker = .{ .gpa = n.gpa, .io = n.io, .sources = srcs.items, .save_dir = n.epochs_dir, .keep_last_eoe = keep, .parallel = @max(16, n.cfg.fetchers) };
        if (n.cfg.epochs_index) |p| w.index = try trust.EpochIndex.load(a, n.io, p);
        // Resume the walk from a saved committee, but at least one step back when the caller
        // wants the last end-of-epoch checkpoint (the walk verifies it in its final step).
        const from = try trust.highestSaved(a, n.io, n.epochs_dir, epoch);
        const info = try w.walk(a, genesis_blob, from, epoch, tip);
        try trust.save(n.io, n.epochs_dir, &info);
        return info;
    }

    // ---------------------------------------------------------------- observer

    /// The ledger-history index follows the store's retention (CONTRACTS 6.8): it drops every
    /// checkpoint below the store's lowest, so List* serve the same window as GetCheckpoint.
    fn pruneHistory(n: *Node) void {
        const h = n.ledger_history orelse return;
        if (!n.lowest_known) return;
        h.pruneBelow(n.lowest.load(.acquire)); // a no-op when nothing lies below
    }

    /// After an unclean stop the store's checkpoint floor comes back as of its last meta write
    /// (store.zig `setFloors`: floors are durable with the next live-table flush or age-out),
    /// below the floor retention had reached; the ledger-history index was pruned to that floor
    /// durably (lhfill.zig `floorWitness`). The node gives the store its floor back before
    /// anything looks at the window. Until this existed every unclean stop left the index's low
    /// end above the store's lowest checkpoint by what retention had pruned since the last
    /// flush (a few hundred checkpoints at the tip), and the backfill then rebuilt the whole
    /// retained window from the store to add them, while retention pruned them again.
    fn restoreFloor(n: *Node, h: *lhist.Index, tip: u64) void {
        if (!n.lowest_known) return;
        const low = n.lowest.load(.acquire);
        const w = (lhfill.restoreFloor(n.st, n.io, h, n.lh_staging, low, tip) catch |e| {
            std.log.err("history: giving the store its checkpoint floor back: {s}", .{@errorName(e)});
            return;
        }) orelse return;
        n.refreshLowest();
        std.log.info("history: the store came back with its lowest checkpoint at {d}, below the floor {d} it had before it stopped (an unclean stop; floors are durable with a live-table flush): floor restored, {d} checkpoints that retention had already passed are not served again; lowest available is {d}", .{ low, w, w - low, n.lowest.load(.acquire) });
    }

    const LhState = enum(u8) { covered = 0, building = 1, gave_up = 2, off = 3 };

    /// Starts the ledger-history backfill (lhfill.zig) when the store holds retained checkpoints
    /// below the index's low end (or the index is empty), built on a thread while the current
    /// index keeps serving. The build reads the store only for the checkpoints no index holds
    /// (those below the current index's low end) and takes the rest from the current index.
    /// What triggers it: an index that is empty or begins above the store's lowest checkpoint
    /// (a store that was followed or restored before the index existed, an index that
    /// restarted at a hole). Not an unclean stop: `restoreFloor` takes that case away.
    fn maybeBackfill(n: *Node, tip: u64) void {
        const h = n.ledger_history orelse return;
        if (n.lh_fill != null or !n.lowest_known) return;
        const lowest = n.lowest.load(.acquire);
        if (tip < lowest) return;
        const gap = lhfill.gapOf(h, lowest, tip);
        if (gap.count() == 0) {
            n.lh_state.store(@intFromEnum(LhState.covered), .release);
            return;
        }
        if (!lhfill.enabled(n.cfg.lh_backfill, if (std.c.getenv("ZUI_LH_BACKFILL")) |v| std.mem.span(v) else null)) {
            if (n.lh_state.swap(@intFromEnum(LhState.off), .acq_rel) != @intFromEnum(LhState.off))
                std.log.warn("history: the backfill is switched off (--no-history-backfill or ZUI_LH_BACKFILL=0). The index holds {?d}..{?d}; checkpoints {d}..{d} ({d}) are in the store and not indexed: ListCheckpoints, ListTransactions and ListEvents answer from {?d}. Retention prunes the gap from below (zui_history_unindexed_checkpoints)", .{ h.indexedLo(), h.indexedHi(), gap.from, gap.to, gap.count(), h.indexedLo() });
            return;
        }
        if (n.lh_fill_tries >= 3) return n.backfillGaveUp(h, gap);
        // Usable CPUs (the cgroup quota included), not the host's.
        const workers = std.math.clamp(usableCpus() / 2, 1, 12);
        n.lh_fill_tries += 1;
        const b = lhfill.Backfill.startOpts(n.gpa, n.io, n.st, lowest, tip, .{ .workers = workers, .staging = n.lh_staging, .live = h, .tip_ms = &n.lh_tip_ms, .mem_bytes = @as(u64, envU32("ZUI_LH_MEM_MB", 256)) << 20, .save_every_ns = @as(u64, envU32("ZUI_LH_SAVE_S", 300)) * std.time.ns_per_s }) catch |e| {
            // Nothing retries a build that could not start: say what stays unindexed.
            std.log.err("history: backfill could not start: {s}", .{@errorName(e)});
            n.lh_fill_err = e;
            return n.backfillGaveUp(h, gap);
        };
        n.lh_fill = b;
        n.lh_state.store(@intFromEnum(LhState.building), .release);
        const begin = b.resumed_at orelse lowest;
        const store_to = b.store_to.load(.monotonic);
        const from_store: u64 = if (store_to < begin) 0 else store_to - begin + 1;
        std.log.info("history: backfill (try {d} of 3): the index holds {?d}..{?d}, the store serves {d}..{d}: {d} checkpoints ({d}..{d}) are not indexed. Reading {d} checkpoints from the store ({d}..{d}, {d} loaders){s}; the rest is copied from the current index, which serves meanwhile. Background work: lowest priority, at most {d} MiB of loaded checkpoints, and it waits whenever the node is more than {d} s behind the tip (ZUI_LH_BACKFILL=0 turns it off)", .{
            n.lh_fill_tries, h.indexedLo(), h.indexedHi(), lowest, tip, gap.count(), gap.from, gap.to, from_store, begin, store_to, workers,
            if (b.resumed_at != null) ", resuming from the staging watermark" else "",
            b.budget >> 20, fast_start.catchup_lag_ms / 1000,
        });
    }

    /// The backfill is not tried again in this run: says so once, with what stays unindexed.
    /// Reads below the index's low end are answered as below the earliest available checkpoint
    /// (lh_service.zig `below_floor`, with the index's low end), never from the gap; on an
    /// edge with a core upstream the lists are passed to the core (edge/route.zig).
    fn backfillGaveUp(n: *Node, h: *lhist.Index, gap: lhfill.Gap) void {
        if (n.lh_state.swap(@intFromEnum(LhState.gave_up), .acq_rel) == @intFromEnum(LhState.gave_up)) return;
        // (gone already after two failed tries; this is for a build that could not start)
        n.dropStaging("the backfill gave up");
        std.log.err("history: backfill gave up after {d} failed tries (last: {s}). The index holds {?d}..{?d}; checkpoints {d}..{d} ({d}) are in the store and NOT indexed: ListCheckpoints, ListTransactions and ListEvents answer from {?d} and report that as their lowest available checkpoint. Not tried again until the next start; retention prunes the gap from below meanwhile (zui_history_unindexed_checkpoints)", .{
            n.lh_fill_tries, @errorName(n.lh_fill_err orelse error.Unknown), h.indexedLo(), h.indexedHi(), gap.from, gap.to, gap.count(), h.indexedLo(),
        });
    }

    /// Commit path, before checkpoint `seq` is indexed: swaps a finished backfill in, caught up
    /// to `seq - 1` (committed). A failed one is dropped and retried (at most 3 tries); one the
    /// index no longer needs (retention passed the gap) is dropped.
    fn adoptBackfill(n: *Node, seq: u64) void {
        const b = n.lh_fill orelse {
            n.lh_mem.store(0, .monotonic);
            n.lh_paused.store(false, .monotonic);
            return;
        };
        const h = n.ledger_history orelse return;
        n.lh_mem.store(b.memoryBytes(), .monotonic);
        n.lh_paused.store(b.paused.load(.monotonic), .monotonic);
        if (n.lowest_known and seq > 0 and b.status() != .ready) {
            const lowest = n.lowest.load(.acquire);
            if (lhfill.gapOf(h, lowest, seq - 1).count() == 0) {
                std.log.info("history: backfill no longer needed: retention moved the store's lowest checkpoint to {d}, and the index holds {?d}..{?d} (nothing unindexed); the build is dropped", .{ lowest, h.indexedLo(), h.indexedHi() });
                b.discard();
                n.lh_fill = null;
                n.lh_fill_tries = 0;
                n.lh_state.store(@intFromEnum(LhState.covered), .release);
                n.dropStaging("its build is no longer needed");
                return;
            }
        }
        switch (b.status()) {
            .running => return,
            .failed => {
                n.lh_fill_err = b.failure orelse error.Unknown;
                std.log.err("history: backfill try {d} of 3 failed: {s} ({d} checkpoints built)", .{ n.lh_fill_tries, @errorName(n.lh_fill_err.?), b.counters.checkpoints.load(.monotonic) + b.copied.load(.monotonic) });
                n.retryBackfill(seq);
                return;
            },
            .ready => {},
        }
        const t0 = source_mod.nowNs();
        const out = b.finish(seq -| 1) catch |e| {
            n.lh_fill_err = e;
            std.log.err("history: backfill try {d} of 3: catch-up to {d}: {s}", .{ n.lh_fill_tries, seq -| 1, @errorName(e) });
            n.retryBackfill(seq);
            return;
        };
        const lo = out.indexedLo();
        h.adopt(out) catch |e| {
            // The live index is unchanged (CURRENT still names its generation); build again
            // (at most 3 tries; a restart resumes from whatever staging state is left).
            n.lh_fill_err = e;
            std.log.err("history: backfill try {d} of 3: adopt: {s}", .{ n.lh_fill_tries, @errorName(e) });
            n.retryBackfill(seq);
            return;
        };
        n.lh_staging_gen = h.generation();
        const c = &b.counters;
        const lowest = n.lowest.load(.acquire);
        const left = lhfill.gapOf(h, lowest, seq -| 1);
        std.log.info("history: backfill done: the index holds {?d}..{d} and the store serves from {d}: {d} checkpoints unindexed. {d} checkpoints and {d} transactions read from the store, {d} checkpoints copied from the previous index, in {d} s ({d} rounds, resumed at {?d}, {d} staging saves, the floor moved {d} times; {d} object versions read, {d} missing; loaded checkpoints held at most {d} MiB, the largest one {d} MiB; waited {d} times, {d} s, for the node to be at the tip); swap {d} ms", .{
            lo, seq -| 1, lowest, left.count(), c.checkpoints.load(.monotonic), c.txs.load(.monotonic), b.copied.load(.monotonic), b.build_ns / std.time.ns_per_s, b.rounds, b.resumed_at, b.saves, b.floor_moves, c.objects.load(.monotonic), c.missing_objects.load(.monotonic), b.peak_bytes.load(.monotonic) >> 20, b.largest.load(.monotonic) >> 20, b.pauses.load(.monotonic), b.paused_ms.load(.monotonic) / 1000, (source_mod.nowNs() - t0) / std.time.ns_per_ms,
        });
        b.destroy();
        n.lh_fill = null;
        n.lh_fill_tries = 0;
        n.lh_fill_err = null;
        n.lh_state.store(@intFromEnum(LhState.covered), .release);
        n.pruneHistory();
    }

    /// Drops a failed backfill and starts it again (at most 3 tries, `maybeBackfill`, which
    /// says so when it gives up). The first retry resumes from the staging watermark; once
    /// that has failed too, the staging state is deleted so the last try builds from the
    /// store's lowest (a staging state that fails the same way on every resume would
    /// otherwise block the backfill on every start).
    fn retryBackfill(n: *Node, seq: u64) void {
        if (n.lh_fill) |b| b.destroy();
        n.lh_fill = null;
        n.lh_state.store(@intFromEnum(LhState.covered), .release);
        if (n.lh_fill_tries >= 2) n.dropStaging("two tries failed from it");
        if (seq > 0) n.maybeBackfill(seq - 1);
    }

    /// Removes the backfill's staging directory (lhfill.zig `removeStaging`) and says what that
    /// freed. A stop ends it between two files; the next start removes the rest.
    fn dropStaging(n: *Node, why: []const u8) void {
        const d = n.lh_staging orelse return;
        n.lh_staging_gen = null;
        const t0 = source_mod.nowNs();
        const r = lhfill.removeStaging(n.io, d, &stop_signal);
        const took = (source_mod.nowNs() - t0) / std.time.ns_per_ms;
        if (r.done) n.lh_staging_bytes.store(0, .monotonic);
        if (r.err) |e| {
            std.log.warn("history: backfill staging {s} could not be removed ({s}): {s}; {d} files, {d} MiB removed", .{ d, why, @errorName(e), r.files, r.bytes >> 20 });
        } else if (!r.done) {
            std.log.info("history: backfill staging: removal ended by the stop after {d} files, {d} MiB; the next start removes the rest", .{ r.files, r.bytes >> 20 });
        } else if (r.files != 0) {
            std.log.info("history: backfill staging removed ({s}): {d} files, {d} MiB freed in {d} ms", .{ why, r.files, r.bytes >> 20, took });
        }
    }

    fn refreshLowest(n: *Node) void {
        var snap = n.st.snapshot();
        defer snap.release();
        if (snapshot.lowestAvailable(&snap, n.restored_epoch)) |l| {
            n.lowest.store(l, .release);
            n.served_lowest.store(if (n.cfg.read_sets) snap.objectsFrom(l) else l, .release);
            n.lowest_known = true;
            n.store_pruned.store(snap.highestPruned() orelse 0, .release);
        }
    }

    /// Retention (CONTRACTS 6.8, node/retention.zig): sui-node's two pruning watermarks, one
    /// tick per 10 s of wall clock, on the writer thread between checkpoints (the follower's
    /// on_idle, after a commit and before the next batch opens). The store applies them as floors and ages
    /// a segment out once both have passed it: nothing is copied, a meta write and some unlinks.
    fn retentionTick(n: *Node) void {
        const cfg: retention.Config = .{
            .checkpoint_epochs = n.st.cfg.retention_epochs,
            .object_epochs = n.st.cfg.object_retention_epochs,
            .smooth = n.st.cfg.smooth,
        };
        const tick_ns = retention.tickMs(cfg.epoch_ms) * std.time.ns_per_ms;
        const now = source_mod.nowNs();
        if (n.ret_last_ns != 0 and now -| n.ret_last_ns < tick_ns) return;
        // Missed ticks (a stall) run now, as tokio's interval bursts them.
        if (n.ret_last_ns == 0) {
            std.log.info("retention: checkpoints {d} epochs, object versions {d} epochs, smooth {}, tick {d} ms (sui-node authority-store-pruning-config)", .{ cfg.checkpoint_epochs, cfg.object_epochs, cfg.smooth, tick_ns / std.time.ns_per_ms });
            if (cfg.checkpoint_epochs < 2) std.log.warn("retention: --retention-epochs {d} is below sui-node's minimum of 2 for checkpoints (allowed for tests and demos)", .{cfg.checkpoint_epochs});
        }
        const ticks: u64 = if (n.ret_last_ns == 0) 1 else @min((now - n.ret_last_ns) / tick_ns, 8640);
        n.ret_last_ns = if (n.ret_last_ns == 0) now else n.ret_last_ns + ticks * tick_ns;
        var snap = n.st.snapshot();
        defer snap.release();
        const hi = snap.highestCommitted() orelse return;
        const cur = (snap.checkpointHeld(hi) orelse return).epoch;
        var m: retention.Marks = .{
            .objects = n.st.obj_floor.load(.monotonic) -| 1,
            .checkpoints = n.st.cp_floor.load(.monotonic) -| 1,
        };
        // A snapshot restore sets both watermarks to the restored checkpoint S (sui-tool).
        if (n.st.cp_floor.load(.monotonic) == 0 and n.st.obj_floor.load(.monotonic) == 0) if (snap.highestPruned()) |s| {
            m = .{ .objects = s, .checkpoints = s };
        };
        // Whatever the store recorded, nothing below its lowest available checkpoint is held:
        // the watermarks start there (a store restored by an older deepwave records no S).
        const low = snapshot.lowestAvailable(&snap, n.restored_epoch);
        m = retention.liftToLowest(m, low orelse 0);
        var lk: LastOf = .{ .n = n, .snap = &snap };
        const chain: retention.Chain = .{ .ctx = &lk, .last_of = LastOf.get };
        for (0..ticks) |_| m = retention.tick(cfg, chain, m, hi, cur);
        const HeldOf = struct {
            fn epochOf(ctx: *anyopaque, seq: u64) ?u64 {
                const s: *const store.Snapshot = @ptrCast(@alignCast(ctx));
                return if (s.checkpointHeld(seq)) |r| r.epoch else null;
            }
        };
        const held: retention.Held = .{ .ctx = &snap, .epoch_of = HeldOf.epochOf };
        const floors: store.Store.Floors = .{
            .cp_pruned = if (m.checkpoints > 0) m.checkpoints else null,
            .obj_pruned = if (m.objects > 0) m.objects else null,
            .cp_epoch = if (m.checkpoints > 0) retention.floorEpoch(held, m.checkpoints + 1, low, hi, cur) else 0,
            .obj_epoch = if (m.objects > 0) retention.floorEpoch(held, m.objects + 1, low, hi, cur) else 0,
        };
        const before = n.lowest.load(.monotonic);
        // The served floor moves first: once the store hides the versions below the new object
        // floor, a request for a checkpoint there must already be answered NOT_FOUND, not fail
        // on a missing input (`refreshLowest` below then sets the exact value).
        if (n.cfg.read_sets) if (floors.obj_pruned) |hp| if (hp + 1 > n.served_lowest.load(.monotonic)) n.served_lowest.store(hp + 1, .release);
        const rep = n.st.setFloors(floors) catch |e| {
            std.log.err("retention: moving the floors (checkpoints {d}, objects {d}) failed: {s}", .{ m.checkpoints, m.objects, @errorName(e) });
            return;
        };
        n.refreshLowest();
        n.pruneHistory();
        n.ret_ticks += ticks;
        const after = n.lowest.load(.monotonic);
        if (rep.segments_aged != 0 or n.ret_ticks % 30 < ticks or (before != after and n.ret_ticks <= ticks)) {
            const aged = n.st.agedSegments();
            std.log.info("retention: tick {d}: objects pruned to {d} (versions from epoch {d}), checkpoints pruned to {d} (epoch {d}); lowest available {d} -> {d}, served from {d}; {d} segments aged out in {d} ms ({d} runs dropped); {d} aged segments ({d} MiB) kept for their live objects", .{
                n.ret_ticks, m.objects, floors.obj_epoch, m.checkpoints, floors.cp_epoch, before, after, n.served_lowest.load(.monotonic), rep.segments_aged, rep.ns / std.time.ns_per_ms, rep.runs_dropped, aged.count, aged.bytes >> 20,
            });
        }
    }

    /// Last checkpoint of an epoch as the store knows it: the checkpoint before the first one
    /// of a later epoch (binary searches over the held checkpoints, cached per ended epoch).
    /// Null when the epoch has not ended or the store holds none of it (sui-node: no pruning).
    const LastOf = struct {
        n: *Node,
        snap: *const store.Snapshot,

        fn get(ctx: *anyopaque, e: u64) ?u64 {
            const l: *LastOf = @ptrCast(@alignCast(ctx));
            if (l.n.ret_last.get(e)) |v| return v;
            const snap = l.snap;
            const hi = snap.highestCommitted() orelse return null;
            const ep = struct {
                fn f(s: *const store.Snapshot, seq: u64) ?u64 {
                    return if (s.checkpointHeld(seq)) |r| r.epoch else null;
                }
            }.f;
            if ((ep(snap, hi) orelse return null) <= e) return null;
            var lo: u64 = 0;
            var h = hi;
            while (lo < h) {
                const mid = lo + (h - lo) / 2;
                if (snap.checkpointHeld(mid) != null) h = mid else lo = mid + 1;
            }
            if ((ep(snap, h) orelse return null) > e) return null;
            var a = h;
            var b = hi;
            while (b - a > 1) {
                const mid = a + (b - a) / 2;
                if ((ep(snap, mid) orelse return null) > e) b = mid else a = mid;
            }
            l.n.ret_last.put(l.n.gpa, e, a) catch {};
            return a;
        }
    };

    /// Bytes of segment cleaning per checkpoint (CONTRACTS 6.8): about 16 MiB of reads per
    /// checkpoint, so a sparse aged segment is copied out over minutes without stalling the
    /// follower; dense ones (the restored live set) are never copied.
    const clean_budget: u64 = 16 << 20;

    fn clean(n: *Node) void {
        if (n.clean_failed) return;
        // A snapshot being written reads object chains as of an older checkpoint: no segment
        // may move under it.
        if (n.snap_busy.load(.acquire)) return;
        // Paced (retention.Pace): a share of the time the follower spends elsewhere, so a cold
        // store slows cleaning down instead of the follower (lane catchup-1306).
        const deadline = n.clean_pace.begin(source_mod.nowNs()) orelse {
            n.clean_skipped.store(n.clean_pace.skipped, .monotonic);
            return;
        };
        const rep = n.st.cleanStepUntil(clean_budget, deadline) catch |e| {
            n.clean_failed = true;
            std.log.err("retention: segment cleaning failed: {s} (cleaning stops; restart to retry)", .{@errorName(e)});
            return;
        };
        n.clean_pace.end(source_mod.nowNs());
        if (rep.tombstones_dropped != 0) _ = n.clean_tombstones.fetchAdd(rep.tombstones_dropped, .monotonic);
        {
            const pr = n.st.cleanProgress();
            n.clean_phase.store(pr.phase, .monotonic);
            n.clean_done.store(pr.done, .monotonic);
            n.clean_total.store(pr.total, .monotonic);
            n.clean_table_ahead.store(pr.table_ahead, .monotonic);
            n.clean_cut.store(pr.cut, .monotonic);
            n.clean_steps.store(n.clean_pace.steps, .monotonic);
        }
        if (rep.segments_dropped != 0) {
            const aged = n.st.agedSegments();
            std.log.info("retention: cleaned {d} sparse segment ({d} MiB), carried {d} live objects ({d} MiB), dropped {d} tombstones; {d} aged segments ({d} MiB) remain", .{
                rep.segments_dropped, rep.bytes_dropped >> 20, n.clean_carried + rep.objects_carried, rep.bytes_carried >> 20, rep.tombstones_dropped, aged.count, aged.bytes >> 20,
            });
            n.clean_carried = 0;
        } else n.clean_carried += rep.objects_carried;
    }

    /// The restore image (lane fast-start) of a store restored from a formal snapshot. Off with
    /// ZUI_FAST_START=0.
    /// After a restore of `epoch` (its `done` marker is written: a stop here resumes at the next
    /// start, which builds beside the follower): the StateService index (with `--indexes`) and
    /// the rpc index's package floors (with `--serve`) from one walk of the restore image, made
    /// durable at the restored checkpoint.
    fn restoreIndexes(n: *Node, epoch: u64) !void {
        if (!n.cfg.indexes and n.cfg.serve_addr == null) return;
        var snap = n.st.snapshot();
        const at = snap.highestCommitted() orelse {
            snap.release();
            return;
        };
        snap.release();
        const t0 = source_mod.nowNs();
        var j: fast_start.Job = .{ .gpa = n.gpa, .st = n.st, .image = .{ .epoch = epoch, .at = at }, .signal = &stop_signal };
        const arena = n.anchor_arena.allocator();
        var ix: ?*index.Index = null;
        defer if (ix) |x| x.deinit();
        var feed: index.feed.Feed = undefined;
        if (n.cfg.indexes) {
            ix = try index.Index.open(n.gpa, n.io, try std.fs.path.join(arena, &.{ n.cfg.dir, "state-index" }), indexBuildOptions());
            feed = index.feed.Feed.init(n.gpa, ix.?, n.st);
            j.feed = &feed;
            j.build = true;
        }
        defer if (j.feed) |f| f.deinit();
        var rx: ?*serve.rpcindex.Index = null;
        defer if (rx) |x| x.deinit();
        if (n.cfg.serve_addr != null) {
            rx = try serve.rpcindex.Index.open(n.gpa, n.io, try std.fs.path.join(arena, &.{ n.cfg.dir, "rpc" }));
            rx.?.committees = .{ .ctx = n, .get = committeeOf };
            j.rpc = rx;
            j.floors = true;
        }
        j.buildNow() catch |e| {
            if (e == error.Stopped) std.log.info("snapshot: index build stopped (it resumes at the next start)", .{});
            return e;
        };
        if (rx) |x| {
            var s2 = n.st.snapshot();
            defer s2.release();
            try x.finishSeed(&s2, at);
        }
        std.log.info("snapshot: indexes built from the restore image at checkpoint {d} in {d} s ({d} objects)", .{ at, (source_mod.nowNs() - t0) / std.time.ns_per_s, j.image_objects.load(.monotonic) });
    }

    /// Bulk-build options of the StateService index.
    /// Threads (ZUI_INDEX_BUILD_THREADS): the env value, else one per usable CPU up to 32. The
    /// index's own default (0) is the host's CPU count: 32 build threads inside a 4-core cgroup.
    /// Memory (ZUI_INDEX_BUILD_MEM_MB): what the partitioned build (index/bulk.zig) may
    /// allocate, by default an eighth of the memory this process can use (`indexBuildMemory`).
    /// ZUI_INDEX_BULK=0 selects the sort-and-merge build instead; only that one reads
    /// ZUI_INDEX_BUILD_GROUPS (passes over the live set: 1 needs temp space for every row, 4,
    /// its default, a quarter of it but reads the live set four times) and it holds one 96 MiB
    /// sort buffer a thread whatever the memory limit.
    fn indexBuildOptions() index.lsm.Options {
        var opts: index.lsm.Options = .{};
        if (std.c.getenv("ZUI_INDEX_BUILD_GROUPS")) |g| opts.build_groups = std.fmt.parseInt(u32, std.mem.span(g), 10) catch opts.build_groups;
        if (std.c.getenv("ZUI_INDEX_BUILD_THREADS")) |g| opts.build_threads = std.fmt.parseInt(usize, std.mem.span(g), 10) catch 0;
        if (opts.build_threads == 0) opts.build_threads = indexBuildThreads(usableCpus());
        if (std.c.getenv("ZUI_INDEX_BULK")) |v| opts.bulk = !std.mem.eql(u8, std.mem.span(v), "0");
        opts.build_mem_bytes = indexBuildMemory(core.hw.detect(null).ram_bytes);
        if (std.c.getenv("ZUI_INDEX_BUILD_MEM_MB")) |v| {
            const mb = std.fmt.parseInt(usize, std.mem.span(v), 10) catch 0;
            if (mb != 0) opts.build_mem_bytes = mb << 20;
        }
        return opts;
    }

    /// Memory the state index build may allocate when this process can use `ram` bytes (the
    /// cgroup's memory.max or memory.high when there is one, core/hw.zig; 0: unknown): an
    /// eighth of it, between 512 MiB and 4 GiB. 2 GiB in a 16 GiB unit.
    pub fn indexBuildMemory(ram: u64) usize {
        if (ram == 0) return 1 << 30;
        return @intCast(std.math.clamp(ram / 8, 512 << 20, 4 << 30));
    }

    /// Index build threads for `usable` CPUs (index/lsm.zig caps its own default at 32 too).
    pub fn indexBuildThreads(usable: u32) usize {
        return std.math.clamp(usable, 1, 32);
    }

    /// CPUs this process can use: the affinity mask capped by the cgroup CPU quota of its own
    /// cgroup and its parents (sync.follower.usableCpus, core/hw.zig).
    pub fn usableCpus() u32 {
        return sync.follower.usableCpus();
    }

    /// Live objects from which a store without a restore image builds its indexes from a
    /// live-set scan in the background instead of before serving (ZUI_LIVE_SCAN_MIN).
    fn liveScanMin() u64 {
        const v = std.c.getenv("ZUI_LIVE_SCAN_MIN") orelse return 4_000_000;
        return std.fmt.parseInt(u64, std.mem.span(v), 10) catch 4_000_000;
    }

    fn fastOn() bool {
        const v = std.c.getenv("ZUI_FAST_START") orelse return true;
        return !std.mem.eql(u8, std.mem.span(v), "0");
    }

    fn restoreImage(n: *Node, snap: *const store.Snapshot) ?fast_start.Image {
        if (!fastOn()) return null;
        // ZUI_RESTORE_IMAGE=0: as if the image had aged out (rig test of the live-scan path)
        if (std.c.getenv("ZUI_RESTORE_IMAGE")) |v| if (std.mem.eql(u8, std.mem.span(v), "0")) return null;
        const m = snapshot.readMarker(n.io, n.node_dir) catch return null;
        if (m.state != .done) return null;
        return fast_start.findImage(snap, m.epoch);
    }

    fn fastJob(n: *Node, img: ?fast_start.Image) !*fast_start.Job {
        if (n.fast) |j| {
            if (j.image == null) j.image = img;
            return j;
        }
        const j = try n.gpa.create(fast_start.Job);
        j.* = .{ .gpa = n.gpa, .st = n.st, .image = img };
        n.fast = j;
        return j;
    }

    /// StateService indexes on disk under `<dir>/state-index` (lane index-disk): built from the
    /// live set when there is no usable index, else replayed from its watermark; then served.
    fn startIndexes(n: *Node) !void {
        const dir = try std.fs.path.join(n.anchor_arena.allocator(), &.{ n.cfg.dir, "state-index" });
        const x = try index.Index.open(n.gpa, n.io, dir, indexBuildOptions());
        n.ix = x;
        const f = try n.gpa.create(index.feed.Feed);
        f.* = index.feed.Feed.init(n.gpa, x, n.st);
        n.ix_feed = f;
        if (fastOn()) {
            var snap = n.st.snapshot();
            defer snap.release();
            const reason = f.buildReason(&snap);
            const img = n.restoreImage(&snap);
            const lag = if (snap.highestCommitted()) |tip| tip -| (x.checkpoint orelse 0) else 0;
            const big = n.st.liveCount() >= liveScanMin() and x.db.onDisk();
            if ((reason != null and (img != null or big)) or (reason == null and lag > 64)) {
                const j = try n.fastJob(img);
                j.feed = f;
                j.build = reason != null;
                std.log.info("state index: {s} in the background (fast start; watermark {?d}, store tip {?d}); StateService answers UNAVAILABLE until it is live", .{ reason orelse "replay", x.checkpoint, snap.highestCommitted() });
                n.service.state = index.state.hook(x);
                n.exec_rpc.setIndex(x); // gas selection answers UNAVAILABLE until the index is live
                return;
            }
        }
        const rep = try f.start();
        if (rep.build) |b| std.log.info("state index: built from {d} live objects ({s}): {d} rows, {d} MiB on disk in {d} s ({d} parts resumed)", .{ b.objects, rep.reason.?, b.entries, b.bytes >> 20, b.ms / 1000, b.resumed_parts });
        std.log.info("state index: at checkpoint {?d} (store tip {?d}), {d} checkpoints replayed, {d} MiB on disk, {d} MiB in memory, ready in {d} ms", .{ x.checkpoint, rep.tip, rep.replayed, x.db.diskBytes() >> 20, x.db.indexMemory() >> 20, rep.ms });
        n.service.state = index.state.hook(x);
        n.exec_rpc.setIndex(x);
    }

    fn onCheckpoint(ctx: *anyopaque, seq: u64, c: *const sync.verify.Checked, blob: []const u8) void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        n.prof.mark(.wait);
        defer n.prof.mark(.misc);
        if (!n.lowest_known) n.refreshLowest();
        // (The retention tick and the cleaning step run in onIdle, after the commit.)
        // The index changes are computed before the commit (old versions still live) and applied
        // in onCommitted, so the index trails the store as sui-node's rpc-store does.
        if (n.ix_feed) |f| if (f.ix.ready.load(.acquire)) f.prepare(seq, blob) catch |e| std.log.err("indexes: checkpoint {d}: {s}", .{ seq, @errorName(e) });
        n.prof.mark(.ix_prepare);
        {
            var ts: std.posix.timespec = undefined;
            _ = std.c.clock_gettime(.REALTIME, &ts);
            const now_ms: u64 = @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
            const i = n.lat_n.load(.monotonic);
            n.lat_ring[i % n.lat_ring.len].store(@intCast(@min(now_ms -| c.timestamp_ms, std.math.maxInt(u32))), .monotonic);
            n.lat_n.store(i + 1, .release);
            n.noteLag(now_ms -| c.timestamp_ms);
            if (n.fetcher) |f| if (f.arrivalMs(seq)) |am| {
                const j = n.arr_n.load(.monotonic);
                n.arr_ring[j % n.arr_ring.len].store(@intCast(@min(am -| c.timestamp_ms, std.math.maxInt(u32))), .monotonic);
                n.arr_n.store(j + 1, .release);
            };
        }
        if (n.fast) |j| j.tip_ts_ms.store(c.timestamp_ms, .monotonic);
        n.lh_tip_ms.store(c.timestamp_ms, .monotonic);
        {
            var arrival: ?u64 = null;
            var archive = false;
            if (n.fetcher) |f| {
                arrival = f.arrivalMs(seq);
                archive = n.noteSources(f, seq, c.timestamp_ms) == .bucket;
            }
            n.cp_metrics.taken(seq, c.timestamp_ms, c.network_total_transactions, c.epoch, arrival, archive);
        }
        if (n.p2p) |pp| pp.noteApplied(seq, c.timestamp_ms);
        if (c.epoch != n.cur_epoch) {
            n.cur_epoch = c.epoch;
            if (n.next_pv) |p| n.cur_pv = p;
            n.next_pv = null;
            n.guard.noteEpoch(n.cur_pv, c.epoch, seq);
            if (n.next_params) |p| {
                if (p.start_ms) |b| if (n.cur_params.start_ms) |a| if (b > a) n.epoch_duration_ms.store(b - a, .monotonic);
                n.cur_params = p;
            }
            n.next_params = null;
        }
        if (n.ledger_history) |h| {
            // Indexed before the store commit; published once committed (seq - 1 here, the tip from statusLoop).
            n.adoptBackfill(seq);
            if (n.lh_staging_gen) |g| if (h.persistedGeneration() >= g) {
                std.log.info("history: adopted backfill persisted (generation {d})", .{g});
                n.dropStaging("the index adopted from it is durable");
            };
            h.addCheckpoint(seq, blob) catch |e| std.log.err("history: index checkpoint {d}: {s}", .{ seq, @errorName(e) });
            // The index (re)started at this checkpoint while the store holds older ones.
            if (n.lh_fill == null and seq > 0) if (h.indexedLo()) |lo| if (lo == seq) n.maybeBackfill(seq - 1);
            if (seq > 0) h.publish(seq - 1);
            n.prof.mark(.ledger);
        }
        n.guard.noteCheckpoint();
        if (n.executor) |x| if (!n.exec_off and !n.guard.skipExec(n.cur_pv)) {
            x.submit(seq, c.epoch, n.cur_pv, n.cur_params, blob);
            if (n.cfg.halt_on_mismatch and x.mismatchSeen() and n.failure == null) {
                n.failure = "execute mismatch";
                n.follower.stop();
            }
        };
        if (n.rpc) |x| if (x.ready.load(.acquire)) {
            // Before this checkpoint's batch commits; rows are idempotent, a replay rewrites them.
            // Any failure stops the node: the store would otherwise commit a checkpoint the index
            // never gets again (the watermark stays put, so a restart replays it from the store).
            x.onCheckpoint(seq, blob) catch |e| {
                std.log.err("rpc index: checkpoint {d}: {s}", .{ seq, @errorName(e) });
                return n.fatal("rpc index write failed");
            };
            // The watermark file is fsynced every rpcindex.wm_sync_every checkpoints, not here
            // per checkpoint; a stale one is levelled with the store at the next start (seed).
            x.commitLazy(seq) catch |e| {
                std.log.err("rpc index: commit {d}: {s}", .{ seq, @errorName(e) });
                return n.fatal("rpc index write failed");
            };
            n.prof.mark(.rpc);
        };
        if (c.end_of_epoch) |eoe| {
            // Persist the next committee before this checkpoint's batch is committed.
            const a = n.anchor_arena.allocator();
            const keys = a.alloc([96]u8, eoe.nextEpochCommittee.len) catch return n.fatal("out of memory");
            const stakes = a.alloc(u64, eoe.nextEpochCommittee.len) catch return n.fatal("out of memory");
            for (eoe.nextEpochCommittee, keys, stakes) |m, *k, *s| {
                k.* = m[0].@"0";
                s.* = m[1];
            }
            var params = blk: {
                var idx = types.CheckpointIndex.init(n.gpa) catch return n.fatal("out of memory");
                defer idx.deinit(n.gpa);
                break :blk trust.epochParamsOfBlob(a, blob, &idx) catch trust.EpochParams{};
            };
            // Safe mode emits no SystemEpochInfoEvent and keeps the reference gas price.
            if (params.rgp == null) params.rgp = n.cur_params.rgp;
            const info: trust.EpochInfo = .{ .epoch = c.epoch + 1, .protocol_version = eoe.nextEpochProtocolVersion.@"0", .keys = keys, .stakes = stakes, .rgp = params.rgp, .start_ms = params.start_ms };
            trust.save(n.io, n.epochs_dir, &info) catch |e| {
                std.log.err("persist committee of epoch {d}: {s}", .{ info.epoch, @errorName(e) });
                return n.fatal("cannot persist the next committee");
            };
            n.next_pv = info.protocol_version;
            n.next_params = params;
            n.guard.noteEpochEnd(info.protocol_version, c.epoch, seq);
            if (n.cfg.sui_conservation != .off) n.cons_pending = .{ .seq = seq, .epoch = c.epoch };
            if (n.cfg.snapshot_write != null) {
                for (eoe.epochCommitments) |cm| switch (cm) {
                    .ECMHLiveObjectSetDigest => |d| n.snap_pending = .{ .seq = seq, .epoch = c.epoch, .root = d.digest.@"0" },
                    else => {},
                };
                if (n.snap_pending == null) std.log.warn("snapshot write: epoch {d} has no state commitment; skipped", .{c.epoch});
            }
            std.log.info("epoch {d} ends at checkpoint {d}; committee of epoch {d} saved (protocol {d}, reference gas price {?d})", .{ c.epoch, seq, info.epoch, info.protocol_version, params.rgp });
        }
    }

    /// Follower read-ahead (prefetch thread only): the ids of `<seq>.aux`'s objects, which
    /// history.onBatch looks up in the store (`inputAction`) on the apply thread.
    fn prefetchAux(ctx: *anyopaque, seq: u64, ids: *std.ArrayList([32]u8)) void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        const h = n.history orelse return;
        const d = h.aux_dir orelse return;
        var nb: [48]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, "{d}.aux", .{seq}) catch return;
        const file = d.openFile(n.io, name, .{}) catch return;
        defer file.close(n.io);
        const size: usize = @intCast((file.stat(n.io) catch return).size);
        if (size > 256 << 20) return;
        n.pf_aux_buf.resize(n.gpa, size) catch return;
        if ((file.readPositionalAll(n.io, n.pf_aux_buf.items, 0) catch return) != size) return;
        _ = n.pf_aux_arena.reset(.{ .retain_with_limit = 4 << 20 });
        const aux = convert.Aux.parse(n.pf_aux_arena.allocator(), n.pf_aux_buf.items) catch return;
        for (aux.objects) |raw| {
            const k = exec.objects.keyOf(raw) catch continue;
            ids.append(n.gpa, k.id) catch return;
        }
    }

    fn onCommitted(ctx: *anyopaque, seq: u64) void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        n.prof.mark(.commit);
        n.cp_metrics.executed(seq);
        defer {
            n.prof.mark(.publish);
            n.prof.checkpoint();
        }
        const cons = if (n.cons_pending) |p| p.seq == seq else false;
        const snap_p = if (n.snap_pending) |p| (if (p.seq == seq) p else null) else null;
        if (cons or snap_p != null) {
            const epoch = if (snap_p) |p| p.epoch else n.cons_pending.?.epoch;
            if (cons) n.cons_pending = null;
            if (snap_p != null) n.snap_pending = null;
            n.startEpochJobs(seq, epoch, if (snap_p) |p| p.root else null, cons);
        }
        if (n.fast) |j| j.onCommitted(seq);
        if (n.ix_feed) |f| if (f.ix.ready.load(.acquire)) f.publish(seq) catch |e| std.log.err("indexes: publish checkpoint {d}: {s}", .{ seq, @errorName(e) });
        // an edge with a core upstream: wakes what waits for this checkpoint (edge/forward.zig)
        if (n.edge_fwd) |f| f.noteApplied();
    }

    /// Follower `on_idle`: the writer thread's background work, once checkpoint `seq` is committed,
    /// published and the follower has moved past it. Until lane tip-cheap both calls sat at the
    /// top of onCheckpoint, so an arriving checkpoint first paid the retention tick and a cleaning
    /// step (about 48 ms at the tip while a clean is in progress, retention.Pace) before its own
    /// commit. No batch is open here either, which is all setFloors and cleanStepUntil ask for,
    /// and the order between checkpoints is unchanged (commit, publish, tick, clean, next
    /// checkpoint): only the wait for the next checkpoint now comes after the step, not before.
    fn onIdle(ctx: *anyopaque, seq: u64) void {
        _ = seq;
        const n: *Node = @ptrCast(@alignCast(ctx));
        // fast start: the background job reads the restore image segment; cleaning and
        // retention wait until the indexes are live
        if (n.fast != null and n.fast.?.active()) return;
        n.retentionTick();
        n.prof.mark(.retention);
        n.clean();
        n.prof.mark(.clean);
    }

    /// `rpcindex.CommitteeSource`: the committee the node persisted for `epoch` (trust.save).
    fn committeeOf(ctx: *anyopaque, arena: std.mem.Allocator, epoch: u64) ?[]const serve.sysstate.Member {
        const n: *Node = @ptrCast(@alignCast(ctx));
        const info = (trust.load(arena, n.io, n.epochs_dir, epoch) catch return null) orelse return null;
        const out = arena.alloc(serve.sysstate.Member, info.keys.len) catch return null;
        for (out, info.keys, info.stakes) |*m, *k, st| m.* = .{ .key = k, .weight = st };
        std.mem.sort(serve.sysstate.Member, out, {}, struct {
            fn lt(_: void, a: serve.sysstate.Member, b: serve.sysstate.Member) bool {
                return std.mem.lessThan(u8, a.key, b.key);
            }
        }.lt);
        return out;
    }

    fn onBatch(ctx: *anyopaque, seq: u64, c: *const sync.verify.Checked, blob: []const u8, b: *store.Batch) anyerror!void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        n.prof.mark(.apply);
        defer n.prof.mark(.state_hash);
        if (n.cons_failed.load(.acquire)) {
            n.cons_failed.store(false, .release);
            if (n.executor != null and !n.exec_off) {
                n.exec_off = true;
                std.log.err("sui conservation: execute mode off, following in verify-only mode", .{});
            }
            if (n.cfg.sui_conservation == .halt and n.failure == null) {
                n.failure = "sui conservation failed";
                n.follower.stop();
            }
        }
        // An edge: a checkpoint that did not come from a core's feed is marked (durably) before
        // this batch is committed. An error stops the commit: its certificate would be another
        // source's with nothing saying so.
        if (n.edge_certs) |cv| try cv.onBatch(seq);
        if (n.history) |h| try h.onBatch(n.st, seq, c, blob, b);
        if (n.reconcile) |r| try r.applied(seq, n.history.?.last_built, b);
        n.prof.mark(.history);
        const pv = if (c.epoch != n.cur_epoch) (n.next_pv orelse n.cur_pv) else n.cur_pv;
        switch (try n.state_hash.onBatch(seq, c, blob, b, pv)) {
            .none, .ok => {},
            .mismatch => {
                // Verify-only from here: the store keeps certified data only.
                if (n.executor != null and !n.exec_off) {
                    n.exec_off = true;
                    std.log.err("state hash: execute mode off, following in verify-only mode", .{});
                }
                if (n.cfg.state_hash == .halt and n.failure == null) {
                    n.failure = "state hash mismatch";
                    n.follower.stop();
                }
            },
        }
    }

    /// serve's ReadSetSource: the store holds the whole read set of checkpoint `seq` and it is
    /// final. A checkpoint built here over p2p whose lists still wait to be compared with
    /// sui-node's (reconcile.zig) is not: a repair may replace them.
    fn readSetHeld(ctx: *const anyopaque, snap: *const store.Snapshot, seq: u64) bool {
        const n: *const Node = @ptrCast(@alignCast(ctx));
        if (!history.readSetHeld(snap, seq)) return false;
        if (n.reconcile) |r| if (history.p2pBuilt(snap, seq) and r.isWaiting(seq)) return false;
        return true;
    }

    /// serve's LoadedSource: the stored loaded runtime object list of a transaction, read through
    /// the request's snapshot. The slice points into the store (a decoded chunk on compressed
    /// segments) and stays valid while that snapshot lives.
    fn loadedOf(ctx: *const anyopaque, snap: *const store.Snapshot, digest: *const [32]u8, at: u64) []const serve.objset.Ref {
        _ = ctx;
        return history.loadedListNear(serve.objset.Ref, snap, digest, at);
    }

    /// p2p.zig: the epoch parameters execution needs (the current epoch, or the next one once
    /// the end-of-epoch checkpoint is committed).
    fn p2pParams(ctx: *anyopaque, epoch: u64) ?@import("p2p_exec.zig").Params {
        const n: *Node = @ptrCast(@alignCast(ctx));
        if (epoch == n.cur_epoch) {
            return .{ .chain = n.cfg.network.params().chain, .pv = n.cur_pv, .rgp = n.cur_params.rgp orelse return null, .start_ms = n.cur_params.start_ms orelse return null };
        }
        if (epoch == n.cur_epoch + 1) if (n.next_params) |np| {
            return .{ .chain = n.cfg.network.params().chain, .pv = n.next_pv orelse return null, .rgp = np.rgp orelse return null, .start_ms = np.start_ms orelse return null };
        };
        return null;
    }

    fn printP2p(n: *Node) void {
        const pp = n.p2p orelse return;
        const x = &pp.stats;
        const built = x.built.load(.monotonic);
        const fb = x.fallbacks.load(.monotonic);
        std.log.info("p2p: {d} connects ({d} failed), {d} pushes, {d} polls, {d} summaries ({d} first by push), {d} contents ({d} errors, {d} MiB), built {d}, delivered first {d}, lost race {d}, late {d}, fallbacks {d} ({d:.2}%), chain-link rejects {d}, txs {d}, served {d} ({d} contents)", .{
            x.connects.load(.monotonic),        x.connect_errors.load(.monotonic),  x.pushes.load(.monotonic),                                                                                     x.polls.load(.monotonic),         x.summaries.load(.monotonic), x.first_by_push.load(.monotonic),
            x.contents.load(.monotonic),        x.contents_errors.load(.monotonic), x.contents_bytes.load(.monotonic) >> 20,                                                                       built,                            x.delivered.load(.monotonic), x.lost_race.load(.monotonic),
            x.late.load(.monotonic),            fb,                                 if (built + fb == 0) @as(f64, 0) else @as(f64, @floatFromInt(fb)) * 100 / @as(f64, @floatFromInt(built + fb)), x.rejected_link.load(.monotonic), x.txs.load(.monotonic),       x.served.load(.monotonic),
            x.served_contents.load(.monotonic),
        });
        std.log.info("p2p peers: {d} up (max {d}), {d} distinct peers connected, {d} candidates, {d} discovery queries; failed connects {d}: {d} silent, {d} refused (closed after handshake or stalled), {d} wrong peer, {d} local", .{
            x.peers_up.load(.monotonic),       x.peers_max.load(.monotonic),      x.peers_ever.load(.monotonic),      pp.cands.count(),                      x.discovery_queries.load(.monotonic),
            x.connect_errors.load(.monotonic), x.connect_silent.load(.monotonic), x.connect_refused.load(.monotonic), x.connect_wrong_peer.load(.monotonic), x.connect_local.load(.monotonic),
        });
        std.log.info("p2p load: {d} pushes ({d} for a checkpoint already seen), {d} polls ({d} poll ticks skipped), {d} contents requests ({d} lost the race), {d} checkpoints with contents paused, active set {d} peers ({d} elections), {d} seed addresses kept from slots", .{
            x.pushes.load(.monotonic),   x.push_dups.load(.monotonic),       x.polls.load(.monotonic),           x.polls_skipped.load(.monotonic), x.fetches.load(.monotonic),
            x.race_lost.load(.monotonic), x.contents_paused.load(.monotonic), @popCount(pp.active.load(.monotonic)), x.elections.load(.monotonic),     x.slot_seed_skips.load(.monotonic),
        });
        for (pp.reasons, pp.reason_counts) |r, c| if (r) |why| std.log.info("p2p fallback {d}x: {s}", .{ c, why });
        @import("p2p_only.zig").printScores(pp);
        if (pp.p2p_only) @import("p2p_only.zig").printSummary(pp, n.follower.failure != null);
    }

    fn fatal(n: *Node, why: []const u8) void {
        if (n.failure == null) n.failure = why;
        n.follower.stop();
    }

    // ---------------------------------------------------------------- run

    pub fn run(n: *Node) !void {
        // From here statusLoop handles signals (graceful stop).
        startup_done.store(true, .release);
        // startupWatch returns within 50 ms of startup_done: join it (never detach a thread that
        // may already have finished).
        if (startup_thread) |t| {
            t.join();
            startup_thread = null;
        }
        // Age-out by data type (store holes + punches) on its own thread, off the commit path.
        // Off by default: `--age-out [on|defer]`, a profile or ZUI_AGE_OUT turns it on,
        // `--age-out off` or ZUI_AGE_OUT=0 forces it off.
        if (n.ageOutMode()) |mode| {
            n.st.startAgerMode(mode) catch |e| std.log.err("store: age-out thread: {s}", .{@errorName(e)});
            // Which reader the ager's read-ahead has (counted in zui_store_age_warm_uring_pages
            // and zui_store_age_warm_fallback_pages; errors in zui_store_age_warm_errors).
            switch (n.st.ageReader()) {
                .uring => std.log.info("store: age-out read-ahead: io_uring page reader, {d} reads in flight, {d}% of the ager's time", .{ n.st.cfg.age_qd, n.st.cfg.age_share_pct }),
                .fallback => std.log.info("store: age-out read-ahead: no io_uring, madvise and a touch per page, {d}% of the ager's time", .{n.st.cfg.age_share_pct}),
                .none => std.log.info("store: age-out read-ahead: off (ZUI_AGE_SERIAL), a page fault per lookup", .{}),
            }
            if (mode == .deferred) std.log.info("store: age-out deferred while the node is more than {d} s behind the tip (it catches up in one run once {d} MiB of history wait below the checkpoint floor)", .{ fast_start.catchup_lag_ms / 1000, n.st.cfg.age_defer_bytes >> 20 });
        }
        // p2p-only: the fetcher is only the spool and its claims (no fetch threads).
        if (n.fetcher) |f| {
            const threads: u32 = if (n.cfg.p2p_only) 0 else @max(1, n.cfg.fetchers);
            try f.start(threads);
            n.logFetchConcurrency(threads);
        }
        // An edge: marked certificates are replaced with the core's while it follows a core.
        if (n.edge_certs) |cv| try cv.start();
        for (n.streams.items) |st| {
            try st.start();
            std.log.info("live stream from {s} (SubscribeCheckpoints over gRPC-web); the source fills gaps", .{st.base});
        }
        if (n.reask) |r| try r.start();
        if (n.reconcile) |r| {
            try r.start();
            std.log.info("p2p read-set reconcile: {d} lists reinstalled, {d} checkpoints waiting", .{ r.stats.loaded.load(.monotonic), r.stats.pending.load(.monotonic) });
        }
        if (n.p2p) |pp| {
            try pp.start();
            std.log.info("p2p state sync from {d} peers (peer id {x}); every transaction executed locally", .{ pp.peers.len, pp.key.public_key.toBytes() });
        }
        if (n.p2p_server) |srv| {
            try srv.start();
            if (n.cfg.p2p_listen) |text| {
                const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.BadP2pListen;
                const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.BadP2pListen;
                const host = std.mem.trim(u8, text[0..colon], "[]");
                const addr = Io.net.IpAddress.parse(host, port) catch return error.BadP2pListen;
                // The listener is optional for a full node (no client of ours depends on peers
                // reaching us): a port already taken (sui-node beside us on 8084) is a warning.
                n.p2p_listener = @import("net").server.Listener.start(n.gpa, n.io, .{
                    .listen = addr,
                    .key = srv.key,
                    .server_name = n.cfg.network.params().p2p_server_name,
                    .handler = srv.handler(),
                    .threads = n.cfg.p2p_listen_threads,
                }) catch |e| blk: {
                    std.log.warn("p2p: cannot listen on {s} ({s}); serving peers on outbound connections only", .{ text, @errorName(e) });
                    break :blk null;
                };
                srv.attachListener(n.p2p_listener);
                if (n.p2p_listener != null) std.log.info("p2p: serving state sync and discovery on {s} (peer id {x}, access {s}{s}{s})", .{ text, srv.key.public_key.toBytes(), @tagName(srv.access), if (srv.external != null) ", advertised " else "", srv.external orelse "" });
            }
        }
        if (n.cfg.indexes) try n.startIndexes();
        // Before serving: the fixes the sweep already found are installed by `open`.
        if (n.sig_order) |ov| if (n.cfg.sig_order_sweep) {
            const sw = try sigorder.Sweep.open(n.gpa, n.io, n.st, ov, n.node_dir);
            n.sig_sweep = sw;
            try sw.start();
            std.log.info("signature order sweep from {s}: {d} fixes reinstalled, resuming at {s}", .{ ov.base, sw.stats.loaded.load(.monotonic), if (sw.next != null) "the last mark" else "the lowest checkpoint" });
        };
        if (n.fast) |j| try j.start();
        n.resumeSnapshotWrite();
        if (n.cfg.gate) |gs| try n.startGate(gs);
        if (n.cfg.serve_addr) |addr| try n.startServe(addr);
        if (n.cfg.serve_tls_addr) |addr| if (n.cfg.serve_addr != null) try n.startServeTls(addr);
        if (n.cfg.native_listen) |addr| try n.startNative(addr);
        if (n.cfg.metrics_addr) |addr| try n.startMetrics(addr);
        if (n.cfg.metrics_push_url) |url| {
            const p = try n.gpa.create(metricspush.Pusher);
            p.* = .{ .gpa = n.gpa, .io = n.io, .url = url, .interval_s = @max(n.cfg.metrics_push_interval_s, 1), .source = .{ .ctx = n, .render = renderMetricsOpaque } };
            n.metrics_pusher = p;
            try p.start();
        }
        if (n.cfg.admin_port) |port| n.startAdmin(port);
        n.guard.noteEpoch(n.cur_pv, n.cur_epoch, n.first_seq);
        if (n.cfg.handoff_sock) |path| n.startHandoff(path);
        try n.threads.append(n.gpa, try std.Thread.spawn(.{}, statusLoop, .{n}));
        n.started_ns = source_mod.nowNs();
        std.log.info("following from checkpoint {d} ({s} mode, {s})", .{ n.first_seq, @tagName(n.cfg.mode), if (n.fetcher != null) "fetch-ahead" else "direct" });

        // The follower treats a missing blob as a source error when it has an end (`to`): right
        // for a complete directory, wrong for the spool, which fills as the fetcher goes. With the
        // spool the follower runs open-ended and the status loop stops it once `to` is applied.
        var res = n.follower.run(if (n.fetcher != null) null else n.cfg.to);
        // An edge with several cores: a feed that fails verification is that core's lie, not the
        // chain's. The checkpoint is fetched again from another core before the node gives up.
        if (n.edge_pool) |pool| {
            var tries: u32 = 0;
            while (tries < 8) : (tries += 1) {
                _ = res catch |e| {
                    if (e != error.BadCheckpoint) break;
                    const fl = n.follower.failure orelse break;
                    if (!n.refetchFromOtherCore(pool, fl.seq)) break;
                    std.log.warn("edge: checkpoint {d} failed verification ({s}); fetched again from another core{s}", .{ fl.seq, fl.verdict.name(), if (n.edge_fb != null) " or the fallback" else "" });
                    n.follower.rewind();
                    res = n.follower.run(if (n.fetcher != null) null else n.cfg.to);
                    continue;
                };
                break;
            }
        }
        // Every committed checkpoint's transactions finish before the final status.
        if (n.executor) |x| {
            stopPhase("executor drain");
            x.drain();
            if (n.cfg.halt_on_mismatch and x.mismatchSeen() and n.failure == null) n.failure = "execute mismatch";
        }
        n.stopping.store(true, .release);
        n.shutdownThreads();
        if (n.follower.failure) |fl| {
            std.log.err("REJECTED checkpoint {d}: {s}", .{ fl.seq, fl.verdict.name() });
            n.failure = "rejected checkpoint";
        }
        res catch |e| switch (e) {
            error.Stopped => {},
            else => {
                std.log.err("follower stopped: {s}", .{@errorName(e)});
                if (n.failure == null) n.failure = @errorName(e);
            },
        };
        n.printStatus(true);
        if (n.failure) |f| return if (std.mem.eql(u8, f, "rejected checkpoint") or std.mem.eql(u8, f, "execute mismatch")) error.Mismatch else error.NodeFailed;
    }

    /// Marks the core that served `seq` as bad for it and spools the checkpoint again from another
    /// core, or, when none is left and the edge has a fallback, from the fallback.
    fn refetchFromOtherCore(n: *Node, pool: *edge.client.Pool, seq: u64) bool {
        const f = n.fetcher orelse return false;
        var sc = source_mod.Scratch.init(n.gpa);
        defer sc.deinit(n.gpa);
        var blob: std.ArrayList(u8) = .empty;
        defer blob.deinit(n.gpa);
        var from_core = false;
        if (pool.blame(seq)) {
            // Straight from the pool: with a fallback the source might route this elsewhere.
            const r = n.source.poolFetch(pool, &sc, seq, &blob, edge.client.Pool.no_deadline, null) catch return false;
            if (r != .ok) return false;
            from_core = true;
        } else {
            const fb = n.edge_fb orelse return false;
            const r = fb.fetchFromFallback(&n.source, &sc, seq, &blob) catch return false;
            if (r != .ok) return false;
        }
        // (the refused copy's aux record, if it left one, must not go with this blob; the
        // origin is this copy's)
        f.writeSpoolAgain(seq, blob.items, sc.aux.items, from_core) catch return false;
        return true;
    }

    /// How long RPC connections get to end by themselves after the stop: the h2 grace
    /// (`--drain-ms`, 20 s: calls in flight are answered, open streams served) and one poll tick
    /// of a connection thread (1 s), by which an idle connection has seen the stop.
    fn rpcDrainNs(drain_ms: u32) u64 {
        return @as(u64, drain_ms) * std.time.ns_per_ms + std.time.ns_per_s;
    }

    /// How long the threads of the connections the server then closes itself get to leave. They
    /// sit in a system call the shutdown of their socket ends, so this is scheduling time. With
    /// `rpcDrainNs` it is `drain_ms` + 2 s, what `stop_drain_s` already adds to the stop
    /// deadline: the forced close costs the stop no time it did not have.
    const rpc_force_ns: u64 = std.time.ns_per_s;

    fn secondSignal() bool {
        return signals.load(.acquire) >= 2;
    }

    /// The RPC server's part of a stop, after `serve_stop` is set and the listeners are woken:
    /// connections end by themselves within the drain (`serve.h2.server.drainThenForce`), the
    /// ones that do not (a peer that stopped reading, half a TLS record, a stream at the end of
    /// its grace) are closed by the server, and their threads are gone before this returns. The
    /// store can then be closed whatever the clients did. Until this existed such a connection
    /// left the node `undrained`: the store was flushed but not closed, and the next start
    /// checked every page of the live table. `undrained` now only means a call is still running
    /// in a handler: no thread is interrupted in the middle of a read of the store.
    fn drainRpc(n: *Node, cut: ?*const fn () bool) void {
        const st = &serve.h2.server.stats;
        const drain_ns: u64 = if (n.rpc_drained) 0 else rpcDrainNs(n.cfg.drain_ms);
        n.rpc_drained = true;
        const d = serve.h2.server.drainThenForce(drain_ns, rpc_force_ns, cut);
        n.undrained = !d.drained;
        const took = d.waited_ns / std.time.ns_per_ms;
        if (d.forced != 0) std.log.warn("shutdown: {d} RPC connections did not end within the drain and were closed by the server", .{d.forced});
        if (d.drained) {
            std.log.info("shutdown: RPC drained in {d} ms", .{took});
        } else std.log.warn("shutdown: {d} connections, {d} calls and {d} streams still running after {d} ms; the store will be flushed, not closed", .{ st.conns.load(.acquire), st.jobs.load(.acquire), st.pumps.load(.acquire), took });
    }

    /// Tells everything that fetches checkpoints to stop, without waiting for any of it: the
    /// fetch threads, the bucket and S3 clients (requests in flight end within ~100 ms, netguard.timed),
    /// fetchers asleep on the download cap, and for a zui1 source the core pool, the fallback
    /// and its prober (source.zig `requestStop`). Called when the follower is stopped by a
    /// signal and again by shutdownThreads on every way out.
    fn requestFetchStop(n: *Node) void {
        if (n.public) |p| p.stopping.store(true, .release);
        if (n.bucket) |b| b.stopping.store(true, .release);
        http.net_cap.stopping.store(true, .release);
        source_mod.requestStop(n.fetcher, &n.source, n.edge_prober);
    }

    fn shutdownThreads(n: *Node) void {
        // The listeners are closed below: no HELLO may be answered with them (handoff.zig).
        handoff.closeOffers();
        // Before any join below: nothing that fetches goes on while the rest is torn down, and
        // by the time the fetch threads are joined they have long seen the flag.
        n.requestFetchStop();
        // The forwarder's threads too (a read of the core's floor may be in flight).
        if (n.edge_fwd) |f| f.requestStop();
        if (n.edge_certs) |cv| cv.requestStop();
        stopPhase("ledger-history backfill (loaders, staging save)");
        // The ledger-history backfill's loaders read the store and what the follower and
        // indexes own: cancel and join them before anything is torn down (follower.run has
        // returned, so the commit path no longer adopts it). Joined later (deinit) they read
        // freed state: SIGSEGV in lhfill.load on ~8% of SIGTERMs within the backfill.
        // The loaders see the stop between two transactions; the save that follows makes what
        // was built durable (one segment rotation), so the next start resumes from here.
        if (n.lh_fill) |b| {
            const tb = source_mod.nowNs();
            const built = b.counters.checkpoints.load(.monotonic) + b.copied.load(.monotonic);
            const through = b.out.indexedHi();
            b.destroy();
            n.lh_fill = null;
            std.log.info("stop: ledger-history backfill stopped and saved through checkpoint {?d} in {d} ms ({d} checkpoints built this run; the next start resumes after it)", .{ through, (source_mod.nowNs() - tb) / std.time.ns_per_ms, built });
        }
        stopPhase("background jobs (epoch jobs, fast start)");
        n.snap_cancel.store(true, .release);
        if (n.snap_thread) |t| {
            t.join();
            n.snap_thread = null;
        }
        if (n.fast) |j| j.shutdown();
        stopPhase("p2p and live streams");
        const t0 = source_mod.nowNs();
        if (n.p2p_listener) |l| {
            if (n.p2p_server) |srv| srv.detachListener();
            l.stop();
            n.p2p_listener = null;
        }
        const t1 = source_mod.nowNs();
        for (n.streams.items) |st| if (st.thread != null) st.stop();
        const t2 = source_mod.nowNs();
        var t3 = t2;
        if (n.p2p) |pp| if (pp.threads.items.len > 0) {
            pp.stop();
            t3 = source_mod.nowNs();
            n.printP2p();
        };
        if (n.reconcile) |r| r.quit();
        if (n.reask) |r| r.requestStop();
        std.log.info("stop: p2p listener {d} ms, streams {d} ms, p2p {d} ms", .{ (t1 - t0) / std.time.ns_per_ms, (t2 - t1) / std.time.ns_per_ms, (t3 - t2) / std.time.ns_per_ms });
        // Bucket requests in flight end within ~100 ms (netguard.timed) and zui/1 calls at their
        // next turn (requestFetchStop above), so the joins below never wait on a socket.
        n.edge_stop.store(true, .release);
        if (n.sig_order) |o| o.stopping.store(true, .release);
        stopPhase("signature order sweep, read-set reconcile");
        if (n.sig_sweep) |sw| sw.join();
        if (n.reconcile) |r| r.stop();
        if (n.reask) |r| r.stop();
        stopPhase("fetch threads");
        const tf = source_mod.nowNs();
        if (n.fetcher) |f| f.stop();
        std.log.info("stop: fetch threads {d} ms", .{(source_mod.nowNs() - tf) / std.time.ns_per_ms});
        // The forwarder's threads end; calls in flight end with their connections.
        if (n.edge_fwd) |f| f.stop();
        // The certificate thread (its call to a core ended with the pool's stop).
        if (n.edge_certs) |cv| cv.stop();
        stopPhase("zui/1 listener, certificates, dictionary warm-up");
        // Subscription streams end (service_shutdown); the hub itself lives until exit, as
        // detached connection threads may still hold it.
        if (n.hub) |h| h.stop();
        if (n.native_listener) |l| {
            l.stop();
            n.native_listener = null;
        }
        if (n.native_certhttp) |h| {
            h.stop(n.gpa);
            n.native_certhttp = null;
        }
        if (n.native_certs) |cs| {
            cs.deinit();
            n.native_certs = null;
        }
        // (only its reload thread: a detached connection thread may still hold the chain)
        if (n.serve_tls_certs) |cs| cs.halt();
        if (n.edge_warm) |t| {
            t.join();
            n.edge_warm = null;
        }
        stopPhase("serve threads and the calls in flight");
        n.serve_stop.store(true, .release);
        // Wake the accept loops before joining them, and close the sockets only after: on Linux
        // closing a listening socket does not wake a blocked accept() (bench-rig run 1: the node
        // never exited at --to with --serve or --metrics), and closing first would let the fd
        // number be reused under a thread still inside accept().
        if (n.serve_server) |*s| wakeListener(n.io, s);
        if (n.serve_tls_server) |*s| wakeListener(n.io, s);
        if (n.metrics_server) |*s| wakeListener(n.io, s);
        for (n.threads.items) |t| t.join();
        n.threads.clearRetainingCapacity();
        // Every exit path (signal, --to, a fatal error) lets the calls in flight finish before
        // the store closes under them (a no-op after gracefulStop drained).
        if (n.serve_server != null) n.drainRpc(null);
        // After the last call: what the gate counted goes to its spool (a clean stop loses
        // nothing). Its threads end without waiting on the network (requests in flight to the
        // gate service are canceled).
        if (n.gate) |ng| ng.stop();
        if (n.serve_server) |*s| s.deinit(n.io);
        n.serve_server = null;
        if (n.serve_tls_server) |*s| s.deinit(n.io);
        n.serve_tls_server = null;
        if (n.metrics_server) |*s| s.deinit(n.io);
        n.metrics_server = null;
    }

    /// Makes a thread blocked in accept() on `srv` return: shutdown() fails a blocked accept on
    /// Linux (SocketNotListening); a connection to the socket wakes it where shutdown of a
    /// listening socket does not (macOS). The accept loops check their stop flag after each accept.
    fn wakeListener(io: Io, srv: *const Io.net.Server) void {
        const st: Io.net.Stream = .{ .socket = srv.socket };
        // A socket handed to a successor (handoff.zig) is shared: shutdown() would end it for the
        // new process too, so only the connect below wakes the accept loop.
        // Nor does it connect: the wake connection would sit in the shared backlog and a real client
        // accepted ahead of it would be reset. The handed-over accept loops poll their stop flag.
        if (handoff.isReleasing()) return;
        st.shutdown(io, .both) catch {};
        var addr = srv.socket.address;
        switch (addr) {
            .ip4 => |*a| if (std.mem.allEqual(u8, &a.bytes, 0)) {
                a.bytes = .{ 127, 0, 0, 1 };
            },
            .ip6 => |*a| if (std.mem.allEqual(u8, &a.bytes, 0)) {
                a.bytes[15] = 1;
            },
        }
        if (addr.connect(io, .{ .mode = .stream })) |c| c.close(io) else |_| {}
    }

    pub fn stop(n: *Node) void {
        n.follower.stop();
    }

    /// Clean shutdown of the store (seals the memtable, flushes the live index).
    pub fn deinit(n: *Node) void {
        // The handoff thread outlives this node until finishActive: it must not read the node
        // (freed at the end of deinit) from here on.
        handoff.closeOffers();
        if (n.metrics_pusher) |p| {
            p.deinit();
            n.gpa.destroy(p);
            n.metrics_pusher = null;
        }
        n.disk_usage.stop();
        if (n.admin_server) |s| s.deinit();
        if (n.rpc_metrics_on) {
            n.rpc_metrics.uninstall();
            n.rpc_metrics.deinit();
        }
        n.state_hash.deinit();
        stopPhase("executor, follower and index teardown");
        // Executor jobs hold store snapshots: end them before the store closes.
        if (n.executor) |x| x.stop();
        n.ret_last.deinit(n.gpa);
        n.exec_rpc.deinit();
        n.follower.deinit();
        if (n.ix_feed) |f| {
            f.deinit();
            n.gpa.destroy(f);
        }
        if (n.ix) |x| {
            x.deinit();
            n.gpa.destroy(x);
        }
        if (n.p2p_server) |srv| {
            srv.deinit();
            n.gpa.destroy(srv);
            n.p2p_server = null;
        }
        // Normally gone already (shutdownThreads); never leave its loaders reading a closed
        // store (SIGSEGV in table.KeyView.Iter.next and LiveTable.get, lane stop-fetch).
        if (n.lh_fill) |b| {
            b.destroy();
            n.lh_fill = null;
        }
        const tc = source_mod.nowNs();
        // From here the deadline is the store close's own (`closeDeadline`).
        closeDeadline();
        if (n.undrained) {
            // Only when a call is still running in a handler after the drain and the forced
            // close (`drainRpc`): its thread may still read the store's mappings. Flush the
            // live table (as a normal flush, safe under readers) and leave the mappings to the
            // process exit; the next start checks the whole table.
            n.st.flushIndex() catch |e| std.log.err("store flush: {s}", .{@errorName(e)});
            std.log.warn("shutdown: store flushed in {d} ms, not closed (a call is still running in a handler); the next start replays from the flush and checks the live table", .{(source_mod.nowNs() - tc) / std.time.ns_per_ms});
            return;
        }
        n.st.close() catch |e| std.log.err("store close: {s}", .{@errorName(e)});
        std.log.info("shutdown: store flushed and closed in {d} ms", .{(source_mod.nowNs() - tc) / std.time.ns_per_ms});
        if (n.rpc) |x| x.deinit();
        if (n.ledger_history) |h| h.deinit();
        n.rio.deinit();
        if (n.executor) |x| {
            x.deinit();
            n.gpa.destroy(x);
        }
        for (n.streams.items) |st| {
            const x = &st.stats;
            std.log.info("live stream {s}: {d} connects ({d} failed), {d} messages, {d} delivered first, {d} duplicates, {d} outside the window, {d} bad, {d} MiB", .{ st.base, x.connects.load(.monotonic), x.connect_errors.load(.monotonic), x.messages.load(.monotonic), x.delivered.load(.monotonic), x.dups.load(.monotonic), x.skipped.load(.monotonic), x.bad.load(.monotonic), x.bytes.load(.monotonic) >> 20 });
            n.gpa.destroy(st);
        }
        n.streams.deinit(n.gpa);
        if (n.sig_sweep) |sw| {
            if (n.sig_order) |o| o.stopping.store(true, .release);
            sw.join();
            const x = &sw.stats;
            std.log.info("signature order sweep: next {d}, {d} checkpoints, {d} candidates, {d} requests, {d} fixed, {d} same, {d} unavailable, {d} rejected, {d} retries", .{ sw.pos.load(.monotonic), x.checkpoints.load(.monotonic), x.candidates.load(.monotonic), x.requests.load(.monotonic), x.fixed.load(.monotonic), x.same.load(.monotonic), x.unavailable.load(.monotonic), x.rejected.load(.monotonic), x.retries.load(.monotonic) });
            sw.deinit();
            n.sig_sweep = null;
        }
        if (n.sig_order) |o| {
            const x = &o.stats;
            std.log.info("signature order from {s}: {d} wanted, {d} requests, {d} served, {d} not found, {d} over budget, {d} timeouts, {d} errors", .{ o.base, x.wanted.load(.monotonic), x.requests.load(.monotonic), x.served.load(.monotonic), x.not_found.load(.monotonic), x.throttled.load(.monotonic), x.timeouts.load(.monotonic), x.errors.load(.monotonic) });
            o.deinit();
            n.gpa.destroy(o);
            n.sig_order = null;
        }
        if (n.fetcher) |f| {
            if (f.inflight) |fl| {
                const st = &fl.ctl.stats;
                std.log.info("edge feed in flight: ended at {d}, peak {d} ({d} at once on the wire); {d} pipelined calls for {d} checkpoints; {d} grows, {d} shrinks, {d} back-offs (errors or a slow core), {d} growth steps that did not fetch faster", .{ fl.target.load(.monotonic), st.peak, fl.peak.load(.monotonic), fl.calls.load(.monotonic), fl.fetched.load(.monotonic), st.grows, st.shrinks, st.backoffs, st.plateaus });
                n.gpa.destroy(fl);
            }
            n.gpa.destroy(f);
        }
        if (n.reconcile) |r| {
            const x = &r.stats;
            std.log.info("p2p read-set reconcile: {d} checkpoints compared ({d} stream copies, {d} bucket copies), {d} repaired ({d} lists, {d} objects), {d} waiting", .{ x.reconciled.load(.monotonic), x.from_stream.load(.monotonic), x.from_bucket.load(.monotonic), x.repaired_checkpoints.load(.monotonic), x.repairs.load(.monotonic), x.objects_added.load(.monotonic), x.pending.load(.monotonic) });
            r.deinit();
            n.reconcile = null;
        }
        if (n.reask) |r| {
            const st = &r.pool.stats;
            const sd = &st.read_sets_settled;
            const gu = &st.read_sets_gave_up;
            const G = edge.client.ReadSetsGaveUp;
            std.log.info("edge read sets asked again: {d} requests; settled by attempt {d}/{d}/{d}/{d}/{d}; given up {d} (unsettled {d}, other core {d}, window {d}, no connection {d}, dropped {d}, error {d})", .{ st.read_sets_reasked.load(.monotonic), sd[0].load(.monotonic), sd[1].load(.monotonic), sd[2].load(.monotonic), sd[3].load(.monotonic), sd[4].load(.monotonic), st.gaveUpTotal(), gu[@intFromEnum(G.unsettled)].load(.monotonic), gu[@intFromEnum(G.other_core)].load(.monotonic), gu[@intFromEnum(G.window)].load(.monotonic), gu[@intFromEnum(G.no_conn)].load(.monotonic), gu[@intFromEnum(G.dropped)].load(.monotonic), gu[@intFromEnum(G.@"error")].load(.monotonic) });
            if (n.edge_fwd) |f| f.read_set_hold = null;
            n.source.reask = null;
            r.deinit();
            n.gpa.destroy(r);
            n.reask = null;
        }
        if (n.history) |h| {
            h.deinit();
            n.gpa.destroy(h);
        }
        if (n.edge_prober) |pr| {
            pr.deinit();
            n.edge_prober = null;
        }
        if (n.edge_fb) |fb| {
            const st = &fb.sw.stats;
            std.log.info("edge fallback: {d} switches to the fallback, {d} back; {d} checkpoints from the cores, {d} from the fallback; {d} probes ({d} good); ended on {s}", .{ st.to_fallback.load(.monotonic), st.to_core.load(.monotonic), st.from_core.load(.monotonic), st.from_fallback.load(.monotonic), st.probes.load(.monotonic), st.probes_ok.load(.monotonic), if (fb.sw.mode() == .core) "zui1" else "the fallback" });
            n.source.edge_fb = null;
            if (fb.src.kind == .dir) fb.src.kind.dir.close(n.io);
            n.gpa.destroy(fb);
            n.edge_fb = null;
        }
        if (n.edge_certs) |cv| {
            cv.stop();
            const cs = &cv.certs.stats;
            std.log.info("edge certificates: {d} marked, {d} replaced with the core's, {d} already equal, {d} pruned first; {d} still marked", .{ cs.marked.load(.monotonic), cs.replaced.load(.monotonic), cs.equal.load(.monotonic), cs.pruned.load(.monotonic), cv.certs.pending() });
            // With a forwarder the marked set lives until exit, like the forwarder: connection
            // threads that outlive the drain may still ask it.
            if (n.edge_fwd == null) cv.deinit();
            n.edge_certs = null;
        }
        if (n.edge_pool) |p| {
            const st = &p.stats;
            std.log.info("edge source: {d} requests, {d} failovers, {d} errors, {d} KiB on the wire, {d} KiB feeds, {d} KiB blobs", .{ st.requests.load(.monotonic), st.failovers.load(.monotonic), st.errors.load(.monotonic), st.wire_bytes.load(.monotonic) >> 10, st.raw_bytes.load(.monotonic) >> 10, st.blob_bytes.load(.monotonic) >> 10 });
            p.deinit();
            n.edge_pool = null;
        }
        if (n.edge_feeder) |f| {
            n.gpa.destroy(f);
            n.edge_feeder = null;
        }
        if (n.native_dicts) |x| {
            x.deinit();
            n.gpa.destroy(x);
            n.native_dicts = null;
        }
        if (n.native_policy) |p| {
            p.deinit();
            n.native_policy = null;
        }
        if (n.public) |h| {
            const st = &h.stats;
            std.log.info("public bucket: {d} gets, {d} hits, {d} misses, {d} errors, {d} MiB, {d} via S3 fallback", .{ st.gets.load(.monotonic), st.hits.load(.monotonic), st.misses.load(.monotonic), st.errors.load(.monotonic), st.bytes.load(.monotonic) >> 20, st.fallback.load(.monotonic) });
            h.deinit();
            n.gpa.destroy(h);
        }
        if (n.bucket) |b| {
            n.logSpend();
            b.deinit();
            n.gpa.destroy(b);
        }
        n.threads.deinit(n.gpa);
        n.anchor_arena.deinit();
        if (n.lock_fd) |fd| dbcheckpoint.unlock(fd);
        n.pf_aux_buf.deinit(n.gpa);
        n.pf_aux_arena.deinit();
        n.gpa.destroy(n);
    }

    fn logSpend(n: *Node) void {
        const b = n.bucket orelse return;
        var buf: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "{{\"gets\":{d},\"misses\":{d},\"bytes\":{d},\"usd\":{d:.4}}}\n", .{ b.stats.gets.load(.monotonic), b.stats.misses.load(.monotonic), b.stats.bytes.load(.monotonic), b.stats.usd() }) catch return;
        std.log.info("s3 spend: {s}", .{line[0 .. line.len - 1]});
        const f = n.node_dir.createFile(n.io, "spend.jsonl", .{ .truncate = false }) catch return;
        defer f.close(n.io);
        const end = (f.stat(n.io) catch return).size;
        f.writePositionalAll(n.io, line, end) catch {};
    }

    // ---------------------------------------------------------------- status, cleaning, signals

    /// SIGTERM/SIGINT (FULLNODE-PARITY section 10; sui-node drops its runtimes without either):
    /// 1. stop accepting and drain: h2 connections get GOAWAY and serve their open streams for
    ///    `drain_ms`, HTTP/1.1 ones finish the response in flight, subscription streams end
    ///    (the follower keeps applying meanwhile, so answers stay current);
    /// 2. stop the follower after the checkpoint it is applying (run() then joins the threads);
    /// 3. flush and close the store (deinit).
    /// The deadline is the kernel timer `onSignal` armed (SIGALRM, `onDeadline`), re-armed below
    /// once the drain ends. No watchdog thread: the one this spawned (64 KiB stack, detached)
    /// aborted every stop on Linux (train/4 rehearsal: `reached unreachable code` in
    /// std.Thread's pthread path inside gracefulStop, SIGABRT, no clean close, a log replay on
    /// the next start): glibc counts the binary's static TLS against a requested stack size, so
    /// a small stack is refused (EINVAL), and std treats that as unreachable. The alarm already
    /// bounded the stop well under `shutdown_timeout_s`.
    fn gracefulStop(n: *Node) void {
        // No takeover is served from this node from here on (a successor that connects now gets BUSY).
        handoff.closeOffers();
        const st = &serve.h2.server.stats;
        stopPhase("rpc drain");
        std.log.info("signal: stopping; draining {d} RPC connections ({d} calls, {d} streams in flight)", .{ st.conns.load(.monotonic), st.jobs.load(.monotonic), st.pumps.load(.monotonic) });
        if (n.serve_server) |*s| {
            n.serve_stop.store(true, .release);
            if (n.hub) |h| h.stop();
            // The forwarded streams end with the local ones: one left open held the drain for
            // all of --drain-ms.
            if (n.edge_fwd) |f| f.endStreams();
            wakeListener(n.io, s);
            n.drainRpc(secondSignal);
            if (signals.load(.acquire) >= 2) std.log.warn("signal: second signal, drain cut short", .{});
            // The drain is over: the rest of the stop gets the plain deadline (lane fast-start).
            _ = std.c.alarm(deadlineS());
        }
        stopPhase("follower (the checkpoint in hand)");
        n.follower.stop();
        // Nothing more is applied: the fetch stage stops with the follower, so its threads are
        // out by the time shutdownThreads joins them and no request outlives the stop.
        n.requestFetchStop();
    }

    /// The end-of-epoch jobs on their own thread, in order: the SUI conservation check (`cons`),
    /// then the formal snapshot of `epoch` (`root` set). Both read the live set as of `seq`.
    fn startEpochJobs(n: *Node, seq: u64, epoch: u64, root: ?[32]u8, cons: bool) void {
        if (n.snap_busy.load(.acquire)) {
            std.log.warn("epoch jobs: epoch {d} skipped (conservation check, snapshot write), the previous epoch's are still running", .{epoch});
            return;
        }
        if (n.snap_thread) |t| {
            t.join();
            n.snap_thread = null;
        }
        n.snap_busy.store(true, .release);
        n.st.agePause(true);
        n.snap_thread = std.Thread.spawn(.{}, epochJobsMain, .{ n, seq, epoch, root, cons }) catch |e| {
            n.snap_busy.store(false, .release);
            n.st.agePause(false);
            std.log.err("snapshot write: epoch {d}: {s}", .{ epoch, @errorName(e) });
            return;
        };
    }

    /// Node start with `--snapshot-write` (lane index-fast): the last ended epoch's snapshot, when
    /// its directory has no MANIFEST and the store is still in the next epoch (a stop or crash
    /// during the online write, which runs once, at the epoch end, otherwise lost that epoch).
    /// Not for the epoch a restore loaded (sui-node writes snapshots of epochs it executed).
    fn resumeSnapshotWrite(n: *Node) void {
        const path = n.cfg.snapshot_write orelse return;
        var arena: std.heap.ArenaAllocator = .init(n.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var snap = n.st.snapshot();
        defer snap.release();
        const top = snap.highestCommitted() orelse return;
        const top_rec = snap.checkpointHeld(top) orelse return;
        const Eoe = struct { seq: u64, epoch: u64, root: [32]u8 };
        const rootOf = struct {
            fn f(ar: std.mem.Allocator, sn: *const store.Snapshot, seq: u64) ?[32]u8 {
                const rec = (sn.checkpointChecked(seq) catch return null) orelse return null;
                const summary = (trust.splitCert(rec.summary_cert) catch return null).summary;
                return snapshot.commitmentOf(ar, summary) catch null;
            }
        }.f;
        const eoe: Eoe = if (rootOf(a, &snap, top)) |r| .{ .seq = top, .epoch = top_rec.epoch, .root = r } else blk: {
            if (top_rec.epoch == 0) return;
            var lk: LastOf = .{ .n = n, .snap = &snap };
            const seq = LastOf.get(&lk, top_rec.epoch - 1) orelse return;
            const r = rootOf(a, &snap, seq) orelse return;
            break :blk .{ .seq = seq, .epoch = top_rec.epoch - 1, .root = r };
        };
        if (n.restored_epoch) |re| if (re == eoe.epoch) return;
        const mpath = std.fmt.allocPrint(a, "{s}/epoch_{d}/MANIFEST", .{ path, eoe.epoch }) catch return;
        if (Io.Dir.cwd().access(n.io, mpath, .{})) |_| return else |_| {}
        std.log.info("snapshot write: epoch {d} (checkpoint {d}) has no snapshot in {s}; writing it now (the node stopped before its write finished)", .{ eoe.epoch, eoe.seq, path });
        n.startEpochJobs(eoe.seq, eoe.epoch, eoe.root, false);
    }

    fn epochJobsMain(n: *Node, seq: u64, epoch: u64, root: ?[32]u8, cons: bool) void {
        defer n.snap_busy.store(false, .release);
        defer n.st.agePause(false);
        if (cons) n.conservationCheck(seq, epoch);
        if (root) |r| n.snapshotWrite(seq, epoch, r);
    }

    const cons_threads = 3;

    /// sui-node's `expensive_check_sui_conservation` at the end of `epoch` (conservation.zig).
    fn conservationCheck(n: *Node, seq: u64, epoch: u64) void {
        std.log.info("sui conservation: starting the check at the end of epoch {d} (checkpoint {d})", .{ epoch, seq });
        // A fixed worker count, not one per 4 cores: the check runs beside the follower inside
        // the node's memory fence, and its speed does not matter (nothing waits for it).
        const r = conservation.scan(n.gpa, n.st, seq, .{ .threads = cons_threads, .cancel = &n.snap_cancel }) catch |e| {
            if (e != error.Cancelled) std.log.err("sui conservation: epoch {d}: {s} (not checked)", .{ epoch, @errorName(e) });
            return;
        };
        const want = conservation.loadExpected(n.io, n.node_dir);
        const v = conservation.judge(&r, want);
        n.cons_stats.note(&r, v);
        conservation.logReport(&r, v, want, false);
        switch (v) {
            .first => if (r.expected()) |e| conservation.saveExpected(n.io, n.node_dir, e, r.epoch) catch |err| std.log.err("sui conservation: save expected values: {s}", .{@errorName(err)}),
            .ok => {},
            .mismatch, .unresolved => n.cons_failed.store(true, .release),
        }
    }

    fn snapshotWrite(n: *Node, seq: u64, epoch: u64, root: [32]u8) void {
        const path = n.cfg.snapshot_write.?;
        Io.Dir.cwd().createDirPath(n.io, path) catch {};
        const out = Io.Dir.cwd().openDir(n.io, path, .{}) catch |e| {
            std.log.err("snapshot write: open {s}: {s}", .{ path, @errorName(e) });
            return;
        };
        defer out.close(n.io);
        std.log.info("snapshot write: epoch {d} (checkpoint {d}) to {s}/epoch_{d}", .{ epoch, seq, path, epoch });
        var stats: snapwrite.Stats = .{};
        const r = snapwrite.write(n.gpa, n.io, n.st, out, .{ .epoch = epoch, .checkpoint = seq, .expect_root = root, .threads = n.cfg.snapshot_write_threads, .cancel = &n.snap_cancel }, &stats) catch |e| {
            std.log.err("snapshot write: epoch {d}: {s} (nothing published)", .{ epoch, @errorName(e) });
            return;
        };
        std.log.info("snapshot write: epoch {d} done: {d} objects, {d} MiB ({d} MiB stored, {d} files) in {d} s; root {x} equals the certified commitment", .{ epoch, r.objects, r.bytes >> 20, r.stored >> 20, r.files, r.ms / 1000, r.root });
    }

    fn statusLoop(n: *Node) void {
        var last_print = source_mod.nowNs();
        var cleaned: u64 = n.first_seq;
        while (!n.stopping.load(.acquire)) {
            n.io.sleep(.fromMilliseconds(100), .awake) catch {};
            if (stop_signal.load(.acquire)) {
                n.gracefulStop();
                return;
            }
            const applied = n.follower.applied_next.load(.acquire);
            if (n.fetcher) |f| {
                const stuck = f.stuck.load(.acquire);
                if (stuck != std.math.maxInt(u64) and applied >= stuck) {
                    std.log.err("source serves bad data for checkpoint {d}; stopping", .{stuck});
                    n.fatal("source serves bad data");
                    return;
                }
            }
            if (n.ledger_history) |h| if (applied > 0) h.publish(applied - 1);
            if (n.fetcher != null) if (n.cfg.to) |to| if (applied > to) {
                n.follower.stop();
                return;
            };
            if (n.fetcher) |f| if (applied > cleaned) {
                f.clean(cleaned, applied);
                cleaned = applied;
            };
            const now = source_mod.nowNs();
            if (n.cfg.status_every_s > 0 and now - last_print >= @as(u64, n.cfg.status_every_s) * std.time.ns_per_s) {
                last_print = now;
                n.printStatus(false);
            }
        }
    }

    var prev_cp: u64 = 0;
    var prev_tx: u64 = 0;
    var prev_ns: u64 = 0;

    fn printStatus(n: *Node, final: bool) void {
        const m = &n.follower.metrics;
        const cps = m.checkpoints.load(.monotonic);
        const txs = m.transactions.load(.monotonic);
        const now = source_mod.nowNs();
        const dt_ns = if (prev_ns == 0) now - n.started_ns else now - prev_ns;
        const dt: f64 = @as(f64, @floatFromInt(@max(dt_ns, 1))) / 1e9;
        const cp_rate = @as(f64, @floatFromInt(cps - prev_cp)) / dt;
        const tx_rate = @as(f64, @floatFromInt(txs - prev_tx)) / dt;
        prev_cp = cps;
        prev_tx = txs;
        prev_ns = now;
        var buf: [2560]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        const applied = n.follower.applied_next.load(.acquire);
        w.print("{s}applied {d} (epoch {d}) | {d} checkpoints {d} txs verified, 0 rejected | {d:.1} cp/s {d:.0} tx/s", .{
            if (final) "final: " else "", applied -| 1, m.epoch.load(.monotonic), cps, txs, cp_rate, tx_rate,
        }) catch {};
        if (n.fetcher) |f| {
            const hi = f.stats.highest.load(.monotonic);
            w.print(" | source tip {d} lag {d}", .{ hi, hi -| (applied -| 1) }) catch {};
            const p = n.latency();
            const a = ringPct(&n.arr_ring, &n.arr_n);
            w.print(" | tip latency p50 {d} ms p90 {d} ms (arrival p50 {d} ms)", .{ p[0], p[1], a[0] }) catch {};
            w.print(" | commit p50 <={d} ms p99 <={d} ms max {d} ms, {d} over 100 ms", .{ m.commitQuantileMs(0.5), m.commitQuantileMs(0.99), m.commit_max_ns.load(.monotonic) / std.time.ns_per_ms, m.commit_gt_100ms.load(.monotonic) }) catch {};
            w.print(" | fetch {d} ms decode {d} ms dup {d}", .{ f.stats.fetch_ns.load(.monotonic) / std.time.ns_per_ms, f.stats.decode_ns.load(.monotonic) / std.time.ns_per_ms, f.stats.dup_hits.load(.monotonic) }) catch {};
        }
        if (n.p2p) |pp| {
            const x = &pp.stats;
            w.print(" | p2p {d} peers {d} first {d} built {d} fallback {d} late", .{ x.peers_up.load(.monotonic), x.delivered.load(.monotonic), x.built.load(.monotonic), x.fallbacks.load(.monotonic), x.late.load(.monotonic) }) catch {};
        }
        for (n.streams.items) |st| {
            w.print(" | stream {d} first {d} dup {d} skipped {d} reconnects", .{ st.stats.delivered.load(.monotonic), st.stats.dups.load(.monotonic), st.stats.skipped.load(.monotonic), st.stats.connects.load(.monotonic) }) catch {};
        }
        if (n.follower.prefetcher) |pf| {
            const s = &pf.stats;
            w.print(" | read-ahead {d} cp {d}+{d} reads, chunks {d} cached {d} read ahead, {d} ms ({d} errors)", .{ m.prefetched.load(.monotonic), s.table_reads.load(.monotonic), s.record_reads.load(.monotonic), s.chunk_cached.load(.monotonic), s.chunk_reads.load(.monotonic), s.ns.load(.monotonic) / std.time.ns_per_ms, s.errors.load(.monotonic) }) catch {};
        }
        {
            const lat = n.st.commitLatency(n.gpa, 1024);
            w.print(" | apply {d} ms commit {d} ms stall {d} ms (commit p50 {d} us p99 {d} us)", .{ m.apply_ns.load(.monotonic) / std.time.ns_per_ms, m.commit_ns.load(.monotonic) / std.time.ns_per_ms, m.stall_ns.load(.monotonic) / std.time.ns_per_ms, lat.p50 / 1000, lat.p99 / 1000 }) catch {};
        }
        n.prof.take(&w);
        {
            const ph = n.clean_phase.load(.monotonic);
            if (ph != 0 or n.clean_steps.load(.monotonic) != 0) {
                const name = switch (ph) {
                    1 => "count",
                    2 => "sweep",
                    else => "idle",
                };
                const unit: []const u8 = if (ph == 1) "pages" else "MiB";
                const sh: u6 = if (ph == 1) 0 else 20;
                w.print(" | cleaner {s} {d}/{d} {s}, {d} steps {d} skipped {d} cut, {d} table pages read ahead", .{ name, n.clean_done.load(.monotonic) >> sh, n.clean_total.load(.monotonic) >> sh, unit, n.clean_steps.load(.monotonic), n.clean_skipped.load(.monotonic), n.clean_cut.load(.monotonic), n.clean_table_ahead.load(.monotonic) }) catch {};
            }
        }
        if (n.history) |h| {
            const s = &h.stats;
            w.print(" | read sets: {d} versions ({d} verified, {d} archive-only, {d} rejected), {d} loaded lists", .{ s.put.load(.monotonic), s.verified.load(.monotonic), s.unverified.load(.monotonic), s.rejected.load(.monotonic), s.loaded_lists.load(.monotonic) }) catch {};
        }
        if (n.executor) |x| {
            const s = &x.stats;
            w.print(" | exec: {d} run (move {d}, system {d}, coin {d}, prologue {d}), {d} match, {d} mismatch, {d} verify-only, {d} exec errors, done to {d}, {d} reruns ({d} matched)", .{ s.executed.load(.monotonic), s.ran_move.load(.monotonic), s.ran_system.load(.monotonic), s.ran_coin.load(.monotonic), s.ran_ccp.load(.monotonic), s.matched.load(.monotonic), s.mismatched.load(.monotonic), s.unsupported.load(.monotonic), s.errors.load(.monotonic), s.done_seq.load(.monotonic), s.reruns.load(.monotonic), s.rerun_matched.load(.monotonic) }) catch {};
            if (s.unsupported.load(.monotonic) > 0) {
                w.writeAll(" (verify-only: ") catch {};
                x.topWhys(&w, if (final) 8 else 3);
                w.writeAll(")") catch {};
            }
        }
        if (n.edge_fb) |fb| {
            const st = &fb.sw.stats;
            w.print(" | edge source {s} ({d} falls, {d} back, {d} from fallback)", .{ if (fb.sw.mode() == .core) "zui1" else "FALLBACK", st.to_fallback.load(.monotonic), st.to_core.load(.monotonic), st.from_fallback.load(.monotonic) }) catch {};
        }
        if (n.public) |h| {
            w.print(" | public {d} gets {d} hits", .{ h.stats.gets.load(.monotonic), h.stats.hits.load(.monotonic) }) catch {};
        }
        if (n.bucket) |b| {
            w.print(" | s3 {d} gets {d} MiB ${d:.4}", .{ b.stats.gets.load(.monotonic), b.stats.bytes.load(.monotonic) >> 20, b.stats.usd() }) catch {};
        }
        {
            const r = memstat.rss();
            const im = n.st.indexMemory();
            w.print(" | mem anon {d} MiB file {d} MiB node gpa {d} MiB | store memtables {d} MiB live dirty {d} MiB", .{ r.anon >> 20, r.file >> 20, memstat.node_gpa.bytes() >> 20, im.memtables >> 20, im.live_dirty >> 20 }) catch {};
            w.print(" | kept exec jobs {d} MiB threads {d} MiB fetch {d} MiB", .{ memstat.keptBytes(.exec_jobs) >> 20, memstat.keptBytes(.exec_threads) >> 20, memstat.keptBytes(.fetch_scratch) >> 20 }) catch {};
            if (n.executor) |x| x.memLine(&w);
        }
        if (move_vm_aot.enabled()) {
            const st = &move_vm_aot.stats;
            w.print(" | vm-aot modules {d} matched {d} digest-miss, functions {d} attached {d} not-hot", .{ st.modules_matched.load(.monotonic), st.modules_digest_miss.load(.monotonic), st.functions_attached.load(.monotonic), st.functions_not_hot.load(.monotonic) }) catch {};
        }
        if (final) {
            const h = &n.follower.commit_hist;
            w.print(" | commit path p50 {d} us p99 {d} us", .{ h.quantile(0.5) / std.time.ns_per_us, h.quantile(0.99) / std.time.ns_per_us }) catch {};
        }
        std.log.info("{s}", .{w.buffered()});
        if (n.fetcher != null) n.printSources();
    }

    /// The race report: when each source first had `seq`, relative to its timestamp.
    /// Records the sightings of `seq` per source; returns the source its full data came from first.
    fn noteSources(n: *Node, f: *source_mod.Fetcher, seq: u64, ts_ms: u64) ?source_mod.SeenSrc {
        var best_any: ?usize = null;
        var best_data: ?usize = null;
        var ms_any: u64 = std.math.maxInt(u64);
        var ms_data: u64 = std.math.maxInt(u64);
        inline for (0..source_mod.n_seen_src) |k| {
            const src: source_mod.SeenSrc = @enumFromInt(k);
            if (f.seenMs(seq, src)) |ms| {
                const j = n.src_n[k].load(.monotonic);
                n.src_ring[k][j % 4096].store(@intCast(@min(ms -| ts_ms, std.math.maxInt(u32))), .monotonic);
                n.src_n[k].store(j + 1, .release);
                if (ms < ms_any) {
                    ms_any = ms;
                    best_any = k;
                }
                const data = src == .p2p_built or src == .stream or src == .bucket;
                if (data and ms < ms_data) {
                    ms_data = ms;
                    best_data = k;
                }
            }
        }
        if (best_any) |k| _ = n.first_any[k].fetchAdd(1, .monotonic);
        if (best_data) |k| _ = n.first_data[k].fetchAdd(1, .monotonic);
        return if (best_data) |k| @enumFromInt(k) else null;
    }

    /// One line: per source p50/p90 of first sighting after the checkpoint timestamp, sightings,
    /// and wins (first of all sources; first with the full checkpoint).
    fn printSources(n: *Node) void {
        var buf: [1024]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        w.writeAll("sources (first sighting after checkpoint timestamp, last 1024):") catch {};
        inline for (0..source_mod.n_seen_src) |k| {
            const total = n.src_n[k].load(.acquire);
            if (total > 0) {
                const q = ringPct(&n.src_ring[k], &n.src_n[k]);
                w.print(" | {s} p50 {d} ms p90 {d} ms seen {d} first {d} first-data {d}", .{ @tagName(@as(source_mod.SeenSrc, @enumFromInt(k))), q[0], q[1], total, n.first_any[k].load(.monotonic), n.first_data[k].load(.monotonic) }) catch {};
            }
        }
        std.log.info("{s}", .{w.buffered()});
    }

    /// Catch-up or tip (fast_start.behind), told to the store's deferred ager when it changes.
    fn noteLag(n: *Node, lag_ms: u64) void {
        const was = n.behind.load(.monotonic);
        const now_behind = fast_start.behind(was, lag_ms);
        if (now_behind == was and n.behind_set) return;
        n.behind_set = true;
        n.behind.store(now_behind, .monotonic);
        n.st.ageBehind(now_behind);
    }

    /// The ager's mode, or null when age-out is off (`--age-out`, the profile, ZUI_AGE_OUT).
    fn ageOutMode(n: *const Node) ?store.Store.AgeMode {
        const env = if (std.c.getenv("ZUI_AGE_OUT")) |v| std.mem.span(v) else null;
        return switch (AgeOut.withEnv(n.cfg.age_out, env)) {
            .off => null,
            .on => .on,
            .deferred => .deferred,
        };
    }

    /// p50 and p90 of the last (up to) 1,024 tip latencies.
    fn latency(n: *Node) [2]u32 {
        return ringPct(&n.lat_ring, &n.lat_n);
    }

    fn ringPct(ring: *const [4096]Atomic(u32), count: *const Atomic(u64)) [2]u32 {
        const total = count.load(.acquire);
        const k: usize = @intCast(@min(total, 1024));
        if (k == 0) return .{ 0, 0 };
        var v: [1024]u32 = undefined;
        for (0..k) |j| v[j] = ring[(total - 1 - j) % ring.len].load(.monotonic);
        std.sort.pdq(u32, v[0..k], {}, std.sort.asc(u32));
        return .{ v[k / 2], v[(k * 9) / 10] };
    }

    // ---------------------------------------------------------------- serve and metrics

    /// `addr.listen`, or the socket a predecessor handed over under `name` (handoff.zig).
    fn listenOrInherit(n: *Node, name: []const u8, text: []const u8, addr: Io.net.IpAddress, opts: Io.net.IpAddress.ListenOptions) !Io.net.Server {
        if (handoff.inherited(name)) |h| {
            if (std.mem.eql(u8, h.addr, text)) {
                std.log.info("handoff: serving {s} on the inherited socket ({s})", .{ name, h.addr });
                return .{ .socket = .{ .handle = h.fd, .address = addr }, .options = {} };
            }
            // the successor is configured for another address: the old socket serves the old one
            std.log.warn("handoff: {s} is configured on {s} but the inherited socket is {s}; closing it and listening on {s}", .{ name, text, h.addr, text });
            handoff.closeFd(h.fd);
        }
        return addr.listen(n.io, opts);
    }

    fn handoffOffers(ctx: *anyopaque, out: *[handoff.max_fds]handoff.Entry) usize {
        const n: *Node = @ptrCast(@alignCast(ctx));
        var k: usize = 0;
        if (n.serve_server) |*s| if (n.cfg.serve_addr) |a| {
            out[k] = .{ .name = "serve", .addr = a, .fd = s.socket.handle };
            k += 1;
        };
        if (n.serve_tls_server) |*s| if (n.cfg.serve_tls_addr) |a| {
            out[k] = .{ .name = "serve_tls", .addr = a, .fd = s.socket.handle };
            k += 1;
        };
        if (n.metrics_server) |*s| if (n.cfg.metrics_addr) |a| {
            out[k] = .{ .name = "metrics", .addr = a, .fd = s.socket.handle };
            k += 1;
        };
        return k;
    }

    /// A successor asked for the store: the SIGTERM path (drain, finish the checkpoint in hand, flush).
    fn handoffRelease(ctx: *anyopaque) void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        // Clients that connect while the store closes and the successor opens it wait in the
        // listen queue: make it long (the kernel caps it at net.core.somaxconn).
        if (n.serve_server) |*s| handoff.raiseBacklog(s.socket.handle);
        if (n.serve_tls_server) |*s| handoff.raiseBacklog(s.socket.handle);
        std.log.info("handoff: a successor took the listening sockets; stopping to release the store", .{});
        requestStop();
    }

    /// Starts the handoff server (this process can be taken over from) and, when this start was
    /// itself a takeover, tells systemd and the old process that it is serving.
    fn startHandoff(n: *Node, path: []const u8) void {
        handoff.active = handoff.Server.start(n.gpa, path, .{ .ctx = n, .offers = handoffOffers, .release = handoffRelease, .stopping = &stop_signal }) catch |e| blk: {
            std.log.err("handoff: cannot listen on {s}: {s} (this process cannot be upgraded without downtime)", .{ path, @errorName(e) });
            break :blk null;
        };
        handoff.ready("following");
    }

    fn parseAddr(text: []const u8) !Io.net.IpAddress {
        const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.BadAddress;
        const port = try std.fmt.parseInt(u16, text[colon + 1 ..], 10);
        return Io.net.IpAddress.parse(text[0..colon], port);
    }

    /// The 32-byte seed in `path`, or a fresh one written there (0600, exclusive create) when the
    /// file does not exist. Returns whether it was created. A file of another size is an error,
    /// never silently replaced: every edge and client pinned the key it derives.
    fn loadOrCreateSeed(io: Io, path: []const u8, seed: *[32]u8) !bool {
        var zb: [std.fs.max_path_bytes]u8 = undefined;
        const z = try std.fmt.bufPrintSentinel(&zb, "{s}", .{path}, 0);
        const fd = std.c.open(z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
        if (fd >= 0) {
            defer _ = std.c.close(fd);
            var buf: [33]u8 = undefined;
            const got = std.c.read(fd, &buf, buf.len);
            if (got != 32) {
                std.log.err("zui/1 identity {s}: {d} bytes, want 32 (not replaced)", .{ path, got });
                return error.BadIdentityFile;
            }
            @memcpy(seed, buf[0..32]);
            return false;
        }
        io.random(seed);
        const w = std.c.open(z, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true }, @as(std.c.mode_t, 0o600));
        if (w < 0) return error.IdentityFileCreate;
        defer _ = std.c.close(w);
        if (std.c.write(w, seed, 32) != 32) return error.IdentityFileWrite;
        if (std.c.fsync(w) != 0) return error.IdentityFileWrite;
        return true;
    }

    /// zui/1 on `text` (UDP): raw QUIC ALPN zui/1 with the Ed25519 identity below, WebTransport
    /// (h3) with a self-signed P-256 certificate that rotates every 7 days (native/certs.zig:
    /// derived from the identity seed, so a restart keeps it); its hash and the next one go to
    /// `native_cert_hash_file` and `GET /native/cert-hash`.
    fn startNative(n: *Node, text: []const u8) !void {
        const addr = try parseAddr(text);
        n.native_hooks = .{ .io = n.io, .st = n.st, .rpc = &n.exec_rpc, .epochs_dir = n.epochs_dir };
        const ds = try n.gpa.create(native.dicts.Dicts);
        ds.* = native.dicts.Dicts.init(n.gpa);
        n.native_dicts = ds;
        if (n.cfg.edge_feed) {
            const fd = try n.gpa.create(native.edgefeed.Feeder);
            fd.* = native.edgefeed.Feeder.init(ds);
            // Read sets go out with the feed only from a node that marks them (its hello then
            // has feature bit 33).
            if (n.service.read_sets != null) fd.read_sets = &n.service;
            n.edge_feeder = fd;
        }
        n.edge_warm = std.Thread.spawn(.{}, edgeWarm, .{n}) catch null;
        if (n.cfg.native_keys) |keys_path| {
            var lb: [std.fs.max_path_bytes]u8 = undefined;
            const ld = n.cfg.native_pass_dir orelse try std.fmt.bufPrint(&lb, "{s}/node/agent-pass", .{n.cfg.dir});
            n.native_policy = try native_pass.load(n.gpa, n.io, keys_path, ld, &n.native_hooks);
        }
        n.native_disp = .{ .svc = &n.service, .ix = n.ix, .edge = n.edge_feeder, .dicts = ds, .software = n.cfg.version_label, .hooks = .{
            .epoch_fallback = n.native_hooks.epochFallback(),
            .simulator = n.native_hooks.simulator(),
            .submitter = n.native_hooks.submitter(),
            .auth = if (n.native_policy) |p| p.auth() else null,
            .agent_pass = if (n.native_policy) |p| p.agentPass() else null,
        } };
        // An edge never hands a certificate on that is not its core's (dispatch.zig `Foreign`).
        if (n.edge_certs) |cv| n.native_disp.foreign = cv.nativeHook();
        var id_seed: [32]u8 = undefined;
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        const id_path = n.cfg.native_identity_file orelse try std.fmt.bufPrint(&pb, "{s}/node/native-identity.seed", .{n.cfg.dir});
        const created = try loadOrCreateSeed(n.io, id_path, &id_seed);
        const ed = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(id_seed);
        // `--native-cert` and `--native-key` come together: a real certificate replaces the
        // self-signed one, and a file that does not pass the checks stops the start
        const files: ?native.certs.Files = if (n.cfg.native_cert != null or n.cfg.native_key != null) .{
            .cert = n.cfg.native_cert orelse {
                std.log.err("zui/1: --native-key without --native-cert", .{});
                return error.BadTlsConfig;
            },
            .key = n.cfg.native_key orelse {
                std.log.err("zui/1: --native-cert without --native-key", .{});
                return error.BadTlsConfig;
            },
        } else null;
        const certs = native.certs.Certs.init(n.gpa, n.io, .{ .seed = id_seed, .hash_file = n.cfg.native_cert_hash_file, .identity_key = ed.public_key.toBytes(), .files = files, .reload = &native_reload }) catch |e| {
            if (files) |f| {
                std.log.err("zui/1: --native-cert {s} with --native-key {s} refused: {s}", .{ f.cert, f.key, native.certs.describe(e) });
                return error.BadTlsConfig;
            }
            std.log.err("zui/1: certificate setup failed ({s}); --native-cert-hash-file {s}", .{ @errorName(e), n.cfg.native_cert_hash_file orelse "(none)" });
            return e;
        };
        n.native_certs = certs;
        if (files != null) installReloadSignal();
        n.native_listener = try native.listener.Listener.start(n.gpa, n.io, .{ .listen = addr, .identity_seed = id_seed, .certs = certs, .slow_worker_exit = simulate.api.releaseThreadCaches, .feed_workers = n.cfg.native_feed_workers, .feed_queue = n.cfg.native_feed_queue, .gate = if (n.gate) |ng| ng.nativeHook() else null }, &n.native_disp);
        // The HTTP form of zui/1 has no gate in front of it yet: with `--gate` it stays off,
        // so nothing a gated node serves goes around the gate.
        if (n.gate != null and n.cfg.native_http_rpc) std.log.warn("gate: --native-http-rpc is off while --gate is on (POST /zui1/rpc is not behind the gate)", .{});
        const hash = certs.cur.sha256;
        // GET http://ADDR/native/cert-hash on TCP at the same address (CORS, for dapps in dev)
        switch (addr) {
            .ip4 => |a4| n.native_certhttp = native.certhttp.Server.startCerts(n.gpa, a4.bytes, a4.port, certs, if (n.cfg.native_http_rpc and n.gate == null) &n.native_disp else null) catch |e| blk: {
                std.log.warn("zui/1: /native/cert-hash not served on tcp {s}: {s}", .{ text, @errorName(e) });
                break :blk null;
            },
            .ip6 => {},
        }
        if (files) |f| {
            std.log.info("serving zui/1 (QUIC zui/1 + WebTransport h3) on {s}; certificate chain from {s} ({d} certificate(s), {s} key, leaf sha256 {x}, not after unix {d}; SIGHUP or a file change loads it again); zui/1 key {x} ({s} {s})", .{ text, f.cert, certs.cur.chain.?.certs.len, @tagName(certs.cur.chain.?.key), &certs.cur.sha256, certs.cur.notAfter(), &ed.public_key.toBytes(), if (created) "new identity in" else "identity from", id_path });
        } else {
            std.log.info("serving zui/1 (QUIC zui/1 + WebTransport h3) on {s}; cert sha256 {x} (rotates at unix {d}); zui/1 key {x} ({s} {s})", .{ text, &hash, certs.view().until[0], &ed.public_key.toBytes(), if (created) "new identity in" else "identity from", id_path });
        }
        // from here the certificate rotates (or is loaded again) in the background
        try certs.start();
    }

    /// Builds the zui/1 response dictionaries (object, checkpoint and edge feed, effects) once the
    /// store holds enough checkpoints, then returns. The only place that builds them (requests
    /// never do); waits in short slices so stop() is quick.
    fn edgeWarm(n: *Node) void {
        const ds = n.native_dicts orelse return;
        while (!n.edge_stop.load(.acquire)) {
            var snap = n.st.snapshot();
            // with the stop flag: a stop does not wait for a build in progress (the join in
            // shutdownThreads used to, for as long as the samples took to read from the store)
            const res = ds.warmCancel(&snap, &n.edge_stop);
            snap.release();
            if (n.edge_stop.load(.acquire)) return;
            if (res) |_| {
                for ([_]native.dicts.Kind{ .object, .checkpoint, .effects }) |k| if (ds.get(k)) |d|
                    std.log.info("zui/1: {s} dictionary {x} ({d} bytes) ready", .{ @tagName(k), d.id, d.content.len });
                return;
            } else |_| {}
            // not enough checkpoints yet (a fresh store): try again in a while
            var waited: u32 = 0;
            while (waited < 30_000 and !n.edge_stop.load(.acquire)) : (waited += 250) {
                n.io.sleep(.fromMilliseconds(250), .awake) catch return;
            }
        }
    }

    fn startServe(n: *Node, text: []const u8) !void {
        const addr = try parseAddr(text);
        n.serve_server = try n.listenOrInherit("serve", text, addr, .{ .reuse_address = true, .kernel_backlog = listen_backlog });
        @atomicStore(c_uint, &stop_drain_s, @intCast(n.cfg.drain_ms / 1000 + 2), .release);
        n.rpc_metrics = rpcmetrics.RpcMetrics.init(n.gpa);
        n.rpc_metrics.install();
        n.rpc_metrics_on = true;
        // The hub lives until exit (detached connection threads may still hold it, see `stop`),
        // so it comes from the page allocator: from `gpa` it was an `ERROR leaked` line at every
        // shutdown, the line protocol-watch's restart alert quotes.
        const h = try std.heap.page_allocator.create(serve.subscribe.Hub);
        h.* = serve.subscribe.Hub.init(n.gpa, n.io, &n.service);
        if (n.cfg.sub_max_subscribers) |m| h.max_subscribers = m;
        if (n.cfg.sub_watermark_interval) |w| h.watermark_interval = w;
        n.hub = h;
        n.service.hub = h;
        try h.start();
        if (n.edge_fwd) |f| try f.start();
        try n.threads.append(n.gpa, try std.Thread.spawn(.{}, serveMain, .{n}));
        std.log.info("serving sui.rpc.v2 (h2c) on {s}", .{text});
    }

    /// The serve port's handler over TLS 1.3 on `text` (same service, same options). With
    /// `serve_tls_cert` and `serve_tls_key` (sui-node `rpc.tls`) it presents that chain and key,
    /// and a file that does not load stops the start, as sui-node's `https_rustls_config` does.
    /// After the start the files are loaded again on SIGHUP or when they change on disk
    /// (native/certs.zig): new connections get the new chain, open ones go on, and files that do
    /// not pass the checks (a damaged chain, a key that is not the leaf's) leave the old one.
    fn startServeTls(n: *Node, text: []const u8) !void {
        const addr = try parseAddr(text);
        if (n.cfg.serve_tls_cert != null or n.cfg.serve_tls_key != null) {
            const cert_path = n.cfg.serve_tls_cert orelse {
                std.log.err("rpc tls: a key without a certificate chain (--serve-tls-cert)", .{});
                return error.BadTlsConfig;
            };
            const key_path = n.cfg.serve_tls_key orelse {
                std.log.err("rpc tls: a certificate chain without a key (--serve-tls-key)", .{});
                return error.BadTlsConfig;
            };
            const files: native.certs.Files = .{ .cert = cert_path, .key = key_path };
            // (before the files are read: a change from here on is a reload)
            const stamp = native.certs.Stamp.of(n.io, files);
            const cert_pem = Io.Dir.cwd().readFileAlloc(n.io, cert_path, n.gpa, .limited(4 << 20)) catch |e| {
                std.log.err("failed to read TLS certificate chain from {s}: {s}", .{ cert_path, @errorName(e) });
                return error.BadTlsConfig;
            };
            defer n.gpa.free(cert_pem);
            const key_pem = Io.Dir.cwd().readFileAlloc(n.io, key_path, n.gpa, .limited(1 << 20)) catch |e| {
                std.log.err("failed to read TLS private key from {s}: {s}", .{ key_path, @errorName(e) });
                return error.BadTlsConfig;
            };
            defer {
                std.crypto.secureZero(u8, key_pem);
                n.gpa.free(key_pem);
            }
            const id = @import("net").tls_identity.load(n.gpa, cert_pem, key_pem) catch |e| {
                std.log.err("failed to load TLS certificate chain {s} and key {s}: {s}", .{ cert_path, key_path, @errorName(e) });
                return error.BadTlsConfig;
            };
            const n_certs = id.certs.len;
            const key_kind = @tagName(id.key);
            var seed: [32]u8 = undefined;
            n.io.random(&seed);
            const cs = try native.certs.Certs.initLoaded(n.gpa, n.io, .{ .seed = seed, .files = files, .reload = &serve_tls_reload, .label = "rpc tls" }, id, stamp);
            n.serve_tls_certs = cs;
            n.serve_tls = native.tcptls.Server.initCerts(n.gpa, n.io, cs);
            n.serve_tls_server = try addr.listen(n.io, .{ .reuse_address = true, .kernel_backlog = listen_backlog });
            try n.threads.append(n.gpa, try std.Thread.spawn(.{}, serveTlsMain, .{n}));
            std.log.info("HTTPS rpc server listening on {s} (TLS 1.3, {d} certificate(s) from {s}, {s} key)", .{ text, n_certs, cert_path, key_kind });
            // The start takes what loads, as before; say so when a reload would refuse it.
            if (cs.start_refusal) |why| std.log.warn("rpc tls: {s} and {s} would be refused on a reload: {s}", .{ cert_path, key_path, native.certs.describe(why) });
            std.log.info("rpc tls: leaf sha256 {x}, not after unix {d}; SIGHUP or a file change loads the certificate again", .{ &cs.cur.sha256, cs.cur.notAfter() });
            installReloadSignal();
            // from here the files are loaded again in the background
            try cs.start();
            return;
        }
        const kp = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generate(n.io);
        var serial: [16]u8 = undefined;
        n.io.random(&serial);
        const now_unix: i64 = @intCast(@divTrunc(Io.Clock.real.now(n.io).toNanoseconds(), std.time.ns_per_s));
        n.serve_tls = native.tcptls.Server.init(n.gpa, n.io, native.cert.generate(kp, serial, now_unix, 13, "localhost"));
        n.serve_tls_server = try n.listenOrInherit("serve_tls", text, addr, .{ .reuse_address = true, .kernel_backlog = listen_backlog });
        try n.threads.append(n.gpa, try std.Thread.spawn(.{}, serveTlsMain, .{n}));
        std.log.info("serving sui.rpc.v2 (h2 over TLS 1.3) on {s}; cert sha256 {x}", .{ text, &n.serve_tls.cert.sha256() });
    }

    /// `--gate`: reads the credential, opens the gate directory and starts the gate's threads.
    /// A node asked to run behind a gate does not start without one.
    fn startGate(n: *Node, gs: gate_mod.Settings) !void {
        // from the general-purpose allocator: it lives until exit (see the field)
        const ng = gate_mod.NodeGate.start(std.heap.smp_allocator, n.io, gs, null) catch |e| {
            std.log.err("gate: cannot start ({s}): --gate-token-file must hold this node's credential (at least 24 characters, one line), --gate-dir must be writable, --gate-ca-file (when given) must be a readable PEM file with a certificate", .{@errorName(e)});
            return e;
        };
        if (gate_mod.loopbackHttp(gs.url)) std.log.warn("gate: the gate URL is plain http on this machine: the credential and the keys travel unencrypted over loopback (meant for a local test gate)", .{});
        n.gate = ng;
        n.gate_handler = ng.handler(n.service.handler());
        // An edge that forwards: denied before routing, and counted local or forwarded at the
        // forwarder's meter (set before any serve thread starts).
        if (n.edge_fwd) |f| {
            f.gate_hook = ng.forwardHook();
            f.meter_hook = ng.meterHook();
        }
        std.log.info("gate: on, edge id {s}, state in {s}, {d} trusted prox{s}; keyless callers get the free tier", .{ gs.edge_id, gs.dir, gs.proxies.len, if (gs.proxies.len == 1) "y" else "ies" });
    }

    fn serveTlsMain(n: *Node) void {
        var sopts = n.cfg.serve_opts;
        sopts.poll_accept = n.cfg.handoff_sock != null;
        sopts.stop_grace_ns = @as(u64, n.cfg.drain_ms) * std.time.ns_per_ms;
        sopts.tls = n.serve_tls.acceptor();
        serve.stream_conn.serveBlocking(n.gpa, n.io, &n.serve_tls_server.?, sopts, n.serveHandler(), &n.serve_stop) catch |e| {
            if (!n.stopping.load(.acquire)) std.log.err("serve-tls: {s}", .{@errorName(e)});
        };
    }

    fn serveMain(n: *Node) void {
        var sopts = n.cfg.serve_opts;
        sopts.poll_accept = n.cfg.handoff_sock != null;
        sopts.stop_grace_ns = @as(u64, n.cfg.drain_ms) * std.time.ns_per_ms;
        serve.stream_conn.serveBlocking(n.gpa, n.io, &n.serve_server.?, sopts, n.serveHandler(), &n.serve_stop) catch |e| {
            if (!n.stopping.load(.acquire)) std.log.err("serve: {s}", .{@errorName(e)});
        };
    }

    /// The admin port (admin.zig). A port already taken (sui-node beside deepwave on the same box)
    /// is a warning, not a failed start.
    fn startAdmin(n: *Node, port: u16) void {
        n.admin_db = .{ .st = n.st, .io = n.io, .epochs_dir = n.epochs_dir, .rpc = &n.rpc };
        n.admin_server = admin.Server.start(n.gpa, n.io, port, .{ .ctx = n, .config = adminConfig, .version = adminVersion, .db = n.admin_db.source() }) catch |e| {
            std.log.warn("admin port 127.0.0.1:{d} not started: {s}", .{ port, @errorName(e) });
            return;
        };
        std.log.info("admin interface on http://127.0.0.1:{d} (/logging, /enable-tracing, /update-endpoint, /db-shell/ls, /node-config, ...)", .{port});
    }

    fn adminVersion(ctx: *anyopaque, w: *std.Io.Writer) anyerror!void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        try w.print("deepwave {s}\n", .{n.cfg.version_label});
        try ops.printProtocolRange(w);
    }

    fn adminConfig(ctx: *anyopaque, w: *std.Io.Writer) anyerror!void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        const c = &n.cfg;
        try w.print("dir = {s}\nmode = {s}\nsource = {s}\n", .{ c.dir, @tagName(c.mode), @tagName(c.source) });
        if (c.serve_addr) |a| try w.print("serve = {s}\n", .{a});
        if (c.metrics_addr) |a| try w.print("metrics = {s}\n", .{a});
        if (c.metrics_push_url) |u| try w.print("metrics push = {s} every {d}s\n", .{ u, c.metrics_push_interval_s });
        if (c.admin_port) |p| try w.print("admin-port = {d}\n", .{p});
        if (c.stream) |u| try w.print("stream = {s}\n", .{u});
        if (n.sig_order) |o| try w.print("sig-order-from = {s}\nsig-order-rps = {d}\n", .{ o.base, o.rps });
        if (c.source == .zui1) switch (c.source.zui1.fallback) {
            .off => try w.print("edge-fallback = off\n", .{}),
            .http => try w.print("edge-fallback = http{s}{s}\n", .{ if (n.public != null) ":" else " (off: no bucket for this network)", if (n.public) |h| h.base else "" }),
            .dir => |path| try w.print("edge-fallback = dir:{s}\n", .{path}),
        };
        try w.print("indexes = {}\nread-sets = {}\nfetchers = {d}\nwindow = {d}\nlookahead = {d}\nsync = {s}\nretention-epochs = {d}\nstate-hash = {s}\nhalt-on-mismatch = {}\n", .{ c.indexes, c.read_sets, c.fetchers, c.window, c.lookahead, @tagName(c.sync_mode), n.st.cfg.retention_epochs, @tagName(c.state_hash), c.halt_on_mismatch });
        const o = &c.serve_opts;
        try w.print("rpc.max-concurrent-streams = {d}\nrpc.max-request-bytes = {d}\nrpc.grpc-timeout-ms = {?d}\nrpc.http1-header-read-timeout-ms = {d}\nrpc.max-connection-age-secs = {?d}\nrpc.max-connection-age-grace-secs = {d}\nrpc.listen-backlog = {d}\n", .{ o.h2.max_streams, o.h2.max_request_bytes, if (o.h2.default_timeout_ns) |t| t / std.time.ns_per_ms else null, o.web.idle_ns / std.time.ns_per_ms, if (o.max_age_ns) |a| a / std.time.ns_per_s else null, o.age_grace_ns / std.time.ns_per_s, listen_backlog });
    }

    /// The `zui_edge_fallback_*` and `zui_edge_source_*` lines of a switch.
    pub fn renderEdgeFallback(w: *std.Io.Writer, sw: *edge.fallback.Switch) !void {
        const on_fb = sw.mode() == .fallback;
        try w.print("# TYPE zui_edge_source_fallback gauge\nzui_edge_source_fallback {d}\n", .{@intFromBool(on_fb)});
        try w.print("# TYPE zui_edge_source gauge\nzui_edge_source{{source=\"zui1\"}} {d}\nzui_edge_source{{source=\"fallback\"}} {d}\n", .{ @intFromBool(!on_fb), @intFromBool(on_fb) });
        try w.print("# TYPE zui_edge_fallback_switches counter\nzui_edge_fallback_switches{{to=\"fallback\"}} {d}\nzui_edge_fallback_switches{{to=\"zui1\"}} {d}\n", .{ sw.stats.to_fallback.load(.monotonic), sw.stats.to_core.load(.monotonic) });
        try w.print("# TYPE zui_edge_fallback_checkpoints counter\nzui_edge_fallback_checkpoints{{from=\"zui1\"}} {d}\nzui_edge_fallback_checkpoints{{from=\"fallback\"}} {d}\n", .{ sw.stats.from_core.load(.monotonic), sw.stats.from_fallback.load(.monotonic) });
        try w.print("# TYPE zui_edge_fallback_probes counter\nzui_edge_fallback_probes {d}\n# TYPE zui_edge_fallback_probes_ok counter\nzui_edge_fallback_probes_ok {d}\n# TYPE zui_edge_fallback_behind_checks counter\nzui_edge_fallback_behind_checks {d}\n", .{ sw.stats.probes.load(.monotonic), sw.stats.probes_ok.load(.monotonic), sw.stats.behind_checks.load(.monotonic) });
        // the reason of the last fall (edge/fallback.zig `Reason`: 0 silent, 1 no feed, 2 wrong chain, 3 shutdown, 4 pruned, 5 behind) and the wait the next return needs
        try w.print("# TYPE zui_edge_fallback_last_reason gauge\nzui_edge_fallback_last_reason {d}\n# TYPE zui_edge_fallback_back_after_ms gauge\nzui_edge_fallback_back_after_ms {d}\n", .{ @intFromEnum(sw.lastReason()), sw.backAfterMs() });
    }

    fn startMetrics(n: *Node, text: []const u8) !void {
        const addr = try parseAddr(text);
        n.metrics_server = try n.listenOrInherit("metrics", text, addr, .{ .reuse_address = true });
        try n.threads.append(n.gpa, try std.Thread.spawn(.{}, metricsMain, .{n}));
        std.log.info("metrics on http://{s}/metrics", .{text});
    }

    fn metricsMain(n: *Node) void {
        while (!n.stopping.load(.acquire)) {
            const srv = &(n.metrics_server orelse return);
            if (n.cfg.handoff_sock != null) {
                // handed-over listener: never block in accept, so the stop needs no wake connection
                const ready = serve.h2.sock.waitReadableRaw(srv.socket.handle, 100) catch return;
                if (!ready) continue;
                if (n.stopping.load(.acquire)) return;
            }
            const stream = srv.accept(n.io) catch return;
            n.answerMetrics(stream);
        }
    }

    fn answerMetrics(n: *Node, stream: Io.net.Stream) void {
        defer stream.close(n.io);
        var rbuf: [4096]u8 = undefined;
        var iov = [_][]u8{&rbuf};
        _ = stream.read(n.io, &iov) catch return;
        var body: std.Io.Writer.Allocating = .init(n.gpa);
        defer body.deinit();
        n.renderMetrics(&body.writer) catch return;
        var wbuf: [4096]u8 = undefined;
        var sw = stream.writer(n.io, &wbuf);
        sw.interface.print("HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n", .{body.writer.end}) catch return;
        sw.interface.writeAll(body.writer.buffered()) catch return;
        sw.interface.flush() catch {};
    }

    /// sui-node's other operator families (ops.zig `NodeMetrics`).
    fn nodeMetrics(n: *Node, cm: ops.Compat) ops.NodeMetrics {
        const last = cm.executed orelse 0;
        const cp_floor = n.st.cp_floor.load(.monotonic);
        const d = n.epoch_duration_ms.load(.monotonic);
        return .{
            .chain_short = ops.chainShort(n.cfg.chain_id orelse mainnet_chain_id),
            .version = n.cfg.version_label,
            .uptime_s = (source_mod.nowNs() - n.started_ns) / std.time.ns_per_s,
            .verified = last,
            .known = cm.synced,
            // sui-node's checkpoint pruner watermark: the checkpoint floor - 1 once retention has
            // moved it, else the restored checkpoint S (a snapshot restore sets the watermarks to
            // S), else 0 (a store followed from the tip has pruned nothing).
            .last_pruned = if (cp_floor > 0) cp_floor - 1 else n.store_pruned.load(.acquire),
            .protocol_version = cm.protocol_version,
            .max_protocol_version = protocol.max_protocol_version,
            .transactions = n.follower.metrics.transactions.load(.monotonic),
            .epoch_duration_ms = d,
        };
    }

    /// sui-node's metric values (ops.zig) from the store and the fetcher.
    pub fn compat(n: *Node) ops.Compat {
        const last = n.st.committed();
        var ts: u64 = 0;
        if (last) |l| {
            if (n.compat_seq.load(.acquire) == l) {
                ts = n.compat_ts.load(.monotonic);
            } else blk: {
                var snap = n.st.snapshot();
                defer snap.release();
                const rec = (snap.checkpointChecked(l) catch break :blk) orelse break :blk;
                const cert = trust.splitCert(rec.summary_cert) catch break :blk;
                const sum = checkpoint.Summary.parse(cert.summary) catch break :blk;
                ts = sum.timestamp_ms;
                n.compat_ts.store(ts, .monotonic);
                n.compat_seq.store(l, .release);
            }
        }
        const synced = if (n.fetcher) |f| f.stats.highest.load(.monotonic) else last orelse 0;
        return .{
            .executed = last,
            .executed_ts_ms = ts,
            .synced = synced,
            .epoch = n.follower.metrics.epoch.load(.monotonic),
            .protocol_version = @atomicLoad(u64, &n.cur_pv, .monotonic),
        };
    }

    /// p2p-state families sui-node registers that core.p2p_metrics (the anemo/quinn hooks) does
    /// not hold: discovery's external-address peer count.
    fn renderSuiP2p(n: *Node, w: *std.Io.Writer) !void {
        if (n.p2p) |pp| {
            try w.print("# HELP num_peers_with_external_address Number of peers with an external address\n# TYPE num_peers_with_external_address gauge\nnum_peers_with_external_address {d}\n", .{pp.cands.count()});
        }
    }

    fn renderMetricsOpaque(ctx: *anyopaque, w: *std.Io.Writer) anyerror!void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        return n.renderMetrics(w);
    }

    pub fn renderMetrics(n: *Node, w: *std.Io.Writer) !void {
        while (!n.render_lock.tryLock()) std.Thread.yield() catch {};
        defer n.render_lock.unlock();
        const cm = n.compat();
        try ops.renderCompat(cm, w);
        const nm = n.nodeMetrics(cm);
        try ops.renderNode(nm, w);
        try n.cp_metrics.render(w, .{
            .objects = n.st.age_stats.objects_dropped.load(.monotonic),
            .tombstones = n.st.age_stats.tombstones_dropped.load(.monotonic) + n.clean_tombstones.load(.monotonic),
            .last_pruned_effects = nm.last_pruned,
            .object_epochs = n.st.cfg.object_retention_epochs,
            .checkpoint_epochs = n.st.cfg.retention_epochs,
            .peers_reported = if (n.p2p) |pp| pp.scores.stats.reported.load(.monotonic) else 0,
        });
        if (n.rpc_metrics_on) try n.rpc_metrics.render(w);
        // Submit path (tx_orchestrator_*, transaction_driver_*, validator_client_*) and p2p
        // (sui_{inbound,outbound}_*, sui_quinn_*): process-wide, as sui-node registers them.
        try @import("rpc_exec").live.submit_metrics.global.render(w);
        {
            var peers: u64 = 0;
            if (n.p2p) |pp| peers += pp.stats.peers_up.load(.monotonic);
            if (n.p2p_listener) |l| peers += l.stats.active.load(.monotonic);
            core.p2p_metrics.quinn.peers.store(@intCast(peers), .monotonic);
        }
        try core.p2p_metrics.render(w);
        // Store: sampled read latency per table and disk bytes per area (typed-store names).
        try store.readstats.render(w);
        n.disk_usage.maybeRefresh(n.gpa, n.io, n.cfg.dir);
        try n.disk_usage.render(w);
        try n.state_hash.render(w);
        // zui_protocol_* families only with --verify-fallback: default /metrics stays as main (train/12).
        if (n.cfg.verify_fallback) try n.guard.render(w);
        try n.cons_stats.render(w);
        try n.follower.metrics.render(w);
        if (n.gate) |ng| try ng.renderMetrics(w);
        try core.cpu.writeMetrics(w);
        try w.print("# TYPE zui_node_uptime_seconds gauge\nzui_node_uptime_seconds {d}\n", .{(source_mod.nowNs() - n.started_ns) / std.time.ns_per_s});
        try w.print("# TYPE zui_store_committed gauge\nzui_store_committed {d}\n", .{n.st.committed() orelse 0});
        // Retention (CONTRACTS 6.8): sui-node's `lowest_available_checkpoint` as GetServiceInfo
        // reports it (the higher of the two floors below, `served_lowest`) and the pruners' marks.
        try w.print("# TYPE zui_lowest_available_checkpoint gauge\nzui_lowest_available_checkpoint {d}\n", .{n.served_lowest.load(.monotonic)});
        try w.print("# TYPE zui_store_checkpoint_floor gauge\nzui_store_checkpoint_floor {d}\n", .{n.st.cp_floor.load(.monotonic)});
        try w.print("# TYPE zui_store_object_floor gauge\nzui_store_object_floor {d}\nzui_store_object_floor_epoch {d}\nzui_store_aged_floor_epoch {d}\n", .{ n.st.obj_floor.load(.monotonic), n.st.obj_floor_epoch.load(.monotonic), n.st.oldest_epoch.load(.monotonic) });
        const p = n.latency();
        try w.print("# TYPE zui_node_tip_latency_ms gauge\nzui_node_tip_latency_ms{{q=\"0.5\"}} {d}\nzui_node_tip_latency_ms{{q=\"0.9\"}} {d}\n", .{ p[0], p[1] });
        const a = ringPct(&n.arr_ring, &n.arr_n);
        try w.print("# TYPE zui_node_arrival_ms gauge\nzui_node_arrival_ms{{q=\"0.5\"}} {d}\nzui_node_arrival_ms{{q=\"0.9\"}} {d}\n", .{ a[0], a[1] });
        if (n.p2p) |pp| {
            inline for (comptime std.meta.fieldNames(p2p_mod.Stats)) |name| {
                try w.print("# TYPE zui_p2p_{s} counter\nzui_p2p_{s} {d}\n", .{ name, name, @field(pp.stats, name).load(.monotonic) });
            }
        }
        if (n.reconcile) |r| {
            inline for (comptime std.meta.fieldNames(reconcile_mod.Stats)) |name| {
                const kind = if (comptime std.mem.eql(u8, name, "pending")) "gauge" else "counter";
                try w.print("# TYPE zui_p2p_readset_{s} {s}\nzui_p2p_readset_{s} {d}\n", .{ name, kind, name, @field(r.stats, name).load(.monotonic) });
            }
        }
        if (n.p2p_server) |srv| try srv.render(w);
        if (n.p2p != null or n.p2p_server != null) try n.renderSuiP2p(w);
        if (n.native_listener) |nl| {
            inline for (comptime std.meta.fieldNames(native.listener.Stats)) |name| {
                try w.print("# TYPE zui_native_{s} counter\nzui_native_{s} {d}\n", .{ name, name, @field(nl.stats, name).load(.monotonic) });
            }
        }
        // zui/1 hellos by the client's protocol minor, and the ones refused (wrong chain, a minor
        // or a feature this node does not have).
        if (n.native_listener != null) {
            const hs = &n.native_disp.hello;
            try w.writeAll("# TYPE zui_native_hello counter\n");
            for (native.hello.minor_labels, 0..) |label, i| try w.print("zui_native_hello{{minor=\"{s}\"}} {d}\n", .{ label, hs.by_minor[i].load(.monotonic) });
            try w.writeAll("# TYPE zui_native_hello_refused counter\n");
            try w.print("zui_native_hello_refused{{reason=\"wrong_chain\"}} {d}\n", .{hs.wrong_chain.load(.monotonic)});
            try w.print("zui_native_hello_refused{{reason=\"minor_unsupported\"}} {d}\n", .{hs.minor_unsupported.load(.monotonic)});
            try w.print("zui_native_hello_refused{{reason=\"feature_missing\"}} {d}\n", .{hs.feature_missing.load(.monotonic)});
        }
        // The edge feed queue: what it holds now, and the feed requests refused, by reason (a
        // client over its share of a full queue; a full queue with nobody over a share).
        if (n.native_listener) |nl| try nl.feed_stats.render(w, "zui_native_feed");
        // The ledger-history index against the store's window: what List* can answer, and the
        // checkpoints the store serves that the index does not hold (0 on a healthy node).
        if (n.ledger_history) |h| if (n.st.committed()) |tip| {
            const gap = lhfill.gapOf(h, n.lowest.load(.acquire), tip);
            try w.print("# TYPE zui_history_indexed_lowest gauge\nzui_history_indexed_lowest {d}\n# TYPE zui_history_indexed_highest gauge\nzui_history_indexed_highest {d}\n", .{ h.indexedLo() orelse 0, h.indexedHi() orelse 0 });
            try w.print("# TYPE zui_history_unindexed_checkpoints gauge\nzui_history_unindexed_checkpoints {d}\n", .{if (n.lowest_known) gap.count() else 0});
            try w.print("# HELP zui_history_backfill_state 0 nothing to do, 1 building, 2 gave up, 3 switched off\n# TYPE zui_history_backfill_state gauge\nzui_history_backfill_state {d}\n", .{n.lh_state.load(.acquire)});
            if (n.lh_staging) |d| {
                const now = source_mod.nowNs();
                if (n.lh_staging_read_ns == 0 or now -| n.lh_staging_read_ns >= 30 * std.time.ns_per_s) {
                    n.lh_staging_read_ns = now;
                    n.lh_staging_bytes.store(lhfill.stagingUse(n.io, d).bytes, .monotonic);
                }
            }
            try w.print("# HELP zui_history_backfill_staging_bytes bytes on disk in the backfill's staging directory (0 when no build is under way)\n# TYPE zui_history_backfill_staging_bytes gauge\nzui_history_backfill_staging_bytes {d}\n", .{n.lh_staging_bytes.load(.monotonic)});
            try w.print("# HELP zui_history_backfill_bytes heap the backfill holds: loaded checkpoints not yet indexed and the open segment of the index it builds\n# TYPE zui_history_backfill_bytes gauge\nzui_history_backfill_bytes {d}\n# TYPE zui_history_backfill_paused gauge\nzui_history_backfill_paused {d}\n", .{ n.lh_mem.load(.monotonic), @intFromBool(n.lh_paused.load(.monotonic)) });
        };
        // The WebTransport certificate: when the one presented now expires, and rotations so far.
        if (n.native_certs) |cs| {
            try w.print("# TYPE zui_native_cert_not_after_seconds gauge\nzui_native_cert_not_after_seconds {d}\n", .{cs.stats.not_after.load(.acquire)});
            try w.print("# TYPE zui_native_cert_rotations counter\nzui_native_cert_rotations {d}\n", .{cs.stats.rotations.load(.monotonic)});
            try w.print("# TYPE zui_native_cert_hash_file_errors counter\nzui_native_cert_hash_file_errors {d}\n", .{cs.stats.hash_file_errors.load(.monotonic)});
            try w.print("# TYPE zui_native_cert_reloads counter\nzui_native_cert_reloads {d}\n", .{cs.stats.reloads.load(.monotonic)});
            try w.print("# TYPE zui_native_cert_reload_errors counter\nzui_native_cert_reload_errors {d}\n", .{cs.stats.reload_errors.load(.monotonic)});
        }
        // `--serve-tls-cert`: when the chain the gRPC TLS port presents expires, reloads that
        // replaced it or were refused, and the unix second of the last one that replaced it (0:
        // the chain is the one read at start).
        if (n.serve_tls_certs) |cs| {
            try w.print("# TYPE zui_serve_tls_cert_not_after_seconds gauge\nzui_serve_tls_cert_not_after_seconds {d}\n", .{cs.stats.not_after.load(.acquire)});
            try w.print("# TYPE zui_serve_tls_cert_reloads counter\nzui_serve_tls_cert_reloads {d}\n", .{cs.stats.reloads.load(.monotonic)});
            try w.print("# TYPE zui_serve_tls_cert_reload_errors counter\nzui_serve_tls_cert_reload_errors {d}\n", .{cs.stats.reload_errors.load(.monotonic)});
            try w.print("# TYPE zui_serve_tls_cert_last_reload_seconds gauge\nzui_serve_tls_cert_last_reload_seconds {d}\n", .{cs.stats.last_reload.load(.acquire)});
        }
        // Edge source (`--source zui1:`): requests, failovers, and wire / feed / blob bytes.
        if (n.edge_pool) |ep| {
            inline for (comptime std.meta.fieldNames(edge.client.Stats)) |name| {
                if (@TypeOf(@field(ep.stats, name)) == std.atomic.Value(u64))
                    try w.print("# TYPE zui_edge_{s} counter\nzui_edge_{s} {d}\n", .{ name, name, @field(ep.stats, name).load(.monotonic) });
            }
            // the re-ask's settled{attempt} and gave_up{reason}
            try ep.stats.renderReadSets(w);
            // what the re-ask's late lists came to (History.planLate)
            if (n.reask) |r| {
                try w.writeAll("# TYPE zui_edge_read_sets_late counter\n");
                inline for (comptime std.meta.fieldNames(history.LateOutcome), 0..) |name, i| try w.print("zui_edge_read_sets_late{{outcome=\"{s}\"}} {d}\n", .{ name, r.outcomes[i].load(.monotonic) });
            }
        }
        // Feed requests in flight at the cores (`--feed-max-inflight`): the count the controller
        // wants now, what is on the wire, and what moved it.
        if (n.fetcher) |f| if (f.inflight) |fl| {
            const st = &fl.ctl.stats;
            try w.print("# TYPE zui_edge_feed_inflight_target gauge\nzui_edge_feed_inflight_target {d}\n# TYPE zui_edge_feed_inflight gauge\nzui_edge_feed_inflight {d}\n# TYPE zui_edge_feed_inflight_peak gauge\nzui_edge_feed_inflight_peak {d}\n", .{ fl.target.load(.monotonic), fl.now.load(.monotonic), fl.peak.load(.monotonic) });
            try w.print("# TYPE zui_edge_feed_pipelined_calls counter\nzui_edge_feed_pipelined_calls {d}\n# TYPE zui_edge_feed_pipelined_checkpoints counter\nzui_edge_feed_pipelined_checkpoints {d}\n# TYPE zui_edge_feed_inflight_backoffs counter\nzui_edge_feed_inflight_backoffs {d}\n# TYPE zui_edge_feed_inflight_plateaus counter\nzui_edge_feed_inflight_plateaus {d}\n", .{ fl.calls.load(.monotonic), fl.fetched.load(.monotonic), st.backoffs, st.plateaus });
        };
        // Edge fallback (`--edge-fallback`): the active source (0 the zui/1 cores, 1 the
        // fallback), switches each way, checkpoints from each side, probes of the cores.
        if (n.edge_fb) |fb| try renderEdgeFallback(w, &fb.sw);
        // Edge routing (`--core-upstream`): served locally, forwarded by reason, the guard.
        if (n.edge_fwd) |f| try edge.forward.renderMetrics(f, w);
        // Edge certificates: marked, replaced, errors by kind, the oldest mark.
        if (n.edge_certs) |cv| {
            try cv.renderMetrics(w);
            const fs = &n.native_disp.foreign_stats;
            if (n.native_listener != null) try w.print("# TYPE zui_edge_cert_zui1_forwarded counter\nzui_edge_cert_zui1_forwarded {d}\n# TYPE zui_edge_cert_zui1_unavailable counter\nzui_edge_cert_zui1_unavailable {d}\n# TYPE zui_edge_cert_feed_withheld counter\nzui_edge_cert_feed_withheld {d}\n", .{ fs.forwarded.load(.monotonic), fs.unavailable.load(.monotonic), fs.feed_withheld.load(.monotonic) });
        }
        if (n.p2p_listener) |l| {
            inline for (comptime std.meta.fieldNames(@import("net").server.Stats)) |name| {
                try w.print("# TYPE zui_p2p_listener_{s} counter\nzui_p2p_listener_{s} {d}\n", .{ name, name, @field(l.stats, name).load(.monotonic) });
            }
        }
        if (n.streams.items.len > 0) {
            // Totals over all streams, then per stream.
            inline for (comptime std.meta.fieldNames(stream_mod.Stats)) |name| {
                var sum: u64 = 0;
                for (n.streams.items) |st| sum += @field(st.stats, name).load(.monotonic);
                try w.print("# TYPE zui_stream_{s} counter\nzui_stream_{s} {d}\n", .{ name, name, sum });
            }
            inline for (comptime std.meta.fieldNames(stream_mod.Stats)) |name| {
                try w.print("# TYPE zui_stream_source_{s} counter\n", .{name});
                for (n.streams.items) |st| try w.print("zui_stream_source_{s}{{url=\"{s}\"}} {d}\n", .{ name, st.base, @field(st.stats, name).load(.monotonic) });
            }
        }
        try w.print("# TYPE zui_store_live_objects gauge\nzui_store_live_objects {d}\n", .{n.st.liveCount()});
        // StateService index feed: old object versions it could not read (their rows were not
        // removed: stale rows, `deepwave-tool verify-index` finds them) and effects it could not
        // decode, on the commit path and in replays of stored checkpoints; the replays alone.
        if (n.ix_feed) |f| {
            const c = f.counters();
            try w.print("# TYPE zui_state_index_feed_missing_old counter\nzui_state_index_feed_missing_old {d}\n# TYPE zui_state_index_feed_undecodable counter\nzui_state_index_feed_undecodable {d}\n# TYPE zui_state_index_feed_unprepared counter\nzui_state_index_feed_unprepared {d}\n", .{ c.missing_old, c.undecodable, c.unprepared });
            try w.print("# TYPE zui_state_index_replay_checkpoints counter\nzui_state_index_replay_checkpoints {d}\n# TYPE zui_state_index_replay_missing_old counter\nzui_state_index_replay_missing_old {d}\n# TYPE zui_state_index_replay_undecodable counter\nzui_state_index_replay_undecodable {d}\n", .{ c.replayed, c.replay_missing_old, c.replay_undecodable });
        }
        // Compressed segments (chunk.zig): decoded-chunk cache, and what a miss costs.
        inline for (comptime std.meta.fieldNames(@TypeOf(n.st.cache.stats))) |name| {
            try w.print("# TYPE zui_store_chunk_{s} counter\nzui_store_chunk_{s} {d}\n", .{ name, name, @field(n.st.cache.stats, name).load(.monotonic) });
        }
        {
            // Decoded-chunk memory: the cache, chunks evicted and not reclaimed yet, chunks a live
            // snapshot may still hold (kept: what a grace period would have pending), snapshots.
            const chm = n.st.chunkMemory();
            try w.print("# TYPE zui_store_chunk_cached_bytes gauge\nzui_store_chunk_cached_bytes {d}\n# TYPE zui_store_chunk_evicted_bytes gauge\nzui_store_chunk_evicted_bytes {d}\n# TYPE zui_store_chunk_kept gauge\nzui_store_chunk_kept {d}\n# TYPE zui_store_chunk_kept_bytes gauge\nzui_store_chunk_kept_bytes {d}\n# TYPE zui_store_chunk_readers gauge\nzui_store_chunk_readers {d}\n", .{
                chm.cached_bytes, chm.evicted_bytes, chm.kept, chm.kept_bytes, chm.readers,
            });
        }
        {
            // Age-out by data type: dead records turned into holes, sidecar bytes written, old
            // frames punched (fallocate), and the superseded locations the passes still wait on.
            const ast = &n.st.age_stats;
            inline for (.{ "steps", "groups_rewritten", "chunks_rewritten", "records_dropped", "bytes_dropped", "phys_written", "phys_punched", "pending_full", "pending_prunes", "pending_behind", "handoff_waits", "deferred", "bulk_runs", "warm_groups", "warm_pages", "warm_uring_pages", "warm_fallback_pages", "warm_errors", "lookups", "lookups_cold", "seg_passes", "set_builds", "set_pages", "set_marked", "set_kept", "set_groups_skipped", "set_chunks_skipped", "set_dead", "set_restarts", "set_inexact", "set_misses", "set_links", "link_kept" }) |name| {
                try w.print("# TYPE zui_store_age_{s} counter\nzui_store_age_{s} {d}\n", .{ name, name, @field(ast, name).load(.monotonic) });
            }
            // Deferred age-out: 1 while the node is far behind the tip, and the logical bytes of
            // history below the checkpoint floor the ager had not processed at its last check.
            try w.print("# TYPE zui_store_age_behind gauge\nzui_store_age_behind {d}\n# TYPE zui_store_age_backlog_bytes gauge\nzui_store_age_backlog_bytes {d}\n", .{
                @intFromBool(n.st.age_behind.load(.monotonic)), ast.backlog.load(.monotonic),
            });
            try w.print("# TYPE zui_store_age_pending gauge\nzui_store_age_pending {d}\n# TYPE zui_store_age_max_step_ms gauge\nzui_store_age_max_step_ms {d}\n# TYPE zui_store_age_failed gauge\nzui_store_age_failed {d}\n", .{
                ast.pending.load(.monotonic), ast.max_step_ns.load(.monotonic) / std.time.ns_per_ms, @intFromBool(ast.failed.load(.monotonic)),
            });
            // The ager's memory: what it holds, the most it has held, its budget, and the two
            // parts that grow with the work (the pending set, old directories not yet taken).
            try w.print("# TYPE zui_store_age_mem_bytes gauge\nzui_store_age_mem_bytes {d}\n# TYPE zui_store_age_mem_max_bytes gauge\nzui_store_age_mem_max_bytes {d}\n# TYPE zui_store_age_mem_budget_bytes gauge\nzui_store_age_mem_budget_bytes {d}\n# TYPE zui_store_age_mem_pending_bytes gauge\nzui_store_age_mem_pending_bytes {d}\n# TYPE zui_store_age_mem_handoff_bytes gauge\nzui_store_age_mem_handoff_bytes {d}\n", .{
                ast.mem.load(.monotonic), ast.mem_max.load(.monotonic), n.st.cfg.age_mem_bytes, ast.mem_pending.load(.monotonic), ast.mem_handoff.load(.monotonic),
            });
            // Time the steps held the age lock, and time spent reading ahead of them (no lock).
            try w.print("# TYPE zui_store_age_locked_ms counter\nzui_store_age_locked_ms {d}\n# TYPE zui_store_age_warm_ms counter\nzui_store_age_warm_ms {d}\n", .{
                ast.locked_ns.load(.monotonic) / std.time.ns_per_ms, ast.warm_ns.load(.monotonic) / std.time.ns_per_ms,
            });
        }
        {
            // Store commit latency over the last 65,536 commits, and the live-index flushes
            // (they run on their own thread; a commit only waits on backpressure).
            // `zui_store_commit_recent_ms`: the last 7,200 commits, about 30 min at the tip.
            const cl = n.st.commitLatency(n.gpa, std.math.maxInt(u64));
            const rc = n.st.commitLatency(n.gpa, 7200);
            inline for (.{ .{ "zui_store_commit_ms", &cl }, .{ "zui_store_commit_recent_ms", &rc } }) |m| {
                try w.print("# TYPE " ++ m[0] ++ " gauge\n" ++ m[0] ++ "{{q=\"0.5\"}} {d:.3}\n" ++ m[0] ++ "{{q=\"0.99\"}} {d:.3}\n" ++ m[0] ++ "{{q=\"0.999\"}} {d:.3}\n" ++ m[0] ++ "{{q=\"1\"}} {d:.3}\n", .{
                    @as(f64, @floatFromInt(m[1].p50)) / 1e6, @as(f64, @floatFromInt(m[1].p99)) / 1e6, @as(f64, @floatFromInt(m[1].p999)) / 1e6, @as(f64, @floatFromInt(m[1].max_window)) / 1e6,
                });
            }
            try w.print("# TYPE zui_store_commits counter\nzui_store_commits {d}\n# TYPE zui_store_commit_max_ms gauge\nzui_store_commit_max_ms {d:.3}\n# TYPE zui_store_commits_over_100ms counter\nzui_store_commits_over_100ms {d}\n", .{ cl.n, @as(f64, @floatFromInt(cl.max_ever)) / 1e6, cl.slow });
            const fs = &n.st.stats;
            try w.print("# TYPE zui_store_corrupt_reads_total counter\nzui_store_corrupt_reads_total {d}\n", .{fs.corrupt_reads.load(.monotonic)});
            try w.print("# TYPE zui_store_index_flushes counter\nzui_store_index_flushes {d}\n# TYPE zui_store_flush_cow_pages counter\nzui_store_flush_cow_pages {d}\n# TYPE zui_store_flush_wait_ms counter\nzui_store_flush_wait_ms {d}\n# TYPE zui_store_flush_last_ms gauge\nzui_store_flush_last_ms {d}\n# TYPE zui_store_flush_runs counter\nzui_store_flush_runs {d}\n# TYPE zui_store_flush_run_pages counter\nzui_store_flush_run_pages {d}\n# TYPE zui_store_live_dirty_pages gauge\nzui_store_live_dirty_pages {d}\n", .{
                fs.index_flushes, fs.flush_cow_pages, fs.flush_wait_ns / std.time.ns_per_ms, fs.flush_last_ns / std.time.ns_per_ms, fs.flush_runs, fs.flush_run_pages, n.st.indexMemory().live_dirty / 4096,
            });
            try w.print("# TYPE zui_store_flush_last_pages gauge\nzui_store_flush_last_pages {d}\n# TYPE zui_store_flush_drain_pages_per_s gauge\nzui_store_flush_drain_pages_per_s {d}\n# TYPE zui_store_flush_pace_ms counter\nzui_store_flush_pace_ms {d}\n# TYPE zui_store_flush_pace_max_ms gauge\nzui_store_flush_pace_max_ms {d}\n# TYPE zui_store_flush_parallel counter\nzui_store_flush_parallel {d}\n", .{
                fs.flush_last_pages, fs.flush_drain_pps, fs.flush_pace_ns / std.time.ns_per_ms, fs.flush_pace_max_ns / std.time.ns_per_ms, fs.flush_parallel,
            });
        }
        if (n.hub) |h| {
            const st = &h.stats;
            try w.print("# TYPE zui_subscription_subscribers gauge\nzui_subscription_subscribers {d}\n", .{st.subscribers.load(.monotonic)});
            try w.print("# TYPE zui_subscription_frames counter\nzui_subscription_frames {d}\n", .{st.frames.load(.monotonic)});
            try w.print("# TYPE zui_subscription_bytes counter\nzui_subscription_bytes {d}\n", .{st.bytes.load(.monotonic)});
            try w.print("# TYPE zui_subscription_publish_lag_ms gauge\nzui_subscription_publish_lag_ms {d}\n", .{st.publish_lag_ms.load(.monotonic)});
            inline for (comptime std.meta.fieldNames(serve.subscribe.Reason), 0..) |name, i| {
                try w.print("zui_subscription_terminations{{reason=\"" ++ name ++ "\"}} {d}\n", .{st.terminations[i].load(.monotonic)});
            }
        }
        try n.service.cp_cache.render(w); // zui_cpcache_*: the GetCheckpoint response cache (serve/cpcache.zig)
        if (n.fetcher) |f| {
            inline for (comptime std.meta.fieldNames(source_mod.FetcherStats)) |name| {
                try w.print("# TYPE zui_fetch_{s} counter\nzui_fetch_{s} {d}\n", .{ name, name, @field(f.stats, name).load(.monotonic) });
            }
        }
        if (n.sig_order) |o| {
            inline for (comptime std.meta.fieldNames(sigorder.Stats)) |name| {
                try w.print("# TYPE zui_sig_order_{s} counter\nzui_sig_order_{s} {d}\n", .{ name, name, @field(o.stats, name).load(.monotonic) });
            }
        }
        if (n.sig_sweep) |sw| {
            inline for (comptime std.meta.fieldNames(sigorder.SweepStats)) |name| {
                try w.print("# TYPE zui_sig_order_sweep_{s} counter\nzui_sig_order_sweep_{s} {d}\n", .{ name, name, @field(sw.stats, name).load(.monotonic) });
            }
            try w.print("# TYPE zui_sig_order_sweep_next gauge\nzui_sig_order_sweep_next {d}\n# TYPE zui_sig_order_fixes gauge\nzui_sig_order_fixes {d}\n# TYPE zui_sig_order_fix_bytes gauge\nzui_sig_order_fix_bytes {d}\n", .{ sw.pos.load(.monotonic), n.st.tx_fix.count(), n.st.tx_fix.heldBytes() });
        }
        if (n.history) |h| {
            inline for (comptime std.meta.fieldNames(history.Stats)) |name| {
                try w.print("# TYPE zui_readset_{s} counter\nzui_readset_{s} {d}\n", .{ name, name, @field(h.stats, name).load(.monotonic) });
            }
        }
        if (n.cur_params.rgp) |r| try w.print("# TYPE zui_node_reference_gas_price gauge\nzui_node_reference_gas_price {d}\n", .{r});
        if (n.executor) |x| {
            inline for (comptime std.meta.fieldNames(execute.Stats)) |name| {
                try w.print("# TYPE zui_exec_{s} counter\nzui_exec_{s} {d}\n", .{ name, name, @field(x.stats, name).load(.monotonic) });
            }
        }
        if (n.public) |h| {
            inline for (comptime std.meta.fieldNames(http.Stats)) |name| {
                try w.print("# TYPE zui_public_{s} counter\nzui_public_{s} {d}\n", .{ name, name, @field(h.stats, name).load(.monotonic) });
            }
        }
        if (n.bucket) |b| {
            try w.print("# TYPE zui_s3_gets counter\nzui_s3_gets {d}\n# TYPE zui_s3_bytes counter\nzui_s3_bytes {d}\n# TYPE zui_s3_usd gauge\nzui_s3_usd {d:.6}\n", .{ b.stats.gets.load(.monotonic), b.stats.bytes.load(.monotonic), b.stats.usd() });
        }
    }
};

/// Reference gas price and start of the epoch that the stored end-of-epoch checkpoint (its
/// `contents`) starts, read from the stored ChangeEpoch transaction and its events.
fn paramsFromStore(tmp: *std.heap.ArenaAllocator, snap: *const store.Snapshot, contents: []const u8) !trust.EpochParams {
    const a = tmp.allocator();
    const cc = try @import("bcs").decode(types.CheckpointContents, a, contents);
    var digests: std.ArrayList([32]u8) = .empty;
    switch (cc) {
        .V1 => |v| for (v.transactions) |t| try digests.append(a, t.transaction.@"0".@"0"),
        .V2 => |v| for (v.transactions) |t| try digests.append(a, t.digest.transaction.@"0".@"0"),
    }
    var i = digests.items.len;
    while (i > 0) {
        i -= 1;
        const rec = (try snap.transactionChecked(&digests.items[i])) orelse continue;
        const sp = try serve.service.splitEnvelope(a, rec.tx);
        const start = trust.changeEpochStart(a, sp.data) orelse continue;
        return .{ .start_ms = start, .rgp = if (rec.events) |ev| trust.epochInfoRgp(a, ev) else null };
    }
    return .{};
}

test "serve answers as sui-node 1.83.1 by default (GetEpoch protocol_config without 1.84 fields)" {
    // DROP-IN-STATUS round 1: deepwave from main left Service.protocol_release_max at deepwave's own
    // max (142), so GetEpoch listed check_groth16_pvk_length and
    // secp256r1_ecrecover_checks_x_below_p, which sui-node 1.83.1 does not have.
    const cfg: Config = .{ .dir = "", .source = .{ .dir = "" } };
    try std.testing.expectEqual(@as(u64, 141), cfg.rpc_release_max);
    try std.testing.expectEqual(@as(?u64, 142), parseRpcRelease("1.84"));
    try std.testing.expectEqual(@as(?u64, 141), parseRpcRelease("1.83.1"));
}
