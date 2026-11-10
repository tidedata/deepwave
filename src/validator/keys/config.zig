//! validator.yaml at mainnet-v1.83.1 (sui-config `node.rs` NodeConfig, kebab-case keys). The YAML
//! subset parser is the full node's (`node.fullnode_yaml`), so a validator.yaml and a fullnode.yaml
//! read the same way. NodeConfig does not deny unknown fields, so unknown keys are kept in
//! `unknown_keys` (the caller logs them) instead of failing; values of a known key with the wrong
//! shape fail with `BadConfig` and name the key in `Loaded.bad_key`.
const std = @import("std");
const node = @import("node");
const yaml = node.fullnode_yaml;
const material = @import("material.zig");

pub const Error = error{ BadConfig, Io, OutOfMemory };

/// A key pair as validator.yaml gives it: `path: file` or an in-place base64 `value`.
pub const KeyLocation = union(enum) {
    path: []const u8,
    value: []const u8,
};

/// AuthorityOverloadConfig (node.rs defaults).
pub const Overload = struct {
    max_txn_age_in_queue_ms: u64 = 1000,
    overload_monitor_interval_ms: u64 = 10_000,
    execution_queue_latency_soft_limit_ms: u64 = 1000,
    execution_queue_latency_hard_limit_ms: u64 = 10_000,
    max_load_shedding_percentage: u32 = 95,
    min_load_shedding_percentage_above_hard_limit: u32 = 50,
    safe_transaction_ready_rate: u32 = 100,
    check_system_overload_at_signing: bool = true,
    max_transaction_manager_queue_length: usize = 100_000,
    max_transaction_manager_per_object_queue_length: usize = 2000,
    admission_queue_capacity_fraction: f64 = 0.5,
    admission_queue_enabled: bool = true,
    admission_queue_failover_timeout_ms: u64 = 30_000,
};

pub const Consensus = struct {
    db_path: []const u8,
    db_retention_epochs: u64 = 0,
    db_pruner_period_secs: u64 = 3600,
    max_pending_transactions: usize = 20_000,
    listen_address: ?[]const u8 = null,
    external_address: ?[]const u8 = null,
};

pub const ValidatorConfig = struct {
    db_path: []const u8,
    /// Multiaddr of the sui.validator.Validator gRPC server.
    network_address: []const u8 = "/ip4/0.0.0.0/tcp/8080",
    metrics_address: []const u8 = "0.0.0.0:9184",
    admin_interface_port: u16 = 1337,
    protocol_key: ?KeyLocation = null,
    worker_key: ?KeyLocation = null,
    account_key: ?KeyLocation = null,
    network_key: ?KeyLocation = null,
    genesis_path: ?[]const u8 = null,
    consensus: ?Consensus = null,
    p2p_listen_address: []const u8 = "0.0.0.0:8084",
    p2p_external_address: ?[]const u8 = null,
    seed_peers: []const []const u8 = &.{},
    jwk_fetch_interval_seconds: u64 = 3600,
    overload: Overload = .{},
    grpc_concurrency_limit: ?usize = 20_000_000_000,
    grpc_load_shed: ?bool = null,
    /// Top-level keys this loader does not know (NodeConfig tolerates them; the caller warns).
    unknown_keys: []const []const u8 = &.{},

    /// Every address this config would bind or dial, for the safety gate.
    pub fn addresses(c: *const ValidatorConfig, arena: std.mem.Allocator) std.mem.Allocator.Error![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        try out.append(arena, c.network_address);
        try out.append(arena, c.metrics_address);
        try out.append(arena, c.p2p_listen_address);
        if (c.p2p_external_address) |a| try out.append(arena, a);
        if (c.consensus) |cc| {
            if (cc.listen_address) |a| try out.append(arena, a);
            if (cc.external_address) |a| try out.append(arena, a);
        }
        for (c.seed_peers) |a| try out.append(arena, a);
        return out.items;
    }
};

/// A loaded config; strings live in `arena`.
pub const Loaded = struct {
    arena: std.heap.ArenaAllocator,
    cfg: ValidatorConfig,
    /// The offending key when `Error.BadConfig` came back through `parse` (static text).
    pub fn deinit(l: *Loaded) void {
        l.arena.deinit();
    }
};

/// Every key NodeConfig (de)serializes at mainnet-v1.83.1 (node.rs, serde(skip) fields excluded).
/// Keys outside this list are what serde ignores; `unknown_keys` lists them.
const known_keys = [_][]const u8{
    "protocol-key-pair", "worker-key-pair", "account-key-pair", "network-key-pair", "db-path",
    "network-address", "json-rpc-address", "rpc", "metrics-address", "admin-interface-port",
    "consensus-config", "fullnode-sync-mode", "grpc-load-shed", "grpc-concurrency-limit",
    "p2p-config", "genesis", "authority-store-pruning-config",
    "end-of-epoch-broadcast-channel-capacity", "checkpoint-executor-config", "metrics",
    "db-checkpoint-config", "expensive-safety-check-config", "transaction-deny-config",
    "peer-deny-sync-config", "dev-inspect-disabled", "certificate-deny-config",
    "state-debug-dump-config", "state-archive-read-config", "state-snapshot-write-config",
    "jwk-fetch-interval-seconds", "zklogin-oauth-providers", "authority-overload-config",
    "run-with-range", "policy-config", "firewall-config", "execution-cache", "enable-soft-bundle",
    "enable-simulate-allowed-proposers", "enable-staggered-submission-signal",
    "verifier-signing-config", "enable-db-write-stall", "enable-db-sync-to-disk",
    "execution-time-observer-config", "recent-submission-dedup-window-ms",
    "chain-override-for-testing", "validator-client-monitor-config", "fork-recovery",
    "transaction-driver-config", "consensus-transaction-pool", "congestion-log", "address-prober",
};

pub fn load(gpa: std.mem.Allocator, io: std.Io, path: []const u8) Error!Loaded {
    const data = Io_readAll(gpa, io, path) catch return error.Io;
    defer gpa.free(data);
    return parse(gpa, data);
}

fn Io_readAll(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 << 20));
}

pub fn parse(gpa: std.mem.Allocator, text: []const u8) Error!Loaded {
    var l: Loaded = .{ .arena = std.heap.ArenaAllocator.init(gpa), .cfg = undefined };
    errdefer l.arena.deinit();
    const a = l.arena.allocator();
    // The YAML parser returns scalars as slices of its input: keep the text in the arena, so the
    // config outlives the caller's buffer (`load` frees the file contents after parsing).
    const owned = try a.dupe(u8, text);
    var err_line: usize = 0;
    const root = yaml.parse(a, owned, &err_line) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.YamlSyntax => error.BadConfig,
    };
    if (root != .map) return error.BadConfig;
    l.cfg = try fromValue(a, root);
    return l;
}

fn str(v: yaml.Value) Error![]const u8 {
    return switch (v) {
        .scalar => |s| s,
        else => error.BadConfig,
    };
}

fn int(comptime T: type, v: yaml.Value) Error!T {
    return std.fmt.parseInt(T, try str(v), 10) catch error.BadConfig;
}

fn boolean(v: yaml.Value) Error!bool {
    const s = try str(v);
    if (std.mem.eql(u8, s, "true")) return true;
    if (std.mem.eql(u8, s, "false")) return false;
    return error.BadConfig;
}

/// serde Duration: `{secs: N, nanos: N}`; milliseconds, rounded down.
fn durationMs(v: yaml.Value) Error!u64 {
    const secs = v.get("secs") orelse return error.BadConfig;
    const nanos = if (v.get("nanos")) |n| try int(u64, n) else 0;
    return (try int(u64, secs)) *| 1000 +| nanos / 1_000_000;
}

/// KeyPairWithPath / AuthorityKeyPairWithPath: untagged `{value: <base64>}` or `{path: <file>}`.
/// serde decodes an in-place value while parsing (a BLS secret for the protocol key, any
/// SuiKeyPair for the others) and reads a file only when the key is used, so the same holds here.
fn keyLocation(v: yaml.Value, authority: bool) Error!KeyLocation {
    if (v.get("value")) |p| {
        const text = try str(p);
        if (authority) {
            var sk = material.decodeAuthorityFile(text) catch return error.BadConfig;
            std.crypto.secureZero(u8, std.mem.asBytes(&sk));
        } else _ = material.checkSuiKeyText(text) catch return error.BadConfig;
        return .{ .value = text };
    }
    if (v.get("path")) |p| return .{ .path = try str(p) };
    return error.BadConfig;
}

fn fromValue(a: std.mem.Allocator, root: yaml.Value) Error!ValidatorConfig {
    var c: ValidatorConfig = .{ .db_path = "" };
    var unknown: std.ArrayList([]const u8) = .empty;
    var have_db = false;
    for (root.map) |p| {
        const k = p.key;
        const v = p.value;
        if (std.mem.eql(u8, k, "db-path")) {
            c.db_path = try str(v);
            have_db = true;
        } else if (std.mem.eql(u8, k, "network-address")) {
            c.network_address = try str(v);
        } else if (std.mem.eql(u8, k, "metrics-address")) {
            c.metrics_address = try str(v);
        } else if (std.mem.eql(u8, k, "admin-interface-port")) {
            c.admin_interface_port = try int(u16, v);
        } else if (std.mem.eql(u8, k, "protocol-key-pair")) {
            c.protocol_key = try keyLocation(v, true);
        } else if (std.mem.eql(u8, k, "worker-key-pair")) {
            c.worker_key = try keyLocation(v, false);
        } else if (std.mem.eql(u8, k, "account-key-pair")) {
            c.account_key = try keyLocation(v, false);
        } else if (std.mem.eql(u8, k, "network-key-pair")) {
            c.network_key = try keyLocation(v, false);
        } else if (std.mem.eql(u8, k, "genesis")) {
            if (v.get("genesis-file-location")) |g| c.genesis_path = try str(g) else return error.BadConfig;
        } else if (std.mem.eql(u8, k, "jwk-fetch-interval-seconds")) {
            c.jwk_fetch_interval_seconds = try int(u64, v);
        } else if (std.mem.eql(u8, k, "grpc-load-shed")) {
            c.grpc_load_shed = if (v == .null) null else try boolean(v);
        } else if (std.mem.eql(u8, k, "grpc-concurrency-limit")) {
            c.grpc_concurrency_limit = if (v == .null) null else try int(usize, v);
        } else if (std.mem.eql(u8, k, "consensus-config")) {
            if (v != .null) c.consensus = try consensus(v);
        } else if (std.mem.eql(u8, k, "p2p-config")) {
            if (v.get("listen-address")) |x| c.p2p_listen_address = try str(x);
            if (v.get("external-address")) |x| {
                if (x != .null) c.p2p_external_address = try str(x);
            }
            if (v.get("seed-peers")) |sp| {
                if (sp != .seq) return error.BadConfig;
                var peers: std.ArrayList([]const u8) = .empty;
                for (sp.seq) |e| {
                    const addr = e.get("address") orelse return error.BadConfig;
                    try peers.append(a, try str(addr));
                }
                c.seed_peers = peers.items;
            }
        } else if (std.mem.eql(u8, k, "authority-overload-config")) {
            c.overload = try overload(v);
        } else {
            var known = false;
            for (known_keys) |kk| {
                if (std.mem.eql(u8, kk, k)) known = true;
            }
            if (!known) try unknown.append(a, k);
        }
    }
    if (!have_db) return error.BadConfig;
    c.unknown_keys = unknown.items;
    return c;
}

fn consensus(v: yaml.Value) Error!Consensus {
    var c: Consensus = .{ .db_path = "" };
    c.db_path = try str(v.get("db-path") orelse return error.BadConfig);
    if (v.get("db-retention-epochs")) |x| if (x != .null) {
        c.db_retention_epochs = try int(u64, x);
    };
    if (v.get("db-pruner-period-secs")) |x| if (x != .null) {
        c.db_pruner_period_secs = try int(u64, x);
    };
    if (v.get("max-pending-transactions")) |x| if (x != .null) {
        c.max_pending_transactions = try int(usize, x);
    };
    if (v.get("listen-address")) |x| if (x != .null) {
        c.listen_address = try str(x);
    };
    if (v.get("external-address")) |x| if (x != .null) {
        c.external_address = try str(x);
    };
    return c;
}

fn overload(v: yaml.Value) Error!Overload {
    var o: Overload = .{};
    if (v != .map) return error.BadConfig;
    for (v.map) |p| {
        const k = p.key;
        const x = p.value;
        if (std.mem.eql(u8, k, "max-txn-age-in-queue")) {
            o.max_txn_age_in_queue_ms = try durationMs(x);
        } else if (std.mem.eql(u8, k, "overload-monitor-interval")) {
            o.overload_monitor_interval_ms = try durationMs(x);
        } else if (std.mem.eql(u8, k, "execution-queue-latency-soft-limit")) {
            o.execution_queue_latency_soft_limit_ms = try durationMs(x);
        } else if (std.mem.eql(u8, k, "execution-queue-latency-hard-limit")) {
            o.execution_queue_latency_hard_limit_ms = try durationMs(x);
        } else if (std.mem.eql(u8, k, "max-load-shedding-percentage")) {
            o.max_load_shedding_percentage = try int(u32, x);
        } else if (std.mem.eql(u8, k, "min-load-shedding-percentage-above-hard-limit")) {
            o.min_load_shedding_percentage_above_hard_limit = try int(u32, x);
        } else if (std.mem.eql(u8, k, "safe-transaction-ready-rate")) {
            o.safe_transaction_ready_rate = try int(u32, x);
        } else if (std.mem.eql(u8, k, "check-system-overload-at-signing")) {
            o.check_system_overload_at_signing = try boolean(x);
        } else if (std.mem.eql(u8, k, "max-transaction-manager-queue-length")) {
            o.max_transaction_manager_queue_length = try int(usize, x);
        } else if (std.mem.eql(u8, k, "max-transaction-manager-per-object-queue-length")) {
            o.max_transaction_manager_per_object_queue_length = try int(usize, x);
        } else if (std.mem.eql(u8, k, "admission-queue-capacity-fraction")) {
            o.admission_queue_capacity_fraction = std.fmt.parseFloat(f64, try str(x)) catch return error.BadConfig;
        } else if (std.mem.eql(u8, k, "admission-queue-enabled")) {
            o.admission_queue_enabled = try boolean(x);
        } else if (std.mem.eql(u8, k, "admission-queue-failover-timeout")) {
            o.admission_queue_failover_timeout_ms = try durationMs(x);
        }
    }
    return o;
}

test "validator.yaml loads known keys, defaults and reports unknown ones" {
    const text =
        \\---
        \\protocol-key-pair:
        \\  path: /keys/protocol.key
        \\worker-key-pair:
        \\  path: /keys/worker.key
        \\network-key-pair:
        \\  value: AGXlMKrYkj+CLojtVPwa9rE1QUKZHJA+XGhfgWp7porR
        \\db-path: /db/authorities_db
        \\network-address: /ip4/127.0.0.1/tcp/8080
        \\consensus-config:
        \\  db-path: /db/consensus
        \\  db-retention-epochs: 2
        \\  listen-address: /ip4/127.0.0.1/udp/8081
        \\p2p-config:
        \\  listen-address: 127.0.0.1:8084
        \\  seed-peers:
        \\  - address: /ip4/127.0.0.1/udp/8085
        \\genesis:
        \\  genesis-file-location: /cfg/genesis.blob
        \\authority-overload-config:
        \\  max-txn-age-in-queue:
        \\    secs: 2
        \\    nanos: 500000000
        \\  max-load-shedding-percentage: 80
        \\something-new: 1
        \\
    ;
    var l = try parse(std.testing.allocator, text);
    defer l.deinit();
    const c = l.cfg;
    try std.testing.expectEqualStrings("/db/authorities_db", c.db_path);
    try std.testing.expectEqualStrings("/keys/worker.key", c.worker_key.?.path);
    try std.testing.expectEqualStrings("AGXlMKrYkj+CLojtVPwa9rE1QUKZHJA+XGhfgWp7porR", c.network_key.?.value);
    try std.testing.expect(c.account_key == null);
    try std.testing.expectEqual(@as(u64, 2), c.consensus.?.db_retention_epochs);
    try std.testing.expectEqual(@as(usize, 20_000), c.consensus.?.max_pending_transactions);
    try std.testing.expectEqual(@as(u64, 2500), c.overload.max_txn_age_in_queue_ms);
    try std.testing.expectEqual(@as(u32, 80), c.overload.max_load_shedding_percentage);
    try std.testing.expectEqual(@as(usize, 1), c.seed_peers.len);
    try std.testing.expectEqual(@as(usize, 1), c.unknown_keys.len);
    try std.testing.expectEqualStrings("something-new", c.unknown_keys[0]);
    try std.testing.expectEqualStrings("/cfg/genesis.blob", c.genesis_path.?);
}

test "a loaded config does not point into the caller's text" {
    const text = try std.testing.allocator.dupe(u8, "db-path: /db/x\nnetwork-address: /ip4/127.0.0.1/tcp/1\n");
    var l = try parse(std.testing.allocator, text);
    defer l.deinit();
    @memset(text, 'Z');
    std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("/db/x", l.cfg.db_path);
    try std.testing.expectEqualStrings("/ip4/127.0.0.1/tcp/1", l.cfg.network_address);
}

test "missing db-path and wrong shapes are rejected" {
    try std.testing.expectError(error.BadConfig, parse(std.testing.allocator, "network-address: x\n"));
    try std.testing.expectError(error.BadConfig, parse(std.testing.allocator, "db-path: /x\nadmin-interface-port: notanumber\n"));
}

test "a validator.yaml written by Mysten's ConfigBuilder (sui genesis) loads, keys in place" {
    // tools/truth/validator-keys: sui-swarm-config ConfigBuilder, committee of 4, StdRng seed 0,
    // genesis as a file (what `sui genesis` saves); db paths rewritten to /opt/sui/db.
    const Facts = struct {
        db_path: []const u8,
        network_address: []const u8,
        metrics_address: []const u8,
        admin_interface_port: u16,
        p2p_listen: []const u8,
        p2p_external: []const u8,
        consensus_db: []const u8,
        authority_pk: []const u8,
        worker_pk: []const u8,
        network_pk: []const u8,
        jwk_fetch_interval_seconds: u64,
        max_txn_age_in_queue_ms: u64,
    };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f = try std.json.parseFromSliceLeaky(Facts, a, std.mem.trim(u8, @embedFile("testdata/mysten-validator-0.jsonl"), "\n"), .{ .ignore_unknown_fields = true });
    var l = try parse(std.testing.allocator, @embedFile("testdata/mysten-validator-0.yaml"));
    defer l.deinit();
    const c = l.cfg;
    try std.testing.expectEqualStrings(f.db_path, c.db_path);
    try std.testing.expectEqualStrings(f.network_address, c.network_address);
    try std.testing.expectEqualStrings(f.metrics_address, c.metrics_address);
    try std.testing.expectEqual(f.admin_interface_port, c.admin_interface_port);
    try std.testing.expectEqualStrings(f.p2p_listen, c.p2p_listen_address);
    try std.testing.expectEqualStrings(f.p2p_external, c.p2p_external_address.?);
    try std.testing.expectEqualStrings(f.consensus_db, c.consensus.?.db_path);
    try std.testing.expectEqualStrings("/opt/sui/config/genesis.blob", c.genesis_path.?);
    try std.testing.expectEqual(f.jwk_fetch_interval_seconds, c.jwk_fetch_interval_seconds);
    try std.testing.expectEqual(f.max_txn_age_in_queue_ms, c.overload.max_txn_age_in_queue_ms);
    try std.testing.expectEqual(@as(?usize, 20_000_000_000), c.grpc_concurrency_limit);
    try std.testing.expect(c.grpc_load_shed == null);
    // every top-level key Mysten writes is one this loader knows
    for (c.unknown_keys) |k| std.debug.print("unknown key {s}\n", .{k});
    try std.testing.expectEqual(@as(usize, 0), c.unknown_keys.len);
    // the in-place keys are Mysten's keys
    const hexpk = struct {
        fn of(al: std.mem.Allocator, b: []const u8) ![]const u8 {
            return std.fmt.allocPrint(al, "{x}", .{b});
        }
    }.of;
    const sk = try material.decodeAuthorityFile(c.protocol_key.?.value);
    try std.testing.expectEqualStrings(f.authority_pk, try hexpk(a, &sk.publicKey().toBytes()));
    const wk = try material.decodeEd25519File(c.worker_key.?.value);
    try std.testing.expectEqualStrings(f.worker_pk, try hexpk(a, &wk.public_key.toBytes()));
    const nk = try material.decodeEd25519File(c.network_key.?.value);
    try std.testing.expectEqualStrings(f.network_pk, try hexpk(a, &nk.public_key.toBytes()));
    // and the API binds the address Mysten's server would (`/ip4/../tcp/<port>/https`)
    const api = @import("../api/server.zig");
    const addr = try api.parseListen(c.network_address);
    const port_text = c.network_address[std.mem.lastIndexOf(u8, c.network_address, "/tcp/").? + 5 ..];
    try std.testing.expectEqual(try std.fmt.parseInt(u16, port_text[0..std.mem.indexOfScalar(u8, port_text, '/').?], 10), addr.getPort());
}

test "an in-place key value Mysten's serde would reject is BadConfig" {
    try std.testing.expectError(error.BadConfig, parse(std.testing.allocator, "db-path: /x\nnetwork-key-pair:\n  value: AAAA\n"));
    try std.testing.expectError(error.BadConfig, parse(std.testing.allocator, "db-path: /x\nprotocol-key-pair:\n  value: //////////////////////////////////////////8=\n"));
}
