//! sui-node's `p2p-config` knobs (sui-config p2p.rs, mainnet-v1.83.1) as `deepwave run
//! --p2p-opt KEY=VALUE`, KEY being the fullnode.yaml path under `p2p-config` (`fullnode_yaml.zig`
//! emits one flag per key it finds). Unset keys keep sui-node's defaults. List values:
//!
//!   discovery.allowlisted-peers=PEERID[@MULTIADDR][,...]
//!   peer-address-overrides=PEERID@MULTIADDR[|MULTIADDR][,...]
//!
//! Applied in node.zig to the follower (p2p.zig), its dial pool and scores, and the server
//! (p2p_serve.zig).
const std = @import("std");
const net = @import("net");

pub const Tuning = struct {
    // ---- discovery
    /// `discovery.interval-period-ms` (5 s): how often one connected peer is asked for peers.
    interval_period_ms: ?u64 = null,
    /// `discovery.target-concurrent-connections` (sui-node 4): deepwave's rotating discovered-peer
    /// slots (`--p2p-discover`, default 32) when set.
    target_concurrent_connections: ?u8 = null,
    /// `discovery.peers-to-query` (1): accepted; deepwave asks one peer per tick.
    peers_to_query: ?u64 = null,
    /// `discovery.get-known-peers-rate-limit` (per peer, requests/s; none).
    get_known_peers_rate_limit: ?u32 = null,
    /// `discovery.use-get-known-peers-v3` (false).
    use_get_known_peers_v3: bool = false,
    /// `discovery.peer-addr-store-path` (default `<db-path>/discovery_peer_cache.yaml`; "off": none).
    peer_addr_store_path: ?[]const u8 = null,
    /// `discovery.peer-failure-cooldown-ms` (1 h).
    peer_failure_cooldown_ms: ?u64 = null,
    /// `discovery.min-peers-for-disconnect` (2).
    min_peers_for_disconnect: ?u32 = null,
    /// `discovery.allowlisted-peers` (`PEERID[@MULTIADDR],...`).
    allowlisted_peers: ?[]const u8 = null,
    /// `peer-address-overrides` (`PEERID@MULTIADDR[|MULTIADDR],...`).
    peer_address_overrides: ?[]const u8 = null,
    // ---- state sync
    push_checkpoint_summary_rate_limit: ?u32 = null,
    get_checkpoint_summary_rate_limit: ?u32 = null,
    get_checkpoint_contents_rate_limit: ?u32 = null,
    get_checkpoint_contents_inflight_limit: ?u32 = null,
    get_checkpoint_contents_per_checkpoint_limit: ?u32 = null,
    /// `state-sync.max-checkpoint-summary-size` (256 KiB): the StateSync request size limit.
    max_checkpoint_summary_size: ?usize = null,
    /// `state-sync.use-get-checkpoint-contents-v2` (true).
    use_get_checkpoint_contents_v2: bool = true,
    peer_scoring_window_ms: ?u64 = null,
    exploration_probability: ?f64 = null,
    peer_failure_rate: ?f64 = null,
    peer_disconnect_threshold_ms: ?u64 = null,
    // ---- network
    /// `excessive-message-size` (32 MiB): `sui_*_excessive_size_*` threshold.
    excessive_message_size: ?usize = null,
};

/// Keys accepted with no effect in deepwave (sui-node internals: mailboxes, channel sizes, download
/// concurrency, its own timeouts), so a fullnode.yaml that sets them still loads.
pub const no_effect = [_][]const u8{
    "discovery.mailbox-capacity",
    "state-sync.interval-period-ms",
    "state-sync.mailbox-capacity",
    "state-sync.synced-checkpoint-broadcast-channel-capacity",
    "state-sync.checkpoint-header-download-concurrency",
    "state-sync.checkpoint-content-download-concurrency",
    "state-sync.checkpoint-content-download-tx-concurrency",
    "state-sync.timeout-ms",
    "state-sync.checkpoint-content-timeout-ms",
    "state-sync.checkpoint-content-timeout-min-ms",
    "state-sync.checkpoint-content-timeout-max-ms",
    "state-sync.wait-interval-when-no-peer-to-sync-content-ms",
    "state-sync.max-checkpoint-lookahead",
    "state-sync.max-checkpoint-sync-batch-size",
};

pub const SetError = error{ BadP2pOpt, UnknownP2pOpt };

fn int(comptime T: type, v: []const u8) SetError!T {
    return std.fmt.parseInt(T, v, 10) catch error.BadP2pOpt;
}

fn boolean(v: []const u8) SetError!bool {
    if (std.mem.eql(u8, v, "true")) return true;
    if (std.mem.eql(u8, v, "false")) return false;
    return error.BadP2pOpt;
}

fn prob(v: []const u8) SetError!f64 {
    const f = std.fmt.parseFloat(f64, v) catch return error.BadP2pOpt;
    if (!(f >= 0 and f <= 1)) return error.BadP2pOpt;
    return f;
}

/// `--p2p-opt KEY=VALUE`.
pub fn set(t: *Tuning, kv: []const u8) SetError!void {
    const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return error.BadP2pOpt;
    const k = kv[0..eq];
    const v = kv[eq + 1 ..];
    const E = std.mem.eql;
    if (E(u8, k, "discovery.interval-period-ms")) {
        t.interval_period_ms = @max(try int(u64, v), 100);
    } else if (E(u8, k, "discovery.target-concurrent-connections")) {
        t.target_concurrent_connections = @intCast(@min(try int(u64, v), 255));
    } else if (E(u8, k, "discovery.peers-to-query")) {
        t.peers_to_query = try int(u64, v);
    } else if (E(u8, k, "discovery.get-known-peers-rate-limit")) {
        t.get_known_peers_rate_limit = try int(u32, v);
    } else if (E(u8, k, "discovery.use-get-known-peers-v3")) {
        t.use_get_known_peers_v3 = try boolean(v);
    } else if (E(u8, k, "discovery.peer-addr-store-path")) {
        if (v.len == 0) return error.BadP2pOpt;
        t.peer_addr_store_path = v;
    } else if (E(u8, k, "discovery.peer-failure-cooldown-ms")) {
        t.peer_failure_cooldown_ms = try int(u64, v);
    } else if (E(u8, k, "discovery.min-peers-for-disconnect")) {
        t.min_peers_for_disconnect = try int(u32, v);
    } else if (E(u8, k, "discovery.access-type")) {
        // handled by --p2p-access (fullnode_yaml maps it there); accepted here too
        _ = parseAccess(v) orelse return error.BadP2pOpt;
    } else if (E(u8, k, "discovery.allowlisted-peers")) {
        t.allowlisted_peers = v;
    } else if (E(u8, k, "peer-address-overrides")) {
        t.peer_address_overrides = v;
    } else if (E(u8, k, "state-sync.push-checkpoint-summary-rate-limit")) {
        t.push_checkpoint_summary_rate_limit = try int(u32, v);
    } else if (E(u8, k, "state-sync.get-checkpoint-summary-rate-limit")) {
        t.get_checkpoint_summary_rate_limit = try int(u32, v);
    } else if (E(u8, k, "state-sync.get-checkpoint-contents-rate-limit")) {
        t.get_checkpoint_contents_rate_limit = try int(u32, v);
    } else if (E(u8, k, "state-sync.get-checkpoint-contents-inflight-limit")) {
        t.get_checkpoint_contents_inflight_limit = try int(u32, v);
    } else if (E(u8, k, "state-sync.get-checkpoint-contents-per-checkpoint-limit")) {
        t.get_checkpoint_contents_per_checkpoint_limit = try int(u32, v);
    } else if (E(u8, k, "state-sync.max-checkpoint-summary-size")) {
        t.max_checkpoint_summary_size = try int(usize, v);
    } else if (E(u8, k, "state-sync.use-get-checkpoint-contents-v2")) {
        t.use_get_checkpoint_contents_v2 = try boolean(v);
    } else if (E(u8, k, "state-sync.peer-scoring-window-ms")) {
        t.peer_scoring_window_ms = try int(u64, v);
    } else if (E(u8, k, "state-sync.exploration-probability")) {
        t.exploration_probability = try prob(v);
    } else if (E(u8, k, "state-sync.peer-failure-rate")) {
        t.peer_failure_rate = try prob(v);
    } else if (E(u8, k, "state-sync.peer-disconnect-threshold-ms")) {
        t.peer_disconnect_threshold_ms = try int(u64, v);
    } else if (E(u8, k, "excessive-message-size")) {
        t.excessive_message_size = try int(usize, v);
    } else {
        for (no_effect) |x| if (E(u8, k, x)) return;
        return error.UnknownP2pOpt;
    }
}

/// True when `key` (a `p2p-config` path) is one `set` takes, with effect or without.
pub fn known(key: []const u8) bool {
    var t: Tuning = .{};
    var buf: [256]u8 = undefined;
    const kv = std.fmt.bufPrint(&buf, "{s}=0", .{key}) catch return false;
    set(&t, kv) catch |e| return e != error.UnknownP2pOpt;
    return true;
}

pub fn parseAccess(v: []const u8) ?net.discovery.AccessType {
    const E = std.ascii.eqlIgnoreCase;
    if (E(v, "public")) return .public;
    if (E(v, "private")) return .private;
    if (E(v, "trusted")) return .trusted;
    return null;
}

pub fn parsePeerId(text: []const u8) ?[32]u8 {
    const t = std.mem.trim(u8, text, " ");
    if (t.len != 64) return null;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, t) catch return null;
    return out;
}

pub const Allowed = struct { id: [32]u8, address: ?[]const u8 };

/// `PEERID[@MULTIADDR],...`. Entries without a valid peer id are skipped (counted in `bad`).
pub fn parseAllowlist(a: std.mem.Allocator, text: []const u8, bad: *usize) ![]const Allowed {
    var out: std.ArrayList(Allowed) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, ',');
    while (it.next()) |item| {
        const at = std.mem.indexOfScalar(u8, item, '@');
        const id = parsePeerId(if (at) |x| item[0..x] else item) orelse {
            bad.* += 1;
            continue;
        };
        try out.append(a, .{ .id = id, .address = if (at) |x| item[x + 1 ..] else null });
    }
    return out.items;
}

pub const Override = struct { id: [32]u8, addresses: []const []const u8 };

/// `PEERID@MULTIADDR[|MULTIADDR],...`.
pub fn parseOverrides(a: std.mem.Allocator, text: []const u8, bad: *usize) ![]const Override {
    var out: std.ArrayList(Override) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, ',');
    while (it.next()) |item| {
        const at = std.mem.indexOfScalar(u8, item, '@') orelse {
            bad.* += 1;
            continue;
        };
        const id = parsePeerId(item[0..at]) orelse {
            bad.* += 1;
            continue;
        };
        var addrs: std.ArrayList([]const u8) = .empty;
        var ai = std.mem.tokenizeScalar(u8, item[at + 1 ..], '|');
        while (ai.next()) |x| if (net.discovery.parseAddress(x) != null) try addrs.append(a, x);
        if (addrs.items.len == 0) {
            bad.* += 1;
            continue;
        }
        try out.append(a, .{ .id = id, .addresses = addrs.items });
    }
    return out.items;
}

test "p2p_config: keys, defaults, lists" {
    var t: Tuning = .{};
    try set(&t, "discovery.peer-failure-cooldown-ms=60000");
    try set(&t, "state-sync.use-get-checkpoint-contents-v2=false");
    try set(&t, "state-sync.exploration-probability=0.25");
    try set(&t, "state-sync.timeout-ms=5000"); // accepted, no effect
    try std.testing.expectEqual(@as(?u64, 60000), t.peer_failure_cooldown_ms);
    try std.testing.expect(!t.use_get_checkpoint_contents_v2);
    try std.testing.expectEqual(@as(?f64, 0.25), t.exploration_probability);
    try std.testing.expectError(error.UnknownP2pOpt, set(&t, "discovery.bogus=1"));
    try std.testing.expectError(error.BadP2pOpt, set(&t, "state-sync.peer-failure-rate=2"));
    try std.testing.expect(known("state-sync.max-checkpoint-lookahead"));
    try std.testing.expect(known("discovery.use-get-known-peers-v3"));
    try std.testing.expect(!known("discovery.bogus"));
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    const id = "d32b55bdf1737ec415df8c88b3bf91e194b59ee3127e3f38ea46fd88ba2e7849";
    var bad: usize = 0;
    const al = try parseAllowlist(ar.allocator(), id ++ "@/dns/a.example/udp/8084,nothex," ++ id, &bad);
    try std.testing.expectEqual(@as(usize, 2), al.len);
    try std.testing.expectEqualStrings("/dns/a.example/udp/8084", al[0].address.?);
    try std.testing.expect(al[1].address == null);
    try std.testing.expectEqual(@as(usize, 1), bad);
    const ov = try parseOverrides(ar.allocator(), id ++ "@/ip4/1.2.3.4/udp/8084|/dns/b.example/udp/1," ++ id ++ "@/ip4/1.2.3.4/tcp/1", &bad);
    try std.testing.expectEqual(@as(usize, 1), ov.len);
    try std.testing.expectEqual(@as(usize, 2), ov[0].addresses.len);
    try std.testing.expectEqual(@as(usize, 2), bad);
}
