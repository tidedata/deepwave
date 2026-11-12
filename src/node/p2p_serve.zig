//! p2p_serve: deepwave answers state sync and discovery for any anemo peer exactly as sui-node 1.83.1
//! does (sui-network state_sync/server.rs, discovery/server.rs, mainnet-v1.83.1). One `Server`
//! per node: its `handler()` serves the inbound listener (src/net/server.zig) and the requests
//! peers send on p2p.zig's outbound connections. It needs only the store; a `P2p` (when the node
//! follows over p2p) adds the genesis summary, the push path and the discovered peers.
//!
//! Routes (StateSync, then Discovery):
//! - PushCheckpointSummary: handed to `P2p.onPush` when there is one; else nothing is stored.
//!   Always `()`.
//! - GetCheckpointSummary: Latest (highest committed), BySequenceNumber (0 = genesis), ByDigest
//!   (the store's checkpoint digest index). Whatever the store holds, else None.
//! - GetCheckpointAvailability: highest committed certified summary + `lowest_available`, the
//!   checkpoint store's floor (node.zig `lowest`; sui-node state_sync/server.rs reads the
//!   checkpoint store alone). GetServiceInfo reports the higher of it and the object floor.
//! - GetCheckpointContents (V1 form; V2 contents are converted like `into_v1`) and
//!   GetCheckpointContentsV2 for every checkpoint in [lowest, highest], found by contents digest
//!   through `ContentsIndex`. Over 128 MiB serialized: 500 (the client pages instead).
//! - GetCheckpointContentsDigests(seq) and GetCheckpointTransactions{seq, start, end} (16 MiB
//!   budget, at least one item; a bad range is 400).
//! - GetKnownPeersV2/V3: our signed NodeInfo (V3: VersionedNodeInfo::V2, as sui-node signs it)
//!   and up to 200 known peers (Public; Trusted only to trusted callers). V3 also takes the
//!   caller's own info into the book.
//! - Anything else (Randomness/SendSignatures on a full node included): 404.
//!
//! Limits are sui-node's defaults: a 256 KiB request body limit on StateSync routes (a larger
//! request gets an empty 200), and the optional per-peer rate limits (Block), per-peer inflight
//! limit and per-checkpoint inflight limit on GetCheckpointContents (V1 only, like sui-node's
//! `add_layer_for_get_checkpoint_contents`), all off unless configured.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const hash = @import("hash");
const store = @import("store");
const net = @import("net");
const p2p_mod = @import("p2p.zig");
const snapshot_mod = @import("snapshot.zig");
const Atomic = std.atomic.Value;

const anemo = net.anemo;
const ss = net.state_sync;
const discovery = net.discovery;
const Status = net.wire.Status;
const Ed25519 = std.crypto.sign.Ed25519;
const Allocator = std.mem.Allocator;

// ------------------------------------------------------------------ routes and counters

pub const RouteId = enum(u8) {
    push_checkpoint_summary,
    get_checkpoint_summary,
    get_checkpoint_availability,
    get_checkpoint_contents,
    get_checkpoint_contents_v2,
    get_checkpoint_contents_digests,
    get_checkpoint_transactions,
    get_known_peers_v2,
    get_known_peers_v3,
    other,

    pub fn of(route: []const u8) RouteId {
        const R = ss.Route;
        const table = .{
            .{ R.push_checkpoint_summary, RouteId.push_checkpoint_summary },
            .{ R.get_checkpoint_summary, RouteId.get_checkpoint_summary },
            .{ R.get_checkpoint_availability, RouteId.get_checkpoint_availability },
            .{ R.get_checkpoint_contents, RouteId.get_checkpoint_contents },
            .{ R.get_checkpoint_contents_v2, RouteId.get_checkpoint_contents_v2 },
            .{ R.get_checkpoint_contents_digests, RouteId.get_checkpoint_contents_digests },
            .{ R.get_checkpoint_transactions, RouteId.get_checkpoint_transactions },
            .{ R.get_known_peers_v2, RouteId.get_known_peers_v2 },
            .{ R.get_known_peers_v3, RouteId.get_known_peers_v3 },
        };
        inline for (table) |e| if (std.mem.eql(u8, route, e[0])) return e[1];
        return .other;
    }

    /// StateSync routes carry sui-node's request size limit (`SizeLimitLayer`).
    pub fn isStateSync(r: RouteId) bool {
        return @intFromEnum(r) <= @intFromEnum(RouteId.get_checkpoint_transactions);
    }

    /// Metric label: the anemo method name.
    pub fn label(r: RouteId) []const u8 {
        return switch (r) {
            .push_checkpoint_summary => "PushCheckpointSummary",
            .get_checkpoint_summary => "GetCheckpointSummary",
            .get_checkpoint_availability => "GetCheckpointAvailability",
            .get_checkpoint_contents => "GetCheckpointContents",
            .get_checkpoint_contents_v2 => "GetCheckpointContentsV2",
            .get_checkpoint_contents_digests => "GetCheckpointContentsDigests",
            .get_checkpoint_transactions => "GetCheckpointTransactions",
            .get_known_peers_v2 => "GetKnownPeersV2",
            .get_known_peers_v3 => "GetKnownPeersV3",
            .other => "other",
        };
    }
};

const n_routes = std.meta.fieldNames(RouteId).len;

pub const RouteStats = struct {
    requests: Atomic(u64) = .init(0),
    bytes_in: Atomic(u64) = .init(0),
    bytes_out: Atomic(u64) = .init(0),
    /// Answered with a non-200 status.
    errors: Atomic(u64) = .init(0),
    /// Refused by a limit (request size, inflight: 429).
    limited: Atomic(u64) = .init(0),
    /// Answered Some (summaries, contents, transactions).
    found: Atomic(u64) = .init(0),
};

/// sui-node 1.83.1 defaults (sui-config p2p.rs StateSyncConfig / DiscoveryConfig).
pub const Limits = struct {
    /// `max_checkpoint_summary_size` (256 KiB): StateSync request bodies above it get an empty 200.
    max_request_size: usize = 256 * 1024,
    /// Per-peer requests/s (Block mode); null = no limit (the default).
    push_checkpoint_summary_rate: ?u32 = null,
    get_checkpoint_summary_rate: ?u32 = null,
    get_checkpoint_contents_rate: ?u32 = null,
    get_known_peers_rate: ?u32 = null,
    /// Per-peer inflight GetCheckpointContents (429 when over); null = no limit.
    get_checkpoint_contents_inflight: ?u32 = null,
    /// Inflight GetCheckpointContents per contents digest across all peers (429); null = none.
    get_checkpoint_contents_per_checkpoint: ?u32 = null,
    /// MAX_FULL_CHECKPOINT_CONTENTS_RESPONSE_SIZE and CHECKPOINT_TRANSACTIONS_RESPONSE_BUDGET.
    max_full_contents: usize = 128 << 20,
    transactions_budget: usize = 16 << 20,
};

/// MAX_PEERS_TO_SEND.
pub const max_peers_to_send = 200;
const one_day_ms: u64 = 24 * 3600 * 1000;

// ------------------------------------------------------------------ contents index

/// Contents digest -> checkpoint sequence number over the retained window, so GetCheckpointContents
/// answers for every checkpoint in [lowest, highest] (sui-node's
/// `checkpoint_sequence_by_contents_digest`). Open addressing, linear probing; one u64 per slot:
/// a 32-bit fingerprint of the digest (its first 4 bytes, which also place the slot) and the
/// sequence number minus `base` plus one (0 = empty). A hit is a candidate only: the caller checks
/// the stored summary's `content_digest`. Sized to the window (2 slots per entry after a rebuild,
/// rebuilt at 80% load, dropping entries below the floor), so 10 to 16 MB per million retained
/// checkpoints. Filled with each committed checkpoint and by a background scan of the retained
/// range at startup (newest first).
pub const ContentsIndex = struct {
    gpa: Allocator,
    io: Io,
    lock: Io.Mutex = .init,
    slots: []u64 = &.{},
    count: usize = 0,
    base: u64 = 0,
    /// Below this, entries are dropped at the next rebuild (the store's floor).
    floor: u64 = 0,

    pub fn deinit(x: *ContentsIndex) void {
        x.gpa.free(x.slots);
        x.slots = &.{};
    }

    fn fp(digest: *const [32]u8) u32 {
        return std.mem.readInt(u32, digest[0..4], .little);
    }

    fn home(f: u32, cap: usize) usize {
        return @intCast((@as(u64, f) * cap) >> 32);
    }

    fn put(slots: []u64, f: u32, off: u32) bool {
        var i = home(f, slots.len);
        const want = (@as(u64, f) << 32) | off;
        while (true) {
            const e = slots[i];
            if (e == 0) {
                slots[i] = want;
                return true;
            }
            if (e == want) return false;
            i += 1;
            if (i == slots.len) i = 0;
        }
    }

    /// Rebuilds with room for `extra` more entries (lock held).
    fn grow(x: *ContentsIndex, extra: usize, new_base: u64) Allocator.Error!void {
        var live: usize = 0;
        for (x.slots) |e| if (e != 0 and x.base + (e & 0xffff_ffff) - 1 >= x.floor) {
            live += 1;
        };
        const cap = @max(1024, (live + extra) * 2);
        const fresh = try x.gpa.alloc(u64, cap);
        @memset(fresh, 0);
        var n: usize = 0;
        for (x.slots) |e| {
            if (e == 0) continue;
            const seq = x.base + (e & 0xffff_ffff) - 1;
            if (seq < x.floor or seq < new_base or seq - new_base >= std.math.maxInt(u32)) continue;
            if (put(fresh, @intCast(e >> 32), @intCast(seq - new_base + 1))) n += 1;
        }
        x.gpa.free(x.slots);
        x.slots = fresh;
        x.count = n;
        x.base = new_base;
    }

    /// Sizes the table for about `n` entries starting at `base` (startup).
    pub fn reserve(x: *ContentsIndex, n: usize, base: u64) Allocator.Error!void {
        x.lock.lockUncancelable(x.io);
        defer x.lock.unlock(x.io);
        x.floor = base;
        try x.grow(n, base);
    }

    pub fn setFloor(x: *ContentsIndex, floor: u64) void {
        x.lock.lockUncancelable(x.io);
        defer x.lock.unlock(x.io);
        x.floor = floor;
    }

    pub const Item = struct { digest: [32]u8, seq: u64 };

    pub fn insertMany(x: *ContentsIndex, items: []const Item) Allocator.Error!void {
        x.lock.lockUncancelable(x.io);
        defer x.lock.unlock(x.io);
        for (items) |it| {
            if (it.seq < x.floor) continue;
            const below = it.seq < x.base;
            if (below or it.seq - x.base >= std.math.maxInt(u32) - 1 or (x.count + 1) * 5 > x.slots.len * 4)
                try x.grow(items.len, if (below or x.slots.len == 0) it.seq -| (1 << 20) else @max(x.base, x.floor));
            if (it.seq < x.base) continue;
            if (put(x.slots, fp(&it.digest), @intCast(it.seq - x.base + 1))) x.count += 1;
        }
    }

    pub fn insert(x: *ContentsIndex, digest: *const [32]u8, seq: u64) Allocator.Error!void {
        return x.insertMany(&.{.{ .digest = digest.*, .seq = seq }});
    }

    /// Candidate sequence numbers for `digest` (at most `out.len`).
    pub fn lookup(x: *ContentsIndex, digest: *const [32]u8, out: []u64) usize {
        x.lock.lockUncancelable(x.io);
        defer x.lock.unlock(x.io);
        if (x.slots.len == 0) return 0;
        const f = fp(digest);
        var i = home(f, x.slots.len);
        var n: usize = 0;
        var probes: usize = 0;
        while (probes < x.slots.len) : (probes += 1) {
            const e = x.slots[i];
            if (e == 0) break;
            if (@as(u32, @intCast(e >> 32)) == f and n < out.len) {
                out[n] = x.base + (e & 0xffff_ffff) - 1;
                n += 1;
            }
            i += 1;
            if (i == x.slots.len) i = 0;
        }
        return n;
    }

    pub fn bytes(x: *ContentsIndex) usize {
        x.lock.lockUncancelable(x.io);
        defer x.lock.unlock(x.io);
        return x.slots.len * @sizeOf(u64);
    }
};

/// `content_digest` of a stored `CertifiedCheckpointSummary` (epoch, sequence_number,
/// network_total_transactions, then the digest with its length byte).
pub fn contentDigestOf(cert: []const u8) ?*const [32]u8 {
    if (cert.len < 57 or cert[24] != 32) return null;
    return cert[25..57];
}

// ------------------------------------------------------------------ peer book

/// Signed node infos learned from discovery (V1: GetKnownPeersV2 answers; versioned: infos
/// callers push with GetKnownPeersV3), kept as signed, newest per peer, with sui-node's
/// admission rules (`update_known_peers`): timestamp at most 30 s ahead and at most a day old,
/// not ourselves, Private/Trusted only from trusted peers, a valid signature.
pub const PeerBook = struct {
    gpa: Allocator,
    io: Io,
    our_id: [32]u8,
    /// Configured peers (seeds with a pinned id): sui-node's `is_trusted_peer`.
    trusted: []const [32]u8 = &.{},
    lock: Io.Mutex = .init,
    v1: std.AutoArrayHashMapUnmanaged([32]u8, Entry) = .empty,
    v2: std.AutoArrayHashMapUnmanaged([32]u8, Entry) = .empty,
    /// Rotates the sample when more than 200 peers are known.
    turn: usize = 0,
    /// A trusted peer's versioned info was added or replaced since the last peer cache write
    /// (sui-node saves `discovery_peer_cache.yaml` when `update_known_peers_versioned` reports
    /// a trusted change).
    trusted_dirty: Atomic(bool) = .init(false),

    pub const Entry = struct { ts: u64, access: discovery.AccessType, envelope: []u8 };
    const max_entries = 10_000;

    pub fn deinit(b: *PeerBook) void {
        for (b.v1.values()) |e| b.gpa.free(e.envelope);
        for (b.v2.values()) |e| b.gpa.free(e.envelope);
        b.v1.deinit(b.gpa);
        b.v2.deinit(b.gpa);
    }

    pub fn isTrusted(b: *const PeerBook, id: *const [32]u8) bool {
        for (b.trusted) |t| if (std.mem.eql(u8, &t, id)) return true;
        return false;
    }

    /// Admits one signed info (`versioned`: a VersionedNodeInfo envelope). True when stored.
    pub fn add(b: *PeerBook, info: *const discovery.SignedInfo, versioned: bool, now_ms: u64) bool {
        if (info.timestamp_ms > now_ms + 30_000 or now_ms -| info.timestamp_ms > one_day_ms) return false;
        if (std.mem.eql(u8, &info.peer_id, &b.our_id)) return false;
        if (info.access_type != .public and !b.isTrusted(&info.peer_id)) return false;
        if (!info.verify()) return false;
        const env = b.gpa.alloc(u8, info.signed_bytes.len + 64) catch return false;
        @memcpy(env[0..info.signed_bytes.len], info.signed_bytes);
        @memcpy(env[info.signed_bytes.len..], &info.signature);
        b.lock.lockUncancelable(b.io);
        defer b.lock.unlock(b.io);
        const map = if (versioned) &b.v2 else &b.v1;
        if (map.getPtr(info.peer_id)) |e| {
            if (e.ts >= info.timestamp_ms) {
                b.gpa.free(env);
                return false;
            }
            b.gpa.free(e.envelope);
            e.* = .{ .ts = info.timestamp_ms, .access = info.access_type, .envelope = env };
            if (versioned and b.isTrusted(&info.peer_id)) b.trusted_dirty.store(true, .release);
            return true;
        }
        if (map.count() >= max_entries) {
            b.gpa.free(env);
            return false;
        }
        map.put(b.gpa, info.peer_id, .{ .ts = info.timestamp_ms, .access = info.access_type, .envelope = env }) catch {
            b.gpa.free(env);
            return false;
        };
        if (versioned and b.isTrusted(&info.peer_id)) b.trusted_dirty.store(true, .release);
        return true;
    }

    /// Discovery's tick: drops infos signed more than a day ago (sui-node `handle_tick`).
    pub fn cull(b: *PeerBook, now_ms: u64) usize {
        b.lock.lockUncancelable(b.io);
        defer b.lock.unlock(b.io);
        var gone: usize = 0;
        inline for (.{ &b.v1, &b.v2 }) |map| {
            var i: usize = 0;
            while (i < map.count()) {
                const e = map.values()[i];
                if (now_ms -| e.ts > one_day_ms) {
                    b.gpa.free(e.envelope);
                    map.swapRemoveAt(i);
                    gone += 1;
                } else i += 1;
            }
        }
        return gone;
    }

    /// The trusted peers' versioned envelopes (what sui-node writes to its peer cache), copied
    /// with `a`.
    pub fn trustedV2(b: *PeerBook, a: Allocator) ![]const []const u8 {
        b.lock.lockUncancelable(b.io);
        defer b.lock.unlock(b.io);
        var out: std.ArrayList([]const u8) = .empty;
        for (b.v2.keys(), b.v2.values()) |*k, e| if (b.isTrusted(k)) try out.append(a, try a.dupe(u8, e.envelope));
        return out.items;
    }

    /// A GetKnownPeers answer: the responder's own info and its peers.
    pub fn addKnownPeers(b: *PeerBook, kp: *const discovery.KnownPeers, versioned: bool, now_ms: u64) usize {
        var n: usize = @intFromBool(b.add(&kp.own, versioned, now_ms));
        for (kp.peers) |*p| n += @intFromBool(b.add(p, versioned, now_ms));
        return n;
    }

    /// Appends up to 200 shareable envelopes as a BCS vector (uleb count + envelopes). With more
    /// than 200 known, peers we are connected to come first (sui-node: "prefer returning peers
    /// that we are connected to as they are known-good"), the rest rotate.
    fn appendShared(b: *PeerBook, a: Allocator, out: *std.ArrayList(u8), versioned: bool, requester_trusted: bool, now_ms: u64, connected: []const [32]u8) !void {
        b.lock.lockUncancelable(b.io);
        defer b.lock.unlock(b.io);
        const map = if (versioned) &b.v2 else &b.v1;
        const vals = map.values();
        var picked: std.ArrayList(usize) = .empty;
        const shareable = struct {
            fn f(e: Entry, now: u64, trusted_caller: bool) bool {
                if (now -| e.ts > one_day_ms) return false;
                return switch (e.access) {
                    .public => true,
                    .private => false,
                    .trusted => trusted_caller,
                };
            }
        }.f;
        if (vals.len > max_peers_to_send) {
            for (connected) |*id| {
                if (picked.items.len >= max_peers_to_send) break;
                const i = map.getIndex(id.*) orelse continue;
                if (std.mem.indexOfScalar(usize, picked.items, i) != null) continue;
                if (shareable(vals[i], now_ms, requester_trusted)) try picked.append(a, i);
            }
        }
        const start = if (vals.len > max_peers_to_send) b.turn % vals.len else 0;
        if (vals.len > max_peers_to_send) b.turn +%= max_peers_to_send;
        const n_connected = picked.items.len;
        for (0..vals.len) |k| {
            if (picked.items.len >= max_peers_to_send) break;
            const i = (start + k) % vals.len;
            if (n_connected > 0 and std.mem.indexOfScalar(usize, picked.items[0..n_connected], i) != null) continue;
            if (shareable(vals[i], now_ms, requester_trusted)) try picked.append(a, i);
        }
        try putUleb(out, a, picked.items.len);
        for (picked.items) |i| try out.appendSlice(a, vals[i].envelope);
    }

    pub fn counts(b: *PeerBook) struct { v1: usize, v2: usize } {
        b.lock.lockUncancelable(b.io);
        defer b.lock.unlock(b.io);
        return .{ .v1 = b.v1.count(), .v2 = b.v2.count() };
    }
};

// ------------------------------------------------------------------ own node info

/// `--p2p-external ADDR:PORT` (or a multiaddr starting with '/') as sui-node's Multiaddr string:
/// `/ip4/A.B.C.D/udp/P`, `/ip6/.../udp/P`, `/dns/NAME/udp/P`.
pub fn externalMultiaddr(a: Allocator, text: []const u8) ![]const u8 {
    if (text.len > 0 and text[0] == '/') {
        if (discovery.parseAddress(text) == null) return error.BadAddress;
        return a.dupe(u8, text);
    }
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.BadAddress;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.BadAddress;
    var host = text[0..colon];
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        host = host[1 .. host.len - 1];
        _ = Io.net.IpAddress.parseIp6(host, port) catch return error.BadAddress;
        return std.fmt.allocPrint(a, "/ip6/{s}/udp/{d}", .{ host, port });
    }
    if (Io.net.IpAddress.parseIp4(host, port)) |_| return std.fmt.allocPrint(a, "/ip4/{s}/udp/{d}", .{ host, port }) else |_| {}
    if (std.mem.indexOfScalar(u8, host, ':') != null) {
        _ = Io.net.IpAddress.parseIp6(host, port) catch return error.BadAddress;
        return std.fmt.allocPrint(a, "/ip6/{s}/udp/{d}", .{ host, port });
    }
    if (host.len == 0) return error.BadAddress;
    return std.fmt.allocPrint(a, "/dns/{s}/udp/{d}", .{ host, port });
}

/// BCS of `NodeInfo { peer_id, addresses, timestamp_ms, access_type }` (`versioned` false) or
/// `VersionedNodeInfo::V2(NodeInfoV2 { addresses: {P2p(peer_id): addresses}, timestamp_ms,
/// access_type })` (true), the forms sui-node signs for GetKnownPeersV2 and V3.
pub fn encodeNodeInfo(a: Allocator, out: *std.ArrayList(u8), peer_id: *const [32]u8, addresses: []const []const u8, ts_ms: u64, access: discovery.AccessType, versioned: bool) !void {
    if (versioned) {
        try out.append(a, 1); // VersionedNodeInfo::V2
        try out.append(a, 1); // one endpoint
        try out.append(a, 0); // EndpointId::P2p
    }
    try out.appendSlice(a, peer_id);
    try putUleb(out, a, addresses.len);
    for (addresses) |s| {
        try putUleb(out, a, s.len);
        try out.appendSlice(a, s);
    }
    var ts: [8]u8 = undefined;
    std.mem.writeInt(u64, &ts, ts_ms, .little);
    try out.appendSlice(a, &ts);
    try out.append(a, @intFromEnum(access));
}

/// The envelope (`data ++ signature`) of our signed info.
pub fn signedNodeInfo(a: Allocator, key: *const Ed25519.KeyPair, addresses: []const []const u8, ts_ms: u64, access: discovery.AccessType, versioned: bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    const id = key.public_key.toBytes();
    try encodeNodeInfo(a, &out, &id, addresses, ts_ms, access, versioned);
    const sig = try key.sign(out.items, null);
    try out.appendSlice(a, &sig.toBytes());
    return out.toOwnedSlice(a);
}

// ------------------------------------------------------------------ server

pub const Server = struct {
    gpa: Allocator,
    io: Io,
    st: *store.Store,
    key: Ed25519.KeyPair,
    /// The follower, when the node runs one: genesis summary, push path, discovered peers.
    p2p: ?*p2p_mod.P2p = null,
    /// The node's `lowest` (the checkpoint store's lowest available checkpoint); when null the
    /// server computes it from the store like node.zig `refreshLowest`.
    lowest: ?*const Atomic(u64) = null,
    restored_epoch: ?u64 = null,
    /// Genesis certified summary when neither the store nor the P2p holds it.
    genesis: ?[]const u8 = null,
    /// Advertised address (Multiaddr string), and the access type we advertise.
    external: ?[]const u8 = null,
    access: discovery.AccessType = .private,
    limits: Limits = .{},
    /// Configured peers' ids: trusted callers see Trusted peers (seeds with a pinned id).
    trusted: []const [32]u8 = &.{},
    stats: [n_routes]RouteStats = @splat(.{}),
    /// `<db-path>/discovery_peer_cache.yaml` (or `discovery.peer-addr-store-path`): trusted peers'
    /// signed infos, read at start, written when one changes (at most every 5 s) and at stop.
    peer_cache_path: ?[]const u8 = null,
    peer_cache_saved_ms: u64 = 0,
    peer_cache_loaded: usize = 0,
    /// The inbound listener, when there is one (its connected peers are shared first). Read
    /// under `listener_mu`; `detachListener` before the listener stops.
    listener: ?*net.server.Listener = null,
    listener_mu: Io.Mutex = .init,
    book_culled_ms: u64 = 0,
    index: ContentsIndex = undefined,
    book: PeerBook = undefined,
    stopping: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    /// Highest committed checkpoint indexed (the tip side), and the next one the startup scan
    /// indexes going down (maxInt: scan done).
    indexed_hi: Atomic(u64) = .init(std.math.maxInt(u64)),
    scan_next: Atomic(u64) = .init(std.math.maxInt(u64)),
    scan_done: Atomic(bool) = .init(false),
    catchup_lock: Io.Mutex = .init,
    /// Cached own infos (re-signed every 5 s, sui-node refreshes them on each discovery tick).
    own_lock: Io.Mutex = .init,
    own_ts: u64 = 0,
    own_v1: []u8 = &.{},
    own_v2: []u8 = &.{},
    /// Cached lowest when `lowest` is null (refreshed each second).
    low_cache: Atomic(u64) = .init(0),
    low_at: Atomic(u64) = .init(0),
    /// Recently served summaries (contents digest -> seq): a client fetches the summary first.
    recent_lock: Io.Mutex = .init,
    recent: [64]ContentsIndex.Item = @splat(.{ .digest = @splat(0), .seq = std.math.maxInt(u64) }),
    recent_at: usize = 0,
    limiter: Limiter = .{},

    pub fn init(s: *Server) !void {
        s.index = .{ .gpa = s.gpa, .io = s.io };
        s.book = .{ .gpa = s.gpa, .io = s.io, .our_id = s.key.public_key.toBytes(), .trusted = s.trusted };
        s.limiter = .{};
        var snap = s.st.snapshot();
        defer snap.release();
        if (snap.highestCommitted()) |hi| {
            const lo = s.lowestNow(&snap) orelse hi;
            // Sized for the window (3 epochs is about 1M checkpoints); it grows past 8M if needed.
            try s.index.reserve(@intCast(@min(hi - @min(lo, hi) + 1, 8 << 20) + 4096), lo);
            s.indexed_hi.store(hi, .release);
            s.scan_next.store(hi, .release);
        } else {
            s.scan_done.store(true, .release);
        }
    }

    /// Starts the indexer thread (catch-up to the tip, startup scan of the retained range), after
    /// reading the peer cache.
    pub fn start(s: *Server) !void {
        s.loadPeerCache();
        s.thread = try std.Thread.spawn(.{ .stack_size = 1 << 20 }, indexLoop, .{s});
    }

    pub fn stop(s: *Server) void {
        const was = s.stopping.swap(true, .acq_rel);
        if (s.thread) |t| t.join();
        s.thread = null;
        // sui-node writes the cache once more when discovery ends.
        if (!was) s.savePeerCache();
    }

    // ---------------------------------------------------------------- peer cache

    /// Reads the peer cache: entries that verify and pass sui-node's admission rules (fresh,
    /// restricted only when trusted) go into the book and the follower's dial pool.
    pub fn loadPeerCache(s: *Server) void {
        const path = s.peer_cache_path orelse return;
        var ar: std.heap.ArenaAllocator = .init(s.gpa);
        defer ar.deinit();
        const a = ar.allocator();
        const text = Io.Dir.cwd().readFileAlloc(s.io, path, a, .limited(16 << 20)) catch |e| {
            if (e != error.FileNotFound) std.log.warn("p2p: peer cache {s}: {s}; ignored", .{ path, @errorName(e) });
            return;
        };
        var skipped: usize = 0;
        const envs = net.peer_cache.read(a, text, &skipped) catch |e| {
            std.log.warn("p2p: peer cache {s} does not parse ({s}); ignored", .{ path, @errorName(e) });
            return;
        };
        const now = s.nowMs();
        var n: usize = 0;
        for (envs) |env| {
            const info = discovery.decodeSignedInfo(a, env, true) catch {
                skipped += 1;
                continue;
            };
            if (s.book.add(&info, true, now)) {
                n += 1;
                if (s.p2p) |p| if (p.slots.len > 0) {
                    _ = p.cands.addFresh(&info, now);
                };
            } else skipped += 1;
        }
        // Loading is not a change (sui-node saves only on a new or newer trusted info).
        s.book.trusted_dirty.store(false, .release);
        s.peer_cache_loaded = n;
        std.log.info("p2p: peer cache {s}: {d} trusted peers loaded, {d} skipped (stale, untrusted or not verifying)", .{ path, n, skipped });
    }

    /// Writes the trusted peers' infos (`<path>.yaml.tmp`, then renamed, as sui-node).
    pub fn savePeerCache(s: *Server) void {
        const path = s.peer_cache_path orelse return;
        s.book.trusted_dirty.store(false, .release);
        s.peer_cache_saved_ms = s.nowMs();
        var ar: std.heap.ArenaAllocator = .init(s.gpa);
        defer ar.deinit();
        const a = ar.allocator();
        const envs = s.book.trustedV2(a) catch return;
        var aw: Io.Writer.Allocating = .init(a);
        net.peer_cache.write(a, &aw.writer, envs) catch return;
        const tmp = std.fmt.allocPrint(a, "{s}.tmp", .{path}) catch return;
        const dir = Io.Dir.cwd();
        dir.writeFile(s.io, .{ .sub_path = tmp, .data = aw.written() }) catch |e| {
            std.log.warn("p2p: peer cache {s}: {s}", .{ tmp, @errorName(e) });
            return;
        };
        dir.rename(tmp, dir, path, s.io) catch |e| std.log.warn("p2p: peer cache {s}: {s}", .{ path, @errorName(e) });
    }

    /// Peers we hold a connection to (outbound sessions and inbound listener peers), copied
    /// with `a`.
    fn connectedIds(s: *Server, a: Allocator) []const [32]u8 {
        var out: std.ArrayList([32]u8) = .empty;
        if (s.p2p) |p| if (p.slots.len > 0) {
            const n = p.n_peers.load(.acquire);
            for (0..n) |i| if (p.up[i].load(.monotonic)) if (p.specs[i].id) |id| out.append(a, id) catch {};
        };
        s.listener_mu.lockUncancelable(s.io);
        defer s.listener_mu.unlock(s.io);
        if (s.listener) |l| if (l.inboundPeers(a)) |ps| {
            for (ps) |ip| out.append(a, ip.id) catch {};
        } else |_| {};
        return out.items;
    }

    pub fn attachListener(s: *Server, l: ?*net.server.Listener) void {
        s.listener_mu.lockUncancelable(s.io);
        defer s.listener_mu.unlock(s.io);
        s.listener = l;
    }

    /// Before the listener stops (and is freed): no request reads its peer list after this.
    pub fn detachListener(s: *Server) void {
        s.attachListener(null);
    }

    pub fn deinit(s: *Server) void {
        s.stop();
        s.index.deinit();
        s.book.deinit();
        s.gpa.free(s.own_v1);
        s.gpa.free(s.own_v2);
        s.limiter.deinit(s.gpa);
    }

    pub fn handler(s: *Server) anemo.Handler {
        return .{ .ctx = @ptrCast(s), .serve = serveFn };
    }

    fn nowMs(s: *const Server) u64 {
        return @intCast(@divTrunc(Io.Clock.real.now(s.io).toNanoseconds(), std.time.ns_per_ms));
    }

    fn nowNs(s: *const Server) u64 {
        return @intCast(Io.Clock.awake.now(s.io).toNanoseconds());
    }

    fn lowestNow(s: *Server, snap: *const store.Snapshot) ?u64 {
        if (s.lowest) |l| return l.load(.acquire);
        const now = s.nowNs();
        const at = s.low_at.load(.acquire);
        if (at != 0 and now -| at < std.time.ns_per_s) return s.low_cache.load(.acquire);
        const l = snapshot_mod.lowestAvailable(snap, s.restored_epoch) orelse return null;
        s.low_cache.store(l, .release);
        s.low_at.store(now, .release);
        return l;
    }

    // ---------------------------------------------------------------- indexing

    fn indexLoop(s: *Server) void {
        var items: std.ArrayList(ContentsIndex.Item) = .empty;
        defer items.deinit(s.gpa);
        while (!s.stopping.load(.acquire)) {
            const now = s.nowMs();
            if (now -| s.book_culled_ms >= 5_000) {
                s.book_culled_ms = now;
                _ = s.book.cull(now);
                if (s.book.trusted_dirty.load(.acquire) and now -| s.peer_cache_saved_ms >= 5_000) s.savePeerCache();
            }
            s.catchUp(4096);
            if (!s.scan_done.load(.acquire)) {
                s.scanStep(&items, 4096) catch {};
                continue;
            }
            s.io.sleep(.fromMilliseconds(50), .awake) catch {};
        }
    }

    /// Indexes committed checkpoints above `indexed_hi` (at most `max`).
    pub fn catchUp(s: *Server, max: usize) void {
        var snap = s.st.snapshot();
        defer snap.release();
        const hi = snap.highestCommitted() orelse return;
        if (s.indexed_hi.load(.acquire) != std.math.maxInt(u64) and s.indexed_hi.load(.acquire) >= hi) return;
        s.catchup_lock.lockUncancelable(s.io);
        defer s.catchup_lock.unlock(s.io);
        var from = s.indexed_hi.load(.acquire);
        if (from == std.math.maxInt(u64)) {
            // Empty at init: index from the floor up (the scan is not needed).
            from = (s.lowestNow(&snap) orelse 0) -| 1;
            if (s.lowestNow(&snap) orelse 0 == 0) from = std.math.maxInt(u64);
        }
        var buf: [256]ContentsIndex.Item = undefined;
        var n: usize = 0;
        var seq: u64 = from +% 1;
        var done: usize = 0;
        while (seq <= hi and done < max) : ({
            seq += 1;
            done += 1;
        }) {
            if (snap.checkpoint(seq)) |rec| if (contentDigestOf(rec.summary_cert)) |d| {
                buf[n] = .{ .digest = d.*, .seq = seq };
                n += 1;
                if (n == buf.len) {
                    s.index.insertMany(&buf) catch {};
                    n = 0;
                }
            };
        }
        if (n > 0) s.index.insertMany(buf[0..n]) catch {};
        s.indexed_hi.store(seq -% 1, .release);
        if (s.lowestNow(&snap)) |l| s.index.setFloor(l);
    }

    /// Indexes up to `max` checkpoints of the startup range, newest first.
    fn scanStep(s: *Server, items: *std.ArrayList(ContentsIndex.Item), max: usize) !void {
        var snap = s.st.snapshot();
        defer snap.release();
        const floor = s.lowestNow(&snap) orelse 0;
        var seq = s.scan_next.load(.acquire);
        items.clearRetainingCapacity();
        var k: usize = 0;
        while (k < max and seq != std.math.maxInt(u64) and seq >= floor) : (k += 1) {
            const rec = snap.checkpoint(seq) orelse {
                // Retained checkpoints are contiguous up to the tip: the first gap is the bottom.
                seq = std.math.maxInt(u64);
                break;
            };
            if (contentDigestOf(rec.summary_cert)) |d| try items.append(s.gpa, .{ .digest = d.*, .seq = seq });
            seq = if (seq == 0) std.math.maxInt(u64) else seq - 1;
        }
        try s.index.insertMany(items.items);
        s.scan_next.store(seq, .release);
        if (seq == std.math.maxInt(u64) or seq < floor) s.scan_done.store(true, .release);
    }

    fn noteRecent(s: *Server, cert: []const u8) void {
        const d = contentDigestOf(cert) orelse return;
        if (cert.len < 16) return;
        const seq = std.mem.readInt(u64, cert[8..16], .little);
        s.recent_lock.lockUncancelable(s.io);
        defer s.recent_lock.unlock(s.io);
        s.recent[s.recent_at % s.recent.len] = .{ .digest = d.*, .seq = seq };
        s.recent_at += 1;
    }

    /// Sequence number of the committed checkpoint whose contents digest is `digest`, checked
    /// against the stored summary.
    pub fn seqByContents(s: *Server, snap: *const store.Snapshot, digest: *const [32]u8) ?store.CheckpointRecord {
        var cand: [8]u64 = undefined;
        var n: usize = 0;
        {
            s.recent_lock.lockUncancelable(s.io);
            defer s.recent_lock.unlock(s.io);
            for (s.recent) |r| if (r.seq != std.math.maxInt(u64) and std.mem.eql(u8, &r.digest, digest) and n < 2) {
                cand[n] = r.seq;
                n += 1;
            };
        }
        n += s.index.lookup(digest, cand[n..]);
        for (cand[0..n]) |seq| {
            const rec = snap.checkpoint(seq) orelse continue;
            const d = contentDigestOf(rec.summary_cert) orelse continue;
            if (std.mem.eql(u8, d, digest)) return rec;
        }
        return null;
    }

    fn genesisCert(s: *Server, snap: *const store.Snapshot) ?[]const u8 {
        if (snap.checkpoint(0)) |rec| return rec.summary_cert;
        if (s.p2p) |p| {
            p.lock.lockUncancelable(p.io);
            defer p.lock.unlock(p.io);
            if (p.genesis) |g| return g;
        }
        return s.genesis;
    }

    // ---------------------------------------------------------------- serving

    fn serveFn(ctx: *anyopaque, a: Allocator, from: *const anemo.PeerId, route: []const u8, body: []const u8) anemo.Reply {
        const s: *Server = @ptrCast(@alignCast(ctx));
        return s.serve(a, from, route, body);
    }

    /// sui_inbound_* are counted by the transport around this call (anemo.zig, net/server.zig;
    /// core.p2p_metrics).
    pub fn serve(s: *Server, a: Allocator, from: *const anemo.PeerId, route: []const u8, body: []const u8) anemo.Reply {
        return s.serveInner(a, from, route, body);
    }

    fn serveInner(s: *Server, a: Allocator, from: *const anemo.PeerId, route: []const u8, body: []const u8) anemo.Reply {
        const r = RouteId.of(route);
        const st = &s.stats[@intFromEnum(r)];
        _ = st.requests.fetchAdd(1, .monotonic);
        _ = st.bytes_in.fetchAdd(body.len, .monotonic);
        const reply: anemo.Reply = blk: {
            if (r.isStateSync() and body.len > s.limits.max_request_size) {
                _ = st.limited.fetchAdd(1, .monotonic);
                break :blk .{ .status = .success, .body = "" };
            }
            break :blk s.answer(a, r, from, body) catch |e| switch (e) {
                error.OutOfMemory => .{ .status = .internal_server_error },
                error.TooManyRequests => blk2: {
                    _ = st.limited.fetchAdd(1, .monotonic);
                    break :blk2 .{ .status = .too_many_requests };
                },
                error.TooLarge => .{ .status = .internal_server_error },
                error.Internal => .{ .status = .internal_server_error },
                else => .{ .status = .bad_request },
            };
        };
        if (reply.status != .success) _ = st.errors.fetchAdd(1, .monotonic);
        _ = st.bytes_out.fetchAdd(reply.body.len, .monotonic);
        return reply;
    }

    const AnswerError = error{ OutOfMemory, TooManyRequests, TooLarge, Internal, BadRequest } || ss.DecodeError || bcs.Error;

    fn ok(a: Allocator, raw: []const u8) AnswerError!anemo.Reply {
        return .{ .status = .success, .body = try net.snappy.compressFrame(a, raw) };
    }

    fn found(s: *Server, r: RouteId) void {
        _ = s.stats[@intFromEnum(r)].found.fetchAdd(1, .monotonic);
    }

    fn answer(s: *Server, a: Allocator, r: RouteId, from: *const anemo.PeerId, body: []const u8) AnswerError!anemo.Reply {
        switch (r) {
            .other => return .{ .status = .not_found },
            .push_checkpoint_summary => {
                if (s.limits.push_checkpoint_summary_rate) |q| s.limiter.wait(s, from, r, q);
                const cert = try decodeRequest(a, body);
                if (s.p2p) |p| p.onPush(from, cert);
                return ok(a, &.{});
            },
            .get_checkpoint_summary => {
                if (s.limits.get_checkpoint_summary_rate) |q| s.limiter.wait(s, from, r, q);
                const req = try decodeRequest(a, body);
                const id = try parseSummaryRequest(req);
                var snap = s.st.snapshot();
                defer snap.release();
                const cert: ?[]const u8 = switch (id) {
                    .latest => blk: {
                        const hi = snap.highestCommitted() orelse return error.Internal;
                        break :blk (snap.checkpoint(hi) orelse return error.Internal).summary_cert;
                    },
                    .seq => |q| if (q == 0) s.genesisCert(&snap) else if (snap.checkpoint(q)) |rec| rec.summary_cert else null,
                    .digest => |d| blk: {
                        const q = snap.checkpointByDigest(&d) orelse break :blk null;
                        break :blk if (snap.checkpoint(q)) |rec| rec.summary_cert else null;
                    },
                };
                if (cert) |c| {
                    s.found(r);
                    s.noteRecent(c);
                }
                return ok(a, try option(a, cert));
            },
            .get_checkpoint_availability => {
                var snap = s.st.snapshot();
                defer snap.release();
                const hi = snap.highestCommitted() orelse return error.Internal;
                const rec = snap.checkpoint(hi) orelse return error.Internal;
                const lo = s.lowestNow(&snap) orelse hi;
                const b = try a.alloc(u8, rec.summary_cert.len + 8);
                @memcpy(b[0..rec.summary_cert.len], rec.summary_cert);
                std.mem.writeInt(u64, b[rec.summary_cert.len..][0..8], lo, .little);
                return ok(a, b);
            },
            .get_checkpoint_contents, .get_checkpoint_contents_v2 => {
                const v1 = r == .get_checkpoint_contents;
                const req = try decodeRequest(a, body);
                if (req.len != 33 or req[0] != 32) return error.BadRequest;
                const digest = req[1..33];
                var held: Held = .{};
                defer held.release(s);
                if (v1) {
                    if (s.limits.get_checkpoint_contents_rate) |q| s.limiter.wait(s, from, r, q);
                    if (s.limits.get_checkpoint_contents_inflight) |m| try held.take(s, peerKey(from), m, .peer);
                    if (s.limits.get_checkpoint_contents_per_checkpoint) |m| try held.take(s, peerKey(digest), m, .checkpoint);
                }
                const full = try s.fullContents(a, digest, v1);
                if (full) |f| {
                    if (f.len > s.limits.max_full_contents) return error.TooLarge;
                    s.found(r);
                }
                return ok(a, try option(a, full));
            },
            .get_checkpoint_contents_digests => {
                const req = try decodeRequest(a, body);
                if (req.len != 8) return error.BadRequest;
                const seq = std.mem.readInt(u64, req[0..8], .little);
                var snap = s.st.snapshot();
                defer snap.release();
                const contents: ?[]const u8 = if (s.retained(&snap, seq)) if (snap.checkpoint(seq)) |rec| rec.contents else null else null;
                if (contents != null) s.found(r);
                return ok(a, try option(a, contents));
            },
            .get_checkpoint_transactions => {
                const req = try decodeRequest(a, body);
                if (req.len != 24) return error.BadRequest;
                const seq = std.mem.readInt(u64, req[0..8], .little);
                const first = std.mem.readInt(u64, req[8..16], .little);
                const end = std.mem.readInt(u64, req[16..24], .little);
                var snap = s.st.snapshot();
                defer snap.release();
                if (!s.retained(&snap, seq)) return ok(a, &.{0});
                const rec = snap.checkpoint(seq) orelse return ok(a, &.{0});
                const out = try transactionsPage(a, &snap, rec.contents, first, end, s.limits.transactions_budget);
                if (out) |o| {
                    s.found(r);
                    return ok(a, o);
                }
                return ok(a, &.{0});
            },
            .get_known_peers_v2, .get_known_peers_v3 => {
                if (s.limits.get_known_peers_rate) |q| s.limiter.wait(s, from, r, q);
                const v3 = r == .get_known_peers_v3;
                const now = s.nowMs();
                if (v3) {
                    // GetKnownPeersRequestV3 { own_info }: the caller's info goes into the book.
                    const req = try decodeRequest(a, body);
                    const info = discovery.decodeSignedInfo(a, req, true) catch return error.BadRequest;
                    _ = s.book.add(&info, true, now);
                }
                var out: std.ArrayList(u8) = .empty;
                try out.appendSlice(a, s.ownInfo(a, v3, now) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Internal);
                try s.book.appendShared(a, &out, v3, s.book.isTrusted(from), now, s.connectedIds(a));
                return ok(a, out.items);
            },
        }
    }

    /// True when `seq` is in [lowest, highest] (sui-node prunes contents below its floor).
    fn retained(s: *Server, snap: *const store.Snapshot, seq: u64) bool {
        const hi = snap.highestCommitted() orelse return false;
        if (seq > hi) return false;
        return seq >= (s.lowestNow(snap) orelse 0);
    }

    /// `VersionedFullCheckpointContents` (or the V1 `FullCheckpointContents`) of the retained
    /// checkpoint with this contents digest.
    pub fn fullContents(s: *Server, a: Allocator, digest: *const [32]u8, v1: bool) AnswerError!?[]const u8 {
        // A checkpoint committed since the indexer's last pass: index the tip first.
        s.catchUp(64);
        var snap = s.st.snapshot();
        defer snap.release();
        const rec = s.seqByContents(&snap, digest) orelse return null;
        if (!s.retained(&snap, rec.seq)) return null;
        return fullFromStore(a, &snap, rec.contents, v1) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    }

    /// Our signed info (`versioned`: the VersionedNodeInfo::V2 envelope GetKnownPeersV3 sends).
    pub fn ownInfo(s: *Server, a: Allocator, versioned: bool, now: u64) ![]const u8 {
        s.own_lock.lockUncancelable(s.io);
        defer s.own_lock.unlock(s.io);
        if (s.own_v1.len == 0 or now -| s.own_ts >= 5_000) {
            const addrs: []const []const u8 = if (s.external) |e| &.{e} else &.{};
            const v1b = try signedNodeInfo(s.gpa, &s.key, addrs, now, s.access, false);
            errdefer s.gpa.free(v1b);
            const v2b = try signedNodeInfo(s.gpa, &s.key, addrs, now, s.access, true);
            s.gpa.free(s.own_v1);
            s.gpa.free(s.own_v2);
            s.own_v1 = v1b;
            s.own_v2 = v2b;
            s.own_ts = now;
        }
        return a.dupe(u8, if (versioned) s.own_v2 else s.own_v1);
    }

    /// Prometheus lines: `zui_p2p_inbound_{requests,bytes_in,bytes_out,errors,limited,found}{route}`
    /// plus the contents index and peer book sizes.
    pub fn render(s: *Server, w: *Io.Writer) !void {
        inline for (comptime std.meta.fieldNames(RouteStats)) |name| {
            try w.print("# TYPE zui_p2p_inbound_{s} counter\n", .{name});
            for (0..n_routes) |i| {
                const r: RouteId = @enumFromInt(i);
                try w.print("zui_p2p_inbound_{s}{{route=\"{s}\"}} {d}\n", .{ name, r.label(), @field(s.stats[i], name).load(.monotonic) });
            }
        }
        try w.print("# TYPE zui_p2p_contents_index_entries gauge\nzui_p2p_contents_index_entries {d}\n", .{s.index.count});
        try w.print("# TYPE zui_p2p_contents_index_bytes gauge\nzui_p2p_contents_index_bytes {d}\n", .{s.index.bytes()});
        try w.print("# TYPE zui_p2p_contents_index_scan_done gauge\nzui_p2p_contents_index_scan_done {d}\n", .{@intFromBool(s.scan_done.load(.acquire))});
        const c = s.book.counts();
        try w.print("# TYPE zui_p2p_known_peers gauge\nzui_p2p_known_peers{{v=\"1\"}} {d}\nzui_p2p_known_peers{{v=\"2\"}} {d}\n", .{ c.v1, c.v2 });
    }
};

// ------------------------------------------------------------------ limits

fn peerKey(id: *const [32]u8) u64 {
    return std.mem.readInt(u64, id[0..8], .little);
}

/// Per-peer GCRA rate limiter (governor `Quota::per_second(q)`, burst q) in Block mode, and the
/// inflight counters (per peer and per checkpoint) of GetCheckpointContents.
const Limiter = struct {
    lock: Io.Mutex = .init,
    /// (peer key ^ route) -> theoretical arrival time (ns).
    tat: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    inflight_peer: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    inflight_cp: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    gpa: ?Allocator = null,

    fn deinit(l: *Limiter, gpa: Allocator) void {
        l.tat.deinit(gpa);
        l.inflight_peer.deinit(gpa);
        l.inflight_cp.deinit(gpa);
    }

    fn wait(l: *Limiter, s: *Server, from: *const [32]u8, r: RouteId, q: u32) void {
        if (q == 0) return;
        const t: u64 = std.time.ns_per_s / q;
        const tau: u64 = t * (q - 1);
        const now = s.nowNs();
        const key = peerKey(from) ^ (@as(u64, @intFromEnum(r)) << 56);
        const delay = blk: {
            l.lock.lockUncancelable(s.io);
            defer l.lock.unlock(s.io);
            if (l.tat.count() > 100_000) l.tat.clearRetainingCapacity();
            const gop = l.tat.getOrPut(s.gpa, key) catch break :blk 0;
            const tat = if (gop.found_existing) @max(gop.value_ptr.*, now) else now;
            gop.value_ptr.* = tat + t;
            break :blk (tat -| now) -| tau;
        };
        if (delay > 0) s.io.sleep(.fromNanoseconds(@intCast(delay)), .awake) catch {};
    }
};

const Held = struct {
    peer: ?u64 = null,
    cp: ?u64 = null,

    fn take(h: *Held, s: *Server, key: u64, max: u32, which: enum { peer, checkpoint }) error{ TooManyRequests, OutOfMemory }!void {
        const l = &s.limiter;
        l.lock.lockUncancelable(s.io);
        defer l.lock.unlock(s.io);
        const map = if (which == .peer) &l.inflight_peer else &l.inflight_cp;
        const gop = try map.getOrPut(s.gpa, key);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        if (gop.value_ptr.* >= max) {
            if (gop.value_ptr.* == 0) _ = map.remove(key);
            return error.TooManyRequests;
        }
        gop.value_ptr.* += 1;
        if (which == .peer) h.peer = key else h.cp = key;
    }

    fn release(h: *Held, s: *Server) void {
        if (h.peer == null and h.cp == null) return;
        const l = &s.limiter;
        l.lock.lockUncancelable(s.io);
        defer l.lock.unlock(s.io);
        if (h.peer) |k| dec(&l.inflight_peer, k);
        if (h.cp) |k| dec(&l.inflight_cp, k);
    }

    fn dec(map: *std.AutoHashMapUnmanaged(u64, u32), k: u64) void {
        const v = map.getPtr(k) orelse return;
        v.* -|= 1;
        if (v.* == 0) _ = map.remove(k);
    }
};

// ------------------------------------------------------------------ codec

/// Request bodies are small (summaries, digests); decompression is capped well above them.
fn decodeRequest(a: Allocator, body: []const u8) ss.DecodeError![]u8 {
    return net.snappy.decompressFrame(a, body, 4 << 20);
}

/// `GetCheckpointSummaryRequest` (Latest | ByDigest(Digest) | BySequenceNumber(u64)), strict BCS.
pub fn parseSummaryRequest(req: []const u8) error{BadRequest}!ss.CheckpointId {
    if (req.len == 0) return error.BadRequest;
    return switch (req[0]) {
        0 => if (req.len == 1) .latest else error.BadRequest,
        1 => if (req.len == 34 and req[1] == 32) .{ .digest = req[2..34].* } else error.BadRequest,
        2 => if (req.len == 9) .{ .seq = std.mem.readInt(u64, req[1..9], .little) } else error.BadRequest,
        else => error.BadRequest,
    };
}

/// BCS `Option<T>` around the raw BCS of T.
pub fn option(a: Allocator, payload: ?[]const u8) Allocator.Error![]const u8 {
    const v = payload orelse return a.dupe(u8, &.{0});
    const b = try a.alloc(u8, v.len + 1);
    b[0] = 1;
    @memcpy(b[1..], v);
    return b;
}

fn putUleb(out: *std.ArrayList(u8), a: Allocator, v: u64) !void {
    var x = v;
    while (true) {
        const b: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x == 0) return out.append(a, b);
        try out.append(a, b | 0x80);
    }
}

/// The stored `CheckpointContents` (V1 or V2) as full contents: `VersionedFullCheckpointContents`
/// (`v1` false) or `FullCheckpointContents` (`v1` true: V2 alias versions dropped, like
/// sui-node's `into_v1`). Null when a transaction is missing (pruned or a restored checkpoint).
pub fn fullFromStore(a: Allocator, snap: *const store.Snapshot, contents: []const u8, v1: bool) !?[]const u8 {
    var r = bcs.Reader.init(contents);
    const tag = try r.uleb32();
    if (tag > 1) return null;
    const n = try r.length();
    if (n > contents.len) return null;
    var txs: std.ArrayList(u8) = .empty;
    var sigs: std.ArrayList(u8) = .empty;
    try putUleb(&txs, a, n);
    try putUleb(&sigs, a, n);
    for (0..n) |_| {
        const d = try r.bytes(66);
        if (d[0] != 32 or d[33] != 32) return null;
        const t = snap.transaction(d[1..33]) orelse return null;
        if (!std.mem.eql(u8, t.effects_digest, d[34..66])) return null;
        try txs.appendSlice(a, t.tx);
        try txs.appendSlice(a, t.effects);
        if (tag == 1) {
            const s0 = r.pos();
            const k = try r.length();
            if (v1) try putUleb(&sigs, a, k);
            for (0..k) |_| {
                const g0 = r.pos();
                _ = try r.bytes(try r.length());
                const g1 = r.pos();
                if (v1) try sigs.appendSlice(a, contents[g0..g1]);
                switch (try r.int(u8)) {
                    0 => {},
                    1 => _ = try r.int(u64),
                    else => return error.InvalidValue,
                }
            }
            if (!v1) try sigs.appendSlice(a, contents[s0..r.pos()]);
        }
    }
    var out: std.ArrayList(u8) = .empty;
    if (!v1) try out.append(a, @intCast(tag));
    try out.appendSlice(a, txs.items);
    if (tag == 0) {
        try out.appendSlice(a, contents[r.pos()..]); // user_signatures as stored
    } else {
        if (r.remaining() != 0) return error.TrailingBytes;
        try out.appendSlice(a, sigs.items);
    }
    return out.items;
}

/// Number of transactions and the (tx, effects) digests of a stored `CheckpointContents`.
fn contentsDigests(a: Allocator, contents: []const u8) !?[]const [66]u8 {
    var r = bcs.Reader.init(contents);
    const tag = try r.uleb32();
    if (tag > 1) return null;
    const n = try r.length();
    if (n > contents.len) return null;
    const out = try a.alloc([66]u8, n);
    for (out) |*o| {
        o.* = (try r.bytes(66))[0..66].*;
        if (tag == 1) {
            const k = try r.length();
            for (0..k) |_| {
                _ = try r.bytes(try r.length());
                if (try r.int(u8) == 1) _ = try r.int(u64);
            }
        }
    }
    return out;
}

/// `Option<Vec<ExecutionData>>` for transactions [start, end) of a checkpoint: items are added
/// while they fit `budget` (always at least one). BadRequest for an empty or out-of-range span;
/// null (None) when a transaction is missing.
pub fn transactionsPage(a: Allocator, snap: *const store.Snapshot, contents: []const u8, start: u64, end: u64, budget: usize) !?[]const u8 {
    const ds = (contentsDigests(a, contents) catch return null) orelse return null;
    if (start >= end or end > ds.len) return error.BadRequest;
    var body: std.ArrayList(u8) = .empty;
    var size: usize = 0;
    var count: usize = 0;
    for (ds[@intCast(start)..@intCast(end)]) |*d| {
        if (d[0] != 32 or d[33] != 32) return null;
        const t = snap.transaction(d[1..33]) orelse return null;
        if (!std.mem.eql(u8, t.effects_digest, d[34..66])) return null;
        const item = t.tx.len + t.effects.len;
        if (count > 0 and size + item > budget) break;
        size += item;
        count += 1;
        try body.appendSlice(a, t.tx);
        try body.appendSlice(a, t.effects);
    }
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, 1);
    try putUleb(&out, a, count);
    try out.appendSlice(a, body.items);
    return out.items;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn corpusFile(gpa: Allocator, rel: []const u8) ![]u8 {
    const c = std.c.getenv("ZUI_CORPUS") orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&pb, "{s}/{s}", .{ std.mem.span(c), rel });
    return Io.Dir.cwd().readFileAlloc(testing.io, path, gpa, .limited(64 << 20)) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
}

fn unhex(a: Allocator, h: []const u8) ![]u8 {
    const out = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

test "p2p_serve: request decoding and response encoding against sync-rpc-codec vectors" {
    const gpa = testing.allocator;
    const text = try corpusFile(gpa, "vectors/sync-rpc-codec/sync.jsonl");
    defer gpa.free(text);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const Vec = struct { id: []const u8, kind: []const u8, bcs_hex: []const u8, snappy_hex: []const u8 };
    var checked: usize = 0;
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        const v = try std.json.parseFromSliceLeaky(Vec, a, line, .{ .ignore_unknown_fields = true });
        const raw = try unhex(a, v.bcs_hex);
        const snap = try unhex(a, v.snappy_hex);
        const dec = try decodeRequest(a, snap);
        try testing.expectEqualSlices(u8, raw, dec);
        if (std.mem.startsWith(u8, v.id, "req/summary/")) {
            const id = try parseSummaryRequest(raw);
            if (std.mem.eql(u8, v.id, "req/summary/latest")) try testing.expect(id == .latest);
            if (std.mem.startsWith(u8, v.id, "req/summary/seq/")) try testing.expectEqual(try std.fmt.parseInt(u64, v.id["req/summary/seq/".len..], 10), id.seq);
            if (std.mem.startsWith(u8, v.id, "req/summary/digest/")) try testing.expect(id == .digest);
            checked += 1;
        } else if (std.mem.startsWith(u8, v.id, "resp/summary/")) {
            // Our Option encoding of the payload, compressed as one write, equals sui-node's bytes.
            const payload: ?[]const u8 = if (std.mem.endsWith(u8, v.id, "/none")) null else raw[1..];
            const enc = try option(a, payload);
            try testing.expectEqualSlices(u8, raw, enc);
            try testing.expectEqualSlices(u8, snap, try net.snappy.compressFrame(a, enc));
            if (payload) |p| {
                const seq = try std.fmt.parseInt(u64, v.id["resp/summary/".len..], 10);
                try testing.expectEqual(seq, std.mem.readInt(u64, p[8..16], .little));
                try testing.expect(contentDigestOf(p) != null);
            }
            checked += 1;
        } else if (std.mem.startsWith(u8, v.id, "req/GetCheckpointContents")) {
            try testing.expect(raw.len == 33 and raw[0] == 32);
            checked += 1;
        } else if (std.mem.startsWith(u8, v.id, "req/contents_digests/")) {
            try testing.expectEqual(try std.fmt.parseInt(u64, v.id["req/contents_digests/".len..], 10), std.mem.readInt(u64, raw[0..8], .little));
            checked += 1;
        } else if (std.mem.startsWith(u8, v.id, "req/transactions/")) {
            try testing.expectEqual(@as(usize, 24), raw.len);
            try testing.expectEqual(try std.fmt.parseInt(u64, v.id["req/transactions/".len..], 10), std.mem.readInt(u64, raw[0..8], .little));
            checked += 1;
        }
    }
    try testing.expect(checked > 600);
}

test "p2p_serve: own NodeInfo encodes like sui-node's (discovery vectors) and verifies" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    // Signed by us: decodes with the client decoder and verifies, both forms.
    const kp = Ed25519.KeyPair.generateDeterministic(@splat(7)) catch unreachable;
    const addr = try externalMultiaddr(a, "203.0.113.8:8084");
    try testing.expectEqualStrings("/ip4/203.0.113.8/udp/8084", addr);
    try testing.expectEqualStrings("/dns/fn.example.org/udp/8084", try externalMultiaddr(a, "fn.example.org:8084"));
    try testing.expectEqualStrings("/ip6/::1/udp/8084", try externalMultiaddr(a, "[::1]:8084"));
    for ([_]bool{ false, true }) |versioned| {
        const env = try signedNodeInfo(a, &kp, &.{addr}, 1_700_000_000_000, .public, versioned);
        const info = try discovery.decodeSignedInfo(a, env, versioned);
        try testing.expect(info.verify());
        try testing.expectEqualSlices(u8, &kp.public_key.toBytes(), &info.peer_id);
        try testing.expectEqualStrings(addr, info.addresses[0]);
        try testing.expectEqual(discovery.AccessType.public, info.access_type);
    }
    // sui-node's own info (corpus): our encoder rebuilds its signed bytes from the fields.
    const text = try corpusFile(gpa, "vectors/sync-rpc-codec/discovery.jsonl");
    defer gpa.free(text);
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    var n: usize = 0;
    while (it.next()) |line| {
        const V = struct { id: []const u8, kind: []const u8, bcs_hex: []const u8 };
        const v = try std.json.parseFromSliceLeaky(V, a, line, .{ .ignore_unknown_fields = true });
        if (!std.mem.eql(u8, v.kind, "GetKnownPeersResponseV2")) continue;
        const kpr = discovery.decodeKnownPeers(a, try unhex(a, v.bcs_hex), false) catch continue;
        for ([_]discovery.SignedInfo{kpr.own} ++ .{}) |info| {
            var out: std.ArrayList(u8) = .empty;
            try encodeNodeInfo(a, &out, &info.peer_id, info.addresses, info.timestamp_ms, info.access_type, false);
            try testing.expectEqualSlices(u8, info.signed_bytes, out.items);
            n += 1;
        }
        for (kpr.peers) |info| {
            var out: std.ArrayList(u8) = .empty;
            try encodeNodeInfo(a, &out, &info.peer_id, info.addresses, info.timestamp_ms, info.access_type, false);
            try testing.expectEqualSlices(u8, info.signed_bytes, out.items);
        }
    }
    try testing.expect(n > 0);
}

test "p2p_serve: contents index finds every entry, drops entries below the floor on rebuild" {
    var x: ContentsIndex = .{ .gpa = testing.allocator, .io = testing.io };
    defer x.deinit();
    try x.reserve(10, 1000);
    var items: [5000]ContentsIndex.Item = undefined;
    for (&items, 0..) |*it, i| it.* = .{ .digest = hash.blake2b256(&.{std.mem.asBytes(&i)}), .seq = 1000 + i };
    try x.insertMany(&items);
    var cand: [8]u64 = undefined;
    for (items) |it| {
        const n = x.lookup(&it.digest, &cand);
        try testing.expect(std.mem.indexOfScalar(u64, cand[0..n], it.seq) != null);
    }
    try testing.expect(x.slots.len * 8 <= 5000 * 8 * 2 * 2);
    x.setFloor(4000);
    var more: [5000]ContentsIndex.Item = undefined;
    for (&more, 0..) |*it, i| it.* = .{ .digest = hash.blake2b256(&.{ "m", std.mem.asBytes(&i) }), .seq = 6000 + i };
    try x.insertMany(&more);
    try testing.expect(x.count < 10_000); // the rebuild dropped seqs below 4000
    for (more) |it| {
        const n = x.lookup(&it.digest, &cand);
        try testing.expect(std.mem.indexOfScalar(u64, cand[0..n], it.seq) != null);
    }
}

fn fakeCert(a: Allocator, seq: u64, content: *const [32]u8) ![]u8 {
    const c = try a.alloc(u8, 120);
    @memset(c, 0xab);
    std.mem.writeInt(u64, c[0..8], 3, .little);
    std.mem.writeInt(u64, c[8..16], seq, .little);
    std.mem.writeInt(u64, c[16..24], seq * 2, .little);
    c[24] = 32;
    @memcpy(c[25..57], content);
    return c;
}

test "p2p_serve: every route against a small store (old contents, digest lookups, paging, limits)" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const n0 = try tmp.dir.realPath(testing.io, &pb);
    var cfg: store.Config = .{ .dir = pb[0..n0], .max_live_objects = 1 << 10, .segment_reserve = 1 << 20 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // Checkpoints 10..14 (V1 contents, 2 transactions each), 15 (V2 contents with alias versions).
    var cds: [6][32]u8 = undefined;
    var cps: [6][32]u8 = undefined;
    var contents_of: [6][]u8 = undefined;
    for (0..6) |k| {
        const seq: u64 = 10 + k;
        var c: std.ArrayList(u8) = .empty;
        const v2 = k == 5;
        try c.append(a, @intFromBool(v2));
        try c.append(a, 2);
        const b = try h.store.begin(seq, 3);
        for (0..2) |j| {
            const txd = hash.blake2b256(&.{ "tx", std.mem.asBytes(&seq), std.mem.asBytes(&j) });
            const efd = hash.blake2b256(&.{ "fx", std.mem.asBytes(&seq), std.mem.asBytes(&j) });
            try c.append(a, 32);
            try c.appendSlice(a, &txd);
            try c.append(a, 32);
            try c.appendSlice(a, &efd);
            if (v2) {
                // one signature (3 bytes) with alias version Some(9), and one with None
                try c.appendSlice(a, &.{ 2, 3, 0xa, 0xb, 0xc, 1, 9, 0, 0, 0, 0, 0, 0, 0, 1, 0xd, 0 });
            }
            try b.transaction(&txd, &efd, try std.fmt.allocPrint(a, "TX{d}.{d}", .{ seq, j }), try std.fmt.allocPrint(a, "EFFECTS{d}.{d}", .{ seq, j }), null);
        }
        if (!v2) try c.appendSlice(a, &.{ 2, 0, 1, 2, 0x5, 0x6 }); // user_signatures: [[], [[5,6]]]
        contents_of[k] = c.items;
        cds[k] = hash.blake2b256(&.{ "CheckpointContents::", c.items });
        const cert = try fakeCert(a, seq, &cds[k]);
        cps[k] = hash.blake2b256(&.{ "CheckpointSummary::", cert });
        try b.checkpoint(cert, c.items);
        try b.checkpointDigest(&cps[k]);
        if (k == 0) try b.highestPruned(10); // the floor: 11
        try h.store.commit(b);
    }

    var low: Atomic(u64) = .init(11);
    var srv: Server = .{ .gpa = gpa, .io = testing.io, .st = h.store, .key = Ed25519.KeyPair.generateDeterministic(@splat(3)) catch unreachable, .lowest = &low, .genesis = "GENESIS", .external = "/ip4/1.2.3.4/udp/8084", .access = .public, .limits = .{ .transactions_budget = 20 } };
    try srv.init();
    defer srv.deinit();
    // The startup scan runs inline here (no thread).
    var items: std.ArrayList(ContentsIndex.Item) = .empty;
    defer items.deinit(gpa);
    while (!srv.scan_done.load(.acquire)) try srv.scanStep(&items, 2);

    const from: anemo.PeerId = @splat(0x55);
    const R = ss.Route;
    const call = struct {
        fn f(s: *Server, ar: Allocator, peer: *const anemo.PeerId, route: []const u8, raw: []const u8) !struct { status: Status, bcs: []const u8 } {
            const rep = s.serve(ar, peer, route, try net.snappy.compressFrame(ar, raw));
            if (rep.status != .success or rep.body.len == 0) return .{ .status = rep.status, .bcs = rep.body };
            return .{ .status = rep.status, .bcs = try ss.decodeBody(ar, rep.body) };
        }
    }.f;

    // Availability: highest 15 and the node's floor.
    const av = try call(&srv, a, &from, R.get_checkpoint_availability, &.{});
    const sp = try ss.splitAvailability(av.bcs);
    try testing.expectEqual(@as(u64, 11), sp.lowest_available_checkpoint);
    try testing.expectEqual(@as(u64, 15), std.mem.readInt(u64, sp.highest_synced_summary[8..16], .little));

    // Summaries: latest, by number (0 = genesis), by digest, unknown digest.
    var q: [34]u8 = undefined;
    var r = try call(&srv, a, &from, R.get_checkpoint_summary, q[0..ss.bcsSummaryRequest(.latest, &q)]);
    try testing.expectEqual(@as(u64, 15), std.mem.readInt(u64, r.bcs[9..17], .little));
    r = try call(&srv, a, &from, R.get_checkpoint_summary, q[0..ss.bcsSummaryRequest(.{ .seq = 0 }, &q)]);
    try testing.expectEqualStrings("\x01GENESIS", r.bcs);
    r = try call(&srv, a, &from, R.get_checkpoint_summary, q[0..ss.bcsSummaryRequest(.{ .digest = cps[2] }, &q)]);
    try testing.expectEqual(@as(u64, 12), std.mem.readInt(u64, r.bcs[9..17], .little));
    r = try call(&srv, a, &from, R.get_checkpoint_summary, q[0..ss.bcsSummaryRequest(.{ .digest = @splat(1) }, &q)]);
    try testing.expectEqualSlices(u8, &.{0}, r.bcs);
    r = try call(&srv, a, &from, R.get_checkpoint_summary, &.{ 3, 0 });
    try testing.expectEqual(Status.bad_request, r.status);

    // Contents V2 of the oldest retained checkpoint (11), by contents digest.
    var dq: [33]u8 = undefined;
    dq[0] = 32;
    dq[1..33].* = cds[1];
    r = try call(&srv, a, &from, R.get_checkpoint_contents_v2, &dq);
    try testing.expectEqualStrings("\x01\x00\x02TX11.0EFFECTS11.0TX11.1EFFECTS11.1\x02\x00\x01\x02\x05\x06", r.bcs);
    // V1 route, same checkpoint: no version tag.
    r = try call(&srv, a, &from, R.get_checkpoint_contents, &dq);
    try testing.expectEqualStrings("\x01\x02TX11.0EFFECTS11.0TX11.1EFFECTS11.1\x02\x00\x01\x02\x05\x06", r.bcs);
    // Below the floor (10, held but pruned): None.
    dq[1..33].* = cds[0];
    r = try call(&srv, a, &from, R.get_checkpoint_contents_v2, &dq);
    try testing.expectEqualSlices(u8, &.{0}, r.bcs);
    // V2 contents: V2 keeps alias versions, the V1 route drops them (`into_v1`).
    dq[1..33].* = cds[5];
    r = try call(&srv, a, &from, R.get_checkpoint_contents_v2, &dq);
    try testing.expectEqualStrings("\x01\x01\x02TX15.0EFFECTS15.0TX15.1EFFECTS15.1\x02\x02\x03\x0a\x0b\x0c\x01\x09\x00\x00\x00\x00\x00\x00\x00\x01\x0d\x00\x02\x03\x0a\x0b\x0c\x01\x09\x00\x00\x00\x00\x00\x00\x00\x01\x0d\x00", r.bcs);
    r = try call(&srv, a, &from, R.get_checkpoint_contents, &dq);
    try testing.expectEqualStrings("\x01\x02TX15.0EFFECTS15.0TX15.1EFFECTS15.1\x02\x02\x03\x0a\x0b\x0c\x01\x0d\x02\x03\x0a\x0b\x0c\x01\x0d", r.bcs);

    // A checkpoint committed after start: found through the tip catch-up.
    {
        const seq: u64 = 16;
        const cd = hash.blake2b256(&.{"empty16"});
        const b = try h.store.begin(seq, 3);
        try b.checkpoint(try fakeCert(a, seq, &cd), &.{ 0, 0, 0 });
        try h.store.commit(b);
        dq[1..33].* = cd;
        r = try call(&srv, a, &from, R.get_checkpoint_contents_v2, &dq);
        try testing.expectEqualSlices(u8, &.{ 1, 0, 0, 0 }, r.bcs);
    }

    // Contents digests by number, and transaction pages (budget 20 bytes: one item per page).
    var sq: [8]u8 = undefined;
    std.mem.writeInt(u64, &sq, 12, .little);
    r = try call(&srv, a, &from, R.get_checkpoint_contents_digests, &sq);
    try testing.expectEqualSlices(u8, contents_of[2], r.bcs[1..]);
    std.mem.writeInt(u64, &sq, 10, .little);
    r = try call(&srv, a, &from, R.get_checkpoint_contents_digests, &sq);
    try testing.expectEqualSlices(u8, &.{0}, r.bcs);
    var tq: [24]u8 = undefined;
    std.mem.writeInt(u64, tq[0..8], 12, .little);
    std.mem.writeInt(u64, tq[8..16], 0, .little);
    std.mem.writeInt(u64, tq[16..24], 2, .little);
    r = try call(&srv, a, &from, R.get_checkpoint_transactions, &tq);
    try testing.expectEqualStrings("\x01\x01TX12.0EFFECTS12.0", r.bcs);
    std.mem.writeInt(u64, tq[8..16], 1, .little);
    r = try call(&srv, a, &from, R.get_checkpoint_transactions, &tq);
    try testing.expectEqualStrings("\x01\x01TX12.1EFFECTS12.1", r.bcs);
    std.mem.writeInt(u64, tq[16..24], 3, .little);
    r = try call(&srv, a, &from, R.get_checkpoint_transactions, &tq);
    try testing.expectEqual(Status.bad_request, r.status);

    // Push without a P2p: accepted, nothing stored.
    r = try call(&srv, a, &from, R.push_checkpoint_summary, try fakeCert(a, 99, &cds[0]));
    try testing.expectEqual(Status.success, r.status);
    try testing.expectEqual(@as(usize, 0), r.bcs.len);

    // Known peers: our signed public info with the external address; V3 takes the caller's info.
    r = try call(&srv, a, &from, R.get_known_peers_v2, &.{});
    var kpr = try discovery.decodeKnownPeers(a, r.bcs, false);
    try testing.expect(kpr.own.verify());
    try testing.expectEqualStrings("/ip4/1.2.3.4/udp/8084", kpr.own.addresses[0]);
    try testing.expectEqual(@as(usize, 0), kpr.peers.len);
    const caller = Ed25519.KeyPair.generateDeterministic(@splat(9)) catch unreachable;
    const cinfo = try signedNodeInfo(a, &caller, &.{"/ip4/5.6.7.8/udp/8084"}, srv.nowMs(), .public, true);
    r = try call(&srv, a, &from, R.get_known_peers_v3, cinfo);
    kpr = try discovery.decodeKnownPeers(a, r.bcs, true);
    try testing.expect(kpr.own.verify());
    try testing.expectEqual(@as(u8, 2), kpr.own.version);
    try testing.expectEqual(@as(usize, 1), kpr.peers.len);
    try testing.expectEqualSlices(u8, &caller.public_key.toBytes(), &kpr.peers[0].peer_id);
    // A private caller is not admitted (not trusted).
    const pkey = Ed25519.KeyPair.generateDeterministic(@splat(10)) catch unreachable;
    const pinfo = try signedNodeInfo(a, &pkey, &.{}, srv.nowMs(), .private, true);
    _ = try call(&srv, a, &from, R.get_known_peers_v3, pinfo);
    try testing.expectEqual(@as(usize, 1), srv.book.counts().v2);

    // Size limit: an oversize StateSync request gets an empty 200; unknown routes 404.
    const big = try a.alloc(u8, 300 * 1024);
    @memset(big, 0);
    const rep = srv.serve(a, &from, R.push_checkpoint_summary, big);
    try testing.expectEqual(Status.success, rep.status);
    try testing.expectEqual(@as(usize, 0), rep.body.len);
    try testing.expectEqual(Status.not_found, srv.serve(a, &from, R.send_signatures, "").status);
    try testing.expect(srv.stats[@intFromEnum(RouteId.get_checkpoint_contents_v2)].found.load(.monotonic) >= 3);

    // Per-checkpoint inflight limit on the V1 route: a held permit makes the next one 429.
    srv.limits.get_checkpoint_contents_per_checkpoint = 1;
    var held: Held = .{};
    try held.take(&srv, peerKey(&cds[1]), 1, .checkpoint);
    dq[1..33].* = cds[1];
    try testing.expectEqual(Status.too_many_requests, srv.serve(a, &from, R.get_checkpoint_contents, try net.snappy.compressFrame(a, &dq)).status);
    try testing.expectEqual(Status.success, srv.serve(a, &from, R.get_checkpoint_contents_v2, try net.snappy.compressFrame(a, &dq)).status);
    held.release(&srv);
    try testing.expectEqual(Status.success, srv.serve(a, &from, R.get_checkpoint_contents, try net.snappy.compressFrame(a, &dq)).status);
}
