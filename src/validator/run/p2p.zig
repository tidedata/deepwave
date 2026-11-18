//! The validator's one anemo endpoint, as sui-node 1.83.1 builds its p2p network
//! (`sui-node/src/lib.rs` `create_p2p_network`): a single QUIC listener on the seat's
//! `p2p-config.listen-address` that serves every route (`sui.StateSync`, `sui.Discovery`,
//! `sui.Randomness`), and one connection per peer pair that both sides use for requests.
//!
//! Routes go by service prefix to the handler registered for it (`setService`); a route no
//! service claims answers 404, as anemo's router does.
//!
//! Outbound requests (`call`) to committee peer `i` take the connection the peer opened to our
//! listener when there is one (`net.server.Listener.request`). Otherwise they go on the one
//! connection this endpoint dials to that peer and keeps (a link per peer, guarded by its
//! mutex), so randomness, state sync and pushes share it: a sui-node closes the older of two
//! connections from the same peer (anemo `ActivePeers::add_peer`, simultaneous-dial tie-break),
//! and a second dialer would keep killing the first. Each link's thread pumps the connection
//! while idle so requests the peer sends on it are answered (anemo uses one connection both
//! ways: a sui-node that we dialed sends its own requests on our connection).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const Ed25519 = std.crypto.sign.Ed25519;
const net = @import("net");
const anemo = net.anemo;
const wire = net.wire;

const log = std.log.scoped(.p2p);

/// anemo service names (the route prefix `/<service>/`).
pub const Service = enum(u8) {
    state_sync,
    discovery,
    randomness,

    pub fn prefix(s: Service) []const u8 {
        return switch (s) {
            .state_sync => "/sui.StateSync/",
            .discovery => "/sui.Discovery/",
            .randomness => "/sui.Randomness/",
        };
    }

    pub fn of(route: []const u8) ?Service {
        for ([_]Service{ .state_sync, .discovery, .randomness }) |s| {
            if (std.mem.startsWith(u8, route, s.prefix())) return s;
        }
        return null;
    }
};

pub const Peer = struct {
    /// Ed25519 network public key = anemo PeerId.
    network_pubkey: [32]u8,
    /// `host:port` or a multiaddr `/ip4/A/udp/P[/https]` (net/peer_addr.zig).
    p2p_address: []const u8,
};

pub const Options = struct {
    /// UDP address the listener binds (`host:port` or multiaddr).
    listen: []const u8,
    /// The committee (or any peers this endpoint calls by index), this node included or not.
    peers: []const Peer,
    /// Index of this node in `peers` (no link), if it is there.
    own_index: ?usize = null,
    /// Ed25519 seed of the network key.
    network_seed: *const [32]u8,
    /// Genesis checkpoint digest (ChainIdentifier): the anemo server name is
    /// `sui-<first 4 bytes, hex>`.
    chain_id: [32]u8,
    /// Request workers of the listener.
    threads: u16 = 4,
};

pub const Stats = struct {
    calls: Atomic(u64) = .init(0),
    via_inbound: Atomic(u64) = .init(0),
    via_link: Atomic(u64) = .init(0),
    dials: Atomic(u64) = .init(0),
    dial_failures: Atomic(u64) = .init(0),
    failures: Atomic(u64) = .init(0),
    served: [3]Atomic(u64) = @splat(.init(0)),
    not_found: Atomic(u64) = .init(0),
};

/// After a failed dial a peer is not dialed again for this long (a caller fails fast).
const redial_backoff_ms: u64 = 500;
/// Idle pump slice of a link (also the longest a caller waits for the link's mutex).
const pump_ms: u64 = 20;

pub const P2p = struct {
    gpa: Allocator,
    io: Io,
    seed: [32]u8,
    server_name_buf: [12]u8 = undefined,
    server_name: []const u8 = "",
    listener: *net.server.Listener = undefined,
    services: [3]Atomic(?*const anemo.Handler) = @splat(.init(null)),
    handlers: [3]anemo.Handler = undefined,
    /// Requests inside each service's handler (`clearService` waits for them).
    inflight: [3]Atomic(u32) = @splat(.init(0)),
    peers: []Peer,
    own_index: ?usize,
    links: []Link,
    stats: Stats = .{},
    stop_flag: Atomic(bool) = .init(false),

    pub fn start(gpa: Allocator, io: Io, opts: Options) !*P2p {
        const self = try gpa.create(P2p);
        errdefer gpa.destroy(self);
        const peers = try gpa.alloc(Peer, opts.peers.len);
        var copied: usize = 0;
        errdefer {
            for (peers[0..copied]) |p| gpa.free(p.p2p_address);
            gpa.free(peers);
        }
        for (opts.peers, peers) |p, *d| {
            d.* = .{ .network_pubkey = p.network_pubkey, .p2p_address = try gpa.dupe(u8, p.p2p_address) };
            copied += 1;
        }
        const links = try gpa.alloc(Link, peers.len);
        errdefer gpa.free(links);
        self.* = .{ .gpa = gpa, .io = io, .seed = opts.network_seed.*, .peers = peers, .own_index = opts.own_index, .links = links };
        self.server_name = std.fmt.bufPrint(&self.server_name_buf, "sui-{x}", .{opts.chain_id[0..4]}) catch unreachable;
        for (links, 0..) |*l, i| l.* = .{ .owner = self, .index = i, .arena = .init(gpa) };
        errdefer for (links) |*l| l.arena.deinit();
        for (links) |*l| {
            l.addr = net.peer_addr.parse(l.arena.allocator(), peers[l.index].p2p_address) catch return error.BadAddress;
        }

        var tmp = std.heap.ArenaAllocator.init(gpa);
        defer tmp.deinit();
        const la = net.peer_addr.parse(tmp.allocator(), opts.listen) catch return error.BadAddress;
        const listen = net.peer_addr.resolve(io, la) catch return error.BadAddress;
        const key = try Ed25519.KeyPair.generateDeterministic(self.seed);
        self.listener = try net.server.Listener.start(gpa, io, .{
            .listen = listen,
            .key = key,
            .server_name = self.server_name,
            .handler = self.handler(),
            .threads = opts.threads,
        });
        errdefer self.listener.stop();
        var started: usize = 0;
        errdefer {
            self.stop_flag.store(true, .release);
            for (links[0..started]) |*l| l.thread.?.join();
        }
        for (links) |*l| {
            if (opts.own_index != null and l.index == opts.own_index.?) continue;
            l.thread = try std.Thread.spawn(.{ .stack_size = 4 << 20 }, Link.loop, .{l});
            started += 1;
        }
        return self;
    }

    /// Shutdown begins: every call in flight (a dial, its handshake, a request on either side's
    /// connection) ends with Cancelled at once and new calls get null, so a thread blocked on a
    /// dead peer does not hold up the joins before `stop`.
    pub fn cancelCalls(self: *P2p) void {
        self.stop_flag.store(true, .release);
    }

    pub fn stop(self: *P2p) void {
        const gpa = self.gpa;
        self.stop_flag.store(true, .release);
        for (self.links) |*l| if (l.thread) |t| t.join();
        for (self.links) |*l| {
            l.drop();
            l.arena.deinit();
        }
        self.listener.stop();
        gpa.free(self.links);
        for (self.peers) |p| gpa.free(p.p2p_address);
        gpa.free(self.peers);
        std.crypto.secureZero(u8, &self.seed);
        gpa.destroy(self);
    }

    /// Mounts `h` for every route of service `s` (replaces an earlier one). Requests that
    /// arrive before a service is mounted get 404, as from a node that does not run it.
    pub fn setService(self: *P2p, s: Service, h: anemo.Handler) void {
        const i = @intFromEnum(s);
        self.handlers[i] = h;
        self.services[i].store(&self.handlers[i], .release);
    }

    /// Unmounts service `s` and returns once no request is inside its handler (the handler's
    /// owner may then be freed).
    pub fn clearService(self: *P2p, s: Service) void {
        const i = @intFromEnum(s);
        self.services[i].store(null, .seq_cst);
        while (self.inflight[i].load(.seq_cst) != 0) Io.sleep(self.io, .fromMilliseconds(1), .awake) catch {};
    }

    pub fn handler(self: *P2p) anemo.Handler {
        return .{ .ctx = @ptrCast(self), .serve = serveFn };
    }

    fn serveFn(ctx: *anyopaque, arena: Allocator, from: *const anemo.PeerId, route: []const u8, body: []const u8) anemo.Reply {
        const self: *P2p = @ptrCast(@alignCast(ctx));
        return self.serve(arena, from, route, body);
    }

    /// The router: the mounted service for the route's prefix, else 404.
    pub fn serve(self: *P2p, arena: Allocator, from: *const anemo.PeerId, route: []const u8, body: []const u8) anemo.Reply {
        const s = Service.of(route) orelse {
            _ = self.stats.not_found.fetchAdd(1, .monotonic);
            return .{ .status = .not_found };
        };
        const i = @intFromEnum(s);
        _ = self.inflight[i].fetchAdd(1, .seq_cst);
        defer _ = self.inflight[i].fetchSub(1, .seq_cst);
        const h = self.services[i].load(.seq_cst) orelse {
            _ = self.stats.not_found.fetchAdd(1, .monotonic);
            return .{ .status = .not_found };
        };
        _ = self.stats.served[i].fetchAdd(1, .monotonic);
        return h.serve(h.ctx, arena, from, route, body);
    }

    pub fn address(self: *const P2p) Io.net.IpAddress {
        return self.listener.address();
    }

    pub fn peerCount(self: *const P2p) usize {
        return self.peers.len;
    }

    pub fn peerId(self: *const P2p, i: usize) *const [32]u8 {
        return &self.peers[i].network_pubkey;
    }

    pub fn indexOf(self: *const P2p, id: *const anemo.PeerId) ?usize {
        for (self.peers, 0..) |p, i| if (std.mem.eql(u8, &p.network_pubkey, id)) return i;
        return null;
    }

    pub fn isSelf(self: *const P2p, i: usize) bool {
        return self.own_index != null and self.own_index.? == i;
    }

    /// The PeerIds connected to our listener (inbound), allocated with `a`.
    pub fn inbound(self: *P2p, a: Allocator) []const [32]u8 {
        const ps = self.listener.inboundPeers(a) catch return &.{};
        const out = a.alloc([32]u8, ps.len) catch return &.{};
        for (ps, out) |p, *o| o.* = p.id;
        return out;
    }

    /// One request to peer `i` with `headers`; null when the peer cannot be reached or the
    /// request failed in transport (a status answer is returned, whatever it is).
    pub fn call(self: *P2p, a: Allocator, i: usize, route: []const u8, headers: []const wire.Header, body: []const u8, timeout_ms: u64) ?anemo.Response {
        if (self.isSelf(i) or self.stop_flag.load(.acquire)) return null;
        _ = self.stats.calls.fetchAdd(1, .monotonic);
        const id = &self.peers[i].network_pubkey;
        if (self.listener.request(a, id, route, headers, body, timeout_ms, &self.stop_flag)) |r| {
            _ = self.stats.via_inbound.fetchAdd(1, .monotonic);
            return r;
        } else |e| if (e != error.NotConnected) {
            _ = self.stats.failures.fetchAdd(1, .monotonic);
            return null;
        }
        const r = self.links[i].request(a, route, headers, body, timeout_ms);
        if (r == null) _ = self.stats.failures.fetchAdd(1, .monotonic) else _ = self.stats.via_link.fetchAdd(1, .monotonic);
        return r;
    }

    fn nowMs(self: *const P2p) u64 {
        return @intCast(@divTrunc(Io.Clock.awake.now(self.io).toNanoseconds(), std.time.ns_per_ms));
    }
};

/// Our outbound connection to one peer.
const Link = struct {
    owner: *P2p,
    index: usize,
    arena: std.heap.ArenaAllocator, // addr
    addr: net.peer_addr.Addr = undefined,
    mu: Io.Mutex = .init,
    out: ?*anemo.Peer = null,
    failed_at_ms: u64 = 0,
    thread: ?std.Thread = null,

    fn drop(l: *Link) void {
        if (l.out) |p| p.deinit();
        l.out = null;
    }

    fn request(l: *Link, a: Allocator, route: []const u8, headers: []const wire.Header, body: []const u8, timeout_ms: u64) ?anemo.Response {
        const n = l.owner;
        l.mu.lockUncancelable(n.io);
        defer l.mu.unlock(n.io);
        if (l.out) |p| {
            if (p.request(a, route, headers, body, timeout_ms)) |r| return r else |e| {
                l.drop();
                // a timeout is the peer's answer being late, not a dead connection: no redial
                if (e == error.RequestTimeout or e == error.Cancelled) return null;
            }
        }
        const p = l.dial() orelse return null;
        l.out = p;
        if (p.request(a, route, headers, body, timeout_ms)) |r| return r else |_| {
            l.drop();
            return null;
        }
    }

    /// Under `mu`.
    fn dial(l: *Link) ?*anemo.Peer {
        const n = l.owner;
        const now = n.nowMs();
        if (l.failed_at_ms != 0 and now -| l.failed_at_ms < redial_backoff_ms) return null;
        _ = n.stats.dials.fetchAdd(1, .monotonic);
        const ip = net.peer_addr.resolve(n.io, l.addr) catch {
            l.failed_at_ms = now;
            return null;
        };
        const p = anemo.Peer.connect(n.gpa, n.io, ip, .{
            .server_name = n.server_name,
            .expected = n.peers[l.index].network_pubkey,
            .identity_seed = n.seed,
            .handler = n.handler(),
            .cancel = &n.stop_flag,
        }) catch |e| {
            _ = n.stats.dial_failures.fetchAdd(1, .monotonic);
            log.debug("dial peer {d} at {s}: {s}", .{ l.index, n.peers[l.index].p2p_address, @errorName(e) });
            l.failed_at_ms = n.nowMs();
            return null;
        };
        l.failed_at_ms = 0;
        return p;
    }

    /// Serves what the peer sends on our connection while no request is using it.
    fn loop(l: *Link) void {
        const n = l.owner;
        while (!n.stop_flag.load(.acquire)) {
            var pumped = false;
            if (l.mu.tryLock()) {
                defer l.mu.unlock(n.io);
                if (l.out) |p| {
                    p.pump(pump_ms) catch l.drop();
                    pumped = true;
                }
            }
            if (!pumped) Io.sleep(n.io, .fromMilliseconds(pump_ms), .awake) catch {};
        }
    }
};

// ---------------------------------------------------------------------------------------------
// tests

const testing = std.testing;

fn freePort(io: Io) !u16 {
    var a: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    const s = try Io.net.IpAddress.bind(&a, io, .{ .mode = .dgram });
    defer s.close(io);
    return s.address.ip4.port;
}

const Echo = struct {
    tag: u8,
    fn serve(ctx: *anyopaque, arena: Allocator, from: *const anemo.PeerId, route: []const u8, body: []const u8) anemo.Reply {
        const e: *Echo = @ptrCast(@alignCast(ctx));
        _ = from;
        const out = arena.alloc(u8, body.len + route.len + 1) catch return .{ .status = .internal_server_error };
        out[0] = e.tag;
        @memcpy(out[1..][0..route.len], route);
        @memcpy(out[1 + route.len ..], body);
        return .{ .status = .success, .body = out };
    }
    fn h(e: *Echo) anemo.Handler {
        return .{ .ctx = @ptrCast(e), .serve = serve };
    }
};

test "p2p: one endpoint routes by service, unmounted services 404, calls go both ways on one connection" {
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var seeds: [2][32]u8 = .{ @splat(0x11), @splat(0x22) };
    var bufs: [2][32]u8 = undefined;
    var peers: [2]Peer = undefined;
    for (0..2) |i| {
        const kp = try Ed25519.KeyPair.generateDeterministic(seeds[i]);
        peers[i] = .{ .network_pubkey = kp.public_key.toBytes(), .p2p_address = try std.fmt.bufPrint(&bufs[i], "127.0.0.1:{d}", .{try freePort(io)}) };
    }
    var eps: [2]*P2p = undefined;
    for (0..2) |i| eps[i] = try P2p.start(gpa, io, .{ .listen = peers[i].p2p_address, .peers = &peers, .own_index = i, .network_seed = &seeds[i], .chain_id = @splat(0x4c), .threads = 2 });
    defer for (eps) |e| e.stop();
    var ss: Echo = .{ .tag = 's' };
    var rn: Echo = .{ .tag = 'r' };
    eps[1].setService(.state_sync, ss.h());
    eps[0].setService(.randomness, rn.h());

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // 0 -> 1: dials (1 has no connection to 0 yet)
    const r1 = eps[0].call(a, 1, "/sui.StateSync/GetCheckpointAvailability", &.{}, "x", 5_000).?;
    try testing.expectEqual(wire.Status.success, r1.status);
    try testing.expectEqualSlices(u8, "s/sui.StateSync/GetCheckpointAvailabilityx", r1.body);
    try testing.expectEqual(@as(u64, 1), eps[0].stats.dials.load(.monotonic));
    // not mounted on 1, and an unknown service
    try testing.expectEqual(wire.Status.not_found, eps[0].call(a, 1, "/sui.Randomness/SendSignatures", &.{}, "", 5_000).?.status);
    try testing.expectEqual(wire.Status.not_found, eps[0].call(a, 1, "/zui.Other/X", &.{}, "", 5_000).?.status);
    // 1 -> 0 goes on the connection 0 opened (no second dial anywhere)
    const r2 = eps[1].call(a, 0, "/sui.Randomness/SendSignatures", &.{}, "y", 5_000).?;
    try testing.expectEqualSlices(u8, "r/sui.Randomness/SendSignaturesy", r2.body);
    try testing.expectEqual(@as(u64, 0), eps[1].stats.dials.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), eps[1].stats.via_inbound.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), eps[0].stats.dials.load(.monotonic));
    // self is never called
    try testing.expect(eps[0].call(a, 0, "/sui.StateSync/X", &.{}, "", 1_000) == null);
}
