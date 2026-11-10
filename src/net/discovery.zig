//! sui-network discovery messages (`sui.Discovery`): signed node infos, as BCS inside snappy.
//! A read-only peer asks `GetKnownPeersV2` (the request is `()`) and learns where other peers
//! are. Decoding borrows the response bytes; verification is the check sui-node runs
//! (`verify_versioned_node_info`): an Ed25519 signature by the PeerId over the BCS of the info,
//! and well-formed P2P addresses.
const std = @import("std");
const Allocator = std.mem.Allocator;
const sig = @import("sig");
const ss = @import("state_sync.zig");
const anemo = @import("anemo.zig");

pub const Error = error{ Malformed, TrailingBytes, TooMany } || Allocator.Error;

pub const AccessType = enum(u8) { public = 0, private = 1, trusted = 2 };

/// A `Multiaddr` as it is serialized: its string form.
pub const Address = []const u8;

/// One `Envelope<NodeInfo | VersionedNodeInfo, Ed25519Signature>`. `signed_bytes` is exactly the
/// BCS of the data that was signed.
pub const SignedInfo = struct {
    peer_id: [32]u8,
    /// P2P addresses (V1: `addresses`; V2: the P2P endpoint's list).
    addresses: []const Address,
    timestamp_ms: u64,
    access_type: AccessType,
    version: u8,
    signed_bytes: []const u8,
    signature: [64]u8,

    pub fn verify(s: *const SignedInfo) bool {
        if (sig.ed25519.verify(&s.peer_id, s.signed_bytes, &s.signature) != .valid) return false;
        return true;
    }
};

pub const KnownPeers = struct {
    own: SignedInfo,
    peers: []const SignedInfo,
};

const max_peers = 1 << 16;
const max_addresses = 64;

const Cur = struct {
    b: []const u8,
    p: usize = 0,
    fn byte(c: *Cur) Error!u8 {
        if (c.p >= c.b.len) return error.Malformed;
        defer c.p += 1;
        return c.b[c.p];
    }
    fn take(c: *Cur, n: usize) Error![]const u8 {
        if (n > c.b.len - c.p) return error.Malformed;
        defer c.p += n;
        return c.b[c.p..][0..n];
    }
    fn uleb(c: *Cur) Error!u64 {
        var v: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            const b = try c.byte();
            if (shift == 63 and b > 1) return error.Malformed;
            v |= @as(u64, b & 0x7f) << @intCast(shift);
            if (b & 0x80 == 0) {
                if (b == 0 and shift > 0) return error.Malformed; // non-canonical
                return v;
            }
            shift += 7;
            if (shift > 63) return error.Malformed;
        }
    }
    fn u64le(c: *Cur) Error!u64 {
        return std.mem.readInt(u64, (try c.take(8))[0..8], .little);
    }
    fn str(c: *Cur) Error![]const u8 {
        const n = try c.uleb();
        if (n > c.b.len - c.p) return error.Malformed;
        const s = try c.take(@intCast(n));
        if (!std.unicode.utf8ValidateSlice(s)) return error.Malformed;
        return s;
    }
    fn addresses(c: *Cur, arena: Allocator) Error![]const Address {
        const n = try c.uleb();
        if (n > max_addresses) return error.TooMany;
        const out = try arena.alloc(Address, @intCast(n));
        for (out) |*a| a.* = try c.str();
        return out;
    }
    fn access(c: *Cur) Error!AccessType {
        return switch (try c.byte()) {
            0 => .public,
            1 => .private,
            2 => .trusted,
            else => error.Malformed,
        };
    }
};

fn nodeInfoV1(c: *Cur, arena: Allocator) Error!SignedInfo {
    var s: SignedInfo = undefined;
    const start = c.p;
    s.peer_id = (try c.take(32))[0..32].*;
    s.addresses = try c.addresses(arena);
    s.timestamp_ms = try c.u64le();
    s.access_type = try c.access();
    s.version = 1;
    s.signed_bytes = c.b[start..c.p];
    return s;
}

fn versionedInfo(c: *Cur, arena: Allocator) Error!SignedInfo {
    const start = c.p;
    const tag = try c.uleb();
    var s: SignedInfo = undefined;
    switch (tag) {
        0 => {
            s = try nodeInfoV1(c, arena);
            s.version = 1;
        },
        1 => {
            // NodeInfoV2 { addresses: BTreeMap<EndpointId, Vec<Multiaddr>>, timestamp_ms, access_type }
            const n = try c.uleb();
            if (n > 8) return error.TooMany;
            var p2p: ?[32]u8 = null;
            s.addresses = &.{};
            for (0..@intCast(n)) |_| {
                switch (try c.uleb()) {
                    0 => {
                        const id = (try c.take(32))[0..32].*;
                        const addrs = try c.addresses(arena);
                        if (p2p == null) {
                            p2p = id;
                            s.addresses = addrs;
                        }
                    },
                    1 => {
                        _ = try c.take(32); // consensus public key (BCS: 32 raw bytes)
                        _ = try c.addresses(arena);
                    },
                    else => return error.Malformed,
                }
            }
            s.peer_id = p2p orelse return error.Malformed;
            s.timestamp_ms = try c.u64le();
            s.access_type = try c.access();
            s.version = 2;
        },
        else => return error.Malformed,
    }
    s.signed_bytes = c.b[start..c.p];
    return s;
}

fn envelope(c: *Cur, arena: Allocator, versioned: bool) Error!SignedInfo {
    var s = if (versioned) try versionedInfo(c, arena) else try nodeInfoV1(c, arena);
    s.signature = (try c.take(64))[0..64].*;
    return s;
}

/// Decodes one signed info (`Envelope<NodeInfo>`, or `Envelope<VersionedNodeInfo>` when
/// `versioned`): the `own_info` of a `GetKnownPeersRequestV3`.
pub fn decodeSignedInfo(arena: Allocator, bcs: []const u8, versioned: bool) Error!SignedInfo {
    var c: Cur = .{ .b = bcs };
    const s = try envelope(&c, arena, versioned);
    if (c.p != bcs.len) return error.TrailingBytes;
    return s;
}

/// Decodes the BCS of `GetKnownPeersResponseV2` (`versioned` false) or `V3` (true).
pub fn decodeKnownPeers(arena: Allocator, bcs: []const u8, versioned: bool) Error!KnownPeers {
    var c: Cur = .{ .b = bcs };
    const own = try envelope(&c, arena, versioned);
    const n = try c.uleb();
    if (n > max_peers) return error.TooMany;
    const peers = try arena.alloc(SignedInfo, @intCast(n));
    for (peers) |*p| p.* = try envelope(&c, arena, versioned);
    if (c.p != bcs.len) return error.TrailingBytes;
    return .{ .own = own, .peers = peers };
}

/// A dialable P2P address from a Multiaddr string: `/ip4/<a>/udp/<port>`, `/ip6/<a>/udp/<port>`
/// or `/dns/<name>/udp/<port>` (what `Multiaddr::to_anemo_address` accepts).
pub const Dial = union(enum) {
    ip4_or_6: std.Io.net.IpAddress,
    dns: struct { host: []const u8, port: u16 },
};

pub fn parseAddress(text: []const u8) ?Dial {
    var it = std.mem.splitScalar(u8, text, '/');
    if (it.next()) |first| if (first.len != 0) return null;
    const proto = it.next() orelse return null;
    const host = it.next() orelse return null;
    const transport = it.next() orelse return null;
    const port_text = it.next() orelse return null;
    if (!std.mem.eql(u8, transport, "udp")) return null;
    const port = std.fmt.parseInt(u16, port_text, 10) catch return null;
    if (std.mem.eql(u8, proto, "ip4")) return .{ .ip4_or_6 = std.Io.net.IpAddress.parseIp4(host, port) catch return null };
    if (std.mem.eql(u8, proto, "ip6")) return .{ .ip4_or_6 = std.Io.net.IpAddress.parseIp6(host, port) catch return null };
    // sui-node's `to_anemo_address` takes /dns, /dns4 and /dns6 alike.
    if (std.mem.eql(u8, proto, "dns") or std.mem.eql(u8, proto, "dns4") or std.mem.eql(u8, proto, "dns6")) return .{ .dns = .{ .host = host, .port = port } };
    return null;
}

pub const CallError = anemo.Error || ss.DecodeError || Error || error{UnexpectedStatus};

/// `GetKnownPeersV2` with the `()` request: a read-only peer needs no node info of its own.
pub fn getKnownPeersV2(p: *anemo.Peer, arena: Allocator) CallError!KnownPeers {
    const hs = [_]@import("wire.zig").Header{.{ .name = "timeout", .value = "10000000000" }};
    const r = try p.request(arena, ss.Route.get_known_peers_v2, &hs, ss.encodeUnitRequest(), 10_000);
    if (r.status != .success) return error.UnexpectedStatus;
    const bcs = try ss.decodeBody(arena, r.body);
    return decodeKnownPeers(arena, bcs, false);
}

/// `GetKnownPeersV3` (sui-node's `use-get-known-peers-v3`): the request carries our signed
/// `VersionedNodeInfo` envelope (`own_v2`, data ++ signature), so the peer learns us too; the
/// answer holds versioned infos.
pub fn getKnownPeersV3(p: *anemo.Peer, arena: Allocator, own_v2: []const u8) CallError!KnownPeers {
    const hs = [_]@import("wire.zig").Header{.{ .name = "timeout", .value = "10000000000" }};
    const body = try @import("snappy.zig").compressFrame(arena, own_v2);
    const r = try p.request(arena, ss.Route.get_known_peers_v3, &hs, body, 10_000);
    if (r.status != .success) return error.UnexpectedStatus;
    const bcs = try ss.decodeBody(arena, r.body);
    return decodeKnownPeers(arena, bcs, true);
}

test "address parsing" {
    try std.testing.expect(parseAddress("/ip4/203.0.113.8/udp/8084").?.ip4_or_6.getPort() == 8084);
    try std.testing.expect(parseAddress("/dns/a.example/udp/1").?.dns.port == 1);
    try std.testing.expect(parseAddress("/dns4/a.example/udp/2").?.dns.port == 2);
    try std.testing.expect(parseAddress("/ip4/1.2.3.4/tcp/80") == null);
    try std.testing.expect(parseAddress("ip4/1.2.3.4/udp/80") == null);
}
