//! Peer addresses as sui-node's config writes them: `host:port`, `[v6]:port`, or a multiaddr
//! `/ip4/A/udp/P`, `/ip6/A/udp/P`, `/dns/H/udp/P`, `/dns4/H/udp/P`, `/dns6/H/udp/P` (a trailing
//! `/p2p/...` or other component is ignored). Host names are resolved at each dial
//! (`resolve`), as sui-node's anemo resolves a `/dns` multiaddr on every connect attempt.
const std = @import("std");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;

pub const Dns = struct {
    name: []const u8,
    port: u16,
    /// `/dns4` and `/dns6` restrict the family; `/dns` and `host:port` take either (IPv4 first).
    family: ?IpAddress.Family = null,
};

pub const Addr = union(enum) {
    ip: IpAddress,
    dns: Dns,
};

pub const Error = error{BadPeerAddress};

/// Parses `text`; a host name is copied into `a`.
pub fn parse(a: std.mem.Allocator, text: []const u8) (Error || std.mem.Allocator.Error)!Addr {
    const t = std.mem.trim(u8, text, " \t");
    if (t.len > 0 and t[0] == '/') return parseMultiaddr(a, t);
    // [v6]:port
    if (t.len > 0 and t[0] == '[') {
        const close = std.mem.indexOfScalar(u8, t, ']') orelse return error.BadPeerAddress;
        if (close + 2 > t.len or t[close + 1] != ':') return error.BadPeerAddress;
        const port = std.fmt.parseInt(u16, t[close + 2 ..], 10) catch return error.BadPeerAddress;
        return .{ .ip = IpAddress.parse(t[1..close], port) catch return error.BadPeerAddress };
    }
    const colon = std.mem.lastIndexOfScalar(u8, t, ':') orelse return error.BadPeerAddress;
    const port = std.fmt.parseInt(u16, t[colon + 1 ..], 10) catch return error.BadPeerAddress;
    const host = t[0..colon];
    if (host.len == 0) return error.BadPeerAddress;
    if (IpAddress.parse(host, port)) |ip| return .{ .ip = ip } else |_| {}
    if (std.mem.indexOfScalar(u8, host, ':') != null) return error.BadPeerAddress; // bare v6 needs []
    Io.net.HostName.validate(host) catch return error.BadPeerAddress;
    return .{ .dns = .{ .name = try a.dupe(u8, host), .port = port } };
}

fn parseMultiaddr(a: std.mem.Allocator, t: []const u8) (Error || std.mem.Allocator.Error)!Addr {
    var it = std.mem.splitScalar(u8, t[1..], '/');
    const proto = it.next() orelse return error.BadPeerAddress;
    const host = it.next() orelse return error.BadPeerAddress;
    const transport = it.next() orelse return error.BadPeerAddress;
    const port_text = it.next() orelse return error.BadPeerAddress;
    if (!std.mem.eql(u8, transport, "udp")) return error.BadPeerAddress; // anemo is QUIC over UDP
    const port = std.fmt.parseInt(u16, port_text, 10) catch return error.BadPeerAddress;
    if (std.mem.eql(u8, proto, "ip4") or std.mem.eql(u8, proto, "ip6")) {
        const ip = IpAddress.parse(host, port) catch return error.BadPeerAddress;
        if ((ip == .ip4) != std.mem.eql(u8, proto, "ip4")) return error.BadPeerAddress;
        return .{ .ip = ip };
    }
    const family: ?IpAddress.Family = if (std.mem.eql(u8, proto, "dns")) null else if (std.mem.eql(u8, proto, "dns4")) .ip4 else if (std.mem.eql(u8, proto, "dns6")) .ip6 else return error.BadPeerAddress;
    Io.net.HostName.validate(host) catch return error.BadPeerAddress;
    return .{ .dns = .{ .name = try a.dupe(u8, host), .port = port, .family = family } };
}

/// The address to dial now: an IP as is; a host name looked up (system resolver), IPv4 first
/// unless the family is fixed.
pub fn resolve(io: Io, addr: Addr) !IpAddress {
    const d = switch (addr) {
        .ip => |ip| return ip,
        .dns => |d| d,
    };
    var buf: [32]Io.net.HostName.LookupResult = undefined;
    var q: Io.Queue(Io.net.HostName.LookupResult) = .init(&buf);
    const hn = Io.net.HostName.init(d.name) catch return error.BadPeerAddress;
    try Io.net.HostName.lookup(hn, io, &q, .{ .port = d.port, .family = d.family });
    var first: ?IpAddress = null;
    while (q.getOneUncancelable(io)) |r| switch (r) {
        .address => |ip| {
            if (ip == .ip4) return ip;
            if (first == null) first = ip;
        },
        .canonical_name => {},
    } else |_| {}
    return first orelse error.UnknownHostName;
}

test "peer address forms" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expect((try parse(a, "104.207.128.152:8084")) == .ip);
    try std.testing.expect((try parse(a, "[2001:db8::1]:8084")) == .ip);
    try std.testing.expect((try parse(a, "/ip4/1.2.3.4/udp/8084")) == .ip);
    try std.testing.expect((try parse(a, "/ip6/2001:db8::1/udp/8084")) == .ip);
    const d = try parse(a, "/dns/ewr-00.mainnet.sui.io/udp/8084");
    try std.testing.expectEqualStrings("ewr-00.mainnet.sui.io", d.dns.name);
    try std.testing.expectEqual(@as(u16, 8084), d.dns.port);
    try std.testing.expect(d.dns.family == null);
    try std.testing.expect((try parse(a, "/dns4/a.b/udp/1")).dns.family.? == .ip4);
    try std.testing.expect((try parse(a, "/dns6/a.b/udp/1")).dns.family.? == .ip6);
    try std.testing.expectEqualStrings("mel-00.mainnet.sui.io", (try parse(a, "mel-00.mainnet.sui.io:8084")).dns.name);
    try std.testing.expectError(error.BadPeerAddress, parse(a, "/dns/a.b/tcp/1"));
    try std.testing.expectError(error.BadPeerAddress, parse(a, "/ip4/a.b/udp/1"));
    try std.testing.expectError(error.BadPeerAddress, parse(a, "nohost"));
    try std.testing.expectError(error.BadPeerAddress, parse(a, "/ip4/1.2.3.4/udp/x"));
    // an IP needs no lookup
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const ip = try resolve(threaded.io(), try parse(a, "/ip4/127.0.0.1/udp/9"));
    try std.testing.expect(ip == .ip4);
    // "localhost" resolves through the system resolver (no network)
    const lh = try resolve(threaded.io(), try parse(a, "localhost:9"));
    try std.testing.expectEqual(@as(u16, 9), lh.getPort());
}
