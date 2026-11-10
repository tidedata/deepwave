//! Multiaddr text as consensus committees carry it ("/ip4/127.0.0.1/udp/8081",
//! "/dns/host.example/tcp/8081"): the host and port to bind or dial. The transport word (udp or
//! tcp) does not matter: consensus runs gRPC over TCP on that port (`to_host_port_str`).
const std = @import("std");

pub const HostPort = struct { host: []const u8, port: u16 };

pub const Error = error{BadMultiaddr};

pub fn parse(text: []const u8) Error!HostPort {
    var it = std.mem.tokenizeScalar(u8, text, '/');
    const kind = it.next() orelse return error.BadMultiaddr;
    const host = it.next() orelse return error.BadMultiaddr;
    if (!(std.mem.eql(u8, kind, "ip4") or std.mem.eql(u8, kind, "ip6") or std.mem.eql(u8, kind, "dns") or std.mem.eql(u8, kind, "dns4") or std.mem.eql(u8, kind, "dns6"))) return error.BadMultiaddr;
    const proto = it.next() orelse return error.BadMultiaddr;
    if (!(std.mem.eql(u8, proto, "tcp") or std.mem.eql(u8, proto, "udp"))) return error.BadMultiaddr;
    const port_text = it.next() orelse return error.BadMultiaddr;
    const port = std.fmt.parseInt(u16, port_text, 10) catch return error.BadMultiaddr;
    return .{ .host = host, .port = port };
}

/// The host a listener binds for a committee address: the address itself when it is loopback,
/// the unspecified address otherwise (`TonicManager::new`: `with_zero_ip`).
pub fn bindHost(host: []const u8) []const u8 {
    if (std.mem.eql(u8, host, "localhost") or std.mem.startsWith(u8, host, "127.")) return "127.0.0.1";
    return "0.0.0.0";
}

/// True for hosts a local test committee uses: localhost, IPv4 loopback and RFC 1918 ranges,
/// IPv6 loopback and unique-local (fc00::/7). DNS names other than localhost are not local.
pub fn isLocalOrPrivate(host: []const u8) bool {
    if (std.mem.eql(u8, host, "localhost") or std.mem.eql(u8, host, "::1")) return true;
    if (std.mem.indexOfScalar(u8, host, ':') != null) {
        if (host.len < 2) return false;
        const first = std.ascii.toLower(host[0]);
        const second = std.ascii.toLower(host[1]);
        return first == 'f' and (second == 'c' or second == 'd');
    }
    const a = std.Io.net.Ip4Address.parse(host, 0) catch return false;
    const b = a.bytes;
    return b[0] == 127 or b[0] == 10 or (b[0] == 172 and b[1] >= 16 and b[1] <= 31) or (b[0] == 192 and b[1] == 168);
}

test "local or private hosts" {
    try std.testing.expect(isLocalOrPrivate("127.0.0.1"));
    try std.testing.expect(isLocalOrPrivate("10.1.2.3"));
    try std.testing.expect(isLocalOrPrivate("172.20.0.1"));
    try std.testing.expect(isLocalOrPrivate("192.168.0.9"));
    try std.testing.expect(isLocalOrPrivate("fd00::1"));
    try std.testing.expect(!isLocalOrPrivate("8.8.8.8"));
    try std.testing.expect(!isLocalOrPrivate("172.32.0.1"));
    try std.testing.expect(!isLocalOrPrivate("val1.example.com"));
}

test "multiaddr" {
    const a = try parse("/ip4/127.0.0.1/udp/8081");
    try std.testing.expectEqualStrings("127.0.0.1", a.host);
    try std.testing.expectEqual(@as(u16, 8081), a.port);
    const b = try parse("/dns/val1.example.com/tcp/8084");
    try std.testing.expectEqualStrings("val1.example.com", b.host);
    try std.testing.expectError(error.BadMultiaddr, parse("/ip4/1.2.3.4/http/80"));
    try std.testing.expectError(error.BadMultiaddr, parse("/ip4/1.2.3.4/tcp/99999"));
    try std.testing.expectEqualStrings("127.0.0.1", bindHost("127.0.0.1"));
    try std.testing.expectEqualStrings("0.0.0.0", bindHost("10.0.0.5"));
}
