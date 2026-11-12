//! Caller addresses for the access gate (docs/GATE.md): the socket peer, an optional
//! forwarded-for header honoured only behind a trusted proxy, the key a rate limit is kept
//! under (the exact IPv4 address, an IPv6 /64) and the prefix a usage row names (IPv4 /24,
//! IPv6 /48).
const std = @import("std");

pub const Ip = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

    pub const none: Ip = .{ .v4 = .{ 0, 0, 0, 0 } };

    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is the IPv4 address.
    pub fn fromV6(b: [16]u8) Ip {
        const mapped = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        if (std.mem.eql(u8, b[0..12], &mapped)) return .{ .v4 = b[12..16].* };
        return .{ .v6 = b };
    }

    pub fn fromNet(a: std.Io.net.IpAddress) Ip {
        return switch (a) {
            .ip4 => |x| .{ .v4 = x.bytes },
            .ip6 => |x| fromV6(x.bytes),
        };
    }

    /// Text without a port; null when it is not an address.
    pub fn parse(text: []const u8) ?Ip {
        const t = std.mem.trim(u8, text, " \t");
        if (t.len == 0 or t.len > 64) return null;
        const inner = if (t[0] == '[') blk: {
            const close = std.mem.indexOfScalar(u8, t, ']') orelse return null;
            break :blk t[1..close];
        } else t;
        return fromNet(std.Io.net.IpAddress.parse(inner, 0) catch return null);
    }

    /// A socket peer as the serving runtime writes it: `1.2.3.4:5678`, `[hex groups]:5678`, or
    /// a bare address. `none` when it cannot be read (every such caller then shares one limit).
    pub fn parsePeer(text: []const u8) Ip {
        if (text.len == 0) return none;
        if (text[0] != '[') {
            // one colon: an IPv4 address and a port
            if (std.mem.indexOfScalar(u8, text, ':')) |i| {
                if (std.mem.indexOfScalarPos(u8, text, i + 1, ':') == null) return parse(text[0..i]) orelse none;
            }
        }
        return parse(text) orelse none;
    }

    /// What a rate limit is kept under: the IPv4 address, or the IPv6 /64 (with the family, so
    /// the two never meet).
    pub fn limitKey(ip: Ip) u128 {
        return switch (ip) {
            .v4 => |b| (@as(u128, 4) << 64) | std.mem.readInt(u32, &b, .big),
            .v6 => |b| (@as(u128, 6) << 64) | std.mem.readInt(u64, b[0..8], .big),
        };
    }

    /// The usage-row group: IPv4 /24 or IPv6 /48, as one word. Never 0.
    pub fn prefixKey(ip: Ip) u64 {
        return switch (ip) {
            .v4 => |b| (@as(u64, 4) << 56) | (@as(u64, b[0]) << 16) | (@as(u64, b[1]) << 8) | b[2],
            .v6 => |b| (@as(u64, 6) << 56) | (@as(u64, std.mem.readInt(u16, b[0..2], .big)) << 32) | (@as(u64, std.mem.readInt(u16, b[2..4], .big)) << 16) | std.mem.readInt(u16, b[4..6], .big),
        };
    }
};

pub const prefix_text_max = 24;

/// `prefixKey` as the text a usage row carries: `203.0.113.0/24`, `2001:db8:1::/48`. The
/// catch-all rows (`prefix_other_v4`, `prefix_other_v6`) print as `0.0.0.0/0` and `::/0`.
pub fn prefixText(buf: *[prefix_text_max]u8, key: u64) []const u8 {
    if (key == prefix_other_v4) return "0.0.0.0/0";
    if (key == prefix_other_v6) return "::/0";
    if (key >> 56 == 4) return std.fmt.bufPrint(buf, "{d}.{d}.{d}.0/24", .{ (key >> 16) & 0xff, (key >> 8) & 0xff, key & 0xff }) catch unreachable;
    return std.fmt.bufPrint(buf, "{x}:{x}:{x}::/48", .{ (key >> 32) & 0xffff, (key >> 16) & 0xffff, key & 0xffff }) catch unreachable;
}

pub const prefix_other_v4: u64 = (@as(u64, 4) << 56) | (@as(u64, 1) << 40);
pub const prefix_other_v6: u64 = (@as(u64, 6) << 56) | (@as(u64, 1) << 55);

/// A usage-row prefix back from text (the gate's `deny` list); null when it is not one of ours.
pub fn parsePrefix(text: []const u8) ?u64 {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return null;
    const bits = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return null;
    const ip = Ip.parse(text[0..slash]) orelse return null;
    return switch (ip) {
        .v4 => if (bits == 24) ip.prefixKey() else null,
        .v6 => if (bits == 48) ip.prefixKey() else null,
    };
}

pub const Cidr = struct {
    ip: Ip,
    bits: u8,

    pub fn parse(text: []const u8) ?Cidr {
        const t = std.mem.trim(u8, text, " \t");
        const slash = std.mem.indexOfScalar(u8, t, '/');
        const ip = Ip.parse(if (slash) |s| t[0..s] else t) orelse return null;
        const max: u8 = if (ip == .v4) 32 else 128;
        const bits = if (slash) |s| std.fmt.parseInt(u8, t[s + 1 ..], 10) catch return null else max;
        if (bits > max) return null;
        return .{ .ip = ip, .bits = bits };
    }

    pub fn contains(c: Cidr, ip: Ip) bool {
        const a: []const u8 = switch (c.ip) {
            .v4 => |*b| b,
            .v6 => |*b| b,
        };
        const b: []const u8 = switch (ip) {
            .v4 => |*x| x,
            .v6 => |*x| x,
        };
        if (a.len != b.len) return false;
        const whole = c.bits / 8;
        if (!std.mem.eql(u8, a[0..whole], b[0..whole])) return false;
        const rest: u3 = @intCast(c.bits % 8);
        if (rest == 0) return true;
        const mask: u8 = @as(u8, 0xff) << @intCast(8 - @as(u4, rest));
        return (a[whole] & mask) == (b[whole] & mask);
    }
};

pub fn trusted(list: []const Cidr, ip: Ip) bool {
    for (list) |c| if (c.contains(ip)) return true;
    return false;
}

/// The caller's address. The socket peer, unless the peer is a trusted proxy: then the
/// rightmost forwarded-for entry that is not itself a trusted proxy (what the last trusted hop
/// saw). With no trusted proxy configured the header is never read.
pub fn caller(peer: Ip, forwarded_for: []const u8, proxies: []const Cidr) Ip {
    if (proxies.len == 0 or forwarded_for.len == 0 or !trusted(proxies, peer)) return peer;
    var it = std.mem.splitBackwardsScalar(u8, forwarded_for, ',');
    var hops: u32 = 0;
    while (it.next()) |part| {
        hops += 1;
        if (hops > 32) break;
        const ip = Ip.parse(part) orelse return peer; // a hop we cannot read: stop at the peer
        if (!trusted(proxies, ip)) return ip;
    }
    return peer;
}

test "ip: parse, mapped addresses, limit and prefix keys" {
    const a = Ip.parse("203.0.113.77").?;
    try std.testing.expectEqual(Ip{ .v4 = .{ 203, 0, 113, 77 } }, a);
    try std.testing.expectEqual(a, Ip.parse(" ::ffff:203.0.113.77 ").?);
    try std.testing.expect(Ip.parse("not an ip") == null);
    try std.testing.expect(Ip.parse("") == null);
    var b: [prefix_text_max]u8 = undefined;
    try std.testing.expectEqualStrings("203.0.113.0/24", prefixText(&b, a.prefixKey()));
    try std.testing.expectEqual(a.prefixKey(), Ip.parse("203.0.113.1").?.prefixKey());
    try std.testing.expect(a.limitKey() != Ip.parse("203.0.113.1").?.limitKey());
    const s = Ip.parse("2001:db8:1:2:3:4:5:6").?;
    try std.testing.expectEqualStrings("2001:db8:1::/48", prefixText(&b, s.prefixKey()));
    // one /64 is one limit, another /64 of the same /48 is another limit and the same row
    try std.testing.expectEqual(s.limitKey(), Ip.parse("2001:db8:1:2::9").?.limitKey());
    try std.testing.expect(s.limitKey() != Ip.parse("2001:db8:1:3::9").?.limitKey());
    try std.testing.expectEqual(s.prefixKey(), Ip.parse("2001:db8:1:3::9").?.prefixKey());
    try std.testing.expectEqual(a.prefixKey(), parsePrefix("203.0.113.0/24").?);
    try std.testing.expectEqual(s.prefixKey(), parsePrefix("2001:db8:1::/48").?);
    try std.testing.expect(parsePrefix("203.0.113.0/16") == null);
    try std.testing.expect(parsePrefix("203.0.113.0") == null);
    try std.testing.expectEqual(a, Ip.parsePeer("203.0.113.77:50123"));
    try std.testing.expectEqual(a, Ip.parsePeer("203.0.113.77"));
    try std.testing.expectEqual(s, Ip.parsePeer("[2001:db8:1:2:3:4:5:6]:443"));
    try std.testing.expectEqual(s, Ip.parsePeer("2001:db8:1:2:3:4:5:6"));
    try std.testing.expectEqual(a, Ip.parsePeer("[0:0:0:0:0:ffff:cb00:714d]:9"));
    try std.testing.expectEqual(Ip.none, Ip.parsePeer(""));
    try std.testing.expectEqual(Ip.none, Ip.parsePeer("nonsense:1"));
    try std.testing.expectEqualStrings("0.0.0.0/0", prefixText(&b, prefix_other_v4));
    try std.testing.expectEqualStrings("::/0", prefixText(&b, prefix_other_v6));
}

test "trusted proxy: the header counts only behind a listed proxy" {
    const peer = Ip.parse("10.0.0.7").?;
    const xff = "198.51.100.4, 203.0.113.9, 10.0.0.8";
    // off (the default): the header is ignored
    try std.testing.expectEqual(peer, caller(peer, xff, &.{}));
    const proxies = [_]Cidr{Cidr.parse("10.0.0.0/8").?};
    // on: the rightmost entry that is not a proxy
    try std.testing.expectEqual(Ip.parse("203.0.113.9").?, caller(peer, xff, &proxies));
    // a peer outside the list cannot use the header
    const outsider = Ip.parse("192.0.2.1").?;
    try std.testing.expectEqual(outsider, caller(outsider, xff, &proxies));
    // nothing usable in the header: the peer
    try std.testing.expectEqual(peer, caller(peer, "10.0.0.9, 10.1.1.1", &proxies));
    try std.testing.expectEqual(peer, caller(peer, "garbage", &proxies));
    try std.testing.expectEqual(peer, caller(peer, "", &proxies));
    try std.testing.expect(Cidr.parse("10.0.0.0/33") == null);
    try std.testing.expect(Cidr.parse("2001:db8::/32").?.contains(Ip.parse("2001:db8:ffff::1").?));
    try std.testing.expect(!Cidr.parse("2001:db8::/32").?.contains(Ip.parse("2001:db9::1").?));
    try std.testing.expect(Cidr.parse("192.0.2.128/25").?.contains(Ip.parse("192.0.2.200").?));
    try std.testing.expect(!Cidr.parse("192.0.2.128/25").?.contains(Ip.parse("192.0.2.100").?));
    try std.testing.expect(Cidr.parse("192.0.2.1").?.contains(Ip.parse("192.0.2.1").?));
}
