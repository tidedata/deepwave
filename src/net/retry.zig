//! Stateless address validation for QUIC listeners (RFC 9000 section 8.1.2, RFC 9001 section 5.8).
//! Under a flood of Initials (spoofed sources cost the sender nothing) a listener answers an
//! Initial without a valid token with a Retry carrying one, and keeps no state; only a client
//! that receives it at its address comes back. Shared by the anemo listener (server.zig) and the
//! zui/1 listener. quinn and deepwave's own client follow Retry (conn.zig `handleRetry`).
const std = @import("std");
const Io = std.Io;
const qc = @import("qcrypto.zig");
const conn_mod = @import("conn.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Seconds a Retry token stays valid (a round trip plus the client's retransmission).
pub const token_ttl_s = 10;
const mac_len = 16;
const token_tag: u8 = 0x5a;
/// tag, issue time, odcid length, odcid (up to 20), mac
pub const max_token = 1 + 4 + 1 + 20 + mac_len;

pub const Guard = struct {
    key: [32]u8,
    /// Half-open connections (not yet established) above which an Initial without a valid token
    /// is answered with a Retry instead of a connection.
    threshold: usize = 64,
    retries_sent: u64 = 0,
    tokens_ok: u64 = 0,
    tokens_bad: u64 = 0,

    pub fn init(key: [32]u8) Guard {
        return .{ .key = key };
    }

    fn mac(g: *const Guard, addr: []const u8, body: []const u8) [mac_len]u8 {
        var h = HmacSha256.init(&g.key);
        h.update(addr);
        h.update(body);
        var out: [HmacSha256.mac_length]u8 = undefined;
        h.final(&out);
        return out[0..mac_len].*;
    }

    /// A token binding `odcid` to the client address `addr` at `now_s`.
    pub fn token(g: *const Guard, out: *[max_token]u8, addr: []const u8, now_s: u32, odcid: []const u8) []const u8 {
        std.debug.assert(odcid.len <= 20);
        out[0] = token_tag;
        std.mem.writeInt(u32, out[1..5], now_s, .big);
        out[5] = @intCast(odcid.len);
        @memcpy(out[6..][0..odcid.len], odcid);
        const n = 6 + odcid.len;
        out[n..][0..mac_len].* = g.mac(addr, out[0..n]);
        return out[0 .. n + mac_len];
    }

    /// The original destination connection id of a token we issued to `addr` no more than
    /// `token_ttl_s` ago, or null.
    pub fn check(g: *const Guard, tok: []const u8, addr: []const u8, now_s: u32) ?[]const u8 {
        if (tok.len < 6 + mac_len or tok[0] != token_tag) return null;
        const ol: usize = tok[5];
        if (ol > 20 or tok.len != 6 + ol + mac_len) return null;
        const want = g.mac(addr, tok[0 .. 6 + ol]);
        if (!std.crypto.timing_safe.eql([mac_len]u8, want, tok[6 + ol ..][0..mac_len].*)) return null;
        const t = std.mem.readInt(u32, tok[1..5], .big);
        if (t > now_s +| 1 or now_s - @min(now_s, t) > token_ttl_s) return null;
        return tok[6..][0..ol];
    }
};

/// Writes a Retry for an Initial from `client_scid` to `odcid`, with a new connection id
/// `new_scid` and `tok`. Returns its length.
pub fn writeRetry(out: []u8, version: u32, client_scid: []const u8, new_scid: []const u8, tok: []const u8, odcid: []const u8, unused_bits: u4) usize {
    var p: usize = 0;
    out[p] = 0xf0 | @as(u8, unused_bits);
    p += 1;
    std.mem.writeInt(u32, out[p..][0..4], version, .big);
    p += 4;
    out[p] = @intCast(client_scid.len);
    p += 1;
    @memcpy(out[p..][0..client_scid.len], client_scid);
    p += client_scid.len;
    out[p] = @intCast(new_scid.len);
    p += 1;
    @memcpy(out[p..][0..new_scid.len], new_scid);
    p += new_scid.len;
    @memcpy(out[p..][0..tok.len], tok);
    p += tok.len;
    out[p..][0..16].* = qc.retryTag(odcid, out[0..p]);
    return p + 16;
}

/// The token of a long-header Initial (empty when it has none), or null when the header does not
/// parse.
pub fn initialToken(d: []const u8) ?[]const u8 {
    if (d.len < 7) return null;
    var p: usize = 5;
    const dl = d[p];
    if (dl > 20) return null;
    p += 1 + @as(usize, dl);
    if (p >= d.len) return null;
    const sl = d[p];
    if (sl > 20) return null;
    p += 1 + @as(usize, sl);
    const tl = conn_mod.getVarint(d, &p) orelse return null;
    if (tl > d.len - p) return null;
    return d[p..][0..@intCast(tl)];
}

/// The bytes of `addr` a token is bound to (family, address, port).
pub fn addrBytes(addr: *const Io.net.IpAddress, buf: *[19]u8) []const u8 {
    switch (addr.*) {
        .ip4 => |a| {
            buf[0] = 4;
            @memcpy(buf[1..5], &a.bytes);
            std.mem.writeInt(u16, buf[5..7], a.port, .big);
            return buf[0..7];
        },
        .ip6 => |a| {
            buf[0] = 6;
            @memcpy(buf[1..17], &a.bytes);
            std.mem.writeInt(u16, buf[17..19], a.port, .big);
            return buf[0..19];
        },
    }
}

test "retry tokens: bound to the address, expire, refuse tampering" {
    const g = Guard.init(@splat(3));
    var buf: [max_token]u8 = undefined;
    const odcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const tok = g.token(&buf, "addr-a", 1000, &odcid);
    try std.testing.expectEqualSlices(u8, &odcid, g.check(tok, "addr-a", 1005).?);
    try std.testing.expect(g.check(tok, "addr-b", 1005) == null);
    try std.testing.expect(g.check(tok, "addr-a", 1000 + token_ttl_s + 1) == null);
    var bad = buf;
    bad[7] ^= 1;
    try std.testing.expect(g.check(bad[0..tok.len], "addr-a", 1001) == null);
    try std.testing.expect(g.check(tok[0 .. tok.len - 1], "addr-a", 1001) == null);
    try std.testing.expect(g.check("", "addr-a", 1001) == null);
}

test "a client follows our Retry and the server accepts the token (anemo-style handshake completes)" {
    const gpa = std.testing.allocator;
    const Connection = conn_mod.Connection;
    const g = Guard.init(@splat(9));
    const addr = "client-addr";
    var seed: [64]u8 = @splat(4);
    const client = try Connection.init(gpa, .{ .server_name = "sui-test", .identity_seed = @as([32]u8, @splat(3)), .seed = seed, .now_unix = 1_800_000_000 }, 0);
    defer client.deinit();
    var d: [conn_mod.max_mtu]u8 = undefined;
    var n = client.pollTransmit(0, &d).?;
    // no token: Retry
    try std.testing.expectEqual(@as(usize, 0), initialToken(d[0..n]).?.len);
    const dl = d[5];
    var odcid_b: [20]u8 = undefined;
    @memcpy(odcid_b[0..dl], d[6..][0..dl]);
    const odcid = odcid_b[0..dl];
    const csl = d[6 + dl];
    var cscid_b: [20]u8 = undefined;
    @memcpy(cscid_b[0..csl], d[7 + dl ..][0..csl]);
    const cscid = cscid_b[0..csl];
    var tb: [max_token]u8 = undefined;
    const tok = g.token(&tb, addr, 100, odcid);
    const new_scid = [_]u8{ 0xaa, 1, 2, 3, 4, 5, 6, 7 };
    var r: [256]u8 = undefined;
    const rn = writeRetry(&r, 1, cscid, &new_scid, tok, odcid, 5);
    client.handleDatagram(1000, r[0..rn]);
    try std.testing.expect(client.retry_scid != null);
    // the client's new Initial carries the token, to the Retry's connection id
    n = client.pollTransmit(2000, &d).?;
    const tok2 = initialToken(d[0..n]).?;
    const orig = g.check(tok2, addr, 101).?;
    try std.testing.expectEqualSlices(u8, odcid, orig);
    const dl2 = d[5];
    try std.testing.expectEqualSlices(u8, &new_scid, d[6..][0..dl2]);
    const sl2 = d[6 + dl2];
    seed[0] = 8;
    const server = try Connection.initServer(gpa, .{ .server_name = "sui-test", .identity_seed = @as([32]u8, @splat(5)), .seed = seed, .now_unix = 1_800_000_000 }, 2000, d[6..][0..dl2], d[7 + dl2 ..][0..sl2]);
    defer server.deinit();
    server.markRetried(orig, d[6..][0..dl2]);
    server.handleDatagram(2000, d[0..n]);
    // run both to completion
    var now: u64 = 3000;
    var rounds: usize = 0;
    while (rounds < 50 and !(client.isEstablished() and server.isEstablished())) : (rounds += 1) {
        while (server.pollTransmit(now, &d)) |m| client.handleDatagram(now, d[0..m]);
        while (client.pollTransmit(now, &d)) |m| server.handleDatagram(now, d[0..m]);
        now += 1000;
    }
    try std.testing.expect(client.isEstablished() and server.isEstablished());
    try std.testing.expect(client.close == null and server.close == null);
}
