//! `multiaddr` 0.18.2 `Multiaddr::from_str` as an accept/reject decision, plus the first two
//! protocol kinds that mysten-network `Multiaddr::to_anemo_address` looks at.
//!
//! Every value parser follows the crate the Rust code calls:
//!   ip4/ip6        core::net parser (Rust 1.8x/1.9x; IPv4 at most 15 bytes, no leading zeros)
//!   ports, memory  `str::parse::<uN>` (optional leading '+', ASCII digits, no overflow)
//!   p2p/ipfs       multibase Base58Btc (base-x 0.2.11) then libp2p-identity PeerId
//!   certhash       multibase 0.9.1 `decode` then multihash 0.19 `Multihash<64>::from_bytes`
//!   onion/onion3   `str::to_uppercase` then data-encoding BASE32 (padded) into 10/35 bytes
//!   garlic64/32    data-encoding BASE64_NOPAD / BASE32_NOPAD_LOWER (with the length gates)
//!   x-parity-ws(s) percent-encoding `percent_decode().decode_utf8()`
//! The binary round trip `to_anemo_address` iterates cannot fail for anything `from_str` wrote.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Kind = enum { none, ip4, ip6, dns, udp, other };

pub const Parsed = struct {
    first: Kind = .none,
    second: Kind = .none,

    /// mysten-network `to_anemo_address`: (Ip4|Ip6|Dns, Udp) first.
    pub fn anemo(p: Parsed) bool {
        return (p.first == .ip4 or p.first == .ip6 or p.first == .dns) and p.second == .udp;
    }
};

/// null when `Multiaddr::from_str` fails.
pub fn parse(arena: Allocator, s: []const u8) Allocator.Error!?Parsed {
    var it = std.mem.splitScalar(u8, s, '/');
    if (!std.mem.eql(u8, it.first(), "")) return null;
    var out: Parsed = .{};
    var n: usize = 0;
    while (it.peek() != null) : (n += 1) {
        const k = (try protocol(arena, &it)) orelse return null;
        if (n == 0) out.first = k else if (n == 1) out.second = k;
    }
    return out;
}

const Split = std.mem.SplitIterator(u8, .scalar);

fn protocol(arena: Allocator, it: *Split) Allocator.Error!?Kind {
    const name = it.next() orelse return null;
    const T = enum {
        ip4,      tcp,               tls,              noise,             udp,           dccp,
        ip6,      dns,               dns4,             dns6,              dnsaddr,       sctp,
        udt,      utp,               unix,             p2p,               ipfs,          http,
        https,    onion,             onion3,           quic,              @"quic-v1",    webtransport,
        ws,       wss,               @"x-parity-ws",   @"x-parity-wss",   @"p2p-websocket-star",
        @"p2p-webrtc-star",          @"webrtc-direct", certhash,          @"p2p-webrtc-direct",
        @"p2p-circuit",              memory,           ip6zone,           ipcidr,        garlic64,
        garlic32, sni,               @"p2p-stardust",  webrtc,
    };
    const t = std.meta.stringToEnum(T, name) orelse return null;
    switch (t) {
        .tls, .noise, .udt, .utp, .http, .https, .quic, .@"quic-v1", .webtransport, .ws, .wss,
        .@"p2p-websocket-star", .@"p2p-webrtc-star", .@"webrtc-direct", .@"p2p-webrtc-direct",
        .@"p2p-circuit", .@"p2p-stardust", .webrtc => return .other,
        else => {},
    }
    const v = it.next() orelse return null;
    return switch (t) {
        .ip4 => if (parseIp4(v) != null) .ip4 else null,
        .ip6 => if (parseIp6(v) != null) .ip6 else null,
        .tcp, .dccp, .sctp => if (parseUint(u16, v) != null) .other else null,
        .udp => if (parseUint(u16, v) != null) .udp else null,
        .memory => if (parseUint(u64, v) != null) .other else null,
        .ipcidr => if (parseUint(u8, v) != null) .other else null,
        .dns => .dns,
        .dns4, .dns6, .dnsaddr, .unix, .ip6zone, .sni => .other,
        .p2p, .ipfs => blk: {
            const d = (try baseX(arena, base58btc, v)) orelse break :blk null;
            break :blk if (peerId(d)) .other else null;
        },
        .onion => if (try onion(arena, v, 16)) .other else null,
        .onion3 => if (try onion(arena, v, 56)) .other else null,
        .@"x-parity-ws", .@"x-parity-wss" => if (try percentUtf8(arena, v)) .other else null,
        .certhash => blk: {
            const d = (try multibase(arena, v)) orelse break :blk null;
            break :blk if (multihash(d) != null) .other else null;
        },
        .garlic64 => blk: {
            if (v.len < 516 or v.len > 616) break :blk null;
            const r = try arena.dupe(u8, v);
            for (r) |*ch| {
                if (ch.* == '-') ch.* = '+' else if (ch.* == '~') ch.* = '/';
            }
            break :blk if ((try dataDecode(arena, &base64, r)) != null) .other else null;
        },
        .garlic32 => blk: {
            if (v.len < 55 and v.len != 52) break :blk null;
            break :blk if ((try dataDecode(arena, &base32_lower, v)) != null) .other else null;
        },
        else => unreachable,
    };
}

// ---- integers ------------------------------------------------------------------------------

/// `str::parse::<T>()` for an unsigned T.
pub fn parseUint(comptime T: type, s: []const u8) ?T {
    if (s.len == 0) return null;
    var d = s;
    if (d[0] == '+') {
        if (d.len == 1) return null;
        d = d[1..];
    }
    var v: T = 0;
    for (d) |ch| {
        if (ch < '0' or ch > '9') return null;
        v = std.math.mul(T, v, 10) catch return null;
        v = std.math.add(T, v, ch - '0') catch return null;
    }
    return v;
}

// ---- core::net parser ----------------------------------------------------------------------

const NetParser = struct {
    s: []const u8,
    i: usize = 0,

    fn readGiven(p: *NetParser, ch: u8) bool {
        if (p.i < p.s.len and p.s[p.i] == ch) {
            p.i += 1;
            return true;
        }
        return false;
    }

    fn digit(ch: u8, radix: u32) ?u32 {
        const v: u32 = switch (ch) {
            '0'...'9' => ch - '0',
            'a'...'z' => ch - 'a' + 10,
            'A'...'Z' => ch - 'A' + 10,
            else => return null,
        };
        return if (v < radix) v else null;
    }

    /// `read_number(radix, Some(max_digits), allow_zero_prefix)`, atomic.
    fn readNumber(p: *NetParser, comptime T: type, radix: u32, max_digits: usize, allow_zero_prefix: bool) ?T {
        const save = p.i;
        const lead_zero = p.i < p.s.len and p.s[p.i] == '0';
        var r: u32 = 0;
        var count: usize = 0;
        while (p.i < p.s.len) {
            const dg = digit(p.s[p.i], radix) orelse break;
            p.i += 1;
            r = r * radix + dg;
            count += 1;
            if (count > max_digits) {
                p.i = save;
                return null;
            }
        }
        if (count == 0 or (!allow_zero_prefix and lead_zero and count > 1) or r > std.math.maxInt(T)) {
            p.i = save;
            return null;
        }
        return @intCast(r);
    }

    fn readIpv4(p: *NetParser) ?[4]u8 {
        const save = p.i;
        var g: [4]u8 = undefined;
        for (&g, 0..) |*slot, i| {
            if (i > 0 and !p.readGiven('.')) {
                p.i = save;
                return null;
            }
            slot.* = p.readNumber(u8, 10, 3, false) orelse {
                p.i = save;
                return null;
            };
        }
        return g;
    }

    /// `read_separator(sep, index, inner)` for the two inner readers of `read_groups`.
    fn sepIpv4(p: *NetParser, i: usize) ?[4]u8 {
        const save = p.i;
        if (i > 0 and !p.readGiven(':')) return null;
        return p.readIpv4() orelse {
            p.i = save;
            return null;
        };
    }

    fn sepGroup(p: *NetParser, i: usize) ?u16 {
        const save = p.i;
        if (i > 0 and !p.readGiven(':')) return null;
        return p.readNumber(u16, 16, 4, true) orelse {
            p.i = save;
            return null;
        };
    }

    const Groups = struct { n: usize, v4: bool };

    fn readGroups(p: *NetParser, groups: []u16) Groups {
        const limit = groups.len;
        var i: usize = 0;
        while (i < limit) : (i += 1) {
            if (i < limit - 1) {
                if (p.sepIpv4(i)) |o| {
                    groups[i] = (@as(u16, o[0]) << 8) | o[1];
                    groups[i + 1] = (@as(u16, o[2]) << 8) | o[3];
                    return .{ .n = i + 2, .v4 = true };
                }
            }
            groups[i] = p.sepGroup(i) orelse return .{ .n = i, .v4 = false };
        }
        return .{ .n = limit, .v4 = false };
    }

    fn readIpv6(p: *NetParser) ?[8]u16 {
        const save = p.i;
        var head: [8]u16 = @splat(0);
        const h = p.readGroups(&head);
        if (h.n == 8) return head;
        if (h.v4 or !p.readGiven(':') or !p.readGiven(':')) {
            p.i = save;
            return null;
        }
        var tail: [7]u16 = @splat(0);
        const limit = 8 - (h.n + 1);
        const t = p.readGroups(tail[0..limit]);
        @memcpy(head[8 - t.n .. 8], tail[0..t.n]);
        return head;
    }
};

pub fn parseIp4(s: []const u8) ?[4]u8 {
    if (s.len > 15) return null;
    var p: NetParser = .{ .s = s };
    const r = p.readIpv4() orelse return null;
    return if (p.i == s.len) r else null;
}

pub fn parseIp6(s: []const u8) ?[8]u16 {
    var p: NetParser = .{ .s = s };
    const r = p.readIpv6() orelse return null;
    return if (p.i == s.len) r else null;
}

// ---- base-x (Base10 / Base36 / Base58) -----------------------------------------------------

const base58btc = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const base58flickr = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
const base10 = "0123456789";
const base36_lower = "0123456789abcdefghijklmnopqrstuvwxyz";
const base36_upper = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// base-x 0.2.11 `decode` over an ASCII alphabet (bytes of `s`).
pub fn baseX(arena: Allocator, comptime alpha: []const u8, s: []const u8) Allocator.Error!?[]u8 {
    if (s.len == 0) return try arena.alloc(u8, 0);
    const lookup = comptime blk: {
        var t: [256]u8 = @splat(0xff);
        for (alpha, 0..) |ch, i| t[ch] = i;
        break :blk t;
    };
    const base: u64 = alpha.len;
    // little-endian u32 limbs
    const limbs = try arena.alloc(u32, s.len / 4 + 2);
    var nl: usize = 1;
    limbs[0] = 0;
    for (s) |ch| {
        const dv = lookup[ch];
        if (dv == 0xff) return null;
        var carry: u64 = dv;
        for (limbs[0..nl]) |*l| {
            carry += @as(u64, l.*) * base;
            l.* = @truncate(carry);
            carry >>= 32;
        }
        if (carry > 0) {
            limbs[nl] = @intCast(carry);
            nl += 1;
        }
    }
    var leaders: usize = 0;
    while (leaders < s.len and s[leaders] == alpha[0]) leaders += 1;
    var nb: usize = nl * 4;
    while (nb > 0 and byteAt(limbs, nb - 1) == 0) nb -= 1;
    const out = try arena.alloc(u8, leaders + nb);
    @memset(out[0..leaders], 0);
    for (0..nb) |k| out[leaders + k] = byteAt(limbs, nb - 1 - k);
    return out;
}

fn byteAt(limbs: []const u32, i: usize) u8 {
    return @truncate(limbs[i / 4] >> @intCast(8 * (i % 4)));
}

// ---- data-encoding -------------------------------------------------------------------------

const Encoding = struct {
    bit: u4,
    pad: bool,
    vals: [256]u8,
};

const PAD: u8 = 0x80;

fn encoding(comptime syms: []const u8, comptime translate_from: []const u8, comptime translate_to: []const u8, comptime pad: bool) Encoding {
    @setEvalBranchQuota(10_000);
    var e: Encoding = .{ .bit = std.math.log2_int(usize, syms.len), .pad = pad, .vals = @splat(0xff) };
    for (syms, 0..) |ch, i| e.vals[ch] = i;
    for (translate_from, translate_to) |f, t| e.vals[f] = e.vals[t];
    if (pad) e.vals['='] = PAD;
    return e;
}

const lower_az = "abcdefghijklmnopqrstuvwxyz";
const upper_az = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const b32l = "abcdefghijklmnopqrstuvwxyz234567";
const b32u = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const b32hl = "0123456789abcdefghijklmnopqrstuv";
const b32hu = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
const b64s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const b64u = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const base2 = encoding("01", "", "", false);
const base8 = encoding("01234567", "", "", false);
const hex_lower = encoding("0123456789abcdef", "ABCDEF", "abcdef", false);
const hex_upper = encoding("0123456789ABCDEF", "abcdef", "ABCDEF", false);
const base32_lower = encoding(b32l, upper_az, lower_az, false);
const base32_upper = encoding(b32u, lower_az, upper_az, false);
const base32_pad_lower = encoding(b32l, upper_az, lower_az, true);
const base32_pad_upper = encoding(b32u, lower_az, upper_az, true);
const base32hex_lower = encoding(b32hl, upper_az[0..22], lower_az[0..22], false);
const base32hex_upper = encoding(b32hu, lower_az[0..22], upper_az[0..22], false);
const base32hex_pad_lower = encoding(b32hl, upper_az[0..22], lower_az[0..22], true);
const base32hex_pad_upper = encoding(b32hu, lower_az[0..22], upper_az[0..22], true);
const base32z = encoding("ybndrfg8ejkmcpqxot1uwisza345h769", "", "", false);
const base64 = encoding(b64s, "", "", false);
const base64_pad = encoding(b64s, "", "", true);
const base64url = encoding(b64u, "", "", false);
const base64url_pad = encoding(b64u, "", "", true);
/// data_encoding::BASE32 (onion addresses): upper case only, padded.
const base32_onion = encoding(b32u, "", "", true);

fn decBlock(bit: u4) usize {
    return switch (bit) {
        4 => 2,
        6 => 4,
        else => 8,
    };
}

/// Decodes a run without padding (`decode_base_mut`): length rule, symbols, trailing bits.
fn decodeRun(e: *const Encoding, in: []const u8, out: []u8) ?usize {
    const bit: usize = e.bit;
    if (bit * in.len % 8 >= bit) return null;
    var acc: u32 = 0;
    var nbits: u5 = 0;
    var o: usize = 0;
    for (in) |ch| {
        const v = e.vals[ch];
        if (v >= (@as(u32, 1) << e.bit)) return null;
        acc = (acc << e.bit) | v;
        nbits += e.bit;
        if (nbits >= 8) {
            nbits -= 8;
            out[o] = @truncate(acc >> nbits);
            o += 1;
            acc &= (@as(u32, 1) << nbits) - 1;
        }
    }
    // check_trail: the leftover low bits of the last symbol must be zero
    if (8 % bit != 0 and nbits != 0 and acc != 0) return null;
    return o;
}

/// `Encoding::decode` (data-encoding 2.10), no ignored characters.
pub fn dataDecode(arena: Allocator, e: *const Encoding, in: []const u8) Allocator.Error!?[]u8 {
    const out = try arena.alloc(u8, in.len * e.bit / 8 + 1);
    if (!e.pad) {
        const n = decodeRun(e, in, out) orelse return null;
        return out[0..n];
    }
    const dec = decBlock(e.bit);
    if (in.len % dec != 0) return null;
    var o: usize = 0;
    var i: usize = 0;
    while (i < in.len) : (i += dec) {
        const blk = in[i .. i + dec];
        var cnt: usize = 0;
        while (cnt < dec and e.vals[blk[dec - 1 - cnt]] == PAD) cnt += 1;
        const len = dec - cnt;
        if (len == 0 or e.bit * len % 8 >= e.bit) return null;
        o += decodeRun(e, blk[0..len], out[o..]) orelse return null;
    }
    return out[0..o];
}

// ---- multibase / multihash / PeerId --------------------------------------------------------

/// multibase 0.9.1 `decode`: code character, then that base.
pub fn multibase(arena: Allocator, s: []const u8) Allocator.Error!?[]u8 {
    if (s.len == 0) return null;
    const rest = s[1..];
    return switch (s[0]) {
        0 => try arena.dupe(u8, rest),
        '0' => try dataDecode(arena, &base2, rest),
        '7' => try dataDecode(arena, &base8, rest),
        '9' => try baseX(arena, base10, rest),
        'f' => try dataDecode(arena, &hex_lower, rest),
        'F' => try dataDecode(arena, &hex_upper, rest),
        'b' => try dataDecode(arena, &base32_lower, rest),
        'B' => try dataDecode(arena, &base32_upper, rest),
        'c' => try dataDecode(arena, &base32_pad_lower, rest),
        'C' => try dataDecode(arena, &base32_pad_upper, rest),
        'v' => try dataDecode(arena, &base32hex_lower, rest),
        'V' => try dataDecode(arena, &base32hex_upper, rest),
        't' => try dataDecode(arena, &base32hex_pad_lower, rest),
        'T' => try dataDecode(arena, &base32hex_pad_upper, rest),
        'h' => try dataDecode(arena, &base32z, rest),
        'k' => blk: {
            const l = try arena.dupe(u8, rest);
            for (l) |*ch| ch.* = std.ascii.toLower(ch.*);
            break :blk try baseX(arena, base36_lower, l);
        },
        'K' => blk: {
            const u = try arena.dupe(u8, rest);
            for (u) |*ch| ch.* = std.ascii.toUpper(ch.*);
            break :blk try baseX(arena, base36_upper, u);
        },
        'Z' => try baseX(arena, base58flickr, rest),
        'z' => try baseX(arena, base58btc, rest),
        'm' => try dataDecode(arena, &base64, rest),
        'M' => try dataDecode(arena, &base64_pad, rest),
        'u' => try dataDecode(arena, &base64url, rest),
        'U' => try dataDecode(arena, &base64url_pad, rest),
        else => null,
    };
}

/// unsigned-varint 0.8 `io::read_u64`: at most 10 bytes, a trailing zero byte is not minimal;
/// bits past 64 are dropped like the Rust shift does.
fn varint(b: []const u8, pos: *usize) ?u64 {
    var n: u64 = 0;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        if (pos.* >= b.len) return null;
        const byte = b[pos.*];
        pos.* += 1;
        n |= @as(u64, byte & 0x7f) << @intCast(7 * i);
        if (byte & 0x80 == 0) {
            if (byte == 0 and i > 0) return null;
            return n;
        }
    }
    return null;
}

pub const Multihash = struct { code: u64, digest: []const u8 };

/// `Multihash<64>::from_bytes`.
pub fn multihash(b: []const u8) ?Multihash {
    var pos: usize = 0;
    const code = varint(b, &pos) orelse return null;
    const size = varint(b, &pos) orelse return null;
    if (size > 64) return null;
    if (b.len - pos != size) return null;
    return .{ .code = code, .digest = b[pos..] };
}

/// libp2p-identity 0.2 `PeerId::from_bytes`.
pub fn peerId(b: []const u8) bool {
    const mh = multihash(b) orelse return false;
    return mh.code == 0x12 or (mh.code == 0 and mh.digest.len <= 42);
}

// ---- onion, percent-decoding ---------------------------------------------------------------

/// `read_onion(&s.to_uppercase())` / `read_onion3`, accept or reject.
fn onion(arena: Allocator, s: []const u8, comptime b32_len: usize) Allocator.Error!bool {
    // Full Unicode upper-casing only matters where it yields ASCII; any other non-ASCII
    // character leaves a non-ASCII byte that every later step rejects.
    const up = try arena.alloc(u8, s.len * 3);
    var n: usize = 0;
    var view = std.unicode.Utf8View.initUnchecked(s);
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        const rep: []const u8 = switch (cp) {
            'a'...'z' => &.{@intCast(cp - 32)},
            0...'a' - 1, 'z' + 1...0x7f => &.{@intCast(cp)},
            0x131 => "I",
            0x17f => "S",
            0xdf => "SS",
            0xfb00 => "FF",
            0xfb01 => "FI",
            0xfb02 => "FL",
            0xfb03 => "FFI",
            0xfb04 => "FFL",
            0xfb05, 0xfb06 => "ST",
            else => return false,
        };
        @memcpy(up[n..][0..rep.len], rep);
        n += rep.len;
    }
    var parts = std.mem.splitScalar(u8, up[0..n], ':');
    const b32 = parts.first();
    if (b32.len != b32_len) return false;
    const port = parts.next() orelse return false;
    const pv = parseUint(u16, port) orelse return false;
    if (pv == 0) return false;
    if (parts.next() != null) return false;
    return (try dataDecode(arena, &base32_onion, b32)) != null;
}

fn percentUtf8(arena: Allocator, s: []const u8) Allocator.Error!bool {
    const out = try arena.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '%' and i + 2 < s.len) {
            const h = std.fmt.charToDigit(s[i + 1], 16) catch null;
            const l = std.fmt.charToDigit(s[i + 2], 16) catch null;
            if (h != null and l != null) {
                out[n] = h.? * 16 + l.?;
                n += 1;
                i += 3;
                continue;
            }
        }
        out[n] = s[i];
        n += 1;
        i += 1;
    }
    return std.unicode.utf8ValidateSlice(out[0..n]);
}

test "multiaddr basics" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const P = struct {
        fn ok(ar2: Allocator, s: []const u8) !?Parsed {
            return parse(ar2, s);
        }
    };
    try std.testing.expect((try P.ok(ar, "/ip4/1.2.3.4/udp/8080")).?.anemo());
    try std.testing.expect((try P.ok(ar, "/dns/a.b/udp/+1/http")).?.anemo());
    try std.testing.expect(!(try P.ok(ar, "/dns4/a.b/udp/1")).?.anemo());
    try std.testing.expect((try P.ok(ar, "")) != null);
    try std.testing.expect((try P.ok(ar, "/")) == null);
    try std.testing.expect((try P.ok(ar, "/ip4/01.2.3.4")) == null);
    try std.testing.expect((try P.ok(ar, "/ip6/::ffff:1.2.3.4/udp/1")).?.anemo());
    try std.testing.expect((try P.ok(ar, "/ip6/1::2::3")) == null);
    try std.testing.expect((try P.ok(ar, "/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")) != null);
    try std.testing.expect((try P.ok(ar, "/onion/aaimaq4ygg2iegci:80")) != null);
    try std.testing.expect((try P.ok(ar, "/onion/aaimaq4ygg2iegci:0")) == null);
}
