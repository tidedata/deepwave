//! Text helpers for the admin port (admin.zig) that reproduce what sui-node 1.83.1's Rust
//! dependencies print or accept, std-only so they unit-test alone (`zig test admin_util.zig`):
//!
//!   query strings     axum `Query<T>` over serde_urlencoded (form decoding, Rust int/bool/f64
//!                     parse errors as serde_path_to_error prints them)
//!   `{:?}`            Rust Debug of a `String`, an `f64` and a `std::time::Duration`
//!   durations         humantime 2.1.0 `parse_duration` (what `/enable-tracing?duration=` takes)
//!   hex               fastcrypto `Hex::decode` (optional "0x", hex crate rules)
//!   base58            bs58 decode to a vector (sui-types `digest_from_base58`, multibase p2p)
//!   multiaddr         multiaddr 0.18.2 `Multiaddr::from_str` and its error Display
//!   io errors         Rust `std::io::Error` Debug for an `open` failure
const std = @import("std");
const Writer = std.Io.Writer;

// ------------------------------------------------------------------ query strings

/// application/x-www-form-urlencoded decoding ('+' is a space, %XX a byte).
pub fn formDecode(arena: std.mem.Allocator, s: []const u8) ![]const u8 {
    if (std.mem.indexOfAny(u8, s, "+%") == null) return s;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '+') {
            try out.append(arena, ' ');
        } else if (s[i] == '%' and i + 2 < s.len and std.ascii.isHex(s[i + 1]) and std.ascii.isHex(s[i + 2])) {
            try out.append(arena, std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch unreachable);
            i += 2;
        } else try out.append(arena, s[i]);
    }
    return out.items;
}

pub const Pair = struct { key: []const u8, value: []const u8 };

/// The decoded `key=value` pairs of a query string in order (form_urlencoded::parse: empty
/// segments are skipped, a segment without '=' is a key with an empty value).
pub fn pairs(arena: std.mem.Allocator, query: []const u8) ![]const Pair {
    var out: std.ArrayList(Pair) = .empty;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |kv| {
        if (kv.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, kv, '=');
        try out.append(arena, .{
            .key = try formDecode(arena, if (eq) |i| kv[0..i] else kv),
            .value = try formDecode(arena, if (eq) |i| kv[i + 1 ..] else ""),
        });
    }
    return out.items;
}

/// axum's `Query` rejection prefix (400).
pub const query_reject = "Failed to deserialize query string: ";

pub const IntError = error{ Empty, Invalid, Overflow };

/// Rust `uN::from_str` (a leading '+' is allowed).
pub fn parseUint(comptime T: type, s0: []const u8) IntError!T {
    if (s0.len == 0) return error.Empty;
    const s = if (s0[0] == '+') s0[1..] else s0;
    if (s.len == 0) return error.Invalid;
    var n: T = 0;
    for (s) |ch| {
        if (ch < '0' or ch > '9') return error.Invalid;
        n = std.math.mul(T, n, 10) catch return error.Overflow;
        n = std.math.add(T, n, ch - '0') catch return error.Overflow;
    }
    return n;
}

/// `ParseIntError` Display.
pub fn intErrorText(e: IntError) []const u8 {
    return switch (e) {
        error.Empty => "cannot parse integer from empty string",
        error.Invalid => "invalid digit found in string",
        error.Overflow => "number too large to fit in target type",
    };
}

/// serde_urlencoded's bool (`provided string was not `true` or `false``).
pub fn parseBool(s: []const u8) ?bool {
    if (std.mem.eql(u8, s, "true")) return true;
    if (std.mem.eql(u8, s, "false")) return false;
    return null;
}
pub const bool_error = "provided string was not `true` or `false`";

pub const FloatError = error{ Empty, Invalid };

/// Rust `f64::from_str`: optional sign, then `inf`/`infinity`/`nan` (any case) or a decimal
/// with an optional exponent (`.5`, `5.`, `1e-3`); no hex, no underscores.
pub fn parseF64(s: []const u8) FloatError!f64 {
    if (s.len == 0) return error.Empty;
    var i: usize = 0;
    var neg = false;
    if (s[0] == '+' or s[0] == '-') {
        neg = s[0] == '-';
        i = 1;
    }
    const body = s[i..];
    if (std.ascii.eqlIgnoreCase(body, "inf") or std.ascii.eqlIgnoreCase(body, "infinity"))
        return if (neg) -std.math.inf(f64) else std.math.inf(f64);
    if (std.ascii.eqlIgnoreCase(body, "nan")) return std.math.nan(f64);
    var j: usize = 0;
    var int_digits: usize = 0;
    while (j < body.len and std.ascii.isDigit(body[j])) : (j += 1) int_digits += 1;
    var frac_digits: usize = 0;
    if (j < body.len and body[j] == '.') {
        j += 1;
        while (j < body.len and std.ascii.isDigit(body[j])) : (j += 1) frac_digits += 1;
    }
    if (int_digits + frac_digits == 0) return error.Invalid;
    if (j < body.len and (body[j] == 'e' or body[j] == 'E')) {
        j += 1;
        if (j < body.len and (body[j] == '+' or body[j] == '-')) j += 1;
        var exp_digits: usize = 0;
        while (j < body.len and std.ascii.isDigit(body[j])) : (j += 1) exp_digits += 1;
        if (exp_digits == 0) return error.Invalid;
    }
    if (j != body.len) return error.Invalid;
    const v = std.fmt.parseFloat(f64, body) catch return error.Invalid;
    return if (neg) -v else v;
}

/// `ParseFloatError` Display.
pub fn floatErrorText(e: FloatError) []const u8 {
    return switch (e) {
        error.Empty => "cannot parse float from empty string",
        error.Invalid => "invalid float literal",
    };
}

// ------------------------------------------------------------------ Rust Debug

/// `{:?}` of a `str`/`String`: double quotes, `\"` `\\` `\n` `\r` `\t` `\0`, other control
/// characters as `\u{..}`; a single quote and printable UTF-8 are written as is.
pub fn writeStrDebug(w: *Writer, s: []const u8) Writer.Error!void {
    try w.writeByte('"');
    for (s) |ch| switch (ch) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0 => try w.writeAll("\\0"),
        1...8, 11, 12, 14...31, 127 => try w.print("\\u{{{x}}}", .{ch}),
        else => try w.writeByte(ch),
    };
    try w.writeByte('"');
}

/// `{:?}` of an `f64` (Rust's `float_to_general_debug`): shortest round-trip digits, decimal
/// with at least one fractional digit for 1e-4 <= |x| < 1e16 (and zero), else exponential
/// (`1e-5`, `1.5e16`); `NaN`, `inf`, `-inf`.
pub fn writeF64Debug(w: *Writer, x: f64) Writer.Error!void {
    if (std.math.isNan(x)) return w.writeAll("NaN");
    if (std.math.isInf(x)) return w.writeAll(if (x < 0) "-inf" else "inf");
    const neg = std.math.signbit(x);
    const a = @abs(x);
    var buf: [64]u8 = undefined;
    if (a == 0 or (a >= 1e-4 and a < 1e16)) {
        const t = std.fmt.bufPrint(&buf, "{d}", .{a}) catch unreachable;
        if (neg) try w.writeByte('-');
        try w.writeAll(t);
        if (std.mem.indexOfScalar(u8, t, '.') == null) try w.writeAll(".0");
        return;
    }
    const t = std.fmt.bufPrint(&buf, "{e}", .{a}) catch unreachable;
    const e = std.mem.indexOfAny(u8, t, "eE") orelse {
        if (neg) try w.writeByte('-');
        return w.writeAll(t);
    };
    var mant = t[0..e];
    // "1.0e5" -> "1e5": Rust writes no fractional part for a one-digit mantissa
    if (std.mem.endsWith(u8, mant, ".0")) mant = mant[0 .. mant.len - 2];
    var exp = t[e + 1 ..];
    var exp_neg = false;
    if (exp.len > 0 and (exp[0] == '+' or exp[0] == '-')) {
        exp_neg = exp[0] == '-';
        exp = exp[1..];
    }
    while (exp.len > 1 and exp[0] == '0') exp = exp[1..];
    if (neg) try w.writeByte('-');
    try w.writeAll(mant);
    try w.writeByte('e');
    if (exp_neg) try w.writeByte('-');
    try w.writeAll(exp);
}

pub const Duration = struct {
    secs: u64,
    nanos: u32,
};

/// `{:?}` of a `std::time::Duration`: `10s`, `1.5s`, `100ms`, `1.5µs`, `7ns` (no precision:
/// every nonzero fractional digit, trailing zeros dropped).
pub fn writeDurationDebug(w: *Writer, d: Duration) Writer.Error!void {
    if (d.secs > 0) return fmtDecimal(w, d.secs, d.nanos, 100_000_000, "s");
    if (d.nanos >= 1_000_000) return fmtDecimal(w, d.nanos / 1_000_000, d.nanos % 1_000_000, 100_000, "ms");
    if (d.nanos >= 1_000) return fmtDecimal(w, d.nanos / 1_000, d.nanos % 1_000, 100, "\u{b5}s");
    return fmtDecimal(w, d.nanos, 0, 1, "ns");
}

fn fmtDecimal(w: *Writer, int: u64, frac0: u32, div0: u32, suffix: []const u8) Writer.Error!void {
    try w.print("{d}", .{int});
    var frac = frac0;
    var div = div0;
    if (frac > 0) {
        try w.writeByte('.');
        var n: usize = 0;
        while (frac > 0 and n < 9 and div > 0) : (n += 1) {
            try w.writeByte('0' + @as(u8, @intCast(frac / div)));
            frac %= div;
            div /= 10;
        }
    }
    try w.writeAll(suffix);
}

// ------------------------------------------------------------------ humantime 2.1.0

/// Rust `char::is_whitespace` (White_Space property).
fn isRustWhitespace(c: u21) bool {
    return switch (c) {
        '\t', '\n', 0x0b, 0x0c, '\r', ' ', 0x85, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
        else => false,
    };
}

const Chars = struct {
    s: []const u8,
    i: usize = 0,
    fn next(c: *Chars) ?u21 {
        if (c.i >= c.s.len) return null;
        const n = std.unicode.utf8ByteSequenceLength(c.s[c.i]) catch {
            c.i += 1;
            return 0xfffd;
        };
        if (c.i + n > c.s.len) {
            c.i = c.s.len;
            return 0xfffd;
        }
        const cp = std.unicode.utf8Decode(c.s[c.i..][0..n]) catch 0xfffd;
        c.i += n;
        return cp;
    }
};

pub const DurationError = error{ InvalidCharacter, NumberExpected, UnknownUnit, NumberOverflow, Empty };

/// humantime::parse_duration (2.1.0, what sui-node's admin uses): one or more `<number><unit>`
/// groups, whitespace allowed between and inside them (`1h 30m`, `1h30m`, `10 s`); integers only.
/// Units: nanos nsec ns, usec us, millis msec ms, seconds second secs sec s, minutes minute min
/// mins m, hours hour hr hrs h, days day d, weeks week w, months month M (30.44 d), years year y
/// (365.25 d).
pub fn parseDuration(src: []const u8) DurationError!Duration {
    var it: Chars = .{ .s = src };
    var cur_s: u64 = 0;
    var cur_ns: u64 = 0;
    var n: u64 = (try firstDigit(&it)) orelse return error.Empty;
    outer: while (true) {
        var off = it.i;
        while (it.next()) |c| {
            switch (c) {
                '0'...'9' => {
                    n = std.math.mul(u64, n, 10) catch return error.NumberOverflow;
                    n = std.math.add(u64, n, c - '0') catch return error.NumberOverflow;
                },
                'a'...'z', 'A'...'Z' => break,
                else => if (!isRustWhitespace(c)) return error.InvalidCharacter,
            }
            off = it.i;
        }
        const start = off;
        off = it.i;
        while (it.next()) |c| {
            switch (c) {
                '0'...'9' => {
                    try addUnit(&cur_s, &cur_ns, n, src[start..off]);
                    n = c - '0';
                    continue :outer;
                },
                'a'...'z', 'A'...'Z' => {},
                else => if (isRustWhitespace(c)) break else return error.InvalidCharacter,
            }
            off = it.i;
        }
        try addUnit(&cur_s, &cur_ns, n, src[start..off]);
        n = (try firstDigit(&it)) orelse {
            // Duration::new(secs, nanos): nanos of exactly 1e9 carry into the seconds
            const s = std.math.add(u64, cur_s, cur_ns / 1_000_000_000) catch return error.NumberOverflow;
            return .{ .secs = s, .nanos = @intCast(cur_ns % 1_000_000_000) };
        };
    }
}

fn firstDigit(it: *Chars) DurationError!?u64 {
    while (it.next()) |c| {
        if (c >= '0' and c <= '9') return c - '0';
        if (isRustWhitespace(c)) continue;
        return error.NumberExpected;
    }
    return null;
}

fn addUnit(cur_s: *u64, cur_ns: *u64, n: u64, unit: []const u8) DurationError!void {
    const eql = std.mem.eql;
    const Mul = struct { s: u64, ns: u64 };
    const m: Mul = if (eql(u8, unit, "nanos") or eql(u8, unit, "nsec") or eql(u8, unit, "ns")) .{ .s = 0, .ns = 1 } else if (eql(u8, unit, "usec") or eql(u8, unit, "us")) .{ .s = 0, .ns = 1000 } else if (eql(u8, unit, "millis") or eql(u8, unit, "msec") or eql(u8, unit, "ms")) .{ .s = 0, .ns = 1_000_000 } else if (eql(u8, unit, "seconds") or eql(u8, unit, "second") or eql(u8, unit, "secs") or eql(u8, unit, "sec") or eql(u8, unit, "s")) .{ .s = 1, .ns = 0 } else if (eql(u8, unit, "minutes") or eql(u8, unit, "minute") or eql(u8, unit, "min") or eql(u8, unit, "mins") or eql(u8, unit, "m")) .{ .s = 60, .ns = 0 } else if (eql(u8, unit, "hours") or eql(u8, unit, "hour") or eql(u8, unit, "hr") or eql(u8, unit, "hrs") or eql(u8, unit, "h")) .{ .s = 3600, .ns = 0 } else if (eql(u8, unit, "days") or eql(u8, unit, "day") or eql(u8, unit, "d")) .{ .s = 86400, .ns = 0 } else if (eql(u8, unit, "weeks") or eql(u8, unit, "week") or eql(u8, unit, "w")) .{ .s = 86400 * 7, .ns = 0 } else if (eql(u8, unit, "months") or eql(u8, unit, "month") or eql(u8, unit, "M")) .{ .s = 2_630_016, .ns = 0 } else if (eql(u8, unit, "years") or eql(u8, unit, "year") or eql(u8, unit, "y")) .{ .s = 31_557_600, .ns = 0 } else return error.UnknownUnit;
    var sec = std.math.mul(u64, n, m.s) catch return error.NumberOverflow;
    const ns_add = std.math.mul(u64, n, m.ns) catch return error.NumberOverflow;
    var ns = std.math.add(u64, cur_ns.*, ns_add) catch return error.NumberOverflow;
    if (ns > 1_000_000_000) {
        sec = std.math.add(u64, sec, ns / 1_000_000_000) catch return error.NumberOverflow;
        ns %= 1_000_000_000;
    }
    cur_s.* = std.math.add(u64, cur_s.*, sec) catch return error.NumberOverflow;
    cur_ns.* = ns;
}

pub fn durationNs(d: Duration) u128 {
    return @as(u128, d.secs) * std.time.ns_per_s + d.nanos;
}

// ------------------------------------------------------------------ hex, base58

/// fastcrypto `Hex::decode`: an optional "0x" prefix, then the hex crate (even length, either
/// case). Null on any error (Display "Invalid value was given to the function").
pub fn hexDecode(arena: std.mem.Allocator, s0: []const u8) !?[]u8 {
    const s = if (std.mem.startsWith(u8, s0, "0x")) s0[2..] else s0;
    if (s.len % 2 != 0) return null;
    const out = try arena.alloc(u8, s.len / 2);
    _ = std.fmt.hexToBytes(out, s) catch return null;
    return out;
}
pub const fastcrypto_invalid_input = "Invalid value was given to the function";

const b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// bs58 decode (Bitcoin alphabet) to bytes; null for a character outside the alphabet.
pub fn b58Decode(arena: std.mem.Allocator, text: []const u8) !?[]u8 {
    var out: std.ArrayList(u8) = .empty; // little-endian accumulator
    for (text) |ch| {
        const d = std.mem.indexOfScalar(u8, b58_alphabet, ch) orelse return null;
        var val: u32 = @intCast(d);
        for (out.items) |*b| {
            val += @as(u32, b.*) * 58;
            b.* = @truncate(val);
            val >>= 8;
        }
        while (val > 0) {
            try out.append(arena, @truncate(val));
            val >>= 8;
        }
    }
    for (text) |ch| {
        if (ch != '1') break;
        try out.append(arena, 0);
    }
    std.mem.reverse(u8, out.items);
    return out.items;
}

/// bs58 encode of a 32-byte digest (the Display form of every Sui digest).
pub fn b58Encode(out: *[64]u8, d: *const [32]u8) []const u8 {
    var digits: [64]u8 = undefined; // little-endian base-58 digits
    var n: usize = 0;
    for (d) |byte| {
        var carry: u32 = byte;
        for (digits[0..n]) |*x| {
            carry += @as(u32, x.*) << 8;
            x.* = @intCast(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            digits[n] = @intCast(carry % 58);
            n += 1;
            carry /= 58;
        }
    }
    var len: usize = 0;
    for (d) |byte| {
        if (byte != 0) break;
        out[len] = '1';
        len += 1;
    }
    var i = n;
    while (i > 0) {
        i -= 1;
        out[len] = b58_alphabet[digits[i]];
        len += 1;
    }
    return out[0..len];
}

/// sui-types `digest_from_base58`: exactly 32 decoded bytes.
pub fn digestFromBase58(text: []const u8) ?[32]u8 {
    var buf: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    if (text.len > 128) return null;
    const b = (b58Decode(fba.allocator(), text) catch return null) orelse return null;
    if (b.len != 32) return null;
    return b[0..32].*;
}

// ------------------------------------------------------------------ multiaddr 0.18.2

pub const Proto = enum { ip4, ip6, dns, dns4, dns6, udp, other };

pub const MaComponent = struct { proto: Proto, value: []const u8 = "" };

pub const Multiaddr = struct {
    /// The first two components (`to_anemo_address` looks at no more).
    first: ?MaComponent = null,
    second: ?MaComponent = null,

    /// `Multiaddr::to_anemo_address`: `/ip4/A/udp/P`, `/ip6/A/udp/P` or `/dns/H/udp/P`, later
    /// components ignored.
    pub fn isAnemo(m: *const Multiaddr) bool {
        const a = m.first orelse return false;
        const b = m.second orelse return false;
        return b.proto == .udp and (a.proto == .ip4 or a.proto == .ip6 or a.proto == .dns);
    }
};

/// `Multiaddr::from_str`. On error `err` holds the Display text (multiaddr `Error`).
pub fn parseMultiaddr(arena: std.mem.Allocator, input: []const u8, err: *[]const u8) !?Multiaddr {
    var parts = std.mem.splitScalar(u8, input, '/');
    if (!std.mem.eql(u8, parts.next() orelse "", "")) {
        err.* = "invalid multiaddr";
        return null;
    }
    var m: Multiaddr = .{};
    var idx: usize = 0;
    while (parts.peek() != null) : (idx += 1) {
        const c = (try component(arena, &parts, err)) orelse return null;
        if (idx == 0) m.first = c else if (idx == 1) m.second = c;
    }
    return m;
}

const invalid_proto = "invalid protocol string";

fn component(arena: std.mem.Allocator, parts: *std.mem.SplitIterator(u8, .scalar), err: *[]const u8) !?MaComponent {
    const name = parts.next().?;
    const eql = std.mem.eql;
    const no_arg = [_][]const u8{ "tls", "noise", "udt", "utp", "http", "https", "quic", "quic-v1", "webtransport", "ws", "wss", "p2p-websocket-star", "p2p-webrtc-star", "webrtc-direct", "p2p-webrtc-direct", "p2p-circuit", "p2p-stardust", "webrtc" };
    for (no_arg) |p| if (eql(u8, name, p)) return .{ .proto = .other };
    const known_arg = [_][]const u8{ "ip4", "tcp", "udp", "dccp", "ip6", "dns", "dns4", "dns6", "dnsaddr", "sctp", "unix", "p2p", "ipfs", "onion", "onion3", "x-parity-ws", "x-parity-wss", "certhash", "memory", "ip6zone", "ipcidr", "garlic64", "garlic32", "sni" };
    var known = false;
    for (known_arg) |p| known = known or eql(u8, name, p);
    if (!known) {
        err.* = try std.fmt.allocPrint(arena, "unknown protocol string: {s}", .{name});
        return null;
    }
    const v = parts.next() orelse {
        err.* = invalid_proto;
        return null;
    };
    if (eql(u8, name, "ip4")) {
        _ = std.Io.net.Ip4Address.parse(v, 0) catch {
            err.* = "failed to parse: invalid IPv4 address syntax";
            return null;
        };
        return .{ .proto = .ip4, .value = v };
    }
    if (eql(u8, name, "ip6")) {
        _ = std.Io.net.Ip6Address.parse(v, 0) catch {
            err.* = "failed to parse: invalid IPv6 address syntax";
            return null;
        };
        return .{ .proto = .ip6, .value = v };
    }
    if (eql(u8, name, "tcp") or eql(u8, name, "udp") or eql(u8, name, "dccp") or eql(u8, name, "sctp")) {
        _ = parseUint(u16, v) catch |e| {
            err.* = try std.fmt.allocPrint(arena, "failed to parse: {s}", .{intErrorText(e)});
            return null;
        };
        return .{ .proto = if (eql(u8, name, "udp")) .udp else .other, .value = v };
    }
    if (eql(u8, name, "memory") or eql(u8, name, "ipcidr")) {
        const r: IntError!void = if (eql(u8, name, "memory")) (if (parseUint(u64, v)) |_| {} else |e| e) else (if (parseUint(u8, v)) |_| {} else |e| e);
        r catch |e| {
            err.* = try std.fmt.allocPrint(arena, "failed to parse: {s}", .{intErrorText(e)});
            return null;
        };
        return .{ .proto = .other, .value = v };
    }
    if (eql(u8, name, "dns")) return .{ .proto = .dns, .value = v };
    if (eql(u8, name, "dns4")) return .{ .proto = .dns4, .value = v };
    if (eql(u8, name, "dns6")) return .{ .proto = .dns6, .value = v };
    if (eql(u8, name, "p2p") or eql(u8, name, "ipfs")) {
        const b = (try b58Decode(arena, v)) orelse {
            err.* = "failed to parse: Invalid base string";
            return null;
        };
        // libp2p PeerId::from_bytes: a multihash (code, size, digest; nothing after), sha2-256
        // or identity of at most 42 bytes
        var r: usize = 0;
        const code = uvarint(b, &r) orelse return invalidMultihash(err);
        const size = uvarint(b, &r) orelse return invalidMultihash(err);
        if (size > 64 or b.len - r != size) return invalidMultihash(err);
        if (!(code == 0x12 or (code == 0 and size <= 42))) {
            err.* = try std.fmt.allocPrint(arena, "failed to parse: unsupported multihash code '{d}'", .{code});
            return null;
        }
        return .{ .proto = .other, .value = v };
    }
    if (eql(u8, name, "garlic64") and (v.len < 516 or v.len > 616)) {
        err.* = invalid_proto;
        return null;
    }
    if (eql(u8, name, "garlic32") and v.len < 55 and v.len != 52) {
        err.* = invalid_proto;
        return null;
    }
    // dnsaddr, unix, ip6zone, sni: any text. onion, onion3, certhash, x-parity-ws(s), garlic:
    // accepted without decoding their value (deepwave gap; never seen in Sui p2p addresses).
    return .{ .proto = .other, .value = v };
}

fn invalidMultihash(err: *[]const u8) ?MaComponent {
    err.* = "failed to parse: invalid multihash";
    return null;
}

/// unsigned-varint u64 (at most 10 bytes, no trailing zero byte).
fn uvarint(b: []const u8, r: *usize) ?u64 {
    var v: u64 = 0;
    var shift: u7 = 0;
    var n: usize = 0;
    while (r.* < b.len and n < 10) : (n += 1) {
        const byte = b[r.*];
        r.* += 1;
        if (shift == 63 and byte > 1) return null;
        v |= @as(u64, byte & 0x7f) << @intCast(shift);
        if (byte & 0x80 == 0) {
            if (byte == 0 and n > 0) return null; // not minimal
            return v;
        }
        shift += 7;
    }
    return null;
}

// ------------------------------------------------------------------ io errors

/// Rust `{:?}` of the `std::io::Error` an `open` failed with: `Os { code: N, kind: K, message: "..." }`
/// (`name`: the errno's `std.c.E` tag; glibc texts, as on the Linux hosts sui-node runs on).
pub fn writeIoErrorDebug(w: *Writer, code: i32, name: []const u8) Writer.Error!void {
    const E = struct { name: []const u8, kind: []const u8, msg: []const u8 };
    const table = [_]E{
        .{ .name = "PERM", .kind = "PermissionDenied", .msg = "Operation not permitted" },
        .{ .name = "NOENT", .kind = "NotFound", .msg = "No such file or directory" },
        .{ .name = "IO", .kind = "Uncategorized", .msg = "Input/output error" },
        .{ .name = "ACCES", .kind = "PermissionDenied", .msg = "Permission denied" },
        .{ .name = "EXIST", .kind = "AlreadyExists", .msg = "File exists" },
        .{ .name = "NOTDIR", .kind = "NotADirectory", .msg = "Not a directory" },
        .{ .name = "ISDIR", .kind = "IsADirectory", .msg = "Is a directory" },
        .{ .name = "INVAL", .kind = "InvalidInput", .msg = "Invalid argument" },
        .{ .name = "NFILE", .kind = "Uncategorized", .msg = "Too many open files in system" },
        .{ .name = "MFILE", .kind = "Uncategorized", .msg = "Too many open files" },
        .{ .name = "TXTBSY", .kind = "ExecutableFileBusy", .msg = "Text file busy" },
        .{ .name = "NOSPC", .kind = "StorageFull", .msg = "No space left on device" },
        .{ .name = "ROFS", .kind = "ReadOnlyFilesystem", .msg = "Read-only file system" },
        .{ .name = "NAMETOOLONG", .kind = "InvalidFilename", .msg = "File name too long" },
        .{ .name = "LOOP", .kind = "FilesystemLoop", .msg = "Too many levels of symbolic links" },
        .{ .name = "DQUOT", .kind = "QuotaExceeded", .msg = "Disk quota exceeded" },
    };
    for (table) |e| if (std.mem.eql(u8, e.name, name))
        return w.print("Os {{ code: {d}, kind: {s}, message: \"{s}\" }}", .{ code, e.kind, e.msg });
    try w.print("Os {{ code: {d}, kind: Uncategorized, message: \"Unknown error {d}\" }}", .{ code, code });
}

/// Rust's error for a path with a NUL byte (`run_path_with_cstr`), as `{:?}` prints it.
pub const nul_path_debug = "Error { kind: InvalidInput, message: \"file name contained an unexpected NUL byte\" }";

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn debugF64(x: f64) ![]const u8 {
    const S = struct {
        var buf: [64]u8 = undefined;
    };
    var w: Writer = .fixed(&S.buf);
    try writeF64Debug(&w, x);
    return w.buffered();
}

test "admin_util: f64 and Duration Debug as Rust prints them" {
    try testing.expectEqualStrings("0.5", try debugF64(0.5));
    try testing.expectEqualStrings("1.0", try debugF64(1.0));
    try testing.expectEqualStrings("0.0", try debugF64(0.0));
    try testing.expectEqualStrings("-0.0", try debugF64(-0.0));
    try testing.expectEqualStrings("0.0001", try debugF64(0.0001));
    try testing.expectEqualStrings("1e-5", try debugF64(0.00001));
    try testing.expectEqualStrings("1.5e-7", try debugF64(1.5e-7));
    try testing.expectEqualStrings("1e16", try debugF64(1e16));
    try testing.expectEqualStrings("1.5e20", try debugF64(1.5e20));
    try testing.expectEqualStrings("1000000000000000.0", try debugF64(1e15));
    try testing.expectEqualStrings("0.1", try debugF64(0.1));
    try testing.expectEqualStrings("NaN", try debugF64(std.math.nan(f64)));
    try testing.expectEqualStrings("-inf", try debugF64(-std.math.inf(f64)));
    var buf: [64]u8 = undefined;
    const cases = [_]struct { d: Duration, s: []const u8 }{
        .{ .d = .{ .secs = 10, .nanos = 0 }, .s = "10s" },
        .{ .d = .{ .secs = 1, .nanos = 500_000_000 }, .s = "1.5s" },
        .{ .d = .{ .secs = 0, .nanos = 100_000_000 }, .s = "100ms" },
        .{ .d = .{ .secs = 0, .nanos = 1_500_000 }, .s = "1.5ms" },
        .{ .d = .{ .secs = 0, .nanos = 1_500 }, .s = "1.5\u{b5}s" },
        .{ .d = .{ .secs = 0, .nanos = 7 }, .s = "7ns" },
        .{ .d = .{ .secs = 0, .nanos = 0 }, .s = "0ns" },
        .{ .d = .{ .secs = 3600, .nanos = 1 }, .s = "3600.000000001s" },
    };
    for (cases) |c| {
        var w: Writer = .fixed(&buf);
        try writeDurationDebug(&w, c.d);
        try testing.expectEqualStrings(c.s, w.buffered());
    }
    var w: Writer = .fixed(&buf);
    try writeStrDebug(&w, "a\"b\\c\n'\x01");
    try testing.expectEqualStrings("\"a\\\"b\\\\c\\n'\\u{1}\"", w.buffered());
}

test "admin_util: humantime parse_duration" {
    const ok = [_]struct { s: []const u8, secs: u64, nanos: u32 }{
        .{ .s = "10s", .secs = 10, .nanos = 0 },
        .{ .s = "1h 30m", .secs = 5400, .nanos = 0 },
        .{ .s = "1h30m", .secs = 5400, .nanos = 0 },
        .{ .s = "10 s", .secs = 10, .nanos = 0 },
        .{ .s = " 1 0s", .secs = 10, .nanos = 0 },
        .{ .s = "1500ms", .secs = 1, .nanos = 500_000_000 },
        .{ .s = "1M", .secs = 2_630_016, .nanos = 0 },
        .{ .s = "2min", .secs = 120, .nanos = 0 },
        .{ .s = "1000000000ns", .secs = 1, .nanos = 0 },
        .{ .s = "999ms 1000ms", .secs = 1, .nanos = 999_000_000 },
    };
    for (ok) |c| {
        const d = try parseDuration(c.s);
        try testing.expectEqual(c.secs, d.secs);
        try testing.expectEqual(c.nanos, d.nanos);
    }
    try testing.expectError(error.Empty, parseDuration(""));
    try testing.expectError(error.Empty, parseDuration("   "));
    try testing.expectError(error.UnknownUnit, parseDuration("10"));
    try testing.expectError(error.UnknownUnit, parseDuration("10x"));
    try testing.expectError(error.InvalidCharacter, parseDuration("1.5s"));
    try testing.expectError(error.NumberExpected, parseDuration("s"));
    try testing.expectError(error.NumberExpected, parseDuration("10s x"));
    try testing.expectError(error.NumberOverflow, parseDuration("99999999999999999999s"));
}

test "admin_util: query, ints, floats, hex, base58, multiaddr" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const p = try pairs(a, "filter=info%2Czui%3Ddebug&&duration=10+s&flag");
    try testing.expectEqual(@as(usize, 3), p.len);
    try testing.expectEqualStrings("info,zui=debug", p[0].value);
    try testing.expectEqualStrings("10 s", p[1].value);
    try testing.expectEqualStrings("flag", p[2].key);
    try testing.expectEqualStrings("", p[2].value);
    try testing.expectEqual(@as(u64, 5), try parseUint(u64, "+5"));
    try testing.expectError(error.Invalid, parseUint(u64, "-5"));
    try testing.expectError(error.Empty, parseUint(u64, ""));
    try testing.expectError(error.Overflow, parseUint(u32, "4294967296"));
    try testing.expectEqual(@as(f64, 0.5), try parseF64("0.5"));
    try testing.expectEqual(@as(f64, 0.5), try parseF64(".5"));
    try testing.expectEqual(@as(f64, 5), try parseF64("5."));
    try testing.expectEqual(@as(f64, 1e-3), try parseF64("1e-3"));
    try testing.expect(std.math.isInf(try parseF64("-Infinity")));
    try testing.expectError(error.Invalid, parseF64("1_0"));
    try testing.expectError(error.Invalid, parseF64("0x10"));
    try testing.expectError(error.Invalid, parseF64("."));
    try testing.expectError(error.Invalid, parseF64("1e"));
    try testing.expectError(error.Empty, parseF64(""));
    try testing.expectEqualSlices(u8, &.{ 0xab, 0xcd }, (try hexDecode(a, "0xABcd")).?);
    try testing.expect((try hexDecode(a, "abc")) == null);
    try testing.expect((try hexDecode(a, "zz")) == null);
    try testing.expectEqual(@as(usize, 0), (try hexDecode(a, "")).?.len);
    // base58: leading '1's are zero bytes
    try testing.expectEqualSlices(u8, &.{ 0, 0, 1 }, (try b58Decode(a, "112")).?);
    const dg = digestFromBase58("4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S").?;
    var eb: [64]u8 = undefined;
    try testing.expectEqualStrings("4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S", b58Encode(&eb, &dg));
    try testing.expectEqualStrings("11111111111111111111111111111111", b58Encode(&eb, &@as([32]u8, @splat(0))));
    try testing.expect(digestFromBase58("2") == null);
    try testing.expect(digestFromBase58("0OIl") == null);
    var err: []const u8 = "";
    const m = (try parseMultiaddr(a, "/ip4/1.2.3.4/udp/8084", &err)).?;
    try testing.expect(m.isAnemo());
    const t = (try parseMultiaddr(a, "/ip4/1.2.3.4/tcp/8080/http", &err)).?;
    try testing.expect(!t.isAnemo());
    try testing.expect((try parseMultiaddr(a, "/dns4/x.io/udp/1", &err)).?.isAnemo() == false);
    try testing.expect((try parseMultiaddr(a, "/dns/x.io/udp/1", &err)).?.isAnemo());
    try testing.expect((try parseMultiaddr(a, "1.2.3.4:80", &err)) == null);
    try testing.expectEqualStrings("invalid multiaddr", err);
    try testing.expect((try parseMultiaddr(a, "/ip4/1.2.3", &err)) == null);
    try testing.expectEqualStrings("failed to parse: invalid IPv4 address syntax", err);
    try testing.expect((try parseMultiaddr(a, "/ip4/1.2.3.4/udp", &err)) == null);
    try testing.expectEqualStrings("invalid protocol string", err);
    try testing.expect((try parseMultiaddr(a, "/ip4/1.2.3.4/udp/70000", &err)) == null);
    try testing.expectEqualStrings("failed to parse: number too large to fit in target type", err);
    try testing.expect((try parseMultiaddr(a, "/ip4/1.2.3.4/udp/1/", &err)) == null);
    try testing.expectEqualStrings("unknown protocol string: ", err);
    try testing.expect((try parseMultiaddr(a, "/foo/1", &err)) == null);
    try testing.expectEqualStrings("unknown protocol string: foo", err);
    try testing.expect((try parseMultiaddr(a, "/ip6/::1/udp/1", &err)).?.isAnemo());
    try testing.expect((try parseMultiaddr(a, "/ip6/fe80::1%eth0/udp/1", &err)) == null);
    try testing.expect((try parseMultiaddr(a, "", &err)) != null); // "" is the empty multiaddr
}
