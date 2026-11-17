//! WebAuthn `clientDataJSON` acceptance exactly as Sui parses it:
//! `serde_json::from_str::<passkey_types::webauthn::CollectedClientData>` (serde_json 1.0.145
//! without `arbitrary_precision` or `float_roundtrip`, passkey-types 0.4.0).
//!
//! What that accepts:
//!   - one JSON object, surrounded only by JSON whitespace (space, tab, CR, LF);
//!   - fields matched after unescaping: "type" (a ClientDataType: the string "webauthn.create",
//!     "webauthn.get" or "payment.get", or the externally tagged form {"<variant>": null}),
//!     "challenge" and "origin" (strings), "crossOrigin" (null or a bool, optional);
//!     a duplicate of any of these four is an error, "type", "challenge" and "origin" are
//!     required;
//!   - any other key, repeated or not, with any JSON value (buffered by serde as Content:
//!     fully parsed, so its strings, escapes and numbers are validated too);
//!   - strings: no raw control characters (< 0x20), escapes \" \\ \/ \b \f \n \r \t \uXXXX,
//!     surrogates only as a valid high+low pair;
//!   - numbers: the JSON grammar; integers that overflow u64/i64 and all non-integers become
//!     f64 the serde_json way, and a result of infinity is an error;
//!   - nesting: serde_json's recursion limit (128 levels counted from the top object; the
//!     enum-object form of "type" counts as one).
//! The input is a Rust `String`, so it is valid UTF-8 (checked by the BCS decoder).
const std = @import("std");

pub const ClientDataType = enum { create, get, payment_get };

pub const ClientData = struct {
    ty: ClientDataType,
    /// Unescaped challenge string, borrowed from the `buf` given to `parse`. Only valid when
    /// `challenge_len <= buf.len`.
    challenge: []const u8,
    challenge_len: usize,
};

const Error = error{Invalid};

const Parser = struct {
    s: []const u8,
    i: usize = 0,
    /// serde_json `remaining_depth`, starting at 128.
    depth: u8 = 128,

    fn peek(p: *Parser) ?u8 {
        return if (p.i < p.s.len) p.s[p.i] else null;
    }

    fn ws(p: *Parser) void {
        while (p.i < p.s.len) : (p.i += 1) {
            switch (p.s[p.i]) {
                ' ', '\n', '\t', '\r' => {},
                else => return,
            }
        }
    }

    fn enter(p: *Parser) Error!void {
        p.depth -= 1;
        if (p.depth == 0) return error.Invalid;
    }

    fn leave(p: *Parser) void {
        p.depth += 1;
    }

    fn ident(p: *Parser, comptime word: []const u8) Error!void {
        if (p.s.len - p.i < word.len or !std.mem.eql(u8, p.s[p.i..][0..word.len], word)) return error.Invalid;
        p.i += word.len;
    }

    fn hex4(p: *Parser) Error!u16 {
        if (p.s.len - p.i < 4) return error.Invalid;
        var v: u16 = 0;
        for (p.s[p.i..][0..4]) |c| {
            const d: u16 = switch (c) {
                '0'...'9' => c - '0',
                'a'...'f' => c - 'a' + 10,
                'A'...'F' => c - 'A' + 10,
                else => return error.Invalid,
            };
            v = v * 16 + d;
        }
        p.i += 4;
        return v;
    }

    /// Parses a string starting at the opening quote. When `out` is given, the unescaped bytes
    /// are written to it (`out_len` set; overflow sets `out_len` past `out.len`).
    fn string(p: *Parser, out: ?[]u8, out_len: ?*usize) Error!void {
        std.debug.assert(p.s[p.i] == '"');
        p.i += 1;
        var n: usize = 0;
        while (true) {
            if (p.i >= p.s.len) return error.Invalid;
            const c = p.s[p.i];
            p.i += 1;
            switch (c) {
                '"' => break,
                '\\' => {
                    if (p.i >= p.s.len) return error.Invalid;
                    const e = p.s[p.i];
                    p.i += 1;
                    var cp: u21 = switch (e) {
                        '"' => '"',
                        '\\' => '\\',
                        '/' => '/',
                        'b' => 0x08,
                        'f' => 0x0c,
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        'u' => 0,
                        else => return error.Invalid,
                    };
                    if (e == 'u') {
                        const n1 = try p.hex4();
                        if (n1 >= 0xDC00 and n1 <= 0xDFFF) return error.Invalid;
                        if (n1 >= 0xD800 and n1 <= 0xDBFF) {
                            if (p.peek() != '\\') return error.Invalid;
                            p.i += 1;
                            if (p.peek() != 'u') return error.Invalid;
                            p.i += 1;
                            const n2 = try p.hex4();
                            if (n2 < 0xDC00 or n2 > 0xDFFF) return error.Invalid;
                            cp = 0x10000 + ((@as(u21, n1) - 0xD800) << 10) + (@as(u21, n2) - 0xDC00);
                        } else cp = n1;
                    }
                    if (out) |o| {
                        var tmp: [4]u8 = undefined;
                        const len = std.unicode.utf8Encode(cp, &tmp) catch return error.Invalid;
                        if (n + len <= o.len) @memcpy(o[n..][0..len], tmp[0..len]);
                        n += len;
                    }
                },
                else => {
                    if (c < 0x20) return error.Invalid;
                    if (out) |o| {
                        if (n < o.len) o[n] = c;
                        n += 1;
                    }
                },
            }
        }
        if (out_len) |l| l.* = n;
    }

    /// Any JSON value (serde_json deserialize_any into Content).
    fn value(p: *Parser) Error!void {
        p.ws();
        const c = p.peek() orelse return error.Invalid;
        switch (c) {
            'n' => try p.ident("null"),
            't' => try p.ident("true"),
            'f' => try p.ident("false"),
            '"' => try p.string(null, null),
            '-', '0'...'9' => try p.number(),
            '[' => {
                try p.enter();
                p.i += 1;
                p.ws();
                if (p.peek() == ']') {
                    p.i += 1;
                } else {
                    while (true) {
                        try p.value();
                        p.ws();
                        const d = p.peek() orelse return error.Invalid;
                        p.i += 1;
                        if (d == ']') break;
                        if (d != ',') return error.Invalid;
                        p.ws();
                        if (p.peek() == ']') return error.Invalid; // trailing comma
                    }
                }
                p.leave();
            },
            '{' => {
                try p.enter();
                p.i += 1;
                var first = true;
                while (true) {
                    p.ws();
                    const d = p.peek() orelse return error.Invalid;
                    if (d == '}') {
                        if (!first) {
                            // reached only right after a comma: handled below
                        }
                        p.i += 1;
                        break;
                    }
                    if (!first) {
                        if (d != ',') return error.Invalid;
                        p.i += 1;
                        p.ws();
                        const k = p.peek() orelse return error.Invalid;
                        if (k != '"') return error.Invalid; // trailing comma or non-string key
                    } else if (d != '"') return error.Invalid;
                    first = false;
                    try p.string(null, null);
                    try p.colon();
                    try p.value();
                }
                p.leave();
            },
            else => return error.Invalid,
        }
    }

    /// passkey_types ClientDataType through serde_json deserialize_enum: a variant-name string,
    /// or a one-entry object {"<variant>": null}.
    fn clientDataType(p: *Parser) Error!ClientDataType {
        p.ws();
        const c = p.peek() orelse return error.Invalid;
        if (c == '"') return p.variantName();
        if (c != '{') return error.Invalid;
        try p.enter();
        p.i += 1;
        p.ws();
        if (p.peek() != '"') return error.Invalid;
        const v = try p.variantName();
        try p.colon();
        p.ws();
        if (p.peek() != 'n') return error.Invalid;
        try p.ident("null");
        p.leave();
        p.ws();
        if (p.peek() != '}') return error.Invalid;
        p.i += 1;
        return v;
    }

    fn variantName(p: *Parser) Error!ClientDataType {
        var b: [16]u8 = undefined;
        var n: usize = 0;
        try p.string(&b, &n);
        if (n > b.len) return error.Invalid;
        const name = b[0..n];
        if (std.mem.eql(u8, name, "webauthn.create")) return .create;
        if (std.mem.eql(u8, name, "webauthn.get")) return .get;
        if (std.mem.eql(u8, name, "payment.get")) return .payment_get;
        return error.Invalid;
    }

    fn colon(p: *Parser) Error!void {
        p.ws();
        if (p.peek() != ':') return error.Invalid;
        p.i += 1;
    }

    fn digit(p: *Parser) ?u8 {
        const c = p.peek() orelse return null;
        return if (c >= '0' and c <= '9') c - '0' else null;
    }

    fn overflowU64(a: u64, b: u64) bool {
        const c = std.math.maxInt(u64);
        return a >= c / 10 and (a > c / 10 or b > c % 10);
    }

    fn overflowI32(a: i32, b: i32) bool {
        const c = std.math.maxInt(i32);
        return a >= @divTrunc(c, 10) and (a > @divTrunc(c, 10) or b > @rem(c, 10));
    }

    fn number(p: *Parser) Error!void {
        if (p.peek() == '-') p.i += 1;
        const first = p.peek() orelse return error.Invalid;
        p.i += 1;
        switch (first) {
            '0' => {
                if (p.digit() != null) return error.Invalid;
                return p.afterInt(0);
            },
            '1'...'9' => {
                var sig: u64 = first - '0';
                while (p.digit()) |d| {
                    if (overflowU64(sig, d)) return p.longInteger(sig);
                    p.i += 1;
                    sig = sig * 10 + d;
                }
                return p.afterInt(sig);
            },
            else => return error.Invalid,
        }
    }

    fn afterInt(p: *Parser, sig: u64) Error!void {
        switch (p.peek() orelse 0) {
            '.' => return p.decimal(sig, 0),
            'e', 'E' => return p.exponent(sig, 0),
            else => {}, // u64 / i64 / f64 for "-big": always finite
        }
    }

    fn longInteger(p: *Parser, sig: u64) Error!void {
        var exp: i32 = 0;
        while (true) {
            switch (p.peek() orelse 0) {
                '0'...'9' => {
                    p.i += 1;
                    exp +%= 1;
                },
                '.' => return p.decimal(sig, exp),
                'e', 'E' => return p.exponent(sig, exp),
                else => return fromParts(sig, exp),
            }
        }
    }

    fn decimal(p: *Parser, sig0: u64, exp_before: i32) Error!void {
        p.i += 1; // '.'
        var sig = sig0;
        var exp_after: i32 = 0;
        while (p.digit()) |d| {
            if (overflowU64(sig, d)) {
                // ignore further digits
                while (p.digit() != null) p.i += 1;
                const e = exp_before + exp_after;
                switch (p.peek() orelse 0) {
                    'e', 'E' => return p.exponent(sig, e),
                    else => return fromParts(sig, e),
                }
            }
            p.i += 1;
            sig = sig * 10 + d;
            exp_after -= 1;
        }
        if (exp_after == 0) return error.Invalid;
        const e = exp_before + exp_after;
        switch (p.peek() orelse 0) {
            'e', 'E' => return p.exponent(sig, e),
            else => return fromParts(sig, e),
        }
    }

    fn exponent(p: *Parser, sig: u64, starting: i32) Error!void {
        p.i += 1; // 'e'
        var positive = true;
        switch (p.peek() orelse 0) {
            '+' => p.i += 1,
            '-' => {
                p.i += 1;
                positive = false;
            },
            else => {},
        }
        const first = p.digit() orelse return error.Invalid;
        p.i += 1;
        var exp: i32 = first;
        while (p.digit()) |d| {
            p.i += 1;
            if (overflowI32(exp, d)) {
                if (sig != 0 and positive) return error.Invalid;
                while (p.digit() != null) p.i += 1;
                return;
            }
            exp = exp * 10 + d;
        }
        const final = if (positive) std.math.add(i32, starting, exp) catch std.math.maxInt(i32) else std.math.sub(i32, starting, exp) catch std.math.minInt(i32);
        return fromParts(sig, final);
    }

    /// serde_json f64_from_parts (no float_roundtrip): error iff the result is infinite.
    fn fromParts(sig: u64, exponent0: i32) Error!void {
        var exp: i64 = exponent0;
        var f: f64 = @floatFromInt(sig);
        while (true) {
            const idx: u64 = if (exp == std.math.minInt(i32)) std.math.maxInt(u64) else @abs(exp);
            if (idx < pow10.len) {
                if (exp >= 0) {
                    f *= pow10[@intCast(idx)];
                    if (std.math.isInf(f)) return error.Invalid;
                } else {
                    f /= pow10[@intCast(idx)];
                }
                return;
            }
            if (f == 0.0) return;
            if (exp >= 0) return error.Invalid;
            f /= 1e308;
            exp += 308;
        }
    }
};

const pow10: [309]f64 = blk: {
    @setEvalBranchQuota(100_000);
    var t: [309]f64 = undefined;
    for (0..309) |i| t[i] = std.fmt.parseFloat(f64, std.fmt.comptimePrint("1e{d}", .{i})) catch unreachable;
    break :blk t;
};

/// Parses clientDataJSON the way Sui does. `buf` receives the unescaped challenge; a challenge
/// longer than `buf` still parses but is reported with a length past `buf.len` (callers treat it
/// as not decodable). Returns null when serde_json would return an error.
pub fn parse(s: []const u8, buf: []u8) ?ClientData {
    return parseImpl(s, buf) catch null;
}

fn parseImpl(s: []const u8, buf: []u8) Error!ClientData {
    var p: Parser = .{ .s = s };
    p.ws();
    if (p.peek() != '{') return error.Invalid;
    try p.enter();
    p.i += 1;
    var ty: ?ClientDataType = null;
    var challenge_len: ?usize = null;
    var have_origin = false;
    var have_cross = false;
    var first = true;
    var keybuf: [16]u8 = undefined;
    while (true) {
        p.ws();
        const d = p.peek() orelse return error.Invalid;
        if (d == '}') {
            if (!first) {}
            p.i += 1;
            break;
        }
        if (!first) {
            if (d != ',') return error.Invalid;
            p.i += 1;
            p.ws();
            if ((p.peek() orelse return error.Invalid) != '"') return error.Invalid;
        } else if (d != '"') return error.Invalid;
        first = false;
        var klen: usize = 0;
        try p.string(&keybuf, &klen);
        const key: []const u8 = if (klen <= keybuf.len) keybuf[0..klen] else "";
        try p.colon();
        if (std.mem.eql(u8, key, "type")) {
            if (ty != null) return error.Invalid;
            ty = try p.clientDataType();
        } else if (std.mem.eql(u8, key, "challenge")) {
            if (challenge_len != null) return error.Invalid;
            p.ws();
            if (p.peek() != '"') return error.Invalid;
            var n: usize = 0;
            try p.string(buf, &n);
            challenge_len = n;
        } else if (std.mem.eql(u8, key, "origin")) {
            if (have_origin) return error.Invalid;
            p.ws();
            if (p.peek() != '"') return error.Invalid;
            try p.string(null, null);
            have_origin = true;
        } else if (std.mem.eql(u8, key, "crossOrigin")) {
            if (have_cross) return error.Invalid;
            p.ws();
            switch (p.peek() orelse return error.Invalid) {
                'n' => try p.ident("null"),
                't' => try p.ident("true"),
                'f' => try p.ident("false"),
                else => return error.Invalid,
            }
            have_cross = true;
        } else {
            try p.value();
        }
    }
    p.leave();
    p.ws();
    if (p.i != p.s.len) return error.Invalid;
    const t = ty orelse return error.Invalid;
    const cl = challenge_len orelse return error.Invalid;
    if (!have_origin) return error.Invalid;
    return .{ .ty = t, .challenge = buf[0..@min(cl, buf.len)], .challenge_len = cl };
}

test "clientDataJSON acceptance" {
    var buf: [64]u8 = undefined;
    const ok = "{\"type\":\"webauthn.get\",\"challenge\":\"abc\",\"origin\":\"https://x\",\"crossOrigin\":false}";
    const cd = parse(ok, &buf).?;
    try std.testing.expectEqual(ClientDataType.get, cd.ty);
    try std.testing.expectEqualStrings("abc", cd.challenge);
    try std.testing.expect(parse("{\"type\":{\"webauthn.get\" : null},\"challenge\":\"a\",\"origin\":\"o\"}", &buf) != null);
    try std.testing.expect(parse("{\"type\":\"webauthn.get\",\"challenge\":\"a\"}", &buf) == null); // no origin
    try std.testing.expect(parse("{\"type\":\"webauthn.get\",\"type\":\"webauthn.get\",\"challenge\":\"a\",\"origin\":\"o\"}", &buf) == null);
    try std.testing.expect(parse("{\"type\":\"webauthn.get\",\"challenge\":\"a\",\"origin\":\"o\",\"x\":1e309}", &buf) == null);
    try std.testing.expect(parse("{\"type\":\"webauthn.get\",\"challenge\":\"a\",\"origin\":\"o\",\"x\":1e308,\"x\":[1,2,{}]}", &buf) != null);
    try std.testing.expect(parse("{\"type\":\"webauthn.get\",\"challenge\":\"a\",\"origin\":\"o\",}", &buf) == null);
    try std.testing.expect(parse("{\"typ\\u0065\":\"webauthn.get\",\"challenge\":\"a\",\"origin\":\"o\"} ", &buf) != null);
    try std.testing.expect(parse("{\"type\":\"webauthn.get\",\"challenge\":\"\\ud800\",\"origin\":\"o\"}", &buf) == null);
}
