//! The two JSON reads zkLogin makes, with serde_json 1.0.145 acceptance rules:
//! - `jwtHeader`: `serde_json::from_slice::<JWTHeader>` (struct {alg: String, kid: String,
//!   typ: Option<String>}; object or 3-element array form; unknown keys skipped; duplicate
//!   known keys rejected).
//! - `claimValue`: `serde_json::from_str::<Value>` of `{<claim>}` then `.get(key).as_str()`
//!   (last duplicate wins; nesting limit 127).
//! Decoded strings are written into a caller buffer; nothing allocates.
const std = @import("std");

pub const Error = error{Json};

const Parser = struct {
    s: []const u8,
    i: usize = 0,
    depth: u32 = 128,
    out: []u8,
    out_len: usize = 0,
    /// Container stack of `skipValue` (one byte per level).
    stack: []u8 = &.{},

    fn ws(p: *Parser) void {
        while (p.i < p.s.len) : (p.i += 1) switch (p.s[p.i]) {
            ' ', '\t', '\n', '\r' => {},
            else => return,
        };
    }

    fn peek(p: *Parser) ?u8 {
        p.ws();
        return if (p.i < p.s.len) p.s[p.i] else null;
    }

    fn expect(p: *Parser, c: u8) Error!void {
        if (p.peek() != c) return error.Json;
        p.i += 1;
    }

    fn ident(p: *Parser, word: []const u8) Error!void {
        if (p.s.len - p.i < word.len or !std.mem.eql(u8, p.s[p.i..][0..word.len], word)) return error.Json;
        p.i += word.len;
    }

    fn hex4(p: *Parser) Error!u16 {
        if (p.s.len - p.i < 4) return error.Json;
        const v = std.fmt.parseInt(u16, p.s[p.i..][0..4], 16) catch return error.Json;
        for (p.s[p.i..][0..4]) |c| if (!std.ascii.isHex(c)) return error.Json;
        p.i += 4;
        return v;
    }

    fn put(p: *Parser, b: []const u8) Error!void {
        if (p.out.len - p.out_len < b.len) return error.Json;
        @memcpy(p.out[p.out_len..][0..b.len], b);
        p.out_len += b.len;
    }

    fn putCp(p: *Parser, cp: u21) Error!void {
        var tmp: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(cp, &tmp) catch return error.Json;
        try p.put(tmp[0..n]);
    }

    /// A string after the opening quote. `decode`: unescape into `out` with serde_json's
    /// validation (UTF-8, surrogate pairs) and return the slice; otherwise skip as
    /// `ignore_str` does (no UTF-8 check, escapes only syntax-checked).
    fn string(p: *Parser, decode: bool) Error![]const u8 {
        const start_out = p.out_len;
        var run = p.i;
        while (true) {
            if (p.i >= p.s.len) return error.Json;
            const c = p.s[p.i];
            if (c == '"') {
                if (decode) try p.put(p.s[run..p.i]);
                p.i += 1;
                break;
            } else if (c == '\\') {
                if (decode) try p.put(p.s[run..p.i]);
                p.i += 1;
                if (p.i >= p.s.len) return error.Json;
                const e = p.s[p.i];
                p.i += 1;
                switch (e) {
                    '"', '\\', '/' => if (decode) try p.put(&.{e}),
                    'b' => if (decode) try p.put("\x08"),
                    'f' => if (decode) try p.put("\x0c"),
                    'n' => if (decode) try p.put("\n"),
                    'r' => if (decode) try p.put("\r"),
                    't' => if (decode) try p.put("\t"),
                    'u' => {
                        const n = try p.hex4();
                        if (decode) try p.unicodeEscape(n);
                    },
                    else => return error.Json,
                }
                run = p.i;
            } else if (c < 0x20) {
                return error.Json;
            } else {
                p.i += 1;
            }
        }
        if (!decode) return &.{};
        const got = p.out[start_out..p.out_len];
        if (!std.unicode.utf8ValidateSlice(got)) return error.Json;
        return got;
    }

    fn unicodeEscape(p: *Parser, first: u16) Error!void {
        if (first >= 0xDC00 and first <= 0xDFFF) return error.Json;
        if (first < 0xD800 or first > 0xDBFF) return p.putCp(first);
        // leading surrogate: must be followed by \u + trailing surrogate
        if (p.i + 1 >= p.s.len or p.s[p.i] != '\\' or p.s[p.i + 1] != 'u') return error.Json;
        p.i += 2;
        const second = try p.hex4();
        if (second < 0xDC00 or second > 0xDFFF) return error.Json;
        const cp: u21 = @intCast((((@as(u32, first) - 0xD800) << 10) | (@as(u32, second) - 0xDC00)) + 0x10000);
        return p.putCp(cp);
    }

    /// JSON number; `value_mode` additionally rejects floats that overflow f64 (Value parsing).
    fn number(p: *Parser, value_mode: bool) Error!void {
        const start = p.i;
        if (p.i < p.s.len and p.s[p.i] == '-') p.i += 1;
        if (p.i >= p.s.len) return error.Json;
        if (p.s[p.i] == '0') {
            p.i += 1;
            if (p.i < p.s.len and std.ascii.isDigit(p.s[p.i])) return error.Json;
        } else if (std.ascii.isDigit(p.s[p.i])) {
            while (p.i < p.s.len and std.ascii.isDigit(p.s[p.i])) p.i += 1;
        } else return error.Json;
        var is_float = false;
        if (p.i < p.s.len and p.s[p.i] == '.') {
            is_float = true;
            p.i += 1;
            if (p.i >= p.s.len or !std.ascii.isDigit(p.s[p.i])) return error.Json;
            while (p.i < p.s.len and std.ascii.isDigit(p.s[p.i])) p.i += 1;
        }
        if (p.i < p.s.len and (p.s[p.i] == 'e' or p.s[p.i] == 'E')) {
            is_float = true;
            p.i += 1;
            if (p.i < p.s.len and (p.s[p.i] == '+' or p.s[p.i] == '-')) p.i += 1;
            if (p.i >= p.s.len or !std.ascii.isDigit(p.s[p.i])) return error.Json;
            while (p.i < p.s.len and std.ascii.isDigit(p.s[p.i])) p.i += 1;
        }
        if (value_mode) {
            const f = std.fmt.parseFloat(f64, p.s[start..p.i]) catch return error.Json;
            if (std.math.isInf(f)) return error.Json;
        }
    }

    /// Skip any value as serde_json's `ignore_value` does: no depth limit, strings not UTF-8
    /// checked. Iterative like serde_json (attacker-chosen nesting must not grow the call
    /// stack): `stack` keeps one byte per open container, and since every level consumes one
    /// input byte, a stack as long as the input never fills.
    fn skipValue(p: *Parser) Error!void {
        var depth: usize = 0;
        while (true) {
            const c = p.peek() orelse return error.Json;
            var opened: ?u8 = null;
            switch (c) {
                'n' => {
                    p.i += 1;
                    try p.ident("ull");
                },
                't' => {
                    p.i += 1;
                    try p.ident("rue");
                },
                'f' => {
                    p.i += 1;
                    try p.ident("alse");
                },
                '-', '0'...'9' => try p.number(false),
                '"' => {
                    p.i += 1;
                    _ = try p.string(false);
                },
                '[', '{' => {
                    if (depth == p.stack.len) @panic("json.skipValue: stack shorter than the input");
                    p.stack[depth] = c;
                    depth += 1;
                    p.i += 1;
                    opened = c;
                },
                else => return error.Json,
            }
            // After a complete value (or right after an opening bracket), close containers until
            // a comma asks for the next element.
            var accept_comma = opened == null;
            if (opened == null and depth == 0) return;
            while (true) {
                const top = p.stack[depth - 1];
                const d = p.peek() orelse return error.Json;
                if (accept_comma and d == ',') {
                    p.i += 1;
                    break;
                }
                if ((top == '[' and d == ']') or (top == '{' and d == '}')) {
                    p.i += 1;
                    depth -= 1;
                    if (depth == 0) return;
                    accept_comma = true;
                    continue;
                }
                if (accept_comma) return error.Json;
                break; // first element of a non-empty container
            }
            if (p.stack[depth - 1] == '{') {
                try p.expect('"');
                _ = try p.string(false);
                try p.expect(':');
            }
        }
    }

    /// Parse any value as serde_json `Value` does (depth limit, validated strings); when
    /// `capture` is set and this is the top-level object, records the last string value of
    /// key `key` (or marks it non-string).
    fn value(p: *Parser, key: ?[]const u8, found: *Found) Error!void {
        const c = p.peek() orelse return error.Json;
        switch (c) {
            'n', 't', 'f' => try p.skipValue(),
            '-', '0'...'9' => try p.number(true),
            '"' => {
                p.i += 1;
                const mark = p.out_len;
                _ = try p.string(true);
                p.out_len = mark;
            },
            '[', '{' => {
                p.depth -= 1;
                if (p.depth == 0) return error.Json;
                defer p.depth += 1;
                p.i += 1;
                const close: u8 = if (c == '[') ']' else '}';
                if (p.peek() == close) {
                    p.i += 1;
                    return;
                }
                while (true) {
                    if (c == '{') {
                        try p.expect('"');
                        const mark = p.out_len;
                        const k = try p.string(true);
                        const is_key = if (key) |want| std.mem.eql(u8, k, want) else false;
                        try p.expect(':');
                        if (is_key) {
                            // value of the wanted key: keep its decoded string if it is one
                            if (p.peek() == '"') {
                                p.i += 1;
                                const v = try p.string(true);
                                // move v to the front of the kept area
                                std.mem.copyForwards(u8, p.out[mark..][0..v.len], v);
                                p.out_len = mark + v.len;
                                found.* = .{ .string = .{ .start = mark, .len = v.len } };
                                // keep this string; later duplicates overwrite after it
                                const keep = p.out_len;
                                _ = keep;
                            } else {
                                p.out_len = mark;
                                try p.value(null, found);
                                found.* = .non_string;
                            }
                        } else {
                            // discard key bytes unless they overlap a kept string
                            p.out_len = mark;
                            try p.value(null, found);
                        }
                    } else {
                        try p.value(null, found);
                    }
                    const d = p.peek() orelse return error.Json;
                    p.i += 1;
                    if (d == close) return;
                    if (d != ',') return error.Json;
                }
            },
            else => return error.Json,
        }
    }
};

const Found = union(enum) {
    missing,
    non_string,
    string: struct { start: usize, len: usize },
};

pub const Header = struct { alg: []const u8, kid: []const u8, typ: ?[]const u8 };

/// `serde_json::from_slice::<JWTHeader>(bytes)`. `buf` needs `2 * bytes.len` bytes: strings are
/// decoded into the first half (the result points there), the second half is skip scratch.
pub fn jwtHeader(bytes: []const u8, buf: []u8) Error!Header {
    if (buf.len < 2 * bytes.len) @panic("json.jwtHeader: buffer shorter than 2 * input");
    var p: Parser = .{ .s = bytes, .out = buf[0..bytes.len], .stack = buf[bytes.len .. 2 * bytes.len] };
    const c = p.peek() orelse return error.Json;
    var alg: ?[]const u8 = null;
    var kid: ?[]const u8 = null;
    var typ: ?(?[]const u8) = null;
    if (c == '{') {
        p.i += 1;
        if (p.peek() != '}') {
            while (true) {
                try p.expect('"');
                const mark = p.out_len;
                const k = try p.string(true);
                const which: u8 = if (std.mem.eql(u8, k, "alg")) 1 else if (std.mem.eql(u8, k, "kid")) 2 else if (std.mem.eql(u8, k, "typ")) 3 else 0;
                p.out_len = mark;
                try p.expect(':');
                switch (which) {
                    1, 2 => {
                        if (which == 1 and alg != null) return error.Json;
                        if (which == 2 and kid != null) return error.Json;
                        try p.expect('"');
                        const v = try p.string(true);
                        if (which == 1) alg = v else kid = v;
                    },
                    3 => {
                        if (typ != null) return error.Json;
                        if (p.peek() == 'n') {
                            p.i += 1;
                            try p.ident("ull");
                            typ = @as(?[]const u8, null);
                        } else {
                            try p.expect('"');
                            typ = @as(?[]const u8, try p.string(true));
                        }
                    },
                    else => try p.skipValue(),
                }
                const d = p.peek() orelse return error.Json;
                p.i += 1;
                if (d == '}') break;
                if (d != ',') return error.Json;
            }
        } else p.i += 1;
    } else if (c == '[') {
        p.i += 1;
        try p.expect('"');
        alg = try p.string(true);
        try p.expect(',');
        try p.expect('"');
        kid = try p.string(true);
        try p.expect(',');
        if (p.peek() == 'n') {
            p.i += 1;
            try p.ident("ull");
            typ = @as(?[]const u8, null);
        } else {
            try p.expect('"');
            typ = @as(?[]const u8, try p.string(true));
        }
        try p.expect(']');
    } else return error.Json;
    if (p.peek() != null) return error.Json; // trailing characters
    return .{ .alg = alg orelse return error.Json, .kid = kid orelse return error.Json, .typ = if (typ) |t| t else null };
}

/// `serde_json::from_str::<Value>(text)` then `.as_object().get(key).as_str()`.
/// Returns error.Json for a parse failure; null when the key is missing or not a string.
pub fn claimValue(text: []const u8, key: []const u8, buf: []u8) Error!?[]const u8 {
    var p: Parser = .{ .s = text, .out = buf };
    var found: Found = .missing;
    if (p.peek() != '{') {
        try p.value(null, &found);
        if (p.peek() != null) return error.Json;
        return null; // not an object (cannot happen for "{...}" inputs)
    }
    try p.value(key, &found);
    if (p.peek() != null) return error.Json;
    return switch (found) {
        .string => |s| buf[s.start..][0..s.len],
        else => null,
    };
}

test "json" {
    var buf: [512]u8 = undefined;
    const h = try jwtHeader("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"1\"}", &buf);
    try std.testing.expectEqualStrings("RS256", h.alg);
    try std.testing.expectEqualStrings("1", h.kid);
    try std.testing.expectError(error.Json, jwtHeader("{\"alg\":\"RS256\",\"alg\":\"x\",\"kid\":\"1\"}", &buf));
    try std.testing.expectError(error.Json, jwtHeader("{\"alg\":\"RS256\"}", &buf));
    const a = try jwtHeader("[\"RS256\",\"k\",null]", &buf);
    try std.testing.expectEqualStrings("k", a.kid);
    try std.testing.expectEqualStrings("https://x", (try claimValue("{\"iss\":\"https://y\",\"iss\":\"https://x\"}", "iss", &buf)).?);
    try std.testing.expect((try claimValue("{\"iss\":1}", "iss", &buf)) == null);
    try std.testing.expectError(error.Json, claimValue("{\"iss\":\"a\",}", "iss", &buf));
    try std.testing.expectEqualStrings("a\u{e9}", (try claimValue("{\"iss\":\"a\\u00e9\"}", "iss", &buf)).?);
    // ignore_value has no depth limit and must not recurse: 100k levels in an unknown key.
    const depth = 100_000;
    const deep = try std.testing.allocator.alloc(u8, 2 * depth + 64);
    defer std.testing.allocator.free(deep);
    var w: std.Io.Writer = .fixed(deep);
    try w.writeAll("{\"x\":");
    try w.splatByteAll('[', depth);
    try w.writeAll("{\"a\":1}");
    try w.splatByteAll(']', depth);
    try w.writeAll(",\"alg\":\"RS256\",\"kid\":\"k\"}");
    const big = try std.testing.allocator.alloc(u8, 2 * w.end);
    defer std.testing.allocator.free(big);
    try std.testing.expectEqualStrings("k", (try jwtHeader(w.buffered(), big)).kid);
    // ... and the same skip grammar as serde_json for the shallow cases.
    for ([_][]const u8{ "[]", "{}", "[1,[2,{}],{\"a\":[]}]", "{\"a\":{\"b\":null},\"c\":-0.5e+3}" }) |v| {
        var t: [96]u8 = undefined;
        const text = try std.fmt.bufPrint(&t, "{{\"x\":{s},\"alg\":\"RS256\",\"kid\":\"k\"}}", .{v});
        _ = try jwtHeader(text, &buf);
    }
    for ([_][]const u8{ "[1,]", "[,1]", "{\"a\":1,}", "{1:2}", "[1 2]", "{\"a\" 1}", "[", "[1", "{\"a\":", "]" }) |v| {
        var t: [96]u8 = undefined;
        const text = try std.fmt.bufPrint(&t, "{{\"x\":{s},\"alg\":\"RS256\",\"kid\":\"k\"}}", .{v});
        try std.testing.expectError(error.Json, jwtHeader(text, &buf));
    }
}
