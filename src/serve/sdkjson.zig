//! The three JSON reads sui-sdk-types makes on the VerifySignature path, as serde_json 1.0.145
//! (no `float_roundtrip`, no `arbitrary_precision`, `preserve_order`) runs them, with serde_json's
//! error texts and positions (`<msg> at line L column C`):
//! - `clientData`: `serde_json::from_str::<CollectedClientData>` (sui-sdk-types passkey.rs: a plain
//!   derive with `type` (enum ClientDataType { Get = "webauthn.get" }), `challenge`, `origin`;
//!   every other key, `crossOrigin` included, goes through `ignore_value`);
//! - `jwtHeader`: `serde_json::from_slice::<Header>` (`alg`, `kid`, `typ: Option<String>`);
//! - `claim`: `serde_json::from_str::<Value>` then `.get(key)` as a string.
//! Control flow and positions follow serde_json's de.rs/read.rs (SliceRead) line by line.
const std = @import("std");
const Allocator = std.mem.Allocator;
const zk = @import("zk");

pub const Error = error{ Json, OutOfMemory };

const D = struct {
    s: []const u8,
    i: usize = 0,
    /// from_slice: parsed strings must be UTF-8 (`as_str`)
    utf8: bool = false,
    arena: Allocator,
    remaining_depth: u32 = 128,
    /// error text; `line == 0` means not positioned yet (serde's custom errors before fix_position)
    msg: []const u8 = "",
    line: usize = 0,
    col: usize = 0,
    stack: std.ArrayList(u8) = .empty,

    fn peek(d: *D) ?u8 {
        return if (d.i < d.s.len) d.s[d.i] else null;
    }
    fn peekOrNull(d: *D) u8 {
        return d.peek() orelse 0;
    }
    fn eat(d: *D) void {
        d.i += 1;
    }
    fn next(d: *D) ?u8 {
        if (d.i >= d.s.len) return null;
        d.i += 1;
        return d.s[d.i - 1];
    }
    fn posAt(d: *D, idx: usize) void {
        const head = d.s[0..idx];
        const sol = if (std.mem.lastIndexOfScalar(u8, head, '\n')) |p| p + 1 else 0;
        d.line = 1 + std.mem.count(u8, d.s[0..sol], "\n");
        d.col = idx - sol;
    }
    /// `error(code)`: position of the current index.
    fn err(d: *D, msg: []const u8) error{Json} {
        d.msg = msg;
        d.posAt(d.i);
        return error.Json;
    }
    /// `peek_error(code)`: position one past the current index.
    fn perr(d: *D, msg: []const u8) error{Json} {
        d.msg = msg;
        d.posAt(@min(d.s.len, d.i + 1));
        return error.Json;
    }
    /// A serde custom error (positioned later by `fix`).
    fn custom(d: *D, msg: []const u8) error{Json} {
        d.msg = msg;
        d.line = 0;
        return error.Json;
    }
    fn customf(d: *D, comptime f: []const u8, args: anytype) Error {
        d.msg = std.fmt.allocPrint(d.arena, f, args) catch return error.OutOfMemory;
        d.line = 0;
        return error.Json;
    }
    /// `fix_position`: an unpositioned error takes the current position.
    fn fix(d: *D, e: Error) Error {
        if (e == error.Json and d.line == 0) d.posAt(d.i);
        return e;
    }

    fn ws(d: *D) ?u8 {
        while (d.peek()) |c| switch (c) {
            ' ', '\n', '\t', '\r' => d.eat(),
            else => return c,
        };
        return null;
    }

    fn ident(d: *D, rest: []const u8) Error!void {
        for (rest) |want| {
            const c = d.next() orelse return d.err("EOF while parsing a value");
            if (c != want) return d.err("expected ident");
        }
    }

    // ---- strings ----

    fn isEscape(c: u8) bool {
        return c == '"' or c == '\\' or c < 0x20;
    }

    fn hex4(d: *D) Error!u16 {
        if (d.s.len - d.i < 4) {
            d.i = d.s.len;
            return d.err("EOF while parsing a string");
        }
        const b = d.s[d.i..][0..4];
        d.i += 4;
        var v: u16 = 0;
        for (b) |c| {
            const x = std.fmt.charToDigit(c, 16) catch return d.err("invalid escape");
            v = v * 16 + x;
        }
        return v;
    }

    fn pushCp(out: *std.ArrayList(u8), a: Allocator, n: u21) Error!void {
        var buf: [4]u8 = undefined;
        const len: usize = if (n < 0x80) 1 else if (n < 0x800) 2 else if (n < 0x10000) 3 else 4;
        switch (len) {
            1 => buf[0] = @intCast(n),
            2 => {
                buf[0] = @intCast(0xc0 | (n >> 6));
                buf[1] = @intCast(0x80 | (n & 0x3f));
            },
            3 => {
                buf[0] = @intCast(0xe0 | (n >> 12));
                buf[1] = @intCast(0x80 | ((n >> 6) & 0x3f));
                buf[2] = @intCast(0x80 | (n & 0x3f));
            },
            else => {
                buf[0] = @intCast(0xf0 | (n >> 18));
                buf[1] = @intCast(0x80 | ((n >> 12) & 0x3f));
                buf[2] = @intCast(0x80 | ((n >> 6) & 0x3f));
                buf[3] = @intCast(0x80 | (n & 0x3f));
            },
        }
        try out.appendSlice(a, buf[0..len]);
    }

    /// `parse_str` with validate = true (called after the opening quote was eaten).
    fn parseStr(d: *D) Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        var start = d.i;
        while (true) {
            while (d.i < d.s.len and !isEscape(d.s[d.i])) d.i += 1;
            if (d.i == d.s.len) return d.err("EOF while parsing a string");
            switch (d.s[d.i]) {
                '"' => {
                    try out.appendSlice(d.arena, d.s[start..d.i]);
                    d.i += 1;
                    if (d.utf8 and !std.unicode.utf8ValidateSlice(out.items)) return d.err("invalid unicode code point");
                    return out.items;
                },
                '\\' => {
                    try out.appendSlice(d.arena, d.s[start..d.i]);
                    d.i += 1;
                    try d.escape(&out);
                    start = d.i;
                },
                else => {
                    d.i += 1;
                    return d.err("control character (\\u0000-\\u001F) found while parsing a string");
                },
            }
        }
    }

    fn escape(d: *D, out: *std.ArrayList(u8)) Error!void {
        const c = d.next() orelse return d.err("EOF while parsing a string");
        const simple: ?u8 = switch (c) {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => 0x08,
            'f' => 0x0c,
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => null,
            else => return d.err("invalid escape"),
        };
        if (simple) |x| return out.append(d.arena, x);
        var n = try d.hex4();
        if (n >= 0xDC00 and n <= 0xDFFF) return d.err("lone leading surrogate in hex escape");
        if (n < 0xD800 or n > 0xDBFF) return pushCp(out, d.arena, n);
        const n1 = n;
        const p1 = d.peek() orelse return d.err("EOF while parsing a string");
        d.eat();
        if (p1 != '\\') return d.err("unexpected end of hex escape");
        const p2 = d.peek() orelse return d.err("EOF while parsing a string");
        d.eat();
        if (p2 != 'u') return d.err("unexpected end of hex escape");
        n = try d.hex4();
        if (n < 0xDC00 or n > 0xDFFF) return d.err("lone leading surrogate in hex escape");
        const cp: u21 = ((@as(u21, n1 - 0xD800) << 10) | (n - 0xDC00)) + 0x10000;
        return pushCp(out, d.arena, cp);
    }

    /// `ignore_str` (after the opening quote): escapes checked, surrogates not paired, no UTF-8 check.
    fn ignoreStr(d: *D) Error!void {
        while (true) {
            while (d.i < d.s.len and !isEscape(d.s[d.i])) d.i += 1;
            if (d.i == d.s.len) return d.err("EOF while parsing a string");
            switch (d.s[d.i]) {
                '"' => {
                    d.i += 1;
                    return;
                },
                '\\' => {
                    d.i += 1;
                    const c = d.next() orelse return d.err("EOF while parsing a string");
                    switch (c) {
                        '"', '\\', '/', 'b', 'f', 'n', 'r', 't' => {},
                        'u' => _ = try d.hex4(),
                        else => return d.err("invalid escape"),
                    }
                },
                else => return d.err("control character (\\u0000-\\u001F) found while parsing a string"),
            }
        }
    }

    // ---- numbers ----

    const Num = union(enum) { u: u64, i: i64, f: f64 };

    fn parseInteger(d: *D, positive: bool) Error!Num {
        const c = d.next() orelse return d.err("EOF while parsing a value");
        switch (c) {
            '0' => {
                if (std.ascii.isDigit(d.peekOrNull())) return d.perr("invalid number");
                return d.parseNumber(positive, 0);
            },
            '1'...'9' => {
                var sig: u64 = c - '0';
                while (true) {
                    const p = d.peekOrNull();
                    if (!std.ascii.isDigit(p)) return d.parseNumber(positive, sig);
                    const digit: u64 = p - '0';
                    if (sig >= std.math.maxInt(u64) / 10 and (sig > std.math.maxInt(u64) / 10 or digit > std.math.maxInt(u64) % 10))
                        return .{ .f = try d.parseLongInteger(positive, sig) };
                    d.eat();
                    sig = sig * 10 + digit;
                }
            },
            else => return d.err("invalid number"),
        }
    }

    fn parseNumber(d: *D, positive: bool, sig: u64) Error!Num {
        return switch (d.peekOrNull()) {
            '.' => .{ .f = try d.parseDecimal(positive, sig, 0) },
            'e', 'E' => .{ .f = try d.parseExponent(positive, sig, 0) },
            else => if (positive) .{ .u = sig } else blk: {
                const neg = -%@as(i64, @bitCast(sig));
                break :blk if (neg >= 0) .{ .f = -@as(f64, @floatFromInt(sig)) } else .{ .i = neg };
            },
        };
    }

    fn parseLongInteger(d: *D, positive: bool, sig: u64) Error!f64 {
        var exponent: i32 = 0;
        while (true) switch (d.peekOrNull()) {
            '0'...'9' => {
                d.eat();
                exponent += 1;
            },
            '.' => return d.parseDecimal(positive, sig, exponent),
            'e', 'E' => return d.parseExponent(positive, sig, exponent),
            else => return d.f64FromParts(positive, sig, exponent),
        };
    }

    fn parseDecimal(d: *D, positive: bool, sig0: u64, exp_before: i32) Error!f64 {
        d.eat();
        var sig = sig0;
        var exp_after: i32 = 0;
        while (std.ascii.isDigit(d.peekOrNull())) {
            const digit: u64 = d.peekOrNull() - '0';
            if (sig >= std.math.maxInt(u64) / 10 and (sig > std.math.maxInt(u64) / 10 or digit > std.math.maxInt(u64) % 10)) {
                // parse_decimal_overflow
                while (std.ascii.isDigit(d.peekOrNull())) d.eat();
                const e = exp_before + exp_after;
                return switch (d.peekOrNull()) {
                    'e', 'E' => d.parseExponent(positive, sig, e),
                    else => d.f64FromParts(positive, sig, e),
                };
            }
            d.eat();
            sig = sig * 10 + digit;
            exp_after -= 1;
        }
        if (exp_after == 0) {
            if (d.peek() != null) return d.perr("invalid number");
            return d.perr("EOF while parsing a value");
        }
        const e = exp_before + exp_after;
        return switch (d.peekOrNull()) {
            'e', 'E' => d.parseExponent(positive, sig, e),
            else => d.f64FromParts(positive, sig, e),
        };
    }

    fn parseExponent(d: *D, positive: bool, sig: u64, starting: i32) Error!f64 {
        d.eat();
        var pos_exp = true;
        switch (d.peekOrNull()) {
            '+' => d.eat(),
            '-' => {
                d.eat();
                pos_exp = false;
            },
            else => {},
        }
        const c = d.next() orelse return d.err("EOF while parsing a value");
        if (!std.ascii.isDigit(c)) return d.err("invalid number");
        var exp: i32 = c - '0';
        while (std.ascii.isDigit(d.peekOrNull())) {
            const digit: i32 = d.peekOrNull() - '0';
            d.eat();
            if (exp >= std.math.maxInt(i32) / 10 and (exp > std.math.maxInt(i32) / 10 or digit > std.math.maxInt(i32) % 10)) {
                // parse_exponent_overflow
                if (sig != 0 and pos_exp) return d.err("number out of range");
                while (std.ascii.isDigit(d.peekOrNull())) d.eat();
                return if (positive) 0.0 else -0.0;
            }
            exp = exp * 10 + digit;
        }
        const final = if (pos_exp) starting +| exp else starting -| exp;
        return d.f64FromParts(positive, sig, final);
    }

    fn f64FromParts(d: *D, positive: bool, sig: u64, exponent0: i32) Error!f64 {
        var exponent = exponent0;
        var f: f64 = @floatFromInt(sig);
        while (true) {
            const a: u32 = @abs(exponent);
            if (a <= 308) {
                const pow = pow10[a];
                if (exponent >= 0) {
                    f *= pow;
                    if (std.math.isInf(f)) return d.err("number out of range");
                } else f /= pow;
                break;
            }
            if (f == 0.0) break;
            if (exponent >= 0) return d.err("number out of range");
            f /= 1e308;
            exponent += 308;
        }
        return if (positive) f else -f;
    }

    fn ignoreInteger(d: *D) Error!void {
        const c = d.next() orelse 0;
        switch (c) {
            '0' => if (std.ascii.isDigit(d.peekOrNull())) return d.perr("invalid number"),
            '1'...'9' => while (std.ascii.isDigit(d.peekOrNull())) d.eat(),
            else => return d.err("invalid number"),
        }
        switch (d.peekOrNull()) {
            '.' => try d.ignoreDecimal(),
            'e', 'E' => try d.ignoreExponent(),
            else => {},
        }
    }
    fn ignoreDecimal(d: *D) Error!void {
        d.eat();
        var any = false;
        while (std.ascii.isDigit(d.peekOrNull())) {
            d.eat();
            any = true;
        }
        if (!any) return d.perr("invalid number");
        switch (d.peekOrNull()) {
            'e', 'E' => try d.ignoreExponent(),
            else => {},
        }
    }
    fn ignoreExponent(d: *D) Error!void {
        d.eat();
        switch (d.peekOrNull()) {
            '+', '-' => d.eat(),
            else => {},
        }
        const c = d.next() orelse 0;
        if (!std.ascii.isDigit(c)) return d.err("invalid number");
        while (std.ascii.isDigit(d.peekOrNull())) d.eat();
    }

    /// `ignore_value`: no recursion limit (an explicit stack).
    fn ignoreValue(d: *D) Error!void {
        d.stack.clearRetainingCapacity();
        var enclosing: ?u8 = null;
        while (true) {
            const p = d.ws() orelse return d.perr("EOF while parsing a value");
            var frame: ?u8 = null;
            switch (p) {
                'n' => {
                    d.eat();
                    try d.ident("ull");
                },
                't' => {
                    d.eat();
                    try d.ident("rue");
                },
                'f' => {
                    d.eat();
                    try d.ident("alse");
                },
                '-' => {
                    d.eat();
                    try d.ignoreInteger();
                },
                '0'...'9' => try d.ignoreInteger(),
                '"' => {
                    d.eat();
                    try d.ignoreStr();
                },
                '[', '{' => {
                    if (enclosing) |e| try d.stack.append(d.arena, e);
                    enclosing = null;
                    d.eat();
                    frame = p;
                },
                else => return d.perr("expected value"),
            }
            var accept_comma: bool = undefined;
            var fr: u8 = undefined;
            if (frame) |f| {
                accept_comma = false;
                fr = f;
            } else if (enclosing) |e| {
                enclosing = null;
                accept_comma = true;
                fr = e;
            } else if (d.stack.pop()) |e| {
                accept_comma = true;
                fr = e;
            } else return;
            while (true) {
                const q = d.ws() orelse return d.perr(if (fr == '[') "EOF while parsing a list" else "EOF while parsing an object");
                if (q == ',' and accept_comma) {
                    d.eat();
                    break;
                } else if ((q == ']' and fr == '[') or (q == '}' and fr == '{')) {
                    // close
                } else {
                    if (accept_comma) return d.perr(if (fr == '[') "expected `,` or `]`" else "expected `,` or `}`");
                    break;
                }
                d.eat();
                fr = d.stack.pop() orelse return;
                accept_comma = true;
            }
            if (fr == '{') {
                const k = d.ws() orelse return d.perr("EOF while parsing an object");
                if (k != '"') return d.perr("key must be a string");
                d.eat();
                try d.ignoreStr();
                const col = d.ws() orelse return d.perr("EOF while parsing an object");
                if (col != ':') return d.perr("expected `:`");
                d.eat();
            }
            enclosing = fr;
        }
    }

    // ---- serde plumbing ----

    fn recurse(d: *D) Error!void {
        d.remaining_depth -= 1;
        if (d.remaining_depth == 0) return d.perr("recursion limit exceeded");
    }

    fn colon(d: *D) Error!void {
        const c = d.ws() orelse return d.perr("EOF while parsing an object");
        if (c != ':') return d.perr("expected `:`");
        d.eat();
    }

    fn endSeq(d: *D) Error!void {
        const c = d.ws() orelse return d.perr("EOF while parsing a list");
        switch (c) {
            ']' => d.eat(),
            ',' => {
                d.eat();
                if (d.ws() == ']') return d.perr("trailing comma");
                return d.perr("trailing characters");
            },
            else => return d.perr("trailing characters"),
        }
    }

    fn endMap(d: *D) Error!void {
        const c = d.ws() orelse return d.perr("EOF while parsing an object");
        switch (c) {
            '}' => d.eat(),
            ',' => return d.perr("trailing comma"),
            else => return d.perr("trailing characters"),
        }
    }

    /// `has_next_element`.
    fn hasNextElement(d: *D, first: *bool) Error!bool {
        const p = d.ws() orelse return d.perr("EOF while parsing a list");
        if (p == ']') return false;
        if (first.*) {
            first.* = false;
            return true;
        }
        if (p == ',') {
            d.eat();
            const q = d.ws() orelse return d.perr("EOF while parsing a value");
            if (q == ']') return d.perr("trailing comma");
            return true;
        }
        return d.perr("expected `,` or `]`");
    }

    /// `has_next_key` then the MapKey string.
    fn nextKey(d: *D, first: *bool) Error!?[]const u8 {
        const p = d.ws() orelse return d.perr("EOF while parsing an object");
        if (p == '}') return null;
        if (first.*) {
            first.* = false;
            if (p != '"') return d.perr("key must be a string");
        } else if (p == ',') {
            d.eat();
            const q = d.ws() orelse return d.perr("EOF while parsing a value");
            if (q == '}') return d.perr("trailing comma");
            if (q != '"') return d.perr("key must be a string");
        } else return d.perr("expected `,` or `}`");
        d.eat();
        return try d.parseStr();
    }

    /// `peek_invalid_type`: consumes the offending value's first token, then a positioned
    /// "invalid type: <unexpected>, expected <exp>".
    fn invalidType(d: *D, exp: []const u8) Error {
        const c = d.peekOrNull();
        const unexp: []const u8 = switch (c) {
            'n' => blk: {
                d.eat();
                d.ident("ull") catch |e| return e;
                break :blk "null";
            },
            't' => blk: {
                d.eat();
                d.ident("rue") catch |e| return e;
                break :blk "boolean `true`";
            },
            'f' => blk: {
                d.eat();
                d.ident("alse") catch |e| return e;
                break :blk "boolean `false`";
            },
            '-', '0'...'9' => blk: {
                if (c == '-') d.eat();
                const n = d.parseInteger(c != '-') catch |e| return e;
                break :blk numText(d.arena, n) catch |e| return e;
            },
            '"' => blk: {
                d.eat();
                const s = d.parseStr() catch |e| return e;
                var aw: std.Io.Writer.Allocating = .init(d.arena);
                aw.writer.writeAll("string \"") catch return error.OutOfMemory;
                zk.errors.escapeDebug(&aw.writer, s) catch return error.OutOfMemory;
                aw.writer.writeAll("\"") catch return error.OutOfMemory;
                break :blk aw.written();
            },
            '[' => "sequence",
            '{' => "map",
            else => return d.perr("expected value"),
        };
        return d.fix(d.customf("invalid type: {s}, expected {s}", .{ unexp, exp }));
    }

    /// `deserialize_string` with the String visitor.
    fn string(d: *D) Error![]const u8 {
        const p = d.ws() orelse return d.perr("EOF while parsing a value");
        if (p == '"') {
            d.eat();
            return d.parseStr();
        }
        return d.invalidType("a string");
    }

    /// `deserialize_unit` (expected "unit").
    fn unit(d: *D) Error!void {
        const p = d.ws() orelse return d.perr("EOF while parsing a value");
        if (p == 'n') {
            d.eat();
            return d.ident("ull");
        }
        return d.invalidType("unit");
    }

    /// `ClientDataType` (one variant, "webauthn.get") through `deserialize_enum`.
    fn clientDataType(d: *D) Error!void {
        const p = d.ws() orelse return d.perr("EOF while parsing a value");
        switch (p) {
            '{' => {
                try d.recurse();
                d.eat();
                try d.variantIdent();
                try d.colon();
                try d.unit();
                d.remaining_depth += 1;
                const q = d.ws() orelse return d.err("EOF while parsing an object");
                if (q != '}') return d.err("expected value");
                d.eat();
            },
            '"' => try d.variantIdent(),
            else => return d.perr("expected value"),
        }
    }

    /// The variant identifier: `deserialize_identifier` -> `deserialize_str`.
    fn variantIdent(d: *D) Error!void {
        const p = d.ws() orelse return d.perr("EOF while parsing a value");
        if (p != '"') return d.invalidType("variant identifier");
        d.eat();
        const s = try d.parseStr();
        if (std.mem.eql(u8, s, "webauthn.get")) return;
        var aw: std.Io.Writer.Allocating = .init(d.arena);
        aw.writer.writeAll("unknown variant `") catch return error.OutOfMemory;
        aw.writer.writeAll(s) catch return error.OutOfMemory;
        aw.writer.writeAll("`, expected `webauthn.get`") catch return error.OutOfMemory;
        return d.fix(d.custom(aw.written()));
    }

    /// `deserialize_any` into a `Value`, remembering the last string value of `key` at the top.
    fn value(d: *D, key: ?[]const u8, found: *?[]const u8) Error!void {
        const p = d.ws() orelse return d.perr("EOF while parsing a value");
        switch (p) {
            'n' => {
                d.eat();
                try d.ident("ull");
            },
            't' => {
                d.eat();
                try d.ident("rue");
            },
            'f' => {
                d.eat();
                try d.ident("alse");
            },
            '-' => {
                d.eat();
                _ = try d.parseInteger(false);
            },
            '0'...'9' => _ = try d.parseInteger(true),
            '"' => {
                d.eat();
                _ = try d.parseStr();
            },
            '[' => {
                try d.recurse();
                d.eat();
                var first = true;
                var none: ?[]const u8 = null;
                while (try d.hasNextElement(&first)) try d.value(null, &none);
                d.remaining_depth += 1;
                try d.endSeq();
            },
            '{' => {
                try d.recurse();
                d.eat();
                var first = true;
                var none: ?[]const u8 = null;
                while (try d.nextKey(&first)) |k| {
                    try d.colon();
                    const is_key = if (key) |want| std.mem.eql(u8, k, want) else false;
                    if (is_key) {
                        // IndexMap insert: a later duplicate replaces the value
                        const at = d.ws();
                        if (at == '"') {
                            d.eat();
                            found.* = try d.parseStr();
                        } else {
                            found.* = null;
                            try d.value(null, &none);
                        }
                    } else try d.value(null, &none);
                }
                d.remaining_depth += 1;
                try d.endMap();
            },
            else => return d.perr("expected value"),
        }
    }

    fn end(d: *D) Error!void {
        if (d.ws() != null) return d.perr("trailing characters");
    }

    fn text(d: *D) Error![]const u8 {
        if (d.line == 0) return d.msg;
        return std.fmt.allocPrint(d.arena, "{s} at line {d} column {d}", .{ d.msg, d.line, d.col });
    }
};

fn numText(a: Allocator, n: D.Num) Error![]const u8 {
    return switch (n) {
        .u => |v| std.fmt.allocPrint(a, "integer `{d}`", .{v}),
        .i => |v| std.fmt.allocPrint(a, "integer `{d}`", .{v}),
        .f => |v| blk: {
            var buf: [64]u8 = undefined;
            break :blk std.fmt.allocPrint(a, "floating point `{s}`", .{ryu(&buf, v)});
        },
    };
}

/// `ryu::Buffer::format` (format64): shortest digits, then ryu's layout rules.
pub fn ryu(buf: *[64]u8, v: f64) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (std.math.signbit(v)) w.writeByte('-') catch unreachable;
    const a = @abs(v);
    if (a == 0) {
        w.writeAll("0.0") catch unreachable;
        return w.buffered();
    }
    var sci: [64]u8 = undefined;
    const e_text = std.fmt.bufPrint(&sci, "{e}", .{a}) catch unreachable;
    // "d.ddddde<exp>" or "de<exp>"
    const e_at = std.mem.indexOfScalar(u8, e_text, 'e').?;
    var digits: [32]u8 = undefined;
    var nd: usize = 0;
    for (e_text[0..e_at]) |c| if (c != '.') {
        digits[nd] = c;
        nd += 1;
    };
    while (nd > 1 and digits[nd - 1] == '0') nd -= 1;
    const e10 = std.fmt.parseInt(i32, e_text[e_at + 1 ..], 10) catch unreachable;
    const len: i32 = @intCast(nd);
    const k = e10 - len + 1; // value = digits * 10^k
    const kk = len + k;
    const d = digits[0..nd];
    if (k >= 0 and kk <= 16) {
        w.writeAll(d) catch unreachable;
        for (0..@intCast(k)) |_| w.writeByte('0') catch unreachable;
        w.writeAll(".0") catch unreachable;
    } else if (kk > 0 and kk <= 16) {
        const p: usize = @intCast(kk);
        w.writeAll(d[0..p]) catch unreachable;
        w.writeByte('.') catch unreachable;
        w.writeAll(d[p..]) catch unreachable;
    } else if (kk > -5 and kk <= 0) {
        w.writeAll("0.") catch unreachable;
        for (0..@intCast(-kk)) |_| w.writeByte('0') catch unreachable;
        w.writeAll(d) catch unreachable;
    } else if (nd == 1) {
        w.print("{s}e{d}", .{ d, kk - 1 }) catch unreachable;
    } else {
        w.print("{c}.{s}e{d}", .{ d[0], d[1..], kk - 1 }) catch unreachable;
    }
    return w.buffered();
}

const pow10: [309]f64 = blk: {
    @setEvalBranchQuota(100000);
    var t: [309]f64 = undefined;
    for (0..309) |i| t[i] = std.fmt.parseFloat(f64, std.fmt.comptimePrint("1e{d}", .{i})) catch unreachable;
    break :blk t;
};

pub const Result = union(enum) { ok: []const u8, err: []const u8 };

/// `serde_json::from_str::<CollectedClientData>`: the challenge string, or serde_json's error.
pub fn clientData(arena: Allocator, s: []const u8) error{OutOfMemory}!Result {
    var d: D = .{ .s = s, .arena = arena };
    const ch = clientDataInner(&d) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Json => return .{ .err = try errText(&d) },
    };
    return .{ .ok = ch };
}

fn errText(d: *D) error{OutOfMemory}![]const u8 {
    return d.text() catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Json => unreachable,
    };
}

fn clientDataInner(d: *D) Error![]const u8 {
    const V = struct {
        ty: bool = false,
        challenge: ?[]const u8 = null,
        origin: ?[]const u8 = null,
        fn seq(st: *@This(), dd: *D, first: *bool) Error!?usize {
            if (!try dd.hasNextElement(first)) return 0;
            try dd.clientDataType();
            st.ty = true;
            if (!try dd.hasNextElement(first)) return 1;
            st.challenge = try dd.string();
            if (!try dd.hasNextElement(first)) return 2;
            st.origin = try dd.string();
            return null;
        }
        fn field(st: *@This(), dd: *D, k: []const u8) Error!void {
            if (std.mem.eql(u8, k, "type")) {
                if (st.ty) return dd.custom("duplicate field `type`");
                try dd.colon();
                try dd.clientDataType();
                st.ty = true;
            } else if (std.mem.eql(u8, k, "challenge")) {
                if (st.challenge != null) return dd.custom("duplicate field `challenge`");
                try dd.colon();
                st.challenge = try dd.string();
            } else if (std.mem.eql(u8, k, "origin")) {
                if (st.origin != null) return dd.custom("duplicate field `origin`");
                try dd.colon();
                st.origin = try dd.string();
            } else {
                try dd.colon();
                try dd.ignoreValue();
            }
        }
        fn done(st: *@This(), dd: *D) Error!void {
            if (!st.ty) return dd.custom("missing field `type`");
            if (st.challenge == null) return dd.custom("missing field `challenge`");
            if (st.origin == null) return dd.custom("missing field `origin`");
        }
    };
    var st: V = .{};
    try structOf(d, "struct CollectedClientData with 3 elements", "struct CollectedClientData", V, &st);
    try d.end();
    return st.challenge.?;
}

/// serde_json `deserialize_struct` with a derived visitor: `[..]` (visit_seq) or `{..}` (visit_map).
fn structOf(d: *D, len_exp: []const u8, exp: []const u8, comptime V: type, st: *V) Error!void {
    const p = d.ws() orelse return d.perr("EOF while parsing a value");
    switch (p) {
        '[' => {
            try d.recurse();
            d.eat();
            var first = true;
            const r: Error!void = blk: {
                if (try st.seq(d, &first)) |missing| break :blk d.customf("invalid length {d}, expected {s}", .{ missing, len_exp });
            };
            d.remaining_depth += 1;
            if (r) |_| {
                d.endSeq() catch |e| return d.fix(e);
            } else |e| {
                if (e == error.OutOfMemory) return e;
                const saved = d.*;
                d.endSeq() catch {};
                restoreMsg(d, saved);
                return d.fix(e);
            }
        },
        '{' => {
            try d.recurse();
            d.eat();
            var first = true;
            const r: Error!void = blk: {
                while (d.nextKey(&first) catch |e| break :blk e) |k| st.field(d, k) catch |e| break :blk e;
                break :blk st.done(d);
            };
            d.remaining_depth += 1;
            if (r) |_| {
                d.endMap() catch |e| return d.fix(e);
            } else |e| {
                if (e == error.OutOfMemory) return e;
                const saved = d.*;
                d.endMap() catch {};
                restoreMsg(d, saved);
                return d.fix(e);
            }
        },
        else => return d.invalidType(exp),
    }
}

/// `(Err(err), _)`: the visitor's error wins; end_seq/end_map still ran (and may have eaten the
/// closing bracket) before fix_position.
fn restoreMsg(d: *D, saved: D) void {
    d.msg = saved.msg;
    d.line = saved.line;
    d.col = saved.col;
}

pub const Header = struct { alg: []const u8, kid: []const u8 };
pub const HeaderResult = union(enum) { ok: Header, err: []const u8 };

/// `serde_json::from_slice::<Header>`.
pub fn jwtHeader(arena: Allocator, s: []const u8) error{OutOfMemory}!HeaderResult {
    var d: D = .{ .s = s, .arena = arena, .utf8 = true };
    var st: HeaderV = .{};
    const r: Error!void = blk: {
        structOf(&d, "struct Header with 3 elements", "struct Header", HeaderV, &st) catch |e| break :blk e;
        break :blk d.end();
    };
    r catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Json => return .{ .err = try errText(&d) },
    };
    return .{ .ok = .{ .alg = st.alg.?, .kid = st.kid.? } };
}

const HeaderV = struct {
    alg: ?[]const u8 = null,
    kid: ?[]const u8 = null,
    typ: bool = false,
    fn optString(dd: *D) Error!void {
        if (dd.ws() == 'n') {
            dd.eat();
            return dd.ident("ull");
        }
        _ = try dd.string();
    }
    fn seq(v: *HeaderV, dd: *D, first: *bool) Error!?usize {
        if (!try dd.hasNextElement(first)) return 0;
        v.alg = try dd.string();
        if (!try dd.hasNextElement(first)) return 1;
        v.kid = try dd.string();
        if (!try dd.hasNextElement(first)) return 2;
        try optString(dd);
        return null;
    }
    fn field(v: *HeaderV, dd: *D, k: []const u8) Error!void {
        if (std.mem.eql(u8, k, "alg")) {
            if (v.alg != null) return dd.custom("duplicate field `alg`");
            try dd.colon();
            v.alg = try dd.string();
        } else if (std.mem.eql(u8, k, "kid")) {
            if (v.kid != null) return dd.custom("duplicate field `kid`");
            try dd.colon();
            v.kid = try dd.string();
        } else if (std.mem.eql(u8, k, "typ")) {
            if (v.typ) return dd.custom("duplicate field `typ`");
            try dd.colon();
            try optString(dd);
            v.typ = true;
        } else {
            try dd.colon();
            try dd.ignoreValue();
        }
    }
    fn done(v: *HeaderV, dd: *D) Error!void {
        if (v.alg == null) return dd.custom("missing field `alg`");
        if (v.kid == null) return dd.custom("missing field `kid`");
    }
};

pub const ClaimResult = union(enum) { ok: ?[]const u8, err: []const u8 };

/// `serde_json::from_str::<Value>(text)` then `.get(key)` as a string (null when absent or not a
/// string, or when the top level is not an object).
pub fn claim(arena: Allocator, s: []const u8, key: []const u8) error{OutOfMemory}!ClaimResult {
    var d: D = .{ .s = s, .arena = arena };
    var found: ?[]const u8 = null;
    const r: Error!void = blk: {
        d.value(key, &found) catch |e| break :blk e;
        break :blk d.end();
    };
    r catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Json => return .{ .err = try errText(&d) },
    };
    return .{ .ok = found };
}

// ------------------------------------------------------------------------------------------------

fn expectErr(comptime f: anytype, input: []const u8, want: []const u8) !void {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const r = try f(a.allocator(), input);
    try std.testing.expectEqualStrings(want, r.err);
}

test "clientDataJSON follows sui-sdk-types (crossOrigin and unknown keys are ignored values)" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const ok = [_][]const u8{
        "{\"type\":\"webauthn.get\",\"challenge\":\"AA\",\"origin\":\"o\",\"crossOrigin\":\"false\"}",
        "{\"type\":\"webauthn.get\",\"challenge\":\"AA\",\"origin\":\"o\",\"crossOrigin\":1,\"crossOrigin\":2}",
        "{\"type\":\"webauthn.get\",\"challenge\":\"AA\",\"origin\":\"o\",\"x\":1e400}",
        "{\"type\":\"webauthn.get\",\"challenge\":\"AA\",\"origin\":\"o\",\"x\":\"\\ud800\"}",
        "{\"type\":{\"webauthn.get\":null},\"challenge\":\"AA\",\"origin\":\"o\"}",
        "[\"webauthn.get\",\"AA\",\"o\"]",
    };
    for (ok) |s| {
        const r = try clientData(a.allocator(), s);
        try std.testing.expectEqualStrings("AA", r.ok);
    }
    // deep nesting in an ignored value has no recursion limit
    var deep: std.ArrayList(u8) = .empty;
    try deep.appendSlice(a.allocator(), "{\"type\":\"webauthn.get\",\"challenge\":\"AA\",\"origin\":\"o\",\"x\":");
    for (0..300) |_| try deep.append(a.allocator(), '[');
    for (0..300) |_| try deep.append(a.allocator(), ']');
    try deep.append(a.allocator(), '}');
    try std.testing.expectEqualStrings("AA", (try clientData(a.allocator(), deep.items)).ok);

    try expectErr(clientData, "{\"type\":\"webauthn.create\",\"challenge\":\"AA\",\"origin\":\"o\"}", "unknown variant `webauthn.create`, expected `webauthn.get` at line 1 column 25");
    try expectErr(clientData, "{\"type\":\"webauthn.get\",\"challenge\":\"AA\"}", "missing field `origin` at line 1 column 40");
    try expectErr(clientData, "{\"type\":\"webauthn.get\",\"type\":1}", "duplicate field `type` at line 1 column 29");
    try expectErr(clientData, "{\"type\":\"webauthn.get\",\"challenge\":1}", "invalid type: integer `1`, expected a string at line 1 column 36");
    try expectErr(clientData, "{\"type\":\"webauthn.get\",\"challenge\":1.5}", "invalid type: floating point `1.5`, expected a string at line 1 column 38");
    try expectErr(clientData, "{\"type\":\"webauthn.get\",\"challenge\":\"\\ud800\"}", "unexpected end of hex escape at line 1 column 43");
    try expectErr(clientData, "{\"type\":\"webauthn.get\",\"challenge\":\"AA\",\"origin\":\"o\"", "EOF while parsing an object at line 1 column 52");
    try expectErr(clientData, "{\"type\":\"webauthn.get\",\"challenge\":\"AA\",\"origin\":\"o\"} x", "trailing characters at line 1 column 55");
    try expectErr(clientData, "[\"webauthn.get\"]", "invalid length 1, expected struct CollectedClientData with 3 elements at line 1 column 16");
}

test "ryu layout" {
    var b: [64]u8 = undefined;
    try std.testing.expectEqualStrings("1.5", ryu(&b, 1.5));
    try std.testing.expectEqualStrings("1e16", ryu(&b, 1e16));
    try std.testing.expectEqualStrings("1000000000000000.0", ryu(&b, 1e15));
    try std.testing.expectEqualStrings("0.0001", ryu(&b, 1e-4));
    try std.testing.expectEqualStrings("0.00001", ryu(&b, 1e-5));
    try std.testing.expectEqualStrings("1e-6", ryu(&b, 1e-6));
    try std.testing.expectEqualStrings("-0.0", ryu(&b, -0.0));
    try std.testing.expectEqualStrings("1.2345e20", ryu(&b, 1.2345e20));
}

test "claim value and jwt header" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const c = try claim(a.allocator(), "{\"iss\":\"a\",\"iss\":\"b\"}", "iss");
    try std.testing.expectEqualStrings("b", c.ok.?);
    const e = try claim(a.allocator(), "{\"iss\":1e400}", "iss");
    try std.testing.expectEqualStrings("number out of range at line 1 column 12", e.err);
    const h = try jwtHeader(a.allocator(), "{\"alg\":\"RS256\",\"typ\":null}");
    try std.testing.expectEqualStrings("missing field `kid` at line 1 column 26", h.err);
    const h2 = try jwtHeader(a.allocator(), "{\"alg\":\"RS256\",\"kid\":\"k\"}");
    try std.testing.expectEqualStrings("k", h2.ok.kid);
}
