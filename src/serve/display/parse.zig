//! Display v2 templates: lexer, AST and parser (sui-display `v2/{lexer,parser,meter,error}.rs`,
//! sui-node 1.83.1). Error values carry what Rust's `FormatError` carries; `fmtError` prints
//! them with Rust's `Display` text, so per-field errors match byte for byte.
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types");

// ---------------------------------------------------------------------------------------------
// Lexer

pub const Token = enum(u8) {
    arrow,
    aarrow,
    tarrow,
    at,
    colon,
    ccolon,
    comma,
    dot,
    dollar,
    ident,
    langle,
    lbrace,
    lbracket,
    llbrace,
    lparen,
    num_dec,
    num_hex,
    pipe,
    pound,
    rangle,
    rbrace,
    rbracket,
    rparen,
    rrbrace,
    string,
    text,
    unexpected,
};

pub const Lexeme = struct {
    ws: bool,
    tok: Token,
    off: usize,
    slice: []const u8,
};

fn isIdentByte(b: u8) bool {
    return b == '_' or std.ascii.isAlphanumeric(b);
}
fn isHexByte(b: u8) bool {
    return b == '_' or std.ascii.isHex(b);
}
fn isDecByte(b: u8) bool {
    return b == '_' or std.ascii.isDigit(b);
}

/// `Lexer`: text mode at level 0, expression mode above. Lexing does not depend on the parser,
/// so the whole source is lexed up front (Rust's `Peekable2` buffers the same sequence).
pub fn lex(arena: Allocator, src: []const u8, expr: bool) Allocator.Error![]Lexeme {
    var out: std.ArrayList(Lexeme) = .empty;
    var level: usize = if (expr) std.math.maxInt(usize) / 2 else 0;
    var off: usize = 0;
    while (true) {
        if (level == 0) {
            if (off >= src.len) break;
            const rest = src[off..];
            switch (rest[0]) {
                '{' => if (rest.len > 1 and rest[1] == '{') {
                    try out.append(arena, .{ .ws = false, .tok = .llbrace, .off = off + 1, .slice = src[off + 1 .. off + 2] });
                    off += 2;
                } else {
                    level += 1;
                    try out.append(arena, .{ .ws = false, .tok = .lbrace, .off = off, .slice = src[off .. off + 1] });
                    off += 1;
                },
                '}' => if (rest.len > 1 and rest[1] == '}') {
                    try out.append(arena, .{ .ws = false, .tok = .rrbrace, .off = off + 1, .slice = src[off + 1 .. off + 2] });
                    off += 2;
                } else {
                    try out.append(arena, .{ .ws = false, .tok = .rbrace, .off = off, .slice = src[off .. off + 1] });
                    off += 1;
                },
                else => {
                    var n: usize = 0;
                    while (n < rest.len and rest[n] != '{' and rest[n] != '}') n += 1;
                    try out.append(arena, .{ .ws = false, .tok = .text, .off = off, .slice = rest[0..n] });
                    off += n;
                },
            }
            continue;
        }
        // expression mode
        const ws_start = off;
        while (off < src.len and std.ascii.isWhitespace(src[off])) off += 1;
        const ws = off > ws_start;
        if (off >= src.len) break;
        const rest = src[off..];
        const b0 = rest[0];
        const b1: ?u8 = if (rest.len > 1) rest[1] else null;
        var tok: Token = undefined;
        var n: usize = 1;
        switch (b0) {
            '-' => if (b1 == '>') {
                tok = .arrow;
                n = 2;
            } else {
                tok = .unexpected;
            },
            '=' => if (b1 == '>') {
                tok = .aarrow;
                n = 2;
            } else {
                tok = .unexpected;
            },
            '~' => if (b1 == '>') {
                tok = .tarrow;
                n = 2;
            } else {
                tok = .unexpected;
            },
            '@' => tok = .at,
            ':' => if (b1 == ':') {
                tok = .ccolon;
                n = 2;
            } else {
                tok = .colon;
            },
            ',' => tok = .comma,
            '.' => tok = .dot,
            '$' => tok = .dollar,
            '0'...'9' => if (b0 == '0' and b1 == 'x' and rest.len > 2 and isHexByte(rest[2])) {
                var k: usize = 2;
                while (k < rest.len and isHexByte(rest[k])) k += 1;
                try out.append(arena, .{ .ws = ws, .tok = .num_hex, .off = off + 2, .slice = rest[2..k] });
                off += k;
                continue;
            } else {
                tok = .num_dec;
                n = 0;
                while (n < rest.len and isDecByte(rest[n])) n += 1;
            },
            'a'...'z', 'A'...'Z', '_' => {
                tok = .ident;
                n = 0;
                while (n < rest.len and isIdentByte(rest[n])) n += 1;
            },
            '<' => tok = .langle,
            '{' => {
                level += 1;
                tok = .lbrace;
            },
            '[' => tok = .lbracket,
            '(' => tok = .lparen,
            '|' => tok = .pipe,
            '#' => tok = .pound,
            '>' => tok = .rangle,
            '}' => {
                level -= 1;
                tok = .rbrace;
            },
            ']' => tok = .rbracket,
            ')' => tok = .rparen,
            '\'' => {
                var escaped = true;
                var found: ?usize = null;
                for (rest, 0..) |b, i| {
                    if (escaped) {
                        escaped = false;
                    } else if (b == '\\') {
                        escaped = true;
                    } else if (b == '\'') {
                        found = i;
                        break;
                    }
                }
                if (found) |i| {
                    try out.append(arena, .{ .ws = ws, .tok = .string, .off = off + 1, .slice = rest[1..i] });
                    off += i + 1;
                    continue;
                }
                tok = .unexpected;
                n = rest.len;
            },
            else => {
                tok = .unexpected;
                n = 1;
                while (n < rest.len and (rest[n] & 0xc0) == 0x80) n += 1;
            },
        }
        try out.append(arena, .{ .ws = ws, .tok = tok, .off = off, .slice = rest[0..n] });
        off += n;
    }
    return out.items;
}

// ---------------------------------------------------------------------------------------------
// Errors

pub const Expected = union(enum) {
    literal: []const u8,
    token: Token,

    fn lessThan(_: void, a: Expected, b: Expected) bool {
        return switch (a) {
            .literal => |x| switch (b) {
                .literal => |y| std.mem.order(u8, x, y) == .lt,
                .token => true,
            },
            .token => |x| switch (b) {
                .literal => false,
                .token => |y| @intFromEnum(x) < @intFromEnum(y),
            },
        };
    }
    fn eql(a: Expected, b: Expected) bool {
        return switch (a) {
            .literal => |x| b == .literal and std.mem.eql(u8, x, b.literal),
            .token => |x| b == .token and b.token == x,
        };
    }
};

/// `ExpectedSet`: only the union of everything tried is ever printed, so a flat list suffices.
pub const ExpectedSet = []const Expected;

fn unionSets(arena: Allocator, a: ExpectedSet, b: ExpectedSet) Allocator.Error!ExpectedSet {
    const out = try arena.alloc(Expected, a.len + b.len);
    @memcpy(out[0..a.len], a);
    @memcpy(out[a.len..], b);
    return out;
}

pub const InvalidNumber = struct { what: []const u8, offset: usize, err: []const u8 };

/// `FormatError` (v2/error.rs).
pub const FormatError = union(enum) {
    /// "BCS error: {msg}"
    bcs: []const u8,
    invalid_hex_character: Lexeme,
    invalid_identifier: Lexeme,
    invalid_number: InvalidNumber,
    odd_hex_literal: Lexeme,
    /// "Storage error: {msg}"
    store: []const u8,
    too_big,
    too_deep,
    too_many_loads,
    too_much_output,
    transform_invalid: []const u8,
    transform_invalid_at: struct { offset: usize, reason: []const u8 },
    unexpected_eos: ExpectedSet,
    unexpected_remaining: Lexeme,
    unexpected_token: struct { actual: Lexeme, expect: ExpectedSet },
    vector_arity: struct { offset: usize, arity: usize },
    vector_no_type,
    vector_type_mismatch: struct { offset: usize, this: types.TypeTag, that: types.TypeTag },
    /// "Deserialization error: {msg}"
    visitor: []const u8,

    pub fn forExprAtOffset(e: FormatError, offset: usize) FormatError {
        return switch (e) {
            .transform_invalid => |r| .{ .transform_invalid_at = .{ .offset = offset, .reason = r } },
            else => e,
        };
    }
};

/// Rust `{:?}` of a `str` (ASCII exact; other printable code points pass through).
pub fn debugStr(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    for (s) |b| switch (b) {
        '\t' => try w.writeAll("\\t"),
        '\r' => try w.writeAll("\\r"),
        '\n' => try w.writeAll("\\n"),
        '\\' => try w.writeAll("\\\\"),
        '"' => try w.writeAll("\\\""),
        0 => try w.writeAll("\\0"),
        1...8, 11, 12, 14...31, 127 => try w.print("\\u{{{x}}}", .{b}),
        else => try w.writeByte(b),
    };
    try w.writeByte('"');
}

fn tokenName(t: Token) []const u8 {
    return switch (t) {
        .arrow => "'->'",
        .aarrow => "'=>'",
        .tarrow => "'~>'",
        .at => "'@'",
        .colon => "':'",
        .ccolon => "'::'",
        .comma => "','",
        .dot => "'.'",
        .dollar => "'$'",
        .ident => "an identifier",
        .langle => "'<'",
        .lbrace => "'{'",
        .lbracket => "'['",
        .llbrace => "'{{'",
        .lparen => "'('",
        .num_dec => "a decimal number",
        .num_hex => "a hexadecimal number",
        .pipe => "'|'",
        .pound => "'#'",
        .rangle => "'>'",
        .rbrace => "'}'",
        .rbracket => "']'",
        .rparen => "')'",
        .rrbrace => "'}}'",
        .string => "a string",
        .text => "text",
        .unexpected => "unexpected input",
    };
}

fn fmtLexeme(w: *std.Io.Writer, l: Lexeme) std.Io.Writer.Error!void {
    if (l.ws) try w.writeAll("whitespace followed by ");
    switch (l.tok) {
        .ident => {
            try w.writeAll("identifier ");
            try debugStr(w, l.slice);
        },
        .num_dec => {
            try w.writeAll("decimal number ");
            try debugStr(w, l.slice);
        },
        .num_hex => {
            try w.writeAll("hexadecimal number ");
            try debugStr(w, l.slice);
        },
        .string => {
            try w.writeAll("string ");
            try debugStr(w, l.slice);
        },
        .text => {
            try w.writeAll("text ");
            try debugStr(w, l.slice);
        },
        .unexpected => {
            try w.writeByte('"');
            for (l.slice) |b| switch (b) {
                '"' => try w.writeAll("\\\""),
                '\\' => try w.writeAll("\\\\"),
                '\n' => try w.writeAll("\\n"),
                '\t' => try w.writeAll("\\t"),
                '\r' => try w.writeAll("\\r"),
                ' '...'!', '#'...'[', ']'...'~' => try w.writeByte(b),
                else => try w.print("\\x{X:0>2}", .{b}),
            };
            try w.writeByte('"');
        },
        else => try w.writeAll(tokenName(l.tok)),
    }
    try w.print(" at byte offset {d}", .{l.off});
}

fn fmtExpected(w: *std.Io.Writer, arena: Allocator, set: ExpectedSet) !void {
    const items = try arena.dupe(Expected, set);
    std.mem.sort(Expected, items, {}, Expected.lessThan);
    var uniq: std.ArrayList(Expected) = .empty;
    for (items) |e| if (uniq.items.len == 0 or !uniq.items[uniq.items.len - 1].eql(e)) try uniq.append(arena, e);
    if (uniq.items.len == 0) return w.writeAll("nothing");
    var prefix: []const u8 = if (uniq.items.len > 1) "one of " else "";
    for (uniq.items, 0..) |e, i| {
        try w.writeAll(prefix);
        switch (e) {
            .literal => |s| try w.print("'{s}'", .{s}),
            .token => |t| try w.writeAll(tokenName(t)),
        }
        prefix = if (i + 2 < uniq.items.len) ", " else ", or ";
    }
}

/// Rust `Display` of `FormatError`.
pub fn fmtError(w: *std.Io.Writer, arena: Allocator, e: FormatError) !void {
    switch (e) {
        .bcs => |m| try w.print("BCS error: {s}", .{m}),
        .invalid_hex_character => |l| {
            try w.writeAll("Hex ");
            try fmtLexeme(w, l);
            try w.writeAll(" contains invalid character");
        },
        .invalid_identifier => |l| {
            try w.writeAll("Invalid ");
            try fmtLexeme(w, l);
        },
        .invalid_number => |n| try w.print("Invalid {s} at byte offset {d}: {s}", .{ n.what, n.offset, n.err }),
        .odd_hex_literal => |l| {
            try w.writeAll("Odd number of characters in hex ");
            try fmtLexeme(w, l);
        },
        .store => |m| try w.print("Storage error: {s}", .{m}),
        .too_big => try w.writeAll("Display contains too many elements"),
        .too_deep => try w.writeAll("Format is nested too deeply"),
        .too_many_loads => try w.writeAll("Display tries to load too many objects"),
        .too_much_output => try w.writeAll("Display produces too much output"),
        .transform_invalid => |r| try w.print("Invalid transform: {s}", .{r}),
        .transform_invalid_at => |t| try w.print("Invalid transform for expression at byte offset {d}: {s}", .{ t.offset, t.reason }),
        .unexpected_eos => |s| {
            try w.writeAll("Unexpected end-of-string, expected ");
            try fmtExpected(w, arena, s);
        },
        .unexpected_remaining => |l| {
            try w.writeAll("Unexpected ");
            try fmtLexeme(w, l);
            try w.writeAll(", expected end-of-string");
        },
        .unexpected_token => |t| {
            try w.writeAll("Unexpected ");
            try fmtLexeme(w, t.actual);
            try w.writeAll(", expected ");
            try fmtExpected(w, arena, t.expect);
        },
        .vector_arity => |v| try w.print("Vector at byte offset {d} requires 1 type parameter, found {d}", .{ v.offset, v.arity }),
        .vector_no_type => try w.writeAll("Internal error: vector without element type"),
        .vector_type_mismatch => |v| {
            try w.print("Vector at byte offset {d}, could have element type ", .{v.offset});
            try fmtTypeTag(w, v.this);
            try w.writeAll(" or ");
            try fmtTypeTag(w, v.that);
        },
        .visitor => |m| try w.print("Deserialization error: {s}", .{m}),
    }
}

pub fn errorString(arena: Allocator, e: FormatError) Allocator.Error![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    fmtError(&aw.writer, arena, e) catch return error.OutOfMemory;
    return aw.written();
}

/// `TypeTag::to_canonical_display(true)`.
pub fn fmtTypeTag(w: *std.Io.Writer, t: types.TypeTag) std.Io.Writer.Error!void {
    switch (t) {
        .bool => try w.writeAll("bool"),
        .u8 => try w.writeAll("u8"),
        .u16 => try w.writeAll("u16"),
        .u32 => try w.writeAll("u32"),
        .u64 => try w.writeAll("u64"),
        .u128 => try w.writeAll("u128"),
        .u256 => try w.writeAll("u256"),
        .address => try w.writeAll("address"),
        .signer => try w.writeAll("signer"),
        .vector => |e| {
            try w.writeAll("vector<");
            try fmtTypeTag(w, e.*);
            try w.writeAll(">");
        },
        .@"struct" => |s| {
            try w.print("0x{x}::{s}::{s}", .{ &s.address.@"0", s.module.@"0", s.name.@"0" });
            if (s.type_args.len > 0) {
                try w.writeAll("<");
                for (s.type_args, 0..) |a, i| {
                    if (i > 0) try w.writeAll(", ");
                    try fmtTypeTag(w, a);
                }
                try w.writeAll(">");
            }
        },
    }
}

// ---------------------------------------------------------------------------------------------
// Meter

pub const Limits = struct {
    max_depth: usize = 32,
    max_nodes: usize = 32768,
    max_loads: usize = 8,
};

pub const Budget = struct { nodes: usize, loads: usize };

pub const Meter = struct {
    depth: usize,
    budget: *Budget,

    fn nest(m: *Meter, p: *Parser) Fail!Meter {
        if (m.depth == 0) return p.fail(.too_deep);
        return .{ .depth = m.depth - 1, .budget = m.budget };
    }
    fn alloc(m: *Meter, p: *Parser) Fail!void {
        if (m.budget.nodes == 0) return p.fail(.too_big);
        m.budget.nodes -= 1;
    }
    fn load(m: *Meter, p: *Parser) Fail!void {
        if (m.budget.loads == 0) return p.fail(.too_many_loads);
        m.budget.loads -= 1;
    }
};

// ---------------------------------------------------------------------------------------------
// AST

pub const Strand = union(enum) {
    text: []const u8,
    expr: Expr,
};

pub const Expr = struct {
    offset: usize,
    alternates: []const Chain,
    transform: ?Transform,
};

pub const Chain = struct {
    root: ?*const Literal,
    accessors: []const Accessor,
};

pub const Accessor = union(enum) {
    field: []const u8,
    positional: u8,
    index: Chain,
    df_index: Chain,
    dof_index: Chain,
    derived: Chain,
};

pub const Literal = union(enum) {
    self_,
    address: [32]u8,
    bool: bool,
    u8: u8,
    u16: u16,
    u32: u32,
    u64: u64,
    u128: u128,
    u256: u256,
    byte_array: []const u8,
    string: []const u8,
    vector: VectorLit,
    @"struct": StructLit,
    @"enum": EnumLit,
};

pub const VectorLit = struct { offset: usize, type_: ?types.TypeTag, elements: []const Chain };
pub const StructLit = struct { type_: types.StructTag, fields: Fields };
pub const EnumLit = struct { type_: types.StructTag, variant_name: ?[]const u8, variant_index: u16, fields: Fields };
pub const Named = struct { name: []const u8, chain: Chain };
pub const Fields = union(enum) {
    positional: []const Chain,
    named: []const Named,
};

pub const Base64Mod = packed struct(u8) { _pad0: u1 = 0, url: bool = false, nopad: bool = false, _pad: u5 = 0 };

pub const Transform = union(enum) {
    base64: Base64Mod,
    bcs: Base64Mod,
    hex,
    json,
    str,
    timestamp,
    url,
};

// ---------------------------------------------------------------------------------------------
// Parser

pub const Fail = error{ Format, OutOfMemory };

const Tried = struct { off: ?usize, set: ExpectedSet };

fn Match(comptime T: type) type {
    return union(enum) {
        found: T,
        tried: Tried,
    };
}

const Pat = struct {
    kind: enum { lit, tok },
    tok: Token,
    lit: []const u8 = "",
    /// for literal patterns with `false` whitespace binding
    no_ws: bool = false,
};

fn tokE(comptime ts: []const Token) []const Expected {
    comptime {
        var out: [ts.len]Expected = undefined;
        for (ts, 0..) |t, i| out[i] = .{ .token = t };
        const final = out;
        return &final;
    }
}

pub const Parser = struct {
    arena: Allocator,
    toks: []const Lexeme,
    i: usize = 0,
    err: FormatError = .too_big,

    fn fail(p: *Parser, e: FormatError) error{Format} {
        p.err = e;
        return error.Format;
    }

    fn peek(p: *const Parser) ?Lexeme {
        return if (p.i < p.toks.len) p.toks[p.i] else null;
    }
    fn peek2(p: *const Parser) ?Lexeme {
        return if (p.i + 1 < p.toks.len) p.toks[p.i + 1] else null;
    }
    fn next(p: *Parser) ?Lexeme {
        const l = p.peek();
        if (l != null) p.i += 1;
        return l;
    }

    fn intoError(p: *Parser, set: ExpectedSet) error{Format} {
        if (p.peek()) |l| return p.fail(.{ .unexpected_token = .{ .actual = l, .expect = set } });
        return p.fail(.{ .unexpected_eos = set });
    }

    fn tried(p: *const Parser, set: ExpectedSet) Tried {
        return .{ .off = if (p.peek()) |l| l.off else null, .set = set };
    }

    fn isTok(p: *const Parser, t: Token) bool {
        const l = p.peek() orelse return false;
        return l.tok == t;
    }
    fn isLit(p: *const Parser, s: []const u8) bool {
        const l = p.peek() orelse return false;
        return l.tok == .ident and std.mem.eql(u8, l.slice, s);
    }

    /// `match_token!` with one token pattern: consume it or fail with `set` (+ `prev`).
    fn expect(p: *Parser, t: Token, prev: ExpectedSet) Fail!Lexeme {
        if (p.isTok(t)) return p.next().?;
        return p.intoError(try unionSets(p.arena, &.{.{ .token = t }}, prev));
    }

    fn alsoTried(p: *Parser, off: ?usize, set: ExpectedSet) Allocator.Error!void {
        switch (p.err) {
            .unexpected_token => |*t| if (off != null and off.? == t.actual.off) {
                t.expect = try unionSets(p.arena, t.expect, set);
            },
            .unexpected_eos => |*s| if (off == null) {
                s.* = try unionSets(p.arena, s.*, set);
            },
            else => {},
        }
    }

    // --- entry points

    pub fn format(arena: Allocator, src: []const u8, meter: *Meter, err: *FormatError) Fail![]const Strand {
        var p: Parser = .{ .arena = arena, .toks = try lex(arena, src, false) };
        const strands = p.parseFormat(meter) catch |e| {
            err.* = p.err;
            return e;
        };
        p.parseEos() catch |e| {
            err.* = p.err;
            return e;
        };
        return strands;
    }

    fn parseEos(p: *Parser) Fail!void {
        if (p.next()) |l| return p.fail(.{ .unexpected_remaining = l });
    }

    fn parseFormat(p: *Parser, meter: *Meter) Fail![]const Strand {
        var out: std.ArrayList(Strand) = .empty;
        while (p.peek() != null) try out.append(p.arena, try p.parseStrand(meter));
        return out.items;
    }

    fn parseStrand(p: *Parser, meter: *Meter) Fail!Strand {
        const l = p.peek();
        if (l) |x| switch (x.tok) {
            .text, .llbrace, .rrbrace => return .{ .text = try p.parseText(meter) },
            .lbrace => return .{ .expr = try p.parseExpr(meter) },
            else => {},
        };
        return p.intoError(comptime tokE(&.{ .text, .llbrace, .rrbrace, .lbrace }));
    }

    fn parseText(p: *Parser, meter: *Meter) Fail![]const u8 {
        var buf: std.ArrayList(u8) = .empty;
        // parse_part
        while (p.peek()) |l| switch (l.tok) {
            .text, .llbrace, .rrbrace => {
                _ = p.next();
                try buf.appendSlice(p.arena, l.slice);
            },
            else => break,
        };
        try meter.alloc(p);
        return buf.items;
    }

    fn parseExpr(p: *Parser, meter: *Meter) Fail!Expr {
        const open = try p.expect(.lbrace, &.{});
        var alts: std.ArrayList(Chain) = .empty;
        try alts.append(p.arena, try p.parseChain(meter));
        var transform: ?Transform = null;
        while (true) {
            if (p.isTok(.rbrace)) {
                _ = p.next();
                break;
            } else if (p.isTok(.colon)) {
                _ = p.next();
                transform = try p.parseXform();
                _ = try p.expect(.rbrace, &.{});
                break;
            } else if (p.isTok(.pipe)) {
                _ = p.next();
                try alts.append(p.arena, try p.parseChain(meter));
            } else return p.intoError(comptime tokE(&.{ .rbrace, .colon, .pipe }));
        }
        try meter.alloc(p);
        return .{ .offset = open.off, .alternates = alts.items, .transform = transform };
    }

    fn validIdent(s: []const u8) bool {
        // move-core-types `is_valid`: [a-zA-Z][a-zA-Z0-9_]* | _[a-zA-Z0-9_]+
        if (s.len == 0) return false;
        if (s[0] == '_') return s.len > 1;
        return std.ascii.isAlphabetic(s[0]);
    }

    fn parseChain(p: *Parser, outer: *Meter) Fail!Chain {
        var meter = try outer.nest(p);
        var accessors: std.ArrayList(Accessor) = .empty;
        var root: ?*const Literal = null;
        switch (try p.tryParseLiteral(&meter)) {
            .found => |lit| {
                const r = try p.arena.create(Literal);
                r.* = lit;
                root = r;
            },
            .tried => |t| {
                if (p.peek()) |l| if (l.tok == .ident) {
                    if (!validIdent(l.slice)) return p.fail(.{ .invalid_identifier = l });
                    _ = p.next();
                    try meter.alloc(p);
                    try accessors.append(p.arena, .{ .field = l.slice });
                };
                if (accessors.items.len == 0) return p.intoError(try unionSets(p.arena, &.{.{ .token = .ident }}, t.set));
            },
        }
        while (true) {
            switch (try p.tryParseAccessor(&meter)) {
                .found => |a| try accessors.append(p.arena, a),
                .tried => break,
            }
        }
        try meter.alloc(p);
        return .{ .root = root, .accessors = accessors.items };
    }

    const literal_set = [_]Expected{
        .{ .token = .dollar },      .{ .token = .at },          .{ .literal = "true" },
        .{ .literal = "false" },    .{ .token = .num_dec },     .{ .token = .num_hex },
        .{ .token = .num_dec },     .{ .token = .num_hex },     .{ .token = .string },
        .{ .literal = "b" },        .{ .literal = "x" },        .{ .token = .ident },
    };

    fn tryParseLiteral(p: *Parser, meter: *Meter) Fail!Match(Literal) {
        const l = p.peek() orelse return .{ .tried = p.tried(&literal_set) };
        switch (l.tok) {
            .dollar => {
                _ = p.next();
                const s = p.peek();
                if (s == null or s.?.ws or s.?.tok != .ident or !std.mem.eql(u8, s.?.slice, "self"))
                    return p.intoError(&.{.{ .literal = "self" }});
                _ = p.next();
                try meter.alloc(p);
                return .{ .found = .self_ };
            },
            .at => {
                _ = p.next();
                try meter.alloc(p);
                return .{ .found = .{ .address = try p.parseAddress() } };
            },
            .ident => {
                if (std.mem.eql(u8, l.slice, "true")) {
                    _ = p.next();
                    try meter.alloc(p);
                    return .{ .found = .{ .bool = true } };
                }
                if (std.mem.eql(u8, l.slice, "false")) {
                    _ = p.next();
                    try meter.alloc(p);
                    return .{ .found = .{ .bool = false } };
                }
                const n2 = p.peek2();
                if (std.mem.eql(u8, l.slice, "b") and n2 != null and !n2.?.ws and n2.?.tok == .string) {
                    _ = p.next();
                    const s = p.next().?;
                    try meter.alloc(p);
                    return .{ .found = .{ .byte_array = try readStringLiteral(p.arena, s.slice) } };
                }
                if (std.mem.eql(u8, l.slice, "x") and n2 != null and !n2.?.ws and n2.?.tok == .string) {
                    _ = p.next();
                    const s = p.next().?;
                    const out = try p.readHexLiteral(s);
                    try meter.alloc(p);
                    return .{ .found = .{ .byte_array = out } };
                }
                if (std.mem.eql(u8, l.slice, "vector")) {
                    _ = p.next();
                    const tps = try p.parseTypeParams(meter);
                    const type_: ?types.TypeTag = switch (tps.len) {
                        0 => null,
                        1 => tps[0],
                        else => return p.fail(.{ .vector_arity = .{ .offset = l.off, .arity = tps.len } }),
                    };
                    const elements = try p.parseArrayElements(meter);
                    if (elements.len == 0 and type_ == null) return p.fail(.{ .vector_arity = .{ .offset = l.off, .arity = 0 } });
                    try meter.alloc(p);
                    return .{ .found = .{ .vector = .{ .offset = l.off, .type_ = type_, .elements = elements } } };
                }
                return .{ .tried = p.tried(&literal_set) };
            },
            .num_dec, .num_hex => {
                if (p.peek2()) |n2| if (n2.tok == .ccolon) return .{ .found = try p.parseData(meter) };
                _ = p.next();
                return .{ .found = try p.parseNumericSuffix(l.off, l.slice, if (l.tok == .num_dec) 10 else 16, meter) };
            },
            .string => {
                _ = p.next();
                try meter.alloc(p);
                return .{ .found = .{ .string = try readStringLiteral(p.arena, l.slice) } };
            },
            else => return .{ .tried = p.tried(&literal_set) },
        }
    }

    const accessor_set = tokE(&.{ .dot, .arrow, .aarrow, .tarrow, .lbracket });

    fn tryParseAccessor(p: *Parser, meter: *Meter) Fail!Match(Accessor) {
        const l = p.peek() orelse return .{ .tried = p.tried(accessor_set) };
        switch (l.tok) {
            .dot => {
                _ = p.next();
                const f = p.peek();
                if (f) |x| switch (x.tok) {
                    .ident => {
                        if (!validIdent(x.slice)) return p.fail(.{ .invalid_identifier = x });
                        _ = p.next();
                        try meter.alloc(p);
                        return .{ .found = .{ .field = x.slice } };
                    },
                    .num_dec => {
                        _ = p.next();
                        const idx = try p.readInt(u8, x.off, x.slice, 10, "positional field index");
                        try meter.alloc(p);
                        return .{ .found = .{ .positional = idx } };
                    },
                    else => {},
                };
                return p.intoError(comptime tokE(&.{ .ident, .num_dec }));
            },
            .arrow, .aarrow, .tarrow => {
                _ = p.next();
                _ = try p.expect(.lbracket, &.{});
                const chain = try p.parseChain(meter);
                _ = try p.expect(.rbracket, &.{});
                try meter.load(p);
                if (l.tok == .aarrow) try meter.load(p);
                try meter.alloc(p);
                return .{ .found = switch (l.tok) {
                    .arrow => .{ .df_index = chain },
                    .aarrow => .{ .dof_index = chain },
                    else => .{ .derived = chain },
                } };
            },
            .lbracket => {
                _ = p.next();
                const chain = try p.parseChain(meter);
                _ = try p.expect(.rbracket, &.{});
                try meter.alloc(p);
                return .{ .found = .{ .index = chain } };
            },
            else => return .{ .tried = p.tried(accessor_set) },
        }
    }

    /// Delimited list tail: after an item, `,` continues and `close` ends.
    fn listStep(p: *Parser, close: Token) Fail!bool {
        const comma = p.isTok(.comma);
        if (comma) _ = p.next();
        if (p.isTok(close)) {
            _ = p.next();
            return true;
        }
        if (comma) return false;
        return p.intoError(try unionSets(p.arena, &.{.{ .token = .comma }}, &.{.{ .token = close }}));
    }

    fn parseChainAlso(p: *Parser, meter: *Meter, off: ?usize, set: ExpectedSet) Fail!Chain {
        return p.parseChain(meter) catch |e| {
            if (e == error.Format) try p.alsoTried(off, set);
            return e;
        };
    }

    fn parseArrayElements(p: *Parser, meter: *Meter) Fail![]const Chain {
        var out: std.ArrayList(Chain) = .empty;
        if (!p.isTok(.lbracket)) return out.items;
        _ = p.next();
        if (p.isTok(.rbracket)) {
            _ = p.next();
            return out.items;
        }
        const t = p.tried(comptime tokE(&.{.rbracket}));
        while (true) {
            try out.append(p.arena, try p.parseChainAlso(meter, t.off, t.set));
            if (try p.listStep(.rbracket)) break;
        }
        return out.items;
    }

    fn parseData(p: *Parser, meter: *Meter) Fail!Literal {
        const type_ = try p.parseDatatype(meter);
        if (!p.isTok(.ccolon)) {
            const t = p.tried(comptime tokE(&.{.ccolon}));
            try meter.alloc(p);
            const fields = p.parseFields(meter) catch |e| {
                if (e == error.Format) try p.alsoTried(t.off, t.set);
                return e;
            };
            return .{ .@"struct" = .{ .type_ = type_, .fields = fields } };
        }
        _ = p.next();
        const l = p.peek();
        if (l) |x| switch (x.tok) {
            .ident => {
                _ = p.next();
                _ = try p.expect(.pound, &.{});
                const n = try p.expect(.num_dec, &.{});
                const idx = try p.readInt(u16, n.off, n.slice, 10, "enum variant index");
                try meter.alloc(p);
                return .{ .@"enum" = .{ .type_ = type_, .variant_name = x.slice, .variant_index = idx, .fields = try p.parseFields(meter) } };
            },
            .num_dec => {
                _ = p.next();
                const idx = try p.readInt(u16, x.off, x.slice, 10, "enum variant index");
                try meter.alloc(p);
                return .{ .@"enum" = .{ .type_ = type_, .variant_name = null, .variant_index = idx, .fields = try p.parseFields(meter) } };
            },
            else => {},
        };
        return p.intoError(comptime tokE(&.{ .ident, .num_dec }));
    }

    fn parseFields(p: *Parser, meter: *Meter) Fail!Fields {
        const named = if (p.isTok(.lparen)) false else if (p.isTok(.lbrace)) true else return p.intoError(comptime tokE(&.{ .lparen, .lbrace }));
        _ = p.next();
        if (named) {
            var out: std.ArrayList(Named) = .empty;
            if (p.isTok(.rbrace)) {
                _ = p.next();
                return .{ .named = out.items };
            }
            const term: ExpectedSet = comptime tokE(&.{.rbrace});
            while (true) {
                const name = try p.expect(.ident, term);
                _ = try p.expect(.colon, &.{});
                const chain = try p.parseChain(meter);
                try out.append(p.arena, .{ .name = name.slice, .chain = chain });
                if (try p.listStep(.rbrace)) break;
            }
            return .{ .named = out.items };
        }
        var out: std.ArrayList(Chain) = .empty;
        if (p.isTok(.rparen)) {
            _ = p.next();
            return .{ .positional = out.items };
        }
        const t = p.tried(comptime tokE(&.{.rparen}));
        while (true) {
            try out.append(p.arena, try p.parseChainAlso(meter, t.off, t.set));
            if (try p.listStep(.rparen)) break;
        }
        return .{ .positional = out.items };
    }

    const type_set = [_]Expected{
        .{ .literal = "address" }, .{ .literal = "bool" }, .{ .literal = "u8" },     .{ .literal = "u16" },
        .{ .literal = "u32" },     .{ .literal = "u64" },  .{ .literal = "u128" },   .{ .literal = "u256" },
        .{ .literal = "vector" },  .{ .token = .num_dec }, .{ .token = .num_hex },
    };

    fn parseType(p: *Parser, outer: *Meter) Fail!types.TypeTag {
        var meter = try outer.nest(p);
        const l = p.peek() orelse return p.intoError(&type_set);
        switch (l.tok) {
            .ident => {
                const prims = [_]struct { []const u8, types.TypeTag }{
                    .{ "address", .address }, .{ "bool", .bool }, .{ "u8", .u8 },     .{ "u16", .u16 },
                    .{ "u32", .u32 },         .{ "u64", .u64 },   .{ "u128", .u128 }, .{ "u256", .u256 },
                };
                for (prims) |pr| if (std.mem.eql(u8, l.slice, pr[0])) {
                    _ = p.next();
                    try meter.alloc(p);
                    return pr[1];
                };
                if (std.mem.eql(u8, l.slice, "vector")) {
                    _ = p.next();
                    const tps = try p.parseTypeParams(&meter);
                    if (tps.len != 1) return p.fail(.{ .vector_arity = .{ .offset = l.off, .arity = tps.len } });
                    try meter.alloc(p);
                    const inner = try p.arena.create(types.TypeTag);
                    inner.* = tps[0];
                    return .{ .vector = inner };
                }
            },
            .num_dec, .num_hex => return .{ .@"struct" = try p.parseDatatype(&meter) },
            else => {},
        }
        return p.intoError(&type_set);
    }

    fn parseDatatype(p: *Parser, meter: *Meter) Fail!types.StructTag {
        const address = try p.parseAddress();
        _ = try p.expect(.ccolon, &.{});
        const module = try p.parseIdentifier();
        _ = try p.expect(.ccolon, &.{});
        const name = try p.parseIdentifier();
        const tps = try p.parseTypeParams(meter);
        try meter.alloc(p);
        return .{ .address = .{ .@"0" = address }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = tps };
    }

    fn parseTypeParams(p: *Parser, meter: *Meter) Fail![]const types.TypeTag {
        var out: std.ArrayList(types.TypeTag) = .empty;
        if (!p.isTok(.langle)) return out.items;
        _ = p.next();
        while (true) {
            try out.append(p.arena, try p.parseType(meter));
            if (try p.listStep(.rangle)) break;
        }
        return out.items;
    }

    fn parseAddress(p: *Parser) Fail![32]u8 {
        const l = p.peek();
        if (l) |x| if (x.tok == .num_hex or x.tok == .num_dec) {
            _ = p.next();
            const v = try p.readInt(u256, x.off, x.slice, if (x.tok == .num_hex) 16 else 10, "'address'");
            var out: [32]u8 = undefined;
            std.mem.writeInt(u256, &out, v, .big);
            return out;
        };
        return p.intoError(comptime tokE(&.{ .num_hex, .num_dec }));
    }

    fn parseIdentifier(p: *Parser) Fail![]const u8 {
        const l = p.peek();
        if (l) |x| if (x.tok == .ident) {
            if (!validIdent(x.slice)) return p.fail(.{ .invalid_identifier = x });
            _ = p.next();
            return x.slice;
        };
        return p.intoError(comptime tokE(&.{.ident}));
    }

    fn parseNumericSuffix(p: *Parser, off: usize, num: []const u8, radix: u8, meter: *Meter) Fail!Literal {
        const l = p.peek();
        if (l) |x| if (!x.ws and x.tok == .ident) {
            const s = x.slice;
            if (std.mem.eql(u8, s, "u8")) {
                _ = p.next();
                try meter.alloc(p);
                return .{ .u8 = try p.readInt(u8, off, num, radix, "'u8'") };
            } else if (std.mem.eql(u8, s, "u16")) {
                _ = p.next();
                try meter.alloc(p);
                return .{ .u16 = try p.readInt(u16, off, num, radix, "'u16'") };
            } else if (std.mem.eql(u8, s, "u32")) {
                _ = p.next();
                try meter.alloc(p);
                return .{ .u32 = try p.readInt(u32, off, num, radix, "'u32'") };
            } else if (std.mem.eql(u8, s, "u64")) {
                _ = p.next();
                try meter.alloc(p);
                return .{ .u64 = try p.readInt(u64, off, num, radix, "'u64'") };
            } else if (std.mem.eql(u8, s, "u128")) {
                _ = p.next();
                try meter.alloc(p);
                return .{ .u128 = try p.readInt(u128, off, num, radix, "'u128'") };
            } else if (std.mem.eql(u8, s, "u256")) {
                _ = p.next();
                try meter.alloc(p);
                return .{ .u256 = try p.readInt(u256, off, num, radix, "'u256'") };
            }
        };
        return p.intoError(&.{
            .{ .literal = "u8" },  .{ .literal = "u16" },  .{ .literal = "u32" },
            .{ .literal = "u64" }, .{ .literal = "u128" }, .{ .literal = "u256" },
        });
    }

    fn parseXform(p: *Parser) Fail!Transform {
        const l = p.peek();
        if (l) |x| if (x.tok == .ident) {
            const s = x.slice;
            if (std.mem.eql(u8, s, "base64")) {
                _ = p.next();
                return .{ .base64 = try p.parseXmod() };
            } else if (std.mem.eql(u8, s, "bcs")) {
                _ = p.next();
                return .{ .bcs = try p.parseXmod() };
            } else if (std.mem.eql(u8, s, "hex")) {
                _ = p.next();
                return .hex;
            } else if (std.mem.eql(u8, s, "json")) {
                _ = p.next();
                return .json;
            } else if (std.mem.eql(u8, s, "str")) {
                _ = p.next();
                return .str;
            } else if (std.mem.eql(u8, s, "ts")) {
                _ = p.next();
                return .timestamp;
            } else if (std.mem.eql(u8, s, "url")) {
                _ = p.next();
                return .url;
            }
        };
        return p.intoError(&.{
            .{ .literal = "base64" }, .{ .literal = "bcs" }, .{ .literal = "hex" }, .{ .literal = "json" },
            .{ .literal = "str" },    .{ .literal = "ts" },  .{ .literal = "url" },
        });
    }

    fn parseXmod(p: *Parser) Fail!Base64Mod {
        var m: Base64Mod = .{};
        if (!p.isTok(.lparen)) return m;
        _ = p.next();
        while (true) {
            if (p.isLit("url")) {
                _ = p.next();
                m.url = true;
            } else if (p.isLit("nopad")) {
                _ = p.next();
                m.nopad = true;
            } else return p.intoError(&.{ .{ .literal = "url" }, .{ .literal = "nopad" } });
            if (try p.listStep(.rparen)) break;
        }
        return m;
    }

    /// `from_str_radix` after removing `_`, with Rust's error texts.
    fn readInt(p: *Parser, comptime T: type, off: usize, slice: []const u8, radix: u8, what: []const u8) Fail!T {
        var digits: std.ArrayList(u8) = .empty;
        for (slice) |c| if (c != '_') try digits.append(p.arena, c);
        var d = digits.items;
        if (T == u256) {
            // move U256: leading zeros trimmed, then the `uint` crate's parser
            var k: usize = 0;
            while (k < d.len and d[k] == '0') k += 1;
            d = d[k..];
            if (radix == 16 and d.len > 64) return p.fail(.{ .invalid_number = .{ .what = what, .offset = off, .err = "Invalid string length" } });
            if (d.len == 0) return 0;
        } else if (d.len == 0) {
            return p.fail(.{ .invalid_number = .{ .what = what, .offset = off, .err = "cannot parse integer from empty string" } });
        }
        return std.fmt.parseUnsigned(T, d, radix) catch |e| switch (e) {
            error.Overflow => p.fail(.{ .invalid_number = .{ .what = what, .offset = off, .err = if (T == u256) "the number is too large for the type" else "number too large to fit in target type" } }),
            error.InvalidCharacter => p.fail(.{ .invalid_number = .{ .what = what, .offset = off, .err = "invalid digit found in string" } }),
        };
    }

    fn readHexLiteral(p: *Parser, l: Lexeme) Fail![]const u8 {
        if (l.slice.len % 2 != 0) return p.fail(.{ .odd_hex_literal = l });
        const out = try p.arena.alloc(u8, l.slice.len / 2);
        _ = std.fmt.hexToBytes(out, l.slice) catch return p.fail(.{ .invalid_hex_character = l });
        return out;
    }
};

/// `read_string_literal`: every `\` is dropped and the byte after it kept.
fn readStringLiteral(arena: Allocator, slice: []const u8) Allocator.Error![]const u8 {
    if (std.mem.indexOfScalar(u8, slice, '\\') == null) return slice;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < slice.len) : (i += 1) {
        if (slice[i] == '\\') {
            i += 1;
            if (i >= slice.len) break;
        }
        try out.append(arena, slice[i]);
    }
    return out.items;
}

test "display parse: simple template and errors" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var budget: Budget = .{ .nodes = 32768, .loads = 8 };
    var m: Meter = .{ .depth = 32, .budget = &budget };
    var err: FormatError = .too_big;
    const s = try Parser.format(a, "https://x.io/{id}/{name | 'none'}.png", &m, &err);
    try std.testing.expectEqual(@as(usize, 5), s.len);
    try std.testing.expect(s[1] == .expr);
    try std.testing.expectEqual(@as(usize, 2), s[3].expr.alternates.len);

    try std.testing.expectError(error.Format, Parser.format(a, "{foo", &m, &err));
    const msg = try errorString(a, err);
    try std.testing.expectEqualStrings("Unexpected end-of-string, expected one of ':', '|', or '}'", msg);
}
