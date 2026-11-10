//! insta's YAML snapshot emitter (insta 1.46.2 `content/yaml/vendored/emitter.rs`, compact mode,
//! indent 2), driven by comptime reflection over the deepwave config types. The output must equal the
//! text insta writes for the Rust `ProtocolConfig`, so this follows the Rust byte for byte.
//!
//! Mapping from Zig types:
//!   struct            -> hash (fields in declaration order; skip rules in `skipField`)
//!   ?T                -> value (null fields are skipped by the parent; a bare null prints `~`)
//!   bool, ints        -> scalars
//!   enum              -> the variant name as a string
//!   union(enum)       -> variant name string (void payload) or hash { Variant: payload }
//!   []const u8        -> string (with insta's quoting rules)
//!   [N]u8             -> sequence of integers (a Rust `[u8; N]`)
//!   []const T         -> sequence; Amendments / []const AddrPair -> hash keyed by 64-digit hex
//!   tuple struct      -> sequence
const std = @import("std");
const types = @import("types.zig");
const Writer = std.Io.Writer;

pub const Error = Writer.Error;

pub const Emitter = struct {
    w: *Writer,
    level: i32 = -1,

    fn indent(e: *Emitter) Error!void {
        if (e.level <= 0) return;
        var i: i32 = 0;
        while (i < e.level) : (i += 1) try e.w.writeAll("  ");
    }

    /// emit_node for a document root: `---\n` is not written (snapshot bodies have no marker).
    pub fn root(e: *Emitter, val: anytype) Error!void {
        e.level = -1;
        try e.node(val);
    }

    fn node(e: *Emitter, val: anytype) Error!void {
        const T = @TypeOf(val);
        switch (@typeInfo(T)) {
            .bool => try e.w.writeAll(if (val) "true" else "false"),
            .int, .comptime_int => try e.w.printInt(val, 10, .lower, .{}),
            .@"enum" => try quotedIfNeeded(e.w, @tagName(val)),
            .optional => if (val) |v| try e.node(v) else try e.w.writeAll("~"),
            .array => |a| {
                if (a.child != u8) @compileError("unsupported array type " ++ @typeName(T));
                try e.seq(val[0..]);
            },
            .pointer => |p| {
                if (p.size != .slice) @compileError("unsupported pointer " ++ @typeName(T));
                if (p.child == u8) {
                    try quotedIfNeeded(e.w, val);
                } else if (T == types.Amendments) {
                    try e.addrMap(val);
                } else if (T == []const types.AddrPair) {
                    try e.addrPairs(val);
                } else {
                    try e.seq(val);
                }
            },
            .@"union" => |u| {
                switch (val) {
                    inline else => |payload, tag| {
                        const P = @TypeOf(payload);
                        if (P == void) {
                            try quotedIfNeeded(e.w, @tagName(tag));
                        } else {
                            _ = u;
                            e.level += 1;
                            try e.w.writeAll(@tagName(tag));
                            try e.w.writeAll(":");
                            try e.value(false, payload);
                            e.level -= 1;
                        }
                    },
                }
            },
            .@"struct" => |s| {
                if (s.is_tuple) {
                    try e.seqTuple(val);
                } else {
                    try e.hash(val);
                }
            },
            else => @compileError("unsupported type " ++ @typeName(T)),
        }
    }

    fn isEmptyHash(comptime T: type, val: T) bool {
        const info = @typeInfo(T).@"struct";
        inline for (info.field_names, info.field_types, info.field_attrs) |name, FT, attrs| {
            if (!skipField(T, name, FT, attrs, @field(val, name))) return false;
        }
        return true;
    }

    fn hash(e: *Emitter, val: anytype) Error!void {
        const T = @TypeOf(val);
        if (isEmptyHash(T, val)) return e.w.writeAll("{}");
        const info = @typeInfo(T).@"struct";
        e.level += 1;
        var cnt: usize = 0;
        inline for (info.field_names, info.field_types, info.field_attrs) |name, FT, attrs| {
            if (!skipField(T, name, FT, attrs, @field(val, name))) {
                if (cnt > 0) {
                    try e.w.writeAll("\n");
                    try e.indent();
                }
                cnt += 1;
                // Field names are comptime: the quoting decision costs nothing at run time.
                try e.w.writeAll(comptime keyText(name));
                const fv = @field(val, name);
                switch (@typeInfo(FT)) {
                    .optional => try e.value(false, fv.?),
                    else => try e.value(false, fv),
                }
            }
        }
        e.level -= 1;
    }

    /// Fields skipped in the snapshot: `skip_serializing_if` in Rust.
    fn skipField(comptime T: type, comptime name: []const u8, comptime FT: type, comptime attrs: std.builtin.Type.Struct.FieldAttributes, v: FT) bool {
        if (comptime std.mem.eql(u8, name, "chain") and @hasDecl(T, "yaml_skip_all")) return true;
        const listed = comptime blk: {
            if (@hasDecl(T, "yaml_skip_all")) {
                if (@hasDecl(T, "yaml_keep")) {
                    for (T.yaml_keep) |k| if (std.mem.eql(u8, k, name)) break :blk false;
                }
                break :blk true;
            }
            if (@hasDecl(T, "yaml_skip")) {
                for (T.yaml_skip) |k| if (std.mem.eql(u8, k, name)) break :blk true;
            }
            break :blk false;
        };
        if (!listed) return false;
        return isDefault(FT, v, attrs.defaultValue(FT).?);
    }

    fn isDefault(comptime F: type, a: F, b: F) bool {
        switch (@typeInfo(F)) {
            .optional => return a == null and b == null,
            .pointer => return a.len == 0 and b.len == 0,
            else => return std.meta.eql(a, b),
        }
    }

    /// emit_val: a value after `key:` (inline=false) or after `-` (inline=true).
    fn value(e: *Emitter, inline_: bool, v: anytype) Error!void {
        const T = @TypeOf(v);
        const container = comptime isSeqLike(T) or isHashLike(T);
        const is_union_hash = comptime @typeInfo(T) == .@"union";
        if (is_union_hash and !unionIsHash(v)) {
            try e.w.writeAll(" ");
            return e.node(v);
        }
        if (!container and !is_union_hash) {
            try e.w.writeAll(" ");
            return e.node(v);
        }
        const empty = isEmptyContainer(v);
        if (inline_ or empty) {
            try e.w.writeAll(" ");
        } else {
            try e.w.writeAll("\n");
            e.level += 1;
            try e.indent();
            e.level -= 1;
        }
        try e.node(v);
    }

    fn isSeqLike(comptime T: type) bool {
        switch (@typeInfo(T)) {
            .array => return true,
            .pointer => |p| return p.size == .slice and p.child != u8 and T != types.Amendments and T != []const types.AddrPair,
            .@"struct" => |s| return s.is_tuple,
            else => return false,
        }
    }

    fn isHashLike(comptime T: type) bool {
        switch (@typeInfo(T)) {
            .@"struct" => |s| return !s.is_tuple,
            .@"union" => return false, // payload unions are hashes; decided at runtime in `val`
            .pointer => return T == types.Amendments or T == []const types.AddrPair,
            else => return false,
        }
    }

    fn unionIsHash(v: anytype) bool {
        switch (v) {
            inline else => |payload| return @TypeOf(payload) != void,
        }
    }

    fn isEmptyContainer(v: anytype) bool {
        const T = @TypeOf(v);
        switch (@typeInfo(T)) {
            .array => |a| return a.len == 0,
            .pointer => return v.len == 0,
            .@"struct" => |s| {
                if (s.is_tuple) return s.field_names.len == 0;
                return isEmptyHash(T, v);
            },
            else => return false,
        }
    }

    fn seq(e: *Emitter, items: anytype) Error!void {
        if (items.len == 0) return e.w.writeAll("[]");
        e.level += 1;
        for (items, 0..) |it, i| {
            if (i > 0) {
                try e.w.writeAll("\n");
                try e.indent();
            }
            try e.w.writeAll("-");
            try e.value(true, it);
        }
        e.level -= 1;
    }

    fn seqTuple(e: *Emitter, t: anytype) Error!void {
        const n = @typeInfo(@TypeOf(t)).@"struct".field_names.len;
        if (n == 0) return e.w.writeAll("[]");
        e.level += 1;
        inline for (0..n) |i| {
            if (i > 0) {
                try e.w.writeAll("\n");
                try e.indent();
            }
            try e.w.writeAll("-");
            try e.value(true, t[i]);
        }
        e.level -= 1;
    }

    fn hexKey(e: *Emitter, k: [32]u8) Error!void {
        const hex = std.fmt.bytesToHex(k, .lower);
        try quotedIfNeeded(e.w, &hex);
    }

    fn addrMap(e: *Emitter, m: types.Amendments) Error!void {
        if (m.len == 0) return e.w.writeAll("{}");
        e.level += 1;
        for (m, 0..) |ent, i| {
            if (i > 0) {
                try e.w.writeAll("\n");
                try e.indent();
            }
            try e.hexKey(ent.k);
            try e.w.writeAll(":");
            try e.value(false, ent.v);
        }
        e.level -= 1;
    }

    fn addrPairs(e: *Emitter, m: []const types.AddrPair) Error!void {
        if (m.len == 0) return e.w.writeAll("{}");
        e.level += 1;
        for (m, 0..) |ent, i| {
            if (i > 0) {
                try e.w.writeAll("\n");
                try e.indent();
            }
            try e.hexKey(ent.k);
            try e.w.writeAll(":");
            try e.w.writeAll(" ");
            try e.hexKey(ent.v);
        }
        e.level -= 1;
    }
};

/// `name:` or `"name":`, decided at comptime.
fn keyText(comptime name: []const u8) []const u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        if (needQuotes(name)) @compileError("field name needs YAML quoting: " ++ name);
        return name ++ ":";
    }
}

// ---- scalar string quoting (emitter.rs `need_quotes` and `escape_str`) ----

fn quotedIfNeeded(w: *Writer, s: []const u8) Error!void {
    if (needQuotes(s)) return escapeStr(w, s);
    try w.writeAll(s);
}

fn escapeStr(w: *Writer, v: []const u8) Error!void {
    try w.writeAll("\"");
    var start: usize = 0;
    for (v, 0..) |byte, i| {
        const esc: []const u8 = switch (byte) {
            '"' => "\\\"",
            '\\' => "\\\\",
            0x00 => "\\u0000",
            0x01 => "\\u0001",
            0x02 => "\\u0002",
            0x03 => "\\u0003",
            0x04 => "\\u0004",
            0x05 => "\\u0005",
            0x06 => "\\u0006",
            0x07 => "\\u0007",
            0x08 => "\\b",
            '\t' => "\\t",
            '\n' => "\\n",
            0x0b => "\\u000b",
            0x0c => "\\f",
            '\r' => "\\r",
            0x0e => "\\u000e",
            0x0f => "\\u000f",
            0x10 => "\\u0010",
            0x11 => "\\u0011",
            0x12 => "\\u0012",
            0x13 => "\\u0013",
            0x14 => "\\u0014",
            0x15 => "\\u0015",
            0x16 => "\\u0016",
            0x17 => "\\u0017",
            0x18 => "\\u0018",
            0x19 => "\\u0019",
            0x1a => "\\u001a",
            0x1b => "\\u001b",
            0x1c => "\\u001c",
            0x1d => "\\u001d",
            0x1e => "\\u001e",
            0x1f => "\\u001f",
            0x7f => "\\u007f",
            else => continue,
        };
        if (start < i) try w.writeAll(v[start..i]);
        try w.writeAll(esc);
        start = i + 1;
    }
    if (start != v.len) try w.writeAll(v[start..]);
    try w.writeAll("\"");
}

pub fn needQuotes(s: []const u8) bool {
    if (s.len == 0) return true;
    if (s[0] == ' ' or s[s.len - 1] == ' ') return true;
    switch (s[0]) {
        '&', '*', '?', '|', '-', '<', '>', '=', '!', '%', '@' => return true,
        else => {},
    }
    for (s) |c| switch (c) {
        ':', '{', '}', '[', ']', ',', '#', '`', '"', '\'', '\\', 0...6, '\t', '\n', '\r', 0x0e...0x1a, 0x1c...0x1f => return true,
        else => {},
    };
    const specials = [_][]const u8{
        "yes", "Yes", "YES", "no",  "No",  "NO",  "True", "TRUE", "true", "False", "FALSE", "false",
        "on",  "On",  "ON",  "off", "Off", "OFF", "null", "Null", "NULL", "~",
    };
    for (specials) |sp| if (std.mem.eql(u8, s, sp)) return true;
    if (s[0] == '.') return true;
    if (std.mem.startsWith(u8, s, "0x")) return true;
    if (parsesAsI64(s)) return true;
    if (parsesAsF64(s)) return true;
    return false;
}

fn parsesAsI64(s: []const u8) bool {
    _ = std.fmt.parseInt(i64, s, 10) catch return false;
    return true;
}

/// Rust `str::parse::<f64>` acceptance: [+-]? (inf|infinity|nan | digits [. digits] [e [+-] digits]
/// | . digits ...), ASCII case-insensitive for the words. No hex, no underscores, no whitespace.
fn parsesAsF64(s_: []const u8) bool {
    var s = s_;
    if (s.len == 0) return false;
    if (s[0] == '+' or s[0] == '-') s = s[1..];
    if (s.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(s, "inf") or std.ascii.eqlIgnoreCase(s, "infinity") or std.ascii.eqlIgnoreCase(s, "nan")) return true;
    var i: usize = 0;
    var digits: usize = 0;
    while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) digits += 1;
    if (i < s.len and s[i] == '.') {
        i += 1;
        while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) digits += 1;
    }
    if (digits == 0) return false;
    if (i < s.len and (s[i] == 'e' or s[i] == 'E')) {
        i += 1;
        if (i < s.len and (s[i] == '+' or s[i] == '-')) i += 1;
        var ed: usize = 0;
        while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) ed += 1;
        if (ed == 0) return false;
    }
    return i == s.len;
}

test "needQuotes mirrors insta" {
    try std.testing.expect(needQuotes("0000000000000000000000000000000000000000000000000000000000000003"));
    try std.testing.expect(!needQuotes("0139cc6e573fac2726fda782e1df80eb3a61eee5721014f262f8b983784799bd"));
    try std.testing.expect(needQuotes("12e45678"));
    try std.testing.expect(needQuotes("0xdba::usdc::USDC"));
    try std.testing.expect(!needQuotes("Mysticeti"));
    try std.testing.expect(needQuotes("true"));
    try std.testing.expect(needQuotes(""));
    try std.testing.expect(needQuotes("-x"));
}
