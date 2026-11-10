//! Suite `bcs-format`: the shape of every Zig type equals the serde-reflection registry of
//! sui-types 1.83.1 (spec/sui-format-1.83.1.yaml.snap), recursively. Both sides are rendered to
//! one normalized line per type and compared as text:
//!
//!   S{a:u8,b:@Other}        struct          N(T)            newtype struct
//!   E{A=-,B=(T),C=(T,U),D={x:T}}   enum (index = position)   ["[T]"] sequence, "bytes", "[T;N]", "?T",
//!   "(T,U)" tuple, "map<K,V>", "str", "@Name" a named type, "unit"
//!
//! Known, documented differences that the Zig side cannot express or must not copy:
//!  - BYTES and SEQ(U8) are both `bytes` (same wire, one Zig type);
//!  - newtype-of-tuple and tuple variants are both `(A,B)`;
//!  - the registry lists TypeTag/TypeInput variants under their serde alias spelling (Bool,
//!    U64, Vector) while serde serializes the renames (bool, u64, vector): compared lowercase.
const std = @import("std");
const harness = @import("harness");
const gen = @import("gen.zig");
const hand = @import("hand.zig");
const bcs = @import("bcs");

// ---------------------------------------------------------------- Zig side

fn registered(comptime T: type) ?[]const u8 {
    inline for (gen.registry) |e| {
        if (e[1] == T) return e[0];
    }
    return null;
}

fn lowerName(comptime n: []const u8) []const u8 {
    comptime var out: [n.len]u8 = undefined;
    inline for (n, 0..) |c, i| out[i] = std.ascii.toLower(c);
    const final = out;
    return &final;
}

fn num(comptime n: usize) []const u8 {
    return std.fmt.comptimePrint("{d}", .{n});
}

fn ref(comptime T: type) []const u8 {
    if (registered(T)) |n| return "@" ++ n;
    return expr(T);
}

fn expr(comptime T: type) []const u8 {
    if (T == bcs.String or T == hand.Identifier) return "str";
    if (T == hand.SuiBitmap) return "bytes";
    switch (@typeInfo(T)) {
        .bool => return "bool",
        .int => return std.fmt.comptimePrint("u{d}", .{@typeInfo(T).int.bits}),
        .void => return "unit",
        .@"enum" => return std.fmt.comptimePrint("u{d}", .{@typeInfo(@typeInfo(T).@"enum".tag_type).int.bits}),
        .array => |a| return "[" ++ ref(a.child) ++ ";" ++ num(a.len) ++ "]",
        .pointer => |p| {
            if (p.size == .slice) {
                if (p.child == u8) return "bytes";
                return "[" ++ ref(p.child) ++ "]";
            }
            return ref(p.child);
        },
        .optional => |o| return "?" ++ ref(o.child),
        .@"struct" => |s| {
            if (@hasDecl(T, "bcs_map")) return "map<" ++ ref(@FieldType(T.Entry, "key")) ++ "," ++ ref(@FieldType(T.Entry, "value")) ++ ">";
            if (@hasDecl(T, "element")) return "[" ++ ref(@typeInfo(@FieldType(T, "items")).pointer.child) ++ "]";
            if (s.is_tuple) {
                comptime var out: []const u8 = "(";
                inline for (s.field_types, 0..) |ft, i| out = out ++ (if (i > 0) "," else "") ++ ref(ft);
                return out ++ ")";
            }
            @compileError("anonymous struct in a type position: " ++ @typeName(T));
        },
        else => @compileError("format: unsupported " ++ @typeName(T)),
    }
}

fn payload(comptime T: type) []const u8 {
    if (T == void) return "-";
    if (@typeInfo(T) == .@"struct" and !@typeInfo(T).@"struct".is_tuple and registered(T) == null and @hasDecl(T, "bcs_no_depth")) {
        const s = @typeInfo(T).@"struct";
        comptime var out: []const u8 = "{";
        inline for (s.field_names, s.field_types, 0..) |n, ft, i| out = out ++ (if (i > 0) "," else "") ++ n ++ ":" ++ ref(ft);
        return out ++ "}";
    }
    if (@typeInfo(T) == .@"struct" and @typeInfo(T).@"struct".is_tuple and registered(T) == null) return expr(T);
    return "(" ++ ref(T) ++ ")";
}

/// Variants of sui-types 1.83.1 that the registry never traced (gen_types.py REGISTRY_HOLES).
fn isHole(comptime type_name: []const u8, comptime variant: []const u8) bool {
    return std.mem.eql(u8, variant, "Passkey") and (std.mem.eql(u8, type_name, "PublicKey") or std.mem.eql(u8, type_name, "CompressedSignature"));
}

fn def(comptime name: []const u8, comptime T: type) []const u8 {
    if (@typeInfo(T) == .@"struct" and @hasDecl(T, "bcs_byte_array")) return "N(bytes)";
    switch (@typeInfo(T)) {
        .@"struct" => |s| {
            if (@hasDecl(T, "bcs_newtype")) return "N(" ++ ref(s.field_types[0]) ++ ")";
            comptime var out: []const u8 = "S{";
            inline for (s.field_names, s.field_types, 0..) |n, ft, i| out = out ++ (if (i > 0) "," else "") ++ n ++ ":" ++ ref(ft);
            return out ++ "}";
        },
        .@"union" => |u| {
            const lower = comptime std.mem.eql(u8, name, "TypeTag") or std.mem.eql(u8, name, "TypeInput");
            comptime var out: []const u8 = "E{";
            comptime var first = true;
            inline for (u.field_names, u.field_types) |n, ft| {
                if (comptime isHole(name, n)) continue;
                out = out ++ (if (first) "" else ",") ++ (if (lower) lowerName(n) else n) ++ "=" ++ payload(ft);
                first = false;
            }
            return out ++ "}";
        },
        else => @compileError("format: not a definition: " ++ @typeName(T)),
    }
}

// ---------------------------------------------------------------- registry side

const Node = union(enum) {
    scalar: []const u8,
    map: []const Entry,
    seq: []const Node,
    none,
    const Entry = struct { key: []const u8, value: Node };
};

const RenderError = error{ BadYaml, OutOfMemory };

const Tok = struct { indent: usize, item: bool, text: []const u8 };

const Parser = struct {
    arena: std.mem.Allocator,
    toks: []const Tok,
    pos: usize = 0,

    fn scalar(s: []const u8) []const u8 {
        const t = std.mem.trim(u8, s, " ");
        if (t.len >= 2 and t[0] == '"' and t[t.len - 1] == '"') return t[1 .. t.len - 1];
        return t;
    }

    /// Splits "key: value" / "key:" (key may be quoted). Returns null if the text is not a key line.
    fn splitKey(text: []const u8) ?struct { key: []const u8, rest: []const u8 } {
        if (text.len == 0) return null;
        if (text[0] == '"') {
            const end = std.mem.indexOfScalarPos(u8, text, 1, '"') orelse return null;
            if (end + 1 < text.len and text[end + 1] == ':') return .{ .key = text[1..end], .rest = std.mem.trim(u8, text[end + 2 ..], " ") };
            return null;
        }
        const c = std.mem.indexOfScalar(u8, text, ':') orelse return null;
        if (c + 1 < text.len and text[c + 1] != ' ') return null;
        return .{ .key = text[0..c], .rest = std.mem.trim(u8, text[c + 1 ..], " ") };
    }

    fn block(p: *Parser) RenderError!Node {
        if (p.toks[p.pos].item) return p.seq(p.toks[p.pos].indent);
        return p.mapping(p.toks[p.pos].indent);
    }

    fn seq(p: *Parser, ind: usize) RenderError!Node {
        var out: std.ArrayList(Node) = .empty;
        while (p.pos < p.toks.len and p.toks[p.pos].item and p.toks[p.pos].indent == ind) {
            p.pos += 1;
            if (p.pos < p.toks.len and !p.toks[p.pos].item and p.toks[p.pos].indent == ind + 2) {
                if (splitKey(p.toks[p.pos].text) != null) {
                    try out.append(p.arena, try p.mapping(ind + 2));
                } else {
                    try out.append(p.arena, .{ .scalar = scalar(p.toks[p.pos].text) });
                    p.pos += 1;
                }
            } else if (p.pos < p.toks.len and p.toks[p.pos].item and p.toks[p.pos].indent == ind + 2) {
                try out.append(p.arena, try p.seq(ind + 2));
            } else try out.append(p.arena, .none);
        }
        return .{ .seq = try out.toOwnedSlice(p.arena) };
    }

    fn mapping(p: *Parser, ind: usize) RenderError!Node {
        var out: std.ArrayList(Node.Entry) = .empty;
        while (p.pos < p.toks.len and !p.toks[p.pos].item and p.toks[p.pos].indent == ind) {
            const kv = splitKey(p.toks[p.pos].text) orelse return error.BadYaml;
            p.pos += 1;
            var v: Node = .none;
            if (kv.rest.len > 0) {
                v = .{ .scalar = scalar(kv.rest) };
            } else if (p.pos < p.toks.len and (p.toks[p.pos].indent > ind or (p.toks[p.pos].item and p.toks[p.pos].indent == ind))) {
                v = try p.block();
            }
            try out.append(p.arena, .{ .key = scalar(kv.key), .value = v });
        }
        return .{ .map = try out.toOwnedSlice(p.arena) };
    }
};

fn parseYaml(arena: std.mem.Allocator, text: []const u8) RenderError!Node {
    var toks: std.ArrayList(Tok) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    var in_body = false;
    var dashes: u8 = 0;
    while (it.next()) |raw| {
        if (std.mem.startsWith(u8, raw, "---")) {
            dashes += 1;
            if (dashes == 2) in_body = true;
            continue;
        }
        if (!in_body) continue;
        const trimmed = std.mem.trim(u8, raw, " ");
        if (trimmed.len == 0) continue;
        var ind = raw.len - std.mem.trimStart(u8, raw, " ").len;
        var c = raw[ind..];
        while (std.mem.startsWith(u8, c, "- ") or std.mem.eql(u8, c, "-")) {
            try toks.append(arena, .{ .indent = ind, .item = true, .text = "" });
            c = if (c.len >= 2) c[2..] else "";
            ind += 2;
        }
        try toks.append(arena, .{ .indent = ind, .item = false, .text = std.mem.trimEnd(u8, c, " ") });
    }
    var p: Parser = .{ .arena = arena, .toks = toks.items };
    return p.mapping(0);
}

fn prim(s: []const u8) ?[]const u8 {
    const t = [_][2][]const u8{
        .{ "U8", "u8" },    .{ "U16", "u16" }, .{ "U32", "u32" }, .{ "U64", "u64" }, .{ "U128", "u128" }, .{ "BOOL", "bool" },
        .{ "STR", "str" },  .{ "BYTES", "bytes" }, .{ "UNIT", "unit" },
    };
    for (t) |e| if (std.mem.eql(u8, e[0], s)) return e[1];
    return null;
}

fn get(n: Node, key: []const u8) ?Node {
    if (n != .map) return null;
    for (n.map) |e| if (std.mem.eql(u8, e.key, key)) return e.value;
    return null;
}

fn yexpr(arena: std.mem.Allocator, n: Node) RenderError![]const u8 {
    switch (n) {
        .scalar => |s| return prim(s) orelse error.BadYaml,
        .map => |m| {
            if (m.len != 1) return error.BadYaml;
            const k = m[0].key;
            const v = m[0].value;
            if (std.mem.eql(u8, k, "TYPENAME")) return std.fmt.allocPrint(arena, "@{s}", .{v.scalar});
            if (std.mem.eql(u8, k, "SEQ")) {
                if (v == .scalar and std.mem.eql(u8, v.scalar, "U8")) return "bytes";
                return std.fmt.allocPrint(arena, "[{s}]", .{try yexpr(arena, v)});
            }
            if (std.mem.eql(u8, k, "OPTION")) return std.fmt.allocPrint(arena, "?{s}", .{try yexpr(arena, v)});
            if (std.mem.eql(u8, k, "TUPLEARRAY")) {
                return std.fmt.allocPrint(arena, "[{s};{s}]", .{ try yexpr(arena, get(v, "CONTENT") orelse return error.BadYaml), (get(v, "SIZE") orelse return error.BadYaml).scalar });
            }
            if (std.mem.eql(u8, k, "TUPLE")) return ytuple(arena, v);
            if (std.mem.eql(u8, k, "MAP")) {
                return std.fmt.allocPrint(arena, "map<{s},{s}>", .{ try yexpr(arena, get(v, "KEY") orelse return error.BadYaml), try yexpr(arena, get(v, "VALUE") orelse return error.BadYaml) });
            }
            return error.BadYaml;
        },
        else => return error.BadYaml,
    }
}

fn ytuple(arena: std.mem.Allocator, v: Node) RenderError![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(arena, '(');
    for (v.seq, 0..) |item, i| {
        if (i > 0) try out.append(arena, ',');
        try out.appendSlice(arena, try yexpr(arena, item));
    }
    try out.append(arena, ')');
    return out.items;
}

fn yfields(arena: std.mem.Allocator, fields: Node, out: *std.ArrayList(u8)) RenderError!void {
    if (fields == .scalar) return; // "[]"
    if (fields != .seq) return error.BadYaml;
    for (fields.seq, 0..) |f, i| {
        if (i > 0) try out.append(arena, ',');
        if (f != .map or f.map.len != 1) return error.BadYaml;
        try out.appendSlice(arena, f.map[0].key);
        try out.append(arena, ':');
        try out.appendSlice(arena, try yexpr(arena, f.map[0].value));
    }
}

fn ydef(arena: std.mem.Allocator, name: []const u8, d: Node) RenderError![]const u8 {
    if (d != .map or d.map.len != 1) return error.BadYaml;
    const kind = d.map[0].key;
    const body = d.map[0].value;
    var out: std.ArrayList(u8) = .empty;
    if (std.mem.eql(u8, kind, "STRUCT")) {
        try out.appendSlice(arena, "S{");
        try yfields(arena, body, &out);
        try out.append(arena, '}');
    } else if (std.mem.eql(u8, kind, "NEWTYPESTRUCT")) {
        try out.appendSlice(arena, "N(");
        try out.appendSlice(arena, try yexpr(arena, body));
        try out.append(arena, ')');
    } else if (std.mem.eql(u8, kind, "ENUM")) {
        const lower = std.mem.eql(u8, name, "TypeTag") or std.mem.eql(u8, name, "TypeInput");
        try out.appendSlice(arena, "E{");
        for (body.map, 0..) |ve, i| {
            _ = std.fmt.parseInt(usize, ve.key, 10) catch return error.BadYaml;
            if (i > 0) try out.append(arena, ',');
            const vm = ve.value.map[0];
            if (lower) {
                for (vm.key) |c| try out.append(arena, std.ascii.toLower(c));
            } else try out.appendSlice(arena, vm.key);
            try out.append(arena, '=');
            const pv = vm.value;
            if (pv == .scalar and std.mem.eql(u8, pv.scalar, "UNIT")) {
                try out.append(arena, '-');
            } else {
                if (pv != .map or pv.map.len != 1) return error.BadYaml;
                const pk = pv.map[0].key;
                const pb = pv.map[0].value;
                if (std.mem.eql(u8, pk, "NEWTYPE")) {
                    const e = try yexpr(arena, pb);
                    // newtype of a tuple and a tuple variant are one shape
                    if (e.len > 0 and e[0] == '(') try out.appendSlice(arena, e) else {
                        try out.append(arena, '(');
                        try out.appendSlice(arena, e);
                        try out.append(arena, ')');
                    }
                } else if (std.mem.eql(u8, pk, "TUPLE")) {
                    try out.appendSlice(arena, try ytuple(arena, pb));
                } else if (std.mem.eql(u8, pk, "STRUCT")) {
                    try out.append(arena, '{');
                    try yfields(arena, pb, &out);
                    try out.append(arena, '}');
                } else return error.BadYaml;
            }
        }
        try out.append(arena, '}');
    } else return error.BadYaml;
    return out.items;
}

// ---------------------------------------------------------------- suite

pub fn run(ctx: *harness.Ctx) !void {
    const arena = ctx.gpa;
    var arena_state: std.heap.ArenaAllocator = .init(arena);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const text = std.Io.Dir.cwd().readFileAlloc(ctx.io, "spec/sui-format-1.83.1.yaml.snap", a, .limited(1 << 22)) catch |e| {
        ctx.fail("registry", "cannot read spec/sui-format-1.83.1.yaml.snap from the repo root ({s})", .{@errorName(e)});
        return;
    };
    const root = parseYaml(a, text) catch |e| {
        ctx.fail("registry", "cannot parse the registry: {s}", .{@errorName(e)});
        return;
    };
    // Registry -> Zig.
    for (root.map) |entry| {
        if (!ctx.selected(entry.key)) continue;
        const want = ydef(a, entry.key, entry.value) catch |e| {
            ctx.fail(entry.key, "registry entry not understood: {s}", .{@errorName(e)});
            continue;
        };
        var found = false;
        inline for (gen.registry) |zt| {
            if (std.mem.eql(u8, entry.key, zt[0])) {
                found = true;
                const got = comptime blk: {
                    @setEvalBranchQuota(2_000_000);
                    break :blk def(zt[0], zt[1]);
                };
                _ = ctx.expectText(entry.key, "shape", want, got);
            }
        }
        if (!found) ctx.fail(entry.key, "registry type has no Zig type", .{});
    }
    // Zig -> registry: no extra types.
    inline for (gen.registry) |zt| {
        if (get(root, zt[0]) == null) ctx.fail(zt[0], "Zig type is not in the registry", .{});
    }
}
