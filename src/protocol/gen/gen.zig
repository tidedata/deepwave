//! Generator for src/protocol/gen_types.zig and src/protocol/gen_data.zig.
//!
//!   ./zig run src/protocol/gen/gen.zig -- <lib.rs> <dump.jsonl> <out_dir>
//!
//! Inputs, both produced from Mysten's code at mainnet-v1.83.1:
//!   lib.rs      crates/sui-protocol-config/src/lib.rs. Only the declarations of `struct FeatureFlags`
//!               and `struct ProtocolConfig` are read: field names, order and Rust types.
//!   dump.jsonl  tools/truth/protocol-config (zui-pc-truth dump): serde_json of the REAL
//!               `ProtocolConfig::get_for_version(v, chain)` for every version and chain.
//!
//! Output:
//!   gen_types.zig  `FeatureFlags` and `ProtocolConfig` with every Rust field, same name, same order.
//!   gen_data.zig   `applyBase(c, v)`: the field changes that version v makes on top of v-1 on the
//!                  unknown chain (the Rust per-version `match`), and `applyChain(c, chain, v)`: what
//!                  mainnet/testnet change on top of the unknown-chain config of the same version.
//!                  Both are derived by diffing the real configs, so applying them in order
//!                  reproduces every (version, chain) config exactly. The conformance suite then
//!                  proves it against the insta YAML of the real configs.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const json = std.json;

const Kind = enum { boolean, uint, enum_, set, option_prim, aliased, gasless, amend, perobject, version, chain, flags };

const Field = struct {
    name: []const u8,
    ty: []const u8, // Zig type
    default: []const u8, // Zig default literal
    kind: Kind,
    prim: []const u8 = "", // for option_prim / uint
    enum_default: []const u8 = "",
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 4) {
        std.debug.print("usage: gen <lib.rs> <dump.jsonl> <out_dir>\n", .{});
        return error.Usage;
    }
    const cwd = Io.Dir.cwd();
    const lib = try cwd.readFileAlloc(io, args[1], arena, .limited(64 << 20));
    const dump = try cwd.readFileAlloc(io, args[2], arena, .limited(1 << 30));
    const out_dir = args[3];

    // MAX_PROTOCOL_VERSION from lib.rs, so a new Mysten release regenerates without edits here
    // (tools/release/runner-job.sh); 141 for mainnet-v1.83.1.
    const max_v = try parseMax(lib);
    const flags = try parseStruct(arena, lib, "struct FeatureFlags {", false);
    const cfgf = try parseStruct(arena, lib, "pub struct ProtocolConfig {", true);

    // chain -> versions (index v-1) -> cfg object
    var by_chain: [3][]json.ObjectMap = undefined;
    const chain_names = [_][]const u8{ "Unknown", "Mainnet", "Testnet" };
    for (&by_chain) |*c| c.* = try arena.alloc(json.ObjectMap, max_v);
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, dump, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const v = try json.parseFromSliceLeaky(json.Value, arena, line, .{});
        const chain = v.object.get("chain").?.string;
        const ver: usize = @intCast(v.object.get("v").?.integer);
        for (chain_names, 0..) |n, ci| if (std.mem.eql(u8, n, chain)) {
            by_chain[ci][ver - 1] = v.object.get("cfg").?.object;
            count += 1;
        };
    }
    if (count != max_v * 3) return error.IncompleteDump;

    // Check the dump's key order equals the declaration order (serde order), per config.
    for (by_chain) |vs| for (vs) |cfg| try checkOrder(cfg, flags, cfgf);

    var types_buf: Io.Writer.Allocating = .init(arena);
    try emitTypes(&types_buf.writer, flags, cfgf);
    var data_buf: Io.Writer.Allocating = .init(arena);
    try emitData(arena, &data_buf.writer, flags, cfgf, by_chain);

    try cwd.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/gen_types.zig", .{out_dir}), .data = types_buf.written() });
    try cwd.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/gen_data.zig", .{out_dir}), .data = data_buf.written() });
    std.debug.print("gen: {d} feature flags, {d} config fields, {d} configs\n", .{ flags.len, cfgf.len, count });
}

// ---------------------------------------------------------------------------------------------
// lib.rs struct parsing

fn parseMax(lib: []const u8) !usize {
    const key = "const MAX_PROTOCOL_VERSION: u64 = ";
    const at = std.mem.indexOf(u8, lib, key) orelse return error.Parse;
    const rest = lib[at + key.len ..];
    const end = std.mem.indexOfScalar(u8, rest, ';') orelse return error.Parse;
    return std.fmt.parseInt(usize, rest[0..end], 10);
}

fn parseStruct(arena: Allocator, lib: []const u8, header: []const u8, is_cfg: bool) ![]Field {
    const start = std.mem.indexOf(u8, lib, header) orelse return error.StructNotFound;
    var lines = std.mem.splitScalar(u8, lib[start + header.len ..], '\n');
    var out: std.ArrayList(Field) = .empty;
    while (lines.next()) |raw| {
        if (raw.len > 0 and raw[0] == '}') break;
        const line = std.mem.trim(u8, raw, " \t");
        if (!std.mem.startsWith(u8, raw, "    ") or raw[4] == ' ') continue;
        if (line.len == 0 or line[0] == '/' or line[0] == '#') continue;
        const colon = std.mem.indexOf(u8, line, ": ") orelse return fail("bad field line", line);
        if (line[line.len - 1] != ',') return fail("field line does not end in comma", line);
        var name = line[0..colon];
        if (std.mem.startsWith(u8, name, "pub ")) name = name[4..];
        const ty = line[colon + 2 .. line.len - 1];
        try out.append(arena, try classify(name, ty, is_cfg));
    }
    return out.items;
}

fn fail(msg: []const u8, line: []const u8) error{Parse} {
    std.debug.print("gen: {s}: {s}\n", .{ msg, line });
    return error.Parse;
}

fn classify(name: []const u8, ty: []const u8, is_cfg: bool) !Field {
    if (is_cfg and std.mem.eql(u8, name, "version")) return .{ .name = name, .ty = "u64", .default = "0", .kind = .version };
    // #[serde(skip)]: not in the snapshot or the dump; set by root.zig from the chain asked for,
    // as `get_for_version` does (`ret.chain = chain`). Execution reads it (`protocol_config.chain()`).
    if (is_cfg and std.mem.eql(u8, name, "chain")) {
        if (!std.mem.eql(u8, ty, "Chain")) return fail("chain field type", ty);
        return .{ .name = name, .ty = "Chain", .default = ".unknown", .kind = .chain };
    }
    if (is_cfg and std.mem.eql(u8, ty, "FeatureFlags")) return .{ .name = name, .ty = "FeatureFlags", .default = ".{}", .kind = .flags };
    if (std.mem.eql(u8, ty, "bool")) return .{ .name = name, .ty = "bool", .default = "false", .kind = .boolean };
    if (std.mem.eql(u8, ty, "u64")) return .{ .name = name, .ty = "u64", .default = "0", .kind = .uint, .prim = "u64" };
    const enums = [_][3][]const u8{
        .{ "ConsensusTransactionOrdering", ".None", "" },
        .{ "ConsensusChoice", ".Narwhal", "" },
        .{ "ConsensusNetwork", ".Anemo", "" },
    };
    for (enums) |e| if (std.mem.eql(u8, ty, e[0])) return .{ .name = name, .ty = e[0], .default = e[1], .kind = .enum_ };
    // 1.84 (protocol 142): move-binary-format limits profile, `#[skip_accessor]`.
    if (std.mem.eql(u8, ty, "Option<BinaryFormatLimitsProfile>")) return .{ .name = name, .ty = "?BinaryFormatLimitsProfile", .default = "null", .kind = .enum_ };
    if (std.mem.eql(u8, ty, "PerObjectCongestionControlMode")) return .{ .name = name, .ty = ty, .default = ".None", .kind = .perobject };
    if (std.mem.eql(u8, ty, "BTreeSet<String>")) return .{ .name = name, .ty = "[]const []const u8", .default = "&.{}", .kind = .set };
    if (std.mem.eql(u8, ty, "Vec<AliasedAddress>")) return .{ .name = name, .ty = "[]const AliasedAddress", .default = "&.{}", .kind = .aliased };
    if (std.mem.eql(u8, ty, "Option<Vec<(String, u64)>>")) return .{ .name = name, .ty = "?[]const GaslessToken", .default = "null", .kind = .gasless };
    if (std.mem.eql(u8, ty, "Option<Arc<Amendments>>")) return .{ .name = name, .ty = "?Amendments", .default = "null", .kind = .amend };
    if (std.mem.startsWith(u8, ty, "Option<") and ty[ty.len - 1] == '>') {
        const inner = ty[7 .. ty.len - 1];
        const prims = [_][2][]const u8{ .{ "u16", "?u16" }, .{ "u32", "?u32" }, .{ "u64", "?u64" }, .{ "usize", "?usize" }, .{ "bool", "?bool" } };
        for (prims) |p| if (std.mem.eql(u8, inner, p[0])) {
            return .{ .name = name, .ty = p[1], .default = "null", .kind = .option_prim, .prim = p[0] };
        };
    }
    return fail("unsupported field type", ty);
}

fn checkOrder(cfg: json.ObjectMap, flags: []const Field, cfgf: []const Field) !void {
    // Keys of the dump appear in declaration order, restricted to the fields that are present.
    var fi: usize = 0;
    for (cfg.keys()) |k| {
        while (fi < cfgf.len and !std.mem.eql(u8, cfgf[fi].name, k)) fi += 1;
        if (fi == cfgf.len) {
            std.debug.print("gen: dump key {s} missing from, or out of order in, ProtocolConfig\n", .{k});
            return error.OrderMismatch;
        }
        fi += 1;
    }
    const ff = cfg.get("feature_flags").?.object;
    var gi: usize = 0;
    for (ff.keys()) |k| {
        while (gi < flags.len and !std.mem.eql(u8, flags[gi].name, k)) gi += 1;
        if (gi == flags.len) {
            std.debug.print("gen: feature flag {s} missing from, or out of order in, FeatureFlags\n", .{k});
            return error.OrderMismatch;
        }
        gi += 1;
    }
}

// ---------------------------------------------------------------------------------------------
// emit gen_types.zig

fn writeId(w: *Io.Writer, name: []const u8) !void {
    if (std.zig.isValidId(name)) try w.writeAll(name) else try w.print("@\"{s}\"", .{name});
}

fn emitTypes(w: *Io.Writer, flags: []const Field, cfgf: []const Field) !void {
    try w.writeAll(
        \\//! GENERATED by src/protocol/gen/gen.zig from sui-protocol-config/src/lib.rs (mainnet-v1.83.1).
        \\//! Do not edit. Every field of the Rust `FeatureFlags` and `ProtocolConfig`, same name, same order.
        \\const types = @import("types.zig");
        \\const methods = @import("methods.zig");
        \\const ConsensusTransactionOrdering = types.ConsensusTransactionOrdering;
        \\const ConsensusChoice = types.ConsensusChoice;
        \\const ConsensusNetwork = types.ConsensusNetwork;
        \\const PerObjectCongestionControlMode = types.PerObjectCongestionControlMode;
        \\const BinaryFormatLimitsProfile = types.BinaryFormatLimitsProfile;
        \\const AliasedAddress = types.AliasedAddress;
        \\const GaslessToken = types.GaslessToken;
        \\const Amendments = types.Amendments;
        \\const Chain = types.Chain;
        \\
        \\/// Rust `FeatureFlags`: every field is skipped in the snapshot when equal to its default.
        \\pub const FeatureFlags = struct {
        \\
    );
    for (flags) |f| {
        try w.writeAll("    ");
        try writeId(w, f.name);
        try w.print(": {s} = {s},\n", .{ f.ty, f.default });
    }
    try w.writeAll(
        \\
        \\    pub const yaml_skip_all = true;
        \\};
        \\
        \\/// Rust `ProtocolConfig`. `chain` is `#[serde(skip)]` in Rust: never rendered, set by `protocol.get`.
        \\pub const ProtocolConfig = struct {
        \\
    );
    for (cfgf) |f| {
        try w.writeAll("    ");
        try writeId(w, f.name);
        if (f.kind == .version) {
            try w.writeAll(": u64 = 0,\n");
        } else {
            try w.print(": {s} = {s},\n", .{ f.ty, f.default });
        }
    }
    try w.writeAll(
        \\
        \\    pub const yaml_skip_all = true;
        \\    pub const yaml_keep = [_][]const u8{ "version", "feature_flags" };
        \\
        \\    /// Rust `field()`: the value, or `ProtocolConfigMissing` where Rust panics (CONSTANT_ERR_MSG).
        \\    pub fn get(self: *const ProtocolConfig, comptime field: []const u8) error{ProtocolConfigMissing}!methods.FieldType(ProtocolConfig, field) {
        \\        return methods.get(ProtocolConfig, self, field);
        \\    }
        \\
        \\    /// Rust `field_as_option()`.
        \\    pub fn getOpt(self: *const ProtocolConfig, comptime field: []const u8) ?methods.FieldType(ProtocolConfig, field) {
        \\        return @field(self, field);
        \\    }
        \\};
        \\
    );
}

// ---------------------------------------------------------------------------------------------
// emit gen_data.zig

const Ctx = struct {
    arena: Allocator,
    w: *Io.Writer,
    /// serialized amendments -> const name
    amend_names: std.StringHashMapUnmanaged(usize) = .empty,
    amend_defs: std.ArrayList([]const u8) = .empty,
};

fn jsonEql(a: json.Value, b: json.Value) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => |x| x == b.bool,
        .integer => |x| x == b.integer,
        .float => |x| x == b.float,
        .number_string => |x| std.mem.eql(u8, x, b.number_string),
        .string => |x| std.mem.eql(u8, x, b.string),
        .array => |x| blk: {
            if (x.items.len != b.array.items.len) break :blk false;
            for (x.items, b.array.items) |p, q| if (!jsonEql(p, q)) break :blk false;
            break :blk true;
        },
        .object => |x| blk: {
            if (x.count() != b.object.count()) break :blk false;
            for (x.keys(), x.values()) |k, v| {
                const o = b.object.get(k) orelse break :blk false;
                if (!jsonEql(v, o)) break :blk false;
            }
            break :blk true;
        },
    };
}

fn zigStr(w: *Io.Writer, s: []const u8) !void {
    try w.writeAll("\"");
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        else => try w.writeByte(c),
    };
    try w.writeAll("\"");
}

fn hexOfBytes(arena: Allocator, arr: json.Array) ![]const u8 {
    if (arr.items.len != 32) return error.BadAddress;
    var b: [32]u8 = undefined;
    for (arr.items, 0..) |x, i| b[i] = @intCast(x.integer);
    const hex = std.fmt.bytesToHex(b, .lower);
    return arena.dupe(u8, &hex);
}

fn numLit(w: *Io.Writer, v: json.Value) !void {
    switch (v) {
        .integer => |x| try w.print("{d}", .{x}),
        .number_string => |s| try w.writeAll(s),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        else => return error.NotANumber,
    }
}

/// Zig expression for a JSON value of field f. `null` (absent) gives the field default.
fn literal(cx: *Ctx, w: *Io.Writer, f: Field, v: ?json.Value) !void {
    const val = v orelse return w.writeAll(f.default);
    switch (f.kind) {
        .boolean, .uint, .option_prim => try numLit(w, val),
        .enum_ => try w.print(".{s}", .{val.string}),
        .perobject => switch (val) {
            .string => |s| try w.print(".{s}", .{s}),
            .object => |o| {
                const ent = o.get("ExecutionTimeEstimate") orelse return error.UnknownPerObjectMode;
                try w.writeAll(".{ .ExecutionTimeEstimate = .{");
                for (ent.object.keys(), ent.object.values()) |k, x| {
                    try w.print(" .{s} = ", .{k});
                    try numLit(w, x);
                    try w.writeAll(",");
                }
                try w.writeAll(" } }");
            },
            else => return error.UnknownPerObjectMode,
        },
        .set => {
            try w.writeAll("&.{");
            for (val.array.items) |s| {
                try w.writeAll(" ");
                try zigStr(w, s.string);
                try w.writeAll(",");
            }
            try w.writeAll(" }");
        },
        .aliased => {
            try w.writeAll("&.{");
            for (val.array.items) |a| {
                try w.print(" .{{ .original = h32(\"{s}\"), .aliased = h32(\"{s}\"), .allowed_tx_digests = &.{{", .{
                    try hexOfBytes(cx.arena, a.object.get("original").?.array),
                    try hexOfBytes(cx.arena, a.object.get("aliased").?.array),
                });
                for (a.object.get("allowed_tx_digests").?.array.items) |d| {
                    try w.print(" h32(\"{s}\"),", .{try hexOfBytes(cx.arena, d.array)});
                }
                try w.writeAll(" } },");
            }
            try w.writeAll(" }");
        },
        .gasless => {
            try w.writeAll("&.{");
            for (val.array.items) |t| {
                try w.writeAll(" .{ ");
                try zigStr(w, t.array.items[0].string);
                try w.print(", {d} }},", .{t.array.items[1].integer});
            }
            try w.writeAll(" }");
        },
        .amend => {
            var tmp: Io.Writer.Allocating = .init(cx.arena);
            const tw = &tmp.writer;
            try tw.writeAll("&.{\n");
            for (val.object.keys(), val.object.values()) |k, inner| {
                try tw.print("    .{{ .k = h32(\"{s}\"), .v = &.{{\n", .{k});
                for (inner.object.keys(), inner.object.values()) |ik, iv| {
                    try tw.print("        .{{ .k = h32(\"{s}\"), .v = h32(\"{s}\") }},\n", .{ ik, iv.string });
                }
                try tw.writeAll("    } },\n");
            }
            try tw.writeAll("}");
            const text = tmp.written();
            const gop = try cx.amend_names.getOrPut(cx.arena, text);
            if (!gop.found_existing) {
                gop.value_ptr.* = cx.amend_defs.items.len;
                try cx.amend_defs.append(cx.arena, text);
            }
            try w.print("amend_{d}", .{gop.value_ptr.*});
        },
        .version, .chain, .flags => unreachable,
    }
}

fn keyOrder(a: []const Field, name: []const u8) ?usize {
    for (a, 0..) |f, i| if (std.mem.eql(u8, f.name, name)) return i;
    return null;
}

/// Emit the assignments that turn `prev` (null = all defaults) into `cur`.
fn diffInto(cx: *Ctx, w: *Io.Writer, flags: []const Field, cfgf: []const Field, prev: ?json.ObjectMap, cur: json.ObjectMap, n: *usize) !void {
    const empty: json.ObjectMap = .empty;
    const p = prev orelse empty;
    for (cfgf) |f| {
        if (f.kind == .version or f.kind == .chain) continue;
        if (std.mem.eql(u8, f.name, "feature_flags")) {
            const pf = if (p.get("feature_flags")) |x| x.object else empty;
            const cf = cur.get("feature_flags").?.object;
            for (flags) |ff| {
                const a = pf.get(ff.name);
                const b = cf.get(ff.name);
                if (a == null and b == null) continue;
                if (a != null and b != null and jsonEql(a.?, b.?)) continue;
                try w.writeAll("    c.feature_flags.");
                try writeId(w, ff.name);
                try w.writeAll(" = ");
                try literal(cx, w, ff, b);
                try w.writeAll(";\n");
                n.* += 1;
            }
            continue;
        }
        const a = p.get(f.name);
        const b = cur.get(f.name);
        if (a == null and b == null) continue;
        if (a != null and b != null and jsonEql(a.?, b.?)) continue;
        try w.writeAll("    c.");
        try writeId(w, f.name);
        try w.writeAll(" = ");
        try literal(cx, w, f, b);
        try w.writeAll(";\n");
        n.* += 1;
    }
}

fn emitData(arena: Allocator, w: *Io.Writer, flags: []const Field, cfgf: []const Field, by_chain: [3][]json.ObjectMap) !void {
    const max_v = by_chain[0].len;
    var cx: Ctx = .{ .arena = arena, .w = w };
    // Bodies are produced first (amendment constants are discovered on the way), then written.
    var body: Io.Writer.Allocating = .init(arena);
    const bw = &body.writer;
    var base_changes: usize = 0;
    var chain_changes = [_]usize{ 0, 0 };
    var chain_versions: [2]std.ArrayList(usize) = .{ .empty, .empty };

    try bw.writeAll(
        \\/// What protocol version `v` changes on top of `v - 1` (unknown chain). Version 1 starts from all defaults.
        \\pub fn applyBase(c: *ProtocolConfig, comptime v: u64) void {
        \\    switch (v) {
        \\
    );
    var v: usize = 1;
    while (v <= max_v) : (v += 1) {
        var arm: Io.Writer.Allocating = .init(arena);
        var n: usize = 0;
        try diffInto(&cx, &arm.writer, flags, cfgf, if (v == 1) null else by_chain[0][v - 2], by_chain[0][v - 1], &n);
        base_changes += n;
        if (n == 0) {
            try bw.print("        {d} => {{}},\n", .{v});
        } else {
            try bw.print("        {d} => {{\n", .{v});
            try bw.writeAll(arm.written());
            try bw.writeAll("        },\n");
        }
    }
    try bw.writeAll(
        \\        else => @compileError("no such protocol version"),
        \\    }
        \\}
        \\
        \\/// What `chain` (mainnet or testnet) changes on top of the unknown-chain config of the same version.
        \\pub fn applyChain(c: *ProtocolConfig, comptime chain: Chain, comptime v: u64) void {
        \\    switch (chain) {
        \\        .unknown => {},
        \\
    );
    const chains = [_]struct { name: []const u8, idx: usize }{ .{ .name = "mainnet", .idx = 1 }, .{ .name = "testnet", .idx = 2 } };
    for (chains) |ch| {
        try bw.print("        .{s} => switch (v) {{\n", .{ch.name});
        v = 1;
        while (v <= max_v) : (v += 1) {
            var arm: Io.Writer.Allocating = .init(arena);
            var n: usize = 0;
            try diffInto(&cx, &arm.writer, flags, cfgf, by_chain[0][v - 1], by_chain[ch.idx][v - 1], &n);
            chain_changes[ch.idx - 1] += n;
            if (n == 0) continue;
            try chain_versions[ch.idx - 1].append(arena, v);
            try bw.print("            {d} => {{\n", .{v});
            try bw.writeAll(arm.written());
            try bw.writeAll("            },\n");
        }
        try bw.writeAll("            else => {},\n        },\n");
    }
    try bw.writeAll("    }\n}\n");

    try w.writeAll(
        \\//! GENERATED by src/protocol/gen/gen.zig from the real sui-protocol-config at mainnet-v1.83.1
        \\//! (tools/truth/protocol-config). Do not edit.
        \\const types = @import("types.zig");
        \\const ProtocolConfig = @import("gen_types.zig").ProtocolConfig;
        \\const Chain = types.Chain;
        \\const h32 = types.h32;
        \\const AddrMapEntry = types.AddrMapEntry;
        \\
        \\
    );
    try w.print("pub const base_changes: usize = {d};\npub const mainnet_changes: usize = {d};\npub const testnet_changes: usize = {d};\n\n", .{ base_changes, chain_changes[0], chain_changes[1] });
    for (chains, 0..) |ch, ci| {
        try w.print("/// Versions at which {s} differs from the unknown chain (sorted).\npub const {s}_versions = [_]u64{{", .{ ch.name, ch.name });
        for (chain_versions[ci].items) |cv| try w.print(" {d},", .{cv});
        try w.writeAll(" };\n\n");
    }
    for (cx.amend_defs.items, 0..) |text, i| {
        try w.print("const amend_{d}: types.Amendments = {s};\n\n", .{ i, text });
    }
    try w.writeAll(body.written());
}
