//! Display v2 (sui-display `v2`, sui-node 1.83.1 `RpcService::render_object_display`): parse a
//! Display object's `fields` templates, evaluate them over an object, write sui.rpc.v2
//! `Display { output = 1, errors = 2 }`.
//!
//! - Parsing shares one node/load budget across every key and value; running out of either
//!   makes the whole Display `None` (`render` returns false, nothing written). Other parse
//!   errors stay with their field.
//! - Names are evaluated first (in order), then values, all charging one output counter
//!   (`max_output_size`). Too much output anywhere, or a name that is null / not a string /
//!   fails / repeats, turns the whole Display into `errors: "<message>"`.
//! - Otherwise `output` holds every field that rendered (a null value for an expression that
//!   found nothing) and `errors` every field that failed, each written only if non-empty.
const std = @import("std");
const Allocator = std.mem.Allocator;
const proto = @import("../proto.zig");
const pbvalue = @import("../pbvalue.zig");
const movelayout = @import("../movelayout.zig");
pub const parse = @import("parse.zig");
pub const eval = @import("eval.zig");

pub const Loaded = eval.Loaded;
pub const Store = eval.Store;
pub const FormatError = parse.FormatError;

pub const Limits = struct {
    max_depth: usize = 32,
    max_nodes: usize = 32768,
    max_loads: usize = 8,
    max_move_value_depth: usize = 32,
    max_output_size: usize = 1024 * 1024,
};

const Parsed = union(enum) { ok: []const parse.Strand, err: FormatError };

/// The rendered Display: per-field results, or one whole-display error.
pub const FieldOut = struct { name: []const u8, result: union(enum) { ok: pbvalue.Value, err: []const u8 } };
pub const Rendered = union(enum) {
    fields: []const FieldOut,
    whole: []const u8,
};

const Whole = union(enum) {
    too_much_output,
    name_empty: []const u8,
    name_invalid: []const u8,
    name_evaluation: struct { src: []const u8, e: FormatError },
    name_duplicate: []const u8,
};

fn wholeString(arena: Allocator, w: Whole) Allocator.Error![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    const o = &aw.writer;
    (switch (w) {
        .too_much_output => o.writeAll("Display produces too much output"),
        .name_empty => |s| blk: {
            o.writeAll("Name pattern ") catch break :blk error.WriteFailed;
            parse.debugStr(o, s) catch break :blk error.WriteFailed;
            break :blk o.writeAll(" produced no output");
        },
        .name_invalid => |s| blk: {
            o.writeAll("Name pattern ") catch break :blk error.WriteFailed;
            parse.debugStr(o, s) catch break :blk error.WriteFailed;
            break :blk o.writeAll(" did not evaluate to a string");
        },
        .name_evaluation => |x| blk: {
            o.writeAll("Error evaluating name pattern ") catch break :blk error.WriteFailed;
            parse.debugStr(o, x.src) catch break :blk error.WriteFailed;
            o.writeAll(": ") catch break :blk error.WriteFailed;
            parse.fmtError(o, arena, x.e) catch break :blk error.WriteFailed;
        },
        .name_duplicate => |s| blk: {
            o.writeAll("Duplicate name ") catch break :blk error.WriteFailed;
            break :blk parse.debugStr(o, s);
        },
    }) catch return error.OutOfMemory;
    return aw.written();
}

const FieldResult = union(enum) { ok: pbvalue.Value, err: FormatError };

/// Evaluates one parsed template with the shared output counter. `error.Format` with
/// `it.err == .too_much_output` is the whole-display error; any other error is the field's.
fn evalOne(it: *eval.Interp, p: Parsed, m: eval.OutMeter) eval.Fail!FieldResult {
    const strands = switch (p) {
        .err => |e| return .{ .err = e },
        .ok => |s| s,
    };
    const vs = it.evalStrands(strands) catch |e| switch (e) {
        error.OutOfMemory => return e,
        error.Format => return .{ .err = it.err },
    } orelse {
        // `V::null(meter)`: a failed charge is the field's TooBig
        if (!m.charge(pbvalue.value_size)) return .{ .err = .too_big };
        return .{ .ok = .null };
    };
    const v = eval.write(it, m, vs) catch |e| switch (e) {
        error.OutOfMemory => return e,
        error.Format => {
            if (it.err == .too_much_output) return error.Format;
            return .{ .err = it.err };
        },
    };
    return .{ .ok = v };
}

/// Renders the Display of an object whose Display object has `fields` (key, template).
/// Returns null when Rust gives `None` (parse ran out of nodes or loads).
pub fn renderFields(arena: Allocator, fields: []const [2][]const u8, root_layout: *const movelayout.Layout, root_bytes: []const u8, store: Store, limits: Limits) Allocator.Error!?Rendered {
    var budget: parse.Budget = .{ .nodes = limits.max_nodes, .loads = limits.max_loads };
    const keys = try arena.alloc(Parsed, fields.len);
    const vals = try arena.alloc(Parsed, fields.len);
    for (fields, keys, vals) |f, *k, *v| {
        inline for (.{ 0, 1 }) |j| {
            var meter: parse.Meter = .{ .depth = limits.max_depth, .budget = &budget };
            var err: FormatError = .too_big;
            const out: *Parsed = if (j == 0) k else v;
            if (parse.Parser.format(arena, f[j], &meter, &err)) |s| {
                out.* = .{ .ok = s };
            } else |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Format => switch (err) {
                    .too_big, .too_many_loads => return null,
                    else => out.* = .{ .err = err },
                },
            }
        }
    }

    var it: eval.Interp = .{ .arena = arena, .store = store, .root = .{ .layout = root_layout, .bytes = root_bytes, .scoped = true } };
    var used: usize = 0;
    const m: eval.OutMeter = .{ .used = &used, .max = limits.max_output_size, .depth = limits.max_move_value_depth };
    const names = try arena.alloc(FieldResult, fields.len);
    const values = try arena.alloc(FieldResult, fields.len);
    for (keys, names) |k, *o| o.* = evalOne(&it, k, m) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Format => return .{ .whole = try wholeString(arena, .too_much_output) },
    };
    for (vals, values) |v, *o| o.* = evalOne(&it, v, m) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Format => return .{ .whole = try wholeString(arena, .too_much_output) },
    };

    var out: std.ArrayList(FieldOut) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    for (fields, names, values) |f, n, v| {
        const name = switch (n) {
            .ok => |x| switch (x) {
                .string => |s| s,
                .null => return .{ .whole = try wholeString(arena, .{ .name_empty = f[0] }) },
                else => return .{ .whole = try wholeString(arena, .{ .name_invalid = f[0] }) },
            },
            .err => |e| return .{ .whole = try wholeString(arena, .{ .name_evaluation = .{ .src = f[0], .e = e } }) },
        };
        // sui-display v2/mod.rs: a map entry per name, the first duplicate fails the whole display
        if ((try seen.getOrPut(arena, name)).found_existing) return .{ .whole = try wholeString(arena, .{ .name_duplicate = name }) };
        try out.append(arena, .{ .name = name, .result = switch (v) {
            .ok => |x| .{ .ok = x },
            .err => |e| .{ .err = try parse.errorString(arena, e) },
        } });
    }
    return .{ .fields = out.items };
}

/// Writes sui.rpc.v2 `Display` as message field `field`.
pub fn writeDisplay(arena: Allocator, w: *proto.Writer, field: u32, r: Rendered) (proto.Error || Allocator.Error)!void {
    const mm = try w.begin(field, 256);
    switch (r) {
        .whole => |s| {
            const v: pbvalue.Value = .{ .string = s };
            try pbvalue.write(w, 2, &v);
        },
        .fields => |fs| {
            var ok: pbvalue.StructBuilder = .{};
            var bad: pbvalue.StructBuilder = .{};
            for (fs) |f| switch (f.result) {
                .ok => |v| try ok.put(arena, f.name, v),
                .err => |e| try bad.put(arena, f.name, .{ .string = e }),
            };
            if (ok.items.items.len > 0) {
                const v: pbvalue.Value = .{ .@"struct" = ok.finish() };
                try pbvalue.write(w, 1, &v);
            }
            if (bad.items.items.len > 0) {
                const v: pbvalue.Value = .{ .@"struct" = bad.finish() };
                try pbvalue.write(w, 2, &v);
            }
        },
    }
    try w.end(mm);
}

/// `render_object_display` minus the Display object lookup: false (nothing written) for `None`.
pub fn render(arena: Allocator, w: *proto.Writer, field: u32, fields: []const [2][]const u8, root_layout: *const movelayout.Layout, root_bytes: []const u8, store: Store, limits: Limits) (proto.Error || Allocator.Error)!bool {
    const r = (try renderFields(arena, fields, root_layout, root_bytes, store, limits)) orelse return false;
    try writeDisplay(arena, w, field, r);
    return true;
}

test {
    _ = parse;
    _ = eval;
}

test "display: object fields, alternates, missing field, transforms" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const types = @import("types");
    const two: [32]u8 = blk: {
        var x: [32]u8 = @splat(0);
        x[31] = 2;
        break :blk x;
    };
    const one: [32]u8 = blk: {
        var x: [32]u8 = @splat(0);
        x[31] = 1;
        break :blk x;
    };
    const u8l: movelayout.Layout = .u8;
    const bytes_l: movelayout.Layout = .{ .vector = &u8l };
    const str_s: movelayout.Struct = .{ .type_ = .{ .address = .{ .@"0" = one }, .module = .{ .@"0" = "string" }, .name = .{ .@"0" = "String" }, .type_args = &.{} }, .fields = &.{.{ .name = "bytes", .layout = bytes_l }} };
    const id_s: movelayout.Struct = .{ .type_ = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "object" }, .name = .{ .@"0" = "ID" }, .type_args = &.{} }, .fields = &.{.{ .name = "bytes", .layout = .address }} };
    const uid_s: movelayout.Struct = .{ .type_ = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "object" }, .name = .{ .@"0" = "UID" }, .type_args = &.{} }, .fields = &.{.{ .name = "id", .layout = .{ .@"struct" = &id_s } }} };
    const nft_s: movelayout.Struct = .{ .type_ = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "nft" }, .name = .{ .@"0" = "Nft" }, .type_args = &.{} }, .fields = &.{
        .{ .name = "id", .layout = .{ .@"struct" = &uid_s } },
        .{ .name = "name", .layout = .{ .@"struct" = &str_s } },
        .{ .name = "level", .layout = .u64 },
    } };
    const root: movelayout.Layout = .{ .@"struct" = &nft_s };
    var bytes: [32 + 1 + 3 + 8]u8 = undefined;
    @memset(bytes[0..32], 0xab);
    bytes[32] = 3;
    @memcpy(bytes[33..36], "Bob");
    std.mem.writeInt(u64, bytes[36..44], 7, .little);
    const NoStore = struct {
        fn latest(_: *const anyopaque, _: Allocator, _: *const [32]u8) Allocator.Error!?Loaded {
            return null;
        }
    };
    const store: Store = .{ .ctx = &bytes, .latest = NoStore.latest };
    const fields = [_][2][]const u8{
        .{ "name", "{name}" },
        .{ "link", "https://x.io/{id}?l={level}" },
        .{ "alt", "{missing | name}" },
        .{ "none", "{missing}" },
        .{ "lvl", "{level:hex}" },
        .{ "bad", "{level:json} x" },
    };
    _ = types;
    const r = (try renderFields(a, &fields, &root, &bytes, store, .{})).?;
    const fs = r.fields;
    try std.testing.expectEqualStrings("Bob", fs[0].result.ok.string);
    try std.testing.expectEqualStrings("https://x.io/0xabababababababababababababababababababababababababababababababab?l=7", fs[1].result.ok.string);
    try std.testing.expectEqualStrings("Bob", fs[2].result.ok.string);
    try std.testing.expect(fs[3].result.ok == .null);
    try std.testing.expectEqualStrings("0000000000000007", fs[4].result.ok.string);
    try std.testing.expectEqualStrings("Invalid transform for expression at byte offset 0: unexpected 'json' in string", fs[5].result.err);
}

test "display: 16k-field positional struct literal renders fast and sorted (review: O(n^2) StructBuilder)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const n = 16000;
    var src: std.ArrayList(u8) = .empty;
    try src.appendSlice(a, "{0xa::m::S(");
    for (0..n) |i| try src.appendSlice(a, if (i == 0) "1u8" else ",1u8");
    try src.appendSlice(a, "):json}");
    const fields = [_][2][]const u8{.{ "big", src.items }};
    const root: movelayout.Layout = .u8;
    const bytes = [_]u8{1};
    const NoStore = struct {
        fn latest(_: *const anyopaque, _: Allocator, _: *const [32]u8) Allocator.Error!?Loaded {
            return null;
        }
    };
    const store: Store = .{ .ctx = &bytes, .latest = NoStore.latest };
    const t0 = monoNs();
    const r = (try renderFields(a, &fields, &root, &bytes, store, .{})).?;
    var buf: proto.Writer = .init(try a.alloc(u8, 4 << 20));
    try writeDisplay(a, &buf, 1, r);
    const ns = monoNs() - t0;
    const es = r.fields[0].result.ok.@"struct";
    try std.testing.expectEqual(@as(usize, n), es.len);
    for (es[1..], es[0 .. es.len - 1]) |x, y| try std.testing.expect(std.mem.order(u8, y.key, x.key) == .lt);
    try std.testing.expectEqualStrings("pos0", es[0].key);
    try std.testing.expectEqualStrings("pos1", es[1].key);
    try std.testing.expectEqualStrings("pos10", es[2].key);
    for (es) |e| try std.testing.expectEqual(@as(f64, 1), e.value.number);
    // quadratic build was ~1.3e8 key compares (0.3-0.6 s ReleaseFast, many seconds in Debug)
    const max_ms: u64 = if (@import("builtin").mode == .debug) 1500 else 50;
    if (ns / std.time.ns_per_ms > max_ms) {
        std.debug.print("16k-field display render took {d} ms (max {d})\n", .{ ns / std.time.ns_per_ms, max_ms });
        return error.TestUnexpectedResult;
    }
}

test "display: duplicate field names fail the whole display" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const root: movelayout.Layout = .u8;
    const bytes = [_]u8{1};
    const NoStore = struct {
        fn latest(_: *const anyopaque, _: Allocator, _: *const [32]u8) Allocator.Error!?Loaded {
            return null;
        }
    };
    const store: Store = .{ .ctx = &bytes, .latest = NoStore.latest };
    var fields: [40][2][]const u8 = undefined;
    for (&fields, 0..) |*f, i| f.* = .{ try std.fmt.allocPrint(a, "n{d}", .{i}), "x" };
    fields[39][0] = "n7";
    const r = (try renderFields(a, &fields, &root, &bytes, store, .{})).?;
    try std.testing.expect(r == .whole);
    try std.testing.expect(std.mem.indexOf(u8, r.whole, "n7") != null);
    fields[39][0] = "n39";
    const r2 = (try renderFields(a, &fields, &root, &bytes, store, .{})).?;
    try std.testing.expectEqual(@as(usize, 40), r2.fields.len);
}

fn monoNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}
