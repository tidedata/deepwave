//! Conformance suite `bcs-codec`: codec edge cases against crates.io `bcs` 0.1.6.
//! Vectors come from tools/truth/bcs-types (see its README); each is an input, the probe type
//! and either the re-encoded bytes or the error kind Rust reported.
const std = @import("std");
const harness = @import("harness");
const bcs = @import("root.zig");

pub const suites = [_]harness.Suite{
    .{
        .name = "bcs-codec",
        .lane = "bcs-types",
        .doc = "codec edge cases (uleb, bool, option, depth, length limits, error parity) vs Rust bcs vectors",
        .run = run,
    },
};

const E = union(enum) {
    A,
    B: u32,
    C: struct { x: u8, y: bool, pub const bcs_no_depth = true; },
    D: []const u8,
    F: struct { u8, u16 },
};
const S = struct {
    a: u16,
    b: ?bcs.String,
    c: [4]u8,
    d: struct { u8, u16 },
    e: []const E,
};
const Nest = union(enum) { Nil, Cons: *const Nest };
const NT = struct {
    @"0": ?*const NT,
    pub const bcs_newtype = true;
};
const Wrapper = struct { v: []const Wrapper };
const UnitStruct = struct {};

const probes = .{
    .{ "bool", bool },
    .{ "u8", u8 },
    .{ "u16", u16 },
    .{ "u32", u32 },
    .{ "u64", u64 },
    .{ "u128", u128 },
    .{ "opt_u32", ?u32 },
    .{ "unit", void },
    .{ "unit_struct", UnitStruct },
    .{ "array4", [4]u8 },
    .{ "tuple_u8_bool", struct { u8, bool } },
    .{ "bytes", []const u8 },
    .{ "string", bcs.String },
    .{ "vec_u32", []const u32 },
    .{ "vec_vec_u8", []const []const u8 },
    .{ "vec_opt_u8", []const ?u8 },
    .{ "enum", E },
    .{ "struct", S },
    .{ "map_u8_u8", bcs.Map(u8, u8) },
    .{ "map_str_u8", bcs.Map(bcs.String, u8) },
    .{ "nest", Nest },
    .{ "newtype_nest", NT },
    .{ "wrapper_nest", Wrapper },
};

const Vector = struct {
    id: []const u8,
    type: []const u8,
    in: []const u8,
    ok: ?[]const u8 = null,
    err: ?[]const u8 = null,
};

fn run(ctx: *harness.Ctx) !void {
    // gpa, not scratch: `nextItem` resets the scratch arena between vectors.
    const text = ctx.corpus.readFileAlloc(ctx.io, "vectors/bcs-codec/vectors.jsonl", ctx.gpa, .limited(1 << 28)) catch |e| {
        ctx.fail("vectors", "cannot read vectors/bcs-codec/vectors.jsonl ({s}); run tools/truth/bcs-types", .{@errorName(e)});
        return;
    };
    defer ctx.gpa.free(text);
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) break;
        ctx.nextItem();
        const arena = ctx.scratch();
        const v = std.json.parseFromSliceLeaky(Vector, arena, line, .{}) catch |e| {
            ctx.fail("vectors", "malformed vector line ({s}): {s}", .{ @errorName(e), line[0..@min(line.len, 120)] });
            continue;
        };
        if (!ctx.selected(v.id)) continue;
        const input = try arena.alloc(u8, v.in.len / 2);
        _ = std.fmt.hexToBytes(input, v.in) catch {
            ctx.fail(v.id, "bad input hex", .{});
            continue;
        };
        var matched = false;
        inline for (probes) |pr| {
            if (!matched and std.mem.eql(u8, v.type, pr[0])) {
                matched = true;
                check(pr[1], ctx, v, input);
            }
        }
        if (!matched) ctx.fail(v.id, "probe type {s} unknown", .{v.type});
    }
}

fn check(comptime T: type, ctx: *harness.Ctx, v: Vector, input: []const u8) void {
    const arena = ctx.scratch();
    var c = ctx.check(v.id);
    defer _ = c.finish();
    if (bcs.decode(T, arena, input)) |val| {
        if (v.err) |want| return c.failf("Rust fails with {s}, zui decoded", .{want});
        const re = bcs.encodeAlloc(T, arena, &val) catch |e| return c.failf("encode: {s}", .{@errorName(e)});
        const want_hex = v.ok orelse return c.failf("vector has neither ok nor err", .{});
        var got_hex: std.Io.Writer.Allocating = .init(arena);
        got_hex.writer.print("{x}", .{re}) catch return c.failf("oom", .{});
        c.text("re-encoded bytes (hex)", want_hex, got_hex.written());
        if (bcs.encodedLen(T, &val) != re.len) c.failf("encodedLen disagrees with encode", .{});
        // The validate-only walk must agree with decode.
        var r = bcs.Reader.init(input);
        bcs.skip(T, &r) catch |e| c.failf("skip failed ({s}) where decode succeeded", .{@errorName(e)});
    } else |e| {
        const want = v.err orelse return c.failf("Rust decodes, zui fails with {s}", .{@errorName(e)});
        c.text("error kind", want, @errorName(e));
        // The validate-only walk must report the same kind.
        var r = bcs.Reader.init(input);
        if (bcs.skip(T, &r)) {
            if (e != error.TrailingBytes) c.failf("skip accepted input that decode rejects ({s})", .{@errorName(e)});
        } else |se| {
            if (se != e) c.failf("skip says {s}, decode says {s}", .{ @errorName(se), @errorName(e) });
        }
    }
}
