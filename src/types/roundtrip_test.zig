//! Property test: deterministic random values of every registry type (every variant of every
//! enum is reached) survive encode -> decode -> encode, validate-and-skip, and tree rendering.
//! Complements the corpus suites for the 89 variants no mainnet checkpoint in the corpus has.
const std = @import("std");
const bcs = @import("bcs");
const hand = @import("hand.zig");
const t = std.testing;

const Rng = std.Random.DefaultPrng;

fn has(comptime T: type, comptime name: []const u8) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union" => @hasDecl(T, name),
        else => false,
    };
}

fn fill(comptime T: type, rng: *Rng, a: std.mem.Allocator, depth: u8, force: ?usize) std.mem.Allocator.Error!T {
    const r = rng.random();
    if (comptime T == hand.GenericSignature or T == hand.SuiSignature) {
        const b = try a.alloc(u8, 97);
        r.bytes(b);
        b[0] = 0;
        return .{ .@"0" = b };
    }
    if (comptime T == hand.SuiBitmap) {
        const b = try a.dupe(u8, &.{ 0x3a, 0x30, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 1, 0, 2, 0 });
        return .{ .@"0" = b };
    }
    if (comptime T == hand.Identifier) return .{ .@"0" = try a.dupe(u8, "ident_1") };
    if (comptime T == hand.Duration) return .{ .secs = r.int(u64) >> 1, .nanos = r.uintLessThan(u32, 1_000_000_000) };
    if (comptime has(T, "bcs_party")) {
        // Valid Party: permissions from the allowed set, members strictly increasing by address.
        const M = @typeInfo(@FieldType(T, "members")).pointer.child;
        const n = r.uintLessThan(usize, 3);
        const m = try a.alloc(M, n);
        for (m, 0..) |*e, i| {
            var addr: [32]u8 = undefined;
            r.bytes(&addr);
            addr[0] = @intCast(i); // strictly increasing first byte
            e.* = .{ .{ .@"0" = addr }, 0b11 };
        }
        return .{ .default_permissions = 0b1, .members = m };
    }
    if (comptime T == hand.Base64PublicKey) return .{ .@"0" = try a.dupe(u8, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") };
    if (comptime has(T, "bcs_byte_array")) {
        var out: T = undefined;
        r.bytes(&out.@"0");
        return out;
    }
    if (comptime @typeInfo(T) == .@"struct" and has(T, "bcs_string")) {
        if (comptime T == hand.Bn254Fq or T == hand.Bn254Fr) return .{ .@"0" = try a.dupe(u8, "12345") };
        return .{ .@"0" = try a.dupe(u8, "str \"q\" \u{e9}") };
    }
    switch (@typeInfo(T)) {
        .bool => return r.boolean(),
        .int => return r.int(T),
        .void => return {},
        .@"enum" => |e| return @enumFromInt(@as(e.tag_type, 0)),
        .array => |ar| {
            var out: T = undefined;
            for (&out) |*s| s.* = try fill(ar.child, rng, a, depth, null);
            return out;
        },
        .pointer => |p| switch (p.size) {
            .slice => {
                const n: usize = if (depth > 5) 0 else r.uintLessThan(usize, 4);
                const out = try a.alloc(p.child, n);
                for (out) |*s| s.* = try fill(p.child, rng, a, depth + 1, null);
                return out;
            },
            .one => {
                const out = try a.create(p.child);
                out.* = try fill(p.child, rng, a, depth + 1, null);
                return out;
            },
            else => unreachable,
        },
        .optional => |o| {
            if (depth > 5 or r.boolean()) return null;
            return try fill(o.child, rng, a, depth + 1, null);
        },
        .@"struct" => |s| {
            if (comptime has(T, "bcs_map")) {
                const n = r.uintLessThan(usize, 3);
                var tmp: std.ArrayList(T.Entry) = .empty;
                var i: usize = 0;
                while (i < n) : (i += 1) {
                    const e: T.Entry = .{ .key = try fill(@FieldType(T.Entry, "key"), rng, a, depth + 1, null), .value = try fill(@FieldType(T.Entry, "value"), rng, a, depth + 1, null) };
                    try tmp.append(a, e);
                }
                // wire order: sorted by encoded key, strictly increasing
                const Sort = struct {
                    fn lessThan(_: void, x: T.Entry, y: T.Entry) bool {
                        var bx: [4096]u8 = undefined;
                        var by: [4096]u8 = undefined;
                        var wx = bcs.Writer.init(&bx);
                        var wy = bcs.Writer.init(&by);
                        bcs.encode(@FieldType(T.Entry, "key"), &x.key, &wx) catch unreachable;
                        bcs.encode(@FieldType(T.Entry, "key"), &y.key, &wy) catch unreachable;
                        return std.mem.order(u8, wx.written(), wy.written()) == .lt;
                    }
                };
                std.mem.sort(T.Entry, tmp.items, {}, Sort.lessThan);
                // drop duplicates
                var w: usize = 0;
                for (tmp.items, 0..) |e, k| {
                    if (k > 0 and !Sort.lessThan({}, tmp.items[w - 1], e)) continue;
                    tmp.items[w] = e;
                    w += 1;
                }
                return .{ .entries = tmp.items[0..w] };
            }
            if (comptime has(T, "element")) { // SizeOneVec
                const one = try a.alloc(@typeInfo(@FieldType(T, "items")).pointer.child, 1);
                one[0] = try fill(@TypeOf(one[0]), rng, a, depth + 1, null);
                return .{ .items = one };
            }
            var out: T = undefined;
            inline for (s.field_names, s.field_types) |n, ft| @field(out, n) = try fill(ft, rng, a, depth + 1, null);
            return out;
        },
        .@"union" => |u| {
            const k: usize = force orelse if (depth > 4) 0 else r.uintLessThan(usize, u.field_names.len);
            inline for (u.field_names, u.field_types, 0..) |n, ft, i| {
                if (i == k) return @unionInit(T, n, try fill(ft, rng, a, depth + 1, null));
            }
            unreachable;
        },
        else => @compileError("fill: " ++ @typeName(T)),
    }
}

pub fn run(comptime T: type, comptime name: []const u8) !void {
    if (comptime (@typeInfo(T) != .@"struct" and @typeInfo(T) != .@"union")) return;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var rng = Rng.init(std.hash.Wyhash.hash(0, name));
    const variants: usize = if (@typeInfo(T) == .@"union") @typeInfo(T).@"union".field_names.len else 1;
    var iter: usize = 0;
    while (iter < variants * 3 + 5) : (iter += 1) {
        _ = arena_state.reset(.retain_capacity);
        const v = try fill(T, &rng, a, 0, if (@typeInfo(T) == .@"union") iter % variants else null);
        const enc = try bcs.encodeAlloc(T, a, &v);
        // decode -> encode
        const d = bcs.decode(T, a, enc) catch |e| {
            std.debug.print("{s}: decode of own encoding failed: {s}\n", .{ name, @errorName(e) });
            return e;
        };
        const enc2 = try bcs.encodeAlloc(T, a, &d);
        try t.expectEqualSlices(u8, enc, enc2);
        var rd = bcs.Reader.init(enc);
        try bcs.skip(T, &rd);
        try rd.finish();
        const txt = try bcs.tree.renderAlloc(T, a, &d);
        try t.expect(txt.len > 0);
        _ = try bcs.View(T).init(enc);
        if (bcs.encodedLen(T, &v) != enc.len) return error.LengthMismatch;
    }
}

/// The enums that have registry variants no mainnet checkpoint in the corpus contains. For every
/// variant of each, Rust (tools/truth/bcs-types/edge) decodes deepwave's encoding with the real
/// sui-types type and returns what it re-encodes; variants_test.zig replays that. Flip `emit`
/// to regenerate testdata/variants_in.txt from the stderr of
/// `zig build test` (lines starting with "VARIANT ").
pub const variant_enums = .{
    "ExecutionErrorKind",      "CommandArgumentError",      "TypeInput",          "TypeTag",
    "PackageUpgradeError",     "CompressedSignature",       "DeleteKind",         "PublicKey",
    "AccumulatorValue",        "ExecutionTimeObservationKey", "ObjectInfoRequestKind", "TypeArgumentError",
    "UnchangedConsensusKind",  "WithdrawFrom",              "EndOfEpochTransactionKind", "Owner",
};
const emit = false;

test "emit variant vectors" {
    if (!emit) return error.SkipZigTest;
    const gen = @import("gen.zig");
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    inline for (variant_enums) |name| {
        const T = @field(gen, name);
        var rng = Rng.init(std.hash.Wyhash.hash(7, name));
        const nv = @typeInfo(T).@"union".field_names.len;
        for (0..nv) |k| {
            for (0..2) |rep| {
                _ = rep;
                const v = try fill(T, &rng, a, 0, k);
                const enc = try bcs.encodeAlloc(T, a, &v);
                std.debug.print("VARIANT {s} {d} {x}\n", .{ name, k, enc });
            }
        }
    }
}
