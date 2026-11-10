//! `sui.rpc.v2.ProtocolConfig` from deepwave's protocol tables, as sui-rpc-api `protocol_config_to_proto`
//! builds it (get_epoch.rs) and prost encodes it:
//! - `protocol_version` (1);
//! - `feature_flags` (2): `feature_map()`, every `bool` field of `FeatureFlags` (BTreeMap order; prost
//!   drops a `false` value, so such an entry is the key alone);
//! - `attributes` (3): every non-null `render` value as a string (u16/u32 through f64 Display, u64 and
//!   strings as is, bools as `true`/`false`, lists as compact JSON);
//! - `configs` (4): the same values as `google.protobuf.Value` (u16/u32 NumberValue, u64 StringValue,
//!   bool BoolValue, `gasless_allowed_token_types` a ListValue of `[string, string]`), plus every
//!   feature flag as a BoolValue.
//! `render` covers every `Option<_>` field of the Rust struct except `#[skip_accessor]`
//! (`include_special_package_amendments`); non-Option fields (`aliased_addresses`) are absent.
//! A read submask selects whole top-level fields (`ProtocolConfig::merge_from`).
const std = @import("std");
const protocol = @import("protocol");
const proto = @import("proto.zig");
const mask = @import("mask.zig");

const Cfg = protocol.ProtocolConfig;
const Flags = protocol.FeatureFlags;

const Kind = enum { number, string_u64, boolean, gasless };

const Attr = struct { name: []const u8, kind: Kind };

fn lessName(_: void, a: Attr, b: Attr) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

/// Every rendered attribute of `ProtocolConfig`, sorted by name (BTreeMap order).
const attrs: []const Attr = blk: {
    @setEvalBranchQuota(1_000_000);
    var list: []const Attr = &.{};
    const info = @typeInfo(Cfg).@"struct";
    for (info.field_names, info.field_types) |fname, ftype| {
        if (std.mem.eql(u8, fname, "include_special_package_amendments")) continue;
        const k: ?Kind = switch (ftype) {
            ?u16, ?u32 => .number,
            ?u64 => .string_u64,
            ?bool => .boolean,
            ?[]const protocol.types.GaslessToken => .gasless,
            else => null,
        };
        if (k) |kind| list = list ++ [_]Attr{.{ .name = fname, .kind = kind }};
    }
    var arr: [list.len]Attr = list[0..list.len].*;
    std.mem.sortUnstable(Attr, &arr, {}, lessName);
    const final = arr;
    break :blk &final;
};

/// Every `bool` field of `FeatureFlags`, sorted.
const flags: []const []const u8 = blk: {
    @setEvalBranchQuota(1_000_000);
    var list: []const []const u8 = &.{};
    const info = @typeInfo(Flags).@"struct";
    for (info.field_names, info.field_types) |fname, ftype| {
        if (ftype == bool) list = list ++ [_][]const u8{fname};
    }
    var arr: [list.len][]const u8 = list[0..list.len].*;
    std.mem.sortUnstable([]const u8, &arr, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    const final = arr;
    break :blk &final;
};

/// One entry of the merged `configs` map: attributes and feature flags interleaved in key order.
const ConfigKey = struct { name: []const u8, attr: ?usize, flag: ?usize };
const config_keys: []const ConfigKey = blk: {
    @setEvalBranchQuota(10_000_000);
    var out: [attrs.len + flags.len]ConfigKey = undefined;
    var i = 0;
    var j = 0;
    var n = 0;
    while (i < attrs.len or j < flags.len) : (n += 1) {
        if (j >= flags.len or (i < attrs.len and std.mem.lessThan(u8, attrs[i].name, flags[j]))) {
            out[n] = .{ .name = attrs[i].name, .attr = i, .flag = null };
            i += 1;
        } else {
            out[n] = .{ .name = flags[j], .attr = null, .flag = j };
            j += 1;
        }
    }
    const final = out;
    break :blk &final;
};

fn flagValue(c: *const Cfg, comptime i: usize) bool {
    return @field(c.feature_flags, flags[i]);
}

/// Rust `f64` Display of an integer below 2^32 is its decimal digits.
fn writeEntryString(w: *proto.Writer, field: u32, key: []const u8, value: []const u8) proto.Error!void {
    const m = try w.begin(field, key.len + value.len + 4);
    try w.string(1, key);
    if (value.len != 0) try w.string(2, value);
    try w.end(m);
}

fn writeJsonString(out: *std.ArrayList(u8), arena: std.mem.Allocator, s: []const u8) !void {
    try out.append(arena, '"');
    for (s) |ch| switch (ch) {
        '"' => try out.appendSlice(arena, "\\\""),
        '\\' => try out.appendSlice(arena, "\\\\"),
        '\n' => try out.appendSlice(arena, "\\n"),
        '\r' => try out.appendSlice(arena, "\\r"),
        '\t' => try out.appendSlice(arena, "\\t"),
        0x08 => try out.appendSlice(arena, "\\b"),
        0x0c => try out.appendSlice(arena, "\\f"),
        0...0x07, 0x0b, 0x0e...0x1f => try out.print(arena, "\\u{x:0>4}", .{ch}),
        else => try out.append(arena, ch),
    };
    try out.append(arena, '"');
}

/// `Value { list_value = 6: ListValue { values = 1: [Value { list_value: [string, string] }] } }`
fn writeGaslessValue(w: *proto.Writer, list: []const protocol.types.GaslessToken) proto.Error!void {
    const lv = try w.begin(6, 64);
    for (list) |t| {
        const v = try w.begin(1, 96);
        const inner = try w.begin(6, 96);
        {
            const a = try w.begin(1, t[0].len + 4);
            try w.string(3, t[0]);
            try w.end(a);
        }
        {
            var nb: [24]u8 = undefined;
            const s = std.fmt.bufPrint(&nb, "{d}", .{t[1]}) catch unreachable;
            const b = try w.begin(1, s.len + 4);
            try w.string(3, s);
            try w.end(b);
        }
        try w.end(inner);
        try w.end(v);
    }
    try w.end(lv);
}

/// The sui-node release deepwave answers as by default (DROP-IN target): sui-node 1.83.1, whose
/// MAX_PROTOCOL_VERSION is 141. Its ProtocolConfig struct has no field 1.84 added
/// (`protocol.release_fields`), so GetEpoch `protocol_config` must not list them at any version.
pub const drop_in_release_max: u64 = 141;

/// Sui release lines and their MAX_PROTOCOL_VERSION (sui-protocol-config `MAX_PROTOCOL_VERSION`).
const release_lines = [_]struct { line: []const u8, max: u64 }{
    .{ .line = "1.83", .max = 141 },
    .{ .line = "1.84", .max = 142 },
};

/// `--rpc-release` value: a release (`1.83`, `1.83.1`, `v1.84.0`, `mainnet-v1.83.1`) or a bare
/// max protocol version (`141`). Null when it names neither.
pub fn parseRelease(text: []const u8) ?u64 {
    var t = text;
    if (std.mem.startsWith(u8, t, "mainnet-")) t = t["mainnet-".len..] else if (std.mem.startsWith(u8, t, "testnet-")) t = t["testnet-".len..];
    if (std.mem.startsWith(u8, t, "v")) t = t[1..];
    if (std.mem.indexOfScalar(u8, t, '.') == null) {
        const v = std.fmt.parseInt(u64, t, 10) catch return null;
        return if (v >= protocol.min_protocol_version and v <= protocol.max_protocol_version) v else null;
    }
    for (release_lines) |r| {
        if (std.mem.eql(u8, t, r.line)) return r.max;
        if (std.mem.startsWith(u8, t, r.line) and t.len > r.line.len and t[r.line.len] == '.') {
            _ = std.fmt.parseInt(u32, t[r.line.len + 1 ..], 10) catch return null;
            return r.max;
        }
    }
    return null;
}

/// The release a GetEpoch answer renders as: the configured one, raised to the chain's current
/// protocol version. A sui-node still following the chain at protocol `current_pv` runs a release
/// whose max is at least that (an older one halts at the epoch change), so once mainnet is on 142
/// every real node lists the 1.84 fields, past epochs included.
pub fn effectiveRelease(configured: u64, current_pv: u64) u64 {
    return @min(@max(configured, current_pv), protocol.max_protocol_version);
}

/// Whether a sui-node whose release tops out at `release_max` knows field `name`.
fn shown(comptime name: []const u8, release_max: u64) bool {
    const r = comptime protocol.fieldRelease(name);
    return r == 0 or release_max >= r;
}

/// The ProtocolConfig message body for `c`, restricted to `m`'s top-level fields, as a sui-node
/// whose release tops out at protocol `release_max` renders it: fields a newer release added
/// (`protocol.fieldRelease`) are left out. Production passes `protocol.max_protocol_version`.
pub fn write(arena: std.mem.Allocator, w: *proto.Writer, c: *const Cfg, m: mask.Mask, release_max: u64) !void {
    @setEvalBranchQuota(200_000);
    if (m.containsDyn("protocol_version")) try w.uint(1, c.version);
    if (m.containsDyn("feature_flags")) {
        inline for (flags, 0..) |name, i| if (shown(name, release_max)) {
            const on = flagValue(c, i);
            const e = try w.begin(2, name.len + 6);
            try w.string(1, name);
            if (on) try w.uint(2, 1);
            try w.end(e);
        };
    }
    if (m.containsDyn("attributes")) {
        inline for (attrs) |a| if (shown(a.name, release_max)) {
            const v = @field(c, a.name);
            if (v) |x| {
                var nb: [24]u8 = undefined;
                switch (a.kind) {
                    .number, .string_u64 => try writeEntryString(w, 3, a.name, std.fmt.bufPrint(&nb, "{d}", .{x}) catch unreachable),
                    .boolean => try writeEntryString(w, 3, a.name, if (x) "true" else "false"),
                    .gasless => {
                        var out: std.ArrayList(u8) = .empty;
                        try out.append(arena, '[');
                        for (x, 0..) |t, k| {
                            if (k > 0) try out.append(arena, ',');
                            try out.append(arena, '[');
                            try writeJsonString(&out, arena, t[0]);
                            try out.append(arena, ',');
                            try writeJsonString(&out, arena, std.fmt.bufPrint(&nb, "{d}", .{t[1]}) catch unreachable);
                            try out.append(arena, ']');
                        }
                        try out.append(arena, ']');
                        try writeEntryString(w, 3, a.name, out.items);
                    },
                }
            }
        };
    }
    if (m.containsDyn("configs")) {
        inline for (config_keys) |k| if (shown(k.name, release_max)) {
            if (k.flag) |fi| {
                const e = try w.begin(4, k.name.len + 8);
                try w.string(1, k.name);
                const v = try w.begin(2, 2);
                try w.uint(4, @intFromBool(flagValue(c, fi)));
                try w.end(v);
                try w.end(e);
            } else if (k.attr) |ai| {
                const a = attrs[ai];
                if (@field(c, a.name)) |x| {
                    const e = try w.begin(4, k.name.len + 32);
                    try w.string(1, k.name);
                    const v = try w.begin(2, 24);
                    switch (a.kind) {
                        .number => {
                            try w.tag(2, 1);
                            const bits: u64 = @bitCast(@as(f64, @floatFromInt(x)));
                            var le: [8]u8 = undefined;
                            std.mem.writeInt(u64, &le, bits, .little);
                            try w.rawAppend(&le);
                        },
                        .string_u64 => {
                            var nb: [24]u8 = undefined;
                            try w.string(3, std.fmt.bufPrint(&nb, "{d}", .{x}) catch unreachable);
                        },
                        .boolean => try w.uint(4, @intFromBool(x)),
                        .gasless => try writeGaslessValue(w, x),
                    }
                    try w.end(v);
                    try w.end(e);
                }
            }
        };
    }
}

test "attribute and flag tables" {
    try std.testing.expect(attrs.len > 300);
    try std.testing.expect(flags.len > 100);
    try std.testing.expectEqual(attrs.len + flags.len, config_keys.len);
    for (config_keys[1..], 0..) |k, i| try std.testing.expect(std.mem.lessThan(u8, config_keys[i].name, k.name));
}

test "release names and the effective release" {
    try std.testing.expectEqual(@as(?u64, 141), parseRelease("1.83"));
    try std.testing.expectEqual(@as(?u64, 141), parseRelease("1.83.1"));
    try std.testing.expectEqual(@as(?u64, 141), parseRelease("mainnet-v1.83.1"));
    try std.testing.expectEqual(@as(?u64, 142), parseRelease("v1.84.0"));
    try std.testing.expectEqual(@as(?u64, 141), parseRelease("141"));
    try std.testing.expectEqual(@as(?u64, null), parseRelease("1.85"));
    try std.testing.expectEqual(@as(?u64, null), parseRelease("1.831"));
    try std.testing.expectEqual(@as(?u64, null), parseRelease("999"));
    try std.testing.expectEqual(@as(?u64, null), parseRelease("1.83.x"));
    try std.testing.expectEqual(@as(u64, 141), effectiveRelease(drop_in_release_max, 104));
    try std.testing.expectEqual(@as(u64, 141), effectiveRelease(drop_in_release_max, 141));
    try std.testing.expectEqual(@as(u64, 142), effectiveRelease(drop_in_release_max, 142));
    try std.testing.expectEqual(@as(u64, 142), effectiveRelease(142, 104));
}

test "a 1.83.1 node lists no 1.84 field (DROP-IN-STATUS round 1, SDK getProtocolConfig)" {
    const cfg = try protocol.get(drop_in_release_max, .mainnet);
    var tree = try mask.Tree.parse(std.testing.allocator, "*");
    defer tree.deinit(std.testing.allocator);
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const buf = try arena.allocator().alloc(u8, 256 * 1024);
    inline for (.{ drop_in_release_max, protocol.max_protocol_version }) |rel| {
        var w = proto.Writer.init(buf);
        try write(arena.allocator(), &w, cfg, tree.mask(), rel);
        const out = w.bytesWritten();
        inline for (.{ "check_groth16_pvk_length", "secp256r1_ecrecover_checks_x_below_p" }) |name| {
            const has = std.mem.indexOf(u8, out, name) != null;
            try std.testing.expectEqual(rel >= 142, has);
        }
        // fields every release has stay
        try std.testing.expect(std.mem.indexOf(u8, out, "max_move_object_size") != null);
    }
}

fn testVarint(b: []const u8, o: *usize) ?u64 {
    var v: u64 = 0;
    var sh: u6 = 0;
    while (o.* < b.len) {
        const c = b[o.*];
        o.* += 1;
        v |= @as(u64, c & 0x7f) << sh;
        if (c & 0x80 == 0) return v;
        if (sh >= 63) return null;
        sh += 7;
    }
    return null;
}

/// One length-delimited field `num` of a protobuf message (test helper).
fn testField(msg: []const u8, num: u64) ?[]const u8 {
    var o: usize = 0;
    while (o < msg.len) {
        const key = testVarint(msg, &o) orelse return null;
        switch (key & 7) {
            0 => _ = testVarint(msg, &o) orelse return null,
            2 => {
                const n: usize = @intCast(testVarint(msg, &o) orelse return null);
                if (key >> 3 == num) return msg[o .. o + n];
                o += n;
            },
            else => return null,
        }
    }
    return null;
}

test "GetEpoch protocol_config is byte-identical to sui-node 1.83.1 at epoch 1305 (vector)" {
    // sui-node 1.83.1 on a production node, 2026-11-08: GetEpoch read_mask epoch,protocol_config
    // (protocol 141). deepwave's node default (drop_in_release_max) must render the same bytes; the
    // 1.84 field set (release 142) must not (DROP-IN-STATUS round 1: 4 SDK getProtocolConfig diffs).
    const resp = @embedFile("vectors/protocfg/getepoch-1305-sui-node-1.83.1.bin");
    const epoch_msg = testField(resp, 1) orelse return error.TestUnexpectedResult;
    const want = testField(epoch_msg, 9) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 0x08), want[0]);
    var o: usize = 1;
    const pv = testVarint(want, &o) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 141), pv);
    const cfg = try protocol.get(pv, .mainnet);
    var tree = try mask.Tree.parse(std.testing.allocator, "*");
    defer tree.deinit(std.testing.allocator);
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const buf = try arena.allocator().alloc(u8, 256 * 1024);
    {
        var w = proto.Writer.init(buf);
        try write(arena.allocator(), &w, cfg, tree.mask(), effectiveRelease(drop_in_release_max, pv));
        try std.testing.expectEqualSlices(u8, want, w.bytesWritten());
    }
    {
        var w = proto.Writer.init(buf);
        try write(arena.allocator(), &w, cfg, tree.mask(), protocol.max_protocol_version);
        try std.testing.expect(!std.mem.eql(u8, want, w.bytesWritten()));
    }
}
