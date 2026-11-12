//! Read sets in the edge feed, at the dispatcher (docs/EDGE.md section 12, NATIVE-PROTOCOL.md
//! 4.1): the feature is advertised only by a node that keeps read sets for its feed, the request
//! flag is a flag only there, and a node without it answers every byte as before. What a feed
//! with read sets carries is tested against real checkpoints in the node lane
//! (`edge_readsets_tests.zig`).
const std = @import("std");
const store = @import("store");
const serve = @import("serve");
const proto = @import("proto.zig");
const dispatch = @import("dispatch.zig");
const edgefeed = @import("edgefeed.zig");
const dicts_mod = @import("dicts.zig");
const Rig = @import("certs_test.zig").Rig;

const bit_feed: u64 = @as(u64, 1) << dispatch.feature_edge_feed_bit;
const bit_read_sets: u64 = @as(u64, 1) << dispatch.feature_feed_read_sets_bit;

fn helloFeatures(a: std.mem.Allocator, d: *dispatch.Dispatcher) !u64 {
    var out: std.ArrayList(u8) = .empty;
    d.handle(a, .{ .method = .hello, .flags = 0, .body = "\x0czui-edge/0.1\x00\x00\x00" }, null, &out);
    const resp = proto.parseResponse(out.items).?;
    try std.testing.expectEqual(@as(u8, 0), resp.status);
    var r: proto.R = .{ .b = resp.body };
    _ = try r.str();
    _ = try r.int(u16);
    _ = try r.fixed(32);
    _ = try r.int(u64);
    _ = try r.int(u64);
    _ = try r.int(u64);
    return r.int(u64);
}

fn feedReq(seq: u64) [12]u8 {
    var b: [12]u8 = undefined;
    std.mem.writeInt(u64, b[0..8], seq, .little);
    std.mem.writeInt(u32, b[8..12], 0, .little);
    return b;
}

fn hasNone(_: *const anyopaque, _: *const store.Snapshot, _: u64) bool {
    return false;
}
fn loadedNone(_: *const anyopaque, _: *const store.Snapshot, _: *const [32]u8, _: u64) []const serve.objset.Ref {
    return &.{};
}

test "feed read sets: advertised and accepted only by a node that keeps them; every other node answers as before" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var ds = dicts_mod.Dicts.init(gpa);
    defer ds.deinit();
    var fd = edgefeed.Feeder.init(&ds);
    const body = feedReq(7);

    // no feed at all: neither bit, the method is unimplemented whatever the flags
    try std.testing.expectEqual(@as(u64, 0), (try helloFeatures(a, &rig.disp)) & (bit_feed | bit_read_sets));

    // the feed without read sets: bit 32 only; READ_SETS is an unknown flag (BAD_REQUEST), and a
    // request without it gets the answer it always got
    rig.disp.edge = &fd;
    try std.testing.expectEqual(bit_feed, (try helloFeatures(a, &rig.disp)) & (bit_feed | bit_read_sets));
    var plain: std.ArrayList(u8) = .empty;
    rig.disp.handle(a, .{ .method = .get_checkpoint_feed, .flags = proto.flag_zstd_ok, .body = &body }, null, &plain);
    try std.testing.expectEqual(@as(u8, 0), proto.parseResponse(plain.items).?.status);
    {
        var out: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .get_checkpoint_feed, .flags = proto.flag_zstd_ok | proto.flag_read_sets, .body = &body }, null, &out);
        try std.testing.expectEqual(@as(u8, @intFromEnum(proto.Code.bad_request)), proto.parseResponse(out.items).?.status);
    }

    // a node that keeps read sets for its feed: both bits; the flag is accepted on the feed and
    // nowhere else, and a request without the flag is answered with the same bytes as above
    rig.svc.read_sets = .{ .ctx = &rig, .has = hasNone };
    rig.svc.loaded = .{ .ctx = &rig, .get = loadedNone };
    fd.read_sets = &rig.svc;
    try std.testing.expectEqual(bit_feed | bit_read_sets, (try helloFeatures(a, &rig.disp)) & (bit_feed | bit_read_sets));
    {
        var out: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .get_checkpoint_feed, .flags = proto.flag_zstd_ok, .body = &body }, null, &out);
        try std.testing.expectEqualSlices(u8, plain.items, out.items);
        var with: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .get_checkpoint_feed, .flags = proto.flag_zstd_ok | proto.flag_read_sets, .body = &body }, null, &with);
        // (checkpoint 7 is not held: Option None either way)
        try std.testing.expectEqualSlices(u8, plain.items, with.items);
        var other: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .get_checkpoint, .flags = proto.flag_read_sets, .body = "\x01\x07\x00\x00\x00\x00\x00\x00\x00\x00" }, null, &other);
        try std.testing.expectEqual(@as(u8, @intFromEnum(proto.Code.bad_request)), proto.parseResponse(other.items).?.status);
        var unknown: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .get_checkpoint_feed, .flags = 0x8, .body = &body }, null, &unknown);
        try std.testing.expectEqual(@as(u8, @intFromEnum(proto.Code.bad_request)), proto.parseResponse(unknown.items).?.status);
    }

    // a client that cannot do without them is told so by a node that has none (hello minor 1)
    fd.read_sets = null;
    {
        var req: std.ArrayList(u8) = .empty;
        const w: proto.W = .{ .gpa = a, .out = &req };
        try w.str("zui-edge/0.2");
        try w.int(u16, 1);
        try w.u8_(0);
        try w.u8_(0);
        try w.int(u16, 0);
        try w.int(u64, bit_read_sets);
        var out: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .hello, .flags = 0, .body = req.items }, null, &out);
        try std.testing.expectEqual(@as(u8, @intFromEnum(proto.Code.feature_missing)), proto.parseResponse(out.items).?.status);
    }
}
