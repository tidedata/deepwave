//! The archive record of a checkpoint (`binpb-done/<seq>.binpb.zst`, a sui.rpc.v2 Checkpoint):
//! per transaction the `unchanged_loaded_runtime_objects` of its effects (objects the
//! transaction read at run time without changing them), and the checkpoint's object set, which
//! carries their bytes. Replay answers read-only runtime loads from them.
const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Ref = struct { id: [32]u8, version: u64 };

pub const Archive = struct {
    /// Raw BCS `Object` bytes of the object set.
    objects: []const []const u8,
    /// Per transaction, in checkpoint order.
    loaded: []const []const Ref,
};

/// A protobuf wire reader: fields with their number, varint value or length-delimited data.
const Reader = struct {
    b: []const u8,
    at: usize = 0,

    const Field = struct { number: u64, varint: u64 = 0, data: []const u8 = &.{} };

    fn varint(r: *Reader) !u64 {
        var x: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            if (r.at >= r.b.len) return error.Truncated;
            const c = r.b[r.at];
            r.at += 1;
            if (shift >= 64) return error.Overlong;
            x |= @as(u64, c & 0x7f) << @intCast(shift);
            if (c & 0x80 == 0) return x;
            shift += 7;
        }
    }

    fn next(r: *Reader) !?Field {
        if (r.at >= r.b.len) return null;
        const key = try r.varint();
        var f: Field = .{ .number = key >> 3 };
        switch (key & 7) {
            0 => f.varint = try r.varint(),
            1 => {
                if (r.at + 8 > r.b.len) return error.Truncated;
                r.at += 8;
            },
            2 => {
                const n = try r.varint();
                if (n > r.b.len - r.at) return error.Truncated;
                f.data = r.b[r.at..][0..n];
                r.at += n;
            },
            5 => {
                if (r.at + 4 > r.b.len) return error.Truncated;
                r.at += 4;
            },
            else => return error.WireType,
        }
        return f;
    }
};

/// Parses a decompressed archive checkpoint with `tx_count` transactions.
pub fn parse(arena: Allocator, dec: []const u8, tx_count: usize) !Archive {
    var objects: std.ArrayList([]const u8) = .empty;
    const loaded = try arena.alloc([]const Ref, tx_count);
    @memset(loaded, &.{});
    var rd: Reader = .{ .b = dec };
    var ti: usize = 0;
    while (try rd.next()) |f| {
        if (f.number == 7) {
            var sr: Reader = .{ .b = f.data };
            while (try sr.next()) |of| if (of.number == 1) {
                var orr: Reader = .{ .b = of.data };
                while (try orr.next()) |bf| if (bf.number == 1) {
                    var br: Reader = .{ .b = bf.data };
                    while (try br.next()) |vf| if (vf.number == 2) try objects.append(arena, vf.data);
                };
            };
        } else if (f.number == 6) {
            if (ti >= tx_count) return error.TxCountMismatch;
            var list: std.ArrayList(Ref) = .empty;
            var tr: Reader = .{ .b = f.data };
            while (try tr.next()) |tf| if (tf.number == 4) {
                var er: Reader = .{ .b = tf.data };
                while (try er.next()) |ef| if (ef.number == 15) {
                    var ref: Ref = .{ .id = undefined, .version = 0 };
                    var have_id = false;
                    var rr: Reader = .{ .b = ef.data };
                    while (try rr.next()) |x| switch (x.number) {
                        1 => {
                            const hex = if (std.mem.startsWith(u8, x.data, "0x")) x.data[2..] else x.data;
                            if (hex.len != 64) return error.BadObjectId;
                            _ = try std.fmt.hexToBytes(&ref.id, hex);
                            have_id = true;
                        },
                        2 => ref.version = x.varint,
                        else => {},
                    };
                    if (!have_id) return error.BadObjectId;
                    try list.append(arena, ref);
                };
            };
            loaded[ti] = list.items;
            ti += 1;
        }
    }
    if (ti != tx_count) return error.TxCountMismatch;
    return .{ .objects = objects.items, .loaded = loaded };
}

test "protobuf varint and fields" {
    // field 2 varint 150, field 1 bytes "ab"
    var r: Reader = .{ .b = &.{ 0x10, 0x96, 0x01, 0x0a, 0x02, 'a', 'b' } };
    const f1 = (try r.next()).?;
    try std.testing.expectEqual(@as(u64, 2), f1.number);
    try std.testing.expectEqual(@as(u64, 150), f1.varint);
    const f2 = (try r.next()).?;
    try std.testing.expectEqual(@as(u64, 1), f2.number);
    try std.testing.expectEqualStrings("ab", f2.data);
    try std.testing.expect((try r.next()) == null);
}
