//! Subscription frame watermarks, byte-exact with sui-rpc-api 1.83.1:
//! `transaction_item_watermark` / `transaction_tick_watermark` / `event_item_watermark` /
//! `event_tick_watermark` (grpc/v2/subscription_service.rs) over `item_watermark` /
//! `boundary_watermark` (ledger_history/watermark.rs), `LedgerPoint` (ledger_point.rs) and the
//! `CursorToken` encoding of sui-rpc-cursor (lib.rs + cursor.proto), plus the covered-checkpoint
//! bookkeeping with `QueryOptions::subscription()` (ascending, no cursor bounds).
//!
//! Wire shapes (prost encodes fields in tag order):
//!   Watermark      { optional bytes cursor = 1; optional uint64 checkpoint = 2;
//!                    optional LedgerPosition cursor_position = 4 }
//!   LedgerPosition { optional uint64 checkpoint = 1; optional uint64 transaction_index = 2;
//!                    optional uint32 event_index = 3 }   (only the lane's coordinates are set)
//!   CursorToken    { CursorKind kind = 5; oneof position { Checkpoints = 6; Transactions = 7;
//!                    Events = 8 }; PublicPosition public_position = 9 }
//!   TransactionsPosition { optional uint64 checkpoint = 1; optional uint64 tx_seq = 2 }
//!   EventsPosition { optional uint64 checkpoint = 1; optional uint64 tx_seq = 2;
//!                    optional uint32 event_index = 3 }
//!   PublicPosition { uint64 checkpoint = 1; uint64 transaction_index = 2; uint32 event_index = 3 }
//!                    (proto3 scalars: zero values are not written)
const std = @import("std");
const proto = @import("proto.zig");

pub const Error = proto.Error;

const Kind = enum(u8) { item = 1, boundary = 2 };

/// The cursor's private coordinates: `Position::Transactions` or `Position::Events`.
const Lane = union(enum) {
    transactions: struct { checkpoint: u64, tx_seq: u64 },
    events: struct { checkpoint: u64, tx_seq: u64, event_index: u32 },
};

/// `LedgerPoint`: the boundary just before the item keyed (checkpoint, tx index, event index).
const Point = struct { checkpoint: u64, transaction_index: u64 = 0, event_index: u32 = 0 };

/// `CursorToken::encode` with a public position (every transaction and event cursor a
/// subscription mints carries one). At most 2 + 2+33 + 2+18 bytes.
fn encodeCursor(buf: *[64]u8, kind: Kind, lane: Lane, public: Point) Error![]const u8 {
    var w = proto.Writer.init(buf);
    try w.uint(5, @intFromEnum(kind));
    switch (lane) {
        .transactions => |p| {
            const m = try w.begin(7, 4);
            try w.uint(1, p.checkpoint);
            try w.uint(2, p.tx_seq);
            try w.end(m);
        },
        .events => |p| {
            const m = try w.begin(8, 6);
            try w.uint(1, p.checkpoint);
            try w.uint(2, p.tx_seq);
            try w.uint(3, p.event_index);
            try w.end(m);
        },
    }
    // PublicPosition: `LedgerPoint::public_position`; a transaction cursor carries no event index
    const ev: u32 = switch (lane) {
        .transactions => 0,
        .events => public.event_index,
    };
    const m = try w.begin(9, 4);
    if (public.checkpoint != 0) try w.uint(1, public.checkpoint);
    if (public.transaction_index != 0) try w.uint(2, public.transaction_index);
    if (ev != 0) try w.uint(3, ev);
    try w.end(m);
    return w.bytesWritten();
}

/// `cursor_watermark`: Watermark { cursor, checkpoint = boundary, cursor_position }.
fn writeWatermark(w: *proto.Writer, field: u32, kind: Kind, lane: Lane, cursor_point: Point, resume_at: Point, boundary: ?u64) Error!void {
    var cbuf: [64]u8 = undefined;
    const cursor = try encodeCursor(&cbuf, kind, lane, cursor_point);
    const m = try w.begin(field, cursor.len + 2 + 11 + 2 + 23);
    try w.bytes(1, cursor);
    if (boundary) |b| try w.uint(2, b);
    // LedgerPoint::to_proto: only the coordinates of the cursor's lane
    const pm = try w.begin(4, 8);
    try w.uint(1, resume_at.checkpoint);
    try w.uint(2, resume_at.transaction_index);
    switch (lane) {
        .transactions => {},
        .events => try w.uint(3, resume_at.event_index),
    }
    try w.end(pm);
    try w.end(m);
}

/// `transaction_item_watermark(cp, tx_lo, tx_index, boundary)`: an Item cursor at
/// `Transactions { cp, tx_lo + tx_index }` carrying the item's key; the frame resumes right
/// after the item (`item_resume` ascending: transaction index + 1).
pub fn writeTxItem(w: *proto.Writer, field: u32, cp: u64, tx_lo: u64, tx_index: u64, boundary: ?u64) Error!void {
    const key: Point = .{ .checkpoint = cp, .transaction_index = tx_index };
    try writeWatermark(w, field, .item, .{ .transactions = .{ .checkpoint = cp, .tx_seq = tx_lo +% tx_index } }, key, .{
        .checkpoint = cp,
        .transaction_index = tx_index +| 1,
    }, boundary);
}

/// `transaction_tick_watermark(cp, tx_hi, boundary)`: a Boundary cursor at
/// `Transactions { cp + 1, tx_hi }`, both the cursor's public position and the frame's
/// resume point being the start of checkpoint `cp + 1`.
pub fn writeTxTick(w: *proto.Writer, field: u32, cp: u64, tx_hi: u64, boundary: ?u64) Error!void {
    const start: Point = .{ .checkpoint = cp +% 1 };
    try writeWatermark(w, field, .boundary, .{ .transactions = .{ .checkpoint = cp +% 1, .tx_seq = tx_hi } }, start, start, boundary);
}

/// `event_item_watermark(cp, tx_lo, tx_index, event_index, boundary)`.
pub fn writeEventItem(w: *proto.Writer, field: u32, cp: u64, tx_lo: u64, tx_index: u64, event_index: u32, boundary: ?u64) Error!void {
    const key: Point = .{ .checkpoint = cp, .transaction_index = tx_index, .event_index = event_index };
    try writeWatermark(w, field, .item, .{ .events = .{ .checkpoint = cp, .tx_seq = tx_lo +% tx_index, .event_index = event_index } }, key, .{
        .checkpoint = cp,
        .transaction_index = tx_index,
        .event_index = event_index +| 1,
    }, boundary);
}

/// `event_tick_watermark(cp, tx_hi, boundary)`.
pub fn writeEventTick(w: *proto.Writer, field: u32, cp: u64, tx_hi: u64, boundary: ?u64) Error!void {
    const start: Point = .{ .checkpoint = cp +% 1 };
    try writeWatermark(w, field, .boundary, .{ .events = .{ .checkpoint = cp +% 1, .tx_seq = tx_hi, .event_index = 0 } }, start, start, boundary);
}

/// `merge_covered_checkpoint_bound(boundary, cp, &QueryOptions::subscription())`: ascending, so
/// the bound advances by max.
pub fn mergeCovered(boundary: ?u64, cp: u64) ?u64 {
    return if (boundary) |b| @max(b, cp) else cp;
}

/// `advance_covered_bound_before_checkpoint(boundary, cp, entry_cp, &subscription())`: an item
/// at `cp` proves `cp - 1` covered, if that is still inside the window (`>= entry_cp`).
pub fn advanceBeforeCheckpoint(boundary: ?u64, cp: u64, entry_cp: u64) ?u64 {
    if (cp == 0) return boundary;
    const candidate = cp - 1;
    if (candidate < entry_cp) return boundary;
    return mergeCovered(boundary, candidate);
}

/// `record_watermark_tick_coverage`: the first tick names the checkpoint right before the entry
/// checkpoint; every tick names a fully processed checkpoint.
pub fn recordTick(boundary: *?u64, entry_cp: *?u64, cp: u64) void {
    if (entry_cp.* == null) entry_cp.* = cp +| 1;
    boundary.* = mergeCovered(boundary.*, cp);
}

/// The per-stream state of a transaction or event subscription in subscription_service.rs.
pub const Coverage = struct {
    boundary: ?u64 = null,
    entry_cp: ?u64 = null,

    /// Before each item of a matched checkpoint `cp` (`entry_checkpoint.get_or_insert(cp)`).
    pub fn item(c: *Coverage, cp: u64) ?u64 {
        if (c.entry_cp == null) c.entry_cp = cp;
        c.boundary = advanceBeforeCheckpoint(c.boundary, cp, c.entry_cp.?);
        return c.boundary;
    }

    /// On a progress tick after checkpoint `cp`.
    pub fn tick(c: *Coverage, cp: u64) ?u64 {
        recordTick(&c.boundary, &c.entry_cp, cp);
        return c.boundary;
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

/// The Watermark body written as field 1 of an otherwise empty parent.
fn body(buf: []u8, comptime f: anytype, args: anytype) ![]const u8 {
    var w = proto.Writer.init(buf);
    try @call(.auto, f, .{&w} ++ .{@as(u32, 1)} ++ args);
    var r = proto.Reader.init(w.bytesWritten());
    const fld = (try r.next()).?;
    try testing.expectEqual(@as(u32, 1), fld.number);
    try testing.expect((try r.next()) == null);
    return fld.data;
}

const Parsed = struct { cursor: []const u8 = "", checkpoint: ?u64 = null, pos: [3]?u64 = .{ null, null, null } };

fn parse(b: []const u8) !Parsed {
    var p: Parsed = .{};
    var r = proto.Reader.init(b);
    while (try r.next()) |f| switch (f.number) {
        1 => p.cursor = f.data,
        2 => p.checkpoint = f.varint,
        4 => {
            var q = proto.Reader.init(f.data);
            while (try q.next()) |g| p.pos[g.number - 1] = g.varint;
        },
        else => return error.Unexpected,
    };
    return p;
}

/// `(position.checkpoint(), position.transaction_index(), position.event_index())`: unset is 0.
fn triple(p: Parsed) [3]u64 {
    return .{ p.pos[0] orelse 0, p.pos[1] orelse 0, p.pos[2] orelse 0 };
}

test "initial_watermark_tick_covers_checkpoint_before_entry" {
    var cov: Coverage = .{};
    const boundary = cov.tick(41);
    try testing.expectEqual(@as(?u64, 42), cov.entry_cp);
    var buf: [128]u8 = undefined;
    const b = try body(&buf, writeTxTick, .{ @as(u64, 41), @as(u64, 100), boundary });
    const p = try parse(b);
    try testing.expectEqual(@as(?u64, 41), p.checkpoint);
    // CursorToken::boundary(Transactions { 42, 100 }).with_public_position({42, 0, 0})
    try testing.expectEqualSlices(u8, &.{ 0x28, 0x02, 0x3a, 0x04, 0x08, 0x2a, 0x10, 0x64, 0x4a, 0x02, 0x08, 0x2a }, p.cursor);
    // LedgerPoint::checkpoint_start(42).to_proto(Transactions): checkpoint and transaction_index
    try testing.expectEqualSlices(u8, &.{
        0x0a, 0x0c, 0x28, 0x02, 0x3a, 0x04, 0x08, 0x2a, 0x10, 0x64, 0x4a, 0x02, 0x08, 0x2a,
        0x10, 0x29, 0x22, 0x04, 0x08, 0x2a, 0x10, 0x00,
    }, b);
}

test "subscription_frames_carry_ledger_positions" {
    // Checkpoint 7 holds transactions 30..33; checkpoint 8 transactions 33..35.
    var bufs: [8][160]u8 = undefined;
    const tx = [_]Parsed{
        try parse(try body(&bufs[0], writeTxItem, .{ @as(u64, 7), @as(u64, 30), @as(u64, 0), @as(?u64, null) })),
        try parse(try body(&bufs[1], writeTxItem, .{ @as(u64, 7), @as(u64, 30), @as(u64, 2), @as(?u64, null) })),
        try parse(try body(&bufs[2], writeTxTick, .{ @as(u64, 7), @as(u64, 33), @as(?u64, 7) })),
        try parse(try body(&bufs[3], writeTxTick, .{ @as(u64, 8), @as(u64, 35), @as(?u64, 8) })),
    };
    const ev = [_]Parsed{
        try parse(try body(&bufs[4], writeEventItem, .{ @as(u64, 7), @as(u64, 30), @as(u64, 1), @as(u32, 0), @as(?u64, null) })),
        try parse(try body(&bufs[5], writeEventItem, .{ @as(u64, 7), @as(u64, 30), @as(u64, 1), @as(u32, 1), @as(?u64, null) })),
        try parse(try body(&bufs[6], writeEventTick, .{ @as(u64, 7), @as(u64, 33), @as(?u64, 7) })),
        try parse(try body(&bufs[7], writeEventItem, .{ @as(u64, 9), @as(u64, 35), @as(u64, 0), @as(u32, 3), @as(?u64, 8) })),
    };
    const want_tx = [_][3]u64{ .{ 7, 1, 0 }, .{ 7, 3, 0 }, .{ 8, 0, 0 }, .{ 9, 0, 0 } };
    const want_ev = [_][3]u64{ .{ 7, 1, 1 }, .{ 7, 1, 2 }, .{ 8, 0, 0 }, .{ 9, 0, 4 } };
    for (tx, want_tx) |p, want| try testing.expectEqual(want, triple(p));
    for (ev, want_ev) |p, want| try testing.expectEqual(want, triple(p));
    // transaction lanes never set event_index; event lanes always do
    for (tx) |p| try testing.expect(p.pos[2] == null and p.pos[1] != null);
    for (ev) |p| try testing.expect(p.pos[2] != null);
    try testing.expectEqual(@as(?u64, null), tx[0].checkpoint);
    try testing.expectEqual(@as(?u64, 8), ev[3].checkpoint);

    // CursorToken::item(Transactions { 7, 30 }).with_public_position({7, 0, 0})
    try testing.expectEqualSlices(u8, &.{ 0x28, 0x01, 0x3a, 0x04, 0x08, 0x07, 0x10, 0x1e, 0x4a, 0x02, 0x08, 0x07 }, tx[0].cursor);
    // CursorToken::item(Events { 7, 31, 1 }).with_public_position({7, 1, 1})
    try testing.expectEqualSlices(u8, &.{ 0x28, 0x01, 0x42, 0x06, 0x08, 0x07, 0x10, 0x1f, 0x18, 0x01, 0x4a, 0x06, 0x08, 0x07, 0x10, 0x01, 0x18, 0x01 }, ev[1].cursor);
    // CursorToken::boundary(Events { 8, 33, 0 }).with_public_position({8, 0, 0})
    try testing.expectEqualSlices(u8, &.{ 0x28, 0x02, 0x42, 0x06, 0x08, 0x08, 0x10, 0x21, 0x18, 0x00, 0x4a, 0x02, 0x08, 0x08 }, ev[2].cursor);
    // a transaction item at index 0 of checkpoint 0: the public position is present but empty
    var b0: [96]u8 = undefined;
    const g = try parse(try body(&b0, writeTxItem, .{ @as(u64, 0), @as(u64, 0), @as(u64, 0), @as(?u64, null) }));
    try testing.expectEqualSlices(u8, &.{ 0x28, 0x01, 0x3a, 0x04, 0x08, 0x00, 0x10, 0x00, 0x4a, 0x00 }, g.cursor);
}

test "covered bound bookkeeping (QueryOptions::subscription)" {
    // advance: candidate cp - 1, only inside the window, merged by max
    try testing.expectEqual(@as(?u64, null), advanceBeforeCheckpoint(null, 10, 10));
    try testing.expectEqual(@as(?u64, 10), advanceBeforeCheckpoint(null, 11, 10));
    try testing.expectEqual(@as(?u64, 12), advanceBeforeCheckpoint(12, 11, 10));
    try testing.expectEqual(@as(?u64, 5), advanceBeforeCheckpoint(5, 0, 0));
    try testing.expectEqual(@as(?u64, 7), mergeCovered(null, 7));
    try testing.expectEqual(@as(?u64, 9), mergeCovered(9, 7));
    // a stream: first match at 10 (entry 10, no bound yet), tick after 10, match at 12
    var c: Coverage = .{};
    try testing.expectEqual(@as(?u64, null), c.item(10));
    try testing.expectEqual(@as(?u64, 10), c.tick(10));
    try testing.expectEqual(@as(?u64, 11), c.item(12));
    try testing.expectEqual(@as(?u64, 10), c.entry_cp);
}
