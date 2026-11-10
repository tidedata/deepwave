//! The ring of our own proposed blocks that SubscribeBlocks streams read (Rust: the tokio
//! broadcast channel behind `BroadcastedBlockStream`). Writers (the core thread) append; each
//! subscriber keeps a cursor and sleeps on the ring's monitor. A subscriber that falls more than
//! `capacity` blocks behind skips to the oldest block still held (Rust: broadcast `Lagged`).
//! Also the wire encoding of BlockRef (BCS: u32 LE round, u32 LE author, 32 digest bytes).
const std = @import("std");
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const types = consensus.types;
const mon = @import("mon.zig");

pub const ref_len = 40;

pub fn encodeRef(r: types.BlockRef) [ref_len]u8 {
    var b: [ref_len]u8 = undefined;
    std.mem.writeInt(u32, b[0..4], r.round, .little);
    std.mem.writeInt(u32, b[4..8], r.author, .little);
    b[8..40].* = r.digest;
    return b;
}

pub fn decodeRef(b: []const u8) ?types.BlockRef {
    if (b.len != ref_len) return null;
    return .{ .round = std.mem.readInt(u32, b[0..4], .little), .author = std.mem.readInt(u32, b[4..8], .little), .digest = b[8..40].* };
}

pub const Entry = struct {
    seq: u64,
    block: []u8,
    excluded: []types.BlockRef,
};

pub const Broadcaster = struct {
    gpa: Allocator,
    mu: mon.Monitor,
    ring: []Entry,
    /// Sequence number the next appended block gets; entries [next_seq - len, next_seq) are held.
    next_seq: u64 = 0,
    closed: bool = false,

    pub fn init(gpa: Allocator, io: std.Io, capacity: usize) Allocator.Error!Broadcaster {
        const ring = try gpa.alloc(Entry, capacity);
        for (ring) |*e| e.* = .{ .seq = 0, .block = &.{}, .excluded = &.{} };
        return .{ .gpa = gpa, .mu = mon.Monitor.init(io), .ring = ring };
    }

    pub fn deinit(b: *Broadcaster) void {
        for (b.ring) |e| {
            b.gpa.free(e.block);
            b.gpa.free(e.excluded);
        }
        b.gpa.free(b.ring);
    }

    pub fn append(b: *Broadcaster, serialized: []const u8, excluded: []const types.BlockRef) Allocator.Error!void {
        const blk = try b.gpa.dupe(u8, serialized);
        errdefer b.gpa.free(blk);
        const exc = try b.gpa.dupe(types.BlockRef, excluded);
        b.mu.lock();
        defer b.mu.unlock();
        const slot = &b.ring[@intCast(b.next_seq % b.ring.len)];
        b.gpa.free(slot.block);
        b.gpa.free(slot.excluded);
        slot.* = .{ .seq = b.next_seq, .block = blk, .excluded = exc };
        b.next_seq += 1;
        b.mu.broadcast();
    }

    pub fn close(b: *Broadcaster) void {
        b.mu.lock();
        b.closed = true;
        b.mu.broadcast();
        b.mu.unlock();
    }

    /// A cursor positioned at the next block to be appended.
    pub fn tail(b: *Broadcaster) u64 {
        b.mu.lock();
        defer b.mu.unlock();
        return b.next_seq;
    }

    pub const Item = struct { block: []u8, excluded: []types.BlockRef };

    /// The block at `*cursor` (copied into `arena`), advancing the cursor. Null on timeout or when
    /// closed.
    pub fn next(b: *Broadcaster, arena: Allocator, cursor: *u64, timeout_ns: u64) Allocator.Error!?Item {
        b.mu.lock();
        defer b.mu.unlock();
        const deadline = mon.monoNs(b.mu.io) +| timeout_ns;
        while (true) {
            if (b.closed) return null;
            const oldest = b.next_seq -| b.ring.len;
            if (cursor.* < oldest) cursor.* = oldest;
            if (cursor.* < b.next_seq) {
                const e = b.ring[@intCast(cursor.* % b.ring.len)];
                cursor.* += 1;
                return .{ .block = try arena.dupe(u8, e.block), .excluded = try arena.dupe(types.BlockRef, e.excluded) };
            }
            const now = mon.monoNs(b.mu.io);
            if (now >= deadline) return null;
            b.mu.waitNs(deadline - now);
        }
    }
};

test "ref encoding is 40 bytes BCS" {
    const r: types.BlockRef = .{ .round = 0x01020304, .author = 5, .digest = @splat(9) };
    const e = encodeRef(r);
    try std.testing.expectEqualSlices(u8, &.{ 4, 3, 2, 1, 5, 0, 0, 0, 9 }, e[0..9]);
    try std.testing.expect(decodeRef(&e).?.eql(r));
    try std.testing.expect(decodeRef(e[0..39]) == null);
}

test "broadcast ring: cursors, lag, close" {
    const gpa = std.testing.allocator;
    var b = try Broadcaster.init(gpa, std.testing.io, 2);
    defer b.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var cur = b.tail();
    try std.testing.expect((try b.next(arena, &cur, 1_000_000)) == null);
    try b.append("one", &.{});
    try b.append("two", &.{.{ .round = 1, .author = 2, .digest = @splat(0) }});
    try b.append("three", &.{});
    // capacity 2: the cursor at 0 lagged, skips to the oldest held ("two")
    var c0: u64 = 0;
    const it = (try b.next(arena, &c0, 0)).?;
    try std.testing.expectEqualStrings("two", it.block);
    try std.testing.expectEqual(@as(usize, 1), it.excluded.len);
    try std.testing.expectEqualStrings("three", (try b.next(arena, &c0, 0)).?.block);
    try std.testing.expect((try b.next(arena, &c0, 1_000_000)) == null);
    b.close();
}
