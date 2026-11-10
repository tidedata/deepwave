//! Grace periods for lock-free readers (two-counter SRCU style).
//!
//! A reader `enter`s before touching any shared mapping or table and `exit`s when done; the
//! writer `retire`s an object only after unpublishing it, and `poll` reclaims it once every
//! reader that could still hold it has exited. Readers never block and never reclaim. Unlike a
//! single reader count, a steady stream of short readers cannot starve reclamation: new readers
//! count on the other parity, so the old parity drains as soon as its readers finish.
const std = @import("std");

const Counter = struct {
    v: std.atomic.Value(u64) align(std.atomic.cache_line) = .init(0),
};

pub fn Rcu(comptime Item: type) type {
    return struct {
        const Self = @This();

        gen: std.atomic.Value(u64) align(std.atomic.cache_line) = .init(0),
        counts: [2]Counter = .{ .{}, .{} },
        // ---- writer only
        pending: std.ArrayList(Item) = .empty,
        grace: std.ArrayList(Item) = .empty,
        grace_parity: u1 = 0,

        pub fn enter(r: *Self) u1 {
            while (true) {
                const g = r.gen.load(.seq_cst);
                const p: u1 = @truncate(g);
                _ = r.counts[p].v.fetchAdd(1, .seq_cst);
                // A writer that flipped `gen` in between may already have seen this parity
                // drained; count on the new parity instead.
                if (r.gen.load(.seq_cst) == g) return p;
                _ = r.counts[p].v.fetchSub(1, .seq_cst);
            }
        }

        pub fn exit(r: *Self, p: u1) void {
            _ = r.counts[p].v.fetchSub(1, .seq_cst);
        }

        /// Writer: `item` is no longer reachable by new readers.
        pub fn retire(r: *Self, gpa: std.mem.Allocator, item: Item) !void {
            try r.pending.append(gpa, item);
        }

        /// Writer: reclaims what is safe and starts a grace period for newly retired items.
        pub fn poll(r: *Self, ctx: anytype, comptime reclaim: fn (@TypeOf(ctx), Item) void) void {
            if (r.grace.items.len > 0) {
                if (r.counts[r.grace_parity].v.load(.seq_cst) != 0) return;
                for (r.grace.items) |it| reclaim(ctx, it);
                r.grace.clearRetainingCapacity();
            }
            if (r.pending.items.len == 0) return;
            const g = r.gen.load(.seq_cst);
            r.grace_parity = @truncate(g);
            r.gen.store(g + 1, .seq_cst);
            std.mem.swap(std.ArrayList(Item), &r.pending, &r.grace);
            if (r.counts[r.grace_parity].v.load(.seq_cst) == 0) {
                for (r.grace.items) |it| reclaim(ctx, it);
                r.grace.clearRetainingCapacity();
            }
        }

        /// Any thread, without the writer's exclusion: a hint only.
        pub fn idleRacy(r: *const Self) bool {
            return @atomicLoad(usize, &r.pending.items.len, .monotonic) == 0 and @atomicLoad(usize, &r.grace.items.len, .monotonic) == 0;
        }

        pub fn idle(r: *const Self) bool {
            return r.pending.items.len == 0 and r.grace.items.len == 0;
        }

        /// No readers may exist: reclaims everything.
        pub fn drainAll(r: *Self, ctx: anytype, comptime reclaim: fn (@TypeOf(ctx), Item) void) void {
            for (r.grace.items) |it| reclaim(ctx, it);
            for (r.pending.items) |it| reclaim(ctx, it);
            r.grace.clearRetainingCapacity();
            r.pending.clearRetainingCapacity();
        }

        pub fn deinit(r: *Self, gpa: std.mem.Allocator) void {
            r.pending.deinit(gpa);
            r.grace.deinit(gpa);
        }
    };
}

test "rcu defers reclamation past readers" {
    const gpa = std.testing.allocator;
    var r: Rcu(u32) = .{};
    defer r.deinit(gpa);
    var freed: std.ArrayList(u32) = .empty;
    defer freed.deinit(gpa);
    const Ctx = struct {
        list: *std.ArrayList(u32),
        fn f(c: @This(), x: u32) void {
            c.list.append(std.testing.allocator, x) catch unreachable;
        }
    };
    const ctx: Ctx = .{ .list = &freed };
    const p = r.enter();
    try r.retire(gpa, 1);
    r.poll(ctx, Ctx.f);
    try std.testing.expectEqual(@as(usize, 0), freed.items.len);
    // a new reader does not hold back the old grace period
    const q = r.enter();
    try r.retire(gpa, 2);
    r.poll(ctx, Ctx.f);
    try std.testing.expectEqual(@as(usize, 0), freed.items.len);
    r.exit(p);
    r.poll(ctx, Ctx.f);
    try std.testing.expectEqualSlices(u32, &.{1}, freed.items);
    r.poll(ctx, Ctx.f); // item 2 waits for q
    try std.testing.expectEqualSlices(u32, &.{1}, freed.items);
    r.exit(q);
    r.poll(ctx, Ctx.f);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2 }, freed.items);
    try std.testing.expect(r.idle());
}
