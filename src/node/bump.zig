//! A single-threaded bump allocator for one transaction's allocations in execute mode.
//!
//! Zig 0.17's `std.heap.ArenaAllocator` is thread-safe: every allocation is an atomic
//! read-modify-write on the current node (plus a compare-and-swap when the bump has to be undone),
//! and the node lane's perf of the executor thread put `ArenaAllocator.alloc` at 9 to 13% of it.
//! An executor thread owns its transaction arena outright, so here an allocation is a pointer bump
//! with no atomics. Chunks are kept across `reset` (up to a limit) and reused in order.
//!
//! Semantics match the arena's: `free` and `resize`/`remap` act in place only on the most recent
//! allocation (or shrink anything), everything else is released by `reset`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const Bump = struct {
    child: Allocator,
    /// Every chunk this allocator holds; `chunks[ci]` is the one being bumped.
    chunks: std.ArrayList([]u8) = .empty,
    ci: usize = 0,
    pos: usize = 0,
    /// Start of the most recent allocation in `chunks[ci]` (in-place resize and free).
    last: usize = 0,

    const min_chunk = 256 << 10;

    pub fn init(child: Allocator) Bump {
        return .{ .child = child };
    }

    pub fn deinit(b: *Bump) void {
        for (b.chunks.items) |c| b.child.free(c);
        b.chunks.deinit(b.child);
        b.* = undefined;
    }

    pub fn allocator(b: *Bump) Allocator {
        return .{ .ptr = b, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    /// Bytes of the chunks held.
    pub fn held(b: *const Bump) usize {
        var n: usize = 0;
        for (b.chunks.items) |c| n += c.len;
        return n;
    }

    /// Releases every allocation; keeps chunks up to `keep` bytes in all (the first ones).
    pub fn reset(b: *Bump, keep: usize) void {
        // Safe builds overwrite what was handed out, so a pointer kept past its reset reads
        // garbage at once (and differs from the certified effects) instead of stale bytes.
        if (std.debug.runtime_safety) for (b.chunks.items[0..@min(b.ci + 1, b.chunks.items.len)], 0..) |c, k| {
            @memset(c[0..if (k == b.ci) b.pos else c.len], 0xaa);
        };
        var kept: usize = 0;
        var n: usize = 0;
        for (b.chunks.items) |c| {
            if (kept + c.len > keep and n > 0) {
                b.child.free(c);
                continue;
            }
            kept += c.len;
            b.chunks.items[n] = c;
            n += 1;
        }
        b.chunks.items.len = n;
        b.ci = 0;
        b.pos = 0;
        b.last = 0;
    }

    fn alloc(ctx: *anyopaque, n: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        _ = ret_addr;
        const b: *Bump = @ptrCast(@alignCast(ctx));
        const a = alignment.toByteUnits();
        while (b.ci < b.chunks.items.len) {
            const c = b.chunks.items[b.ci];
            const base = @intFromPtr(c.ptr);
            const start = std.mem.alignForward(usize, base + b.pos, a) - base;
            if (start + n <= c.len) {
                b.last = start;
                b.pos = start + n;
                return c.ptr + start;
            }
            // The next kept chunk, if any (the rest of this one is wasted until the reset).
            if (b.ci + 1 >= b.chunks.items.len) break;
            b.ci += 1;
            b.pos = 0;
        }
        // A new chunk after the current one: at least twice the last one, and room for `n`.
        const prev = if (b.chunks.items.len > 0) b.chunks.items[b.chunks.items.len - 1].len else 0;
        const size = @max(min_chunk, prev * 2, n + a);
        const c = b.child.alloc(u8, size) catch return null;
        b.chunks.append(b.child, c) catch {
            b.child.free(c);
            return null;
        };
        b.ci = b.chunks.items.len - 1;
        const base = @intFromPtr(c.ptr);
        const start = std.mem.alignForward(usize, base, a) - base;
        b.last = start;
        b.pos = start + n;
        return c.ptr + start;
    }

    fn isLast(b: *const Bump, buf: []u8) bool {
        if (b.ci >= b.chunks.items.len) return false;
        const c = b.chunks.items[b.ci];
        return buf.ptr == c.ptr + b.last and b.last + buf.len == b.pos;
    }

    fn resize(ctx: *anyopaque, buf: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
        _ = alignment;
        _ = ret_addr;
        const b: *Bump = @ptrCast(@alignCast(ctx));
        if (!b.isLast(buf)) return new_len <= buf.len;
        const c = b.chunks.items[b.ci];
        if (b.last + new_len > c.len) return false;
        b.pos = b.last + new_len;
        return true;
    }

    fn remap(ctx: *anyopaque, buf: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        return if (resize(ctx, buf, alignment, new_len, ret_addr)) buf.ptr else null;
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: Alignment, ret_addr: usize) void {
        _ = alignment;
        _ = ret_addr;
        const b: *Bump = @ptrCast(@alignCast(ctx));
        if (b.isLast(buf)) b.pos = b.last;
    }
};

test "bump: aligned, in-place growth of the last allocation, reuse after reset" {
    var b: Bump = .init(std.testing.allocator);
    defer b.deinit();
    const a = b.allocator();
    const x = try a.alloc(u8, 3);
    const y = try a.alloc(u64, 2);
    try std.testing.expect(@intFromPtr(y.ptr) % 8 == 0);
    try std.testing.expect(a.resize(y, 4));
    try std.testing.expect(!a.resize(x, 100));
    var list: std.ArrayList(u32) = .empty;
    for (0..100_000) |i| try list.append(a, @intCast(i));
    for (list.items, 0..) |v, i| try std.testing.expectEqual(@as(u32, @intCast(i)), v);
    const big = try a.alloc(u8, 4 << 20);
    @memset(big, 7);
    b.reset(1 << 20);
    try std.testing.expect(b.chunks.items.len >= 1);
    const z = try a.alloc(u8, 10);
    try std.testing.expectEqual(b.chunks.items[0].ptr, z.ptr);
}
