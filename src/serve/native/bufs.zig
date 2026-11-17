//! Byte buffers the worker pools hand back and take again instead of allocating and freeing one
//! per job. The node's allocator maps every block of 128 KiB or more on its own (main.zig
//! `nodeAllocator`, M_MMAP_THRESHOLD): a fresh response buffer per job was an mmap and a munmap
//! per job, and each takes the process's mmap lock for writing, which every page fault of every
//! other thread then waits behind. A kept buffer keeps its pages.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Bufs = struct {
    mu: Io.Mutex = .init,
    free: std.ArrayList(std.ArrayList(u8)) = .empty,
    /// Bytes of capacity kept in `free`; a buffer given back past `keep_bytes` is freed.
    kept: usize = 0,
    keep_bytes: usize = 64 << 20,

    pub fn deinit(b: *Bufs, gpa: Allocator) void {
        for (b.free.items) |*x| x.deinit(gpa);
        b.free.deinit(gpa);
        b.* = undefined;
    }

    /// An empty buffer, with the capacity of one given back if there is one.
    pub fn take(b: *Bufs, io: Io) std.ArrayList(u8) {
        b.mu.lockUncancelable(io);
        defer b.mu.unlock(io);
        var x = b.free.pop() orelse return .empty;
        b.kept -= x.capacity;
        x.clearRetainingCapacity();
        return x;
    }

    pub fn give(b: *Bufs, gpa: Allocator, io: Io, x: *std.ArrayList(u8)) void {
        defer x.* = .empty;
        if (x.capacity == 0) return;
        b.mu.lockUncancelable(io);
        defer b.mu.unlock(io);
        if (b.kept + x.capacity > b.keep_bytes) return x.deinit(gpa);
        b.free.append(gpa, x.*) catch return x.deinit(gpa);
        b.kept += x.capacity;
    }
};

test "a buffer given back is taken again with its capacity" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var b: Bufs = .{};
    defer b.deinit(gpa);
    var x = b.take(io);
    try x.appendNTimes(gpa, 7, 300 << 10);
    const p = x.items.ptr;
    b.give(gpa, io, &x);
    try std.testing.expectEqual(@as(usize, 0), x.capacity);
    var y = b.take(io);
    defer y.deinit(gpa);
    try std.testing.expectEqual(p, y.items.ptr);
    try std.testing.expectEqual(@as(usize, 0), y.items.len);
    try std.testing.expect(y.capacity >= 300 << 10);
}

test "past keep_bytes a buffer is freed" {
    const gpa = std.testing.allocator;
    var b: Bufs = .{ .keep_bytes = 1000 };
    defer b.deinit(gpa);
    var x: std.ArrayList(u8) = .empty;
    try x.appendNTimes(gpa, 1, 4096);
    b.give(gpa, std.testing.io, &x);
    try std.testing.expectEqual(@as(usize, 0), b.free.items.len);
}
