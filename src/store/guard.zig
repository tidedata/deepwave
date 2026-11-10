//! Use-after-release guard (`Config.uaf_guard`, `ZUI_UAF_GUARD=1`; on in every store opened by
//! a Debug or ReleaseSafe test build).
//!
//! Store reads are zero-copy: a slice points into a segment mapping or a decoded chunk, valid
//! only while the snapshot that read it lives. Once its grace period ends the store unmaps the
//! segment view or frees the chunk, and the address range is soon reused by a new mapping or
//! allocation, so a stale slice usually reads someone else's bytes instead of faulting. With the
//! guard on, a released range is never reused: it is replaced by an inaccessible reservation
//! (PROT_NONE, its pages given back), so the first touch through a stale slice faults at the
//! read, with the reader's stack, instead of rendering garbage or crashing somewhere else.
//!
//! Costs: the released address space stays reserved (cheap on 64-bit, no memory), and chunk
//! buffers are page rounded. For tests, stress runs and shadow rehearsals, not production.
const std = @import("std");
const builtin = @import("builtin");

const page = std.heap.page_size_min;

/// On by default where a fault is the wanted outcome: test binaries with runtime safety.
pub const default_on = builtin.is_test and std.debug.runtime_safety;

/// `ZUI_UAF_GUARD=1` turns the guard on in any build.
pub fn fromEnv() bool {
    const v = std.c.getenv("ZUI_UAF_GUARD") orelse return false;
    return v[0] == '1';
}

/// Replaces `[ptr, ptr+len)` (page aligned, rounded up) with an inaccessible reservation.
pub fn poisonRange(ptr: [*]const u8, len: usize) void {
    const n = std.mem.alignForward(usize, @max(len, 1), page);
    const p: [*]align(page) u8 = @ptrCast(@alignCast(@constCast(ptr)));
    const m = std.posix.mmap(p, n, .{}, .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = true }, -1, 0) catch {
        // Could not swap the mapping: drop it (the plain unmap behaviour).
        std.posix.munmap(p[0..n]);
        return;
    };
    std.debug.assert(m.ptr == p);
}

/// Page allocator whose `free` poisons instead of unmapping (decoded chunks and their items).
pub const allocator: std.mem.Allocator = .{ .ptr = undefined, .vtable = &vtable };

const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

fn alloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
    _ = ra;
    if (alignment.toByteUnits() > page) return null;
    const n = std.mem.alignForward(usize, @max(len, 1), page);
    const m = std.posix.mmap(null, n, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0) catch return null;
    return m.ptr;
}

fn resize(_: *anyopaque, mem: []u8, _: std.mem.Alignment, new_len: usize, _: usize) bool {
    return std.mem.alignForward(usize, @max(new_len, 1), page) <= std.mem.alignForward(usize, @max(mem.len, 1), page);
}

fn remap(ctx: *anyopaque, mem: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
    return if (resize(ctx, mem, a, new_len, ra)) mem.ptr else null;
}

fn free(_: *anyopaque, mem: []u8, _: std.mem.Alignment, _: usize) void {
    poisonRange(mem.ptr, mem.len);
}

test "guard allocator round trip" {
    const a = allocator;
    const b = try a.alloc(u8, 5000);
    @memset(b, 7);
    try std.testing.expect(b.len == 5000 and b[4999] == 7);
    const it = try a.create(u64);
    it.* = 3;
    a.destroy(it);
    a.free(b);
}
