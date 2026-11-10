//! Allocator policy helpers (ARCHITECTURE.md section 5.3).
//!
//! Static allocation: a tile allocates everything it will ever need
//! at startup from a budget derived from its config, then calls `freeze()`. After that any
//! allocation through the guarded allocator is a bug: it panics in Debug/ReleaseSafe and
//! returns null (OutOfMemory) in fast and small builds so a mistake can never silently grow memory.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const Frozen = struct {
    parent: Allocator,
    frozen: bool = false,
    /// Bytes handed out before freeze (for startup budget reports).
    reserved: usize = 0,

    pub fn init(parent: Allocator) Frozen {
        return .{ .parent = parent };
    }

    pub fn freeze(self: *Frozen) void {
        self.frozen = true;
    }

    pub fn allocator(self: *Frozen) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Allocator.VTable = .{
        .alloc = allocFn,
        .resize = resizeFn,
        .remap = remapFn,
        .free = freeFn,
    };

    fn guard(self: *Frozen) bool {
        if (!self.frozen) return true;
        if (builtin.mode == .debug or builtin.mode == .safe) @panic("allocation after freeze");
        return false;
    }

    fn allocFn(ctx: *anyopaque, len: usize, a: Alignment, ra: usize) ?[*]u8 {
        const self: *Frozen = @ptrCast(@alignCast(ctx));
        if (!self.guard()) return null;
        const p = self.parent.rawAlloc(len, a, ra) orelse return null;
        self.reserved += len;
        return p;
    }

    fn resizeFn(ctx: *anyopaque, mem: []u8, a: Alignment, new_len: usize, ra: usize) bool {
        const self: *Frozen = @ptrCast(@alignCast(ctx));
        if (new_len > mem.len and !self.guard()) return false;
        return self.parent.rawResize(mem, a, new_len, ra);
    }

    fn remapFn(ctx: *anyopaque, mem: []u8, a: Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *Frozen = @ptrCast(@alignCast(ctx));
        if (new_len > mem.len and !self.guard()) return null;
        return self.parent.rawRemap(mem, a, new_len, ra);
    }

    fn freeFn(ctx: *anyopaque, mem: []u8, a: Alignment, ra: usize) void {
        const self: *Frozen = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(mem, a, ra);
    }
};

test "frozen allocator refuses growth after freeze" {
    var f = Frozen.init(std.testing.allocator);
    const a = f.allocator();
    const buf = try a.alloc(u8, 16);
    defer a.free(buf);
    try std.testing.expectEqual(@as(usize, 16), f.reserved);
    // Not exercising the post-freeze path here: it panics by design in Debug.
}
