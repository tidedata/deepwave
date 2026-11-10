//! Memory accounting for the node's status line (`| mem ...`): the process's anonymous and
//! file-backed resident pages (Linux /proc/self/status) and live bytes through counting
//! allocators. Anonymous growth is what matters on a production node; clean file-backed pages (the
//! store's mapped segments and index runs) are page cache the kernel reclaims under pressure.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

/// Counts live bytes handed out by `parent`. One relaxed atomic per call.
pub const Counting = struct {
    parent: Allocator,
    live: std.atomic.Value(i64) = .init(0),

    pub fn allocator(c: *Counting) Allocator {
        return .{ .ptr = c, .vtable = &vtable };
    }

    pub fn bytes(c: *const Counting) u64 {
        return @intCast(@max(c.live.load(.monotonic), 0));
    }

    const vtable: Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn alloc(ctx: *anyopaque, n: usize, a: Alignment, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        const p = c.parent.rawAlloc(n, a, ra) orelse return null;
        _ = c.live.fetchAdd(@intCast(n), .monotonic);
        traceBig(n, ra);
        return p;
    }

    fn resize(ctx: *anyopaque, m: []u8, a: Alignment, n: usize, ra: usize) bool {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        if (!c.parent.rawResize(m, a, n, ra)) return false;
        _ = c.live.fetchAdd(@as(i64, @intCast(n)) - @as(i64, @intCast(m.len)), .monotonic);
        if (n > m.len) traceBig(n, ra);
        return true;
    }

    fn remap(ctx: *anyopaque, m: []u8, a: Alignment, n: usize, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        const p = c.parent.rawRemap(m, a, n, ra) orelse return null;
        _ = c.live.fetchAdd(@as(i64, @intCast(n)) - @as(i64, @intCast(m.len)), .monotonic);
        if (n > m.len) traceBig(n, ra);
        return p;
    }

    fn free(ctx: *anyopaque, m: []u8, a: Alignment, ra: usize) void {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.parent.rawFree(m, a, ra);
        _ = c.live.fetchSub(@intCast(m.len), .monotonic);
    }
};

/// Bytes kept across resets by reused per-checkpoint buffers, by owner (status line `kept`).
pub const Kept = enum { exec_jobs, exec_threads, fetch_scratch };
pub var kept: [3]std.atomic.Value(i64) = @splat(.init(0));

/// Moves `owner`'s gauge from `last.*` to `now` bytes.
pub fn keep(owner: Kept, last: *u64, now: u64) void {
    if (now == last.*) return;
    _ = kept[@intFromEnum(owner)].fetchAdd(@as(i64, @intCast(now)) - @as(i64, @intCast(last.*)), .monotonic);
    last.* = now;
}

pub fn keptBytes(owner: Kept) u64 {
    return @intCast(@max(kept[@intFromEnum(owner)].load(.monotonic), 0));
}

/// Allocations of at least this many bytes are logged with their return address
/// (`ZUI_MEMTRACE=1`); `memstat.rss` is the anchor to turn it into a symbol offset.
pub var trace_min: usize = std.math.maxInt(usize);

fn traceBig(n: usize, ra: usize) void {
    if (n < trace_min) return;
    std.log.warn("memtrace: {d} MiB at ra 0x{x} (rss fn 0x{x})", .{ n >> 20, ra, @intFromPtr(&rss) });
}

/// The allocator exec's Move-call executor gets (package caches and VM runtimes per thread).
pub var exec_gpa: Counting = .{ .parent = std.heap.smp_allocator };

/// The node's own allocator for `run` (main.zig sets the parent).
pub var node_gpa: Counting = .{ .parent = std.heap.smp_allocator };

/// Resident pages of this process in bytes: anonymous (private memory) and file-backed.
pub const Rss = struct { anon: u64 = 0, file: u64 = 0 };

pub fn rss() Rss {
    if (builtin.os.tag != .linux) return .{};
    var buf: [4096]u8 = undefined;
    const fd = std.posix.openatZ(std.posix.AT.FDCWD, "/proc/self/status", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch return .{};
    defer _ = std.posix.system.close(fd);
    const n = std.posix.read(fd, &buf) catch return .{};
    return parseStatus(buf[0..n]);
}

fn parseStatus(text: []const u8) Rss {
    var out: Rss = .{};
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        const f: *u64 = if (std.mem.startsWith(u8, line, "RssAnon:")) &out.anon else if (std.mem.startsWith(u8, line, "RssFile:")) &out.file else continue;
        var t = std.mem.tokenizeAny(u8, line[8..], " \t");
        const kb = std.fmt.parseInt(u64, t.next() orelse continue, 10) catch continue;
        f.* = kb << 10;
    }
    return out;
}

test "memstat: status parse and counting" {
    const r = parseStatus("Name:\tx\nRssAnon:\t  1024 kB\nRssFile:\t     8 kB\n");
    try std.testing.expectEqual(@as(u64, 1 << 20), r.anon);
    try std.testing.expectEqual(@as(u64, 8 << 10), r.file);
    var c: Counting = .{ .parent = std.testing.allocator };
    const a = c.allocator();
    const x = try a.alloc(u8, 100);
    try std.testing.expectEqual(@as(u64, 100), c.bytes());
    const y = try a.realloc(x, 300);
    try std.testing.expectEqual(@as(u64, 300), c.bytes());
    a.free(y);
    try std.testing.expectEqual(@as(u64, 0), c.bytes());
}
