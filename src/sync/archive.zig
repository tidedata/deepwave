//! Archive source: a directory of `<seq>.chk` blobs (`0x01 ++ BCS(CheckpointData)`), the layout
//! of the corpus `chk/` directory and of a local mirror of Mysten's checkpoint archive. A blob is
//! read straight into the caller's buffer with one positional read (no intermediate copy).
const std = @import("std");
const Io = std.Io;

pub const Archive = struct {
    dir: Io.Dir,

    pub fn open(io: Io, path: []const u8) !Archive {
        return .{ .dir = try Io.Dir.cwd().openDir(io, path, .{}) };
    }

    pub fn close(a: *Archive, io: Io) void {
        a.dir.close(io);
    }

    pub const Read = enum { ok, missing };

    /// Reads checkpoint `seq` into `buf` (its capacity is kept between calls).
    pub fn read(a: *const Archive, gpa: std.mem.Allocator, io: Io, seq: u64, buf: *std.ArrayList(u8)) !Read {
        var nb: [40]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, "{d}.chk", .{seq}) catch unreachable;
        const f = a.dir.openFile(io, name, .{}) catch |e| switch (e) {
            error.FileNotFound => return .missing,
            else => return e,
        };
        defer f.close(io);
        const size: usize = @intCast((try f.stat(io)).size);
        try buf.ensureTotalCapacity(gpa, size);
        buf.items.len = size;
        const n = try f.readPositionalAll(io, buf.items, 0);
        if (n != size) return error.ShortRead;
        return .ok;
    }
};
