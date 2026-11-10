//! Small file helpers for the validator's own files (signer watermarks, epoch store, configs).
//! Every write that must survive a crash is fsynced; replacing a file goes through a temp file
//! and rename.
const std = @import("std");
const Io = std.Io;

pub const Error = error{ Io, OutOfMemory };

pub fn makePath(io: Io, path: []const u8) Error!void {
    Io.Dir.cwd().createDirPath(io, path) catch return error.Io;
}

/// Whole file, or null when it does not exist.
pub fn readAll(gpa: std.mem.Allocator, io: Io, path: []const u8, max: usize) Error!?[]u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max)) catch |e| switch (e) {
        error.FileNotFound => null,
        error.OutOfMemory => error.OutOfMemory,
        else => error.Io,
    };
}

/// Replaces `path` with `bytes` atomically (temp file, fsync, rename).
pub fn writeAtomic(io: Io, path: []const u8, bytes: []const u8) Error!void {
    var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path}) catch return error.Io;
    const cwd = Io.Dir.cwd();
    const f = cwd.createFile(io, tmp, .{ .truncate = true }) catch return error.Io;
    defer f.close(io);
    f.writePositionalAll(io, bytes, 0) catch return error.Io;
    f.sync(io) catch return error.Io;
    cwd.rename(tmp, cwd, path, io) catch return error.Io;
}

/// An exclusive advisory lock on `path` held until `release` (or process exit).
pub const FileLock = struct {
    fd: std.c.fd_t,

    pub const LockError = error{ Locked, Io };

    pub fn acquire(path: []const u8) LockError!FileLock {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const p = std.fmt.bufPrintSentinel(&buf, "{s}", .{path}, 0) catch return error.Io;
        const fd = std.c.open(p, .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true }, @as(std.c.mode_t, 0o600));
        if (fd < 0) return error.Io;
        if (std.c.flock(fd, std.c.LOCK.EX | std.c.LOCK.NB) != 0) {
            _ = std.c.close(fd);
            return error.Locked;
        }
        return .{ .fd = fd };
    }

    pub fn release(l: *FileLock) void {
        _ = std.c.close(l.fd);
        l.fd = -1;
    }
};

/// An append-only log of checksummed records in one file: `[len u32][crc32 u32][payload]`.
/// Recovery keeps every complete record and cuts a torn tail. One `sync` makes a group durable.
pub const RecordLog = struct {
    io: Io,
    file: Io.File,
    end: u64,

    pub const max_record = 16 << 20;

    /// Opens (creating) `path`, calls `visit(ctx, payload)` for every intact record in order and
    /// truncates anything after the last one. The file is replayed record by record (one record in
    /// memory at a time), so a large log does not need a large buffer.
    pub fn open(gpa: std.mem.Allocator, io: Io, path: []const u8, ctx: anytype, comptime visit: anytype) Error!RecordLog {
        const cwd = Io.Dir.cwd();
        const f = cwd.createFile(io, path, .{ .read = true, .truncate = false }) catch return error.Io;
        errdefer f.close(io);
        const size = (f.stat(io) catch return error.Io).size;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        var at: u64 = 0;
        while (at + 8 <= size) {
            var hdr: [8]u8 = undefined;
            const hn = f.readPositionalAll(io, &hdr, at) catch return error.Io;
            if (hn < 8) break;
            const len = std.mem.readInt(u32, hdr[0..4], .little);
            if (len > max_record or at + 8 + len > size) break;
            buf.resize(gpa, len) catch return error.OutOfMemory;
            const pn = f.readPositionalAll(io, buf.items, at + 8) catch return error.Io;
            if (pn < len) break;
            if (std.hash.Crc32.hash(buf.items) != std.mem.readInt(u32, hdr[4..8], .little)) break;
            visit(ctx, buf.items);
            at += 8 + len;
        }
        if (at != size) {
            f.setLength(io, at) catch return error.Io;
            f.sync(io) catch return error.Io;
        }
        return .{ .io = io, .file = f, .end = at };
    }

    pub fn close(l: *RecordLog) void {
        l.file.close(l.io);
    }

    /// Appends one record (not yet durable).
    pub fn append(l: *RecordLog, payload: []const u8) Error!void {
        if (payload.len > max_record) return error.Io;
        var hdr: [8]u8 = undefined;
        std.mem.writeInt(u32, hdr[0..4], @intCast(payload.len), .little);
        std.mem.writeInt(u32, hdr[4..8], std.hash.Crc32.hash(payload), .little);
        l.file.writePositionalAll(l.io, &hdr, l.end) catch return error.Io;
        l.file.writePositionalAll(l.io, payload, l.end + 8) catch return error.Io;
        l.end += 8 + payload.len;
    }

    pub fn sync(l: *RecordLog) Error!void {
        l.file.sync(l.io) catch return error.Io;
    }

    /// Starts a replacement log at `tmp_path` (truncated). Records are appended with `append`,
    /// then `finishReplace` makes it the log at `path`.
    pub fn beginReplace(l: *const RecordLog, tmp_path: []const u8) Error!RecordLog {
        const f = Io.Dir.cwd().createFile(l.io, tmp_path, .{ .read = true, .truncate = true }) catch return error.Io;
        return .{ .io = l.io, .file = f, .end = 0 };
    }

    /// Syncs the replacement `next`, renames it over `path` and makes it this log. The old file
    /// is closed. On error `l` is unchanged and `next` is closed.
    pub fn finishReplace(l: *RecordLog, next: *RecordLog, tmp_path: []const u8, path: []const u8) Error!void {
        errdefer {
            next.file.close(l.io);
            Io.Dir.cwd().deleteFile(l.io, tmp_path) catch {};
        }
        try next.sync();
        const cwd = Io.Dir.cwd();
        cwd.rename(tmp_path, cwd, path, l.io) catch return error.Io;
        l.file.close(l.io);
        l.* = next.*;
    }
};

test "record log recovers intact records and cuts a torn tail" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pbuf[0..try tmp.dir.realPath(io, &pbuf)];
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/x.log", .{dir});
    const Ctx = struct {
        n: usize = 0,
        fn visit(c: *@This(), p: []const u8) void {
            _ = p;
            c.n += 1;
        }
    };
    var c: Ctx = .{};
    var l = try RecordLog.open(std.testing.allocator, io, path, &c, Ctx.visit);
    try l.append("one");
    try l.append("two");
    try l.sync();
    // torn third record
    try l.file.writePositionalAll(io, &[_]u8{ 9, 0, 0, 0, 1 }, l.end);
    l.close();
    c = .{};
    var l2 = try RecordLog.open(std.testing.allocator, io, path, &c, Ctx.visit);
    defer l2.close();
    try std.testing.expectEqual(@as(usize, 2), c.n);
    try std.testing.expectEqual(@as(u64, 8 + 3 + 8 + 3), l2.end);
}
