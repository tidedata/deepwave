//! deepwave-native DB checkpoints and `restore-db` (sui-node `db-checkpoint-config` and `sui-tool
//! restore-db`): a consistent copy of a stopped node directory for fast local restore and
//! backups, made in seconds and with almost no extra disk.
//!
//! Why it is cheap: segments (`store/seg/<epoch>.log`) are append-only and never written again
//! once their epoch is over; cleaning deletes a sealed segment, it never rewrites one. So sealed
//! segments are hard links (shared inodes; deleting either side keeps the other). Everything
//! the store writes in place (the current segment, the live table, its journal, `meta`) and the
//! small node files are cloned where the filesystem can (FICLONE on XFS/btrfs, clonefile on
//! APFS) and copied otherwise. The node fetch spool is left out.
//!
//! The store is opened once first (recovery, then a clean close that flushes the live table),
//! so the copy restarts without replay. A node directory holds an advisory lock (`node/LOCK`)
//! while deepwave runs; these tools refuse to touch a directory whose lock is held.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

pub const lock_name = "node/LOCK";

/// Takes the node directory's lock (`<dir>/node/LOCK`, flock exclusive, non-blocking). The fd
/// stays open (the lock with it) until the process exits or `unlock`.
pub fn lock(dir: []const u8) !std.c.fd_t {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const node_dir = try std.fmt.bufPrintSentinel(&buf, "{s}/node", .{dir}, 0);
    _ = std.c.mkdir(node_dir, 0o700);
    const p = try std.fmt.bufPrintSentinel(&buf, "{s}/" ++ lock_name, .{dir}, 0);
    const fd = std.c.open(p, .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true }, @as(std.c.mode_t, 0o600));
    if (fd < 0) return error.LockOpen;
    if (std.c.flock(fd, std.c.LOCK.EX | std.c.LOCK.NB) != 0) {
        _ = std.c.close(fd);
        return error.NodeRunning;
    }
    return fd;
}

pub fn unlock(fd: std.c.fd_t) void {
    _ = std.c.close(fd);
}

pub const Report = struct {
    linked: u64 = 0,
    linked_bytes: u64 = 0,
    cloned: u64 = 0,
    cloned_bytes: u64 = 0,
    copied: u64 = 0,
    copied_bytes: u64 = 0,
    ms: u64 = 0,
};

const ficlone: u32 = 0x40049409;
extern "c" fn clonefile(src: [*:0]const u8, dst: [*:0]const u8, flags: u32) c_int;

/// Clones `src` to `dst` (a new file) when the filesystem shares extents; false otherwise.
fn cloneFile(src: [:0]const u8, dst: [:0]const u8) bool {
    switch (builtin.os.tag) {
        .macos => return clonefile(src, dst, 0) == 0,
        .linux => {
            const s = std.c.open(src, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
            if (s < 0) return false;
            defer _ = std.c.close(s);
            const d = std.c.open(dst, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true }, @as(std.c.mode_t, 0o600));
            if (d < 0) return false;
            defer _ = std.c.close(d);
            if (std.os.linux.errno(std.os.linux.ioctl(d, ficlone, @intCast(s))) == .SUCCESS) return true;
            _ = std.c.unlink(dst);
            return false;
        },
        else => return false,
    }
}

fn segEpoch(rel: []const u8) ?u64 {
    const pre = "store/seg/";
    if (!std.mem.startsWith(u8, rel, pre) or !std.mem.endsWith(u8, rel, ".log")) return null;
    return std.fmt.parseInt(u64, rel[pre.len .. rel.len - 4], 10) catch null;
}

fn skipped(rel: []const u8) bool {
    return std.mem.eql(u8, rel, "node/spool") or std.mem.startsWith(u8, rel, "node/spool/") or std.mem.eql(u8, rel, lock_name);
}

/// Copies the node directory `src` to `dst` (which must not exist): sealed segments as hard
/// links, the rest cloned or copied.
pub fn copyTree(gpa: std.mem.Allocator, io: Io, src: []const u8, dst: []const u8) !Report {
    const t0 = nowNs();
    var rep: Report = .{};
    const cwd = Io.Dir.cwd();
    if (cwd.statFile(io, dst, .{})) |_| return error.DestinationExists else |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    }
    var sd = try cwd.openDir(io, src, .{ .iterate = true });
    defer sd.close(io);
    // The current segment (highest epoch) is still appended to: copied, never linked.
    var top: ?u64 = null;
    {
        var segs = sd.openDir(io, "store/seg", .{ .iterate = true }) catch null;
        if (segs) |*d| {
            defer d.close(io);
            var it = d.iterate();
            while (try it.next(io)) |e| {
                var nb: [256]u8 = undefined;
                const rel = std.fmt.bufPrint(&nb, "store/seg/{s}", .{e.name}) catch continue;
                if (segEpoch(rel)) |ep| top = if (top) |t| @max(t, ep) else ep;
            }
        }
    }
    try cwd.createDirPath(io, dst);
    var w = try sd.walk(gpa);
    defer w.deinit();
    var sb: [std.fs.max_path_bytes]u8 = undefined;
    var db: [std.fs.max_path_bytes]u8 = undefined;
    while (try w.next(io)) |e| {
        if (skipped(e.path)) continue;
        const dpath = try std.fmt.bufPrintSentinel(&db, "{s}/{s}", .{ dst, e.path }, 0);
        switch (e.kind) {
            .directory => try cwd.createDirPath(io, dpath),
            .file => {
                const spath = try std.fmt.bufPrintSentinel(&sb, "{s}/{s}", .{ src, e.path }, 0);
                const size = (try cwd.statFile(io, spath, .{})).size;
                if (segEpoch(e.path)) |ep| if (top == null or ep < top.?) {
                    if (cwd.hardLink(spath, cwd, dpath, io, .{})) |_| {
                        rep.linked += 1;
                        rep.linked_bytes += size;
                        continue;
                    } else |_| {}
                };
                if (cloneFile(spath, dpath)) {
                    rep.cloned += 1;
                    rep.cloned_bytes += size;
                } else {
                    try Io.Dir.copyFile(cwd, spath, cwd, dpath, io, .{});
                    rep.copied += 1;
                    rep.copied_bytes += size;
                }
            },
            else => {},
        }
    }
    rep.ms = (nowNs() - t0) / std.time.ns_per_ms;
    return rep;
}

fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

test "db checkpoint: sealed segments are linked, the current one and the index are copied, the spool is skipped" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(io, &pb);
    const base = pb[0..base_len];
    var ab: [std.fs.max_path_bytes]u8 = undefined;
    const src = try std.fmt.bufPrint(&ab, "{s}/src", .{base});
    var bb: [std.fs.max_path_bytes]u8 = undefined;
    const dst = try std.fmt.bufPrint(&bb, "{s}/dst", .{base});
    const files = [_]struct { p: []const u8, d: []const u8 }{
        .{ .p = "src/store/seg/00001304.log", .d = "sealed" },
        .{ .p = "src/store/seg/00001305.log", .d = "current" },
        .{ .p = "src/store/index/live-00000001.tbl", .d = "table" },
        .{ .p = "src/store/meta", .d = "meta" },
        .{ .p = "src/node/epochs/1305.json", .d = "{}" },
        .{ .p = "src/node/spool/1.chk", .d = "blob" },
        .{ .p = "src/node/LOCK", .d = "" },
    };
    for (files) |f| {
        try tmp.dir.createDirPath(io, std.fs.path.dirname(f.p).?);
        try tmp.dir.writeFile(io, .{ .sub_path = f.p, .data = f.d });
    }
    const rep = try copyTree(gpa, io, src, dst);
    try std.testing.expectEqual(@as(u64, 1), rep.linked);
    try std.testing.expectEqual(@as(u64, 4), rep.cloned + rep.copied);
    var rb: [64]u8 = undefined;
    try std.testing.expectEqualStrings("sealed", try tmp.dir.readFile(io, "dst/store/seg/00001304.log", &rb));
    try std.testing.expectEqualStrings("current", try tmp.dir.readFile(io, "dst/store/seg/00001305.log", &rb));
    try std.testing.expectEqualStrings("{}", try tmp.dir.readFile(io, "dst/node/epochs/1305.json", &rb));
    try std.testing.expectError(error.FileNotFound, tmp.dir.readFile(io, "dst/node/spool/1.chk", &rb));
    try std.testing.expectError(error.FileNotFound, tmp.dir.readFile(io, "dst/node/LOCK", &rb));
    // the copy of the current segment is independent of the source
    try tmp.dir.writeFile(io, .{ .sub_path = "src/store/seg/00001305.log", .data = "changed" });
    try std.testing.expectEqualStrings("current", try tmp.dir.readFile(io, "dst/store/seg/00001305.log", &rb));
    try std.testing.expectError(error.DestinationExists, copyTree(gpa, io, src, dst));

    // the lock: a second holder is refused until the first lets go
    const fd = try lock(src);
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        // flock locks belong to the open file description: a second open in the same process conflicts
        try std.testing.expectError(error.NodeRunning, lock(src));
    }
    unlock(fd);
    unlock(try lock(src));
}
