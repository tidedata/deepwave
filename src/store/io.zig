//! I/O backends of the store: `RealIo` (pwrite/fdatasync/mmap, io_uring on Linux) and
//! `SimIo` (the deterministic simulated disk in sim.zig). The engine only ever calls the
//! functions on `Backend`, so every byte it writes or reads in a simulation run goes through
//! the same code paths as on a real disk.
//!
//! File names are relative to the store directory: `meta`, `seg/<epoch>.log`, `index/<gen>.idx`.
//!
//! io_uring commit path (`uringWriteSync`): unique user_data per request, every flushed SQE
//! submitted and every CQE reaped before return, EINTR/EAGAIN/EBUSY from io_uring_enter retried,
//! and a request whose CQE says EINTR/EAGAIN redone instead of failing the commit.
const std = @import("std");
const guard = @import("guard.zig");
const builtin = @import("builtin");
const sim = @import("sim.zig");
const linux = std.os.linux;

pub const Fd = u32;
pub const max_files = 1 << 16;

pub const SyncMode = enum {
    /// No fsync: crash safe against a process crash only (what sui-node's RocksDB writes give).
    none,
    /// fdatasync (Linux) / fsync (macOS): durable against power loss on Linux.
    data,
    /// Linux fdatasync, macOS F_FULLFSYNC (flushes the drive cache).
    full,
};

/// An OS failure the store reports as `error.Io`: the errno goes to stderr first, so a flaky run
/// (a full or lazily restored volume, a signal) names its cause instead of a bare `Io`.
fn ioErr(comptime op: []const u8, e: linux.E) error{Io} {
    std.debug.print("store io: {s} failed: errno {s}\n", .{ op, @tagName(e) });
    return error.Io;
}

pub const Error = error{
    Io,
    NoSpace,
    FileNotFound,
    TooManyFiles,
    ShortRead,
    Crashed,
} || std.mem.Allocator.Error;

pub const Backend = union(enum) {
    real: *RealIo,
    sim: *sim.SimIo,

    /// A second handle on `name` for unbuffered writes (Linux O_DIRECT), safe to use from
    /// several threads at once; null where there is none (simulator, other systems): the
    /// caller writes through `write` instead.
    pub fn openDirect(b: Backend, name: []const u8) ?std.posix.fd_t {
        return switch (b) {
            .real => |r| r.openDirect(name),
            .sim => null,
        };
    }
    pub fn closeDirect(b: Backend, h: std.posix.fd_t) void {
        _ = b;
        if (is_linux) _ = linux.close(h) else _ = std.c.close(h);
    }
    /// Writes all of `data` at `off` through a handle from `openDirect` (buffer, offset and
    /// length 4096-aligned).
    pub fn pwriteAll(b: Backend, h: std.posix.fd_t, off: u64, data: []const u8) Error!void {
        _ = b;
        var done: usize = 0;
        while (done < data.len) done += try pwrite(h, data[done..], off + done);
    }
    /// The OS handle of an open file, for buffered writes from several threads at once (pwrite);
    /// null in the simulator (single-threaded by construction).
    pub fn rawHandle(b: Backend, fd: Fd) ?std.posix.fd_t {
        return switch (b) {
            .real => |r| r.handle(fd),
            .sim => null,
        };
    }
    /// Writes back the dirty cached pages of [off, off+len) and waits for them (Linux
    /// sync_file_range WAIT_BEFORE|WRITE|WAIT_AFTER, a data-integrity write-back like
    /// fdatasync's; no file metadata): the volume sees the writes now, while the pages stay
    /// cached. Elsewhere a no-op (the closing fdatasync covers them).
    pub fn writeBack(b: Backend, h: std.posix.fd_t, off: u64, len: u64) Error!void {
        _ = b;
        if (is_linux and (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64)) {
            const flags: usize = 1 | 2 | 4;
            while (true) switch (linux.errno(linux.syscall4(.sync_file_range, @as(usize, @bitCast(@as(isize, h))), off, len, flags))) {
                .SUCCESS => break,
                .INTR => continue,
                else => |e| return ioErr("sync_file_range", e),
            };
        }
    }
    pub fn fdatasync(b: Backend, h: std.posix.fd_t) Error!void {
        _ = b;
        if (is_linux) try linuxFdatasync(h) else try cFsync(h);
    }

    pub fn openFile(b: Backend, name: []const u8, create: bool) Error!Fd {
        return switch (b) {
            inline else => |x| x.openFile(name, create),
        };
    }
    pub fn closeFile(b: Backend, fd: Fd) void {
        switch (b) {
            inline else => |x| x.closeFile(fd),
        }
    }
    pub fn size(b: Backend, fd: Fd) Error!u64 {
        return switch (b) {
            inline else => |x| x.size(fd),
        };
    }
    pub fn read(b: Backend, fd: Fd, off: u64, buf: []u8) Error!void {
        return switch (b) {
            inline else => |x| x.read(fd, off, buf),
        };
    }
    pub fn write(b: Backend, fd: Fd, off: u64, data: []const u8) Error!void {
        return switch (b) {
            inline else => |x| x.write(fd, off, data),
        };
    }
    pub fn sync(b: Backend, fd: Fd) Error!void {
        return switch (b) {
            inline else => |x| x.sync(fd),
        };
    }
    /// One durable append: write then sync, submitted together on io_uring.
    pub fn writeSync(b: Backend, fd: Fd, off: u64, data: []const u8) Error!void {
        return switch (b) {
            inline else => |x| x.writeSync(fd, off, data),
        };
    }
    pub fn truncate(b: Backend, fd: Fd, len: u64) Error!void {
        return switch (b) {
            inline else => |x| x.truncate(fd, len),
        };
    }
    pub fn remove(b: Backend, name: []const u8) Error!void {
        return switch (b) {
            inline else => |x| x.remove(name),
        };
    }
    pub fn syncDir(b: Backend) Error!void {
        return switch (b) {
            inline else => |x| x.syncDir(),
        };
    }
    /// Read-only view of the file, `reserve` bytes long. Bytes below `size(fd)` are valid and
    /// stay valid (and show later writes) until `unmap`.
    pub fn map(b: Backend, fd: Fd, reserve: u64) Error![]const u8 {
        return switch (b) {
            inline else => |x| x.map(fd, reserve),
        };
    }
    pub fn unmap(b: Backend, fd: Fd, view: []const u8) void {
        switch (b) {
            inline else => |x| x.unmap(fd, view),
        }
    }
    /// Writable private view of the file's first `len` bytes: writes stay in memory (never
    /// reach the file) until written with `write`; `dropPrivate` then turns the view back into
    /// plain file pages.
    pub fn mapRw(b: Backend, fd: Fd, len: u64) Error![]align(4096) u8 {
        return switch (b) {
            inline else => |x| x.mapRw(fd, len),
        };
    }
    pub fn unmapRw(b: Backend, fd: Fd, view: []align(4096) u8) void {
        switch (b) {
            inline else => |x| x.unmapRw(fd, view),
        }
    }
    /// Discards the private copies of `view` (whose bytes must already equal the file's).
    pub fn dropPrivate(b: Backend, fd: Fd, view: []align(4096) u8) Error!void {
        return switch (b) {
            inline else => |x| x.dropPrivate(fd, view),
        };
    }
    /// Discards the private copies of `view[off..][0..len]` (page aligned; the bytes must already
    /// equal the file's), leaving the rest of the mapping alone.
    pub fn dropRange(b: Backend, fd: Fd, view: []align(4096) u8, off: u64, len: u64) Error!void {
        return switch (b) {
            inline else => |x| x.dropRange(fd, view, off, len),
        };
    }
    /// Page-cache hint for bulk streams (lane fast-start): writes back `[off, off + len)` of the
    /// file (when `write_back`) and drops it from the page cache, so a bulk read or write inside a
    /// memory-capped cgroup neither piles up dirty pages nor makes the kernel reclaim under the
    /// writer. Advisory: no error, a no-op off Linux and in the simulator.
    pub fn dropCache(b: Backend, fd: Fd, off: u64, len: u64, write_back: bool) void {
        switch (b) {
            .real => |x| x.dropCache(fd, off, len, write_back),
            .sim => {},
        }
    }
    /// Starts reading `[off, off + len)` of a file into the page cache asynchronously
    /// (POSIX_FADV_WILLNEED), for preads that follow. Advisory: a no-op off Linux and in the
    /// simulator.
    pub fn willNeedFile(b: Backend, fd: Fd, off: u64, len: u64) void {
        switch (b) {
            .real => |x| x.willNeedFile(fd, off, len),
            .sim => {},
        }
    }
    /// Frees the 4096-aligned blocks of `[off, off + len)` (they read as zeros after; the file
    /// size stays): fallocate(PUNCH_HOLE | KEEP_SIZE) on Linux, F_PUNCHHOLE on macOS, a no-op
    /// where neither exists. Durable with the file's next sync. The caller rounds the range in.
    pub fn punch(b: Backend, fd: Fd, off: u64, len: u64) Error!void {
        return switch (b) {
            inline else => |x| x.punch(fd, off, len),
        };
    }
    /// Bytes the file occupies on disk (st_blocks * 512; the simulator counts non-zero blocks).
    pub fn allocated(b: Backend, fd: Fd) Error!u64 {
        return switch (b) {
            inline else => |x| x.allocated(fd),
        };
    }
    /// Names of the files in `sub` (caller frees each name and the slice with gpa).
    pub fn listDir(b: Backend, gpa: std.mem.Allocator, sub: []const u8) Error![][]u8 {
        return switch (b) {
            inline else => |x| x.listDir(gpa, sub),
        };
    }
    /// Epochs of the `seg/<epoch>.log` files, ascending (caller frees with gpa).
    pub fn listSegments(b: Backend, gpa: std.mem.Allocator) Error![]u64 {
        return switch (b) {
            inline else => |x| x.listSegments(gpa),
        };
    }
    pub fn exists(b: Backend, name: []const u8) bool {
        return switch (b) {
            inline else => |x| x.exists(name),
        };
    }
};

/// Access advice for mappings of real files (no-ops elsewhere). Segments, runs and the live
/// table are read at random (one record or slot per lookup): without this, every cold fault
/// reads ahead ~128 KiB around a ~300-byte record, which multiplies the IO and fills the page
/// cache (and a memory-limited cgroup) with bytes nobody reads. Scans that are sequential
/// (recovery replay, cleaning sweeps) ask for their range with `willNeed` first.
pub fn adviseRandom(view: []const u8) void {
    advise(view, std.posix.MADV.RANDOM);
}

/// Starts reading `range` (part of a mapping) into the page cache asynchronously.
/// Linux caps one WILLNEED at the file's read-ahead size (force_page_cache_ra: max(io_pages,
/// ra_pages), 128 KiB here), so a large range is asked for in slices of that size; one call for
/// 32 MiB read 128 KiB and left the rest to 4 KiB faults (box 5, LiveScan over the live table).
pub fn willNeed(range: []const u8) void {
    const slice: usize = 128 << 10;
    var off: usize = 0;
    while (off < range.len) : (off += slice) advise(range[off..@min(range.len, off + slice)], std.posix.MADV.WILLNEED);
}

/// Drops the pages of `range` (part of a read-only file mapping) from this process; they stay
/// in the page cache only as clean, reclaimable pages (bulk sequential passes: the converter).
pub fn dontNeed(range: []const u8) void {
    advise(range, std.posix.MADV.DONTNEED);
}

/// Marks the pages of `range` (part of a mapping) as first to reclaim (MADV_COLD, Linux 5.4+;
/// a no-op elsewhere). Nothing is dropped: a page used again is simply referenced again. For
/// one-pass scans through a memory-capped cgroup, so they do not evict the hot set.
pub fn cold(range: []const u8) void {
    if (builtin.os.tag != .linux) return;
    advise(range, std.os.linux.MADV.COLD);
}

fn advise(range: []const u8, advice: u32) void {
    if (range.len == 0) return;
    const ps = std.heap.pageSize();
    const start = std.mem.alignBackward(usize, @intFromPtr(range.ptr), ps);
    const end = @intFromPtr(range.ptr) + range.len;
    const p: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(start);
    std.posix.madvise(p, end - start, advice) catch {};
}

pub fn segName(buf: []u8, epoch: u64) []const u8 {
    return std.fmt.bufPrint(buf, "seg/{d:0>8}.log", .{epoch}) catch unreachable;
}

/// The live table file of table generation `tg`.
pub fn liveName(buf: []u8, tg: u64) []const u8 {
    return std.fmt.bufPrint(buf, "index/live-{d:0>8}.tbl", .{tg}) catch unreachable;
}

pub const journal_name = "index/live.jnl";

/// Sealed run `run` of `epoch`.
pub fn runName(buf: []u8, epoch: u64, run: u64) []const u8 {
    return std.fmt.bufPrint(buf, "index/{d:0>8}-{d:0>4}.run", .{ epoch, run }) catch unreachable;
}

pub const IndexFile = union(enum) {
    run: struct { epoch: u64, run: u64 },
    live: u64,
    other,
};

/// Classifies a file name inside `index/`.
pub fn parseIndexName(name: []const u8) IndexFile {
    if (std.mem.endsWith(u8, name, ".run")) {
        const dash = std.mem.indexOfScalar(u8, name, '-') orelse return .other;
        const e = std.fmt.parseInt(u64, name[0..dash], 10) catch return .other;
        const r = std.fmt.parseInt(u64, name[dash + 1 .. name.len - 4], 10) catch return .other;
        return .{ .run = .{ .epoch = e, .run = r } };
    }
    if (std.mem.startsWith(u8, name, "live-") and std.mem.endsWith(u8, name, ".tbl")) {
        const tg = std.fmt.parseInt(u64, name[5 .. name.len - 4], 10) catch return .other;
        return .{ .live = tg };
    }
    return .other;
}

pub fn parseSegName(name: []const u8) ?u64 {
    if (!std.mem.endsWith(u8, name, ".log")) return null;
    return std.fmt.parseInt(u64, name[0 .. name.len - 4], 10) catch null;
}

const is_linux = builtin.os.tag == .linux;
const is_darwin = builtin.os.tag.isDarwin();

/// Real files. Hot paths use raw descriptors (pwrite, fdatasync, mmap); directory work goes
/// through std.Io.
pub const RealIo = struct {
    io: std.Io,
    root: std.Io.Dir,
    files: []?std.Io.File,
    gpa: std.mem.Allocator,
    sync_mode: SyncMode,
    ring: if (is_linux) ?linux.IoUring else void,
    /// Request counter of `ring`: request k carries user_data 2k (write) and 2k+1 (fsync).
    ring_seq: u64 = 0,
    /// Use-after-release guard (guard.zig): unmapped views become inaccessible reservations.
    guard: bool = false,

    pub const Options = struct {
        sync: SyncMode = .data,
        /// Linux: drive commits through io_uring (write + linked fdatasync, one syscall).
        uring: bool = true,
    };

    pub fn init(gpa: std.mem.Allocator, io: std.Io, path: []const u8, opts: Options) !*RealIo {
        try std.Io.Dir.cwd().createDirPath(io, path);
        var root = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
        errdefer root.close(io);
        try root.createDirPath(io, "seg");
        try root.createDirPath(io, "index");
        const r = try gpa.create(RealIo);
        errdefer gpa.destroy(r);
        const files = try gpa.alloc(?std.Io.File, 4096);
        @memset(files, null);
        r.* = .{ .io = io, .root = root, .files = files, .gpa = gpa, .sync_mode = opts.sync, .ring = if (is_linux) null else {} };
        if (is_linux and opts.uring) r.ring = linux.IoUring.init(8, 0) catch null;
        return r;
    }

    pub fn deinit(r: *RealIo) void {
        for (r.files) |*f| if (f.*) |file| {
            file.close(r.io);
            f.* = null;
        };
        if (is_linux) if (r.ring) |*ring| ring.deinit();
        r.root.close(r.io);
        r.gpa.free(r.files);
        r.gpa.destroy(r);
    }

    pub fn usesUring(r: *const RealIo) bool {
        if (is_linux) return r.ring != null;
        return false;
    }

    /// Linux: evicts `[off, off + len)` of a file from the page cache (written back first when
    /// `write_back`), so a bulk pass (the converter, fast-start's restore and image walk) does
    /// not fill a memory-limited cgroup with pages nobody rereads.
    pub fn dropCache(r: *RealIo, fd: Fd, off: u64, len: u64, write_back: bool) void {
        if (!is_linux or len == 0) return;
        const h = r.handle(fd);
        const hu: usize = @bitCast(@as(isize, h));
        // SYNC_FILE_RANGE_WAIT_BEFORE | WRITE | WAIT_AFTER
        if (write_back) _ = linux.syscall4(.sync_file_range, hu, off, len, 7);
        _ = linux.fadvise(h, @intCast(off), @intCast(len), linux.POSIX_FADV.DONTNEED);
    }

    pub fn willNeedFile(r: *RealIo, fd: Fd, off: u64, len: u64) void {
        if (!is_linux or len == 0) return;
        _ = linux.fadvise(r.handle(fd), @intCast(off), @intCast(len), linux.POSIX_FADV.WILLNEED);
    }

    fn openDirect(r: *RealIo, name: []const u8) ?std.posix.fd_t {
        if (!is_linux) return null;
        var zb: [256]u8 = undefined;
        if (name.len >= zb.len) return null;
        @memcpy(zb[0..name.len], name);
        zb[name.len] = 0;
        const rc = linux.openat(r.root.handle, @ptrCast(&zb), .{ .ACCMODE = .RDWR, .DIRECT = true, .CLOEXEC = true }, 0);
        if (linux.errno(rc) != .SUCCESS) return null;
        return @intCast(rc);
    }

    fn handle(r: *RealIo, fd: Fd) std.posix.fd_t {
        return r.files[fd].?.handle;
    }

    pub fn openFile(r: *RealIo, name: []const u8, create: bool) Error!Fd {
        const slot = for (r.files, 0..) |f, i| {
            if (f == null) break i;
        } else return error.TooManyFiles;
        const file = if (create)
            r.root.createFile(r.io, name, .{ .read = true, .truncate = false }) catch return error.Io
        else
            r.root.openFile(r.io, name, .{ .mode = .read_write }) catch |e| return switch (e) {
                error.FileNotFound => error.FileNotFound,
                else => error.Io,
            };
        r.files[slot] = file;
        return @intCast(slot);
    }

    pub fn closeFile(r: *RealIo, fd: Fd) void {
        if (r.files[fd]) |f| f.close(r.io);
        r.files[fd] = null;
    }

    pub fn size(r: *RealIo, fd: Fd) Error!u64 {
        const h = r.handle(fd);
        if (is_linux) {
            const rc = linux.lseek(h, 0, linux.SEEK.END);
            if (linux.errno(rc) != .SUCCESS) return ioErr("lseek", linux.errno(rc));
            return @intCast(rc);
        } else {
            const rc = std.c.lseek(h, 0, std.c.SEEK.END);
            if (rc < 0) return error.Io;
            return @intCast(rc);
        }
    }

    pub fn read(r: *RealIo, fd: Fd, off: u64, buf: []u8) Error!void {
        const h = r.handle(fd);
        var done: usize = 0;
        while (done < buf.len) {
            const n = pread(h, buf[done..], off + done) catch |e| switch (e) {
                error.Interrupted => continue,
                else => return error.Io,
            };
            if (n == 0) return error.ShortRead;
            done += n;
        }
    }

    pub fn write(r: *RealIo, fd: Fd, off: u64, data: []const u8) Error!void {
        const h = r.handle(fd);
        var done: usize = 0;
        while (done < data.len) {
            const n = pwrite(h, data[done..], off + done) catch |e| return e;
            done += n;
        }
    }

    pub fn sync(r: *RealIo, fd: Fd) Error!void {
        return syncHandle(r.handle(fd), r.sync_mode);
    }

    pub fn writeSync(r: *RealIo, fd: Fd, off: u64, data: []const u8) Error!void {
        if (is_linux) if (r.ring) |*ring| if (r.sync_mode != .none) {
            return uringWriteSync(ring, &r.ring_seq, r.handle(fd), off, data) catch |e| switch (e) {
                // Rewriting the same bytes at the same offset is idempotent; the sync then
                // covers them. Never taken after a failed fdatasync (that is `Failed`).
                error.Short => {
                    try r.write(fd, off, data);
                    try r.sync(fd);
                },
                // Nothing of the request reached the kernel: retire the ring, go portable.
                error.Unusable => {
                    ring.deinit();
                    r.ring = null;
                    try r.write(fd, off, data);
                    try r.sync(fd);
                },
                error.NoSpace => error.NoSpace,
                error.Failed => error.Io,
            };
        };
        try r.write(fd, off, data);
        try r.sync(fd);
    }

    pub fn punch(r: *RealIo, fd: Fd, off: u64, len: u64) Error!void {
        if (len == 0) return;
        const h = r.handle(fd);
        if (is_linux) {
            const rc = linux.fallocate(h, 0x02 | 0x01, @intCast(off), @intCast(len)); // PUNCH_HOLE | KEEP_SIZE
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .OPNOTSUPP, .NOSYS => {},
                else => return error.Io,
            }
        } else if (is_darwin) {
            const FPunch = extern struct { flags: u32 = 0, reserved: u32 = 0, offset: i64, length: i64 };
            var a: FPunch = .{ .offset = @intCast(off), .length = @intCast(len) };
            const F_PUNCHHOLE = 99;
            if (std.c.fcntl(h, F_PUNCHHOLE, &a) != 0) switch (std.posix.errno(-1)) {
                .OPNOTSUPP, .INVAL => {},
                else => return error.Io,
            };
        }
    }

    pub fn allocated(r: *RealIo, fd: Fd) Error!u64 {
        const h = r.handle(fd);
        if (is_linux) {
            var st: linux.Statx = undefined;
            if (linux.errno(linux.statx(h, "", linux.AT.EMPTY_PATH, .{ .BLOCKS = true }, &st)) != .SUCCESS) return error.Io;
            return st.blocks * 512;
        }
        var st: std.c.Stat = undefined;
        if (std.c.fstat(h, &st) != 0) return error.Io;
        return @as(u64, @intCast(st.blocks)) * 512;
    }

    pub fn truncate(r: *RealIo, fd: Fd, len: u64) Error!void {
        const h = r.handle(fd);
        if (is_linux) {
            const e = linux.errno(linux.ftruncate(h, @intCast(len)));
            if (e != .SUCCESS) return ioErr("ftruncate", e);
        } else {
            if (std.c.ftruncate(h, @intCast(len)) != 0) return error.Io;
        }
    }

    pub fn remove(r: *RealIo, name: []const u8) Error!void {
        r.root.deleteFile(r.io, name) catch |e| switch (e) {
            error.FileNotFound => return,
            else => return error.Io,
        };
    }

    pub fn syncDir(r: *RealIo) Error!void {
        if (r.sync_mode == .none) return;
        inline for (.{ ".", "seg", "index" }) |sub| {
            // .iterate opens a real read fd: without it Linux opens O_PATH and fsync fails with EBADF.
            var d = r.root.openDir(r.io, sub, .{ .iterate = true }) catch return error.Io;
            defer d.close(r.io);
            // A failed directory sync means a new or removed file may not be durable: report it
            // (fsync errors are never retried). Only "not supported on this fd" is tolerated.
            try syncDirHandle(d.handle);
        }
    }

    pub fn map(r: *RealIo, fd: Fd, reserve: u64) Error![]const u8 {
        const len = std.mem.alignForward(u64, @max(reserve, 1), std.heap.pageSize());
        const m = std.posix.mmap(null, @intCast(len), .{ .READ = true }, .{ .TYPE = .SHARED }, r.handle(fd), 0) catch return error.Io;
        return m;
    }

    pub fn unmap(r: *RealIo, fd: Fd, view: []const u8) void {
        _ = fd;
        if (r.guard) return guard.poisonRange(view.ptr, view.len);
        std.posix.munmap(@alignCast(view));
    }

    fn rwFlags(fixed: bool) std.posix.MAP {
        var f: std.posix.MAP = .{ .TYPE = .PRIVATE };
        if (fixed) f.FIXED = true;
        if (is_linux) f.NORESERVE = true;
        return f;
    }

    pub fn mapRw(r: *RealIo, fd: Fd, len: u64) Error![]align(4096) u8 {
        const n = std.mem.alignForward(u64, @max(len, 1), std.heap.pageSize());
        const m = std.posix.mmap(null, @intCast(n), .{ .READ = true, .WRITE = true }, rwFlags(false), r.handle(fd), 0) catch return error.Io;
        return @alignCast(m[0..@intCast(len)]);
    }

    pub fn unmapRw(r: *RealIo, fd: Fd, view: []align(4096) u8) void {
        _ = fd;
        if (r.guard) return guard.poisonRange(view.ptr, view.len);
        const n = std.mem.alignForward(usize, @max(view.len, 1), std.heap.pageSize());
        std.posix.munmap(@alignCast(view.ptr[0..n]));
    }

    pub fn dropPrivate(r: *RealIo, fd: Fd, view: []align(4096) u8) Error!void {
        // Replace the whole mapping in place (MAP_FIXED is atomic for concurrent readers): the
        // private copies go, clean file pages come back on the next touch.
        const n = std.mem.alignForward(usize, @max(view.len, 1), std.heap.pageSize());
        const m = std.posix.mmap(@alignCast(view.ptr), n, .{ .READ = true, .WRITE = true }, rwFlags(true), r.handle(fd), 0) catch return error.Io;
        if (m.ptr != view.ptr) return error.Io;
        // The new mapping lost the old one's advice: the live table is read at random.
        adviseRandom(m);
    }

    pub fn dropRange(r: *RealIo, fd: Fd, view: []align(4096) u8, off: u64, len: u64) Error!void {
        if (len == 0) return;
        const p: [*]align(4096) u8 = @alignCast(view.ptr + off);
        if (is_linux) {
            // Private anonymous copies go, file pages come back on the next touch; no VMA split
            // (a MAP_FIXED remap per range would fragment the mapping).
            const rc = linux.madvise(p, @intCast(len), linux.MADV.DONTNEED);
            if (linux.errno(rc) != .SUCCESS) return ioErr("madvise", linux.errno(rc));
            return;
        }
        const pa: [*]align(std.heap.page_size_min) u8 = @alignCast(p);
        const m = std.posix.mmap(pa, @intCast(len), .{ .READ = true, .WRITE = true }, rwFlags(true), r.handle(fd), off) catch return error.Io;
        if (m.ptr != pa) return error.Io;
    }

    pub fn listDir(r: *RealIo, gpa: std.mem.Allocator, sub: []const u8) Error![][]u8 {
        var d = r.root.openDir(r.io, sub, .{ .iterate = true }) catch return error.Io;
        defer d.close(r.io);
        var list: std.ArrayList([]u8) = .empty;
        errdefer {
            for (list.items) |x| gpa.free(x);
            list.deinit(gpa);
        }
        var it = d.iterate();
        while (it.next(r.io) catch return error.Io) |e| {
            if (e.kind != .file) continue;
            try list.append(gpa, try gpa.dupe(u8, e.name));
        }
        return list.toOwnedSlice(gpa);
    }

    pub fn listSegments(r: *RealIo, gpa: std.mem.Allocator) Error![]u64 {
        var d = r.root.openDir(r.io, "seg", .{ .iterate = true }) catch return error.Io;
        defer d.close(r.io);
        var list: std.ArrayList(u64) = .empty;
        errdefer list.deinit(gpa);
        var it = d.iterate();
        while (it.next(r.io) catch return error.Io) |e| {
            if (parseSegName(e.name)) |ep| try list.append(gpa, ep);
        }
        std.mem.sort(u64, list.items, {}, std.sort.asc(u64));
        return list.toOwnedSlice(gpa);
    }

    pub fn exists(r: *RealIo, name: []const u8) bool {
        const f = r.root.openFile(r.io, name, .{}) catch return false;
        f.close(r.io);
        return true;
    }
};

fn pread(h: std.posix.fd_t, buf: []u8, off: u64) !usize {
    if (is_linux) {
        const rc = linux.pread(h, buf.ptr, buf.len, @intCast(off));
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .INTR => error.Interrupted,
            else => |e| ioErr("pread", e),
        };
    } else {
        const rc = std.c.pread(h, buf.ptr, buf.len, @intCast(off));
        if (rc < 0) return if (std.c.errno(rc) == .INTR) error.Interrupted else error.Io;
        return @intCast(rc);
    }
}

fn pwrite(h: std.posix.fd_t, data: []const u8, off: u64) Error!usize {
    if (is_linux) {
        const rc = linux.pwrite(h, data.ptr, data.len, @intCast(off));
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .INTR => 0,
            .NOSPC => error.NoSpace,
            else => |e| ioErr("pwrite", e),
        };
    } else {
        const rc = std.c.pwrite(h, data.ptr, data.len, @intCast(off));
        if (rc < 0) return switch (std.c.errno(rc)) {
            .INTR => 0,
            .NOSPC => error.NoSpace,
            else => error.Io,
        };
        return @intCast(rc);
    }
}

fn syncDirHandle(h: std.posix.fd_t) Error!void {
    if (is_linux) {
        switch (linux.errno(linux.fsync(h))) {
            .SUCCESS, .INVAL => {},
            else => |e| return ioErr("fsync(dir)", e),
        }
    } else {
        const rc = std.c.fsync(h);
        if (rc != 0) switch (std.c.errno(rc)) {
            .INVAL, .OPNOTSUPP => {},
            else => return error.Io,
        };
    }
}

// The node's SIGINT/SIGTERM handler has no SA_RESTART: a sync or io_uring wait in the thread the
// signal lands on returns EINTR, which is a retry, not an I/O error.
fn linuxFdatasync(h: std.posix.fd_t) Error!void {
    while (true) switch (linux.errno(linux.fdatasync(h))) {
        .SUCCESS => return,
        .INTR => continue,
        else => |e| return ioErr("fdatasync", e),
    };
}

fn cFsync(h: std.posix.fd_t) Error!void {
    while (true) {
        const rc = std.c.fsync(h);
        if (rc == 0) return;
        if (std.c.errno(rc) != .INTR) return error.Io;
    }
}

fn syncHandle(h: std.posix.fd_t, mode: SyncMode) Error!void {
    switch (mode) {
        .none => {},
        .data, .full => if (is_linux) {
            try linuxFdatasync(h);
        } else if (is_darwin and mode == .full) {
            if (std.c.fcntl(h, std.c.F.FULLFSYNC) != 0) try cFsync(h);
        } else {
            try cFsync(h);
        },
    }
}

const UringError = error{
    /// The write landed short or its CQE said EINTR/EAGAIN: redo it synchronously.
    Short,
    /// The write or the fdatasync failed (EIO and the like). Never retried: after a failed
    /// fdatasync the kernel may have marked the dirty pages clean (fsyncgate).
    Failed,
    NoSpace,
    /// io_uring_enter kept refusing the submission and none of it was taken: the ring holds
    /// two flushed SQEs that must never run, so the caller closes it.
    Unusable,
};

/// One write + linked fdatasync in one io_uring_enter. On every return the ring is empty: no
/// flushed SQE left for a later call to submit (it would point at this call's buffer, which the
/// caller reuses, or at a stack page), and no CQE left for a later call to mistake for its own.
fn uringWriteSync(ring: *linux.IoUring, seq: *u64, h: std.posix.fd_t, off: u64, data: []const u8) UringError!void {
    std.debug.assert(ring.sq_ready() == 0);
    std.debug.assert(data.len > 0);
    seq.* +%= 1;
    const tag_w = seq.* << 1;
    const tag_s = tag_w | 1;
    // The ring has 8 entries and is empty: both fit.
    const w = ring.write(tag_w, h, data, off) catch unreachable;
    w.flags |= linux.IOSQE_IO_LINK;
    _ = ring.fsync(tag_s, h, linux.IORING_FSYNC_DATASYNC) catch unreachable;

    // Submit. The kernel's SQ head says what it took, whatever io_uring_enter returned: EINTR
    // cuts only the wait; EAGAIN (no memory, a capped cgroup) and EBUSY (CQ overcommitted)
    // take nothing and are worth a retry after a pause (this ring has no other requests whose
    // completions could free room).
    var pauses: u32 = 0;
    while (ring.sq_ready() > 0) {
        _ = ring.submit_and_wait(2) catch |e| switch (e) {
            error.SignalInterrupt => continue,
            error.SystemResources, error.CompletionQueueOvercommitted => {
                pauses += 1;
                if (pauses > max_ring_pauses and ring.sq_ready() == 2) return error.Unusable;
                ringPause(pauses);
                continue;
            },
            // A refused enter took nothing (the SQ head did not move).
            else => if (ring.sq_ready() == 2) return error.Unusable else {
                pauses += 1;
                ringPause(pauses);
                continue;
            },
        };
    }

    // Reap both CQEs before the buffer goes back to the caller. Anything else in the CQ is
    // stale (it cannot be, by the invariant above) and dropped.
    var res_w: ?i32 = null;
    var res_s: ?i32 = null;
    pauses = 0;
    while (res_w == null or res_s == null) {
        var cqes: [4]linux.io_uring_cqe = undefined;
        const n = ring.copy_cqes(&cqes, 1) catch |e| switch (e) {
            error.SignalInterrupt => continue,
            else => {
                // The requests are in the kernel and reference `data`: keep waiting.
                pauses += 1;
                ringPause(pauses);
                continue;
            },
        };
        for (cqes[0..n]) |c| {
            if (c.user_data == tag_w) res_w = c.res else if (c.user_data == tag_s) res_s = c.res;
        }
    }
    std.debug.assert(ring.sq_ready() == 0);

    const rw = res_w.?;
    if (rw < 0) return switch (@as(linux.E, @enumFromInt(-rw))) {
        // Some file systems return EAGAIN for a blocking write; a signal can cut one short.
        .INTR, .AGAIN => error.Short,
        .NOSPC, .DQUOT => error.NoSpace,
        else => error.Failed,
    };
    // A short write breaks the link: the fdatasync completes with ECANCELED.
    if (@as(usize, @intCast(rw)) != data.len) return error.Short;
    if (res_s.? < 0) return error.Failed;
}

const max_ring_pauses = 64;

/// Backoff between refused io_uring_enter calls: 50 us doubling to 6.4 ms.
fn ringPause(n: u32) void {
    const us: u64 = @as(u64, 50) << @intCast(@min(n, 8) - 1);
    const ts: linux.timespec = .{ .sec = 0, .nsec = @intCast(us * 1000) };
    _ = linux.nanosleep(&ts, null);
}

test "real io round trip and growing map" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    const path = path_buf[0..n];
    const r = try RealIo.init(gpa, io, path, .{});
    defer r.deinit();
    const b: Backend = .{ .real = r };
    var nb: [64]u8 = undefined;
    const fd = try b.openFile(segName(&nb, 3), true);
    const view = try b.map(fd, 1 << 30);
    defer b.unmap(fd, view);
    try b.writeSync(fd, 0, "hello");
    try std.testing.expectEqualStrings("hello", view[0..5]);
    try b.write(fd, 8192, "world");
    try b.sync(fd);
    try std.testing.expectEqual(@as(u64, 8197), try b.size(fd));
    try std.testing.expectEqualStrings("world", view[8192..8197]);
    var buf: [5]u8 = undefined;
    try b.read(fd, 8192, &buf);
    try std.testing.expectEqualStrings("world", &buf);
    try b.truncate(fd, 5);
    try std.testing.expectEqual(@as(u64, 5), try b.size(fd));
    const segs = try b.listSegments(gpa);
    defer gpa.free(segs);
    try std.testing.expectEqualSlices(u64, &.{3}, segs);
    b.closeFile(fd);
    try std.testing.expect(b.exists(segName(&nb, 3)));
    try b.remove(segName(&nb, 3));
    try std.testing.expect(!b.exists(segName(&nb, 3)));
}

test "io_uring linked write+fdatasync matches the portable path (Linux)" {
    if (!is_linux) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    var data: [64 << 10]u8 = undefined;
    for (&data, 0..) |*x, i| x.* = @truncate(i *% 131 +% 7);
    var ns: [2]u64 = undefined;
    for ([_]bool{ true, false }, 0..) |uring, k| {
        var sub_buf: [600]u8 = undefined;
        const sub = try std.fmt.bufPrint(&sub_buf, "{s}/{d}", .{ path_buf[0..n], k });
        const r = try RealIo.init(gpa, io, sub, .{ .sync = .data, .uring = uring });
        defer r.deinit();
        if (uring and !r.usesUring()) return error.SkipZigTest; // kernel without io_uring
        try std.testing.expectEqual(uring, r.usesUring());
        const b: Backend = .{ .real = r };
        var nb: [64]u8 = undefined;
        const fd = try b.openFile(segName(&nb, 1), true);
        const view = try b.map(fd, 64 << 20);
        defer b.unmap(fd, view);
        const groups = 256;
        const t0 = @import("clock.zig").now();
        for (0..groups) |g| {
            data[0] = @truncate(g);
            try b.writeSync(fd, g * data.len, &data);
        }
        ns[k] = (@import("clock.zig").now() - t0) / groups;
        try std.testing.expectEqual(@as(u64, groups * data.len), try b.size(fd));
        for (0..groups) |g| {
            data[0] = @truncate(g);
            try std.testing.expectEqualSlices(u8, &data, view[g * data.len ..][0..data.len]);
            var back: [data.len]u8 = undefined;
            try b.read(fd, g * data.len, &back);
            try std.testing.expectEqualSlices(u8, &data, &back);
        }
    }
    std.debug.print("io_uring write+fdatasync 64 KiB: {d} ns/commit, pwrite+fdatasync: {d} ns/commit\n", .{ ns[0], ns[1] });
}

test "io_uring ring is empty after every commit; registered file + fixed buffer cost (Linux)" {
    // Measures what registered resources (IORING_REGISTER_FILES/BUFFERS,
    // IOSQE_FIXED_FILE + WRITE_FIXED) would save on the commit path, against the plain linked
    // write + fdatasync and pwrite + fdatasync, interleaved round by round.
    if (!is_linux) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    const r = try RealIo.init(gpa, io, path_buf[0..n], .{ .sync = .data });
    defer r.deinit();
    if (!r.usesUring()) return error.SkipZigTest;
    const b: Backend = .{ .real = r };
    var nb: [64]u8 = undefined;
    const fd = try b.openFile(segName(&nb, 1), true);
    const h = r.handle(fd);
    const buf = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(4096), 64 << 10);
    defer std.heap.page_allocator.free(buf);
    for (buf, 0..) |*x, i| x.* = @truncate(i *% 7);
    var fr = try linux.IoUring.init(8, 0);
    defer fr.deinit();
    try fr.register_files(&.{h});
    var iov = [_]std.posix.iovec{.{ .base = buf.ptr, .len = buf.len }};
    try fr.register_buffers(&iov);
    const clock = @import("clock.zig");
    const rounds = 8;
    const per = 64;
    for ([_]usize{ 4096, 64 << 10 }) |len| {
        var tot = [3]u64{ 0, 0, 0 };
        var off: u64 = 0;
        for (0..rounds) |_| for (0..3) |k| {
            const t0 = clock.now();
            for (0..per) |_| {
                switch (k) {
                    0 => try b.writeSync(fd, off, buf[0..len]),
                    1 => {
                        try b.write(fd, off, buf[0..len]);
                        try b.sync(fd);
                    },
                    else => {
                        var v: std.posix.iovec = .{ .base = buf.ptr, .len = len };
                        const w = try fr.write_fixed(1, 0, &v, off, 0);
                        w.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE;
                        const f = try fr.fsync(2, 0, linux.IORING_FSYNC_DATASYNC);
                        f.flags |= linux.IOSQE_FIXED_FILE;
                        _ = try fr.submit_and_wait(2);
                        for (0..2) |_| try std.testing.expect((try fr.copy_cqe()).res >= 0);
                    },
                }
                off += len;
            }
            tot[k] += clock.now() - t0;
        };
        try std.testing.expectEqual(@as(u32, 0), r.ring.?.sq_ready());
        try std.testing.expectEqual(@as(u32, 0), r.ring.?.cq_ready());
        const c = rounds * per;
        std.debug.print("commit {d} B: uring {d} ns, pwrite+fdatasync {d} ns, uring fixed file+buffer {d} ns\n", .{ len, tot[0] / c, tot[1] / c, tot[2] / c });
    }
}

test "commit durability cost: append vs overwrite of written blocks, fdatasync vs O_DIRECT|O_DSYNC (Linux)" {
    // An append changes the file size, so each fdatasync also commits the file system journal;
    // an overwrite of blocks already written and synced changes no metadata. O_DIRECT|O_DSYNC
    // makes the write itself durable (no separate fdatasync).
    if (!is_linux) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    const r = try RealIo.init(gpa, io, path_buf[0..n], .{ .sync = .data, .uring = false });
    defer r.deinit();
    const b: Backend = .{ .real = r };
    const per = 256;
    const buf = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(4096), 64 << 10);
    defer std.heap.page_allocator.free(buf);
    for (buf, 0..) |*x, i| x.* = @truncate(i *% 13);
    const clock = @import("clock.zig");
    for ([_]usize{ 4096, 64 << 10 }) |len| {
        var ns: [4]u64 = undefined;
        for (0..4) |k| {
            var nb: [64]u8 = undefined;
            const name = segName(&nb, 10 + k + len);
            const fd = try b.openFile(name, true);
            defer b.closeFile(fd);
            const overwrite = k == 1 or k == 3;
            if (overwrite) {
                var off: u64 = 0;
                while (off < per * len) : (off += buf.len) try b.write(fd, off, buf[0..@min(buf.len, per * len - off)]);
                try b.sync(fd);
            }
            const direct = k >= 2;
            var dh: std.posix.fd_t = -1;
            if (direct) {
                var zb: [80]u8 = undefined;
                @memcpy(zb[0..name.len], name);
                zb[name.len] = 0;
                const rc = linux.openat(r.root.handle, @ptrCast(&zb), .{ .ACCMODE = .RDWR, .DIRECT = true, .DSYNC = true, .CLOEXEC = true }, 0);
                if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest; // no O_DIRECT here
                dh = @intCast(rc);
            }
            defer if (direct) {
                _ = linux.close(dh);
            };
            const t0 = clock.now();
            for (0..per) |i| {
                if (direct) try b.pwriteAll(dh, i * len, buf[0..len]) else try b.writeSync(fd, i * len, buf[0..len]);
            }
            ns[k] = (clock.now() - t0) / per;
        }
        std.debug.print("durable commit {d} B: append+fdatasync {d} ns, overwrite+fdatasync {d} ns, append O_DIRECT|O_DSYNC {d} ns, overwrite O_DIRECT|O_DSYNC {d} ns\n", .{ len, ns[0], ns[1], ns[2], ns[3] });
    }
}
