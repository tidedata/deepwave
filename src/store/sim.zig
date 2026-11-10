//! Deterministic simulated disk and clock (deterministic simulation testing). Every fault is drawn from a
//! seeded PRNG, so a seed replays bit for bit.
//!
//! Model: each file has a volatile image (the page cache: what reads and maps see) and a durable
//! image (the platter). Writes go to the volatile image and mark 512-byte sectors dirty; `sync`
//! moves dirty sectors (and the file length) to the durable image. Namespace changes (create,
//! remove) become durable at `syncDir`. A crash keeps an arbitrary subset of the unsynced work:
//!   - each dirty sector persists or not; a persisted sector may be torn (only a prefix of its
//!     new bytes lands) when `torn_sectors` is set;
//!   - an unsynced length change persists or not;
//!   - an unsynced create or remove persists or not (files vanish or come back).
//! Corruption faults, for corruption seeds only: `misdirect_ppm` sends a synced sector to the
//! wrong place, `rot` flips a byte of durable data (a latent sector error).
//! Whole-write faults (storage fault model), per seed:
//!   - `misdirect_write_ppm`: a write lands whole at a wrong place, a sector-aligned offset of
//!     the same file or of another file, on the disk image at once; its own target keeps the old
//!     bytes on disk (a lost write) while the page cache shows the new ones until a crash;
//!   - `crash_garble_pending`: a crash garbles the target of the pending write (the newest
//!     write whose sectors are still dirty, or the write the crash interrupted): each of its
//!     sectors becomes random bytes on disk with probability 1/2.
//! The clock advances by a random latency per operation with rare slow spikes.
//!
//! I/O error faults (`io_armed` only, so a harness can keep them out of its own checks):
//!   - `read_error_ppm`: a read fails with EIO, nothing read; the disk is fine (a transient
//!     media or transport error). Recovery must not mistake it for a torn or missing record;
//!   - `write_error_ppm`: a write fails with EIO or ENOSPC after a random whole-sector prefix of
//!     it reached the page cache (that prefix is dirty and may persist like any unsynced write);
//!   - `sync_error_ppm`: fdatasync fails with EIO, and, as Linux does after a failed write-back,
//!     each dirty sector either reached the disk or was dropped: marked clean while the page
//!     cache keeps the new bytes, so reads still see them and a later successful sync does not
//!     write them (fsyncgate). Only a crash shows the loss.
const std = @import("std");
const io_mod = @import("io.zig");

const Error = io_mod.Error;
const Fd = io_mod.Fd;

pub const sector = 512;

pub const Faults = struct {
    /// Probability (of 256) that an unsynced sector persists across a crash.
    persist_256: u16 = 128,
    /// Persisted sectors may hold only a prefix of their new bytes.
    torn_sectors: bool = true,
    /// Probability (of 256) that an unsynced create/remove/length change persists.
    meta_persist_256: u16 = 128,
    /// Per synced sector, parts per million that land at a wrong sector of the same file.
    misdirect_ppm: u32 = 0,
    latency_min_ns: u64 = 5_000,
    latency_max_ns: u64 = 120_000,
    slow_ppm: u32 = 2_000,
    slow_ns: u64 = 40_000_000,
    read_error_ppm: u32 = 0,
    write_error_ppm: u32 = 0,
    sync_error_ppm: u32 = 0,
    /// Per write, parts per million that land whole at a wrong place (see the header).
    misdirect_write_ppm: u32 = 0,
    /// A crash garbles the pending write's target sectors (see the header).
    crash_garble_pending: bool = false,
};

const SimFile = struct {
    name: [64]u8 = undefined,
    name_len: u8 = 0,
    used: bool = false,
    /// Exists in the volatile namespace.
    live: bool = false,
    /// Exists in the durable namespace.
    durable: bool = false,
    cache: []align(4096) u8 = &.{},
    disk: []align(4096) u8 = &.{},
    cache_len: u64 = 0,
    disk_len: u64 = 0,
    /// Highest length the volatile image ever reached (pages touched in `cache` and `disk`).
    hw: u64 = 0,
    dirty: std.DynamicBitSetUnmanaged = .{},

    fn nameOf(f: *const SimFile) []const u8 {
        return f.name[0..f.name_len];
    }
};

pub const Stats = struct {
    ops: u64 = 0,
    writes: u64 = 0,
    syncs: u64 = 0,
    bytes_written: u64 = 0,
    crashes: u64 = 0,
    sectors_lost: u64 = 0,
    sectors_torn: u64 = 0,
    files_lost: u64 = 0,
    files_resurrected: u64 = 0,
    misdirected: u64 = 0,
    rotted: u64 = 0,
    read_errors: u64 = 0,
    write_errors: u64 = 0,
    sync_errors: u64 = 0,
    /// Dirty sectors a failed sync marked clean without writing.
    sectors_dropped: u64 = 0,
    misdirected_writes: u64 = 0,
    /// 4096-byte blocks of segment files a misdirected write may have overwritten (each
    /// write: its blocks plus one for a straddle), so a harness can bound the groups it lost.
    misdirect_seg_blocks: u64 = 0,
    sectors_garbled: u64 = 0,
    clock_ns: u64 = 0,
};

pub const SimIo = struct {
    gpa: std.mem.Allocator,
    prng: std.Random.DefaultPrng,
    faults: Faults,
    file_cap: u64,
    files: []SimFile,
    /// fd -> file index (maxInt: closed)
    fds: []u32,
    /// Mutating operations left before the crash (null: no crash scheduled).
    crash_in: ?u64 = null,
    crashed: bool = false,
    /// I/O error faults apply only while set.
    io_armed: bool = false,
    stats: Stats = .{},
    /// Running hash of every operation and fault decision (determinism check).
    trace: u64 = 0,
    /// Targeted read errors (`failReads`), armed or not.
    fail_name: [64]u8 = undefined,
    fail_name_len: u8 = 0,
    fail_skip: u32 = 0,
    fail_left: u32 = 0,
    /// The pending write (crash_garble_pending): file index and byte range; `interrupted` when
    /// the crash hit the write itself (nothing of it reached the cache).
    pending: ?struct { file: u32, off: u64, len: u64, interrupted: bool } = null,

    pub fn init(gpa: std.mem.Allocator, seed: u64, faults: Faults, file_cap: u64) !*SimIo {
        const s = try gpa.create(SimIo);
        errdefer gpa.destroy(s);
        const files = try gpa.alloc(SimFile, 1024);
        errdefer gpa.free(files);
        @memset(files, .{});
        const fds = try gpa.alloc(u32, 4096);
        @memset(fds, std.math.maxInt(u32));
        s.* = .{ .gpa = gpa, .prng = .init(seed), .faults = faults, .file_cap = std.mem.alignForward(u64, file_cap, 4096), .files = files, .fds = fds };
        return s;
    }

    pub fn deinit(s: *SimIo) void {
        for (s.files) |*f| s.freeFile(f);
        s.gpa.free(s.files);
        s.gpa.free(s.fds);
        s.gpa.destroy(s);
    }

    fn freeFile(s: *SimIo, f: *SimFile) void {
        if (!f.used) return;
        if (s.pending) |pw| if (pw.file == f - s.files.ptr) {
            s.pending = null;
        };
        std.heap.page_allocator.free(f.cache);
        std.heap.page_allocator.free(f.disk);
        f.dirty.deinit(s.gpa);
        f.* = .{};
    }

    /// Bytes of file images touched now, by name prefix (memory diagnosis: ZUI_DST_MEM).
    pub const Touched = struct { files: u64 = 0, seg: u64 = 0, side: u64 = 0, age: u64 = 0, other: u64 = 0 };
    pub fn touched(s: *SimIo) Touched {
        var r: Touched = .{};
        for (s.files) |*f| {
            if (!f.used) continue;
            r.files += 1;
            const b = 2 * f.hw;
            const n = f.nameOf();
            if (std.mem.endsWith(u8, n, ".side")) r.side += b else if (std.mem.endsWith(u8, n, ".age")) r.age += b else if (std.mem.startsWith(u8, n, "seg")) r.seg += b else r.other += b;
        }
        return r;
    }

    fn rnd(s: *SimIo) std.Random {
        return s.prng.random();
    }

    fn mix(s: *SimIo, v: u64) void {
        s.trace = std.hash.Wyhash.hash(s.trace, std.mem.asBytes(&v));
    }

    fn tick(s: *SimIo) void {
        const r = s.rnd();
        var ns = r.intRangeAtMost(u64, s.faults.latency_min_ns, s.faults.latency_max_ns);
        if (r.uintLessThan(u32, 1_000_000) < s.faults.slow_ppm) ns += s.faults.slow_ns;
        s.stats.clock_ns += ns;
        s.stats.ops += 1;
    }

    fn ioFault(s: *SimIo, ppm: u32) bool {
        return s.io_armed and ppm != 0 and s.rnd().uintLessThan(u32, 1_000_000) < ppm;
    }

    /// Counts one mutating operation against the crash schedule.
    fn step(s: *SimIo) Error!void {
        if (s.crashed) return error.Crashed;
        if (s.crash_in) |*n| {
            if (n.* == 0) {
                s.crashed = true;
                return error.Crashed;
            }
            n.* -= 1;
        }
        s.tick();
    }

    /// After `skip` good reads of file `name`, its next `n` reads fail with EIO (a unit test's
    /// targeted transient error).
    pub fn failReads(s: *SimIo, name: []const u8, skip: u32, n: u32) void {
        @memcpy(s.fail_name[0..name.len], name);
        s.fail_name_len = @intCast(name.len);
        s.fail_skip = skip;
        s.fail_left = n;
    }

    pub fn scheduleCrash(s: *SimIo, ops: ?u64) void {
        s.crash_in = ops;
    }

    fn find(s: *SimIo, name: []const u8) ?*SimFile {
        for (s.files) |*f| if (f.used and f.live and std.mem.eql(u8, f.nameOf(), name)) return f;
        return null;
    }

    fn findAny(s: *SimIo, name: []const u8) ?*SimFile {
        for (s.files) |*f| if (f.used and std.mem.eql(u8, f.nameOf(), name)) return f;
        return null;
    }

    fn file(s: *SimIo, fd: Fd) *SimFile {
        return &s.files[s.fds[fd]];
    }

    pub fn openFile(s: *SimIo, name: []const u8, create: bool) Error!Fd {
        if (s.crashed) return error.Crashed;
        const f = s.find(name) orelse blk: {
            if (!create) return error.FileNotFound;
            try s.step();
            if (s.findAny(name)) |old| {
                // A removed (or never durable) file of the same name: reuse it, emptied.
                old.live = true;
                old.cache_len = 0;
                break :blk old;
            }
            const nf = for (s.files) |*x| {
                if (!x.used) break x;
            } else return error.TooManyFiles;
            nf.* = .{ .used = true, .live = true, .durable = false };
            @memcpy(nf.name[0..name.len], name);
            nf.name_len = @intCast(name.len);
            nf.cache = std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(4096), s.file_cap) catch return error.OutOfMemory;
            nf.disk = std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(4096), s.file_cap) catch return error.OutOfMemory;
            nf.dirty = std.DynamicBitSetUnmanaged.initEmpty(s.gpa, s.file_cap / sector) catch return error.OutOfMemory;
            break :blk nf;
        };
        const fd = for (s.fds, 0..) |x, i| {
            if (x == std.math.maxInt(u32)) break i;
        } else return error.TooManyFiles;
        s.fds[fd] = @intCast(f - s.files.ptr);
        s.mix(0x0f ^ fd);
        return @intCast(fd);
    }

    pub fn closeFile(s: *SimIo, fd: Fd) void {
        s.fds[fd] = std.math.maxInt(u32);
    }

    pub fn size(s: *SimIo, fd: Fd) Error!u64 {
        if (s.crashed) return error.Crashed;
        return s.file(fd).cache_len;
    }

    pub fn read(s: *SimIo, fd: Fd, off: u64, buf: []u8) Error!void {
        if (s.crashed) return error.Crashed;
        const f = s.file(fd);
        if (off + buf.len > f.cache_len) return error.ShortRead;
        s.tick();
        if (s.fail_left > 0 and std.mem.eql(u8, f.nameOf(), s.fail_name[0..s.fail_name_len])) {
            if (s.fail_skip > 0) s.fail_skip -= 1 else {
                s.fail_left -= 1;
                s.stats.read_errors += 1;
                return error.Io;
            }
        }
        if (s.ioFault(s.faults.read_error_ppm)) {
            s.stats.read_errors += 1;
            s.mix(0x4e ^ off);
            return error.Io;
        }
        @memcpy(buf, f.cache[off..][0..buf.len]);
    }

    pub fn write(s: *SimIo, fd: Fd, off: u64, data: []const u8) Error!void {
        const was_crashed = s.crashed;
        s.step() catch |e| {
            if (!was_crashed and s.faults.crash_garble_pending and data.len > 0)
                s.pending = .{ .file = s.fds[fd], .off = off, .len = data.len, .interrupted = true };
            return e;
        };
        const f = s.file(fd);
        if (off + data.len > s.file_cap) return error.NoSpace;
        var len = data.len;
        var fail: ?Error = null;
        if (data.len > 0 and s.ioFault(s.faults.write_error_ppm)) {
            // A whole-sector prefix lands (possibly none of it), then the error.
            const r = s.rnd();
            const first_end = @min(data.len, std.mem.alignForward(u64, off + 1, sector) - off);
            const cut = r.uintLessThan(u64, (data.len - first_end + sector - 1) / sector + 1);
            len = if (r.boolean()) 0 else @min(data.len, first_end + cut * sector);
            fail = if (r.uintLessThan(u8, 4) == 0) error.NoSpace else error.Io;
            s.stats.write_errors += 1;
            s.mix(0x3e ^ off ^ len);
        }
        if (off > f.cache_len and len > 0) @memset(f.cache[f.cache_len..off], 0);
        @memcpy(f.cache[off..][0..len], data[0..len]);
        if (len > 0) f.cache_len = @max(f.cache_len, off + len);
        f.hw = @max(f.hw, f.cache_len);
        const misdirected = len > 0 and fail == null and s.faults.misdirect_write_ppm != 0 and
            s.rnd().uintLessThan(u32, 1_000_000) < s.faults.misdirect_write_ppm;
        if (misdirected) {
            s.misdirectWrite(f, data[0..len]);
        } else if (len > 0) {
            var sct = off / sector;
            while (sct * sector < off + len) : (sct += 1) f.dirty.set(sct);
            if (s.faults.crash_garble_pending) s.pending = .{ .file = s.fds[fd], .off = off, .len = len, .interrupted = false };
        }
        if (fail) |e| return e;
        s.stats.writes += 1;
        s.stats.bytes_written += data.len;
        s.mix(off ^ data.len ^ (@as(u64, fd) << 48));
    }

    /// A misdirected write: `data` goes straight to the disk image at a sector-aligned offset
    /// of this file or another live one (half each), never to its own target, which stays
    /// clean (the page cache shows the new bytes; the disk keeps the old ones).
    fn misdirectWrite(s: *SimIo, own: *SimFile, data: []const u8) void {
        const r = s.rnd();
        var t = own;
        if (r.boolean()) {
            var cand: [1024]u16 = undefined;
            var n: usize = 0;
            for (s.files, 0..) |*x, i| if (x.used and x.live and x != own and x.disk_len > 0) {
                cand[n] = @intCast(i);
                n += 1;
            };
            if (n > 0) t = &s.files[cand[r.uintLessThan(usize, n)]];
        }
        const span = @max(t.disk_len, data.len);
        var at = sector * r.uintLessThan(u64, std.math.divCeil(u64, span, sector) catch unreachable);
        if (at + data.len > s.file_cap) at = (s.file_cap - data.len) / sector * sector;
        @memcpy(t.disk[at..][0..data.len], data);
        t.hw = @max(t.hw, at + data.len);
        s.stats.misdirected_writes += 1;
        if (std.mem.startsWith(u8, t.nameOf(), "seg/")) s.stats.misdirect_seg_blocks += (std.math.divCeil(u64, data.len, 4096) catch unreachable) + 1;
        s.mix(0x6d ^ at ^ (@as(u64, @intCast(t - s.files.ptr)) << 40));
    }

    pub fn sync(s: *SimIo, fd: Fd) Error!void {
        try s.step();
        const f = s.file(fd);
        var it = f.dirty.iterator(.{});
        const r = s.rnd();
        const nsect = s.file_cap / sector;
        if (s.ioFault(s.faults.sync_error_ppm)) {
            // Write-back failed part way: each dirty sector reached the disk or was dropped
            // (clean in the cache, never written); the length change too.
            while (it.next()) |sct| {
                if (r.boolean()) {
                    @memcpy(f.disk[sct * sector ..][0..sector], f.cache[sct * sector ..][0..sector]);
                } else s.stats.sectors_dropped += 1;
            }
            f.dirty.unsetAll();
            if (r.boolean()) f.disk_len = f.cache_len;
            s.stats.sync_errors += 1;
            s.mix(0x2e ^ fd);
            return error.Io;
        }
        while (it.next()) |sct| {
            var dst = sct;
            if (s.faults.misdirect_ppm != 0 and r.uintLessThan(u32, 1_000_000) < s.faults.misdirect_ppm) {
                dst = r.uintLessThan(u64, @max(1, @min(nsect, std.math.divCeil(u64, f.cache_len, sector) catch unreachable)));
                s.stats.misdirected += 1;
            }
            @memcpy(f.disk[dst * sector ..][0..sector], f.cache[sct * sector ..][0..sector]);
        }
        f.dirty.unsetAll();
        f.disk_len = f.cache_len;
        s.stats.syncs += 1;
        s.mix(0x5c ^ fd);
    }

    pub fn writeSync(s: *SimIo, fd: Fd, off: u64, data: []const u8) Error!void {
        try s.write(fd, off, data);
        try s.sync(fd);
    }

    pub fn truncate(s: *SimIo, fd: Fd, len: u64) Error!void {
        try s.step();
        const f = s.file(fd);
        if (len > s.file_cap) return error.NoSpace;
        if (len > f.cache_len) {
            // Extension reads as zeros.
            @memset(f.cache[f.cache_len..len], 0);
            var sct = f.cache_len / sector;
            while (sct * sector < len) : (sct += 1) f.dirty.set(sct);
        }
        if (len < f.cache_len) {
            @memset(f.cache[len..f.cache_len], 0);
            var sct = len / sector;
            while (sct * sector < f.cache_len) : (sct += 1) f.dirty.set(sct);
        }
        f.cache_len = len;
        f.hw = @max(f.hw, len);
        s.mix(0x7e ^ len);
    }

    /// Hole punch: the range reads as zeros at once; like any unsynced change, a crash keeps it
    /// sector by sector or not at all.
    pub fn punch(s: *SimIo, fd: Fd, off: u64, len: u64) Error!void {
        try s.step();
        const f = s.file(fd);
        const end = @min(off + len, f.cache_len);
        if (off >= end) return;
        @memset(f.cache[off..end], 0);
        var sct = off / sector;
        while (sct * sector < end) : (sct += 1) f.dirty.set(sct);
        s.mix(0x9c ^ off ^ len);
    }

    pub fn allocated(s: *SimIo, fd: Fd) Error!u64 {
        if (s.crashed) return error.Crashed;
        const f = s.file(fd);
        var n: u64 = 0;
        var p: u64 = 0;
        while (p < f.cache_len) : (p += 4096) {
            const blk = f.cache[p..@min(p + 4096, f.cache_len)];
            if (std.mem.indexOfNone(u8, blk, &.{0}) != null) n += 4096;
        }
        return n;
    }

    pub fn remove(s: *SimIo, name: []const u8) Error!void {
        try s.step();
        if (s.find(name)) |f| f.live = false;
        s.mix(0x4e ^ name.len);
    }

    pub fn syncDir(s: *SimIo) Error!void {
        try s.step();
        for (s.files) |*f| {
            if (!f.used) continue;
            f.durable = f.live;
            // A removed file is gone for good once the removal is durable.
            if (!f.live and !s.isOpen(f)) s.freeFile(f);
        }
        s.mix(0xd1);
    }

    fn isOpen(s: *SimIo, f: *const SimFile) bool {
        const idx: u32 = @intCast(f - s.files.ptr);
        for (s.fds) |x| if (x == idx) return true;
        return false;
    }

    pub fn map(s: *SimIo, fd: Fd, reserve: u64) Error![]const u8 {
        if (s.crashed) return error.Crashed;
        const f = s.file(fd);
        return f.cache[0..@min(s.file_cap, std.mem.alignForward(u64, @max(reserve, 1), 4096))];
    }

    pub fn unmap(s: *SimIo, fd: Fd, view: []const u8) void {
        _ = s;
        _ = fd;
        _ = view;
    }

    /// A private writable view: a separate copy of the file's current bytes.
    pub fn mapRw(s: *SimIo, fd: Fd, len: u64) Error![]align(4096) u8 {
        if (s.crashed) return error.Crashed;
        const f = s.file(fd);
        if (len > s.file_cap) return error.NoSpace;
        const v = std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(4096), @max(len, 1)) catch return error.OutOfMemory;
        const n = @min(len, f.cache_len);
        @memcpy(v[0..n], f.cache[0..n]);
        @memset(v[n..], 0);
        return v[0..len];
    }

    pub fn unmapRw(s: *SimIo, fd: Fd, view: []align(4096) u8) void {
        _ = s;
        _ = fd;
        std.heap.page_allocator.free(view.ptr[0..@max(view.len, 1)]);
    }

    /// Checks that the private view equals the file (the store's contract) and resyncs it.
    pub fn dropPrivate(s: *SimIo, fd: Fd, view: []align(4096) u8) Error!void {
        if (s.crashed) return error.Crashed;
        const f = s.file(fd);
        const n = @min(view.len, f.cache_len);
        std.debug.assert(std.mem.eql(u8, view[0..n], f.cache[0..n]));
        @memcpy(view[0..n], f.cache[0..n]);
    }

    pub fn dropRange(s: *SimIo, fd: Fd, view: []align(4096) u8, off: u64, len: u64) Error!void {
        if (s.crashed) return error.Crashed;
        const f = s.file(fd);
        const end = @min(off + len, view.len);
        if (off >= end) return;
        const n = @min(end, f.cache_len) -| off;
        // Equal but for the page checksums (a background flush seals its copies, not the view);
        // the view then takes the file's bytes, as a real mapping does.
        var q: u64 = 0;
        while (q < n) : (q += 4096) {
            const m = @min(4096, n - q) -| 8;
            std.debug.assert(std.mem.eql(u8, view[off + q ..][0..m], f.cache[off + q ..][0..m]));
        }
        @memcpy(view[off..][0..n], f.cache[off..][0..n]);
    }

    pub fn listDir(s: *SimIo, gpa: std.mem.Allocator, sub: []const u8) Error![][]u8 {
        if (s.crashed) return error.Crashed;
        var list: std.ArrayList([]u8) = .empty;
        errdefer {
            for (list.items) |x| gpa.free(x);
            list.deinit(gpa);
        }
        for (s.files) |*f| {
            if (!f.used or !f.live) continue;
            const n = f.nameOf();
            if (n.len <= sub.len + 1 or !std.mem.startsWith(u8, n, sub) or n[sub.len] != '/') continue;
            const rest = n[sub.len + 1 ..];
            if (std.mem.indexOfScalar(u8, rest, '/') != null) continue;
            try list.append(gpa, try gpa.dupe(u8, rest));
        }
        return list.toOwnedSlice(gpa);
    }

    pub fn listSegments(s: *SimIo, gpa: std.mem.Allocator) Error![]u64 {
        if (s.crashed) return error.Crashed;
        var list: std.ArrayList(u64) = .empty;
        errdefer list.deinit(gpa);
        for (s.files) |*f| {
            if (!f.used or !f.live) continue;
            const n = f.nameOf();
            if (!std.mem.startsWith(u8, n, "seg/")) continue;
            if (io_mod.parseSegName(n[4..])) |e| try list.append(gpa, e);
        }
        std.mem.sort(u64, list.items, {}, std.sort.asc(u64));
        return list.toOwnedSlice(gpa);
    }

    pub fn exists(s: *SimIo, name: []const u8) bool {
        return s.find(name) != null;
    }

    /// Power loss: applies the fault model to every unsynced change, then resets the volatile
    /// state to what the disk holds. All descriptors are closed.
    pub fn crash(s: *SimIo) void {
        const r = s.rnd();
        s.stats.crashes += 1;
        if (s.pending) |pw| garble: {
            s.pending = null;
            const f = &s.files[pw.file];
            if (!f.used) break :garble;
            var sct = pw.off / sector;
            const end = @min(pw.off + pw.len, s.file_cap);
            while (sct * sector < end) : (sct += 1) {
                if (!pw.interrupted and !f.dirty.isSet(sct)) continue;
                if (!r.boolean()) continue;
                r.bytes(f.disk[sct * sector ..][0..sector]);
                f.dirty.unset(sct);
                f.hw = @max(f.hw, (sct + 1) * sector);
                s.stats.sectors_garbled += 1;
            }
            s.mix(0x9a ^ pw.off);
        }
        for (s.files) |*f| {
            if (!f.used) continue;
            var it = f.dirty.iterator(.{});
            while (it.next()) |sct| {
                if (r.uintLessThan(u16, 256) < s.faults.persist_256) {
                    var n: usize = sector;
                    if (s.faults.torn_sectors and r.boolean()) {
                        n = r.uintLessThan(usize, sector);
                        s.stats.sectors_torn += 1;
                    }
                    @memcpy(f.disk[sct * sector ..][0..n], f.cache[sct * sector ..][0..n]);
                } else s.stats.sectors_lost += 1;
            }
            f.dirty.unsetAll();
            if (f.cache_len != f.disk_len and r.uintLessThan(u16, 256) < s.faults.meta_persist_256) f.disk_len = f.cache_len;
            if (f.live != f.durable) {
                if (r.uintLessThan(u16, 256) < s.faults.meta_persist_256) {
                    f.durable = f.live;
                } else if (f.durable) s.stats.files_resurrected += 1 else s.stats.files_lost += 1;
            }
            f.live = f.durable;
            if (!f.live) {
                s.freeFile(f);
                continue;
            }
            const keep = f.cache_len;
            @memcpy(f.cache[0..f.disk_len], f.disk[0..f.disk_len]);
            if (keep > f.disk_len) @memset(f.cache[f.disk_len..keep], 0);
            f.cache_len = f.disk_len;
            s.mix(f.disk_len);
        }
        @memset(s.fds, std.math.maxInt(u32));
        s.crashed = false;
        s.crash_in = null;
    }

    /// Latent sector error: flips one byte of durable data in a random file whose name starts
    /// with `prefix`. Returns false when there is nothing to damage.
    pub fn rot(s: *SimIo, prefix: []const u8) bool {
        const r = s.rnd();
        var candidates: [1024]u16 = undefined;
        var n: usize = 0;
        for (s.files, 0..) |*f, i| {
            if (f.used and f.live and f.disk_len > 0 and std.mem.startsWith(u8, f.nameOf(), prefix)) {
                candidates[n] = @intCast(i);
                n += 1;
            }
        }
        if (n == 0) return false;
        const f = &s.files[candidates[r.uintLessThan(usize, n)]];
        const at = r.uintLessThan(u64, f.disk_len);
        const bit: u8 = @as(u8, 1) << r.int(u3);
        f.disk[at] ^= bit;
        f.cache[at] ^= bit;
        s.stats.rotted += 1;
        return true;
    }
    /// A lost write at a chosen place: `len` bytes of the durable data of file `name` from
    /// `off` read back as zeros. Returns false when the file or range does not exist.
    pub fn zeroAt(s: *SimIo, name: []const u8, off: u64, len: u64) bool {
        const f = s.find(name) orelse return false;
        if (off + len > f.disk_len) return false;
        @memset(f.disk[off..][0..len], 0);
        @memset(f.cache[off..][0..len], 0);
        return true;
    }

    /// Latent sector error at a chosen place: flips one bit of byte `off` of the durable data
    /// of file `name`. Returns false when the file or byte does not exist.
    pub fn rotAt(s: *SimIo, name: []const u8, off: u64) bool {
        const f = s.find(name) orelse return false;
        if (off >= f.disk_len) return false;
        const bit: u8 = @as(u8, 1) << s.rnd().int(u3);
        f.disk[off] ^= bit;
        f.cache[off] ^= bit;
        s.stats.rotted += 1;
        return true;
    }
};

test "sim crash keeps synced data and may lose the rest" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 1, .{ .persist_256 = 0, .meta_persist_256 = 0 }, 1 << 20);
    defer sim.deinit();
    const fd = try sim.openFile("seg/00000001.log", true);
    try sim.syncDir();
    try sim.writeSync(fd, 0, "durable!");
    try sim.write(fd, 4096, "volatile");
    sim.crash();
    const fd2 = try sim.openFile("seg/00000001.log", false);
    try std.testing.expectEqual(@as(u64, 8), try sim.size(fd2));
    var b: [8]u8 = undefined;
    try sim.read(fd2, 0, &b);
    try std.testing.expectEqualStrings("durable!", &b);
    // an unsynced create vanishes
    _ = try sim.openFile("index/x", true);
    sim.crash();
    try std.testing.expect(!sim.exists("index/x"));
}

test "sim crash schedule" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 2, .{}, 1 << 16);
    defer sim.deinit();
    const fd = try sim.openFile("meta", true);
    sim.scheduleCrash(1);
    try sim.write(fd, 0, "a");
    try std.testing.expectError(error.Crashed, sim.sync(fd));
    try std.testing.expectError(error.Crashed, sim.write(fd, 0, "b"));
    sim.crash();
    try std.testing.expect(!sim.crashed);
}
