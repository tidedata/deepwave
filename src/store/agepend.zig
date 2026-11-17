//! The ager's pending set (store.zig `Ager.pending`): locations of records whose successor the
//! object floor scan has seen below the object floor, kept until a pass (the object pass or the
//! checkpoint pass) visits them and turns them into holes.
//!
//! Bucketed by location: a bucket is `2^bits` bytes of one segment (16 MiB by default), with
//! its entries in a small hash set in memory and/or in extents of an append-only file of its
//! segment (`index/<epoch>.pend`) on disk. Every operation costs at most one bucket, never the
//! whole set, so a set of 50 million locations takes no longer per step than one of 50:
//!   - add: one hash insert; past the memory cap, the buckets the passes reach last (just
//!     below the object pass, needed only by the checkpoint pass; then the farthest ahead of
//!     the object pass) are written out whole and freed, down to seven eighths of the cap;
//!   - contains: one hash lookup; a bucket with entries on disk is read back whole when a pass
//!     (or the read-ahead, with no lock) first asks in it;
//!   - forget: a record turned into a hole leaves its bucket's memory (a bucket written out
//!     again carries only what is left);
//!   - prune: buckets both passes have left are dropped from the front of the list; a segment
//!     file goes once no bucket has an extent in it.
//! Files are scratch: never synced, removed at a clean close and at the next open (the scan
//! rebuilds the set from the durable marks). Every entry is true by itself (a dead record's
//! location), so an extent that cannot be read back (an I/O error, a checksum) only means
//! fewer holes, never a wrong one.
const std = @import("std");
const io_mod = @import("io.zig");
const cs = @import("checksum.zig");
const format = @import("format.zig");

const Backend = io_mod.Backend;
const Fd = io_mod.Fd;

const sum_seed: u64 = 0x70656e64;

const Extent = struct { off: u64, n: u64, sum: u64 };

const Set = std.AutoHashMapUnmanaged(u64, void);

const Bucket = struct {
    id: u64,
    /// Entries noted since the bucket was last written out: in memory only.
    mem: Set = .empty,
    /// Entries read back from its extents (`loaded`): on disk as well, so writing the bucket
    /// out again only frees them.
    cache: Set = .empty,
    loaded: bool = false,
    ext: std.ArrayList(Extent) = .empty,
    /// Entries in `ext` (with repeats: a location may be in two extents).
    disk_n: u64 = 0,
    /// Bytes counted for it in `Pending.mem_bytes` (`reacct`).
    acct: u64 = 0,
    /// Removals from each table since its last rebuild (each leaves a tombstone).
    mem_removed: u64 = 0,
    cache_removed: u64 = 0,

    fn bytes(b: *const Bucket) u64 {
        return (@as(u64, b.mem.capacity()) + b.cache.capacity()) * slot_bytes + b.ext.capacity * @sizeOf(Extent) + @sizeOf(Bucket);
    }
};

/// Bytes of one hash slot (a key and its metadata byte).
pub const slot_bytes = 9;

/// Extents a bucket gathers before it is written out as one (when it is next read back).
const max_extents = 8;

/// `live`: extents not yet dropped; `bytes`: theirs. A dead extent's whole blocks are punched
/// (one of 64 KiB or more starts on a block).
const SegFile = struct { epoch: u64, fd: Fd, len: u64, live: u64, bytes: u64 = 0 };

pub const Stats = struct {
    /// Entries written to disk, bucket writes, bucket reads, extents unreadable (I/O error or
    /// checksum: counted as empty), writes that failed (the bucket stayed in memory), adds
    /// refused because memory was at its hard cap and nothing could be written out.
    spilled: u64 = 0,
    spills: u64 = 0,
    loads: u64 = 0,
    read_errors: u64 = 0,
    write_errors: u64 = 0,
    refused: u64 = 0,
    /// Buckets dropped because both passes had left them.
    pruned: u64 = 0,
    /// Writes of a bucket a pass is in (nothing else left to write out), and buckets whose
    /// extents were written again as one.
    active_spills: u64 = 0,
    merges: u64 = 0,
};

pub const Pending = struct {
    /// Bucket span (bits of location). Set before the first add.
    bits: u6 = 24,
    /// Memory caps: entries and bytes held in memory (the buckets' tables). Past either, buckets
    /// are written out; past either by an eighth with nothing left to write, adds are refused.
    max_entries: u64 = 1 << 23,
    max_bytes: u64 = 64 << 20,
    /// Where the passes are (set by the ager before it adds): the eviction order.
    obj_at: u64 = 0,
    cp_at: u64 = 0,
    buckets: std.ArrayList(*Bucket) = .empty,
    files: std.ArrayList(SegFile) = .empty,
    /// Entries in memory (both tables of every bucket), of them those only in memory, and
    /// entries in extents.
    mem_n: u64 = 0,
    new_n: u64 = 0,
    mem_bytes: u64 = 0,
    disk_n: u64 = 0,
    /// Reused buffer for one bucket's keys (a write or a read).
    scratch: std.ArrayList(u64) = .empty,
    stats: Stats = .{},

    /// Frees everything. `remove`: the files go too (a clean close); else they are only closed
    /// (a crash, or a release without I/O: the next open removes them).
    pub fn deinit(p: *Pending, gpa: std.mem.Allocator, be: Backend, remove: bool) void {
        for (p.buckets.items) |b| freeBucket(gpa, b);
        p.buckets.deinit(gpa);
        for (p.files.items) |f| {
            be.closeFile(f.fd);
            if (remove) {
                var nb: [40]u8 = undefined;
                be.remove(fileName(&nb, f.epoch)) catch {};
            }
        }
        p.files.deinit(gpa);
        p.scratch.deinit(gpa);
        const keep_bits = p.bits;
        const keep_e = p.max_entries;
        const keep_b = p.max_bytes;
        p.* = .{ .bits = keep_bits, .max_entries = keep_e, .max_bytes = keep_b };
    }

    /// Entries (those on disk counted as written, repeats and forgotten ones included).
    pub fn count(p: *const Pending) u64 {
        return p.new_n + p.disk_n;
    }

    /// Bytes held in memory (tables, bucket list, scratch).
    pub fn memBytes(p: *const Pending) u64 {
        return p.mem_bytes + p.buckets.capacity * 8 + p.files.capacity * @sizeOf(SegFile) + p.scratch.capacity * 8;
    }

    /// Bytes of the live extents.
    pub fn diskBytes(p: *const Pending) u64 {
        var n: u64 = 0;
        for (p.files.items) |f| n += f.bytes;
        return n;
    }

    fn bucketIndex(p: *const Pending, id: u64) struct { i: usize, found: bool } {
        var lo: usize = 0;
        var hi: usize = p.buckets.items.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            const x = p.buckets.items[mid].id;
            if (x == id) return .{ .i = mid, .found = true };
            if (x < id) lo = mid + 1 else hi = mid;
        }
        return .{ .i = lo, .found = false };
    }

    fn find(p: *const Pending, l: u64) ?*Bucket {
        const at = p.bucketIndex(l >> p.bits);
        return if (at.found) p.buckets.items[at.i] else null;
    }

    /// Whether `l` is pending. A bucket with entries on disk is read back first (one bucket,
    /// once until it is written out again).
    pub fn contains(p: *Pending, gpa: std.mem.Allocator, be: Backend, l: u64) bool {
        const b = p.find(l) orelse return false;
        if (b.mem.contains(l) or b.cache.contains(l)) return true;
        if (b.loaded or b.ext.items.len == 0) return false;
        p.load(gpa, be, b);
        return b.cache.contains(l);
    }

    /// Whether `l` is pending in memory (no read).
    pub fn inMem(p: *const Pending, l: u64) bool {
        const b = p.find(l) orelse return false;
        return b.mem.contains(l) or b.cache.contains(l);
    }

    /// Notes `l`. Error.Full: memory at its hard cap and nothing could be written out (a
    /// write error; the caller counts it as dropped).
    pub fn add(p: *Pending, gpa: std.mem.Allocator, be: Backend, l: u64) error{ Full, OutOfMemory }!void {
        if (p.mem_n >= p.max_entries or p.mem_bytes >= p.max_bytes) p.evict(gpa, be, null);
        if (p.mem_n >= p.max_entries + p.max_entries / 8 or p.mem_bytes >= p.max_bytes + p.max_bytes / 8) {
            p.stats.refused += 1;
            return error.Full;
        }
        const id = l >> p.bits;
        const at = p.bucketIndex(id);
        const b = if (at.found) p.buckets.items[at.i] else blk: {
            try p.buckets.ensureUnusedCapacity(gpa, 1);
            const nb = try gpa.create(Bucket);
            nb.* = .{ .id = id };
            p.buckets.insertAssumeCapacity(at.i, nb);
            break :blk nb;
        };
        if (b.cache.contains(l)) return;
        const gop = try b.mem.getOrPut(gpa, l);
        p.reacct(b);
        if (!gop.found_existing) {
            p.mem_n += 1;
            p.new_n += 1;
        }
    }

    /// Forgets `l` (its record is a hole now). True if it was in memory. (One read back from
    /// disk comes back if its bucket is read again: the pass then finds a hole and forgets it
    /// again.) A table left empty is freed and one left sparse shrinks: a pass that empties
    /// the buckets it goes through frees their memory then, not when both passes have left
    /// them. (On an edge the checkpoint pass is 13 h behind: the object pass's emptied tables,
    /// kept at full size until then, took the memory, and adds were refused (seen
    /// 2026-11-13).)
    pub fn forget(p: *Pending, gpa: std.mem.Allocator, l: u64) bool {
        const b = p.find(l) orelse return false;
        if (b.mem.remove(l)) {
            p.new_n -= 1;
            b.mem_removed += 1;
            p.tidy(gpa, b, &b.mem, &b.mem_removed);
        } else if (b.cache.remove(l)) {
            b.cache_removed += 1;
            p.tidy(gpa, b, &b.cache, &b.cache_removed);
        } else return false;
        p.mem_n -= 1;
        return true;
    }

    fn tidy(p: *Pending, gpa: std.mem.Allocator, b: *Bucket, t: *Set, removed: *u64) void {
        const cap = t.capacity();
        if (t.count() == 0) {
            t.clearAndFree(gpa);
            removed.* = 0;
            p.reacct(b);
        } else if (removed.* >= cap / 4) {
            removed.* = 0;
            if (cap < 64 or t.count() * 4 >= cap) return t.rehash(std.hash_map.AutoContext(u64){});
            // Rebuilt at the size its entries need (in place without memory for the copy).
            var m: Set = .empty;
            m.ensureTotalCapacity(gpa, t.count()) catch return t.rehash(std.hash_map.AutoContext(u64){});
            var it = t.keyIterator();
            while (it.next()) |k| m.putAssumeCapacityNoClobber(k.*, {});
            t.deinit(gpa);
            t.* = m;
            p.reacct(b);
        }
    }

    /// Drops every bucket that ends at or before `behind` (both passes have left it).
    pub fn prune(p: *Pending, gpa: std.mem.Allocator, be: Backend, behind: u64) void {
        if (behind == 0) return;
        const first_kept = behind >> p.bits; // buckets below this id end at or before `behind`
        var n: usize = 0;
        while (n < p.buckets.items.len and p.buckets.items[n].id < first_kept) : (n += 1) {
            const b = p.buckets.items[n];
            p.mem_n -= b.mem.count() + b.cache.count();
            p.new_n -= b.mem.count();
            p.mem_bytes -= b.acct;
            p.disk_n -= b.disk_n;
            for (b.ext.items) |x| p.release(be, b.id, x);
            freeBucket(gpa, b);
            p.stats.pruned += 1;
        }
        if (n == 0) return;
        const rest = p.buckets.items.len - n;
        std.mem.copyForwards(*Bucket, p.buckets.items[0..rest], p.buckets.items[n..]);
        p.buckets.shrinkRetainingCapacity(rest);
    }

    /// Brings `mem_bytes` up to date with bucket `b`'s tables.
    fn reacct(p: *Pending, b: *Bucket) void {
        const now = b.bytes();
        p.mem_bytes = p.mem_bytes - b.acct + now;
        b.acct = now;
    }

    fn epochOfBucket(p: *const Pending, id: u64) u64 {
        return format.epochOf(id << p.bits);
    }

    /// One extent of bucket `id` is dead: its whole blocks are punched, and its file goes
    /// when it holds no live extent.
    fn release(p: *Pending, be: Backend, id: u64, x: Extent) void {
        const e = p.epochOfBucket(id);
        for (p.files.items, 0..) |*f, i| if (f.epoch == e) {
            f.live -= 1;
            f.bytes -|= x.n * 8;
            const lo = std.mem.alignForward(u64, x.off, format.block);
            const hi = std.mem.alignBackward(u64, x.off + x.n * 8, format.block);
            if (f.live != 0 and hi > lo) be.punch(f.fd, lo, hi - lo) catch {};
            if (f.live == 0) {
                be.closeFile(f.fd);
                var nb: [40]u8 = undefined;
                be.remove(fileName(&nb, e)) catch {};
                _ = p.files.swapRemove(i);
            }
            return;
        };
    }

    /// Frees memory until it is at seven eighths of its caps, bucket by bucket in the order the
    /// passes need them last: below the object pass from the top down (the checkpoint pass's
    /// bucket left), then above the object pass from the top down, then the buckets the passes
    /// are in. A bucket goes whole: what is only in memory is written as one more extent, what
    /// was read back is dropped (it is on disk). A pass that asks again reads its bucket back
    /// (a bucket's worth of reading), where a refused add lost the entry for good. Only `keep`
    /// (the bucket being read back) stays.
    fn evict(p: *Pending, gpa: std.mem.Allocator, be: Backend, keep: ?*Bucket) void {
        const ob = p.obj_at >> p.bits;
        const cb = p.cp_at >> p.bits;
        const n_lo = p.max_entries / 8 * 7;
        const b_lo = p.max_bytes / 8 * 7;
        var round: u8 = 0;
        while (round < 3) : (round += 1) {
            var i = p.buckets.items.len;
            while (i > 0) {
                if (p.mem_n <= n_lo and p.mem_bytes <= b_lo) return;
                i -= 1;
                const b = p.buckets.items[i];
                if (b == keep or b.mem.capacity() + b.cache.capacity() == 0) continue;
                const take = switch (round) {
                    0 => b.id < ob and b.id != cb,
                    1 => b.id > ob,
                    else => true,
                };
                if (!take) continue;
                if (round == 2) p.stats.active_spills += 1;
                p.spill(gpa, be, b) catch return; // a write error: stop (the caps then refuse)
            }
        }
    }

    /// Writes bucket `b` out and frees its tables: the entries only in memory as one more
    /// extent, or (read back, with `max_extents` extents) everything it holds as one extent in
    /// place of the others.
    fn spill(p: *Pending, gpa: std.mem.Allocator, be: Backend, b: *Bucket) !void {
        const merge = b.loaded and b.ext.items.len >= max_extents;
        const n = b.mem.count() + if (merge) b.cache.count() else 0;
        if (n > 0) {
            p.scratch.clearRetainingCapacity();
            try p.scratch.ensureTotalCapacity(gpa, n);
            var it = b.mem.keyIterator();
            while (it.next()) |k| p.scratch.appendAssumeCapacity(k.*);
            if (merge) {
                var ic = b.cache.keyIterator();
                while (ic.next()) |k| p.scratch.appendAssumeCapacity(k.*);
            }
            const data = std.mem.sliceAsBytes(p.scratch.items);
            const f = p.file(gpa, be, p.epochOfBucket(b.id)) catch |err| {
                p.stats.write_errors += 1;
                return err;
            };
            try b.ext.ensureUnusedCapacity(gpa, 1);
            if (data.len >= 64 << 10) f.len = std.mem.alignForward(u64, f.len, format.block);
            be.write(f.fd, f.len, data) catch |err| {
                p.stats.write_errors += 1;
                return err;
            };
            const x: Extent = .{ .off = f.len, .n = n, .sum = cs.hash(sum_seed ^ f.len, data) };
            f.len += data.len;
            f.live += 1;
            f.bytes += data.len;
            if (merge) {
                // The new extent first: a file is removed only when it holds no live extent.
                for (b.ext.items) |old| p.release(be, b.id, old);
                p.disk_n -= b.disk_n;
                b.disk_n = 0;
                b.ext.clearRetainingCapacity();
                p.stats.merges += 1;
            }
            b.ext.appendAssumeCapacity(x);
            b.disk_n += n;
            p.disk_n += n;
            p.stats.spilled += n;
            p.stats.spills += 1;
        }
        p.mem_n -= b.mem.count() + b.cache.count();
        p.new_n -= b.mem.count();
        b.mem.clearAndFree(gpa);
        b.cache.clearAndFree(gpa);
        b.mem_removed = 0;
        b.cache_removed = 0;
        b.loaded = false;
        p.reacct(b);
    }

    /// Reads bucket `b`'s extents back into its cache, then makes room elsewhere if that passed
    /// the caps. An extent that cannot be read counts as empty (counted).
    fn load(p: *Pending, gpa: std.mem.Allocator, be: Backend, b: *Bucket) void {
        const e = p.epochOfBucket(b.id);
        const fi = for (p.files.items, 0..) |f, i| {
            if (f.epoch == e) break i;
        } else null;
        p.stats.loads += 1;
        b.loaded = true;
        for (b.ext.items) |x| {
            const f = p.files.items[fi orelse {
                p.stats.read_errors += 1;
                continue;
            }];
            p.scratch.clearRetainingCapacity();
            p.scratch.resize(gpa, @intCast(x.n)) catch {
                p.stats.read_errors += 1;
                continue;
            };
            const data = std.mem.sliceAsBytes(p.scratch.items);
            be.read(f.fd, x.off, data) catch {
                p.stats.read_errors += 1;
                continue;
            };
            if (cs.hash(sum_seed ^ x.off, data) != x.sum) {
                p.stats.read_errors += 1;
                continue;
            }
            b.cache.ensureUnusedCapacity(gpa, @intCast(x.n)) catch {
                p.stats.read_errors += 1;
                continue;
            };
            for (p.scratch.items) |k| {
                if (b.mem.contains(k)) continue;
                const gop = b.cache.getOrPutAssumeCapacity(k);
                if (!gop.found_existing) p.mem_n += 1;
            }
            p.reacct(b);
        }
        p.reacct(b);
        if (p.mem_n > p.max_entries or p.mem_bytes > p.max_bytes) p.evict(gpa, be, b);
    }

    fn file(p: *Pending, gpa: std.mem.Allocator, be: Backend, epoch: u64) !*SegFile {
        for (p.files.items) |*f| if (f.epoch == epoch) return f;
        try p.files.ensureUnusedCapacity(gpa, 1);
        var nb: [40]u8 = undefined;
        const name = fileName(&nb, epoch);
        const fd = try be.openFile(name, true);
        be.truncate(fd, 0) catch |err| {
            be.closeFile(fd);
            return err;
        };
        p.files.appendAssumeCapacity(.{ .epoch = epoch, .fd = fd, .len = 0, .live = 0 });
        return &p.files.items[p.files.items.len - 1];
    }
};

fn freeBucket(gpa: std.mem.Allocator, b: *Bucket) void {
    b.mem.deinit(gpa);
    b.cache.deinit(gpa);
    b.ext.deinit(gpa);
    gpa.destroy(b);
}

pub fn fileName(buf: []u8, epoch: u64) []const u8 {
    return std.fmt.bufPrint(buf, "index/{d:0>8}.pend", .{epoch}) catch unreachable;
}

/// Whether `name` (inside `index/`) is a file of the pending set.
pub fn isFileName(name: []const u8) bool {
    return std.mem.endsWith(u8, name, ".pend");
}

fn testPending(bits: u6, max_entries: u64) Pending {
    return .{ .bits = bits, .max_entries = max_entries, .max_bytes = 1 << 30 };
}

test "pending set: buckets written out and read back keep every entry; prune drops only what is behind" {
    const gpa = std.testing.allocator;
    const sim = try @import("sim.zig").SimIo.init(gpa, 5, .{}, 4 << 20);
    defer sim.deinit();
    const be: Backend = .{ .sim = sim };
    var p = testPending(16, 1000);
    defer p.deinit(gpa, be, true);
    var prng: std.Random.DefaultPrng = .init(11);
    const rnd = prng.random();
    var all: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer all.deinit(gpa);
    // Two segments, 64 buckets each; the passes in the middle of the first.
    p.obj_at = format.loc(1, 32 << 16);
    p.cp_at = format.loc(1, 8 << 16);
    for (0..40_000) |_| {
        const l = format.loc(1 + rnd.uintLessThan(u64, 2), rnd.uintLessThan(u64, 64 << 16));
        try all.put(gpa, l, {});
        try p.add(gpa, be, l);
        try std.testing.expect(p.mem_n <= p.max_entries + p.max_entries / 8);
    }
    try std.testing.expectEqual(@as(u64, 0), p.stats.refused);
    try std.testing.expect(p.stats.spills > 10 and p.disk_n > 0);
    // Every entry answers (reading buckets back as asked), and nothing else does.
    var it = all.keyIterator();
    while (it.next()) |l| try std.testing.expect(p.contains(gpa, be, l.*));
    for (0..20_000) |_| {
        const l = format.loc(1 + rnd.uintLessThan(u64, 2), rnd.uintLessThan(u64, 64 << 16));
        try std.testing.expectEqual(all.contains(l), p.contains(gpa, be, l));
    }
    try std.testing.expect(p.stats.loads > 0);
    try std.testing.expectEqual(@as(u64, 0), p.stats.read_errors);
    // Forgotten entries leave memory and stay gone after their bucket is written out again.
    var gone: u64 = 0;
    it = all.keyIterator();
    while (it.next()) |l| {
        if (l.* & 1 == 0 and p.inMem(l.*)) {
            try std.testing.expect(p.forget(gpa, l.*));
            gone += 1;
        }
    }
    try std.testing.expect(gone > 0);
    // Prune: everything before the second segment goes, its file with it.
    p.prune(gpa, be, format.loc(2, 0));
    it = all.keyIterator();
    while (it.next()) |l| {
        if (l.* < format.loc(2, 0)) continue;
        try std.testing.expect(p.contains(gpa, be, l.*) or (l.* & 1 == 0));
    }
    for (p.buckets.items) |b| try std.testing.expect(b.id >= format.loc(2, 0) >> 16);
    for (p.files.items) |f| try std.testing.expect(f.epoch >= 2);
}

test "pending set: an extent that reads back damaged counts as empty, never as another entry" {
    const gpa = std.testing.allocator;
    const sim = try @import("sim.zig").SimIo.init(gpa, 6, .{}, 1 << 20);
    defer sim.deinit();
    const be: Backend = .{ .sim = sim };
    var p = testPending(20, 1 << 20);
    defer p.deinit(gpa, be, true);
    p.obj_at = format.loc(1, 1 << 30);
    for (0..4096) |i| try p.add(gpa, be, format.loc(1, 1000 + i * 2));
    const b = p.buckets.items[0];
    try p.spill(gpa, be, b);
    try std.testing.expectEqual(@as(u64, 0), b.mem.count());
    // Damage the extent on the page cache: its keys now name other locations.
    var junk: [64]u8 = undefined;
    for (&junk, 0..) |*x, i| x.* = @truncate(i * 7 + 1);
    try be.write(p.files.items[0].fd, 8, &junk);
    try std.testing.expect(!p.contains(gpa, be, format.loc(1, 1000)));
    try std.testing.expect(!p.contains(gpa, be, format.loc(1, 1001)));
    try std.testing.expect(p.stats.read_errors > 0);
    // (The extent stays on disk until its bucket is pruned: the file with it.)
}

test "pending set: adds pinned in the buckets the passes are in never refuse and lose nothing" {
    const gpa = std.testing.allocator;
    const sim = try @import("sim.zig").SimIo.init(gpa, 7, .{}, 8 << 20);
    defer sim.deinit();
    const be: Backend = .{ .sim = sim };
    // 1 MiB buckets, room for 1,000 entries: 60,000 adds, 95% of them in the object pass's
    // bucket or the checkpoint pass's (a live edge: the scan notes what the passes are at).
    var p = testPending(20, 1000);
    p.max_bytes = 64 << 10;
    defer p.deinit(gpa, be, true);
    p.obj_at = format.loc(1, (5 << 20) + 1000);
    p.cp_at = format.loc(1, (2 << 20) + 1000);
    var prng: std.Random.DefaultPrng = .init(12);
    const rnd = prng.random();
    var all: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer all.deinit(gpa);
    for (0..60_000) |i| {
        const r = rnd.uintLessThan(u32, 100);
        const base: u64 = if (r < 60) 5 << 20 else if (r < 95) 2 << 20 else @as(u64, rnd.uintLessThan(u64, 8)) << 20;
        const l = format.loc(1, base + rnd.uintLessThan(u64, 1 << 20));
        try all.put(gpa, l, {});
        try p.add(gpa, be, l); // error.Full fails the test
        try std.testing.expect(p.mem_n <= p.max_entries + p.max_entries / 8);
        try std.testing.expect(p.mem_bytes <= p.max_bytes + p.max_bytes / 8);
        // The passes ask in their buckets now and then (reading them back).
        if (i % 997 == 0) _ = p.contains(gpa, be, p.obj_at + i);
        if (i % 1499 == 0) _ = p.contains(gpa, be, p.cp_at + i);
    }
    try std.testing.expectEqual(@as(u64, 0), p.stats.refused);
    try std.testing.expect(p.stats.active_spills > 0);
    try std.testing.expect(p.count() >= all.count());
    // Every entry answers, asked in location order as a pass asks (a bucket read back once).
    var keys: std.ArrayList(u64) = .empty;
    defer keys.deinit(gpa);
    var it = all.keyIterator();
    while (it.next()) |l| try keys.append(gpa, l.*);
    std.mem.sort(u64, keys.items, {}, std.sort.asc(u64));
    for (keys.items) |l| try std.testing.expect(p.contains(gpa, be, l));
    try std.testing.expectEqual(@as(u64, 0), p.stats.read_errors + p.stats.write_errors);
}

test "pending set: a pass that empties the buckets it goes through frees their memory then" {
    const gpa = std.testing.allocator;
    const sim = try @import("sim.zig").SimIo.init(gpa, 8, .{}, 8 << 20);
    defer sim.deinit();
    const be: Backend = .{ .sim = sim };
    // The object pass empties bucket after bucket far ahead of the checkpoint pass (nothing is
    // pruned): 400 buckets of 2,000 entries each through a set with room for 4,000.
    var p = testPending(16, 4000);
    p.max_bytes = 1 << 20;
    defer p.deinit(gpa, be, true);
    p.cp_at = format.loc(1, 0);
    var keys: std.ArrayList(u64) = .empty;
    defer keys.deinit(gpa);
    for (0..400) |k| {
        keys.clearRetainingCapacity();
        p.obj_at = format.loc(1, @as(u64, k) << 16);
        for (0..2000) |j| {
            const l = format.loc(1, (@as(u64, k) << 16) + j * 8);
            try keys.append(gpa, l);
            try p.add(gpa, be, l);
        }
        for (keys.items) |l| try std.testing.expect(p.forget(gpa, l) or !p.inMem(l));
        try std.testing.expect(p.mem_bytes <= p.max_bytes);
    }
    try std.testing.expectEqual(@as(u64, 0), p.stats.refused);
    try std.testing.expectEqual(@as(u64, 0), p.mem_n);
    // What is left in memory: the bucket list's own records, no tables.
    try std.testing.expect(p.mem_bytes <= p.buckets.items.len * (@sizeOf(Bucket) + 16 * @sizeOf(Extent)));
}
