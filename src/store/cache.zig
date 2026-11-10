//! Decoded-chunk cache for compressed segments (chunk.zig). Sharded, CLOCK eviction, a byte
//! budget. Readers on any thread look up and insert; an evicted buffer is unpublished at once
//! (no new reader can find it) but only freed once no reader that got it can still be running
//! (`takeEvicted` -> `Store.chunkReclaim`), so a slice a reader got stays valid until its
//! snapshot ends. Any thread may run that reclaim (readers too: a store that only serves reads
//! must not grow its evicted list without bound).
//!
//! Which readers got a chunk: every snapshot registers a reader epoch (`Readers`), and each
//! lookup or insert widens the item's [lo, hi] range of reader epochs under the shard lock. An
//! evicted item is freed once no registered epoch falls in its range. A long-lived snapshot so
//! pins the chunks it read (plus chunks another reader got on both sides of its epoch, at most
//! what the cache held when it started), never everything evicted while it lives: a grace
//! period over all readers (the two-counter SRCU this replaced) let one snapshot held across
//! commits pin every chunk evicted after it began (box 1, 2026-11-08: a 20-minute startup seed
//! under one snapshot pinned ~1M chunks, 33 GB of heap).
const std = @import("std");

pub const nshards = 64;

pub const Item = struct {
    key: u64,
    data: []u8,
    ref: std.atomic.Value(bool) = .init(true),
    /// Reader epochs that got `data` (shard lock): lo > hi when no reader did (the writer's
    /// seeding inserts).
    lo: u64 = std.math.maxInt(u64),
    hi: u64 = 0,

    fn note(it: *Item, ep: ?u64) void {
        const e = ep orelse return;
        it.lo = @min(it.lo, e);
        it.hi = @max(it.hi, e);
    }
};

pub const Spin = struct {
    v: std.atomic.Value(u32) = .init(0),
    pub fn lock(s: *Spin) void {
        while (s.v.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    pub fn tryLock(s: *Spin) bool {
        return s.v.cmpxchgStrong(0, 1, .acquire, .monotonic) == null;
    }
    pub fn unlock(s: *Spin) void {
        s.v.store(0, .release);
    }
};

const Shard = struct {
    lock: Spin = .{},
    map: std.AutoHashMapUnmanaged(u64, *Item) = .empty,
    clock: std.ArrayList(*Item) = .empty,
    hand: usize = 0,
    bytes: u64 = 0,
};

pub const Stats = struct {
    hits: std.atomic.Value(u64) = .init(0),
    misses: std.atomic.Value(u64) = .init(0),
    evictions: std.atomic.Value(u64) = .init(0),
    /// A miss's pread + frame check + decode, summed and the slowest (store.chunkData).
    miss_ns: std.atomic.Value(u64) = .init(0),
    miss_max_ns: std.atomic.Value(u64) = .init(0),
    miss_bytes: std.atomic.Value(u64) = .init(0),
    /// Evicted chunks freed, and those a reader still held when first reclaimed (pinned).
    freed: std.atomic.Value(u64) = .init(0),
    pinned: std.atomic.Value(u64) = .init(0),
};

pub const Cache = struct {
    /// Bookkeeping: shard maps, clock rings, the evicted list.
    gpa: std.mem.Allocator,
    /// Decoded chunk bytes and their items (the store's use-after-release guard swaps in
    /// guard.allocator here); `put` takes data allocated with it.
    mem: std.mem.Allocator,
    shard_budget: u64,
    shards: [nshards]Shard = @splat(.{}),
    ev_lock: Spin = .{},
    evicted: std.ArrayList(*Item) = .empty,
    evicted_bytes: std.atomic.Value(u64) = .init(0),
    stats: Stats = .{},

    pub fn init(gpa: std.mem.Allocator, budget: u64) Cache {
        return .{ .gpa = gpa, .mem = gpa, .shard_budget = @max(budget / nshards, 1 << 16) };
    }

    /// No readers may exist.
    pub fn deinit(c: *Cache) void {
        for (&c.shards) |*sh| {
            for (sh.clock.items) |it| c.free(it);
            sh.clock.deinit(c.gpa);
            sh.map.deinit(c.gpa);
        }
        for (c.evicted.items) |it| c.free(it);
        c.evicted.deinit(c.gpa);
    }

    pub fn free(c: *Cache, it: *Item) void {
        c.mem.free(it.data);
        c.mem.destroy(it);
    }

    fn shardOf(c: *Cache, key: u64) *Shard {
        const h = key *% 0x9e3779b97f4a7c15;
        return &c.shards[@intCast(h >> 58)];
    }

    /// `ep`: the reader epoch of the snapshot that will use the slice (Readers.enter).
    pub fn get(c: *Cache, key: u64, ep: u64) ?[]const u8 {
        const sh = c.shardOf(key);
        sh.lock.lock();
        defer sh.lock.unlock();
        const it = sh.map.get(key) orelse {
            _ = c.stats.misses.fetchAdd(1, .monotonic);
            return null;
        };
        it.note(ep);
        it.ref.store(true, .monotonic);
        _ = c.stats.hits.fetchAdd(1, .monotonic);
        return it.data;
    }

    /// Inserts `data` (allocated with `mem`; the cache owns it from here) and returns the cached
    /// slice: `data`, or the copy another thread inserted first (then `data` is freed). `ep`: the
    /// reader epoch that uses the slice, null for an insert nobody reads (the writer's seeding).
    pub fn put(c: *Cache, key: u64, data: []u8, ep: ?u64) error{OutOfMemory}![]const u8 {
        const it = c.mem.create(Item) catch {
            c.mem.free(data);
            return error.OutOfMemory;
        };
        it.* = .{ .key = key, .data = data };
        it.note(ep);
        const sh = c.shardOf(key);
        sh.lock.lock();
        defer sh.lock.unlock();
        if (sh.map.get(key)) |old| {
            c.free(it);
            old.note(ep);
            return old.data;
        }
        sh.map.put(c.gpa, key, it) catch {
            c.free(it);
            return error.OutOfMemory;
        };
        sh.clock.append(c.gpa, it) catch {
            _ = sh.map.remove(key);
            c.free(it);
            return error.OutOfMemory;
        };
        sh.bytes += data.len;
        c.evictLocked(sh, it);
        return data;
    }

    /// CLOCK until the shard is within budget (never evicts `keep`).
    fn evictLocked(c: *Cache, sh: *Shard, keep: *Item) void {
        var spins: usize = 0;
        while (sh.bytes > c.shard_budget and sh.clock.items.len > 1 and spins < 4 * sh.clock.items.len) : (spins += 1) {
            if (sh.hand >= sh.clock.items.len) sh.hand = 0;
            const it = sh.clock.items[sh.hand];
            if (it == keep or it.ref.swap(false, .monotonic)) {
                sh.hand += 1;
                continue;
            }
            _ = sh.clock.swapRemove(sh.hand);
            _ = sh.map.remove(it.key);
            sh.bytes -= it.data.len;
            _ = c.stats.evictions.fetchAdd(1, .monotonic);
            c.ev_lock.lock();
            defer c.ev_lock.unlock();
            c.evicted.append(c.gpa, it) catch {
                // Leak rather than free under a reader.
                continue;
            };
            _ = c.evicted_bytes.fetchAdd(it.data.len, .monotonic);
        }
    }

    /// Whether `key` is cached (no stats, no reference bit: read-ahead asks before it reads).
    pub fn contains(c: *Cache, key: u64) bool {
        const sh = c.shardOf(key);
        sh.lock.lock();
        defer sh.lock.unlock();
        return sh.map.contains(key);
    }

    /// Evicts `key` now (its buffer is freed like any eviction, once no reader holds it): the
    /// chunk was rewritten by age-out.
    pub fn drop(c: *Cache, key: u64) void {
        const sh = c.shardOf(key);
        sh.lock.lock();
        defer sh.lock.unlock();
        const it = sh.map.get(key) orelse return;
        _ = sh.map.remove(key);
        for (sh.clock.items, 0..) |x, i| if (x == it) {
            _ = sh.clock.swapRemove(i);
            break;
        };
        if (sh.hand >= sh.clock.items.len) sh.hand = 0;
        sh.bytes -= it.data.len;
        c.ev_lock.lock();
        defer c.ev_lock.unlock();
        c.evicted.append(c.gpa, it) catch return; // leak rather than free under a reader
        _ = c.evicted_bytes.fetchAdd(it.data.len, .monotonic);
    }

    /// Moves the evicted items to `out` (the caller frees them once no reader can have them).
    pub fn takeEvicted(c: *Cache, out: *std.ArrayList(*Item)) void {
        c.ev_lock.lock();
        defer c.ev_lock.unlock();
        std.mem.swap(std.ArrayList(*Item), out, &c.evicted);
        c.evicted_bytes.store(0, .monotonic);
    }

    pub fn bytes(c: *Cache) u64 {
        var b: u64 = 0;
        for (&c.shards) |*sh| b += @atomicLoad(u64, &sh.bytes, .monotonic);
        return b;
    }
};

/// The reader epochs of live snapshots (see the file comment). A snapshot registers at the
/// current epoch (`enter`) and leaves at release (`exit`); the reclaimer advances the epoch, so
/// readers that start after an item's eviction never fall in its range. Entries are kept in
/// epoch order with a count each; when the table is full a reader joins the newest entry
/// (correct for any epoch, as long as a reader registers and stamps the same one).
pub const Readers = struct {
    pub const cap = 256;
    pub const gone_cap = 64;

    lock: Spin = .{},
    cur: u64 = 1,
    n: u32 = 0,
    ep: [cap]u64 = undefined,
    cnt: [cap]u32 = undefined,
    /// Epochs whose last reader left since the last `view` (`gone_over`: more than fit).
    gone_n: u32 = 0,
    gone_over: bool = false,
    gone: [gone_cap]u64 = undefined,

    pub fn enter(r: *Readers) u64 {
        r.lock.lock();
        defer r.lock.unlock();
        if (r.n > 0 and (r.ep[r.n - 1] == r.cur or r.n == cap)) {
            r.cnt[r.n - 1] += 1;
            return r.ep[r.n - 1];
        }
        r.ep[r.n] = r.cur;
        r.cnt[r.n] = 1;
        r.n += 1;
        return r.cur;
    }

    /// True when `e` lost its last reader (items it pinned may be free now).
    pub fn exit(r: *Readers, e: u64) bool {
        r.lock.lock();
        defer r.lock.unlock();
        var i: u32 = r.n;
        while (i > 0) {
            i -= 1;
            if (r.ep[i] == e) break;
        } else unreachable; // exit without enter
        r.cnt[i] -= 1;
        if (r.cnt[i] != 0) return false;
        std.mem.copyForwards(u64, r.ep[i .. r.n - 1], r.ep[i + 1 .. r.n]);
        std.mem.copyForwards(u32, r.cnt[i .. r.n - 1], r.cnt[i + 1 .. r.n]);
        r.n -= 1;
        if (r.gone_n < gone_cap) {
            r.gone[r.gone_n] = e;
            r.gone_n += 1;
        } else r.gone_over = true;
        return true;
    }

    /// Later readers register past every epoch handed out so far.
    pub fn advance(r: *Readers) void {
        r.lock.lock();
        defer r.lock.unlock();
        r.cur += 1;
    }

    /// Live epochs (ascending) and the epochs gone since the previous view (sorted), then
    /// advances the epoch. Every reader that registers after this call is newer than `v.ep`.
    pub fn view(r: *Readers, v: *View) void {
        r.lock.lock();
        v.n = r.n;
        @memcpy(v.ep[0..r.n], r.ep[0..r.n]);
        v.gone_n = r.gone_n;
        v.gone_over = r.gone_over;
        @memcpy(v.gone[0..r.gone_n], r.gone[0..r.gone_n]);
        r.gone_n = 0;
        r.gone_over = false;
        r.cur += 1;
        r.lock.unlock();
        std.mem.sortUnstable(u64, v.gone[0..v.gone_n], {}, std.sort.asc(u64));
    }

    /// Live snapshots (a gauge; racy).
    pub fn live(r: *Readers) u64 {
        r.lock.lock();
        defer r.lock.unlock();
        var t: u64 = 0;
        for (r.cnt[0..r.n]) |c| t += c;
        return t;
    }

    pub const View = struct {
        n: u32 = 0,
        ep: [cap]u64 = undefined,
        gone_n: u32 = 0,
        gone_over: bool = false,
        gone: [gone_cap]u64 = undefined,

        /// The oldest live epoch in [lo, hi]: a reader that may hold the item. Null: none.
        pub fn holder(v: *const View, lo: u64, hi: u64) ?u64 {
            if (lo > hi) return null;
            const eps = v.ep[0..v.n];
            const i = std.sort.lowerBound(u64, eps, lo, order);
            return if (i < eps.len and eps[i] <= hi) eps[i] else null;
        }

        /// Whether epoch `e` lost its last reader since the previous view.
        pub fn isGone(v: *const View, e: u64) bool {
            if (v.gone_over) return true;
            const g = v.gone[0..v.gone_n];
            const i = std.sort.lowerBound(u64, g, e, order);
            return i < g.len and g[i] == e;
        }

        fn order(a: u64, b: u64) std.math.Order {
            return std.math.order(a, b);
        }
    };
};

test "readers: an evicted item is held only while a reader in its epoch range lives" {
    var r: Readers = .{};
    var v: Readers.View = .{};
    const long = r.enter();
    r.advance();
    const a = r.enter();
    r.advance();
    const b = r.enter();
    r.view(&v);
    // An item only `a` got, one the long reader and `b` got, one nobody got.
    try std.testing.expectEqual(@as(?u64, a), v.holder(a, a));
    try std.testing.expectEqual(@as(?u64, long), v.holder(long, b));
    try std.testing.expectEqual(@as(?u64, null), v.holder(std.math.maxInt(u64), 0));
    try std.testing.expect(r.exit(a));
    r.view(&v);
    try std.testing.expect(v.isGone(a) and !v.isGone(b));
    try std.testing.expectEqual(@as(?u64, null), v.holder(a, a));
    // Readers that start after the view never fall in an evicted item's range.
    const c = r.enter();
    try std.testing.expect(c > b);
    try std.testing.expect(r.exit(b));
    try std.testing.expect(r.exit(c));
    try std.testing.expect(r.exit(long));
    try std.testing.expectEqual(@as(u64, 0), r.live());
}

test "readers: a full table shares the newest entry" {
    var r: Readers = .{};
    var eps: [Readers.cap + 8]u64 = undefined;
    for (&eps) |*e| {
        e.* = r.enter();
        r.advance();
    }
    try std.testing.expectEqual(@as(u32, Readers.cap), r.n);
    try std.testing.expectEqual(eps[Readers.cap - 1], eps[Readers.cap + 7]);
    try std.testing.expectEqual(@as(u64, Readers.cap + 8), r.live());
    for (eps) |e| _ = r.exit(e);
    try std.testing.expectEqual(@as(u32, 0), r.n);
}

test "cache evicts over budget and keeps evicted buffers until taken" {
    const gpa = std.testing.allocator;
    var c = Cache.init(gpa, nshards * (1 << 16));
    defer c.deinit();
    var keep: ?[]const u8 = null;
    for (0..4096) |i| {
        const d = try gpa.alloc(u8, 4096);
        @memset(d, @truncate(i));
        const s = try c.put(i, d, 1);
        if (i == 0) keep = s;
    }
    try std.testing.expect(c.bytes() <= nshards * (1 << 16) + nshards * 4096);
    // The first buffer is evicted but still readable until taken.
    try std.testing.expectEqual(@as(u8, 0), keep.?[100]);
    var ev: std.ArrayList(*Item) = .empty;
    defer ev.deinit(gpa);
    c.takeEvicted(&ev);
    try std.testing.expect(ev.items.len > 0);
    for (ev.items) |it| c.free(it);
    try std.testing.expect(c.get(4095, 1) != null);
}
