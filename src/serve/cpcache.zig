//! Pre-encoded GetCheckpoint responses (pre-encoded bytes, never re-rendered
//! per call). Key: the checkpoint's sequence number plus the request's raw `read_mask` bytes
//! (`maskKey`). Value: the encoded GetCheckpointResponse message, and lazily its zstd and gzip
//! frames, so a repeated call is a lookup and one write: no store read, no decode, no render, no
//! compression.
//!
//! A checkpoint's response never changes once it is committed, with two exceptions the caller
//! handles: availability (lowest..=latest is checked before the lookup on every call) and
//! `display`, which renders from live Display objects (requests that select it are not cached).
//!
//! Sharded, each shard a spinlocked map plus CLOCK ring under a byte budget. Entries are
//! reference counted: a reader holds one while it writes the bytes, eviction drops the cache's
//! own, the last release frees. Budget 0 turns the cache off.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Spin = @import("store").cache.Spin;

pub const nshards = 16;

pub const Entry = struct {
    seq: u64,
    hash: u64,
    /// The store's transaction-fix generation the response was rendered at (store txfix.zig):
    /// a later fix for this checkpoint (a submitted signature order) makes it stale.
    gen: u64 = 0,
    /// Epoch of the checkpoint (its record's segment in the store), for the lookup that runs
    /// before any store read: the record is readable only while that segment is in the store's
    /// window. Null when the caller did not say (`put`, `putGen`): such an entry is never served
    /// without the record being read first.
    epoch: ?u64 = null,
    /// Monotonic time (ns) the checkpoint's record was last read from the store for this entry:
    /// when it was rendered, or by a later call that read the record and then served the entry.
    /// The lookup that runs before any store read serves an entry only while this is recent, so
    /// a record that went bad on disk is read again, and reported, within that time.
    checked_ns: std.atomic.Value(u64) = .init(0),
    /// The same for the store's loaded-list fixes (`Store.list_fix`): a transaction of this
    /// checkpoint whose loaded runtime object list was replaced since makes it stale.
    gen_lists: u64 = 0,
    /// The same for the store's certificate fixes (`Store.cert_fix`): this checkpoint's quorum
    /// certificate was replaced since (an edge installing its core's, docs/EDGE.md section 13).
    gen_certs: u64 = 0,
    mask: []u8,
    bytes: []u8,
    /// Compressed frames of `bytes` (codec.compress), filled by the first call that asks.
    zstd: std.atomic.Value(?[*]u8) = .init(null),
    zstd_len: usize = 0,
    gzip: std.atomic.Value(?[*]u8) = .init(null),
    gzip_len: usize = 0,
    refs: std.atomic.Value(u32) = .init(1),
    ref: std.atomic.Value(bool) = .init(true),

    fn size(e: *const Entry) usize {
        return e.bytes.len + e.mask.len + @sizeOf(Entry);
    }
};

const Shard = struct {
    lock: Spin = .{},
    map: std.AutoHashMapUnmanaged(u64, *Entry) = .empty,
    clock: std.ArrayList(*Entry) = .empty,
    hand: usize = 0,
    bytes: u64 = 0,
};

pub const Stats = struct {
    hits: std.atomic.Value(u64) = .init(0),
    misses: std.atomic.Value(u64) = .init(0),
    inserts: std.atomic.Value(u64) = .init(0),
    evictions: std.atomic.Value(u64) = .init(0),
    /// Responses not cached because one alone is over the per-entry limit (`fits`).
    too_big: std.atomic.Value(u64) = .init(0),
};

pub const Cache = struct {
    /// Bytes over all shards; 0: off.
    budget: u64 = 256 << 20,
    shards: [nshards]Shard = @splat(.{}),
    stats: Stats = .{},

    pub fn deinit(c: *Cache, gpa: Allocator) void {
        for (&c.shards) |*sh| {
            for (sh.clock.items) |e| release(gpa, e);
            sh.clock.deinit(gpa);
            sh.map.deinit(gpa);
            sh.* = .{};
        }
    }

    pub fn enabled(c: *const Cache) bool {
        return c.budget > 0;
    }

    fn keyOf(seq: u64, mask: []const u8) u64 {
        return std.hash.Wyhash.hash(seq, mask);
    }

    fn shardOf(c: *Cache, k: u64) *Shard {
        return &c.shards[@intCast(k >> 60)];
    }

    /// The cached response, with a reference the caller drops with `release`.
    pub fn get(c: *Cache, seq: u64, mask: []const u8) ?*Entry {
        const e = c.peek(seq, mask) orelse {
            if (c.enabled()) _ = c.stats.misses.fetchAdd(1, .monotonic);
            return null;
        };
        _ = c.stats.hits.fetchAdd(1, .monotonic);
        return e;
    }

    /// `get` that counts neither a hit nor a miss: for a lookup that is followed by `get` when
    /// it does not serve the entry (the caller counts the hit when it does, `stats.hits`).
    pub fn peek(c: *Cache, seq: u64, mask: []const u8) ?*Entry {
        if (!c.enabled()) return null;
        const k = keyOf(seq, mask);
        const sh = c.shardOf(k);
        sh.lock.lock();
        defer sh.lock.unlock();
        const e = sh.map.get(k) orelse return null;
        if (e.seq != seq or !std.mem.eql(u8, e.mask, mask)) return null;
        _ = e.refs.fetchAdd(1, .monotonic);
        e.ref.store(true, .monotonic);
        return e;
    }

    /// Caches a copy of `bytes` for (seq, mask). Errors are dropped: the cache is an optimisation.
    pub fn put(c: *Cache, gpa: Allocator, seq: u64, mask: []const u8, bytes: []const u8) void {
        c.putGen(gpa, seq, mask, bytes, 0);
    }

    /// Drops the entry for (seq, mask) if there is one (a stale response; readers holding it
    /// keep it alive until they release it).
    pub fn drop(c: *Cache, gpa: Allocator, seq: u64, mask: []const u8) void {
        if (!c.enabled()) return;
        const k = keyOf(seq, mask);
        const sh = c.shardOf(k);
        const victim: ?*Entry = blk: {
            sh.lock.lock();
            defer sh.lock.unlock();
            const e = sh.map.get(k) orelse break :blk null;
            if (e.seq != seq or !std.mem.eql(u8, e.mask, mask)) break :blk null;
            _ = sh.map.remove(k);
            for (sh.clock.items, 0..) |v, i| if (v == e) {
                _ = sh.clock.swapRemove(i);
                break;
            };
            sh.bytes -= e.size();
            break :blk e;
        };
        if (victim) |e| release(gpa, e);
    }

    /// `put`, recording the transaction-fix generation the response was rendered at.
    pub fn putGen(c: *Cache, gpa: Allocator, seq: u64, mask: []const u8, bytes: []const u8, gen: u64) void {
        c.putAt(gpa, seq, null, 0, mask, bytes, gen, 0);
    }

    /// `putGen`, with the loaded-list fix generation as well.
    pub fn putGens(c: *Cache, gpa: Allocator, seq: u64, mask: []const u8, bytes: []const u8, gen: u64, gen_lists: u64) void {
        c.putAt(gpa, seq, null, 0, mask, bytes, gen, gen_lists);
    }

    /// `putGens` for a checkpoint of `epoch` (`Entry.epoch`) whose record was read at `now_ns`
    /// (`Entry.checked_ns`).
    pub fn putAt(c: *Cache, gpa: Allocator, seq: u64, epoch: ?u64, now_ns: u64, mask: []const u8, bytes: []const u8, gen: u64, gen_lists: u64) void {
        c.putAll(gpa, seq, epoch, now_ns, mask, bytes, gen, gen_lists, 0);
    }

    /// `putAt`, with the certificate fix generation as well.
    pub fn putAll(c: *Cache, gpa: Allocator, seq: u64, epoch: ?u64, now_ns: u64, mask: []const u8, bytes: []const u8, gen: u64, gen_lists: u64, gen_certs: u64) void {
        if (!c.enabled()) return;
        const shard_budget = c.budget / nshards;
        if (bytes.len + mask.len + @sizeOf(Entry) > shard_budget / 4) {
            // one response may not flush a shard
            _ = c.stats.too_big.fetchAdd(1, .monotonic);
            return;
        }
        const k = keyOf(seq, mask);
        const e = gpa.create(Entry) catch return;
        e.* = .{ .seq = seq, .hash = k, .gen = gen, .gen_lists = gen_lists, .gen_certs = gen_certs, .epoch = epoch, .checked_ns = .init(now_ns), .mask = gpa.dupe(u8, mask) catch {
            gpa.destroy(e);
            return;
        }, .bytes = gpa.dupe(u8, bytes) catch {
            gpa.free(e.mask);
            gpa.destroy(e);
            return;
        } };
        var dropped: std.ArrayList(*Entry) = .empty;
        defer {
            for (dropped.items) |d| release(gpa, d);
            dropped.deinit(gpa);
        }
        const sh = c.shardOf(k);
        sh.lock.lock();
        defer sh.lock.unlock();
        const gop = sh.map.getOrPut(gpa, k) catch {
            dropped.append(gpa, e) catch {};
            return;
        };
        if (gop.found_existing) {
            // Same key (or a hash collision): keep the one already there.
            dropped.append(gpa, e) catch {};
            return;
        }
        sh.clock.append(gpa, e) catch {
            _ = sh.map.remove(k);
            dropped.append(gpa, e) catch {};
            return;
        };
        gop.value_ptr.* = e;
        sh.bytes += e.size();
        _ = c.stats.inserts.fetchAdd(1, .monotonic);
        var spins: usize = 0;
        while (sh.bytes > shard_budget and sh.clock.items.len > 1 and spins < 4 * sh.clock.items.len) : (spins += 1) {
            if (sh.hand >= sh.clock.items.len) sh.hand = 0;
            const v = sh.clock.items[sh.hand];
            if (v == e or v.ref.swap(false, .monotonic)) {
                sh.hand += 1;
                continue;
            }
            _ = sh.clock.swapRemove(sh.hand);
            _ = sh.map.remove(v.hash);
            sh.bytes -= v.size();
            _ = c.stats.evictions.fetchAdd(1, .monotonic);
            dropped.append(gpa, v) catch release(gpa, v); // refs > 1 while readers hold it
        }
    }

    pub fn bytesHeld(c: *Cache) u64 {
        var b: u64 = 0;
        for (&c.shards) |*sh| b += @atomicLoad(u64, &sh.bytes, .monotonic);
        return b;
    }

    /// Responses held now.
    pub fn entries(c: *Cache) u64 {
        var n: u64 = 0;
        for (&c.shards) |*sh| {
            sh.lock.lock();
            defer sh.lock.unlock();
            n += sh.clock.items.len;
        }
        return n;
    }

    /// Prometheus text for the node's /metrics. The `zui_cpcache_*` families are deepwave's own
    /// (sui-node has no such cache): lookups that hit and missed, responses inserted, evicted and
    /// refused as too big for one entry, and the bytes and entries held now.
    pub fn render(c: *Cache, w: *std.Io.Writer) !void {
        const st = &c.stats;
        inline for (.{ .{ "hits", &st.hits }, .{ "misses", &st.misses }, .{ "inserts", &st.inserts }, .{ "evictions", &st.evictions }, .{ "oversize_rejects", &st.too_big } }) |m| {
            try w.print("# TYPE zui_cpcache_" ++ m[0] ++ " counter\nzui_cpcache_" ++ m[0] ++ " {d}\n", .{m[1].load(.monotonic)});
        }
        try w.print("# TYPE zui_cpcache_bytes gauge\nzui_cpcache_bytes {d}\n# TYPE zui_cpcache_entries gauge\nzui_cpcache_entries {d}\n# TYPE zui_cpcache_budget_bytes gauge\nzui_cpcache_budget_bytes {d}\n", .{ c.bytesHeld(), c.entries(), c.budget });
    }
};

/// Drops one reference; the last frees the entry.
pub fn release(gpa: Allocator, e: *Entry) void {
    if (e.refs.fetchSub(1, .acq_rel) != 1) return;
    if (e.zstd.load(.acquire)) |p| gpa.free(p[0..e.zstd_len]);
    if (e.gzip.load(.acquire)) |p| gpa.free(p[0..e.gzip_len]);
    gpa.free(e.bytes);
    gpa.free(e.mask);
    gpa.destroy(e);
}

pub const Which = enum { zstd, gzip };
pub const CompressFn = *const fn (gpa: Allocator, payload: []const u8) anyerror![]u8;

/// The entry's frame for a compressed encoding, compressing once (`f` returns gpa memory; a
/// racing caller's copy is freed). Null when compression fails.
pub fn compressed(gpa: Allocator, e: *Entry, which: Which, f: CompressFn) ?[]const u8 {
    const slot = if (which == .zstd) &e.zstd else &e.gzip;
    const len_p = if (which == .zstd) &e.zstd_len else &e.gzip_len;
    if (slot.load(.acquire)) |p| return p[0..@atomicLoad(usize, len_p, .acquire)];
    const z = f(gpa, e.bytes) catch return null;
    compressLock.lock();
    defer compressLock.unlock();
    if (slot.load(.acquire)) |p| {
        gpa.free(z);
        return p[0..len_p.*];
    }
    // The length is stored before the pointer is published.
    @atomicStore(usize, len_p, z.len, .release);
    slot.store(z.ptr, .release);
    return z;
}

var compressLock: Spin = .{};

/// The cache key part of a request's `read_mask`: every occurrence's raw bytes, each with its
/// length (absent and present-but-empty differ, as they do for the response).
pub fn maskKey(arena: Allocator, parts: []const []const u8) ![]const u8 {
    var n: usize = 0;
    for (parts) |p| n += 4 + p.len;
    const out = try arena.alloc(u8, n);
    var i: usize = 0;
    for (parts) |p| {
        std.mem.writeInt(u32, out[i..][0..4], @intCast(p.len), .little);
        @memcpy(out[i + 4 ..][0..p.len], p);
        i += 4 + p.len;
    }
    return out;
}

test "cpcache: hit, miss, eviction keeps held entries alive" {
    const gpa = std.testing.allocator;
    var c: Cache = .{ .budget = nshards * 64 * 1024 };
    defer c.deinit(gpa);
    const k0 = try maskKey(gpa, &.{"a"});
    defer gpa.free(k0);
    const k1 = try maskKey(gpa, &.{});
    defer gpa.free(k1);
    try std.testing.expect(c.get(1, k0) == null);
    c.put(gpa, 1, k0, "hello");
    const e = c.get(1, k0).?;
    try std.testing.expectEqualStrings("hello", e.bytes);
    try std.testing.expect(c.get(1, k1) == null);
    try std.testing.expect(c.get(2, k0) == null);
    // Flood the cache: `e` is evicted but stays readable while held.
    var buf: [2048]u8 = @splat(7);
    for (0..4096) |i| c.put(gpa, 100 + i, k0, &buf);
    try std.testing.expect(c.bytesHeld() <= c.budget + nshards * 4096);
    try std.testing.expectEqualStrings("hello", e.bytes);
    const Z = struct {
        fn run(a: Allocator, b: []const u8) anyerror![]u8 {
            return a.dupe(u8, b);
        }
    };
    try std.testing.expectEqualStrings("hello", compressed(gpa, e, .zstd, Z.run).?);
    try std.testing.expectEqualStrings("hello", compressed(gpa, e, .zstd, Z.run).?);
    release(gpa, e);
    // Absent and present-empty masks are different keys.
    const k2 = try maskKey(gpa, &.{""});
    defer gpa.free(k2);
    try std.testing.expect(!std.mem.eql(u8, k1, k2));
}

test "cpcache: stats are rendered as zui_cpcache_* metrics" {
    const gpa = std.testing.allocator;
    var c: Cache = .{ .budget = nshards * 64 * 1024 };
    defer c.deinit(gpa);
    const k = try maskKey(gpa, &.{"a"});
    defer gpa.free(k);
    try std.testing.expect(c.get(1, k) == null); // miss
    c.put(gpa, 1, k, "hello"); // insert
    release(gpa, c.get(1, k).?); // hit
    release(gpa, c.get(1, k).?); // hit
    // one response over the per-entry limit (a quarter of a shard) is refused and counted
    const big = try gpa.alloc(u8, 64 * 1024);
    defer gpa.free(big);
    @memset(big, 1);
    c.put(gpa, 2, k, big);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try c.render(&out.writer);
    const held = "hello".len + k.len + @sizeOf(Entry);
    var want_buf: [1024]u8 = undefined;
    const want = try std.fmt.bufPrint(&want_buf,
        \\# TYPE zui_cpcache_hits counter
        \\zui_cpcache_hits 2
        \\# TYPE zui_cpcache_misses counter
        \\zui_cpcache_misses 1
        \\# TYPE zui_cpcache_inserts counter
        \\zui_cpcache_inserts 1
        \\# TYPE zui_cpcache_evictions counter
        \\zui_cpcache_evictions 0
        \\# TYPE zui_cpcache_oversize_rejects counter
        \\zui_cpcache_oversize_rejects 1
        \\# TYPE zui_cpcache_bytes gauge
        \\zui_cpcache_bytes {d}
        \\# TYPE zui_cpcache_entries gauge
        \\zui_cpcache_entries 1
        \\# TYPE zui_cpcache_budget_bytes gauge
        \\zui_cpcache_budget_bytes {d}
        \\
    , .{ held, c.budget });
    try std.testing.expectEqualStrings(want, out.writer.buffered());
    // a cache that is off counts nothing as too big
    var off: Cache = .{ .budget = 0 };
    off.put(gpa, 1, k, "x");
    try std.testing.expectEqual(@as(u64, 0), off.stats.too_big.load(.monotonic));
}

test "cpcache: a stale entry is dropped and replaced, readers keep the old bytes" {
    const gpa = std.testing.allocator;
    var c: Cache = .{ .budget = nshards * 64 * 1024 };
    defer c.deinit(gpa);
    const k = try maskKey(gpa, &.{"t"});
    defer gpa.free(k);
    c.putGen(gpa, 9, k, "old", 3);
    const held = c.get(9, k).?;
    try std.testing.expectEqual(@as(u64, 3), held.gen);
    // put keeps the existing entry; drop then put replaces it.
    c.putGen(gpa, 9, k, "new", 4);
    try std.testing.expectEqualStrings("old", c.get(9, k).?.bytes);
    release(gpa, held); // the get just above
    c.drop(gpa, 9, k);
    try std.testing.expect(c.get(9, k) == null);
    try std.testing.expectEqualStrings("old", held.bytes);
    c.putGen(gpa, 9, k, "new", 4);
    const e = c.get(9, k).?;
    try std.testing.expectEqualStrings("new", e.bytes);
    try std.testing.expectEqual(@as(u64, 4), e.gen);
    release(gpa, e);
    release(gpa, held);
    // Dropping what is not there is a no-op.
    c.drop(gpa, 10, k);
}
