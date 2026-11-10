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
        if (!c.enabled()) return null;
        const k = keyOf(seq, mask);
        const sh = c.shardOf(k);
        sh.lock.lock();
        defer sh.lock.unlock();
        const e = sh.map.get(k) orelse {
            _ = c.stats.misses.fetchAdd(1, .monotonic);
            return null;
        };
        if (e.seq != seq or !std.mem.eql(u8, e.mask, mask)) {
            _ = c.stats.misses.fetchAdd(1, .monotonic);
            return null;
        }
        _ = e.refs.fetchAdd(1, .monotonic);
        e.ref.store(true, .monotonic);
        _ = c.stats.hits.fetchAdd(1, .monotonic);
        return e;
    }

    /// Caches a copy of `bytes` for (seq, mask). Errors are dropped: the cache is an optimisation.
    pub fn put(c: *Cache, gpa: Allocator, seq: u64, mask: []const u8, bytes: []const u8) void {
        if (!c.enabled()) return;
        const shard_budget = c.budget / nshards;
        if (bytes.len + mask.len + @sizeOf(Entry) > shard_budget / 4) return; // one response may not flush a shard
        const k = keyOf(seq, mask);
        const e = gpa.create(Entry) catch return;
        e.* = .{ .seq = seq, .hash = k, .mask = gpa.dupe(u8, mask) catch {
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
