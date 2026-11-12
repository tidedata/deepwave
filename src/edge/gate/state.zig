//! What the gate keeps in memory, every table of a fixed size:
//! - `take` / `debit`: a token bucket in its GCRA form, one atomic word per bucket;
//! - `KeyTable`: resolved keys by a keyed hash of the key (the key itself is never stored), read
//!   without a lock (a sequence lock per entry), written under the gate's writer lock;
//! - `IpTable`: one bucket per keyless caller address, claimed and found without a lock;
//! - `IpDeny`: prefixes the gate has denied for a while;
//! - `Prices`, `Plans`, `Messages`: small intern pools the entries point into.
const std = @import("std");
const Atomic = std.atomic.Value;
const Allocator = std.mem.Allocator;
const contract = @import("contract.zig");
const methods = @import("methods.zig");

pub const SpinLock = struct {
    v: Atomic(bool) = .init(false),

    pub fn lock(l: *SpinLock) void {
        var spins: u32 = 0;
        while (l.v.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            spins += 1;
            if (spins & 63 == 0) std.Thread.yield() catch {} else std.atomic.spinLoopHint();
        }
    }
    pub fn unlock(l: *SpinLock) void {
        l.v.store(false, .release);
    }
};

// ---------------------------------------------------------------- token bucket

/// Takes `cost` units at `now` (monotonic ns) from the bucket whose state is `tat`: one unit
/// every `interval_ns`, at most `burst_ns` worth held back for a burst. Null: taken. Otherwise
/// the time until the same request would pass, and nothing is taken. `interval_ns` 0 is a rate
/// of zero: nothing passes. A request that costs more than the burst passes on a full bucket.
pub fn take(tat: *Atomic(u64), now: u64, interval_ns: u64, burst_ns: u64, cost: u32) ?u64 {
    if (cost == 0) return null;
    if (interval_ns == 0) return std.time.ns_per_s;
    const need = @as(u64, cost) *| interval_ns;
    const cap = @max(burst_ns, need);
    var cur = tat.load(.monotonic);
    while (true) {
        const next = @max(cur, now) +| need;
        if (next - now > cap) return next - now - cap;
        cur = tat.cmpxchgWeak(cur, next, .monotonic, .monotonic) orelse return null;
    }
}

/// Books `cost` units that were already spent (a forwarded call's extra units): the bucket may
/// go into debt, which the next `take` waits out.
pub fn debit(tat: *Atomic(u64), now: u64, interval_ns: u64, cost: u32) void {
    if (cost == 0 or interval_ns == 0) return;
    const need = @as(u64, cost) *| interval_ns;
    var cur = tat.load(.monotonic);
    while (true) {
        cur = tat.cmpxchgWeak(cur, @max(cur, now) +| need, .monotonic, .monotonic) orelse return;
    }
}

/// `rps` as the time between two units; 0 for a rate of zero.
pub fn intervalNs(rps: f64) u64 {
    if (!(rps > 0)) return 0;
    const ns = @as(f64, std.time.ns_per_s) / rps;
    return if (ns < 1) 1 else @intFromFloat(ns);
}

// ---------------------------------------------------------------- keys

pub const KeyStatus = enum(u8) {
    ok,
    invalid,
    suspended,
    exhausted,
    unknown,
    /// The gate could not be asked: free-tier treatment for a short while, then asked again.
    unresolved,

    pub fn from(s: contract.Status) KeyStatus {
        return switch (s) {
            .ok => .ok,
            .invalid => .invalid,
            .suspended => .suspended,
            .exhausted => .exhausted,
            .unknown => .unknown,
        };
    }
};

pub const kid_words = contract.max_key_id_len / 8;

/// A key's settings as one consistent copy.
pub const Cfg = struct {
    status: KeyStatus = .unresolved,
    plan: u8 = Plans.none,
    /// Index into `Messages` (0: none): the gate's text for a refusal.
    msg: u8 = 0,
    deny_status: KeyStatus = .ok,
    deny_msg: u8 = 0,
    leased: bool = false,
    /// Index into `Prices`, or `Prices.none`.
    set: u16 = Prices.none,
    interval_ns: u64 = 0,
    burst_ns: u64 = 0,
    forward_milli: u32 = 1000,
    max_streams: u32 = 0,
    /// Monotonic ns: the answer's `ttl_s` ends.
    expires_ns: u64 = 0,
    /// No new resolve for this key before this.
    retry_ns: u64 = 0,
    /// A deny from the gate holds until this (0: none; max: until the next resolve answer).
    deny_until_ns: u64 = 0,
    lease_total: u64 = 0,
};

pub const Entry = struct {
    /// Odd while the words below are being written.
    seq: Atomic(u32) = .init(0),
    /// Changes when the slot is given to another key (odd while `kid` is being written).
    tenant: Atomic(u32) = .init(0),
    hi: Atomic(u64) = .init(0),
    w_flags: Atomic(u64) = .init(0),
    w_interval: Atomic(u64) = .init(0),
    w_burst: Atomic(u64) = .init(0),
    w_limits: Atomic(u64) = .init(0),
    w_expires: Atomic(u64) = .init(0),
    w_retry: Atomic(u64) = .init(0),
    w_deny_until: Atomic(u64) = .init(0),
    w_lease_total: Atomic(u64) = .init(0),
    // Live state, on a cache line of its own: a call writes here (the bucket, the lease), and
    // the settings above are read by every other thread serving this key.
    tat: Atomic(u64) align(std.atomic.cache_line) = .init(0),
    lease_left: Atomic(i64) = .init(0),
    streams: Atomic(u32) = .init(0),
    /// Monotonic seconds of the last admitted call.
    last_s: Atomic(u32) = .init(0),
    refreshing: Atomic(bool) = .init(false),
    kid_len: Atomic(u32) align(std.atomic.cache_line) = .init(0),
    kid: [kid_words]Atomic(u64) = @splat(.init(0)),

    fn packFlags(c: Cfg) u64 {
        return @as(u64, @intFromEnum(c.status)) | (@as(u64, c.plan) << 8) | (@as(u64, c.msg) << 16) | (@as(u64, @intFromEnum(c.deny_status)) << 24) |
            (@as(u64, @intFromBool(c.leased)) << 32) | (@as(u64, c.deny_msg) << 40) | (@as(u64, c.set) << 48);
    }

    /// The settings and the key hash's upper half, or null when a writer was at it three times
    /// in a row (the caller treats that as a miss).
    pub fn read(e: *const Entry, hi: *u64) ?Cfg {
        var tries: u32 = 0;
        while (tries < 4) : (tries += 1) {
            const s1 = e.seq.load(.acquire);
            if (s1 & 1 != 0) {
                std.atomic.spinLoopHint();
                continue;
            }
            hi.* = e.hi.load(.monotonic);
            const f = e.w_flags.load(.monotonic);
            const lim = e.w_limits.load(.monotonic);
            const c: Cfg = .{
                .status = @enumFromInt(@as(u8, @truncate(f))),
                .plan = @truncate(f >> 8),
                .msg = @truncate(f >> 16),
                .deny_status = @enumFromInt(@as(u8, @truncate(f >> 24))),
                .leased = (f >> 32) & 1 != 0,
                .deny_msg = @truncate(f >> 40),
                .set = @truncate(f >> 48),
                .interval_ns = e.w_interval.load(.monotonic),
                .burst_ns = e.w_burst.load(.monotonic),
                .forward_milli = @truncate(lim),
                .max_streams = @truncate(lim >> 32),
                .expires_ns = e.w_expires.load(.monotonic),
                .retry_ns = e.w_retry.load(.monotonic),
                .deny_until_ns = e.w_deny_until.load(.monotonic),
                .lease_total = e.w_lease_total.load(.monotonic),
            };
            if (e.seq.load(.acquire) == s1) return c;
        }
        return null;
    }

    /// Writer lock held.
    pub fn write(e: *Entry, hi: u64, c: Cfg) void {
        _ = e.seq.fetchAdd(1, .acq_rel);
        e.hi.store(hi, .monotonic);
        e.w_flags.store(packFlags(c), .monotonic);
        e.w_interval.store(c.interval_ns, .monotonic);
        e.w_burst.store(c.burst_ns, .monotonic);
        e.w_limits.store(@as(u64, c.forward_milli) | (@as(u64, c.max_streams) << 32), .monotonic);
        e.w_expires.store(c.expires_ns, .monotonic);
        e.w_retry.store(c.retry_ns, .monotonic);
        e.w_deny_until.store(c.deny_until_ns, .monotonic);
        e.w_lease_total.store(c.lease_total, .monotonic);
        _ = e.seq.fetchAdd(1, .acq_rel);
    }

    /// Writer lock held: the slot now belongs to the key whose id is `kid`.
    pub fn setKid(e: *Entry, kid: []const u8) void {
        _ = e.tenant.fetchAdd(1, .acq_rel);
        var buf: [contract.max_key_id_len]u8 = @splat(0);
        const n = @min(kid.len, buf.len);
        @memcpy(buf[0..n], kid[0..n]);
        for (&e.kid, 0..) |*w, i| w.store(std.mem.readInt(u64, buf[i * 8 ..][0..8], .little), .monotonic);
        e.kid_len.store(@intCast(n), .monotonic);
        _ = e.tenant.fetchAdd(1, .acq_rel);
    }

    /// The key id, when the slot still belongs to `tenant`.
    pub fn readKid(e: *const Entry, tenant: u32, out: *[contract.max_key_id_len]u8) ?[]const u8 {
        if (tenant & 1 != 0 or e.tenant.load(.acquire) != tenant) return null;
        for (&e.kid, 0..) |*w, i| std.mem.writeInt(u64, out[i * 8 ..][0..8], w.load(.monotonic), .little);
        const n = e.kid_len.load(.monotonic);
        if (e.tenant.load(.acquire) != tenant or n > out.len) return null;
        return out[0..n];
    }

    pub fn kidEquals(e: *const Entry, kid: []const u8) bool {
        var buf: [contract.max_key_id_len]u8 = undefined;
        const mine = e.readKid(e.tenant.load(.acquire), &buf) orelse return false;
        return std.mem.eql(u8, mine, kid);
    }
};

pub const KeyTable = struct {
    tags: []Atomic(u64),
    entries: []Entry,
    mask: u32,
    /// Entries in use (writer side).
    used: Atomic(u32) = .init(0),

    /// Every lookup reads this many tags (two cache lines), so a slot can be emptied and
    /// reused in place without tombstones.
    pub const window = 16;

    pub fn init(gpa: Allocator, capacity: u32) !KeyTable {
        const n = std.math.ceilPowerOfTwo(u32, @max(capacity, window)) catch return error.OutOfMemory;
        const tags = try gpa.alloc(Atomic(u64), n);
        errdefer gpa.free(tags);
        const entries = try gpa.alloc(Entry, n);
        for (tags) |*t| t.* = .init(0);
        for (entries) |*e| e.* = .{};
        return .{ .tags = tags, .entries = entries, .mask = n - 1 };
    }

    pub fn deinit(t: *KeyTable, gpa: Allocator) void {
        gpa.free(t.tags);
        gpa.free(t.entries);
    }

    pub fn tagOf(h: u128) u64 {
        const lo: u64 = @truncate(h);
        return if (lo == 0) 1 else lo;
    }

    pub const Found = struct { idx: u32, cfg: Cfg, tenant: u32 };

    /// The entry of the key hashed to `h`. No lock, no write.
    pub fn find(t: *const KeyTable, h: u128) ?Found {
        const tag = tagOf(h);
        const want_hi: u64 = @truncate(h >> 64);
        const base: u32 = @truncate(tag);
        var i: u32 = 0;
        while (i < window) : (i += 1) {
            const idx = (base +% i) & t.mask;
            if (t.tags[idx].load(.monotonic) != tag) continue;
            const e = &t.entries[idx];
            const tenant = e.tenant.load(.acquire);
            var hi: u64 = 0;
            const cfg = e.read(&hi) orelse continue;
            if (hi != want_hi) continue;
            return .{ .idx = idx, .cfg = cfg, .tenant = tenant };
        }
        return null;
    }

    pub const Place = struct {
        idx: u32,
        existing: bool,
        /// The slot holds another key the caller must drop (`remove`) before it writes.
        victim: bool = false,
    };

    /// Writer lock held. Where the key hashed to `h` lives or may be put: its own slot, an empty
    /// one, or the slot of the entry `evictable` likes best (highest score; 0: keep). Null when
    /// the window is full of entries that must stay.
    pub fn place(t: *KeyTable, h: u128, ctx: anytype, comptime evictable: fn (@TypeOf(ctx), *const Entry, Cfg) u64) ?Place {
        const tag = tagOf(h);
        const want_hi: u64 = @truncate(h >> 64);
        const base: u32 = @truncate(tag);
        var empty: ?u32 = null;
        var victim: ?u32 = null;
        var best: u64 = 0;
        var i: u32 = 0;
        while (i < window) : (i += 1) {
            const idx = (base +% i) & t.mask;
            const cur = t.tags[idx].load(.monotonic);
            const e = &t.entries[idx];
            if (cur == 0) {
                if (empty == null) empty = idx;
                continue;
            }
            var hi: u64 = 0;
            const cfg = e.read(&hi) orelse continue;
            if (cur == tag and hi == want_hi) return .{ .idx = idx, .existing = true };
            const score = evictable(ctx, e, cfg);
            if (score > best) {
                best = score;
                victim = idx;
            }
        }
        if (empty) |idx| return .{ .idx = idx, .existing = false };
        if (victim) |idx| return .{ .idx = idx, .existing = false, .victim = true };
        return null;
    }

    /// Writer lock held: publishes `idx` under `h` (after `Entry.write`).
    pub fn publish(t: *KeyTable, idx: u32, h: u128) void {
        if (t.tags[idx].load(.monotonic) == 0) _ = t.used.fetchAdd(1, .monotonic);
        t.tags[idx].store(tagOf(h), .release);
    }

    /// Writer lock held.
    pub fn remove(t: *KeyTable, idx: u32) void {
        if (t.tags[idx].load(.monotonic) == 0) return;
        t.tags[idx].store(0, .release);
        const e = &t.entries[idx];
        // readers that matched the tag a moment ago now fail the `hi` check
        e.write(0, .{});
        e.refreshing.store(false, .release);
        _ = t.used.fetchSub(1, .monotonic);
    }
};

// ---------------------------------------------------------------- keyless callers

pub const IpSlot = struct {
    /// 0: free.
    key: Atomic(u64) = .init(0),
    tat: Atomic(u64) = .init(0),
    streams: Atomic(u32) = .init(0),
    last_s: Atomic(u32) = .init(0),
};

/// One bucket per caller address (`ident.Ip.limitKey`). Slots are claimed with one
/// compare-and-swap and freed by `sweep` once idle; when a window is full of busy slots the
/// caller shares `overflow`, so a flood of addresses costs no memory and is still limited.
pub const IpTable = struct {
    slots: []IpSlot,
    mask: u32,
    seed: u64,
    overflow: IpSlot = .{ .key = .init(1) },
    overflowed: Atomic(u64) = .init(0),

    pub const window = 8;

    pub fn init(gpa: Allocator, capacity: u32, seed: u64) !IpTable {
        const n = std.math.ceilPowerOfTwo(u32, @max(capacity, window)) catch return error.OutOfMemory;
        const slots = try gpa.alloc(IpSlot, n);
        for (slots) |*s| s.* = .{};
        return .{ .slots = slots, .mask = n - 1, .seed = seed };
    }

    pub fn deinit(t: *IpTable, gpa: Allocator) void {
        gpa.free(t.slots);
    }

    pub fn keyOf(t: *const IpTable, limit_key: u128) u64 {
        const k = std.hash.Wyhash.hash(t.seed, std.mem.asBytes(&limit_key));
        return if (k < 2) 2 else k;
    }

    pub fn get(t: *IpTable, limit_key: u128, now_s: u32) *IpSlot {
        const k = t.keyOf(limit_key);
        const base: u32 = @truncate(k);
        var i: u32 = 0;
        while (i < window) : (i += 1) {
            const s = &t.slots[(base +% i) & t.mask];
            if (s.key.load(.monotonic) == k) return touch(s, now_s);
        }
        i = 0;
        while (i < window) : (i += 1) {
            const s = &t.slots[(base +% i) & t.mask];
            const cur = s.key.cmpxchgStrong(0, k, .acq_rel, .monotonic) orelse return touch(s, now_s);
            if (cur == k) return touch(s, now_s);
        }
        _ = t.overflowed.fetchAdd(1, .monotonic);
        return &t.overflow;
    }

    fn touch(s: *IpSlot, now_s: u32) *IpSlot {
        if (s.last_s.load(.monotonic) != now_s) s.last_s.store(now_s, .monotonic);
        return s;
    }

    /// Frees slots idle for `idle_s` with no stream open, among `n` slots from `start`. Returns
    /// where the next sweep starts.
    pub fn sweep(t: *IpTable, now_s: u32, idle_s: u32, start: u32, n: u32) u32 {
        var i: u32 = 0;
        while (i < n and i <= t.mask) : (i += 1) {
            const s = &t.slots[(start +% i) & t.mask];
            if (s.key.load(.monotonic) == 0) continue;
            if (s.streams.load(.monotonic) != 0) continue;
            if (now_s -| s.last_s.load(.monotonic) < idle_s) continue;
            s.key.store(0, .release);
        }
        return (start +% i) & t.mask;
    }

    pub fn count(t: *const IpTable) u32 {
        var n: u32 = 0;
        for (t.slots) |*s| n += @intFromBool(s.key.load(.monotonic) != 0);
        return n;
    }
};

/// Prefixes (`ident.Ip.prefixKey`) the gate denied, each until a monotonic time.
pub const IpDeny = struct {
    n: Atomic(u32) = .init(0),
    slots: [size]Slot = @splat(.{}),

    pub const size = 1024;
    pub const window = 16;
    const Slot = struct {
        key: Atomic(u64) = .init(0),
        until_ns: Atomic(u64) = .init(0),
        /// status | message index << 8
        meta: Atomic(u32) = .init(0),
    };

    pub const Hit = struct { status: KeyStatus, msg: u8 };

    fn base(key: u64) u32 {
        return @truncate(std.hash.Wyhash.hash(0x64656e79, std.mem.asBytes(&key)));
    }

    pub fn find(d: *const IpDeny, key: u64, now: u64) ?Hit {
        if (d.n.load(.monotonic) == 0) return null;
        const b = base(key);
        var i: u32 = 0;
        while (i < window) : (i += 1) {
            const s = &d.slots[(b +% i) % size];
            if (s.key.load(.monotonic) != key) continue;
            if (s.until_ns.load(.monotonic) <= now) return null;
            const m = s.meta.load(.monotonic);
            return .{ .status = @enumFromInt(@as(u8, @truncate(m))), .msg = @truncate(m >> 8) };
        }
        return null;
    }

    /// Writer lock held. A full window drops the entry that ends first.
    pub fn put(d: *IpDeny, key: u64, until_ns: u64, status: KeyStatus, msg: u8, now: u64) void {
        const b = base(key);
        var pick: ?*Slot = null;
        var pick_until: u64 = std.math.maxInt(u64);
        var i: u32 = 0;
        while (i < window) : (i += 1) {
            const s = &d.slots[(b +% i) % size];
            const k = s.key.load(.monotonic);
            if (k == key) {
                pick = s;
                break;
            }
            const u = if (k == 0) 0 else s.until_ns.load(.monotonic);
            if (u <= now or u < pick_until) {
                pick_until = if (u <= now) 0 else u;
                pick = s;
                if (u <= now) {
                    // free or over: as good as it gets, but keep looking for the key itself
                    var j = i + 1;
                    while (j < window) : (j += 1) {
                        const s2 = &d.slots[(b +% j) % size];
                        if (s2.key.load(.monotonic) == key) pick = s2;
                    }
                    break;
                }
            }
        }
        const s = pick.?;
        const was = s.key.load(.monotonic);
        s.until_ns.store(0, .monotonic);
        s.key.store(key, .release);
        s.meta.store(@as(u32, @intFromEnum(status)) | (@as(u32, msg) << 8), .monotonic);
        s.until_ns.store(until_ns, .release);
        if (was == 0) _ = d.n.fetchAdd(1, .monotonic);
    }

    /// Writer lock held.
    pub fn sweep(d: *IpDeny, now: u64) void {
        if (d.n.load(.monotonic) == 0) return;
        for (&d.slots) |*s| {
            if (s.key.load(.monotonic) == 0) continue;
            if (s.until_ns.load(.monotonic) > now) continue;
            s.key.store(0, .release);
            _ = d.n.fetchSub(1, .monotonic);
        }
    }
};

// ---------------------------------------------------------------- intern pools

/// Price tables shared by the keys that carry the same one. Writer lock held for `intern` and
/// `release`; readers load single words.
pub const Prices = struct {
    sets: [size]methods.PriceSet = @splat(.{}),
    hashes: [size]u64 = @splat(0),
    refs: [size]u32 = @splat(0),

    pub const size = 128;
    pub const none: u16 = 0xffff;

    pub fn intern(p: *Prices, set: *const methods.PriceSet) ?u16 {
        const h = set.hash();
        var free: ?u16 = null;
        for (0..size) |i| {
            if (p.refs[i] != 0 and p.hashes[i] == h) {
                p.refs[i] += 1;
                return @intCast(i);
            }
            if (p.refs[i] == 0 and free == null) free = @intCast(i);
        }
        const i = free orelse return null;
        const dst = &p.sets[i];
        inline for (.{ "w", "per_item", "per_minute" }) |f| {
            for (&@field(dst, f), &@field(set, f)) |*d, *s| @atomicStore(u32, d, s.*, .monotonic);
        }
        p.hashes[i] = h;
        p.refs[i] = 1;
        return i;
    }

    pub fn release(p: *Prices, i: u16) void {
        if (i >= size) return;
        if (p.refs[i] > 0) p.refs[i] -= 1;
    }

    pub const Price = struct { w: u32, per_item: u32, per_minute: u32 };

    pub fn get(p: *const Prices, set: u16, method: u8) Price {
        if (set >= size) return .{ .w = 1, .per_item = 0, .per_minute = 0 };
        const s = &p.sets[set];
        return .{
            .w = @atomicLoad(u32, &s.w[method], .monotonic),
            .per_item = @atomicLoad(u32, &s.per_item[method], .monotonic),
            .per_minute = @atomicLoad(u32, &s.per_minute[method], .monotonic),
        };
    }

    pub fn inUse(p: *const Prices) u32 {
        var n: u32 = 0;
        for (p.refs) |r| n += @intFromBool(r != 0);
        return n;
    }
};

/// Plan names for metric labels: the keyless tier, "none", up to 13 the gate names, "other".
pub const Plans = struct {
    names: [size][contract.max_plan_len]u8 = undefined,
    lens: [size]u8 = @splat(0),
    n: Atomic(u32) = .init(2),

    pub const size = 16;
    pub const free: u8 = 0;
    pub const none: u8 = 1;
    pub const other: u8 = size - 1;

    pub fn init() Plans {
        var p: Plans = .{};
        p.set(free, "keyless");
        p.set(none, "none");
        p.set(other, "other");
        return p;
    }

    fn set(p: *Plans, i: u8, text: []const u8) void {
        @memcpy(p.names[i][0..text.len], text);
        p.lens[i] = @intCast(text.len);
    }

    /// Writer lock held.
    pub fn intern(p: *Plans, text: []const u8) u8 {
        if (text.len == 0) return none;
        const n = p.n.load(.monotonic);
        for (0..n) |i| if (std.mem.eql(u8, p.names[i][0..p.lens[i]], text)) return @intCast(i);
        if (std.mem.eql(u8, text, "other") or n >= other) return other;
        // a label value: keep it to what a metric line can carry unescaped
        for (text) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.')) return other;
        p.set(@intCast(n), text);
        p.n.store(n + 1, .release);
        return @intCast(n);
    }

    pub fn name(p: *const Plans, i: u8) []const u8 {
        const k = if (i < p.n.load(.acquire) or i == other) i else other;
        return p.names[k][0..p.lens[k]];
    }
};

/// Refusal texts the gate sent, kept verbatim. Index 0 is "none". A full pool answers 0 (the
/// node's own text is used).
pub const Messages = struct {
    text: [size][contract.max_message_len]u8 = undefined,
    lens: [size]Atomic(u32) = @splat(.init(0)),
    n: u8 = 1,

    pub const size = 64;

    /// Writer lock held.
    pub fn intern(m: *Messages, s: []const u8) u8 {
        if (s.len == 0 or s.len > contract.max_message_len) return 0;
        for (1..m.n) |i| if (std.mem.eql(u8, m.text[i][0..m.lens[i].load(.monotonic)], s)) return @intCast(i);
        if (m.n == size) return 0;
        const i = m.n;
        @memcpy(m.text[i][0..s.len], s);
        m.lens[i].store(@intCast(s.len), .release);
        m.n += 1;
        return i;
    }

    pub fn get(m: *const Messages, i: u8) []const u8 {
        if (i == 0 or i >= size) return "";
        return m.text[i][0..m.lens[i].load(.acquire)];
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "bucket: a burst, then the steady rate, within 1 percent over a minute" {
    const cases = [_]struct { rps: f64, burst: u32, offered_hz: u64 }{
        .{ .rps = 50, .burst = 100, .offered_hz = 1000 },
        .{ .rps = 3, .burst = 5, .offered_hz = 97 },
        .{ .rps = 2000, .burst = 4000, .offered_hz = 10_000 },
        .{ .rps = 0.5, .burst = 1, .offered_hz = 10 },
    };
    for (cases) |c| {
        var tat: Atomic(u64) = .init(0);
        const iv = intervalNs(c.rps);
        const burst_ns = @as(u64, c.burst) * iv;
        const t0: u64 = 1_000_000 * std.time.ns_per_s;
        const step = std.time.ns_per_s / c.offered_hz;
        var allowed: u64 = 0;
        var in_first_instant: u64 = 0;
        // the burst is there at once
        for (0..c.burst * 2) |_| {
            if (take(&tat, t0, iv, burst_ns, 1) == null) in_first_instant += 1;
        }
        try testing.expectEqual(@as(u64, c.burst), in_first_instant);
        allowed = in_first_instant;
        var now = t0;
        while (now < t0 + 60 * std.time.ns_per_s) {
            now += step;
            if (take(&tat, now, iv, burst_ns, 1) == null) allowed += 1;
        }
        const want: f64 = @as(f64, @floatFromInt(c.burst)) + c.rps * 60;
        const got: f64 = @floatFromInt(allowed);
        try testing.expect(@abs(got - want) <= want * 0.01);
    }
}

test "bucket: weights, retry-after, a zero rate, a cost above the burst, debt" {
    var tat: Atomic(u64) = .init(0);
    const iv = intervalNs(10); // 100 ms a unit
    const burst_ns = 20 * iv;
    var now: u64 = 5_000 * std.time.ns_per_s;
    // 20 units of burst: four calls of weight 5
    for (0..4) |_| try testing.expect(take(&tat, now, iv, burst_ns, 5) == null);
    // the next one of weight 5 has to wait for five units: 500 ms
    try testing.expectEqual(@as(?u64, 500 * std.time.ns_per_ms), take(&tat, now, iv, burst_ns, 5));
    // a refusal takes nothing: one unit is there after 100 ms
    try testing.expectEqual(@as(?u64, 100 * std.time.ns_per_ms), take(&tat, now, iv, burst_ns, 1));
    now += 100 * std.time.ns_per_ms;
    try testing.expect(take(&tat, now, iv, burst_ns, 1) == null);
    // cost 0 always passes and takes nothing
    const before = tat.load(.monotonic);
    try testing.expect(take(&tat, now, iv, burst_ns, 0) == null);
    try testing.expectEqual(before, tat.load(.monotonic));
    // a zero rate passes nothing
    var z: Atomic(u64) = .init(0);
    try testing.expect(take(&z, now, intervalNs(0), 0, 1) != null);
    try testing.expectEqual(@as(u64, 0), intervalNs(-1));
    // a call that costs more than the burst passes on a full bucket, then the bucket is in debt
    var big: Atomic(u64) = .init(0);
    try testing.expect(take(&big, now, iv, 2 * iv, 50) == null);
    try testing.expect(take(&big, now, iv, 2 * iv, 1) != null);
    try testing.expect(take(&big, now + 50 * iv, iv, 2 * iv, 1) == null);
    // debt from a forwarded call's extra units delays the next call by exactly that much: the
    // call's own unit and the four booked after it
    var d: Atomic(u64) = .init(0);
    try testing.expect(take(&d, now, iv, iv, 1) == null);
    try testing.expectEqual(@as(?u64, iv), take(&d, now, iv, iv, 1));
    debit(&d, now, iv, 4);
    try testing.expectEqual(@as(?u64, 5 * iv), take(&d, now, iv, iv, 1));
}

fn neverEvict(_: void, _: *const Entry, _: Cfg) u64 {
    return 0;
}
fn evictInvalid(_: void, _: *const Entry, c: Cfg) u64 {
    return if (c.status == .invalid) 1 else 0;
}

test "key table: find, replace in place, a full window, eviction" {
    const gpa = testing.allocator;
    var t = try KeyTable.init(gpa, 64);
    defer t.deinit(gpa);
    const h1: u128 = (@as(u128, 0xaaaa) << 64) | 7;
    try testing.expect(t.find(h1) == null);
    const p1 = t.place(h1, {}, neverEvict).?;
    try testing.expect(!p1.existing);
    t.entries[p1.idx].setKid("kid_one");
    t.entries[p1.idx].write(@truncate(h1 >> 64), .{ .status = .ok, .plan = 3, .interval_ns = 1000, .burst_ns = 5000, .forward_milli = 1500, .max_streams = 4, .expires_ns = 99, .leased = true, .lease_total = 77, .set = 9, .msg = 2, .deny_msg = 5 });
    t.publish(p1.idx, h1);
    const f = t.find(h1).?;
    try testing.expectEqual(p1.idx, f.idx);
    try testing.expectEqual(KeyStatus.ok, f.cfg.status);
    try testing.expectEqual(@as(u8, 3), f.cfg.plan);
    try testing.expectEqual(@as(u32, 1500), f.cfg.forward_milli);
    try testing.expectEqual(@as(u32, 4), f.cfg.max_streams);
    try testing.expectEqual(@as(u64, 77), f.cfg.lease_total);
    try testing.expectEqual(@as(u16, 9), f.cfg.set);
    try testing.expectEqual(@as(u8, 2), f.cfg.msg);
    try testing.expectEqual(@as(u8, 5), f.cfg.deny_msg);
    try testing.expect(f.cfg.leased);
    var kb: [contract.max_key_id_len]u8 = undefined;
    try testing.expectEqualStrings("kid_one", t.entries[f.idx].readKid(f.tenant, &kb).?);
    try testing.expect(t.entries[f.idx].kidEquals("kid_one"));
    // the same low half with another high half is another key
    const h2: u128 = (@as(u128, 0xbbbb) << 64) | 7;
    try testing.expect(t.find(h2) == null);
    try testing.expect(t.place(h1, {}, neverEvict).?.existing);
    // fill the window of low half 7: 15 more fit, the 17th does not
    var k: u64 = 1;
    while (k < KeyTable.window) : (k += 1) {
        const h: u128 = (@as(u128, k) << 64) | 7;
        const p = t.place(h, {}, neverEvict).?;
        t.entries[p.idx].write(k, .{ .status = .invalid });
        t.publish(p.idx, h);
    }
    try testing.expectEqual(@as(u32, KeyTable.window), t.used.load(.monotonic));
    const extra: u128 = (@as(u128, 0xcccc) << 64) | 7;
    try testing.expect(t.place(extra, {}, neverEvict) == null);
    // with a policy that gives up invalid entries, one of them makes room
    const pe = t.place(extra, {}, evictInvalid).?;
    try testing.expect(!pe.existing and pe.victim and pe.idx != p1.idx);
    t.remove(pe.idx);
    try testing.expectEqual(@as(u32, KeyTable.window - 1), t.used.load(.monotonic));
    // a reader holding the old tenant no longer gets a key id after the slot changes hands
    const old_tenant = t.entries[p1.idx].tenant.load(.monotonic);
    t.remove(p1.idx);
    try testing.expect(t.find(h1) == null);
    t.entries[p1.idx].setKid("kid_two");
    try testing.expect(t.entries[p1.idx].readKid(old_tenant, &kb) == null);
}

test "ip table: one slot per address, overflow when full, idle slots freed" {
    const gpa = testing.allocator;
    var t = try IpTable.init(gpa, 8, 0x1234);
    defer t.deinit(gpa);
    const a = t.get(1, 100);
    try testing.expect(a == t.get(1, 100));
    try testing.expect(a != t.get(2, 100));
    // far more addresses than slots: memory does not grow, the extra ones share one bucket
    var k: u128 = 10;
    while (k < 1000) : (k += 1) _ = t.get(k, 100);
    try testing.expectEqual(@as(u32, 8), t.count());
    try testing.expect(t.overflowed.load(.monotonic) > 900);
    // a slot with a stream open stays; idle ones go after `idle_s`
    a.streams.store(1, .monotonic);
    _ = t.sweep(100 + 59, 60, 0, 8);
    try testing.expectEqual(@as(u32, 8), t.count());
    _ = t.sweep(100 + 60, 60, 0, 8);
    try testing.expectEqual(@as(u32, 1), t.count());
    try testing.expect(a == t.get(1, 200));
}

test "ip deny: found until it ends, bounded, the earliest entry gives way" {
    var d: IpDeny = .{};
    try testing.expect(d.find(42, 10) == null);
    d.put(42, 1000, .exhausted, 3, 10);
    const hit = d.find(42, 999).?;
    try testing.expectEqual(KeyStatus.exhausted, hit.status);
    try testing.expectEqual(@as(u8, 3), hit.msg);
    try testing.expect(d.find(42, 1000) == null);
    try testing.expect(d.find(43, 10) == null);
    // an update moves the end
    d.put(42, 5000, .suspended, 0, 10);
    try testing.expectEqual(KeyStatus.suspended, d.find(42, 4000).?.status);
    try testing.expectEqual(@as(u32, 1), d.n.load(.monotonic));
    // many more than the table holds: the count stays within it
    var k: u64 = 100;
    while (k < 100 + 10 * IpDeny.size) : (k += 1) d.put(k, 9000 + k, .exhausted, 0, 10);
    try testing.expect(d.n.load(.monotonic) <= IpDeny.size);
    d.sweep(1 << 40);
    try testing.expectEqual(@as(u32, 0), d.n.load(.monotonic));
}

test "intern pools: prices shared and bounded, plans capped for labels, messages verbatim" {
    const gpa = testing.allocator;
    const p = try gpa.create(Prices);
    defer gpa.destroy(p);
    p.* = .{};
    var s1: methods.PriceSet = .{};
    s1.w[3] = 9;
    const a = p.intern(&s1).?;
    try testing.expectEqual(a, p.intern(&s1).?);
    try testing.expectEqual(@as(u32, 9), p.get(a, 3).w);
    var s2 = s1;
    s2.per_item[4] = 10;
    const b = p.intern(&s2).?;
    try testing.expect(a != b);
    try testing.expectEqual(@as(u32, 2), p.inUse());
    p.release(a);
    try testing.expectEqual(@as(u32, 2), p.inUse()); // still one holder
    p.release(a);
    try testing.expectEqual(@as(u32, 1), p.inUse());
    // the pool is bounded
    var n: u32 = 0;
    var s3: methods.PriceSet = .{};
    while (n < Prices.size + 10) : (n += 1) {
        s3.w[5] = 1000 + n;
        if (p.intern(&s3) == null) break;
    }
    try testing.expectEqual(@as(u32, Prices.size - 1), n);

    var plans = Plans.init();
    try testing.expectEqualStrings("keyless", plans.name(Plans.free));
    const dev = plans.intern("developer");
    try testing.expectEqual(dev, plans.intern("developer"));
    try testing.expectEqualStrings("developer", plans.name(dev));
    try testing.expectEqual(Plans.none, plans.intern(""));
    try testing.expectEqual(Plans.other, plans.intern("has \"quotes\""));
    var nb: [8]u8 = undefined;
    for (0..40) |i| _ = plans.intern(std.fmt.bufPrint(&nb, "p{d}", .{i}) catch unreachable);
    try testing.expectEqual(Plans.other, plans.intern("one-too-many"));
    try testing.expectEqualStrings("other", plans.name(Plans.other));

    const m = try gpa.create(Messages);
    defer gpa.destroy(m);
    m.* = .{};
    const first = m.intern("Out of credits. Top up at gate.example.");
    try testing.expect(first != 0);
    try testing.expectEqual(first, m.intern("Out of credits. Top up at gate.example."));
    try testing.expectEqualStrings("Out of credits. Top up at gate.example.", m.get(first));
    try testing.expectEqualStrings("", m.get(0));
    try testing.expectEqual(@as(u8, 0), m.intern(""));
    var mb: [16]u8 = undefined;
    for (0..200) |i| _ = m.intern(std.fmt.bufPrint(&mb, "text {d}", .{i}) catch unreachable);
    try testing.expectEqual(@as(u8, 0), m.intern("no room left"));
}
