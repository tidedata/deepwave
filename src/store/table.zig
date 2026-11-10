//! Index structures of the store. All are derived from the segment logs and rebuilt from them
//! when missing or damaged.
//!
//! `LiveTable`: ObjectID -> location of the newest version or tombstone record. A linear-probing
//! hash table of 20-byte slots laid out in 4096-byte pages (204 slots plus a page checksum),
//! struct of arrays: the 204 locations first (every one 8-byte aligned, so lock-free readers load
//! them atomically), then the 204 keys, then the checksum. A slot's key is 96 bits of
//! SipHash-2-4-128 of the id's last 24 bytes, keyed by a 16-byte secret drawn from the OS when
//! the store is created and kept in `meta` (lane disk-fit; until then a slot held those 24 bytes
//! themselves, 32-byte slots, 127 per page: `LegacyPage`, read only to migrate an old table).
//!
//! Why 96 bits is enough. Two ids share a key only by chance: object ids cannot be ground
//! against a key nobody outside the store knows (the secret never leaves the store directory,
//! and the clock-derived `seed` is not used for it). By the birthday bound the odds that any two
//! of n ids collide are about n^2 / 2^97: 6e-12 at 10^9 ids, far below the odds of an undetected
//! disk or memory error over the store's life. If it happened anyway, the writer would treat the
//! second id as the first (one slot for both); readers would not return the wrong object: every
//! read path checks the full 32-byte id in the record the slot names (`Snapshot.latest`,
//! `visibleLoc`, `objectFind`, the iterators), and a head record of another id reads as absent.
//! The id tail (not the full id) is hashed so an old table's slots migrate without the records.
//!
//! The table lives in a file-backed private mapping (`index/live-<tg>.tbl`): clean pages are page
//! cache (evictable), only pages changed since the last flush are private memory, and only those
//! pages are written at a flush (store.zig). Deleting a slot (a tombstone dropped by pruning) uses
//! backward-shift deletion, so capacity is bounded by the live set plus the retained tombstones,
//! not by history. One writer, lock-free readers: inserts and updates publish with release stores;
//! deletions move slots under a sequence lock that readers validate.
//!
//! Size: `livePagesFor(c)` pages hold c + c/7 + 1 slots, so a table sized for c objects takes
//! ceil((c + c/7 + 1) / 204) * 4096 bytes, 20.08 bytes per slot. A restore sizes it for 1.25x
//! the objects (store.zig `bulkLiveFinish`): 1.4286 slots per object, 28.7 bytes per object;
//! 772.9M objects -> 22.2 GB (21,142 MiB; 32-byte slots: 35.6 GB, 33,962 MiB).
//!
//! `KeyTable`: u64 key -> location, the memtable for object versions and transactions (in
//! memory, spanning epoch changes). `CpArray`: checkpoint seq -> location, append-only and
//! sorted. `Run`: a sealed, immutable, memory-mapped copy of one memtable
//! (`index/<epoch>-<run>.run`, in the slot of the epoch its range ends in), written once and
//! dropped with that segment. Runs are never merged.
const std = @import("std");
const checksum = @import("checksum.zig");

pub const Error = error{IndexFull};

// ---------------------------------------------------------------------------------- live table

/// Tombstone flag in a live location (records are 8-byte aligned, so bit 0 of a location is 0).
pub const tomb: u64 = 1;

/// Compact-record flag in a live location (bit 1): the newest version is a compact record (no
/// version-index entry), so superseding it needs a link record, decided without a read.
pub const compact: u64 = 2;

pub inline fn locOf(x: u64) u64 {
    return x & ~(tomb | compact);
}

/// Bytes of the object id a key is derived from (and a legacy slot held).
pub const tail_len = 24;
pub const Tail = [tail_len]u8;

pub inline fn tailOf(id: *const [32]u8) *const Tail {
    return id[32 - tail_len ..][0..tail_len];
}

/// Bytes of a slot key.
pub const key_len = 12;
pub const Key = [key_len]u8;
/// The store's key secret (meta `live_key`).
pub const Secret = [16]u8;

const Sip = std.crypto.auth.siphash.SipHash128(2, 4);

/// The slot key of an id tail under `secret`: the first 96 bits of SipHash-2-4-128.
pub fn keyOfTail(secret: *const Secret, tail: *const Tail) Key {
    var out: [Sip.mac_length]u8 = undefined;
    Sip.create(&out, tail, secret);
    return out[0..key_len].*;
}

pub fn keyOf(secret: *const Secret, id: *const [32]u8) Key {
    return keyOfTail(secret, tailOf(id));
}

pub const per_page = 204;
pub const page_size = 4096;

pub const Page = extern struct {
    /// 0: empty. Else the record location, `| tomb` for a tombstone.
    locs: [per_page]u64,
    keys: [per_page][key_len]u8,
    _r: u64 = 0,
    /// checksum.hash over bytes [0, 4088) seeded with the page number; 0 for an all-zero page.
    sum: u64 = 0,
};

/// The 32-byte slot of tables written before lane disk-fit (key = the id tail itself). Only
/// read, to migrate such a table (store.zig `migrateLive`).
pub const LegacySlot = extern struct {
    id: Tail align(8),
    loc: u64,
};

pub const legacy_per_page = 127;

pub const LegacyPage = extern struct {
    slots: [legacy_per_page]LegacySlot,
    _r: [3]u64 = @splat(0),
    sum: u64 = 0,
};

comptime {
    std.debug.assert(@sizeOf(Page) == page_size);
    std.debug.assert(@offsetOf(Page, "keys") % 4 == 0 and key_len % 4 == 0);
    std.debug.assert(@offsetOf(Page, "sum") == page_size - 8);
    std.debug.assert(@sizeOf(LegacySlot) == 32);
    std.debug.assert(@sizeOf(LegacyPage) == page_size);
    std.debug.assert(@offsetOf(LegacyPage, "sum") == page_size - 8);
}

/// Maximum fill (occupied slots, live plus tombstones) before the table must grow.
pub fn liveLimit(nslots: u64) u64 {
    return nslots - nslots / 8;
}

pub fn livePagesFor(capacity: u64) u64 {
    const slots = capacity + capacity / 7 + 1;
    return @max(1, std.math.divCeil(u64, slots, per_page) catch unreachable);
}

/// Key `j` of a page as three u32 words (4-byte aligned: `keys` starts at offset 1632).
inline fn keyWords(pg: *Page, j: usize) *[3]u32 {
    return @ptrCast(@alignCast(&pg.keys[j]));
}

inline fn keyWordsConst(pg: *const Page, j: usize) *const [3]u32 {
    return @ptrCast(@alignCast(&pg.keys[j]));
}

/// Writes slot `j` of a page that no reader sees (a bulk build's window, a migration page).
pub fn setSlot(pg: *Page, j: usize, key: *const Key, l: u64) void {
    pg.keys[j] = key.*;
    pg.locs[j] = l;
}

pub const Change = enum { none, inserted_live, inserted_tomb, updated, live_to_tomb, tomb_to_live };


/// Copy-on-write state of a background flush (store.zig `FlushJob`). While a flush runs, the
/// pages it writes (`frozen`, the dirty set at the freeze) must keep their frozen bytes until
/// the flusher has copied them: the writer's first touch of a page in a generation takes
/// `lock` and, for a frozen page the flusher has not captured yet, saves its bytes first. The
/// flusher copies pages and drops private pages under the same lock, so a page it sees clean
/// (dirty bit 0, checked under the lock) cannot change until it releases the lock.
pub const Cow = struct {
    lock_word: std.atomic.Value(u32) = .init(0),
    /// The frozen dirty set (pages the flush writes), immutable while the flush runs.
    frozen: []const u64,
    /// Frozen pages the flusher has copied (set under the lock).
    captured: []u64,
    /// Bytes of frozen pages saved by the writer before it changed them (under the lock).
    saved: std.AutoHashMapUnmanaged(u64, *[page_size]u8) = .empty,
    gpa: std.mem.Allocator,
    /// Pages saved by the writer (stats).
    saves: u64 = 0,

    pub fn lock(c: *Cow) void {
        while (c.lock_word.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }

    pub fn unlock(c: *Cow) void {
        c.lock_word.store(0, .release);
    }

    pub inline fn bit(words: []const u64, p: u64) bool {
        return @atomicLoad(u64, &words[p / 64], .monotonic) & (@as(u64, 1) << @intCast(p % 64)) != 0;
    }

    pub fn deinit(c: *Cow) void {
        var it = c.saved.valueIterator();
        while (it.next()) |v| c.gpa.destroy(v.*);
        c.saved.deinit(c.gpa);
    }
};

pub const LiveTable = struct {
    pages: []align(page_size) Page,
    nslots: u64,
    seed: u64,
    secret: Secret,
    /// Sequence lock over deletions (odd while slots move).
    seq: std.atomic.Value(u64) = .init(0),
    // ---- writer only
    count: u64 = 0,
    live: u64 = 0,
    dirty: []u64,
    ndirty: u64 = 0,
    /// Set by the store while a background flush runs (see `Cow`); null otherwise.
    cow: ?*Cow = null,

    pub fn init(gpa: std.mem.Allocator, pages: []align(page_size) Page, seed: u64, secret: Secret) !LiveTable {
        const words = std.math.divCeil(usize, pages.len, 64) catch unreachable;
        const dirty = try gpa.alloc(u64, words);
        @memset(dirty, 0);
        return .{ .pages = pages, .nslots = pages.len * per_page, .seed = seed, .secret = secret, .dirty = dirty };
    }

    pub fn deinit(t: *LiveTable, gpa: std.mem.Allocator) void {
        gpa.free(t.dirty);
    }

    /// The slot key of `full` in this table.
    pub fn keyFor(t: *const LiveTable, full: *const [32]u8) Key {
        return keyOf(&t.secret, full);
    }

    inline fn home(t: *const LiveTable, key: *const Key) u64 {
        return homeOf(t.seed, t.nslots, key);
    }

    /// Reader: the home slot of `full` (its page is `homeSlot / per_page`), for read-ahead.
    pub fn homeSlot(t: *const LiveTable, full: *const [32]u8) u64 {
        const k = t.keyFor(full);
        return t.home(&k);
    }

    inline fn next(t: *const LiveTable, i: u64) u64 {
        return if (i + 1 == t.nslots) 0 else i + 1;
    }

    /// Slot `i`'s location word (read it with an atomic load outside the writer).
    pub inline fn locPtr(t: *const LiveTable, i: u64) *u64 {
        return &t.pages[i / per_page].locs[i % per_page];
    }

    /// Writer: slot `i`'s key.
    pub inline fn keyAt(t: *const LiveTable, i: u64) *const Key {
        return &t.pages[i / per_page].keys[i % per_page];
    }

    inline fn keyEqAtomic(t: *const LiveTable, i: u64, key: *const Key) bool {
        const w = keyWordsConst(&t.pages[i / per_page], i % per_page);
        inline for (0..3) |j| {
            const k = std.mem.readInt(u32, key[j * 4 ..][0..4], .native);
            if (@atomicLoad(u32, &w[j], .acquire) != k) return false;
        }
        return true;
    }

    /// Reader-safe lookup: the published location of `id` (tomb bit included), or null.
    pub fn get(t: *const LiveTable, full: *const [32]u8) ?u64 {
        const key = t.keyFor(full);
        return t.getKey(&key);
    }

    pub fn getKey(t: *const LiveTable, key: *const Key) ?u64 {
        const h = t.home(key);
        while (true) {
            const s0 = t.seq.load(.acquire);
            if (s0 & 1 != 0) {
                std.atomic.spinLoopHint();
                continue;
            }
            var i = h;
            const r: ?u64 = while (true) : (i = t.next(i)) {
                const l = @atomicLoad(u64, t.locPtr(i), .acquire);
                if (l == 0) break null;
                if (t.keyEqAtomic(i, key)) break l;
            };
            if (t.seq.load(.acquire) == s0) return r;
        }
    }

    /// Writer: index of the slot holding `id`.
    pub fn find(t: *const LiveTable, full: *const [32]u8) ?u64 {
        const key = t.keyFor(full);
        return t.findKey(&key);
    }

    pub fn findKey(t: *const LiveTable, key: *const Key) ?u64 {
        var i = t.home(key);
        while (true) : (i = t.next(i)) {
            if (t.locPtr(i).* == 0) return null;
            if (std.mem.eql(u8, t.keyAt(i), key)) return i;
        }
    }

    pub fn locAt(t: *const LiveTable, i: u64) u64 {
        return t.locPtr(i).*;
    }

    /// Writer: the location of `id` (tomb bit included), or null.
    pub fn lookup(t: *const LiveTable, id: *const [32]u8) ?u64 {
        return if (t.find(id)) |i| t.locAt(i) else null;
    }

    /// Writer, before it changes slot `i`: marks its page dirty. The first touch of a page in a
    /// flush generation also saves the page's frozen bytes while a background flush still needs
    /// them (`Cow`). The dirty bit is published (under the flush lock) before any byte changes.
    inline fn touch(t: *LiveTable, i: u64) void {
        const p = i / per_page;
        const bit = @as(u64, 1) << @intCast(p % 64);
        if (t.dirty[p / 64] & bit != 0) return;
        if (t.cow) |c| t.touchSlow(c, p) else @atomicStore(u64, &t.dirty[p / 64], t.dirty[p / 64] | bit, .monotonic);
        t.ndirty += 1;
    }

    fn touchSlow(t: *LiveTable, c: *Cow, p: u64) void {
        const bit = @as(u64, 1) << @intCast(p % 64);
        while (true) {
            c.lock();
            if (Cow.bit(c.frozen, p) and !Cow.bit(c.captured, p) and !c.saved.contains(p)) {
                const copy = c.gpa.create([page_size]u8) catch null;
                const ok = if (copy) |cp| blk: {
                    c.saved.put(c.gpa, p, cp) catch {
                        c.gpa.destroy(cp);
                        break :blk false;
                    };
                    const src: *const [page_size]u8 = @ptrCast(&t.pages[p]);
                    cp.* = src.*;
                    c.saves += 1;
                    break :blk true;
                } else false;
                if (!ok) {
                    // Out of memory for the copy: wait for the flusher to capture the page.
                    c.unlock();
                    while (!Cow.bit(c.captured, p)) std.atomic.spinLoopHint();
                    continue;
                }
            }
            @atomicStore(u64, &t.dirty[p / 64], t.dirty[p / 64] | bit, .seq_cst);
            c.unlock();
            return;
        }
    }

    fn storeKey(t: *LiveTable, i: u64, key: *const Key) void {
        const w = keyWords(&t.pages[i / per_page], i % per_page);
        inline for (0..3) |j| @atomicStore(u32, &w[j], std.mem.readInt(u32, key[j * 4 ..][0..4], .native), .monotonic);
    }

    fn storeSlot(t: *LiveTable, i: u64, key: *const Key, l: u64) void {
        t.touch(i);
        t.storeKey(i, key);
        @atomicStore(u64, t.locPtr(i), l, .release);
    }

    /// Writer: sets `id` to `l` unless it already holds an equal or later location (idempotent
    /// and monotone, so replaying the log over any older table state converges).
    pub fn upsert(t: *LiveTable, full: *const [32]u8, l: u64) Error!Change {
        const key = t.keyFor(full);
        return t.upsertKey(&key, l);
    }

    pub fn upsertKey(t: *LiveTable, key: *const Key, l: u64) Error!Change {
        var i = t.home(key);
        while (true) : (i = t.next(i)) {
            const cur = t.locPtr(i).*;
            if (cur == 0) {
                if (t.count >= liveLimit(t.nslots)) return error.IndexFull;
                t.storeSlot(i, key, l);
                t.count += 1;
                if (l & tomb == 0) {
                    t.live += 1;
                    return .inserted_live;
                }
                return .inserted_tomb;
            }
            if (std.mem.eql(u8, t.keyAt(i), key)) {
                if (locOf(l) <= locOf(cur)) return .none;
                const was_tomb = cur & tomb != 0;
                t.touch(i);
                @atomicStore(u64, t.locPtr(i), l, .release);
                const is_tomb = l & tomb != 0;
                if (was_tomb and !is_tomb) {
                    t.live += 1;
                    return .tomb_to_live;
                }
                if (!was_tomb and is_tomb) {
                    t.live -= 1;
                    return .live_to_tomb;
                }
                return .updated;
            }
        }
    }

    /// Writer: deletes `id` if its slot holds exactly `l` (backward-shift deletion under the
    /// sequence lock). Returns whether it deleted.
    pub fn remove(t: *LiveTable, full: *const [32]u8, l: u64) bool {
        var i = t.find(full) orelse return false;
        if (t.locAt(i) != l) return false;
        _ = t.seq.fetchAdd(1, .acq_rel);
        defer _ = t.seq.fetchAdd(1, .release);
        if (l & tomb == 0) t.live -= 1;
        t.count -= 1;
        var j = i;
        while (true) {
            j = t.next(j);
            const lj = t.locAt(j);
            if (lj == 0) break;
            const kj = t.keyAt(j).*;
            const k = t.home(&kj);
            // slot j may move to i when its home is not cyclically within (i, j].
            const within = if (i <= j) (k > i and k <= j) else (k > i or k <= j);
            if (!within) {
                t.storeSlot(i, &kj, lj);
                i = j;
            }
        }
        t.touch(i);
        @atomicStore(u64, t.locPtr(i), 0, .release);
        const zero: Key = @splat(0);
        t.storeKey(i, &zero);
        return true;
    }

    /// Writer: every occupied slot (for growth and checks).
    pub fn forEach(t: *const LiveTable, ctx: anytype, comptime f: fn (@TypeOf(ctx), *const Key, u64) anyerror!void) !void {
        for (t.pages) |*p| for (&p.locs, &p.keys) |l, *k| if (l != 0) try f(ctx, k, l);
    }

    pub fn pageSum(t: *const LiveTable, p: u64) u64 {
        const bytes: *const [page_size]u8 = @ptrCast(&t.pages[p]);
        return pageChecksum(t.seed, p, bytes);
    }

    /// Writer: stores the page checksum into page `p` (before the page is written out).
    pub fn sealPage(t: *LiveTable, p: u64) void {
        const bytes: *const [page_size]u8 = @ptrCast(&t.pages[p]);
        t.pages[p].sum = pageChecksum(t.seed, p, bytes);
    }

    /// The page checksum of a copy of page `p` (what `sealPage` stores, without touching the
    /// table): a background flush seals its copies, never the shared pages.
    pub fn sealCopy(t: *const LiveTable, p: u64, bytes: *[page_size]u8) void {
        const sum = pageChecksum(t.seed, p, bytes);
        std.mem.writeInt(u64, bytes[page_size - 8 ..], sum, .little);
    }

    pub fn clearDirty(t: *LiveTable) void {
        @memset(t.dirty, 0);
        t.ndirty = 0;
    }

    pub fn isDirty(t: *const LiveTable, p: u64) bool {
        return t.dirty[p / 64] & (@as(u64, 1) << @intCast(p % 64)) != 0;
    }
};

/// The home slot of `key` in a table of `nslots` slots hashed with `seed` (also the order a bulk
/// build places keys in).
pub inline fn homeOf(seed: u64, nslots: u64, key: *const Key) u64 {
    const h = checksum.hash(seed, key);
    return @truncate((@as(u128, h) * nslots) >> 64);
}


pub fn pageChecksum(seed: u64, p: u64, bytes: *const [page_size]u8) u64 {
    return checksum.hash(seed ^ (p *% 0x9e3779b97f4a7c15) ^ 0x6c697665, bytes[0 .. page_size - 8]);
}

/// A page read from disk is valid when its checksum matches. Every page written is sealed, an
/// empty one included, so an all-zero page is a lost or zeroed write; it passes only with
/// `allow_zero`: a table or journal written before empty pages were sealed, or a table page
/// never written (a fresh table file is sparse).
pub fn pageValid(seed: u64, p: u64, bytes: *const [page_size]u8, allow_zero: bool) bool {
    const sum = std.mem.readInt(u64, bytes[page_size - 8 ..], .little);
    if (sum == 0 and std.mem.allEqual(u8, bytes, 0)) return allow_zero;
    return sum == pageChecksum(seed, p, bytes);
}

// ---------------------------------------------------------------------------------- key tables

fn capacityFor(max_items: u64) u64 {
    // load factor at most 7/8
    return std.math.ceilPowerOfTwo(u64, @max(16, max_items + max_items / 7 + 1)) catch unreachable;
}

/// u64 key -> location. Keys are hashes; collisions are resolved by the caller checking the
/// record, so equal keys may occupy several slots. 16 bytes per slot.
pub const KeyEntry = extern struct {
    key: u64,
    loc: u64,
};

inline fn keyHome(seed: u64, mask: u64, key: u64) u64 {
    var x = key ^ seed;
    x = (x ^ (x >> 30)) *% 0xbf58476d1ce4e5b9;
    x = (x ^ (x >> 27)) *% 0x94d049bb133111eb;
    return (x ^ (x >> 31)) & mask;
}

/// Read-only probe view of a key table (memtable or sealed run region).
pub const KeyView = struct {
    entries: []const KeyEntry,
    mask: u64,
    seed: u64,

    pub fn find(v: KeyView, key: u64) Iter {
        if (v.entries.len == 0) return .{ .v = v, .key = key, .i = 0, .end = true };
        return .{ .v = v, .key = key, .i = keyHome(v.seed, v.mask, key) };
    }

    pub const Iter = struct {
        v: KeyView,
        key: u64,
        i: u64,
        end: bool = false,

        pub fn next(it: *Iter) ?u64 {
            if (it.end) return null;
            while (true) {
                const e = &it.v.entries[it.i];
                const l = @atomicLoad(u64, &e.loc, .acquire);
                if (l == 0) {
                    it.end = true;
                    return null;
                }
                it.i = (it.i + 1) & it.v.mask;
                if (e.key == it.key) return l;
            }
        }
    };
};

pub const KeyTable = struct {
    entries: []KeyEntry,
    mask: u64,
    seed: u64,
    count: u64 = 0,
    limit: u64,

    pub fn init(gpa: std.mem.Allocator, max_items: u64, seed: u64) !KeyTable {
        const cap = capacityFor(max_items);
        const entries = try gpa.alloc(KeyEntry, cap);
        @memset(std.mem.sliceAsBytes(entries), 0);
        return .{ .entries = entries, .mask = cap - 1, .seed = seed, .limit = max_items };
    }

    pub fn deinit(t: *KeyTable, gpa: std.mem.Allocator) void {
        gpa.free(t.entries);
    }

    pub fn reset(t: *KeyTable) void {
        if (t.count != 0) @memset(std.mem.sliceAsBytes(t.entries), 0);
        t.count = 0;
    }

    pub fn view(t: *const KeyTable) KeyView {
        return .{ .entries = t.entries, .mask = t.mask, .seed = t.seed };
    }

    pub fn find(t: *const KeyTable, key: u64) KeyView.Iter {
        return t.view().find(key);
    }

    /// Writer: adds (key, l) unless that exact pair is present (idempotent replay).
    pub fn put(t: *KeyTable, key: u64, l: u64) Error!void {
        var i = keyHome(t.seed, t.mask, key);
        while (true) : (i = (i + 1) & t.mask) {
            const e = &t.entries[i];
            if (e.loc == 0) {
                if (t.count >= t.limit) return error.IndexFull;
                e.key = key;
                @atomicStore(u64, &e.loc, l, .release);
                t.count += 1;
                return;
            }
            if (e.key == key and e.loc == l) return;
        }
    }
};

/// Fills `out` (capacity a power of two, zeroed) with every entry of `src`.
fn rehashInto(out: []KeyEntry, seed: u64, src: []const KeyEntry) void {
    if (out.len == 0) return;
    const mask = out.len - 1;
    for (src) |e| {
        if (e.loc == 0) continue;
        var i = keyHome(seed, mask, e.key);
        while (out[i].loc != 0) i = (i + 1) & mask;
        out[i] = e;
    }
}

pub const CpEntry = extern struct {
    seq: u64,
    loc: u64,
};

/// Checkpoint seq -> location, appended in increasing seq order.
pub const CpArray = struct {
    entries: []CpEntry,
    n: std.atomic.Value(u64) = .init(0),

    pub fn init(gpa: std.mem.Allocator, max: u64) !CpArray {
        return .{ .entries = try gpa.alloc(CpEntry, @max(1, max)) };
    }

    pub fn deinit(c: *CpArray, gpa: std.mem.Allocator) void {
        gpa.free(c.entries);
    }

    pub fn len(c: *const CpArray) u64 {
        return c.n.load(.monotonic);
    }

    pub fn append(c: *CpArray, seq: u64, l: u64) Error!void {
        const n = c.n.load(.monotonic);
        if (n > 0 and c.entries[n - 1].seq == seq and c.entries[n - 1].loc == l) return;
        if (n >= c.entries.len) return error.IndexFull;
        c.entries[n] = .{ .seq = seq, .loc = l };
        c.n.store(n + 1, .release);
    }

    pub fn slice(c: *const CpArray) []const CpEntry {
        return c.entries[0..c.n.load(.acquire)];
    }
};

/// Location of `seq` in a sorted checkpoint array.
pub fn cpFind(cps: []const CpEntry, seq: u64) ?u64 {
    if (cps.len == 0 or seq < cps[0].seq or seq > cps[cps.len - 1].seq) return null;
    // Dense ranges (the common case) resolve in one step.
    const guess = seq - cps[0].seq;
    if (guess < cps.len and cps[guess].seq == seq) return cps[guess].loc;
    var lo: usize = 0;
    var hi: usize = cps.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (cps[mid].seq < seq) lo = mid + 1 else hi = mid;
    }
    if (lo < cps.len and cps[lo].seq == seq) return cps[lo].loc;
    return null;
}

/// The memtable: object versions, transactions and checkpoints of the log range
/// [start_loc, ...), across epochs. Sealed into a `Run` when full or at close; `epoch` is the
/// epoch of the run's end, set when sealing.
pub const Mem = struct {
    ver: KeyTable,
    tx: KeyTable,
    cps: CpArray,
    epoch: u64 = std.math.maxInt(u64),
    start_loc: u64 = 0,
    /// Checksum of the commit record just before `start_loc` (null: unknown).
    start_anchor: ?u64 = null,

    pub fn init(gpa: std.mem.Allocator, max_ver: u64, max_tx: u64, max_cp: u64, seed: u64) !*Mem {
        const m = try gpa.create(Mem);
        errdefer gpa.destroy(m);
        var ver = try KeyTable.init(gpa, max_ver, seed ^ 0x1);
        errdefer ver.deinit(gpa);
        var tx = try KeyTable.init(gpa, max_tx, seed ^ 0x2);
        errdefer tx.deinit(gpa);
        const cps = try CpArray.init(gpa, max_cp);
        m.* = .{ .ver = ver, .tx = tx, .cps = cps };
        return m;
    }

    pub fn deinit(m: *Mem, gpa: std.mem.Allocator) void {
        m.ver.deinit(gpa);
        m.tx.deinit(gpa);
        m.cps.deinit(gpa);
        gpa.destroy(m);
    }

    pub fn reset(m: *Mem) void {
        m.ver.reset();
        m.tx.reset();
        m.cps.n.store(0, .monotonic);
        m.epoch = std.math.maxInt(u64);
        m.start_loc = 0;
        m.start_anchor = null;
    }

    pub fn empty(m: *const Mem) bool {
        return m.ver.count == 0 and m.tx.count == 0 and m.cps.len() == 0;
    }

    /// Whether `ver`, `tx` and `cp` more entries fit.
    pub fn fits(m: *const Mem, ver: u64, tx: u64, cp: u64) bool {
        return m.ver.count + ver <= m.ver.limit and m.tx.count + tx <= m.tx.limit and m.cps.len() + cp <= m.cps.entries.len;
    }
};

// ---------------------------------------------------------------------------------- sealed runs

pub const RunHeader = extern struct {
    magic: [8]u8 = "ZUIRUN01".*,
    algo: u32,
    _r: u32 = 0,
    checksum: u64 = 0,
    seed: u64,
    epoch: u64,
    run: u64,
    start_loc: u64,
    end_loc: u64,
    has_anchor: u64,
    /// Commit checksum at `end_loc` (the chain anchor for whatever follows the run).
    end_anchor: u64,
    min_seq: u64,
    max_seq: u64,
    ver_slots: u64,
    tx_slots: u64,
    ncp: u64,
    ver_count: u64,
    tx_count: u64,
    /// Pages after the header page: ver region, tx region, cp region, then the page sums.
    data_pages: u64,
    sums_hash: u64,

    pub fn sum(h: *const RunHeader) u64 {
        var c = h.*;
        c.checksum = 0;
        return checksum.hash(0x72756e68, std.mem.asBytes(&c));
    }
};

fn pagesOf(bytes: u64) u64 {
    return std.math.divCeil(u64, bytes, page_size) catch unreachable;
}

pub const RunLayout = struct {
    ver_off: u64,
    tx_off: u64,
    cp_off: u64,
    sums_off: u64,
    data_pages: u64,
    total: u64,

    pub fn of(ver_slots: u64, tx_slots: u64, ncp: u64) RunLayout {
        const ver_off: u64 = page_size;
        const tx_off = ver_off + pagesOf(ver_slots * 16) * page_size;
        const cp_off = tx_off + pagesOf(tx_slots * 16) * page_size;
        const sums_off = cp_off + pagesOf(ncp * 16) * page_size;
        const data_pages = (sums_off - page_size) / page_size;
        const total = sums_off + pagesOf(data_pages * 8) * page_size;
        return .{ .ver_off = ver_off, .tx_off = tx_off, .cp_off = cp_off, .sums_off = sums_off, .data_pages = data_pages, .total = total };
    }
};

// ---------------------------------------------------------------------------------- run filters

/// Per-run key filter: a split-block Bloom filter (32-byte blocks, 8 bits set per key, one in
/// each 32-bit word). A lookup that the filter rules out skips the run's index page, so a cold
/// lookup reads only the runs that may hold the key. The filter section sits after the run
/// image (`RunLayout.total`): runs written before filters end there and open without one
/// (every lookup probes them), and older readers ignore the trailing section.
pub const Bloom = struct {
    blocks: []const [8]u32,
    seed: u64,

    const salt = [8]u32{ 0x47b6137b, 0x44974d91, 0x8824ad5b, 0xa2b7289d, 0x705495c7, 0x2df1424b, 0x9efc4947, 0x5c6bfb31 };
    pub const bits_per_key = 10;

    pub fn blocksFor(n: u64) u64 {
        if (n == 0) return 0;
        return @max(1, std.math.divCeil(u64, n * bits_per_key, 256) catch unreachable);
    }

    inline fn mix(seed: u64, key: u64) u64 {
        var x = key ^ seed ^ 0x626c6f6f6d66696c;
        x = (x ^ (x >> 33)) *% 0xff51afd7ed558ccd;
        x = (x ^ (x >> 33)) *% 0xc4ceb9fe1a85ec53;
        return x ^ (x >> 33);
    }

    inline fn blockOf(h: u64, n: usize) usize {
        return @intCast((@as(u128, h) * n) >> 64);
    }

    /// False: no key of the run has this value. True: it may (or the filter is empty of blocks
    /// because the region has no keys at all, which answers false).
    pub fn mayContain(b: Bloom, key: u64) bool {
        if (b.blocks.len == 0) return false;
        const h = mix(b.seed, key);
        const blk = &b.blocks[blockOf(h, b.blocks.len)];
        const lo: u32 = @truncate(h);
        inline for (0..8) |i| {
            const bit: u5 = @intCast((lo *% salt[i]) >> 27);
            if (blk[i] & (@as(u32, 1) << bit) == 0) return false;
        }
        return true;
    }

    pub fn insert(blocks: [][8]u32, seed: u64, key: u64) void {
        const h = mix(seed, key);
        const blk = &blocks[blockOf(h, blocks.len)];
        const lo: u32 = @truncate(h);
        inline for (0..8) |i| {
            const bit: u5 = @intCast((lo *% salt[i]) >> 27);
            blk[i] |= @as(u32, 1) << bit;
        }
    }
};

/// Header page of a run's filter section (at `RunLayout.total`), followed by the version
/// filter's blocks, then the transaction filter's, padded to a page.
pub const FilterHeader = extern struct {
    magic: [8]u8 = "ZUIFLT01".*,
    checksum: u64 = 0,
    seed: u64,
    ver_blocks: u64,
    tx_blocks: u64,
    /// checksum.hash over the block bytes (both filters).
    data_hash: u64,

    pub fn sum(h: *const FilterHeader) u64 {
        var c = h.*;
        c.checksum = 0;
        return checksum.hash(0x666c7468, std.mem.asBytes(&c));
    }

    pub fn sectionLen(ver_blocks: u64, tx_blocks: u64) u64 {
        return page_size + pagesOf((ver_blocks + tx_blocks) * 32) * page_size;
    }
};

/// The filter seed of a run: its header's checksum mixed in (that covers the run's locations,
/// key counts and page sums), so a self-consistent filter section of another run (a stale or
/// misplaced one: same store seed, same layout) never validates as this run's. A filter that
/// wrongly rules a key out would hide it from every lookup.
fn filterSeed(h: *const RunHeader) u64 {
    return h.seed ^ std.math.rotl(u64, h.checksum, 29) ^ 0x9e3779b97f4a7c15;
}

fn fillFilter(blocks: [][8]u32, seed: u64, entries: []const KeyEntry) void {
    if (blocks.len == 0) return;
    for (entries) |e| {
        if (e.loc == 0) continue;
        Bloom.insert(blocks, seed, e.key);
    }
}

/// The filter section of a run image, checked: null when the run has none (written before
/// filters) or it is damaged (the run is then probed like an unfiltered one).
fn openFilters(view: []const u8, total: u64, h: *const RunHeader) ?struct { ver: Bloom, tx: Bloom } {
    if (view.len < total + page_size) return null;
    var fh: FilterHeader = undefined;
    @memcpy(std.mem.asBytes(&fh), view[total..][0..@sizeOf(FilterHeader)]);
    if (!std.mem.eql(u8, &fh.magic, "ZUIFLT01") or fh.sum() != fh.checksum) return null;
    if (fh.seed != filterSeed(h)) return null;
    if (fh.ver_blocks != Bloom.blocksFor(h.ver_count) or fh.tx_blocks != Bloom.blocksFor(h.tx_count)) return null;
    if (fh.ver_blocks > (1 << 36) or fh.tx_blocks > (1 << 36)) return null;
    const data_len = (fh.ver_blocks + fh.tx_blocks) * 32;
    if (view.len < total + page_size + data_len) return null;
    const data = view[total + page_size ..][0..data_len];
    if (checksum.hash(0x666c7464, data) != fh.data_hash) return null;
    const all: []const [8]u32 = @alignCast(std.mem.bytesAsSlice([8]u32, data));
    return .{
        .ver = .{ .blocks = all[0..fh.ver_blocks], .seed = fh.seed },
        .tx = .{ .blocks = all[fh.ver_blocks..], .seed = fh.seed },
    };
}

/// Serializes `m` (covering [m.start_loc, end_loc)) into a run file image.
pub fn buildRun(gpa: std.mem.Allocator, m: *const Mem, run: u64, end_loc: u64, end_anchor: ?u64) ![]align(page_size) u8 {
    const ver_slots: u64 = if (m.ver.count == 0) 0 else capacityFor(m.ver.count);
    const tx_slots: u64 = if (m.tx.count == 0) 0 else capacityFor(m.tx.count);
    const cps = m.cps.slice();
    const lay = RunLayout.of(ver_slots, tx_slots, cps.len);
    const ver_blocks = Bloom.blocksFor(m.ver.count);
    const tx_blocks = Bloom.blocksFor(m.tx.count);
    const img = try gpa.alignedAlloc(u8, .fromByteUnits(page_size), lay.total + FilterHeader.sectionLen(ver_blocks, tx_blocks));
    @memset(img, 0);
    const ver: []KeyEntry = @alignCast(std.mem.bytesAsSlice(KeyEntry, img[lay.ver_off..][0 .. ver_slots * 16]));
    rehashInto(ver, m.ver.seed, m.ver.entries);
    const tx: []KeyEntry = @alignCast(std.mem.bytesAsSlice(KeyEntry, img[lay.tx_off..][0 .. tx_slots * 16]));
    rehashInto(tx, m.tx.seed, m.tx.entries);
    @memcpy(img[lay.cp_off..][0 .. cps.len * 16], std.mem.sliceAsBytes(cps));
    const sums: []u64 = @alignCast(std.mem.bytesAsSlice(u64, img[lay.sums_off..][0 .. lay.data_pages * 8]));
    for (sums, 0..) |*s, p| s.* = checksum.hash(p ^ 0x72756e70, img[page_size + p * page_size ..][0..page_size]);
    var h: RunHeader = .{
        .algo = checksum.current_algo,
        // The memtable's base seed (ver uses seed ^ 1, tx seed ^ 2).
        .seed = m.ver.seed ^ 0x1,
        .epoch = m.epoch,
        .run = run,
        .start_loc = m.start_loc,
        .end_loc = end_loc,
        .has_anchor = @intFromBool(end_anchor != null),
        .end_anchor = end_anchor orelse 0,
        .min_seq = if (cps.len > 0) cps[0].seq else 0,
        .max_seq = if (cps.len > 0) cps[cps.len - 1].seq else 0,
        .ver_slots = ver_slots,
        .tx_slots = tx_slots,
        .ncp = cps.len,
        .ver_count = m.ver.count,
        .tx_count = m.tx.count,
        .data_pages = lay.data_pages,
        .sums_hash = checksum.hash(0x73756d73, std.mem.sliceAsBytes(sums)),
    };
    h.checksum = h.sum();
    @memcpy(img[0..@sizeOf(RunHeader)], std.mem.asBytes(&h));
    // The filter section (after the run proper: see Bloom).
    const fseed = filterSeed(&h);
    const fdata = img[lay.total + page_size ..][0 .. (ver_blocks + tx_blocks) * 32];
    const fblocks: [][8]u32 = @alignCast(std.mem.bytesAsSlice([8]u32, fdata));
    fillFilter(fblocks[0..ver_blocks], fseed, m.ver.entries);
    fillFilter(fblocks[ver_blocks..], fseed, m.tx.entries);
    var fh: FilterHeader = .{ .seed = fseed, .ver_blocks = ver_blocks, .tx_blocks = tx_blocks, .data_hash = checksum.hash(0x666c7464, fdata) };
    fh.checksum = fh.sum();
    @memcpy(img[lay.total..][0..@sizeOf(FilterHeader)], std.mem.asBytes(&fh));
    return img;
}

/// A sealed run, mapped read-only. Immutable once published.
pub const Run = struct {
    header: RunHeader,
    view: []const u8,
    fd: u32,
    ver: KeyView,
    tx: KeyView,
    cps: []const CpEntry,
    /// Key filters (null: the run has none, every lookup probes it). They point into `view`, or
    /// into `filter_mem` once the store copied them to memory (Store.pinFilters).
    ver_filter: ?Bloom = null,
    tx_filter: ?Bloom = null,
    filter_mem: ?[]align(64) u8 = null,

    /// Parses and checks a mapped run file (`deep`: every data page checksum too).
    pub fn open(view: []const u8, fd: u32, deep: bool) error{Corrupt}!Run {
        if (view.len < page_size) return error.Corrupt;
        var h: RunHeader = undefined;
        @memcpy(std.mem.asBytes(&h), view[0..@sizeOf(RunHeader)]);
        if (!std.mem.eql(u8, &h.magic, "ZUIRUN01") or h.algo != checksum.current_algo or h.sum() != h.checksum) return error.Corrupt;
        if (h.ver_slots > (1 << 40) or h.tx_slots > (1 << 40) or h.ncp > (1 << 40)) return error.Corrupt;
        if ((h.ver_slots != 0 and !std.math.isPowerOfTwo(h.ver_slots)) or (h.tx_slots != 0 and !std.math.isPowerOfTwo(h.tx_slots))) return error.Corrupt;
        const lay = RunLayout.of(h.ver_slots, h.tx_slots, h.ncp);
        if (lay.data_pages != h.data_pages or view.len < lay.total) return error.Corrupt;
        const sums_bytes = view[lay.sums_off..][0 .. lay.data_pages * 8];
        if (checksum.hash(0x73756d73, sums_bytes) != h.sums_hash) return error.Corrupt;
        if (deep) {
            for (0..lay.data_pages) |p| {
                const want = std.mem.readInt(u64, sums_bytes[p * 8 ..][0..8], .little);
                if (checksum.hash(p ^ 0x72756e70, view[page_size + p * page_size ..][0..page_size]) != want) return error.Corrupt;
            }
        }
        const ver: []const KeyEntry = @alignCast(std.mem.bytesAsSlice(KeyEntry, view[lay.ver_off..][0 .. h.ver_slots * 16]));
        const tx: []const KeyEntry = @alignCast(std.mem.bytesAsSlice(KeyEntry, view[lay.tx_off..][0 .. h.tx_slots * 16]));
        const cps: []const CpEntry = @alignCast(std.mem.bytesAsSlice(CpEntry, view[lay.cp_off..][0 .. h.ncp * 16]));
        const flt = openFilters(view, lay.total, &h);
        return .{
            .header = h,
            .view = view,
            .fd = fd,
            .ver = .{ .entries = ver, .mask = if (h.ver_slots == 0) 0 else h.ver_slots - 1, .seed = h.seed ^ 0x1 },
            .tx = .{ .entries = tx, .mask = if (h.tx_slots == 0) 0 else h.tx_slots - 1, .seed = h.seed ^ 0x2 },
            .cps = cps,
            .ver_filter = if (flt) |f| f.ver else null,
            .tx_filter = if (flt) |f| f.tx else null,
        };
    }

    /// Whether the version index may hold `key` (false: skip the run).
    pub fn mayHaveVer(r: *const Run, key: u64) bool {
        const f = r.ver_filter orelse return true;
        return f.mayContain(key);
    }

    /// Whether the transaction index may hold `key` (false: skip the run).
    pub fn mayHaveTx(r: *const Run, key: u64) bool {
        const f = r.tx_filter orelse return true;
        return f.mayContain(key);
    }

    /// Bytes of the filter blocks (both filters), for copying them out of the mapping.
    pub fn filterBytes(r: *const Run) []const u8 {
        const v = r.ver_filter orelse return &.{};
        const t = r.tx_filter.?;
        const n = v.blocks.len + t.blocks.len;
        if (n == 0) return &.{};
        const base: [*]const u8 = if (v.blocks.len > 0) @ptrCast(v.blocks.ptr) else @ptrCast(t.blocks.ptr);
        return base[0 .. n * 32];
    }

    /// Points the filters at `mem`, a copy of `filterBytes` (64-byte aligned).
    pub fn useFilterMem(r: *Run, mem: []align(64) u8) void {
        const v = r.ver_filter.?;
        const all: []const [8]u32 = @alignCast(std.mem.bytesAsSlice([8]u32, @as([]const u8, mem)));
        r.ver_filter = .{ .blocks = all[0..v.blocks.len], .seed = v.seed };
        r.tx_filter = .{ .blocks = all[v.blocks.len..], .seed = v.seed };
        r.filter_mem = mem;
    }

    pub fn findCp(r: *const Run, seq: u64) ?u64 {
        return cpFind(r.cps, seq);
    }
};

// ---------------------------------------------------------------------------------- tests

fn testId(n: u64) [32]u8 {
    var id: [32]u8 = @splat(0);
    std.mem.writeInt(u64, id[0..8], n *% 0x9e3779b97f4a7c15, .little);
    std.mem.writeInt(u64, id[24..32], n, .big);
    return id;
}

fn heapPages(gpa: std.mem.Allocator, n: usize) ![]align(page_size) Page {
    const b = try gpa.alignedAlloc(Page, .fromByteUnits(page_size), n);
    @memset(std.mem.sliceAsBytes(b), 0);
    return b;
}

const test_secret: Secret = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

test "live table: 20-byte slots, struct of arrays, keys under the secret" {
    try std.testing.expectEqual(@as(usize, 1632), @offsetOf(Page, "keys"));
    try std.testing.expectEqual(@as(usize, 4080), @offsetOf(Page, "_r"));
    // 773M objects, sized like a restore (1.25x): about 22.2 GB.
    const n: u64 = 772_902_304;
    const pages = livePagesFor(n + n / 4);
    try std.testing.expect(pages * page_size < 22_300_000_000 and pages * page_size > 22_100_000_000);
    // The key depends on the secret and the id tail only.
    var id = testId(9);
    const k1 = keyOf(&test_secret, &id);
    id[0] ^= 0xff; // outside the tail
    try std.testing.expectEqualSlices(u8, &k1, &keyOf(&test_secret, &id));
    var other = test_secret;
    other[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &k1, &keyOf(&other, &id)));
    // Every slot of a page lands where the struct-of-arrays layout says.
    const gpa = std.testing.allocator;
    const pg = try heapPages(gpa, 2);
    defer gpa.free(pg);
    var t = try LiveTable.init(gpa, pg, 5, test_secret);
    defer t.deinit(gpa);
    var k: u64 = 0;
    while (k < liveLimit(t.nslots)) : (k += 1) _ = try t.upsert(&testId(k), 8 * (k + 1));
    k = 0;
    while (k < liveLimit(t.nslots)) : (k += 1) {
        const i = t.find(&testId(k)).?;
        try std.testing.expectEqual(8 * (k + 1), pg[i / per_page].locs[i % per_page]);
        try std.testing.expectEqualSlices(u8, &t.keyFor(&testId(k)), &pg[i / per_page].keys[i % per_page]);
    }
}

test "live table: two ids with one key share a slot (the writer cannot tell them apart)" {
    // A forced collision: the table answers by key, so the second id's location replaces the
    // first's. Readers then check the id in the record (store tests: "a key collision reads
    // as absent").
    const gpa = std.testing.allocator;
    const pages = try heapPages(gpa, 1);
    defer gpa.free(pages);
    var t = try LiveTable.init(gpa, pages, 2, test_secret);
    defer t.deinit(gpa);
    const key = t.keyFor(&testId(1));
    try std.testing.expectEqual(Change.inserted_live, try t.upsertKey(&key, 64));
    try std.testing.expectEqual(Change.updated, try t.upsertKey(&key, 128));
    try std.testing.expectEqual(@as(?u64, 128), t.get(&testId(1)));
    try std.testing.expectEqual(@as(u64, 1), t.count);
}

test "live table upsert is monotone, idempotent, counts" {
    const gpa = std.testing.allocator;
    const pages = try heapPages(gpa, 2);
    defer gpa.free(pages);
    var t = try LiveTable.init(gpa, pages, 7, test_secret);
    defer t.deinit(gpa);
    const id = testId(5);
    try std.testing.expectEqual(Change.inserted_live, try t.upsert(&id, 104));
    try std.testing.expectEqual(Change.none, try t.upsert(&id, 56));
    try std.testing.expectEqual(@as(?u64, 104), t.get(&id));
    try std.testing.expectEqual(Change.live_to_tomb, try t.upsert(&id, 208 | tomb));
    try std.testing.expectEqual(@as(u64, 0), t.live);
    try std.testing.expectEqual(Change.tomb_to_live, try t.upsert(&id, 304));
    try std.testing.expectEqual(@as(u64, 1), t.live);
    const other = testId(6);
    try std.testing.expectEqual(@as(?u64, null), t.get(&other));
    try std.testing.expectEqual(@as(u64, 1), t.count);
    try std.testing.expect(!t.remove(&id, 208 | tomb));
    try std.testing.expect(t.remove(&id, 304));
    try std.testing.expectEqual(@as(?u64, null), t.get(&id));
    try std.testing.expectEqual(@as(u64, 0), t.count);
}

test "live table deletion keeps every other key reachable (fill, churn, wraparound)" {
    const gpa = std.testing.allocator;
    const pages = try heapPages(gpa, 3);
    defer gpa.free(pages);
    var t = try LiveTable.init(gpa, pages, 3, test_secret);
    defer t.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(11);
    const r = prng.random();
    var present: [400]?u64 = @splat(null);
    var step: u64 = 1;
    for (0..20_000) |_| {
        const k = r.uintLessThan(usize, present.len);
        const id = testId(k);
        if (present[k]) |l| {
            if (r.boolean()) {
                try std.testing.expect(t.remove(&id, l));
                present[k] = null;
            } else {
                step += 1;
                _ = try t.upsert(&id, step * 8);
                present[k] = step * 8;
            }
        } else if (t.count < liveLimit(t.nslots)) {
            step += 1;
            _ = try t.upsert(&id, step * 8);
            present[k] = step * 8;
        }
        if (step % 97 == 0) for (present, 0..) |p, q| try std.testing.expectEqual(p, t.get(&testId(q)));
    }
    var n: u64 = 0;
    for (present, 0..) |p, q| {
        try std.testing.expectEqual(p, t.get(&testId(q)));
        if (p != null) n += 1;
    }
    try std.testing.expectEqual(n, t.count);
}

test "live table full" {
    const gpa = std.testing.allocator;
    const pages = try heapPages(gpa, 1);
    defer gpa.free(pages);
    var t = try LiveTable.init(gpa, pages, 1, test_secret);
    defer t.deinit(gpa);
    var k: u64 = 0;
    while (k < liveLimit(t.nslots)) : (k += 1) _ = try t.upsert(&testId(k), 8 * (k + 1));
    try std.testing.expectError(error.IndexFull, t.upsert(&testId(k), 8));
}

test "page checksums" {
    var page: [page_size]u8 align(page_size) = @splat(0);
    // An all-zero page is a lost write unless the table predates sealed empty pages.
    try std.testing.expect(pageValid(5, 3, &page, true));
    try std.testing.expect(!pageValid(5, 3, &page, false));
    // A sealed empty page is valid either way.
    std.mem.writeInt(u64, page[page_size - 8 ..], pageChecksum(5, 3, &page), .little);
    try std.testing.expect(pageValid(5, 3, &page, false));
    @memset(&page, 0);
    page[17] = 1;
    try std.testing.expect(!pageValid(5, 3, &page, true));
    const s = pageChecksum(5, 3, &page);
    std.mem.writeInt(u64, page[page_size - 8 ..], s, .little);
    try std.testing.expect(pageValid(5, 3, &page, false));
    try std.testing.expect(!pageValid(5, 4, &page, false));
}

test "key table duplicates" {
    var t = try KeyTable.init(std.testing.allocator, 100, 9);
    defer t.deinit(std.testing.allocator);
    try t.put(5, 10);
    try t.put(5, 10);
    try t.put(5, 20);
    try t.put(6, 30);
    var it = t.find(5);
    try std.testing.expectEqual(@as(?u64, 10), it.next());
    try std.testing.expectEqual(@as(?u64, 20), it.next());
    try std.testing.expectEqual(@as(?u64, null), it.next());
    try std.testing.expectEqual(@as(u64, 3), t.count);
}

test "index full" {
    var t = try KeyTable.init(std.testing.allocator, 2, 1);
    defer t.deinit(std.testing.allocator);
    try t.put(1, 2);
    try t.put(2, 3);
    try std.testing.expectError(error.IndexFull, t.put(3, 4));
}

test "run round trip" {
    const gpa = std.testing.allocator;
    const m = try Mem.init(gpa, 64, 64, 16, 42);
    defer m.deinit(gpa);
    m.epoch = 3;
    m.start_loc = 24;
    for (0..40) |i| try m.ver.put(i * 7919, 8 * (i + 10));
    for (0..9) |i| try m.tx.put(i * 104729, 8 * (i + 100));
    for (0..5) |i| try m.cps.append(100 + i * 2, 8 * (i + 1000));
    const img = try buildRun(gpa, m, 0, 999 * 8, 77);
    defer gpa.free(img);
    const r = try Run.open(img, 0, true);
    for (0..40) |i| {
        var it = r.ver.find(i * 7919);
        try std.testing.expectEqual(@as(?u64, 8 * (i + 10)), it.next());
    }
    for (0..9) |i| {
        var it = r.tx.find(i * 104729);
        try std.testing.expectEqual(@as(?u64, 8 * (i + 100)), it.next());
    }
    var miss = r.tx.find(5);
    try std.testing.expectEqual(@as(?u64, null), miss.next());
    try std.testing.expectEqual(@as(?u64, 8 * 1002), r.findCp(104));
    try std.testing.expectEqual(@as(?u64, null), r.findCp(105));
    try std.testing.expectEqual(@as(u64, 77), r.header.end_anchor);
    img[page_size + 3] ^= 1;
    try std.testing.expectError(error.Corrupt, Run.open(img, 0, true));
}

test "run filters: every key passes, most others are ruled out; a run without a filter section probes everything; a damaged one is dropped" {
    const gpa = std.testing.allocator;
    const m = try Mem.init(gpa, 2048, 512, 16, 5);
    defer m.deinit(gpa);
    m.epoch = 2;
    m.start_loc = 24;
    var prng: std.Random.DefaultPrng = .init(23);
    const rnd = prng.random();
    var vkeys: [2000]u64 = undefined;
    var tkeys: [500]u64 = undefined;
    for (&vkeys, 0..) |*k, i| {
        k.* = rnd.int(u64);
        try m.ver.put(k.*, 8 * (i + 10));
    }
    for (&tkeys, 0..) |*k, i| {
        k.* = rnd.int(u64);
        try m.tx.put(k.*, 8 * (i + 5000));
    }
    try m.cps.append(7, 8 * 9000);
    const img = try buildRun(gpa, m, 0, 9999 * 8, null);
    defer gpa.free(img);
    const lay = RunLayout.of(capacityFor(vkeys.len), capacityFor(tkeys.len), 1);
    try std.testing.expectEqual(lay.total + FilterHeader.sectionLen(Bloom.blocksFor(vkeys.len), Bloom.blocksFor(tkeys.len)), img.len);

    const r = try Run.open(img, 0, true);
    try std.testing.expect(r.ver_filter != null and r.tx_filter != null);
    for (vkeys) |k| try std.testing.expect(r.mayHaveVer(k));
    for (tkeys) |k| try std.testing.expect(r.mayHaveTx(k));
    var fp_ver: usize = 0;
    var fp_tx: usize = 0;
    for (0..20_000) |_| {
        const k = rnd.int(u64);
        if (r.mayHaveVer(k)) fp_ver += 1;
        if (r.mayHaveTx(k)) fp_tx += 1;
    }
    // 10 bits per key: about 1% false positives; 5% leaves room for the small sizes here.
    try std.testing.expect(fp_ver < 1000);
    try std.testing.expect(fp_tx < 1000);

    // Copied out of the mapping (Store.pinFilters): same answers.
    var pinned = r;
    const fb = pinned.filterBytes();
    const mem = try gpa.alignedAlloc(u8, .fromByteUnits(64), fb.len);
    defer gpa.free(mem);
    @memcpy(mem, fb);
    pinned.useFilterMem(mem);
    for (vkeys) |k| try std.testing.expect(pinned.mayHaveVer(k));
    for (tkeys) |k| try std.testing.expect(pinned.mayHaveTx(k));
    var prng2: std.Random.DefaultPrng = .init(99);
    for (0..5000) |_| {
        const k = prng2.random().int(u64);
        try std.testing.expectEqual(r.mayHaveVer(k), pinned.mayHaveVer(k));
        try std.testing.expectEqual(r.mayHaveTx(k), pinned.mayHaveTx(k));
    }

    // A run written before filters (the image ends at the run proper): no filter, every key probes.
    const old = try Run.open(img[0..lay.total], 0, true);
    try std.testing.expect(old.ver_filter == null and old.tx_filter == null);
    try std.testing.expect(old.mayHaveVer(12345) and old.mayHaveTx(12345));
    for (vkeys) |k| {
        var it = old.ver.find(k);
        try std.testing.expect(it.next() != null);
    }

    // A flipped bit in the filter blocks or its header: the run opens without a filter.
    img[lay.total + page_size + 77] ^= 4;
    const bad = try Run.open(img, 0, true);
    try std.testing.expect(bad.ver_filter == null and bad.tx_filter == null);
    img[lay.total + page_size + 77] ^= 4;
    img[lay.total + 20] ^= 1;
    const bad_h = try Run.open(img, 0, true);
    try std.testing.expect(bad_h.ver_filter == null);
    img[lay.total + 20] ^= 1;
    const good = try Run.open(img, 0, false);
    try std.testing.expect(good.ver_filter != null);
}

test "run filters: an empty region rules every key out" {
    const gpa = std.testing.allocator;
    const m = try Mem.init(gpa, 64, 64, 16, 8);
    defer m.deinit(gpa);
    m.epoch = 1;
    m.start_loc = 24;
    try m.ver.put(42, 800);
    try m.cps.append(3, 900);
    const img = try buildRun(gpa, m, 0, 999 * 8, null);
    defer gpa.free(img);
    const r = try Run.open(img, 0, true);
    try std.testing.expect(r.mayHaveVer(42));
    try std.testing.expect(!r.mayHaveTx(42));
    try std.testing.expect(!r.mayHaveTx(7));
}

test "run filters: a valid filter section of another run (same store seed and counts) is refused" {
    const gpa = std.testing.allocator;
    var imgs: [2][]align(page_size) u8 = undefined;
    for (&imgs, 0..) |*img, n| {
        const m = try Mem.init(gpa, 256, 64, 16, 5);
        defer m.deinit(gpa);
        m.epoch = 2;
        m.start_loc = 24;
        for (0..200) |i| try m.ver.put((i + 1) *% 0x9e3779b97f4a7c15 +% n * 1000003, 8 * (i + 10));
        for (0..40) |i| try m.tx.put((i + 1) *% 0xc2b2ae3d27d4eb4f +% n * 1000003, 8 * (i + 500));
        try m.cps.append(7 + n, 8 * 900);
        img.* = try buildRun(gpa, m, 0, (999 + n) * 8, null);
    }
    defer for (imgs) |img| gpa.free(img);
    try std.testing.expectEqual(imgs[0].len, imgs[1].len);
    const lay = RunLayout.of(capacityFor(200), capacityFor(40), 1);
    // Run 1's filter section in run 0's image: self-consistent, but not run 0's.
    @memcpy(imgs[0][lay.total..], imgs[1][lay.total..]);
    const r = try Run.open(imgs[0], 0, true);
    try std.testing.expect(r.ver_filter == null and r.tx_filter == null);
    for (0..200) |i| try std.testing.expect(r.mayHaveVer((i + 1) *% 0x9e3779b97f4a7c15));
}
