//! Signature speed layer: caches and parallel batches that change no verdict.
//!
//! Everything here is OFF by default (`configure` turns pieces on), so the full node's behaviour
//! is untouched until a flag enables it. Every fast path gives the verdict the plain path gives:
//!   - public-key caches: decoding a key is a pure function of its bytes, so a decoded key (or the
//!     fact that it does not decode) is cached under those bytes. Ed25519, secp256k1, secp256r1.
//!   - zkLogin proof cache: a Groth16 success is a pure function of (mode, usage, keys, the
//!     authenticator's proof inputs, the JWK modulus). Only successes are cached; a failure is
//!     recomputed so its error text is always the live one.
//!   - Ed25519 verified-signature cache: `ed25519.verify(pk, msg, sig)` accepting is a pure
//!     function of the three byte strings; only acceptances are cached, under a Blake2b-256 of
//!     (pk, msg, sig), so a hit stands for exactly that triple and anything else is recomputed.
//!   - parallel Ed25519 batch: the batch verdict is "every item verifies"; splitting the items over
//!     threads and and-ing the results gives the same verdict (ed25519-consensus semantics).
//!   - multisig: all-Ed25519 members are checked in one batch; only a passing batch is trusted, a
//!     failing one falls back to the member-by-member path, which decides the verdict.
const std = @import("std");
const hash = @import("hash");
const core = @import("core");
const zk = @import("zk");
const zkl = zk.zklogin;
const ed25519 = @import("ed25519.zig");
const ecdsa = @import("ecdsa.zig");
const verdict = @import("verdict.zig");
const Verdict = verdict.Verdict;

const Atomic = std.atomic.Value;
const ZkFail = @typeInfo(@TypeOf(zkl.verify)).@"fn".return_type.?;

// ---------------------------------------------------------------------------------------------
// Switches

pub const Config = struct {
    /// Cache decoded public keys (Ed25519, secp256k1, secp256r1).
    pk_cache: bool = false,
    /// Cache successful zkLogin proof verifications.
    zk_cache: bool = false,
    /// Cache accepted single Ed25519 signatures (user signatures and zkLogin ephemeral
    /// signatures; filled by the single path and by the validator's Ed25519 pre-step).
    ed_verified_cache: bool = false,
    /// Check Ed25519 members of a multisig in one batch when there are at least this many
    /// (0: off). Needs at least 2.
    multisig_batch_min: u8 = 0,
};

var sw_pk: Atomic(bool) = .init(false);
var sw_zk: Atomic(bool) = .init(false);
var sw_edv: Atomic(bool) = .init(false);
var sw_ms: Atomic(u8) = .init(0);

pub fn configure(c: Config) void {
    sw_pk.store(c.pk_cache, .monotonic);
    sw_zk.store(c.zk_cache, .monotonic);
    sw_edv.store(c.ed_verified_cache, .monotonic);
    sw_ms.store(if (c.multisig_batch_min == 1) 2 else c.multisig_batch_min, .monotonic);
}

pub fn pkCacheOn() bool {
    return sw_pk.load(.monotonic);
}

pub fn zkCacheOn() bool {
    return sw_zk.load(.monotonic);
}

pub fn edVerifiedOn() bool {
    return sw_edv.load(.monotonic);
}

pub fn config() Config {
    return .{ .pk_cache = sw_pk.load(.monotonic), .zk_cache = sw_zk.load(.monotonic), .ed_verified_cache = sw_edv.load(.monotonic), .multisig_batch_min = sw_ms.load(.monotonic) };
}

/// Everything on, with the defaults to measure first.
pub const all_on: Config = .{ .pk_cache = true, .zk_cache = true, .ed_verified_cache = true, .multisig_batch_min = 4 };

// ---------------------------------------------------------------------------------------------
// Sharded set-associative cache

const SpinLock = struct {
    v: Atomic(u32) = .init(0),
    fn lock(l: *SpinLock) void {
        while (l.v.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn tryLock(l: *SpinLock) bool {
        return l.v.cmpxchgStrong(0, 1, .acquire, .monotonic) == null;
    }
    fn unlock(l: *SpinLock) void {
        l.v.store(0, .release);
    }
};

pub const Stats = struct { hits: u64, misses: u64, inserts: u64 };

/// Fixed-size cache: `shards` locks, each guarding `ways` entries; a key maps to one shard by its
/// hash and replaces round-robin inside it. Keys are fixed-size byte arrays compared whole.
pub fn Cache(comptime key_len: usize, comptime Val: type, comptime shards: usize, comptime ways: usize) type {
    return struct {
        const Self = @This();
        const Entry = struct { used: bool = false, key: [key_len]u8 = undefined, val: Val = undefined };
        const Shard = struct {
            lock: SpinLock = .{},
            next: u8 = 0,
            hits: u64 = 0,
            misses: u64 = 0,
            inserts: u64 = 0,
            e: [ways]Entry = @splat(.{}),
        };
        shards_: [shards]Shard = @splat(.{}),

        fn shardOf(key: *const [key_len]u8) usize {
            return @intCast(std.hash.Wyhash.hash(0x7a756963616368, key) % shards);
        }

        pub fn get(c: *Self, key: *const [key_len]u8) ?Val {
            const s = &c.shards_[shardOf(key)];
            s.lock.lock();
            defer s.lock.unlock();
            for (&s.e) |*e| {
                if (e.used and std.mem.eql(u8, &e.key, key)) {
                    s.hits += 1;
                    return e.val;
                }
            }
            s.misses += 1;
            return null;
        }

        /// Whether `key` is cached, without counting a hit or a miss.
        pub fn contains(c: *Self, key: *const [key_len]u8) bool {
            const s = &c.shards_[shardOf(key)];
            s.lock.lock();
            defer s.lock.unlock();
            for (&s.e) |*e| if (e.used and std.mem.eql(u8, &e.key, key)) return true;
            return false;
        }

        pub fn put(c: *Self, key: *const [key_len]u8, val: Val) void {
            const s = &c.shards_[shardOf(key)];
            s.lock.lock();
            defer s.lock.unlock();
            var slot: ?*Entry = null;
            for (&s.e) |*e| {
                if (e.used and std.mem.eql(u8, &e.key, key)) {
                    slot = e;
                    break;
                }
                if (!e.used and slot == null) slot = e;
            }
            const e = slot orelse blk: {
                const i = s.next;
                s.next = @intCast((@as(usize, i) + 1) % ways);
                break :blk &s.e[i];
            };
            e.* = .{ .used = true, .key = key.*, .val = val };
            s.inserts += 1;
        }

        /// Sums the per-shard counters (each read under its shard lock; not one atomic snapshot).
        pub fn stats(c: *Self) Stats {
            var t: Stats = .{ .hits = 0, .misses = 0, .inserts = 0 };
            for (&c.shards_) |*s| {
                s.lock.lock();
                t.hits += s.hits;
                t.misses += s.misses;
                t.inserts += s.inserts;
                s.lock.unlock();
            }
            return t;
        }

        pub fn clear(c: *Self) void {
            for (&c.shards_) |*s| {
                s.lock.lock();
                for (&s.e) |*e| e.used = false;
                s.lock.unlock();
            }
        }
    };
}

// ---------------------------------------------------------------------------------------------
// Public-key decode caches

/// ECDSA keys: tag byte = length (33 or 65 are the only parseable lengths; others never cached),
/// then the bytes zero padded.
const ecdsa_key_len = 66;

fn ecdsaKey(pk: []const u8) ?[ecdsa_key_len]u8 {
    if (pk.len != 33 and pk.len != 65) return null;
    var k: [ecdsa_key_len]u8 = @splat(0);
    k[0] = @intCast(pk.len);
    @memcpy(k[1 .. 1 + pk.len], pk);
    return k;
}

var ed_cache: Cache(32, ?ed25519.Point, 4096, 4) = .{};
var k1_cache: Cache(ecdsa_key_len, ?ecdsa.secp256k1.Key, 1024, 4) = .{};
var r1_cache: Cache(ecdsa_key_len, ?ecdsa.secp256r1.Key, 1024, 4) = .{};

/// `ed25519.decompress` of a public key, through the cache when it is on.
pub fn edDecodeKey(pk: *const [32]u8) ?ed25519.Point {
    if (!sw_pk.load(.monotonic)) return ed25519.decompress(pk);
    if (ed_cache.get(pk)) |v| return v;
    const v = ed25519.decompress(pk);
    ed_cache.put(pk, v);
    return v;
}

/// Cache lookup only (null: not cached; a cached `null` means the key does not decode). Lets a
/// caller decode a miss together with another point (`decompress2`) and then `edPutKey` it.
pub fn edGetKey(pk: *const [32]u8) ??ed25519.Point {
    return ed_cache.get(pk);
}

pub fn edPutKey(pk: *const [32]u8, v: ?ed25519.Point) void {
    ed_cache.put(pk, v);
}

/// `parsePublicKey` of secp256k1 / secp256r1 through the cache when it is on.
pub fn ecdsaDecodeKey(comptime kind: enum { k1, r1 }, pk: []const u8) ?(if (kind == .k1) ecdsa.secp256k1.Key else ecdsa.secp256r1.Key) {
    const M = if (kind == .k1) ecdsa.secp256k1 else ecdsa.secp256r1;
    if (!sw_pk.load(.monotonic)) return M.parsePublicKey(pk);
    const key = ecdsaKey(pk) orelse return M.parsePublicKey(pk);
    const c = if (kind == .k1) &k1_cache else &r1_cache;
    if (c.get(&key)) |v| return v;
    const v = M.parsePublicKey(pk);
    c.put(&key, v);
    return v;
}

pub fn pkCacheStats() struct { ed25519: Stats, secp256k1: Stats, secp256r1: Stats } {
    return .{ .ed25519 = ed_cache.stats(), .secp256k1 = k1_cache.stats(), .secp256r1 = r1_cache.stats() };
}

pub fn clearCaches() void {
    ed_cache.clear();
    k1_cache.clear();
    r1_cache.clear();
    zk_cache.clear();
    edv_cache.clear();
}

// ---------------------------------------------------------------------------------------------
// Ed25519 verified-signature cache

/// 32768 entries (~1.2 MB): several large blocks' worth of signatures between the pre-step that
/// fills them and the per-transaction pass that reads them.
var edv_cache: Cache(32, void, 4096, 8) = .{};

/// The cache key of (pk, msg, sig): Blake2b-256 over a domain tag, pk, the message length, the
/// message and the signature (every field fixed size or length prefixed, so distinct triples
/// never share an input).
pub fn edVerifiedKey(pk: *const [32]u8, msg: []const u8, sig: *const [64]u8) [32]u8 {
    var h = hash.Blake2b256.init();
    h.update("zui ed25519 ok v1");
    h.update(pk);
    var l: [8]u8 = undefined;
    std.mem.writeInt(u64, &l, msg.len, .little);
    h.update(&l);
    h.update(msg);
    h.update(sig);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Whether `ed25519.verify` accepted the triple behind `key` (counted as a hit or a miss).
pub fn edVerifiedGet(key: *const [32]u8) bool {
    return edv_cache.get(key) != null;
}

/// Lookup without counting (pre-steps skipping what is already cached).
pub fn edVerifiedContains(key: *const [32]u8) bool {
    return edv_cache.contains(key);
}

/// Record that `ed25519.verify` accepted the triple behind `key`. Only ever call this with a
/// key of a triple that verified (`.valid`); the cache never holds a rejection.
pub fn edVerifiedPut(key: *const [32]u8) void {
    edv_cache.put(key, {});
}

pub fn edVerifiedStats() Stats {
    return edv_cache.stats();
}

// ---------------------------------------------------------------------------------------------
// Pre-verified scope (sig.batch)

/// Keys (`edVerifiedKey`) of Ed25519 triples a batch pass already verified (`.valid` only),
/// sorted, for the per-signature pass of the same call (`sig.batch`). Read only while set.
pub const PreSet = struct {
    keys: []const [32]u8,

    pub fn contains(s: *const PreSet, k: *const [32]u8) bool {
        var lo: usize = 0;
        var hi: usize = s.keys.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, &s.keys[mid], k)) {
                .eq => return true,
                .lt => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return false;
    }

    pub fn lessThan(_: void, a: [32]u8, b: [32]u8) bool {
        return std.mem.order(u8, &a, &b) == .lt;
    }
};

threadlocal var pre_scope: ?*const PreSet = null;

/// Installs `s` as this thread's pre-verified set (null clears it); returns the previous one.
pub fn setScope(s: ?*const PreSet) ?*const PreSet {
    const prev = pre_scope;
    pre_scope = s;
    return prev;
}

/// A pre-verified set is installed on this thread.
pub inline fn scopeOn() bool {
    return pre_scope != null;
}

/// The triple behind `key` was verified (`.valid`) by this thread's batch pass.
pub fn scopeHas(key: *const [32]u8) bool {
    const s = pre_scope orelse return false;
    return s.contains(key);
}

// ---------------------------------------------------------------------------------------------
// zkLogin proof cache

var zk_cache: Cache(32, void, 1024, 4) = .{};

fn hashField(h: *hash.Blake2b256, comptime F: type, f: F) void {
    h.update(std.mem.asBytes(&f.l));
}

fn hashBytes(h: *hash.Blake2b256, b: []const u8) void {
    var l: [8]u8 = undefined;
    std.mem.writeInt(u64, &l, b.len, .little);
    h.update(&l);
    h.update(b);
}

/// The cache key for `zkl.verify(env, a)` once the JWK modulus string `n` is known, or null when
/// the authenticator's proof shape is not fixed yet (those fail fast anyway).
fn zkKey(env: *const zkl.Env, a: *const zkl.Authenticator, n: []const u8) ?[32]u8 {
    if (a.a_n != 3 or a.c_n != 3 or !a.b_shape_ok) return null;
    var h = hash.Blake2b256.init();
    h.update("zui zklogin verified v1");
    var m: [2]u8 = .{ @intFromEnum(env.mode), @intFromEnum(env.usage) };
    h.update(&m);
    h.update(&env.keys.id);
    for (a.a) |f| hashField(&h, @TypeOf(f), f);
    for (a.b) |pair| for (pair) |f| hashField(&h, @TypeOf(f), f);
    for (a.c) |f| hashField(&h, @TypeOf(f), f);
    hashBytes(&h, a.iss_value);
    h.update(&.{a.index_mod_4});
    hashBytes(&h, a.header_base64);
    h.update(&a.seed);
    var me: [8]u8 = undefined;
    std.mem.writeInt(u64, &me, a.max_epoch, .little);
    h.update(&me);
    const eph = a.eph();
    h.update(&.{eph.flag});
    hashBytes(&h, eph.pk);
    hashBytes(&h, n);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// `zkl.verify` with successes cached (when on). The result is the same as `zkl.verify`.
pub fn zkVerify(env: *const zkl.Env, a: *const zkl.Authenticator) ZkFail {
    if (!sw_zk.load(.monotonic)) return zkl.verify(env, a);
    // One lookup: the key and the proof check use the same modulus.
    const n = env.jwks.lookup(zkl.normalizeIss(a.iss), a.kid) orelse return zkl.verify(env, a);
    const key = zkKey(env, a, n) orelse return zkl.verifyWithModulus(env, a, n);
    if (zk_cache.get(&key) != null) return .none;
    const r = zkl.verifyWithModulus(env, a, n);
    if (r == .none) zk_cache.put(&key, {});
    return r;
}

pub fn zkCacheStats() Stats {
    return zk_cache.stats();
}

/// One zkLogin signature for `zkPreverify`: the environment it is checked under and its
/// parsed authenticator.
pub const ZkItem = struct { env: *const zkl.Env, auth: *const zkl.Authenticator };

pub const ZkPreverifyOpts = struct {
    /// null: `core.pool.shared()` (inline when none is installed).
    pool: ?*core.pool.Pool = null,
    max_lanes: usize = 0,
    /// Batch scalars; null: a ChaCha CSPRNG seeded from OS entropy. Tests pass a fixed one.
    rng: ?std.Random = null,
};

pub const ZkPreverifyStats = struct {
    items: usize = 0,
    /// Already in the cache.
    cached: usize = 0,
    /// Pairing checks run in batches (an item in Both mode may need two).
    checked: usize = 0,
    /// Successes added to the cache.
    filled: usize = 0,
};

const ZkPre = struct {
    key: [32]u8 = undefined,
    jobs: [2]?zkl.PairingJob = .{ null, null },
    nj: u8 = 0,
    state: enum(u8) { skip, pending, ok } = .skip,
};

const ZkPreJob = struct {
    items: []const ZkItem,
    st: []ZkPre,
    cached: *Atomic(usize),

    fn run(j: ZkPreJob, lo: usize, hi: usize) void {
        for (lo..hi) |i| {
            const it = j.items[i];
            const p = &j.st[i];
            p.* = .{};
            // as zkVerify: a missing JWK or proof shape never reaches the cache
            const n = it.env.jwks.lookup(zkl.normalizeIss(it.auth.iss), it.auth.kid) orelse continue;
            p.key = zkKey(it.env, it.auth, n) orelse continue;
            if (zk_cache.contains(&p.key)) {
                _ = j.cached.fetchAdd(1, .monotonic);
                continue;
            }
            p.nj = @intCast(zkl.pairingJobs(it.env, it.auth, n, &p.jobs));
            p.state = .pending;
        }
    }
};

/// Validator pre-verify stage for zkLogin: checks the Groth16 proofs of many signatures as
/// randomized batches on the CPU pool (per verifying key, `zkl.FixedVk.verifyBatch`) and puts
/// every success in the zkLogin proof cache under exactly the key `zkVerify` looks up. Later
/// `zkVerify` calls on these signatures hit the cache; failures are not cached, so `zkVerify`
/// recomputes them and returns the live error. Verdicts therefore stay those of per-transaction
/// verification. Does nothing while the zk cache is off (`configure`). JWK lookups run on the
/// pool's threads and must be thread-safe. Allocation failure only skips the fill.
pub fn zkPreverify(io: std.Io, gpa: std.mem.Allocator, items: []const ZkItem, opts: ZkPreverifyOpts) ZkPreverifyStats {
    var stats: ZkPreverifyStats = .{ .items = items.len };
    if (!sw_zk.load(.monotonic) or items.len == 0) return stats;
    const cpool = opts.pool orelse core.pool.shared();
    const st = gpa.alloc(ZkPre, items.len) catch return stats;
    defer gpa.free(st);
    var cached: Atomic(usize) = .init(0);
    core.pool.forRange(cpool, items.len, 4, opts.max_lanes, ZkPreJob{ .items = items, .st = st, .cached = &cached }, ZkPreJob.run);
    stats.cached = cached.load(.monotonic);

    var chacha: std.Random.ChaCha = undefined;
    const rng = opts.rng orelse blk: {
        chacha = zk.groth16.osRng(io);
        break :blk chacha.random();
    };
    const bopts: zk.groth16.BatchOpts = .{ .pool = cpool, .max_lanes = opts.max_lanes };
    var batch: std.ArrayList(zkl.FixedVk.BatchItem) = .empty;
    defer batch.deinit(gpa);
    var owner: std.ArrayList(u32) = .empty;
    defer owner.deinit(gpa);
    var ok: std.ArrayList(bool) = .empty;
    defer ok.deinit(gpa);
    // Round k checks version k of every still-pending item, one batch per verifying key.
    for (0..2) |round| {
        var keys_seen: [4]?*const zkl.FixedVk = @splat(null);
        for (st) |p| {
            if (p.state != .pending or round >= p.nj) continue;
            const j = p.jobs[round] orelse continue;
            for (&keys_seen) |*ks| {
                if (ks.* == j.vk) break;
                if (ks.* == null) {
                    ks.* = j.vk;
                    break;
                }
            }
        }
        for (keys_seen) |maybe_vk| {
            const vk = maybe_vk orelse break;
            batch.clearRetainingCapacity();
            owner.clearRetainingCapacity();
            for (st, 0..) |p, i| {
                if (p.state != .pending or round >= p.nj) continue;
                const j = p.jobs[round] orelse continue;
                if (j.vk != vk) continue;
                batch.append(gpa, .{ .x = j.x, .proof = j.proof }) catch return stats;
                owner.append(gpa, @intCast(i)) catch return stats;
            }
            ok.resize(gpa, batch.items.len) catch return stats;
            vk.verifyBatch(gpa, batch.items, rng, bopts, ok.items);
            stats.checked += batch.items.len;
            for (owner.items, ok.items) |i, v| if (v) {
                st[i].state = .ok;
                zk_cache.put(&st[i].key, {});
                stats.filled += 1;
            };
        }
    }
    return stats;
}

// ---------------------------------------------------------------------------------------------
// Parallel Ed25519 batch

pub const BatchOpts = struct {
    /// 0: one per CPU.
    threads: u32 = 0,
    /// A thread is only worth its start-up above this many items.
    min_per_thread: usize = 48,
    /// Items per scratch fill on one thread (bounds the per-thread scratch).
    chunk: usize = 512,
};

const Worker = struct {
    items: []const ed25519.BatchItem,
    scratch: []u8,
    ok: bool = true,

    fn run(w: *Worker) void {
        w.ok = ed25519.verifyBatch(w.items, w.scratch) == .valid;
    }
};

// ---------------------------------------------------------------------------------------------
// Persistent worker pool: threads and scratch are created once (`startPool`) and reused by every
// `verifyBatchParallel` call; without a pool (or while another call holds it) the call spawns
// threads itself, as before.

const pool_max = 64;
const pool_chunk: usize = 512;
const pool_scratch_len = (pool_chunk + 1) * ed25519.batch_scratch_per_item + 64;

const Pool = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    n: usize, // worker threads (the caller is one more lane)
    threads: [pool_max]?std.Thread = @splat(null),
    scratch: [pool_max][]u8 = undefined,
    /// Futex word the workers wait on; bumped for every job and for shutdown.
    gen: Atomic(u32) align(4) = .init(0),
    stop: Atomic(bool) = .init(false),
    /// Lanes (workers) that still have to finish the current job; the caller waits for 0.
    pending: Atomic(u32) align(4) = .init(0),
    /// Workers with index < active take part in the current job.
    active: Atomic(u32) = .init(0),
    slices: [pool_max][]const ed25519.BatchItem = undefined,
    ok: [pool_max]Atomic(bool) = @splat(.init(true)),
    busy: SpinLock = .{},

    fn workerMain(p: *Pool, idx: usize) void {
        var seen: u32 = 0;
        while (true) {
            while (p.gen.load(.acquire) == seen) p.io.futexWaitUncancelable(u32, &p.gen.raw, seen);
            seen = p.gen.load(.acquire);
            if (p.stop.load(.acquire)) return;
            if (idx >= p.active.load(.acquire)) continue;
            const r = ed25519.verifyBatch(p.slices[idx], p.scratch[idx - 1]) == .valid;
            p.ok[idx].store(r, .release);
            if (p.pending.fetchSub(1, .acq_rel) == 1) p.io.futexWake(u32, &p.pending.raw, 1);
        }
    }
};

var pool: ?*Pool = null;

/// Start the persistent pool: `threads` lanes in total counting the caller (0: one per CPU), at
/// most 64. Call once at startup, before verifying; a second call is a no-op. Returns false (and
/// leaves the spawn-per-call fallback in place) when memory or threads are not available.
pub fn startPool(io: std.Io, gpa: std.mem.Allocator, threads: u32) bool {
    if (pool != null) return true;
    const lanes: usize = @min(pool_max, if (threads != 0) threads else (std.Thread.getCpuCount() catch 1));
    if (lanes < 2) return false;
    const p = gpa.create(Pool) catch return false;
    p.* = .{ .io = io, .gpa = gpa, .n = lanes - 1 };
    var made: usize = 0;
    while (made < p.n) : (made += 1) {
        p.scratch[made] = gpa.alloc(u8, pool_scratch_len) catch break;
        p.threads[made] = std.Thread.spawn(.{ .stack_size = 16 << 20 }, Pool.workerMain, .{ p, made + 1 }) catch {
            gpa.free(p.scratch[made]);
            break;
        };
    }
    if (made == 0) {
        gpa.destroy(p);
        return false;
    }
    p.n = made; // lanes that did start; indexes 1..made
    pool = p;
    return true;
}

/// Stop and free the pool (tests, shutdown). Not safe while a batch is running.
pub fn stopPool() void {
    const p = pool orelse return;
    pool = null;
    p.stop.store(true, .release);
    _ = p.gen.fetchAdd(1, .release);
    p.io.futexWake(u32, &p.gen.raw, std.math.maxInt(u32));
    for (p.threads[0..p.n]) |t| if (t) |th| th.join();
    for (p.scratch[0..p.n]) |b| p.gpa.free(b);
    p.gpa.destroy(p);
}

/// Run `items` over the pool in `lanes` slices; null when the pool is missing or busy.
fn poolBatch(items: []const ed25519.BatchItem, lanes_wanted: usize) ?bool {
    const p = pool orelse return null;
    if (!p.busy.tryLock()) return null;
    defer p.busy.unlock();
    const lanes = @min(lanes_wanted, p.n + 1);
    const slice_len = (items.len + lanes - 1) / lanes;
    var used: usize = 1;
    while (used < lanes and used * slice_len < items.len) : (used += 1) {}
    // worker i (1-based) takes slice i and scratch i-1
    for (1..used) |i| {
        const lo = i * slice_len;
        p.slices[i] = items[lo..@min(items.len, lo + slice_len)];
    }
    p.pending.store(@intCast(used - 1), .release);
    p.active.store(@intCast(used), .release);
    _ = p.gen.fetchAdd(1, .release);
    p.io.futexWake(u32, &p.gen.raw, std.math.maxInt(u32));
    // the caller's lane: slice 0 on a scratch of its own (heap, freed here)
    var none: [0]u8 = .{};
    const mine: []u8 = p.gpa.alloc(u8, pool_scratch_len) catch &none;
    defer if (mine.len != 0) p.gpa.free(mine);
    var all = ed25519.verifyBatch(items[0..@min(items.len, slice_len)], mine) == .valid;
    while (true) {
        const left = p.pending.load(.acquire);
        if (left == 0) break;
        p.io.futexWaitUncancelable(u32, &p.pending.raw, left);
    }
    for (1..used) |i| all = all and p.ok[i].load(.acquire);
    return all;
}

/// `ed25519.verifyBatch` with the items split over threads (the persistent pool when `startPool`
/// ran and is free, else threads spawned for this call). Same verdicts: empty is
/// verify:InvalidInput, any bad item verify:InvalidSignature. Never fails for lack of memory or
/// threads (it falls back to fewer threads, then to one-by-one checks).
pub fn verifyBatchParallel(gpa: std.mem.Allocator, items: []const ed25519.BatchItem, opts: BatchOpts) Verdict {
    if (items.len == 0) return .{ .invalid = .verify_invalid_input };
    const cpus: usize = if (opts.threads != 0) opts.threads else (std.Thread.getCpuCount() catch 1);
    const by_size = @max(1, items.len / @max(1, opts.min_per_thread));
    var nt: usize = @min(@min(cpus, by_size), 64);
    if (nt < 1) nt = 1;
    if (nt > 1) if (poolBatch(items, nt)) |all| return if (all) .valid else .{ .invalid = .verify_invalid_signature };
    const per = @min(opts.chunk, (items.len + nt - 1) / nt);
    const scratch_each = (per + 1) * ed25519.batch_scratch_per_item + 64;
    var workers: [64]Worker = undefined;
    var bufs: [64][]u8 = undefined;
    var nbuf: usize = 0;
    defer for (bufs[0..nbuf]) |b| gpa.free(b);
    var threads: [64]?std.Thread = @splat(null);
    const slice_len = (items.len + nt - 1) / nt;
    var started: usize = 0;
    var i: usize = 0;
    var inline_slices: [64]usize = undefined;
    var n_inline: usize = 0;
    while (i < nt) : (i += 1) {
        const lo = i * slice_len;
        if (lo >= items.len) break;
        const hi = @min(items.len, lo + slice_len);
        const buf: []u8 = gpa.alloc(u8, scratch_each) catch &.{};
        if (buf.len != 0) {
            bufs[nbuf] = buf;
            nbuf += 1;
        }
        workers[i] = .{ .items = items[lo..hi], .scratch = buf };
        started = i + 1;
        if (i == 0) continue; // the caller runs slice 0
        threads[i] = std.Thread.spawn(.{ .stack_size = 16 << 20 }, Worker.run, .{&workers[i]}) catch null;
        if (threads[i] == null) {
            inline_slices[n_inline] = i;
            n_inline += 1;
        }
    }
    workers[0].run();
    for (inline_slices[0..n_inline]) |s| workers[s].run();
    var all = workers[0].ok;
    for (1..started) |s| {
        if (threads[s]) |t| t.join();
        all = all and workers[s].ok;
    }
    return if (all) .valid else .{ .invalid = .verify_invalid_signature };
}

// ---------------------------------------------------------------------------------------------
// Multisig fast path

pub fn multisigBatchMin() u8 {
    return sw_ms.load(.monotonic);
}

/// Scratch for a batch of up to 10 members (a multisig has at most 10 keys), aligned for the
/// batch tables.
pub const ms_scratch_len = 10 * ed25519.batch_scratch_per_item + 64;

/// All items verify in one batch (true) or not (false: the caller must check one by one).
pub fn batchAllValid(items: []const ed25519.BatchItem, scratch: []u8) bool {
    if (items.len == 0) return false;
    return ed25519.verifyBatch(items, scratch) == .valid;
}

// ---------------------------------------------------------------------------------------------

test "cache hit, replace and clear" {
    var c: Cache(4, u32, 2, 2) = .{};
    const k1 = [4]u8{ 1, 2, 3, 4 };
    try std.testing.expect(c.get(&k1) == null);
    c.put(&k1, 7);
    try std.testing.expectEqual(@as(u32, 7), c.get(&k1).?);
    c.put(&k1, 9);
    try std.testing.expectEqual(@as(u32, 9), c.get(&k1).?);
    for (0..40) |i| c.put(&.{ @intCast(i), 9, 9, 9 }, @intCast(i));
    c.clear();
    try std.testing.expect(c.get(&k1) == null);
}

test "ed25519 key cache agrees with decompress" {
    configure(.{ .pk_cache = true });
    defer configure(.{});
    defer clearCaches();
    var seed: [32]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(1);
    var good: usize = 0;
    for (0..64) |_| {
        prng.random().bytes(&seed);
        const want = ed25519.decompress(&seed);
        for (0..2) |_| {
            const got = edDecodeKey(&seed);
            try std.testing.expectEqual(want == null, got == null);
            if (want) |w| try std.testing.expectEqualSlices(u8, &w.toBytes(), &got.?.toBytes());
        }
        if (want != null) good += 1;
    }
    try std.testing.expect(good > 0);
    try std.testing.expect(pkCacheStats().ed25519.hits >= 64);
}

test "parallel batch: empty and a bad item" {
    const gpa = std.testing.allocator;
    try std.testing.expectEqual(Verdict{ .invalid = .verify_invalid_input }, verifyBatchParallel(gpa, &.{}, .{}));
    const kp = std.crypto.sign.Ed25519.KeyPair.generate(std.testing.io);
    var items: [150]ed25519.BatchItem = undefined;
    var sigs: [150][64]u8 = undefined;
    const pkb = kp.public_key.toBytes();
    const msg = "zui fast batch";
    for (&items, &sigs) |*it, *s| {
        s.* = (try kp.sign(msg, null)).toBytes();
        it.* = .{ .pk = &pkb, .msg = msg, .sig = s };
    }
    try std.testing.expectEqual(Verdict.valid, verifyBatchParallel(gpa, &items, .{ .threads = 3, .min_per_thread = 10 }));
    sigs[111][5] ^= 1;
    try std.testing.expectEqual(Verdict{ .invalid = .verify_invalid_signature }, verifyBatchParallel(gpa, &items, .{ .threads = 3, .min_per_thread = 10 }));
    sigs[111][5] ^= 1;
    // the same through a persistent pool, several calls in a row
    try std.testing.expect(startPool(std.testing.io, std.heap.page_allocator, 4));
    defer stopPool();
    for (0..3) |_| {
        try std.testing.expectEqual(Verdict.valid, verifyBatchParallel(gpa, &items, .{ .threads = 4, .min_per_thread = 10 }));
        sigs[149][0] ^= 1;
        try std.testing.expectEqual(Verdict{ .invalid = .verify_invalid_signature }, verifyBatchParallel(gpa, &items, .{ .threads = 4, .min_per_thread = 10 }));
        sigs[149][0] ^= 1;
    }
}

fn zkDebug(f: ZkFail, buf: []u8) []const u8 {
    return f.debugAlloc(buf);
}

test "zkPreverify fills the zk cache; zkVerify verdicts equal zkl.verify on corpus items" {
    const gpa = std.testing.allocator;
    const set = (try zk.corpus_vectors.load(gpa, std.testing.io, &.{ "corpus001.items.jsonl", "edge.items.jsonl" }, 1000)) orelse return error.SkipZigTest;
    defer set.deinit();
    configure(.{ .zk_cache = true });
    defer configure(.{});
    defer clearCaches();
    clearCaches();
    const p = try core.pool.Pool.init(std.testing.io, gpa, 4);
    defer p.deinit();
    var prng = std.Random.DefaultPrng.init(0x7a6b);
    const modes = [_]zkl.Mode{ .v1_only, .both, .v2_only };
    const envs = try gpa.alloc(zkl.Env, set.items.len * modes.len);
    defer gpa.free(envs);
    const items = try gpa.alloc(ZkItem, envs.len);
    defer gpa.free(items);
    for (set.items, 0..) |*it, i| for (modes, 0..) |m, k| {
        envs[i * modes.len + k] = .{ .keys = &set.keys, .jwks = it.jwks(), .usage = .prod, .mode = m };
        items[i * modes.len + k] = .{ .env = &envs[i * modes.len + k], .auth = &it.auth };
    };
    // off: nothing happens
    configure(.{});
    try std.testing.expectEqual(@as(usize, 0), zkPreverify(std.testing.io, gpa, items, .{ .pool = p, .rng = prng.random() }).filled);
    configure(.{ .zk_cache = true });
    const st = zkPreverify(std.testing.io, gpa, items, .{ .pool = p, .rng = prng.random() });
    var n_ok: usize = 0;
    var b1: [512]u8 = undefined;
    var b2: [512]u8 = undefined;
    const before = zkCacheStats();
    for (items) |it| {
        const want = zkl.verify(it.env, it.auth);
        const got = zkVerify(it.env, it.auth);
        try std.testing.expectEqualStrings(zkDebug(want, &b1), zkDebug(got, &b2));
        n_ok += @intFromBool(want == .none);
    }
    const after = zkCacheStats();
    // every success was filled by the batch, so every successful zkVerify was a cache hit
    try std.testing.expect(n_ok > 0);
    try std.testing.expectEqual(n_ok, st.filled);
    try std.testing.expectEqual(@as(u64, n_ok), after.hits - before.hits);
    // a second pass finds them cached
    const st2 = zkPreverify(std.testing.io, gpa, items, .{ .pool = p });
    try std.testing.expectEqual(n_ok, st2.cached);
    try std.testing.expectEqual(@as(usize, 0), st2.filled);
    std.debug.print("zkPreverify corpus: {d} items, {d} checked, {d} filled\n", .{ st.items, st.checked, st.filled });
}

test "ed25519 verified cache: keys bind pk, message and signature" {
    clearCaches();
    defer clearCaches();
    var pk: [32]u8 = @splat(1);
    var sg: [64]u8 = @splat(2);
    var msg: [32]u8 = @splat(3);
    const k0 = edVerifiedKey(&pk, &msg, &sg);
    edVerifiedPut(&k0);
    try std.testing.expect(edVerifiedGet(&k0));
    // every single-bit change of any input is another key, and misses
    for (0..32) |i| {
        pk[i] ^= 0x80;
        try std.testing.expect(!edVerifiedGet(&edVerifiedKey(&pk, &msg, &sg)));
        pk[i] ^= 0x80;
        msg[i] ^= 0x01;
        try std.testing.expect(!edVerifiedGet(&edVerifiedKey(&pk, &msg, &sg)));
        msg[i] ^= 0x01;
    }
    for (0..64) |i| {
        sg[i] ^= 0x10;
        try std.testing.expect(!edVerifiedGet(&edVerifiedKey(&pk, &msg, &sg)));
        sg[i] ^= 0x10;
    }
    // the message length is bound too (a shorter message plus shifted bytes is another key)
    try std.testing.expect(!edVerifiedGet(&edVerifiedKey(&pk, msg[0..31], &sg)));
    try std.testing.expect(edVerifiedGet(&edVerifiedKey(&pk, &msg, &sg)));
    clearCaches();
    try std.testing.expect(!edVerifiedGet(&k0));
}
