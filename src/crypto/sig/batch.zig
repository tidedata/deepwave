//! sig.batch: many user signatures (or many transactions' signature sets) verified at once, with
//! exactly the verdicts of one-by-one verification (`user.verifyParsed`,
//! `user.verifyTransaction`): same verdict, same rejection reason, same errors, item by item.
//!
//! How. Pass 1 collects the Ed25519 "leaves" (single Ed25519 signatures, Ed25519 members of a
//! multisig, zkLogin ephemeral Ed25519 signatures) and checks them all together: on one thread,
//! on the CPU pool, or through the process's accelerator backend (`setBackend`, installed by
//! gpu.engine: GPU or pool as its calibrated table says). zkLogin proofs are batch-checked into
//! the zk proof cache (`fast.zkPreverify`, when that cache is on). Pass 2 runs the ordinary
//! per-item check, in parallel on the pool, with the set of leaves pass 1 accepted installed as a
//! thread scope (`fast.setScope`): an accepted leaf skips its curve work, everything else (parse,
//! key and address checks, flags, epochs, weights, the leaves pass 1 did NOT accept) runs as it
//! always does. Only acceptances cross from pass 1 to pass 2, so a rejection always comes from the
//! single path and carries its reason; a backend that wrongly rejects only costs time.
//!
//! The CPU leaf check is `ed25519.verifyBatch` over chunks of `chunk` items (one batch equation,
//! ~1.7x cheaper per signature than single checks on a test machine); a chunk that fails is checked one
//! by one, so per-leaf answers equal `ed25519.verify`.
const std = @import("std");
const core = @import("core");
const user = @import("user.zig");
const fast = @import("fast.zig");
const ed25519 = @import("ed25519.zig");
const verdict = @import("verdict.zig");
const zk = @import("zk");
const Verdict = verdict.Verdict;
const Pool = core.pool.Pool;
const Atomic = std.atomic.Value;

/// Where pass 1 checks the Ed25519 leaves.
pub const Path = enum {
    /// The calling thread (batch-equation chunks).
    cpu1,
    /// The CPU pool (`Options.pool`, else core.pool.shared(); inline when none).
    pool,
    /// The installed backend (gpu.engine: its dispatch table picks GPU or pool); the pool when
    /// none is installed.
    accel,

    pub fn parse(s: []const u8) ?Path {
        if (std.mem.eql(u8, s, "gpu")) return .accel;
        return std.meta.stringToEnum(Path, s);
    }
};

/// An Ed25519 leaf checker with per-item answers equal to `ed25519.verify` (gpu.engine).
pub const Backend = struct {
    ctx: *anyopaque,
    verify_each: *const fn (ctx: *anyopaque, items: []const ed25519.BatchItem, out: []Verdict) void,
    name: []const u8 = "accel",
};

var backend_ptr: Atomic(?*const Backend) = .init(null);
var default_path: Atomic(u8) = .init(@intFromEnum(Path.cpu1));

/// Installs (or with null removes) the process's leaf backend. `b` must outlive its use.
pub fn setBackend(b: ?*const Backend) void {
    backend_ptr.store(b, .release);
}

pub fn backend() ?*const Backend {
    return backend_ptr.load(.acquire);
}

/// The path callers get when `Options.path` is null (gpu.engine sets it: accel when the signature
/// engine is on, cpu1 when off).
pub fn setDefaultPath(p: Path) void {
    default_path.store(@intFromEnum(p), .monotonic);
}

pub fn defaultPath() Path {
    return @enumFromInt(default_path.load(.monotonic));
}

pub const Options = struct {
    /// null: `defaultPath()`.
    path: ?Path = null,
    /// null: core.pool.shared() (inline when none).
    pool: ?*Pool = null,
    /// For the zkLogin batch's CSPRNG; null skips the zkLogin batch (pass 2 checks proofs alone).
    io: ?std.Io = null,
    /// Smallest batch that goes through the passes at all; below it every item runs the single
    /// path directly (the passes cost more than they save on a few signatures).
    min_items: usize = 1,
};

pub const Stats = struct {
    path: Path = .cpu1,
    items: usize = 0,
    leaves: usize = 0,
    /// Leaves pass 1 accepted (each saves its curve work in pass 2).
    accepted: usize = 0,
    zk_items: usize = 0,
    zk_filled: usize = 0,
    /// Pass 1 time and pass 2 time.
    leaf_ns: u64 = 0,
    item_ns: u64 = 0,

    pub fn add(s: *Stats, o: Stats) void {
        s.path = o.path;
        s.items += o.items;
        s.leaves += o.leaves;
        s.accepted += o.accepted;
        s.zk_items += o.zk_items;
        s.zk_filled += o.zk_filled;
        s.leaf_ns += o.leaf_ns;
        s.item_ns += o.item_ns;
    }
};

/// One parsed user signature to check for `author` over `digest` (as `user.verifyParsed`).
pub const SigItem = struct {
    env: *const user.UserSigEnv,
    parsed: *const user.Parsed,
    digest: *const [32]u8,
    author: *const user.Address,
    /// The parse scratch of `parsed` (verifyParsed needs it for multisig zkLogin members).
    scratch: []u8,
};

pub const SigResult = user.Error!Verdict;

/// One transaction's signature set (as `user.verifyTransaction`).
pub const TxItem = struct {
    env: *const user.UserSigEnv,
    /// IntentMessage BCS ([0, 0, 0] ++ TransactionData).
    intent: []const u8,
    sigs: []const []const u8,
    aliases: []const user.AliasSet,
    /// `user.txScratchLen(sigs)` bytes.
    scratch: []u8,
};

pub const TxOutcome = (user.Error || error{Bcs})!user.TxResult;

/// Items per batch equation in the CPU leaf check.
pub const chunk = 64;
const chunk_scratch = (chunk + 1) * ed25519.batch_scratch_per_item + 64;

/// Per-leaf `ed25519.verify` answers for `items[lo..hi]`, by batch-equation chunks (a failing
/// chunk is checked one by one). `scratch`: at least `chunk_scratch` bytes, or empty (singles).
pub fn edVerifyRange(items: []const ed25519.BatchItem, out: []Verdict, scratch: []u8) void {
    std.debug.assert(out.len == items.len);
    var lo: usize = 0;
    while (lo < items.len) {
        const hi = @min(items.len, lo + chunk);
        const c = items[lo..hi];
        if (c.len >= 4 and scratch.len >= chunk_scratch and ed25519.verifyBatch(c, scratch) == .valid) {
            @memset(out[lo..hi], .valid);
        } else {
            for (c, out[lo..hi]) |it, *o| o.* = ed25519.verify(it.pk, it.msg, it.sig);
        }
        lo = hi;
    }
}

threadlocal var tl_scratch: ?[]u8 = null;

/// This thread's chunk scratch (kept for the thread's life; empty when out of memory).
fn threadScratch() []u8 {
    if (tl_scratch) |s| return s;
    const s = std.heap.page_allocator.alignedAlloc(u8, .@"64", chunk_scratch) catch return &.{};
    tl_scratch = s;
    return s;
}

/// `edVerifyRange` with this thread's chunk scratch.
pub fn edVerifyLeaves(items: []const ed25519.BatchItem, out: []Verdict) void {
    edVerifyRange(items, out, threadScratch());
}

const EdJob = struct {
    items: []const ed25519.BatchItem,
    out: []Verdict,
    fn run(j: EdJob, lo: usize, hi: usize) void {
        edVerifyRange(j.items[lo..hi], j.out[lo..hi], threadScratch());
    }
};

/// Per-leaf answers on the CPU: one thread (`pool` null and none shared) or the pool's lanes.
pub fn edVerifyCpu(pool: ?*Pool, items: []const ed25519.BatchItem, out: []Verdict) void {
    core.pool.forRange(pool, items.len, chunk, 0, EdJob{ .items = items, .out = out }, EdJob.run);
}

/// Pass 1 over `leaves` on `path`; fills `ok`.
fn checkLeaves(path: Path, pool: ?*Pool, leaves: []const ed25519.BatchItem, out: []Verdict) void {
    switch (path) {
        .cpu1 => edVerifyRange(leaves, out, threadScratch()),
        .pool => edVerifyCpu(pool, leaves, out),
        .accel => if (backend()) |b| b.verify_each(b.ctx, leaves, out) else edVerifyCpu(pool, leaves, out),
    }
}

/// Per-leaf `ed25519.verify` answers on `path` (pool null: core.pool.shared()).
pub fn verifyLeaves(path: Path, pool: ?*Pool, leaves: []const ed25519.BatchItem, out: []Verdict) void {
    checkLeaves(path, pool orelse core.pool.shared(), leaves, out);
}

/// The Ed25519 leaves of one parsed signature over `digest`.
fn addLeaves(gpa: std.mem.Allocator, list: *std.ArrayList(ed25519.BatchItem), p: *const user.Parsed, digest: *const [32]u8) std.mem.Allocator.Error!void {
    switch (p.*) {
        .single => |s| if (s.scheme == .ed25519 and s.pk.len == 32 and s.sig.len == 64) {
            try list.append(gpa, .{ .pk = s.pk[0..32], .msg = digest, .sig = s.sig[0..64] });
        },
        .multisig => |*m| {
            // zip(sigs, bitmap indices), as the member loop pairs them
            var bit: u5 = 0;
            for (m.sigs[0..m.n_sigs]) |s| {
                while (bit < 10 and (m.bitmap >> @as(u4, @intCast(bit))) & 1 == 0) bit += 1;
                if (bit >= 10) break;
                const idx: usize = bit;
                bit += 1;
                if (idx >= m.n_pks) break;
                const pk = m.pks[idx];
                if (s.kind != .ed25519 or pk.bytes.len != 32 or s.bytes.len != 64) continue;
                try list.append(gpa, .{ .pk = pk.bytes[0..32], .msg = digest, .sig = s.bytes[0..64] });
            }
        },
        .zklogin => |*z| {
            const us = z.auth.user_signature;
            if (us.len == 97 and us[0] == 0) try list.append(gpa, .{ .pk = us[65..97], .msg = digest, .sig = us[1..65] });
        },
        .passkey => {},
    }
}

/// Sorted keys of the accepted leaves.
fn acceptedSet(gpa: std.mem.Allocator, pool: ?*Pool, leaves: []const ed25519.BatchItem, out: []const Verdict) std.mem.Allocator.Error![][32]u8 {
    var n: usize = 0;
    for (out) |v| n += @intFromBool(v == .valid);
    const keys = try gpa.alloc([32]u8, n);
    const pos = try gpa.alloc(u32, leaves.len);
    defer gpa.free(pos);
    var k: u32 = 0;
    for (out, pos) |v, *p| {
        p.* = k;
        if (v == .valid) k += 1;
    }
    const Job = struct {
        leaves: []const ed25519.BatchItem,
        out: []const Verdict,
        pos: []const u32,
        keys: [][32]u8,
        fn run(j: @This(), lo: usize, hi: usize) void {
            for (lo..hi) |i| if (j.out[i] == .valid) {
                const it = j.leaves[i];
                j.keys[j.pos[i]] = fast.edVerifiedKey(it.pk, it.msg, it.sig);
            };
        }
    };
    core.pool.forRange(pool, leaves.len, 256, 0, Job{ .leaves = leaves, .out = out, .pos = pos, .keys = keys }, Job.run);
    std.mem.sortUnstable([32]u8, keys, {}, fast.PreSet.lessThan);
    return keys;
}

/// Shared pass-1 driver: leaves already collected; zk items too. Returns the accepted set (owned).
fn passOne(gpa: std.mem.Allocator, path: Path, pool: ?*Pool, o: Options, leaves: []const ed25519.BatchItem, zitems: []const fast.ZkItem, st: *Stats) std.mem.Allocator.Error![]const [32]u8 {
    const t0 = nowNs();
    defer st.leaf_ns += nowNs() - t0;
    st.leaves += leaves.len;
    st.zk_items += zitems.len;
    if (zitems.len > 0 and path != .cpu1) if (o.io) |io| {
        st.zk_filled += fast.zkPreverify(io, gpa, zitems, .{ .pool = pool }).filled;
    };
    const out = try gpa.alloc(Verdict, leaves.len);
    defer gpa.free(out);
    checkLeaves(path, pool, leaves, out);
    const keys = try acceptedSet(gpa, if (path == .cpu1) null else pool, leaves, out);
    st.accepted += keys.len;
    return keys;
}

fn zkItemOf(env: *const user.UserSigEnv, p: *const user.Parsed) ?fast.ZkItem {
    if (p.* != .zklogin) return null;
    const z = if (env.zklogin) |*z| z else return null;
    return .{ .env = z, .auth = &p.zklogin.auth };
}

/// `user.verifyParsed` for every item, as one batch. `out.len == items.len`.
pub fn verifySigs(gpa: std.mem.Allocator, items: []const SigItem, out: []SigResult, o: Options) Stats {
    std.debug.assert(out.len == items.len);
    const path = o.path orelse defaultPath();
    const pool = o.pool orelse core.pool.shared();
    var st: Stats = .{ .path = path, .items = items.len };
    if (items.len < @max(1, o.min_items)) {
        for (items, out) |*it, *r| r.* = user.verifyParsed(it.env, it.parsed, it.digest, it.author, it.scratch);
        return st;
    }
    const keys: []const [32]u8 = blk: {
        var leaves: std.ArrayList(ed25519.BatchItem) = .empty;
        defer leaves.deinit(gpa);
        var zitems: std.ArrayList(fast.ZkItem) = .empty;
        defer zitems.deinit(gpa);
        for (items) |*it| {
            addLeaves(gpa, &leaves, it.parsed, it.digest) catch break :blk &.{};
            if (zkItemOf(it.env, it.parsed)) |z| zitems.append(gpa, z) catch {};
        }
        break :blk passOne(gpa, path, pool, o, leaves.items, zitems.items, &st) catch &.{};
    };
    defer if (keys.len > 0) gpa.free(keys);
    const set: fast.PreSet = .{ .keys = keys };
    const t1 = nowNs();
    const Job = struct {
        items: []const SigItem,
        out: []SigResult,
        set: *const fast.PreSet,
        fn run(j: @This(), lo: usize, hi: usize) void {
            const prev = fast.setScope(j.set);
            defer _ = fast.setScope(prev);
            for (j.items[lo..hi], j.out[lo..hi]) |*it, *r| r.* = user.verifyParsed(it.env, it.parsed, it.digest, it.author, it.scratch);
        }
    };
    core.pool.forRange(if (path == .cpu1) null else pool, items.len, 16, 0, Job{ .items = items, .out = out, .set = &set }, Job.run);
    st.item_ns = nowNs() - t1;
    return st;
}

/// `user.verifyTransaction` for every item, as one batch. `out.len == items.len`.
pub fn verifyTxs(gpa: std.mem.Allocator, items: []const TxItem, out: []TxOutcome, o: Options) Stats {
    std.debug.assert(out.len == items.len);
    const path = o.path orelse defaultPath();
    const pool = o.pool orelse core.pool.shared();
    var st: Stats = .{ .path = path, .items = items.len };
    if (items.len < @max(1, o.min_items)) {
        for (items, out) |*it, *r| r.* = user.verifyTransaction(it.env, it.intent, it.sigs, it.aliases, it.scratch);
        return st;
    }
    // Pass 1 parses every signature once more into its own scratch (pass 2's verifyTransaction
    // parses again into the item's): leaves are matched by content, never by pointer.
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const keys: []const [32]u8 = blk: {
        const a = arena.allocator();
        var leaves: std.ArrayList(ed25519.BatchItem) = .empty;
        defer leaves.deinit(gpa);
        var zitems: std.ArrayList(fast.ZkItem) = .empty;
        defer zitems.deinit(gpa);
        const digests = a.alloc([32]u8, items.len) catch break :blk &.{};
        for (items, digests) |*it, *d| {
            if (it.intent.len < 3) continue;
            d.* = user.intentDigest(it.intent);
            for (it.sigs) |s| {
                const sc = a.alloc(u8, user.scratchLen(s.len)) catch break :blk &.{};
                const p = a.create(user.Parsed) catch break :blk &.{};
                if (user.parse(s, p, sc) != null) continue;
                addLeaves(gpa, &leaves, p, d) catch break :blk &.{};
                if (zkItemOf(it.env, p)) |z| zitems.append(gpa, z) catch {};
            }
        }
        break :blk passOne(gpa, path, pool, o, leaves.items, zitems.items, &st) catch &.{};
    };
    defer if (keys.len > 0) gpa.free(keys);
    const set: fast.PreSet = .{ .keys = keys };
    const t1 = nowNs();
    const Job = struct {
        items: []const TxItem,
        out: []TxOutcome,
        set: *const fast.PreSet,
        fn run(j: @This(), lo: usize, hi: usize) void {
            const prev = fast.setScope(j.set);
            defer _ = fast.setScope(prev);
            for (j.items[lo..hi], j.out[lo..hi]) |*it, *r| r.* = user.verifyTransaction(it.env, it.intent, it.sigs, it.aliases, it.scratch);
        }
    };
    core.pool.forRange(if (path == .cpu1) null else pool, items.len, 8, 0, Job{ .items = items, .out = out, .set = &set }, Job.run);
    st.item_ns = nowNs() - t1;
    return st;
}

fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    if (@import("builtin").os.tag == .linux) {
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    } else {
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
    }
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ---------------------------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn edUserSig(a: std.mem.Allocator, kp: std.crypto.sign.Ed25519.KeyPair, digest: *const [32]u8) ![]u8 {
    const s = try kp.sign(digest, null);
    const out = try a.alloc(u8, 97);
    out[0] = 0;
    out[1..65].* = s.toBytes();
    out[65..97].* = kp.public_key.toBytes();
    return out;
}

fn addrOf(pk: *const [32]u8) user.Address {
    var h = @import("hash").Blake2b256.init();
    h.update(&.{0});
    h.update(pk);
    var o: user.Address = undefined;
    h.final(&o);
    return o;
}

test "verifySigs: same verdicts as verifyParsed on every path (valid, wrong signer, bad signature, bad key)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const env: user.UserSigEnv = .{ .epoch = 1 };
    const n = 300;
    const parsed = try a.alloc(user.Parsed, n);
    const scratch = try a.alloc([]u8, n);
    const digests = try a.alloc([32]u8, n);
    const authors = try a.alloc(user.Address, n);
    const items = try a.alloc(SigItem, n);
    var seed: [32]u8 = @splat(7);
    for (0..n) |i| {
        seed[0] = @intCast(i & 0xff);
        seed[1] = @intCast(i >> 8);
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        digests[i] = @splat(@intCast(i % 251));
        const raw = try edUserSig(a, kp, &digests[i]);
        authors[i] = addrOf(&kp.public_key.toBytes());
        switch (i % 7) {
            1 => raw[10] ^= 1, // bad signature
            2 => authors[i][0] ^= 1, // wrong signer
            3 => raw[70] ^= 0x80, // key bits
            4 => digests[i][0] ^= 1, // other message
            else => {},
        }
        scratch[i] = try a.alloc(u8, user.scratchLen(raw.len));
        try testing.expect(user.parse(raw, &parsed[i], scratch[i]) == null);
        items[i] = .{ .env = &env, .parsed = &parsed[i], .digest = &digests[i], .author = &authors[i], .scratch = scratch[i] };
    }
    const want = try a.alloc(SigResult, n);
    for (items, want) |*it, *w| w.* = user.verifyParsed(it.env, it.parsed, it.digest, it.author, it.scratch);
    const pool = try Pool.init(testing.io, testing.allocator, 4);
    defer pool.deinit();
    for ([_]Path{ .cpu1, .pool, .accel }) |path| {
        const got = try a.alloc(SigResult, n);
        const st = verifySigs(testing.allocator, items, got, .{ .path = path, .pool = pool });
        try testing.expectEqual(@as(usize, n), st.leaves);
        try testing.expect(st.accepted > 0 and st.accepted < n);
        for (want, got) |w, g| try testing.expectEqualDeep(w, g);
    }
    // the scope is gone afterwards
    try testing.expect(!fast.scopeOn());
}

test "verifyTxs: same results as verifyTransaction" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const env: user.UserSigEnv = .{ .epoch = 1 };
    // TransactionData::V1 with a ProgrammableTransaction kind is hard to build by hand here; a
    // malformed intent is still a per-item result that must match (error.Bcs), and an empty set.
    const intents = [_][]const u8{ &.{ 0, 0, 0, 1 }, &.{ 1, 0, 0 }, &.{} };
    const items = try a.alloc(TxItem, intents.len);
    for (intents, items) |it, *x| x.* = .{ .env = &env, .intent = it, .sigs = &.{}, .aliases = &.{}, .scratch = &.{} };
    const got = try a.alloc(TxOutcome, items.len);
    _ = verifyTxs(testing.allocator, items, got, .{ .path = .pool });
    for (items, got) |*it, g| try testing.expectEqualDeep(user.verifyTransaction(it.env, it.intent, it.sigs, it.aliases, it.scratch), g);
}

test "edVerifyRange equals ed25519.verify per item, chunks with and without a bad item" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 200;
    const items = try a.alloc(ed25519.BatchItem, n);
    const msgs = try a.alloc([32]u8, n);
    const sigs = try a.alloc([64]u8, n);
    const pks = try a.alloc([32]u8, n);
    var seed: [32]u8 = @splat(3);
    for (0..n) |i| {
        seed[0] = @intCast(i);
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        msgs[i] = @splat(@intCast(i));
        sigs[i] = (try kp.sign(&msgs[i], null)).toBytes();
        pks[i] = kp.public_key.toBytes();
        if (i == 70 or i == 199) sigs[i][3] ^= 1;
        items[i] = .{ .pk = &pks[i], .msg = &msgs[i], .sig = &sigs[i] };
    }
    const out = try a.alloc(Verdict, n);
    edVerifyRange(items, out, threadScratch());
    for (items, out) |it, v| try testing.expectEqualDeep(ed25519.verify(it.pk, it.msg, it.sig), v);
    @memset(out, .valid);
    edVerifyRange(items, out, &.{});
    for (items, out) |it, v| try testing.expectEqualDeep(ed25519.verify(it.pk, it.msg, it.sig), v);
}
