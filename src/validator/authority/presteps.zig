//! The two batch pre-steps of the signature pre-verification stage (preverify.zig
//! `Config.pre_steps`). zui-only and local: they only warm `sig.fast` caches that change no
//! verdict, and the per-transaction `sig.user` check that follows decides every accept, reject
//! and reason exactly as before. Both do nothing while their cache is off (`sig.fast.configure`).
//!   - `ZkStep`: every top-level zkLogin signature of the batch has its Groth16 proof checked in
//!     randomized batches (`sig.fast.zkPreverify`); successes land in the zk proof cache that
//!     `sig.fast.zkVerify` reads. Signatures that do not parse, whose max_epoch is out of range,
//!     whose provider is not supported, or whose JWK is unknown are skipped: the per-transaction
//!     check rejects them as before without ever reaching the proof.
//!   - `Ed25519Step`: every plain Ed25519 user signature (flag 0x00, 97 bytes) is checked over
//!     the intent digest with `gpu.Accel.ed25519VerifyEach` (CPU single, CPU pool or GPU per the
//!     dispatch table; per-item verdicts equal to `sig.ed25519.verify`), and the accepted ones go
//!     into the Ed25519 verified-signature cache that the single Ed25519 path of `sig.user` reads.
//!     By default it only runs when the Accel sends the batch to a GPU (gpu or mix path): on a
//!     CPU path it would do the very single verifications the per-transaction pass does on the
//!     same pool, plus the cache traffic (measured slower: `deepwave-validator preverify-bench
//!     --pre-steps --pre-cpu`). `cpu = true` runs it on CPU paths too (tests, bench).
//! Multisig members, passkeys, ECDSA and zkLogin ephemeral signatures are left to the
//! per-transaction pass.
const std = @import("std");
const core = @import("core");
const sig = @import("sig");
const zk = @import("zk");
const gpu = @import("gpu");
const preverify = @import("preverify.zig");

const zkl = zk.zklogin;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const Pool = core.pool.Pool;

fn add(c: *Atomic(u64), n: usize) void {
    _ = c.fetchAdd(@intCast(n), .monotonic);
}

/// zkLogin Groth16 batch. `gpa` must be thread safe (the stage runs on several intake threads).
pub const ZkStep = struct {
    io: std.Io,
    gpa: Allocator,
    calls: Atomic(u64) = .init(0),
    /// Top-level zkLogin signatures handed to `zkPreverify`.
    sigs: Atomic(u64) = .init(0),
    /// Already in the zk cache.
    cached: Atomic(u64) = .init(0),
    /// Successes added to the zk cache.
    filled: Atomic(u64) = .init(0),

    pub fn step(s: *ZkStep) preverify.PreStep {
        return .{ .name = "zklogin", .ctx = s, .run = run, .wants = wants };
    }

    fn wants(_: ?*anyopaque, _: usize, flag: u8) bool {
        return flag == zkl.flag and sig.fast.zkCacheOn();
    }

    fn run(ctx: ?*anyopaque, pool: ?*Pool, env: *const sig.user.UserSigEnv, items: []const preverify.Item) void {
        const s: *ZkStep = @ptrCast(@alignCast(ctx.?));
        if (!sig.fast.zkCacheOn()) return;
        const zenv = if (env.zklogin) |*z| z else return;
        add(&s.calls, 1);
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var list: std.ArrayList(sig.fast.ZkItem) = .empty;
        for (items) |it| for (it.sigs) |raw| {
            if (raw.len == 0 or raw[0] != zkl.flag) continue;
            const scratch = a.alloc(u8, sig.user.scratchLen(raw.len)) catch return;
            const p = a.create(sig.user.Parsed) catch return;
            if (sig.user.parse(raw, p, scratch) != null) continue;
            const z = &p.zklogin;
            if (!zkl.checkEpoch(z.auth.max_epoch, env.epoch, env.flags.zklogin_max_epoch_upper_bound_delta)) continue;
            if (env.flags.zklogin_supported_providers.count() != 0) {
                const prov = sig.user.OidcProvider.fromIss(z.auth.iss) orelse continue;
                if (!env.flags.zklogin_supported_providers.contains(prov)) continue;
            }
            list.append(a, .{ .env = zenv, .auth = &z.auth }) catch return;
        };
        if (list.items.len == 0) return;
        const st = sig.fast.zkPreverify(s.io, s.gpa, list.items, .{ .pool = pool });
        add(&s.sigs, st.items);
        add(&s.cached, st.cached);
        add(&s.filled, st.filled);
    }
};

/// Ed25519 batch through a `gpu.Accel` (its own pool setting: `Accel.pool`, else
/// `core.pool.shared()`). `gpa` must be thread safe.
/// The step pays only when the GPU alone clearly beats the pool: its checks run before the per-
/// transaction pass, not beside it, and the pass still decodes keys and checks authors. So a
/// mixed path is never used, and the batch must be big enough that a quarter of it would already
/// go to the GPU (measured on the M5 Pro: GPU from 2048 in the table, the step pays from ~8k).
fn gpuPays(a: *gpu.Accel, n: usize) bool {
    const p = a.pathFor(.ed25519, n / 4);
    return p.isGpu() and !p.isMix();
}

pub const Ed25519Step = struct {
    accel: *gpu.Accel,
    gpa: Allocator,
    calls: Atomic(u64) = .init(0),
    /// Plain Ed25519 signatures seen.
    sigs: Atomic(u64) = .init(0),
    /// Already in the verified cache (not checked again).
    cached: Atomic(u64) = .init(0),
    /// Checked through the Accel.
    checked: Atomic(u64) = .init(0),
    /// Accepted and added to the verified cache.
    filled: Atomic(u64) = .init(0),
    /// Batches left to the per-transaction pass (the Accel picked a CPU path and `cpu` is off).
    skipped: Atomic(u64) = .init(0),
    /// Also run when the Accel picks a CPU path for the batch.
    cpu: bool = false,

    pub fn step(s: *Ed25519Step) preverify.PreStep {
        return .{ .name = "ed25519", .ctx = s, .run = run, .wants = wants };
    }

    fn wants(ctx: ?*anyopaque, batch_n: usize, flag: u8) bool {
        const s: *Ed25519Step = @ptrCast(@alignCast(ctx.?));
        if (flag != 0 or !sig.fast.edVerifiedOn()) return false;
        return s.cpu or gpuPays(s.accel, batch_n);
    }

    const ed_len = 1 + 64 + 32;

    const Ctx = struct {
        items: []const sig.ed25519.BatchItem,
        keys: [][32]u8,
        skip: []bool,
        out: []const sig.Verdict,

        fn keyRange(c: Ctx, lo: usize, hi: usize) void {
            for (lo..hi) |i| {
                const it = c.items[i];
                c.keys[i] = sig.fast.edVerifiedKey(it.pk, it.msg, it.sig);
                c.skip[i] = sig.fast.edVerifiedContains(&c.keys[i]);
            }
        }

        fn putRange(c: Ctx, lo: usize, hi: usize) void {
            for (c.out[lo..hi], c.keys[lo..hi]) |v, *k| if (v == .valid) sig.fast.edVerifiedPut(k);
        }
    };

    fn run(ctx: ?*anyopaque, pool: ?*Pool, env: *const sig.user.UserSigEnv, items: []const preverify.Item) void {
        _ = env;
        const s: *Ed25519Step = @ptrCast(@alignCast(ctx.?));
        if (!sig.fast.edVerifiedOn()) return;
        add(&s.calls, 1);
        var n: usize = 0;
        for (items) |it| for (it.sigs) |raw| {
            n += @intFromBool(raw.len == ed_len and raw[0] == 0);
        };
        if (n == 0) return;
        add(&s.sigs, n);
        if (!s.cpu and !gpuPays(s.accel, n)) {
            add(&s.skipped, 1);
            return;
        }
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const all = a.alloc(sig.ed25519.BatchItem, n) catch return;
        const keys = a.alloc([32]u8, n) catch return;
        const skip = a.alloc(bool, n) catch return;
        var k: usize = 0;
        // `items` (and their digests) live until the stage is done: the pointers stay valid
        for (items) |*it| for (it.sigs) |raw| {
            if (raw.len != ed_len or raw[0] != 0) continue;
            all[k] = .{ .pk = raw[65..97], .msg = &it.digest, .sig = raw[1..65] };
            k += 1;
        };
        core.pool.forRange(pool, n, 16, 0, Ctx{ .items = all, .keys = keys, .skip = skip, .out = &.{} }, Ctx.keyRange);
        // the ones still to check, compacted (keys move with them)
        var m: usize = 0;
        for (0..n) |i| if (!skip[i]) {
            all[m] = all[i];
            keys[m] = keys[i];
            m += 1;
        };
        add(&s.cached, n - m);
        if (m == 0) return;
        const out = a.alloc(sig.Verdict, m) catch return;
        s.accel.ed25519VerifyEach(all[0..m], out);
        add(&s.checked, m);
        core.pool.forRange(pool, m, 16, 0, Ctx{ .items = all[0..m], .keys = keys[0..m], .skip = skip[0..m], .out = out }, Ctx.putRange);
        var ok: usize = 0;
        for (out) |v| ok += @intFromBool(v == .valid);
        add(&s.filled, ok);
    }
};

/// Both pre-steps (zkLogin first: its proofs are the most expensive), built once and installed
/// in a `preverify.Config` (the steps point into this struct: keep it at a fixed address).
pub const Set = struct {
    zk: ZkStep,
    ed: Ed25519Step,
    steps: [2]preverify.PreStep = undefined,

    pub fn init(s: *Set, io: std.Io, gpa: Allocator, accel: *gpu.Accel) void {
        s.* = .{ .zk = .{ .io = io, .gpa = gpa }, .ed = .{ .accel = accel, .gpa = gpa } };
        s.steps = .{ s.zk.step(), s.ed.step() };
    }

    pub fn slice(s: *const Set) []const preverify.PreStep {
        return &s.steps;
    }

    /// Turns on the two caches the steps fill (both verdict-neutral), keeping the other
    /// `sig.fast` switches as they are.
    pub fn enableCaches() void {
        var c = sig.fast.config();
        c.zk_cache = true;
        c.ed_verified_cache = true;
        sig.fast.configure(c);
    }

    /// The caches these steps can fill: the zk cache always, the Ed25519 verified cache only
    /// when the Ed25519 step can run (a GPU is open, or `ed.cpu`). Without one, every per-
    /// transaction Ed25519 check would pay the cache key hash for nothing.
    pub fn enableUsed(s: *const Set) void {
        var c = sig.fast.config();
        c.zk_cache = true;
        c.ed_verified_cache = s.ed.cpu or s.ed.accel.deviceCount() > 0;
        sig.fast.configure(c);
    }
};
