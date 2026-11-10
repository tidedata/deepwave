//! The accelerator: batch operations that run on one CPU thread, on the shared CPU pool
//! (core.pool), or on every GPU of one kind, picked per batch size from a dispatch table
//! (core.dispatch; filled by calibration in calibrate.zig, cached per machine). Every operation
//! returns what the CPU code returns (the harness in check.zig compares them); a GPU failure of
//! any kind falls back to the CPU pool with the same answer, is counted, and backs the GPU path
//! off for a while. Off by default: `Accel.init(.off)` never opens a device.
//!
//! GPU batches are cut into chunks and pipelined: each device has two slots (two streams on
//! CUDA, two command buffers on Metal); while a chunk runs on one slot the CPU pool prepares the
//! next one in the other, and a freed slot takes the next chunk, so faster devices take more of
//! the batch.
const std = @import("std");
const core = @import("core");
const hash = @import("hash");
const sig = @import("sig");
const zk = @import("zk");
const backend = @import("backend.zig");

const ed25519 = sig.ed25519;
const bn = zk.bn254;
const consts = zk.poseidon.constants;
const Fr = bn.Fr;
const Fq = bn.Fq;
const Allocator = std.mem.Allocator;
const scalar = std.crypto.ecc.Edwards25519.scalar;
const Pool = core.pool.Pool;
pub const Op = core.dispatch.Op;
pub const Path = core.dispatch.Path;
pub const Table = core.dispatch.Table;

pub const Mode = enum {
    off,
    auto,
    metal,
    cuda,

    pub fn parse(s: []const u8) ?Mode {
        return std.meta.stringToEnum(Mode, s);
    }
};

pub const max_devices = 8;

/// Minimal lock (no Io needed): GPU sequences are short and the devices are shared.
const SpinLock = struct {
    held: std.atomic.Value(bool) = .init(false),
    fn lock(l: *SpinLock) void {
        while (l.held.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.Thread.yield() catch {};
    }
    fn unlock(l: *SpinLock) void {
        l.held.store(false, .release);
    }
};

pub const Stats = struct {
    /// Ed25519 GPU pipeline: ns the caller spent in host prep, and ns from submit to collect.
    ed_prep_ns: std.atomic.Value(u64) = .init(0),
    ed_gpu_ns: std.atomic.Value(u64) = .init(0),
    gpu_items: std.atomic.Value(u64) = .init(0),
    cpu_items: std.atomic.Value(u64) = .init(0),
    fallbacks: std.atomic.Value(u64) = .init(0),

    pub fn add(c: *std.atomic.Value(u64), n: u64) void {
        _ = c.fetchAdd(n, .monotonic);
    }
    pub fn get(c: *const std.atomic.Value(u64)) u64 {
        return c.load(.monotonic);
    }
};

pub fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// Persistent per-device buffers (grow-only), by role and pipeline slot.
const Role = enum(u8) { ed_in, ed_out, ed_prm, ed_scr, pos_in, pos_out, pos_prm, mul_pts, mul_sc, mul_out, mul_prm, msm_a, msm_b, msm_prm, f_x, f_y, f_out, f_prm };
const n_roles = @typeInfo(Role).@"enum".field_names.len;

const Dev = struct {
    be: backend.Backend,
    bufs: [n_roles * backend.max_slots]?backend.Buffer = @splat(null),
    ed_consts: ?backend.Buffer = null,
    /// Poseidon round constants and MDS matrix per input count (device memory).
    pos_c: [17]?backend.Buffer = @splat(null),
    pos_m: [17]?backend.Buffer = @splat(null),

    fn deinit(d: *Dev) void {
        for (d.bufs) |b| if (b) |x| d.be.free(x);
        if (d.ed_consts) |x| d.be.free(x);
        for (d.pos_c) |b| if (b) |x| d.be.free(x);
        for (d.pos_m) |b| if (b) |x| d.be.free(x);
        d.be.deinit();
    }

    /// The slot's buffer for `role`, at least `len` bytes (host-visible unless `device`).
    fn buf(d: *Dev, role: Role, slot: usize, len: usize, device: bool) backend.Error!backend.Buffer {
        const i = @intFromEnum(role) * backend.max_slots + slot;
        if (d.bufs[i]) |b| {
            if (b.len >= len) return b;
            d.be.free(b);
            d.bufs[i] = null;
        }
        // grow by half again so a run of slightly larger batches does not reallocate each time
        const want = @max(len + len / 2, 4096);
        const b = if (device) try d.be.allocDevice(want) else try d.be.alloc(want);
        d.bufs[i] = b;
        return b;
    }
};

pub const InitOpts = struct {
    mode: Mode = .auto,
    /// Use at most this many devices (0: all).
    max_devices: usize = 0,
};

/// Backend calls are serialised by `mutex` (devices and their buffers are shared), so one Accel
/// may be used from many threads; CPU paths run without the lock.
pub const Accel = struct {
    devs: [max_devices]Dev = undefined,
    ndev: usize = 0,
    kind: backend.Kind = .none,
    gpa: Allocator,
    /// CPU pool for prep and CPU batches; null: core.pool.shared() (null too: inline).
    pool: ?*Pool = null,
    table: Table,
    /// Every batch takes this path (harness, calibration); clamped to what exists.
    forced: ?Path = null,
    stats: Stats = .{},
    mutex: SpinLock = .{},
    /// GPU back-off after a failure: GPU paths run on the pool until this time.
    backoff_until: std.atomic.Value(u64) = .init(0),
    fail_streak: std.atomic.Value(u32) = .init(0),
    /// Set for good when a GPU Ed25519 batch answered one of its canaries wrong (a known-valid
    /// and two known-invalid signatures ride in every GPU batch): from then on Ed25519 never goes
    /// to a GPU in this process, forced paths included.
    ed_gpu_bad: std.atomic.Value(bool) = .init(false),
    canary_trips: std.atomic.Value(u64) = .init(0),

    pub fn init(gpa: Allocator, mode: Mode) Accel {
        return initOpts(gpa, .{ .mode = mode });
    }

    pub fn initOpts(gpa: Allocator, o: InitOpts) Accel {
        var a: Accel = .{ .gpa = gpa, .table = Table.static(0) };
        const kind: backend.Kind = switch (o.mode) {
            .off => .none,
            .auto => backend.Backend.detectKind(),
            .metal => .metal,
            .cuda => .cuda,
        };
        if (kind == .none) return a;
        var want = backend.Backend.deviceCount(kind);
        if (envDevices()) |e| want = @min(want, e);
        if (o.max_devices != 0) want = @min(want, o.max_devices);
        want = @min(want, max_devices);
        for (0..want) |i| {
            const be = backend.Backend.openDevice(kind, @intCast(i)) catch continue;
            a.devs[a.ndev] = .{ .be = be };
            a.ndev += 1;
        }
        if (a.ndev > 0) a.kind = kind;
        a.table = Table.static(a.ndev);
        return a;
    }

    pub fn deinit(a: *Accel) void {
        for (a.devs[0..a.ndev]) |*d| d.deinit();
        a.ndev = 0;
    }

    pub fn active(a: *const Accel) bool {
        return a.ndev > 0;
    }

    pub fn deviceCount(a: *const Accel) usize {
        return a.ndev;
    }

    pub fn name(a: *const Accel) []const u8 {
        return if (a.ndev > 0) a.devs[0].be.name() else "none";
    }

    pub fn deviceName(a: *const Accel, i: usize) []const u8 {
        return a.devs[i].be.name();
    }

    pub fn devicePci(a: *const Accel, i: usize) []const u8 {
        return a.devs[i].be.pciId();
    }

    /// Every batch goes to the GPU on all devices (for the equality harness).
    pub fn forceGpu(a: *Accel) void {
        a.forced = Path.gpu(a.ndev);
    }

    fn getPool(a: *const Accel) ?*Pool {
        return a.pool orelse core.pool.shared();
    }

    pub fn poolLanes(a: *const Accel) usize {
        return if (a.getPool()) |p| p.lanes() else 1;
    }

    /// The path a batch of `n` items of `op` takes now.
    pub fn pathFor(a: *Accel, op: Op, n: usize) Path {
        var p = a.forced orelse a.table.pick(op, n);
        if (p.isGpu()) {
            if (a.ndev == 0) return if (n > 1) .pool else .cpu1;
            if (op == .ed25519 and a.ed_gpu_bad.load(.monotonic)) return if (n > 1) .pool else .cpu1;
            if (a.forced == null and nowNs() < a.backoff_until.load(.monotonic)) return .pool;
            if (p.gpuDevices() > a.ndev) p = p.withDevices(a.ndev);
            if (p.isMix() and (op == .msm or a.poolLanes() < 2)) p = Path.gpu(p.gpuDevices());
        }
        return p;
    }

    fn noteGpuFailure(a: *Accel) void {
        Stats.add(&a.stats.fallbacks, 1);
        const streak = a.fail_streak.fetchAdd(1, .monotonic) + 1;
        const secs: u64 = @min(@as(u64, 600), @as(u64, 1) << @intCast(@min(streak, 10)));
        a.backoff_until.store(nowNs() + secs * std.time.ns_per_s, .monotonic);
    }

    fn noteGpuOk(a: *Accel) void {
        if (a.fail_streak.load(.monotonic) != 0) a.fail_streak.store(0, .monotonic);
    }

    // ------------------------------------------------------------------------------------------
    // Chunked multi-device pipeline

    /// Runs `op` over [0, n) in chunks on `ndev` devices, two slots each. `op` provides
    /// `prep(a, dev, slot, lo, hi)`, `launch(a, dev, slot, lo, hi)` and `finish(a, dev, slot, lo, hi)`.
    /// On any error every slot is drained and the error returned (the caller redoes the batch on
    /// the CPU).
    fn runChunks(a: *Accel, op: anytype, n: usize, ndev: usize, chunk: usize) backend.Error!void {
        var c = Claim.init(n);
        return a.runClaimed(op, &c, ndev, chunk, false);
    }

    /// `runChunks` over ranges taken from `claim` (from the back when `back`, so CPU lanes can
    /// take small grains from the front of the same batch at the same time).
    fn runClaimed(a: *Accel, op: anytype, claim: *Claim, ndev: usize, chunk: usize, back: bool) backend.Error!void {
        const Inflight = struct { lo: usize, hi: usize };
        var inflight: [max_devices][backend.max_slots]?Inflight = @splat(@splat(null));
        var drained = false;
        var err: ?backend.Error = null;
        while (true) {
            // fill free slots, slot 0 of every device first so all devices start early
            if (err == null) {
                outer: for (0..backend.max_slots) |s| for (0..ndev) |d| {
                    if (drained) break :outer;
                    if (inflight[d][s] != null) continue;
                    const r = (if (back) claim.takeBack(chunk) else claim.takeFront(chunk)) orelse {
                        drained = true;
                        break :outer;
                    };
                    const lo = r[0];
                    const hi = r[1];
                    op.prep(a, d, s, lo, hi) catch |e| {
                        err = e;
                        break :outer;
                    };
                    op.launch(a, d, s, lo, hi) catch |e| {
                        err = e;
                        break :outer;
                    };
                    inflight[d][s] = .{ .lo = lo, .hi = hi };
                };
            }
            // anything in flight?
            var any = false;
            for (0..ndev) |d| for (0..backend.max_slots) |s| {
                if (inflight[d][s] != null) any = true;
            };
            if (!any) break;
            // collect the first slot that is done (poll; when more work waits, a short spin)
            var got = false;
            while (!got) {
                for (0..ndev) |d| for (0..backend.max_slots) |s| {
                    const f = inflight[d][s] orelse continue;
                    if (!a.devs[d].be.done(s)) continue;
                    inflight[d][s] = null;
                    got = true;
                    a.devs[d].be.wait(s) catch |e| {
                        if (err == null) err = e;
                        continue;
                    };
                    if (err == null) op.finish(a, d, s, f.lo, f.hi) catch |e| {
                        err = e;
                    };
                };
                if (!got) std.atomic.spinLoopHint();
            }
        }
        if (err) |e| return e;
    }

    /// GPU on `ndev` devices and the CPU pool on one batch at once: a driver thread feeds the GPUs
    /// chunks from the back while the pool lanes take grains from the front, so both finish
    /// together whatever their speeds. `cpu(ctx, lo, hi)` is the per-item CPU path. Any GPU error
    /// redoes the whole batch on the pool (same answers).
    fn runHybrid(a: *Accel, op: anytype, n: usize, ndev: usize, chunk: usize, ctx: anytype, comptime cpu: fn (@TypeOf(ctx), usize, usize) void) bool {
        var claim = Claim.init(n);
        const Driver = struct {
            fn run(acc: *Accel, o: @TypeOf(op), c: *Claim, nd: usize, ch: usize, err: *bool) void {
                acc.mutex.lock();
                defer acc.mutex.unlock();
                acc.runClaimed(o, c, nd, ch, true) catch {
                    err.* = true;
                };
            }
        };
        var gpu_err = false;
        const th = std.Thread.spawn(.{}, Driver.run, .{ a, op, &claim, ndev, chunk, &gpu_err }) catch return false;
        const C = @TypeOf(ctx);
        const Lane = struct {
            c: *Claim,
            ctx: C,
            fn run(l: @This(), _: usize, _: usize) void {
                while (l.c.takeFront(16)) |r| cpu(l.ctx, r[0], r[1]);
            }
        };
        // one lane fewer than the pool has: the driver thread needs a core for host prep
        const lanes = a.poolLanes() - 1;
        core.pool.forRange(a.getPool(), lanes, 1, lanes, Lane{ .c = &claim, .ctx = ctx }, Lane.run);
        th.join();
        if (gpu_err) {
            a.noteGpuFailure();
            core.pool.forRange(a.getPool(), n, a.grainFor(n, 4), 0, ctx, cpu);
            return true;
        }
        a.noteGpuOk();
        return true;
    }

    /// GPU chunk size in a mixed batch: small enough that the end of the batch balances.
    fn mixChunk(n: usize, ndev: usize) usize {
        return std.math.clamp(n / (8 * ndev), 512, 1 << 15);
    }

    fn chunkFor(n: usize, ndev: usize, min_chunk: usize, max_chunk: usize) usize {
        const per = (n + 2 * ndev - 1) / (2 * ndev);
        return std.math.clamp(per, @min(min_chunk, n), max_chunk);
    }

    // ------------------------------------------------------------------------------------------
    // Ed25519

    /// One verdict per item, equal to `ed25519.verify` on each (ZIP-215 cofactored check).
    pub fn ed25519VerifyEach(a: *Accel, items: []const ed25519.BatchItem, out: []sig.Verdict) void {
        std.debug.assert(out.len == items.len);
        const p = a.pathFor(.ed25519, items.len);
        switch (p) {
            .cpu1 => edCpuRange(.{ .items = items, .out = out }, 0, items.len),
            .pool => a.edPool(items, out),
            _ => {
                // the canaries ride at the back (a mixed batch's GPU side starts there)
                const cn = edCanaries();
                const n = items.len;
                const ext = a.gpa.alloc(ed25519.BatchItem, n + n_canaries) catch return a.edPoolCounted(items, out);
                defer a.gpa.free(ext);
                const eout = a.gpa.alloc(sig.Verdict, n + n_canaries) catch return a.edPoolCounted(items, out);
                defer a.gpa.free(eout);
                @memcpy(ext[0..n], items);
                @memcpy(ext[n..], &cn.items);
                a.edGpuPath(p, ext, eout);
                for (eout[n..], cn.want) |g, w| if (!std.meta.eql(g, w)) {
                    a.edCanaryTrip();
                    return a.edPoolCounted(items, out);
                };
                @memcpy(out, eout[0..n]);
                return;
            },
        }
        Stats.add(&a.stats.cpu_items, items.len);
    }

    fn edPoolCounted(a: *Accel, items: []const ed25519.BatchItem, out: []sig.Verdict) void {
        a.edPool(items, out);
        Stats.add(&a.stats.cpu_items, items.len);
    }

    fn edGpuPath(a: *Accel, p: Path, items: []const ed25519.BatchItem, out: []sig.Verdict) void {
        if (p.isMix()) {
            const op: EdOp = .{ .items = items, .out = out };
            if (a.runHybrid(&op, items.len, p.gpuDevices(), mixChunk(items.len, p.gpuDevices()), EdCtx{ .items = items, .out = out }, edCpuRange)) {
                Stats.add(&a.stats.gpu_items, items.len);
                return;
            }
        }
        if (a.edGpu(items, out, p.gpuDevices())) |_| {
            a.noteGpuOk();
            Stats.add(&a.stats.gpu_items, items.len);
        } else |_| {
            a.noteGpuFailure();
            a.edPool(items, out);
        }
    }

    /// A canary came back wrong: the GPU Ed25519 path is off for good (counted as a fallback, so
    /// calibrate.checkDevices reports the device as failed).
    fn edCanaryTrip(a: *Accel) void {
        _ = a.canary_trips.fetchAdd(1, .monotonic);
        Stats.add(&a.stats.fallbacks, 1);
        if (!a.ed_gpu_bad.swap(true, .monotonic))
            std.log.err("gpu: an Ed25519 canary came back wrong on {s}; the GPU Ed25519 path is off for this process (CPU answers from now on)", .{a.name()});
    }

    /// Same verdict as `ed25519.verifyBatch` computed from per-item results: valid iff every item
    /// is; the failing reason is verify:InvalidSignature, and an empty batch is InvalidInput.
    pub fn ed25519VerifyBatch(a: *Accel, items: []const ed25519.BatchItem) sig.Verdict {
        if (items.len == 0) return .{ .invalid = .verify_invalid_input };
        if (a.pathFor(.ed25519, items.len) == .cpu1) {
            Stats.add(&a.stats.cpu_items, items.len);
            var scratch: [64 * 1024]u8 = undefined;
            return ed25519.verifyBatch(items, &scratch);
        }
        const out = a.gpa.alloc(sig.Verdict, items.len) catch {
            Stats.add(&a.stats.cpu_items, items.len);
            for (items) |it| if (ed25519.verify(it.pk, it.msg, it.sig) != .valid) return .{ .invalid = .verify_invalid_signature };
            return .valid;
        };
        defer a.gpa.free(out);
        a.ed25519VerifyEach(items, out);
        for (out) |v| if (v != .valid) return .{ .invalid = .verify_invalid_signature };
        return .valid;
    }

    const EdCtx = struct { items: []const ed25519.BatchItem, out: []sig.Verdict };
    /// Per-item `ed25519.verify` answers, by batch-equation chunks (a failing chunk one by one).
    fn edCpuRange(c: EdCtx, lo: usize, hi: usize) void {
        sig.batch.edVerifyLeaves(c.items[lo..hi], c.out[lo..hi]);
    }

    fn grainFor(a: *const Accel, n: usize, min_grain: usize) usize {
        const lanes = a.poolLanes();
        return @max(min_grain, n / (lanes * 4));
    }

    fn edPool(a: *Accel, items: []const ed25519.BatchItem, out: []sig.Verdict) void {
        core.pool.forRange(a.getPool(), items.len, a.grainFor(items.len, 4), 0, EdCtx{ .items = items, .out = out }, edCpuRange);
    }

    pub const ed_words = 44;
    /// Per-item GPU scratch (the kernel's A and R window tables), ED_SCR_WORDS in ed25519.inc.
    const ed_scr_words = 640;
    const ed_max_chunk = 1 << 15;

    const EdOp = struct {
        items: []const ed25519.BatchItem,
        out: []sig.Verdict,

        const PrepCtx = struct { items: []const ed25519.BatchItem, w: []u32 };
        fn prepRange(c: PrepCtx, lo: usize, hi: usize) void {
            for (lo..hi) |i| edPrep(c.items[i], c.w[i * ed_words ..][0..ed_words]);
        }

        fn prep(op: *const EdOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const dev = &a.devs[d];
            const n = hi - lo;
            const ib = try dev.buf(.ed_in, s, n * ed_words * 4, false);
            const iw = ib.words();
            const t0 = nowNs();
            core.pool.forRange(a.getPool(), n, a.grainFor(n, 64), 0, PrepCtx{ .items = op.items[lo..hi], .w = iw }, prepRange);
            Stats.add(&a.stats.ed_prep_ns, nowNs() - t0);
        }

        fn launch(_: *const EdOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const dev = &a.devs[d];
            const n = hi - lo;
            const ib = try dev.buf(.ed_in, s, n * ed_words * 4, false);
            const ob = try dev.buf(.ed_out, s, n * 4, false);
            const pb = try dev.buf(.ed_prm, s, 16, false);
            const cb = try a.edConsts(d);
            pb.words()[0] = @intCast(n);
            pb.words()[2] = @truncate(nowNs());
            pb.words()[3] = @truncate(nowNs() >> 32);
            const sb = try dev.buf(.ed_scr, s, n * ed_scr_words * 4, true);
            try dev.be.submit(s, .ed25519, &.{ ib, cb, ob, pb, sb }, n);
        }

        fn finish(op: *const EdOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const ob = try a.devs[d].buf(.ed_out, s, (hi - lo) * 4, false);
            const ow = ob.words();
            const pw = (try a.devs[d].buf(.ed_prm, s, 16, false)).words();
            Stats.add(&a.stats.ed_gpu_ns, nowNs() -% (@as(u64, pw[3]) << 32 | pw[2]));
            for (op.out[lo..hi], 0..) |*o, i| o.* = switch (ow[i]) {
                1 => .valid,
                2 => .{ .invalid = .pk_invalid_input },
                else => .{ .invalid = .verify_invalid_signature },
            };
        }
    };

    fn edGpu(a: *Accel, items: []const ed25519.BatchItem, out: []sig.Verdict, ndev: usize) backend.Error!void {
        a.mutex.lock();
        defer a.mutex.unlock();
        const op: EdOp = .{ .items = items, .out = out };
        try a.runChunks(&op, items.len, ndev, chunkFor(items.len, ndev, 256, ed_max_chunk));
    }

    /// d, 2d, sqrt(-1), then kB and k(2^128 B) for k = 1..128 (affine Niels), on the device, each
    /// field element as the kernel's ten radix-2^25.5 limbs (putLimbs).
    fn edConsts(a: *Accel, d: usize) backend.Error!backend.Buffer {
        const dev = &a.devs[d];
        if (dev.ed_consts) |b| return b;
        const words = 30 + 2 * 128 * 30;
        const w = a.gpa.alloc(u32, words) catch return error.OutOfMemory;
        defer a.gpa.free(w);
        putLimbs(w[0..10], ed25519.Fe.d);
        putLimbs(w[10..20], ed25519.Fe.d2);
        putLimbs(w[20..30], ed25519.Fe.sqrtm1);
        var b128 = ed25519.basepoint;
        for (0..128) |_| b128 = b128.dbl();
        for ([2]ed25519.Point{ ed25519.basepoint, b128 }, 0..) |base, ti| {
            var cur = base;
            for (0..128) |i| {
                const n = cur.toAffineNiels();
                const o = 30 + ti * 128 * 30 + i * 30;
                putLimbs(w[o..][0..10], n.ypx);
                putLimbs(w[o + 10 ..][0..10], n.ymx);
                putLimbs(w[o + 20 ..][0..10], n.xy2d);
                cur = cur.add(base);
            }
        }
        const b = try dev.be.allocDevice(words * 4);
        dev.be.upload(b, 0, std.mem.sliceAsBytes(w)) catch |e| {
            dev.be.free(b);
            return e;
        };
        dev.ed_consts = b;
        return b;
    }

    // ------------------------------------------------------------------------------------------
    // Poseidon

    /// `out[i] = poseidon(inputs[i*n .. (i+1)*n])` for 1 <= n <= 16 (the width-(n+1) circomlib
    /// permutation, as zk.poseidon.hash).
    pub fn poseidonBatch(a: *Accel, n: usize, inputs: []const Fr, out: []Fr) void {
        const count = out.len;
        std.debug.assert(n >= 1 and n <= 16 and inputs.len == count * n);
        const p = a.pathFor(.poseidon, count);
        const ctx = PoCtx{ .n = n, .in = inputs, .out = out };
        switch (p) {
            .cpu1 => poCpuRange(ctx, 0, count),
            .pool => core.pool.forRange(a.getPool(), count, a.grainFor(count, 8), 0, ctx, poCpuRange),
            _ => {
                if (p.isMix()) {
                    const op: PosOp = .{ .n = n, .in = inputs, .out = out };
                    if (a.runHybrid(&op, count, p.gpuDevices(), mixChunk(count, p.gpuDevices()), ctx, poCpuRange)) {
                        Stats.add(&a.stats.gpu_items, count);
                        return;
                    }
                }
                if (a.poseidonGpu(n, inputs, out, p.gpuDevices())) |_| {
                    a.noteGpuOk();
                    Stats.add(&a.stats.gpu_items, count);
                    return;
                } else |_| {
                    a.noteGpuFailure();
                    core.pool.forRange(a.getPool(), count, a.grainFor(count, 8), 0, ctx, poCpuRange);
                }
            },
        }
        Stats.add(&a.stats.cpu_items, count);
    }

    const PoCtx = struct { n: usize, in: []const Fr, out: []Fr };
    fn poCpuRange(c: PoCtx, lo: usize, hi: usize) void {
        for (lo..hi) |i| c.out[i] = zk.poseidon.hash(c.in[i * c.n ..][0..c.n]).?;
    }

    fn posConsts(a: *Accel, d: usize, nn: usize) backend.Error![2]backend.Buffer {
        const dev = &a.devs[d];
        if (dev.pos_c[nn]) |c| return .{ c, dev.pos_m[nn].? };
        switch (nn) {
            inline 1...16 => |k| {
                @setEvalBranchQuota(1_000_000);
                const t = k + 1;
                const rp: usize = consts.partial_rounds[t - 2];
                const cc = @field(consts, std.fmt.comptimePrint("c{d}", .{t}));
                const mm = @field(consts, std.fmt.comptimePrint("m{d}", .{t}));
                const cb = try dev.be.allocDevice((8 + rp) * t * 32);
                errdefer dev.be.free(cb);
                const mb = try dev.be.allocDevice(t * t * 32);
                errdefer dev.be.free(mb);
                try dev.be.upload(cb, 0, std.mem.sliceAsBytes(cc[0 .. (8 + rp) * t]));
                try dev.be.upload(mb, 0, std.mem.sliceAsBytes(mm[0 .. t * t]));
                dev.pos_c[nn] = cb;
                dev.pos_m[nn] = mb;
                return .{ cb, mb };
            },
            else => unreachable,
        }
    }

    const PosOp = struct {
        n: usize,
        in: []const Fr,
        out: []Fr,

        fn prep(op: *const PosOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const ib = try a.devs[d].buf(.pos_in, s, (hi - lo) * op.n * 32, false);
            @memcpy(ib.ptr[0 .. (hi - lo) * op.n * 32], std.mem.sliceAsBytes(op.in[lo * op.n .. hi * op.n]));
        }
        fn launch(op: *const PosOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const dev = &a.devs[d];
            const count = hi - lo;
            const ib = try dev.buf(.pos_in, s, count * op.n * 32, false);
            const ob = try dev.buf(.pos_out, s, count * 32, false);
            const pb = try dev.buf(.pos_prm, s, 16, false);
            const cm = try a.posConsts(d, op.n);
            pb.words()[0] = @intCast(op.n);
            pb.words()[1] = @intCast(consts.partial_rounds[op.n - 1]);
            pb.words()[2] = @intCast(count);
            try dev.be.submit(s, .poseidon, &.{ ib, cm[0], cm[1], ob, pb }, count);
        }
        fn finish(op: *const PosOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const ob = try a.devs[d].buf(.pos_out, s, (hi - lo) * 32, false);
            @memcpy(std.mem.sliceAsBytes(op.out[lo..hi]), ob.ptr[0 .. (hi - lo) * 32]);
        }
    };

    fn poseidonGpu(a: *Accel, n: usize, inputs: []const Fr, out: []Fr, ndev: usize) backend.Error!void {
        a.mutex.lock();
        defer a.mutex.unlock();
        const op: PosOp = .{ .n = n, .in = inputs, .out = out };
        try a.runChunks(&op, out.len, ndev, chunkFor(out.len, ndev, 1024, 1 << 18));
    }

    // ------------------------------------------------------------------------------------------
    // BN254 G1 multi-scalar multiplication (Groth16 public-input accumulation)

    /// sum_i scalars[i] * points[i], scalars as canonical little-endian limbs (< r). Equal to the
    /// CPU sum of `G1J.mulLimbs` (same group element; the Jacobian representative may differ).
    pub fn g1Msm(a: *Accel, points: []const bn.G1, scalars: []const [4]u64) bn.G1J {
        std.debug.assert(points.len == scalars.len);
        const p = a.pathFor(.msm, points.len);
        switch (p) {
            .cpu1 => {},
            .pool => {
                Stats.add(&a.stats.cpu_items, points.len);
                return a.g1MsmPool(points, scalars);
            },
            _ => {
                if (a.g1MsmGpu(points, scalars, p.gpuDevices())) |r| {
                    a.noteGpuOk();
                    Stats.add(&a.stats.gpu_items, points.len);
                    return r;
                } else |_| {
                    a.noteGpuFailure();
                    Stats.add(&a.stats.cpu_items, points.len);
                    return a.g1MsmPool(points, scalars);
                }
            },
        }
        Stats.add(&a.stats.cpu_items, points.len);
        return g1MsmCpu(points, scalars);
    }

    pub fn g1MsmCpu(points: []const bn.G1, scalars: []const [4]u64) bn.G1J {
        var acc = bn.G1J.identity;
        for (points, scalars) |p, k| acc = acc.add(bn.G1J.mulLimbs(p, &k));
        return acc;
    }

    const MsmPoolCtx = struct { pts: []const bn.G1, ks: []const [4]u64, parts: []bn.G1J, grain: usize };
    fn msmPoolRange(c: MsmPoolCtx, lo: usize, hi: usize) void {
        c.parts[lo / c.grain] = g1MsmCpu(c.pts[lo..hi], c.ks[lo..hi]);
    }

    fn g1MsmPool(a: *Accel, points: []const bn.G1, scalars: []const [4]u64) bn.G1J {
        const n = points.len;
        const grain = a.grainFor(n, 4);
        const nparts = (n + grain - 1) / grain;
        var stack_parts: [256]bn.G1J = undefined;
        const heap = if (nparts > stack_parts.len) a.gpa.alloc(bn.G1J, nparts) catch return g1MsmCpu(points, scalars) else null;
        defer if (heap) |h| a.gpa.free(h);
        const parts = heap orelse stack_parts[0..nparts];
        core.pool.forRange(a.getPool(), n, grain, 0, MsmPoolCtx{ .pts = points, .ks = scalars, .parts = parts, .grain = grain }, msmPoolRange);
        var acc = bn.G1J.identity;
        for (parts) |p| acc = acc.add(p);
        return acc;
    }

    const MsmOp = struct {
        pts: []const bn.G1,
        ks: []const [4]u64,
        acc: bn.G1J = bn.G1J.identity,

        fn prep(op: *MsmOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const n = hi - lo;
            const pb = try a.devs[d].buf(.mul_pts, s, n * 96, false);
            const sb = try a.devs[d].buf(.mul_sc, s, n * 32, false);
            packPoints(pb.words(), op.pts[lo..hi]);
            @memcpy(sb.ptr[0 .. n * 32], std.mem.sliceAsBytes(op.ks[lo..hi]));
        }
        fn launch(_: *MsmOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const dev = &a.devs[d];
            const n = hi - lo;
            const pb = try dev.buf(.mul_pts, s, n * 96, false);
            const sb = try dev.buf(.mul_sc, s, n * 32, false);
            var bufa = try dev.buf(.msm_a, s, n * 96, true);
            var bufb = try dev.buf(.msm_b, s, ((n + 1) / 2) * 96, true);
            // one 16-byte parameter block per launch (the launches are queued, not waited on)
            const prm = try dev.buf(.msm_prm, s, 16 * 64, false);
            const pw = prm.words();
            pw[0] = @intCast(n);
            try dev.be.submit(s, .g1_mul, &.{ pb, sb, bufa, prm.at(0) }, n);
            var cur = n;
            var k: usize = 1;
            while (cur > 1) : (k += 1) {
                const next = (cur + 1) / 2;
                pw[k * 4] = @intCast(next);
                pw[k * 4 + 1] = @intCast(cur);
                try dev.be.submit(s, .g1_add_pairs, &.{ bufa, bufb, prm.at(k * 16) }, next);
                std.mem.swap(backend.Buffer, &bufa, &bufb);
                cur = next;
            }
            // remember which buffer holds the sum: the parity of the pass count
            pw[63 * 4] = @intCast(k - 1);
        }
        fn finish(op: *MsmOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const dev = &a.devs[d];
            const n = hi - lo;
            const prm = try dev.buf(.msm_prm, s, 16 * 64, false);
            const passes = prm.words()[63 * 4];
            const src = if (passes % 2 == 0) try dev.buf(.msm_a, s, n * 96, true) else try dev.buf(.msm_b, s, ((n + 1) / 2) * 96, true);
            var w: [24]u32 = undefined;
            try dev.be.download(src, 0, std.mem.sliceAsBytes(&w));
            op.acc = op.acc.add(unpackJ(&w));
        }
    };

    fn g1MsmGpu(a: *Accel, points: []const bn.G1, scalars: []const [4]u64, ndev: usize) backend.Error!bn.G1J {
        const n = points.len;
        if (n == 0) return bn.G1J.identity;
        a.mutex.lock();
        defer a.mutex.unlock();
        var op: MsmOp = .{ .pts = points, .ks = scalars };
        // one chunk per device and slot; at most 2^62 passes so the parameter blocks fit
        try a.runChunks(&op, n, ndev, chunkFor(n, ndev, 64, 1 << 22));
        return op.acc;
    }

    /// out[i] = scalars[i] * points[i] for many independent terms (one per Groth16 proof, so a batch of
    /// zkLogin verifications reaches the GPU threshold even though each proof has only 1 to 8 public
    /// inputs). Same group elements as `G1J.mulLimbs`.
    pub fn g1MulEach(a: *Accel, points: []const bn.G1, scalars: []const [4]u64, out: []bn.G1J) void {
        std.debug.assert(points.len == scalars.len and out.len == points.len);
        const n = points.len;
        const p = a.pathFor(.mul_each, n);
        const ctx = MulCtx{ .pts = points, .ks = scalars, .out = out };
        switch (p) {
            .cpu1 => mulCpuRange(ctx, 0, n),
            .pool => core.pool.forRange(a.getPool(), n, a.grainFor(n, 2), 0, ctx, mulCpuRange),
            _ => {
                if (p.isMix() and n > 0) {
                    const op: MulOp = .{ .pts = points, .ks = scalars, .out = out };
                    if (a.runHybrid(&op, n, p.gpuDevices(), mixChunk(n, p.gpuDevices()), ctx, mulCpuRange)) {
                        Stats.add(&a.stats.gpu_items, n);
                        return;
                    }
                }
                if (a.g1MulEachGpu(points, scalars, out, p.gpuDevices())) |_| {
                    a.noteGpuOk();
                    Stats.add(&a.stats.gpu_items, n);
                    return;
                } else |_| {
                    a.noteGpuFailure();
                    core.pool.forRange(a.getPool(), n, a.grainFor(n, 2), 0, ctx, mulCpuRange);
                }
            },
        }
        Stats.add(&a.stats.cpu_items, n);
    }

    const MulCtx = struct { pts: []const bn.G1, ks: []const [4]u64, out: []bn.G1J };
    fn mulCpuRange(c: MulCtx, lo: usize, hi: usize) void {
        for (lo..hi) |i| c.out[i] = bn.G1J.mulLimbs(c.pts[i], &c.ks[i]);
    }

    const MulOp = struct {
        pts: []const bn.G1,
        ks: []const [4]u64,
        out: []bn.G1J,

        fn prep(op: *const MulOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const n = hi - lo;
            const pb = try a.devs[d].buf(.mul_pts, s, n * 96, false);
            const sb = try a.devs[d].buf(.mul_sc, s, n * 32, false);
            packPoints(pb.words(), op.pts[lo..hi]);
            @memcpy(sb.ptr[0 .. n * 32], std.mem.sliceAsBytes(op.ks[lo..hi]));
        }
        fn launch(_: *const MulOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const dev = &a.devs[d];
            const n = hi - lo;
            const pb = try dev.buf(.mul_pts, s, n * 96, false);
            const sb = try dev.buf(.mul_sc, s, n * 32, false);
            const ob = try dev.buf(.mul_out, s, n * 96, false);
            const prm = try dev.buf(.mul_prm, s, 16, false);
            prm.words()[0] = @intCast(n);
            try dev.be.submit(s, .g1_mul, &.{ pb, sb, ob, prm }, n);
        }
        fn finish(op: *const MulOp, a: *Accel, d: usize, s: usize, lo: usize, hi: usize) backend.Error!void {
            const ob = try a.devs[d].buf(.mul_out, s, (hi - lo) * 96, false);
            const w = ob.words();
            for (op.out[lo..hi], 0..) |*r, i| r.* = unpackJ(w[i * 24 ..][0..24]);
        }
    };

    fn g1MulEachGpu(a: *Accel, points: []const bn.G1, scalars: []const [4]u64, out: []bn.G1J, ndev: usize) backend.Error!void {
        if (points.len == 0) return;
        a.mutex.lock();
        defer a.mutex.unlock();
        const op: MulOp = .{ .pts = points, .ks = scalars, .out = out };
        try a.runChunks(&op, points.len, ndev, chunkFor(points.len, ndev, 256, 1 << 17));
    }

    // ------------------------------------------------------------------------------------------
    // Field self test (harness): out = op(a, b) lane by lane, 32 bytes per value, on device `dev`.

    pub const FieldOp = enum(u32) { fr_mul, fq_mul, fx_mul, fr_add, fr_sub, fx_add, fx_sub, fq_add, fq_sub, fx_sq };

    pub fn fieldOp(a: *Accel, op: FieldOp, x: []const [32]u8, y: []const [32]u8, out: [][32]u8) backend.Error!void {
        for (0..a.ndev) |d| try a.fieldOpOn(d, op, x, y, out);
    }

    /// `fieldOp` on one device (every device computes it in `fieldOp`; the last one's result stays).
    pub fn fieldOpOn(a: *Accel, d: usize, op: FieldOp, x: []const [32]u8, y: []const [32]u8, out: [][32]u8) backend.Error!void {
        a.mutex.lock();
        defer a.mutex.unlock();
        const dev = &a.devs[d];
        const n = x.len;
        const xb = try dev.buf(.f_x, 0, n * 32, false);
        const yb = try dev.buf(.f_y, 0, n * 32, false);
        const ob = try dev.buf(.f_out, 0, n * 32, false);
        const pb = try dev.buf(.f_prm, 0, 16, false);
        @memcpy(xb.ptr[0 .. n * 32], std.mem.sliceAsBytes(x));
        @memcpy(yb.ptr[0 .. n * 32], std.mem.sliceAsBytes(y));
        pb.words()[0] = @intFromEnum(op);
        pb.words()[1] = @intCast(n);
        try dev.be.launch(.selftest, &.{ xb, yb, ob, pb }, n);
        @memcpy(std.mem.sliceAsBytes(out), ob.ptr[0 .. n * 32]);
    }
};

/// [lo, hi) of a batch still unclaimed: CPU lanes take from the front, GPU chunks from the back.
const Claim = struct {
    /// lo in the low 32 bits, hi in the high 32 bits.
    v: std.atomic.Value(u64),

    fn init(n: usize) Claim {
        return .{ .v = .init(@as(u64, @intCast(n)) << 32) };
    }
    fn takeFront(c: *Claim, want: usize) ?[2]usize {
        var cur = c.v.load(.acquire);
        while (true) {
            const lo: usize = @intCast(cur & 0xffff_ffff);
            const hi: usize = @intCast(cur >> 32);
            if (lo >= hi) return null;
            const nlo = @min(hi, lo + want);
            cur = c.v.cmpxchgWeak(cur, @as(u64, hi) << 32 | nlo, .acq_rel, .acquire) orelse return .{ lo, nlo };
        }
    }
    fn takeBack(c: *Claim, want: usize) ?[2]usize {
        var cur = c.v.load(.acquire);
        while (true) {
            const lo: usize = @intCast(cur & 0xffff_ffff);
            const hi: usize = @intCast(cur >> 32);
            // the GPU end takes at most half of what is left, and leaves short tails to the CPU
            // lanes, so a slow device never holds the last items alone
            const left = hi - lo;
            if (left < 512) return null;
            const take = @min(want, left / 2);
            const nhi = hi - take;
            cur = c.v.cmpxchgWeak(cur, @as(u64, nhi) << 32 | lo, .acq_rel, .acquire) orelse return .{ nhi, hi };
        }
    }
};

fn envDevices() ?usize {
    const v = std.c.getenv("ZUI_GPU_DEVICES") orelse return null;
    return std.fmt.parseInt(usize, std.mem.span(v), 10) catch null;
}

fn packPoints(w: []u32, points: []const bn.G1) void {
    for (points, 0..) |p, i| {
        const q = w[i * 24 ..][0..24];
        @memcpy(std.mem.sliceAsBytes(q[0..8]), std.mem.asBytes(&p.x.l));
        @memcpy(std.mem.sliceAsBytes(q[8..16]), std.mem.asBytes(&p.y.l));
        q[16] = @intFromBool(p.infinity);
        @memset(q[17..24], 0);
    }
}

fn unpackJ(q: *const [24]u32) bn.G1J {
    var r: bn.G1J = undefined;
    @memcpy(std.mem.asBytes(&r.x.l), std.mem.sliceAsBytes(q[0..8]));
    @memcpy(std.mem.asBytes(&r.y.l), std.mem.sliceAsBytes(q[8..16]));
    @memcpy(std.mem.asBytes(&r.z.l), std.mem.sliceAsBytes(q[16..24]));
    return r;
}

/// Canonical field element as the ed25519 kernel's limbs: ten little-endian fields of 26, 25, 26, ...
/// bits (radix 2^25.5).
fn putLimbs(dst: *[10]u32, f: ed25519.Fe) void {
    const x = std.mem.readInt(u256, &f.toBytes(), .little);
    var off: u9 = 0;
    for (dst, 0..) |*l, i| {
        const bits: u9 = if (i % 2 == 0) 26 else 25;
        l.* = @intCast((x >> @intCast(off)) & ((@as(u256, 1) << @intCast(bits)) - 1));
        off += bits;
    }
}

fn putBytes(dst: []u32, b: *const [32]u8) void {
    for (0..8) |i| dst[i] = std.mem.readInt(u32, b[i * 4 ..][0..4], .little);
}

/// k = SHA-512(R || A || msg) mod l, as the CPU verifier computes it.
fn hashK(r_bytes: *const [32]u8, a_bytes: *const [32]u8, msg: []const u8) [32]u8 {
    var h = hash.Sha512.init();
    h.update(r_bytes);
    h.update(a_bytes);
    h.update(msg);
    var d: [64]u8 = undefined;
    h.final(&d);
    return scalar.reduce64(d);
}

/// Signed radix-2^w digits of x (x < 2^(w*(N-1))), in [-2^(w-1), 2^(w-1) - 1] except the top one.
fn signedDigits(comptime N: usize, comptime w: u4, x: u256, neg: bool) [N]i8 {
    var out: [N]i8 = undefined;
    var v = x;
    var carry: i32 = 0;
    const half: i32 = 1 << (w - 1);
    for (0..N) |i| {
        var d: i32 = @as(i32, @intCast(@as(u32, @truncate(v)) & ((1 << w) - 1))) + carry;
        v >>= w;
        carry = 0;
        if (d >= half and i + 1 < N) {
            d -= 1 << w;
            carry = 1;
        }
        out[i] = @intCast(if (neg) -d else d);
    }
    std.debug.assert(v == 0 and carry == 0);
    return out;
}

/// Host part of one GPU verification (sig.ed25519 checkHalf): s canonical check, k, the half-size
/// pair (c0, c1), t = c1 * s mod l and the window digits of the quad multiplication. The GPU
/// decodes A and R and evaluates [8]([c0]A + [c1]R - [t]B).
/// Layout (words): A (0..8), R (8..16), flags (16: bit 1 s not canonical, so only A is decided),
/// digits from word 17: c0, c1 (33 signed radix-16 each, c0 negated when c0 < 0), t_lo, t_hi (17
/// signed radix-256 each).
pub const n_canaries = 3;

const Canaries = struct {
    pk: [32]u8,
    msg: [2][32]u8,
    sig: [2][64]u8,
    items: [n_canaries]ed25519.BatchItem,
    want: [n_canaries]sig.Verdict,
};

var canaries: Canaries = undefined;
var canary_state: std.atomic.Value(u8) = .init(0);

/// One valid signature and two invalid ones (other message; a flipped bit in s), with the CPU's
/// answers. Built once.
pub fn edCanaries() *const Canaries {
    while (true) switch (canary_state.load(.acquire)) {
        2 => return &canaries,
        0 => if (canary_state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) {
            const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x5a)) catch unreachable;
            const c = &canaries;
            c.pk = kp.public_key.toBytes();
            c.msg[0] = @splat(0x11);
            c.msg[1] = @splat(0x12);
            c.sig[0] = (kp.sign(&c.msg[0], null) catch unreachable).toBytes();
            c.sig[1] = c.sig[0];
            c.sig[1][40] ^= 0x01;
            c.items = .{
                .{ .pk = &c.pk, .msg = &c.msg[0], .sig = &c.sig[0] },
                .{ .pk = &c.pk, .msg = &c.msg[1], .sig = &c.sig[0] },
                .{ .pk = &c.pk, .msg = &c.msg[0], .sig = &c.sig[1] },
            };
            for (&c.want, c.items) |*w, it| w.* = ed25519.verify(it.pk, it.msg, it.sig);
            std.debug.assert(c.want[0] == .valid and c.want[1] != .valid and c.want[2] != .valid);
            canary_state.store(2, .release);
            return c;
        },
        else => std.atomic.spinLoopHint(),
    };
}

pub fn edPrep(it: ed25519.BatchItem, w: *[Accel.ed_words]u32) void {
    putBytes(w[0..8], it.pk);
    putBytes(w[8..16], it.sig[0..32]);
    const s = it.sig[32..64];
    if (!ed25519.isCanonicalScalar(s)) {
        @memset(w[16..], 0);
        w[16] = 2;
        return;
    }
    const k = hashK(it.sig[0..32], it.pk, it.msg);
    const hs = ed25519.halfSize(std.mem.readInt(u256, &k, .little));
    var c1b: [32]u8 = @splat(0);
    std.mem.writeInt(u128, c1b[0..16], hs.c1, .little);
    const t = std.mem.readInt(u256, &scalar.mul(c1b, s.*), .little);
    w[16] = 0;
    const digits: *[(Accel.ed_words - 17) * 4]i8 = @ptrCast(w[17..]);
    @memset(digits, 0);
    digits[0..33].* = signedDigits(33, 4, hs.c0, hs.c0_neg);
    digits[33..66].* = signedDigits(33, 4, hs.c1, false);
    digits[66..83].* = signedDigits(17, 8, @as(u128, @truncate(t)), false);
    digits[83..100].* = signedDigits(17, 8, t >> 128, false);
}

test "signed digits reconstruct the scalar" {
    var prng = std.Random.DefaultPrng.init(3);
    for (0..2000) |_| {
        const x: u256 = prng.random().int(u128) >> prng.random().uintLessThan(u7, 100);
        inline for (.{ .{ 33, 4 }, .{ 17, 8 } }) |nw| {
            const d = signedDigits(nw[0], nw[1], x, false);
            var acc: i512 = 0;
            var i: usize = nw[0];
            while (i > 0) {
                i -= 1;
                acc = (acc << nw[1]) + d[i];
                if (i + 1 < nw[0]) try std.testing.expect(d[i] >= -(1 << (nw[1] - 1)) and d[i] < (1 << (nw[1] - 1)));
            }
            try std.testing.expectEqual(@as(i512, x), acc);
        }
    }
}
