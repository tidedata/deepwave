//! First-start calibration of the dispatch table (core.dispatch): for each batch operation and
//! a ladder of batch sizes, time every path this machine has (one CPU thread, the CPU pool, the
//! GPU on 1..N devices) and keep the fastest per size. Capped at a few seconds; the result is
//! cached per hardware fingerprint (CPU, pool lanes, GPU kind, device names and PCI ids, kernel
//! source, build mode) under the data dir or the deepwave-hw cache, so later starts load it.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("core");
const sig = @import("sig");
const zk = @import("zk");
const ops = @import("ops.zig");
const kernels = @import("kernels.zig");

const ed25519 = sig.ed25519;
const bn = zk.bn254;
const Fr = bn.Fr;
const Accel = ops.Accel;
const Op = core.dispatch.Op;
const Path = core.dispatch.Path;
const Table = core.dispatch.Table;
const OpTable = core.dispatch.OpTable;
const op_count = core.dispatch.op_count;

/// The sweep ladder (gpu-check --sweep uses the same sizes), plus 64k when there are 2+ GPUs.
pub const sizes = [_]usize{ 1, 16, 64, 128, 256, 512, 1000, 2048, 4096, 16384, 65536 };
pub const max_paths = 2 + 2 * ops.max_devices;

pub const Options = struct {
    /// Total wall-clock budget; sizes past it reuse the last winner.
    budget_ms: u64 = 6000,
    /// Largest size measured (65536 only matters with several GPUs).
    max_size: usize = 0,
    log: bool = false,
};

pub const Result = struct {
    table: Table,
    /// us per item, NaN where not measured.
    us: [op_count][sizes.len][max_paths]f64,
    paths: [max_paths]Path,
    npaths: usize,
    nsizes: usize,
    elapsed_ms: u64,

    pub fn write(r: *const Result, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (0..op_count) |o| {
            try w.print("{s:<9} {s:>6}", .{ @tagName(@as(Op, @enumFromInt(o))), "n" });
            for (r.paths[0..r.npaths]) |p| try w.print(" {f:>9}", .{p});
            try w.writeAll("   pick (us/op)\n");
            for (0..r.nsizes) |si| {
                try w.print("{s:<9} {d:>6}", .{ "", sizes[si] });
                for (0..r.npaths) |pi| {
                    const v = r.us[o][si][pi];
                    if (std.math.isNan(v)) try w.print(" {s:>9}", .{"-"}) else try w.print(" {d:>9.3}", .{v});
                }
                try w.print("   {f}\n", .{r.table.pick(@enumFromInt(o), sizes[si])});
            }
        }
    }
};

const n_keys = 512;

const Inputs = struct {
    arena: std.heap.ArenaAllocator,
    items: []ed25519.BatchItem,
    verdicts: []sig.Verdict,
    pin: []Fr,
    pout: []Fr,
    pts: []bn.G1,
    ks: [][4]u64,
    jout: []bn.G1J,

    fn init(gpa: std.mem.Allocator, max: usize) !Inputs {
        var self: Inputs = undefined;
        self.arena = .init(gpa);
        errdefer self.arena.deinit();
        const a = self.arena.allocator();
        var prng = std.Random.DefaultPrng.init(0xca11b);
        const rnd = prng.random();
        // a few hundred distinct signatures, cycled (the paths cache nothing per key)
        const pks = try a.alloc([32]u8, n_keys);
        const sigs = try a.alloc([64]u8, n_keys);
        const msgs = try a.alloc([32]u8, n_keys);
        for (0..n_keys) |i| {
            var seed: [32]u8 = undefined;
            rnd.bytes(&seed);
            const kp = ed25519.KeyPair.fromSeed(&seed);
            rnd.bytes(&msgs[i]); // Sui signs a 32-byte intent digest
            pks[i] = kp.pk;
            sigs[i] = kp.sign(&msgs[i]);
        }
        self.items = try a.alloc(ed25519.BatchItem, max);
        for (self.items, 0..) |*it, i| it.* = .{ .pk = &pks[i % n_keys], .msg = &msgs[i % n_keys], .sig = &sigs[i % n_keys] };
        self.verdicts = try a.alloc(sig.Verdict, max);
        self.pin = try a.alloc(Fr, max * 3);
        for (self.pin) |*f| {
            var b: [32]u8 = undefined;
            rnd.bytes(&b);
            f.* = Fr.fromBytesLeModOrder(&b);
        }
        self.pout = try a.alloc(Fr, max);
        self.pts = try a.alloc(bn.G1, max);
        self.ks = try a.alloc([4]u64, max);
        self.jout = try a.alloc(bn.G1J, max);
        var base: [64]bn.G1 = undefined;
        for (&base) |*p| {
            var kb: [32]u8 = undefined;
            rnd.bytes(&kb);
            kb[31] &= 0x1f;
            p.* = bn.G1J.mulLimbs(bn.curve.g1_generator, &Fr.limbsLe(&kb)).toAffine();
        }
        for (0..max) |i| {
            self.pts[i] = base[i % 64];
            var kb: [32]u8 = undefined;
            rnd.bytes(&kb);
            kb[31] &= 0x1f;
            self.ks[i] = Fr.limbsLe(&kb);
        }
        return self;
    }

    fn run(in: *Inputs, a: *Accel, op: Op, n: usize) void {
        switch (op) {
            .ed25519 => a.ed25519VerifyEach(in.items[0..n], in.verdicts[0..n]),
            .poseidon => a.poseidonBatch(3, in.pin[0 .. n * 3], in.pout[0..n]),
            .msm => std.mem.doNotOptimizeAway(a.g1Msm(in.pts[0..n], in.ks[0..n])),
            .mul_each => a.g1MulEach(in.pts[0..n], in.ks[0..n], in.jout[0..n]),
        }
    }
};

/// Best-of time in ns for one batch, after one warm-up: at least 2 timed runs, more while under
/// `target_ns` in total (at most 50).
fn timeBatch(in: *Inputs, a: *Accel, op: Op, n: usize, target_ns: u64) u64 {
    in.run(a, op, n);
    var best: u64 = std.math.maxInt(u64);
    var spent: u64 = 0;
    var reps: usize = 0;
    while (reps < 2 or (spent < target_ns and reps < 50)) : (reps += 1) {
        const t0 = ops.nowNs();
        in.run(a, op, n);
        const dt = ops.nowNs() - t0;
        best = @min(best, dt);
        spent += dt;
    }
    return best;
}

/// Known-answer check of every op on the GPU paths (all devices, so every device gets chunks)
/// against the CPU pool: a device or driver that computes a wrong answer (a shader compiler bug,
/// a broken driver) is never used for that op, whatever the timings or a cached table say.
/// Ed25519 items include invalid signatures (a third verify a different message).
pub fn checkDevices(gpa: std.mem.Allocator, a: *Accel) [op_count]bool {
    var ok: [op_count]bool = @splat(true);
    if (a.deviceCount() == 0) return ok;
    const n = 4096;
    var in = Inputs.init(gpa, n) catch return @splat(false);
    defer in.arena.deinit();
    const ar = in.arena.allocator();
    const saved = a.forced;
    defer a.forced = saved;
    const gpu_path = Path.gpu(a.deviceCount());
    const fails0 = ops.Stats.get(&a.stats.fallbacks);
    // ed25519: valid and invalid mixed
    {
        const items = ar.dupe(ed25519.BatchItem, in.items[0..n]) catch return @splat(false);
        for (items, 0..) |*it, i| if (i % 3 == 0) {
            it.msg = in.items[(i + 1) % n_keys].msg;
        };
        const want = ar.alloc(sig.Verdict, n) catch return @splat(false);
        const got = ar.alloc(sig.Verdict, n) catch return @splat(false);
        a.forced = .pool;
        a.ed25519VerifyEach(items, want);
        a.forced = gpu_path;
        a.ed25519VerifyEach(items, got);
        for (want, got) |x, y| if (!std.meta.eql(x, y)) {
            ok[@intFromEnum(Op.ed25519)] = false;
            break;
        };
    }
    {
        const want = ar.alloc(Fr, n) catch return @splat(false);
        a.forced = .pool;
        a.poseidonBatch(3, in.pin[0 .. n * 3], want);
        a.forced = gpu_path;
        a.poseidonBatch(3, in.pin[0 .. n * 3], in.pout[0..n]);
        for (want, in.pout[0..n]) |x, y| if (!x.eql(y)) {
            ok[@intFromEnum(Op.poseidon)] = false;
            break;
        };
    }
    {
        const want = ar.alloc(bn.G1J, n) catch return @splat(false);
        a.forced = .pool;
        a.g1MulEach(in.pts[0..n], in.ks[0..n], want);
        a.forced = gpu_path;
        a.g1MulEach(in.pts[0..n], in.ks[0..n], in.jout[0..n]);
        for (want, in.jout[0..n]) |x, y| if (!x.toAffine().eql(y.toAffine())) {
            ok[@intFromEnum(Op.mul_each)] = false;
            break;
        };
        a.forced = gpu_path;
        const got = a.g1Msm(in.pts[0..n], in.ks[0..n]).toAffine();
        ok[@intFromEnum(Op.msm)] = got.eql(Accel.g1MsmCpu(in.pts[0..n], in.ks[0..n]).toAffine());
    }
    // a path that fell back to the CPU proved nothing about the device
    if (ops.Stats.get(&a.stats.fallbacks) != fails0) {
        a.backoff_until.store(0, .monotonic);
        a.fail_streak.store(0, .monotonic);
        return @splat(false);
    }
    return ok;
}

/// Replaces every GPU step of an op that failed `checkDevices` with the pool.
pub fn dropFailed(t: *Table, ok: [op_count]bool) void {
    for (&t.ops, ok) |*o, good| {
        if (good) continue;
        var nt: OpTable = .{};
        for (o.steps[0..o.len]) |st| nt.push(st.min_n, if (st.path.isGpu()) .pool else st.path);
        o.* = nt;
    }
}

/// Measures every path at every size (within the budget) and returns the table of winners.
/// Uses `a`'s pool and devices; restores `a.forced` and the backoff state afterwards.
pub fn calibrate(gpa: std.mem.Allocator, a: *Accel, o: Options) !Result {
    const t_start = ops.nowNs();
    const max_size: usize = if (o.max_size != 0) o.max_size else if (a.deviceCount() >= 2) 65536 else 16384;
    var nsizes: usize = 0;
    while (nsizes < sizes.len and sizes[nsizes] <= max_size) nsizes += 1;
    var in = try Inputs.init(gpa, sizes[nsizes - 1]);
    defer in.arena.deinit();

    var r: Result = .{ .table = undefined, .us = undefined, .paths = undefined, .npaths = 0, .nsizes = nsizes, .elapsed_ms = 0 };
    for (&r.us) |*x| for (x) |*y| for (y) |*z| {
        z.* = std.math.nan(f64);
    };
    r.paths[0] = .cpu1;
    r.npaths = 1;
    if (a.poolLanes() > 1) {
        r.paths[r.npaths] = .pool;
        r.npaths += 1;
    }
    for (1..a.deviceCount() + 1) |k| {
        r.paths[r.npaths] = Path.gpu(k);
        r.npaths += 1;
    }
    if (a.poolLanes() > 1) for (1..a.deviceCount() + 1) |k| {
        r.paths[r.npaths] = Path.mix(k);
        r.npaths += 1;
    };
    const dev_ok = checkDevices(gpa, a);
    const saved_forced = a.forced;
    defer a.forced = saved_forced;
    const budget_ns = o.budget_ms * std.time.ns_per_ms;
    const per_op_ns = budget_ns / op_count;

    var table: Table = .{ .ops = undefined, .calibrated = true };
    for (0..op_count) |oi| {
        const op: Op = @enumFromInt(oi);
        const op_start = ops.nowNs();
        var t: OpTable = .{};
        var skip: [max_paths]bool = @splat(false);
        for (0..nsizes) |si| {
            const n = sizes[si];
            if (ops.nowNs() - op_start > per_op_ns) {
                // out of budget: larger sizes keep the last winner (a bigger batch never favours a
                // path with more per-batch overhead less)
                break;
            }
            var best: f64 = std.math.inf(f64);
            var best_p: Path = .cpu1;
            for (r.paths[0..r.npaths], 0..) |p, pi| {
                if (skip[pi]) continue;
                // a mixed batch splits only from 1k items (smaller ones go to one side anyway)
                if (p.isMix() and (op == .msm or n < 1000)) continue;
                if (p.isGpu() and !dev_ok[oi]) continue;
                a.forced = p;
                const fails = ops.Stats.get(&a.stats.fallbacks);
                const ns = timeBatch(&in, a, op, n, 20 * std.time.ns_per_ms);
                if (ops.Stats.get(&a.stats.fallbacks) != fails) {
                    // a GPU path that fails is never chosen
                    skip[pi] = true;
                    continue;
                }
                const us = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(n)) / 1e3;
                r.us[oi][si][pi] = us;
                // ties within 3% go to the cheaper path (earlier in the list)
                if (us < best * 0.97) {
                    best = us;
                    best_p = p;
                }
            }
            // stop timing a CPU path that is already 4x off the best (it only gets worse)
            for (r.paths[0..r.npaths], 0..) |p, pi| {
                if (p.isGpu()) continue;
                const v = r.us[oi][si][pi];
                if (!std.math.isNan(v) and v > 4 * best and n >= 256) skip[pi] = true;
            }
            t.push(@intCast(n), best_p);
            if (o.log) std.debug.print("calibrate {s} n={d} best {f} {d:.3} us/op\n", .{ @tagName(op), n, best_p, best });
        }
        if (t.len == 0) t.push(0, .cpu1);
        table.ops[oi] = t;
    }
    // the backoff a failing path caused during calibration does not outlive it
    a.backoff_until.store(0, .monotonic);
    a.fail_streak.store(0, .monotonic);
    r.table = table;
    r.elapsed_ms = (ops.nowNs() - t_start) / std.time.ns_per_ms;
    return r;
}

/// The hardware fingerprint the cache is keyed by.
pub fn fingerprint(buf: []u8, a: *const Accel) []const u8 {
    const m = core.hw.detect(null);
    var w: std.Io.Writer = .fixed(buf);
    const src_hash = std.hash.Wyhash.hash(0, kernels.cuda_source) ^ std.hash.Wyhash.hash(1, kernels.metal_source);
    // v2: the CPU Ed25519 path checks batch-equation chunks (sig.batch), so old timings are stale
    w.print("v2 cpu={s} cores={d} lanes={d} mode={s} gpu={s}:{d}", .{
        if (m.brand_len > 0) m.brandName() else @tagName(m.arch),
        m.logical_cores,
        a.poolLanes(),
        @tagName(builtin.mode),
        @tagName(a.kind),
        a.deviceCount(),
    }) catch return w.buffered();
    for (0..a.deviceCount()) |i| w.print(",{s}@{s}", .{ a.deviceName(i), a.devicePci(i) }) catch return w.buffered();
    w.print(" src={x}", .{src_hash}) catch {};
    // one line, no spaces in names that would break the cache file's first line
    const out = w.buffered();
    for (out) |*c| if (c.* == '\n') {
        c.* = ' ';
    };
    return out;
}

pub const Source = enum { cache, calibrated, static };

/// The table for this machine: from `dir` (or the default hw cache dir) when the fingerprint
/// matches, else calibrated now and written there. Installs it on `a` and says where it came from.
pub fn autoTable(io: std.Io, gpa: std.mem.Allocator, a: *Accel, dir: ?[]const u8, force: bool, o: Options) Source {
    var fp_buf: [512]u8 = undefined;
    const fp = fingerprint(&fp_buf, a);
    var dir_buf: [512]u8 = undefined;
    const d = dir orelse core.dispatch.defaultCacheDir(&dir_buf);
    if (!force) if (d) |dd| if (core.dispatch.loadCache(io, gpa, dd, fp)) |t| {
        a.table = t;
        // the cached timings say nothing about this start's driver: check the answers again
        dropFailed(&a.table, checkDevices(gpa, a));
        return .cache;
    };
    const r = calibrate(gpa, a, o) catch return .static;
    a.table = r.table;
    if (d) |dd| core.dispatch.saveCache(io, gpa, dd, fp, &r.table) catch {};
    return .calibrated;
}

/// Everything a process needs for batch dispatch, from a hw Plan: the CPU pool (installed as
/// core.pool.shared when none is), the Accel on every usable GPU (none when the plan says gpu
/// off), and the dispatch table (forced path, cached calibration, a new calibration, or the static
/// table, as the plan's `calibrate` says).
pub const Setup = struct {
    accel: Accel,
    pool: ?*core.pool.Pool,
    installed_pool: bool,
    source: Source,

    pub fn deinit(s: *Setup) void {
        s.accel.deinit();
        if (s.installed_pool) {
            _ = core.pool.setShared(null);
            if (s.pool) |p| p.deinit();
        }
    }
};

pub fn fromPlan(io: std.Io, gpa: std.mem.Allocator, plan: *const core.hw.Plan, cache_dir: ?[]const u8, log: bool) Setup {
    var s: Setup = .{ .accel = undefined, .pool = core.pool.shared(), .installed_pool = false, .source = .static };
    if (s.pool == null and plan.pool_threads > 1) {
        if (core.pool.Pool.init(io, gpa, plan.pool_threads)) |p| {
            s.pool = p;
            s.installed_pool = true;
            _ = core.pool.setShared(p);
        } else |_| {}
    }
    const mode: ops.Mode = if (plan.gpu_mode == .off) .off else .auto;
    s.accel = Accel.initOpts(gpa, .{ .mode = mode, .max_devices = if (plan.gpu_devices) |n| n else 0 });
    if (plan.dispatch) |d| {
        s.accel.forced = if (d.isGpu() and s.accel.deviceCount() > 0) d.withDevices(@min(d.gpuDevices(), s.accel.deviceCount())) else d;
        return s;
    }
    switch (plan.calibrate) {
        .off => {},
        .auto, .force => s.source = autoTable(io, gpa, &s.accel, cache_dir, plan.calibrate == .force, .{ .log = log }),
    }
    return s;
}

test "dropFailed moves only the failed ops off the GPU" {
    var t = Table.static(2);
    var ok: [op_count]bool = @splat(true);
    ok[@intFromEnum(Op.poseidon)] = false;
    dropFailed(&t, ok);
    try std.testing.expectEqual(Path.pool, t.pick(.poseidon, 1 << 20));
    try std.testing.expectEqual(Path.gpu(2), t.pick(.msm, 1 << 20));
}
