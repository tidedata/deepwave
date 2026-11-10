//! GPU-vs-CPU equality harness: the same inputs go through the accelerator and through the CPU
//! code (sig.ed25519, zk.poseidon, bn254 G1J) and every output must be identical. Covers each
//! field's primitive operations (the shader arithmetic), Ed25519 batch verdicts (valid signatures,
//! corrupted ones, non-canonical s, undecodable keys, small-order points), Poseidon at every width
//! 1..16, and G1 MSMs (zero scalars, infinity, duplicate and negated points). A silent GPU
//! failure (fallback to the CPU) counts as a mismatch.
const std = @import("std");
const sig = @import("sig");
const zk = @import("zk");
const ops = @import("ops.zig");

const ed25519 = sig.ed25519;
const bn = zk.bn254;
const Fr = bn.Fr;
const Fq = bn.Fq;
const Accel = ops.Accel;

pub const Config = struct {
    seed: u64 = 0x5a55,
    ed_items: usize = 2048,
    poseidon_items: usize = 4096,
    msm_max: usize = 600,
    field_items: usize = 4096,
};

pub const Report = struct {
    checked: u64 = 0,
    mismatches: u64 = 0,
    detail_budget: u32 = 20,

    pub fn miss(r: *Report, comptime fmt: []const u8, args: anytype) void {
        r.mismatches += 1;
        if (r.detail_budget > 0) {
            r.detail_budget -= 1;
            std.debug.print("gpu mismatch: " ++ fmt ++ "\n", args);
        }
    }
};

pub fn run(gpa: std.mem.Allocator, accel: *Accel, cfg: Config, rep: *Report) !void {
    if (!accel.active()) return error.NoDevice;
    var prng = std.Random.DefaultPrng.init(cfg.seed);
    const rnd = prng.random();
    const before = ops.Stats.get(&accel.stats.fallbacks);
    try fields(gpa, accel, rnd, cfg.field_items, rep);
    try ed(gpa, accel, rnd, cfg.ed_items, rep);
    try poseidon(gpa, accel, rnd, cfg.poseidon_items, rep);
    try msm(gpa, accel, rnd, cfg.msm_max, rep);
    try mulEach(gpa, accel, rnd, cfg.msm_max, rep);
    try otherThread(accel, rnd, rep);
    // the mixed path (GPU from the back, CPU pool from the front of the same batch), and each
    // device count, give the same answers
    const saved = accel.forced;
    defer accel.forced = saved;
    const Path = @import("core").dispatch.Path;
    if (accel.poolLanes() > 1) {
        accel.forced = Path.mix(accel.deviceCount());
        try ed(gpa, accel, rnd, @max(cfg.ed_items, 4096), rep);
        try poseidon(gpa, accel, rnd, @max(cfg.poseidon_items, 16 * 2048), rep);
        try mulEach(gpa, accel, rnd, @max(cfg.msm_max, 2048), rep);
    }
    var k: usize = 1;
    while (k < accel.deviceCount()) : (k += 1) {
        accel.forced = Path.gpu(k);
        try ed(gpa, accel, rnd, cfg.ed_items, rep);
        try poseidon(gpa, accel, rnd, cfg.poseidon_items, rep);
        try msm(gpa, accel, rnd, cfg.msm_max, rep);
    }
    const after = ops.Stats.get(&accel.stats.fallbacks);
    if (after != before) rep.miss("{d} GPU launches failed and fell back to the CPU", .{after - before});
}

/// g1MulEach (one term per proof) equals the per-term CPU product.
fn mulEach(gpa: std.mem.Allocator, accel: *Accel, rnd: std.Random, n: usize, rep: *Report) !void {
    const pts = try gpa.alloc(bn.G1, n);
    defer gpa.free(pts);
    const ks = try gpa.alloc([4]u64, n);
    defer gpa.free(ks);
    const got = try gpa.alloc(bn.G1J, n);
    defer gpa.free(got);
    for (0..n) |i| {
        pts[i] = if (i % 13 == 4) bn.G1.identity else randPoint(rnd);
        var kb = randBytes(rnd);
        kb[31] &= 0x1f;
        ks[i] = if (i % 11 == 3) .{ 0, 0, 0, 0 } else Fr.limbsLe(&kb);
    }
    accel.g1MulEach(pts, ks, got);
    for (0..n) |i| {
        rep.checked += 1;
        if (!got[i].toAffine().eql(bn.G1J.mulLimbs(pts[i], &ks[i]).toAffine())) rep.miss("g1 mul each i={d}", .{i});
    }
}

/// The accelerator works from a thread other than the one that opened it (CUDA contexts are per
/// thread): Poseidon batch from a spawned thread, no fallbacks, same outputs as the CPU.
fn otherThread(accel: *Accel, rnd: std.Random, rep: *Report) !void {
    const T = struct {
        fn run(a: *Accel, seed: u64, bad: *bool) void {
            var prng = std.Random.DefaultPrng.init(seed);
            const r = prng.random();
            var ins: [64]Fr = undefined;
            var out: [64]Fr = undefined;
            for (&ins) |*x| {
                var b: [32]u8 = undefined;
                r.bytes(&b);
                x.* = Fr.fromBytesLeModOrder(&b);
            }
            a.poseidonBatch(1, &ins, &out);
            for (ins, out) |i, o| {
                const want = zk.poseidon.hash(&.{i}).?;
                if (!std.meta.eql(want, o)) bad.* = true;
            }
        }
    };
    var bad = false;
    const before = ops.Stats.get(&accel.stats.fallbacks);
    const th = std.Thread.spawn(.{}, T.run, .{ accel, rnd.int(u64), &bad }) catch return;
    th.join();
    rep.checked += 1;
    if (bad) rep.miss("poseidon from a spawned thread differs", .{});
    if (ops.Stats.get(&accel.stats.fallbacks) != before) rep.miss("spawned thread fell back to the CPU", .{});
}

fn randBytes(rnd: std.Random) [32]u8 {
    var b: [32]u8 = undefined;
    rnd.bytes(&b);
    return b;
}

// ------------------------------------------------------------------------------------------------
// field arithmetic

fn fields(gpa: std.mem.Allocator, accel: *Accel, rnd: std.Random, n: usize, rep: *Report) !void {
    const x = try gpa.alloc([32]u8, n * 3);
    defer gpa.free(x);
    const y = try gpa.alloc([32]u8, n * 3);
    defer gpa.free(y);
    const out = try gpa.alloc([32]u8, n * 3);
    defer gpa.free(out);
    const want = try gpa.alloc([32]u8, n * 3);
    defer gpa.free(want);

    inline for (.{ .{ Fr, ops.Accel.FieldOp.fr_mul, ops.Accel.FieldOp.fr_add, ops.Accel.FieldOp.fr_sub }, .{ Fq, ops.Accel.FieldOp.fq_mul, ops.Accel.FieldOp.fq_add, ops.Accel.FieldOp.fq_sub } }) |spec| {
        const F = spec[0];
        const mont = spec[1];
        for (0..n) |i| {
            var a = F.fromBytesLeModOrder(&randBytes(rnd));
            var b = F.fromBytesLeModOrder(&randBytes(rnd));
            if (i == 0) {
                a = F.zero;
                b = F.zero;
            } else if (i == 1) {
                a = F.one.neg();
                b = F.one.neg();
            } else if (i == 2) {
                a = F.one.neg();
                b = F.one;
            }
            for (0..3) |op| {
                x[op * n + i] = std.mem.toBytes(a.l);
                y[op * n + i] = std.mem.toBytes(b.l);
                const r = switch (op) {
                    0 => a.mul(b),
                    1 => a.add(b),
                    else => a.sub(b),
                };
                want[op * n + i] = std.mem.toBytes(r.l);
            }
        }
        try compareField(accel, mont, x[0..n], y[0..n], out[0..n], want[0..n], rep, @typeName(F) ++ " mul");
        try compareField(accel, spec[2], x[n .. 2 * n], y[n .. 2 * n], out[0..n], want[n .. 2 * n], rep, @typeName(F) ++ " add");
        try compareField(accel, spec[3], x[2 * n ..][0..n], y[2 * n ..][0..n], out[0..n], want[2 * n ..][0..n], rep, @typeName(F) ++ " sub");
    }

    // 2^255 - 19: edge values then random
    const Fe = ed25519.Fe;
    for (0..n) |i| {
        var a = Fe.fromBytes(&randBytes(rnd));
        var b = Fe.fromBytes(&randBytes(rnd));
        if (i == 0) {
            a = Fe.zero;
            b = Fe.zero;
        } else if (i == 1) {
            a = Fe.zero.sub(Fe.one);
            b = Fe.zero.sub(Fe.one);
        } else if (i == 2) {
            a = Fe.zero.sub(Fe.one);
            b = Fe.one;
        }
        x[i] = a.toBytes();
        y[i] = b.toBytes();
        want[i] = a.mul(b).toBytes();
        x[n + i] = x[i];
        y[n + i] = y[i];
        want[n + i] = a.add(b).toBytes();
        x[2 * n + i] = x[i];
        y[2 * n + i] = y[i];
        want[2 * n + i] = a.sub(b).toBytes();
    }
    try compareField(accel, .fx_mul, x[0..n], y[0..n], out[0..n], want[0..n], rep, "fe25519 mul");
    try compareField(accel, .fx_add, x[n .. 2 * n], y[n .. 2 * n], out[0..n], want[n .. 2 * n], rep, "fe25519 add");
    try compareField(accel, .fx_sub, x[2 * n ..][0..n], y[2 * n ..][0..n], out[0..n], want[2 * n ..][0..n], rep, "fe25519 sub");
    for (0..n) |i| want[i] = Fe.fromBytes(&x[i]).sq().toBytes();
    try compareField(accel, .fx_sq, x[0..n], y[0..n], out[0..n], want[0..n], rep, "fe25519 sq");
}

fn compareField(accel: *Accel, op: Accel.FieldOp, x: []const [32]u8, y: []const [32]u8, out: [][32]u8, want: []const [32]u8, rep: *Report, what: []const u8) !void {
    accel.fieldOp(op, x, y, out) catch |e| {
        rep.miss("{s}: launch failed: {s}", .{ what, @errorName(e) });
        return;
    };
    for (want, out, 0..) |w, o, i| {
        rep.checked += 1;
        if (!std.mem.eql(u8, &w, &o)) {
            rep.miss("{s} lane {d}", .{ what, i });
            break;
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Ed25519

fn ed(gpa: std.mem.Allocator, accel: *Accel, rnd: std.Random, n: usize, rep: *Report) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const total = n + 4;
    const pks = try arena.alloc([32]u8, total);
    const sigs = try arena.alloc([64]u8, total);
    const msgs = try arena.alloc([]u8, total);
    const items = try arena.alloc(ed25519.BatchItem, total);
    for (0..n) |i| {
        const seed = randBytes(rnd);
        const kp = ed25519.KeyPair.fromSeed(&seed);
        const len = rnd.uintLessThan(usize, 200);
        msgs[i] = try arena.alloc(u8, len);
        rnd.bytes(msgs[i]);
        pks[i] = kp.pk;
        sigs[i] = kp.sign(msgs[i]);
        switch (i % 10) {
            5 => msgs[i] = try arena.dupe(u8, "tampered message"),
            6 => sigs[i][rnd.uintLessThan(usize, 64)] ^= @as(u8, 1) << rnd.int(u3),
            7 => { // non-canonical s: s + l (still below 2^256)
                const s = std.mem.readInt(u256, sigs[i][32..64], .little);
                std.mem.writeInt(u256, sigs[i][32..64], s +% ed25519.l_int, .little);
            },
            8 => pks[i] = randBytes(rnd), // may not decode
            9 => sigs[i][0..32].* = randBytes(rnd), // R random, may not decode
            else => {},
        }
    }
    // small-order key and R with s = 0: accepted by ZIP-215
    var ident: [32]u8 = @splat(0);
    ident[0] = 1;
    for (0..2) |j| {
        const i = n + j;
        msgs[i] = try arena.dupe(u8, "small order");
        pks[i] = ident;
        sigs[i] = @splat(0);
        sigs[i][0] = 1;
    }
    // the order-2 point (0, -1) as key
    {
        const i = n + 2;
        msgs[i] = try arena.dupe(u8, "order two");
        pks[i] = @splat(0);
        pks[i][0] = 0xec;
        pks[i][1] = 0xff;
        for (2..31) |k| pks[i][k] = 0xff;
        pks[i][31] = 0x7f;
        sigs[i] = @splat(0);
        sigs[i][0] = 1;
    }
    {
        const i = n + 3;
        msgs[i] = try arena.alloc(u8, 0);
        pks[i] = @splat(0xff);
        sigs[i] = @splat(0xff);
    }
    for (items, 0..) |*it, i| it.* = .{ .pk = &pks[i], .msg = msgs[i], .sig = &sigs[i] };

    const got = try arena.alloc(sig.Verdict, total);
    accel.ed25519VerifyEach(items, got);
    var valid: usize = 0;
    for (items, got, 0..) |it, g, i| {
        const want = ed25519.verify(it.pk, it.msg, it.sig);
        rep.checked += 1;
        if (want == .valid) valid += 1;
        if (!std.meta.eql(want, g)) rep.miss("ed25519 item {d} (case {d}): cpu {s} gpu {s}", .{ i, i % 10, want.truthName(), g.truthName() });
    }
    if (valid == 0 or valid == total) rep.miss("ed25519 corpus is degenerate ({d} of {d} valid)", .{ valid, total });
    // the batch verdict agrees with the CPU batch verdict
    const want_batch = blk: {
        var scratch: [1 << 16]u8 = undefined;
        break :blk ed25519.verifyBatch(items, &scratch);
    };
    rep.checked += 1;
    if (!std.meta.eql(want_batch, accel.ed25519VerifyBatch(items))) rep.miss("ed25519 batch verdict", .{});
    // an all-valid batch
    var good: std.ArrayList(ed25519.BatchItem) = .empty;
    for (items, got) |it, g| if (g == .valid) try good.append(arena, it);
    rep.checked += 1;
    if (accel.ed25519VerifyBatch(good.items) != .valid) rep.miss("ed25519 all-valid batch rejected", .{});
}

// ------------------------------------------------------------------------------------------------
// Poseidon

fn poseidon(gpa: std.mem.Allocator, accel: *Accel, rnd: std.Random, items: usize, rep: *Report) !void {
    const count = @max(8, items / 16);
    for (1..17) |n| {
        const inputs = try gpa.alloc(Fr, count * n);
        defer gpa.free(inputs);
        const out = try gpa.alloc(Fr, count);
        defer gpa.free(out);
        for (inputs, 0..) |*f, i| f.* = if (i < n) Fr.zero else Fr.fromBytesLeModOrder(&randBytes(rnd));
        accel.poseidonBatch(n, inputs, out);
        for (out, 0..) |o, i| {
            rep.checked += 1;
            const want = zk.poseidon.hash(inputs[i * n ..][0..n]).?;
            if (!want.eql(o)) {
                rep.miss("poseidon n={d} item {d}", .{ n, i });
                break;
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
// BN254 G1 MSM

fn randPoint(rnd: std.Random) bn.G1 {
    var k = randBytes(rnd);
    k[31] &= 0x1f;
    return bn.G1J.mulLimbs(bn.curve.g1_generator, &Fr.limbsLe(&k)).toAffine();
}

fn msm(gpa: std.mem.Allocator, accel: *Accel, rnd: std.Random, max_n: usize, rep: *Report) !void {
    const sizes = [_]usize{ 1, 2, 3, 7, 8, 9, 64, max_n };
    for (sizes) |n| {
        const pts = try gpa.alloc(bn.G1, n);
        defer gpa.free(pts);
        const ks = try gpa.alloc([4]u64, n);
        defer gpa.free(ks);
        for (0..n) |i| {
            pts[i] = randPoint(rnd);
            var kb = randBytes(rnd);
            kb[31] &= 0x1f;
            ks[i] = Fr.limbsLe(&kb);
            switch (i % 11) {
                3 => ks[i] = .{ 0, 0, 0, 0 },
                4 => pts[i] = bn.G1.identity,
                5 => if (i > 0) {
                    pts[i] = pts[i - 1];
                    ks[i] = ks[i - 1];
                },
                6 => if (i > 0) {
                    pts[i] = pts[i - 1].neg();
                    ks[i] = ks[i - 1];
                },
                7 => ks[i] = .{ 1, 0, 0, 0 },
                else => {},
            }
        }
        const got = accel.g1Msm(pts, ks).toAffine();
        const want = Accel.g1MsmCpu(pts, ks).toAffine();
        rep.checked += 1;
        if (!got.eql(want)) rep.miss("g1 msm n={d}", .{n});
    }
}

// ------------------------------------------------------------------------------------------------
// bench

fn now() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn line(what: []const u8, n: usize, cpu_ns: u64, gpu_ns: u64) void {
    const nf: f64 = @floatFromInt(n);
    std.debug.print("{s:<22} n={d:<7} cpu {d:>9.2} us/op  gpu {d:>9.2} us/op  speedup {d:.2}x\n", .{
        what,                                  n,
        @as(f64, @floatFromInt(cpu_ns)) / nf / 1e3, @as(f64, @floatFromInt(gpu_ns)) / nf / 1e3,
        @as(f64, @floatFromInt(cpu_ns)) / @as(f64, @floatFromInt(@max(gpu_ns, 1))),
    });
}

/// CPU path against GPU path on the same batch (the GPU numbers include host-side decode and hash).
pub fn bench(gpa: std.mem.Allocator, accel: *Accel, n: usize) !void {
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    std.debug.print("gpu bench on {s}\n", .{accel.name()});

    const pks = try arena.alloc([32]u8, n);
    const sigs = try arena.alloc([64]u8, n);
    const msgs = try arena.alloc([]u8, n);
    const items = try arena.alloc(ed25519.BatchItem, n);
    const verdicts = try arena.alloc(sig.Verdict, n);
    for (0..n) |i| {
        const kp = ed25519.KeyPair.fromSeed(&randBytes(rnd));
        msgs[i] = try arena.alloc(u8, 100);
        rnd.bytes(msgs[i]);
        pks[i] = kp.pk;
        sigs[i] = kp.sign(msgs[i]);
        items[i] = .{ .pk = &pks[i], .msg = msgs[i], .sig = &sigs[i] };
    }
    var t0 = now();
    for (items, verdicts) |it, *v| v.* = ed25519.verify(it.pk, it.msg, it.sig);
    const cpu_ed = now() - t0;
    accel.forceGpu();
    t0 = now();
    accel.ed25519VerifyEach(items, verdicts);
    line("ed25519 verify", n, cpu_ed, now() - t0);
    for (0..3) |_| {
        accel.stats.ed_prep_ns.store(0, .monotonic);
        accel.stats.ed_gpu_ns.store(0, .monotonic);
        t0 = now();
        accel.ed25519VerifyEach(items, verdicts);
        const tot = now() - t0;
        std.debug.print("  ed25519 n={d}: total {d:.3} us/op, host prep {d:.3} us/op (caller time), gpu submit-to-collect {d:.3} us/op summed over slots\n", .{ n, @as(f64, @floatFromInt(tot)) / @as(f64, @floatFromInt(n)) / 1e3, @as(f64, @floatFromInt(accel.stats.ed_prep_ns.load(.monotonic))) / @as(f64, @floatFromInt(n)) / 1e3, @as(f64, @floatFromInt(accel.stats.ed_gpu_ns.load(.monotonic))) / @as(f64, @floatFromInt(n)) / 1e3 });
    }

    const pn = n * 4;
    const pin = try arena.alloc(Fr, pn * 3);
    const pout = try arena.alloc(Fr, pn);
    for (pin) |*f| f.* = Fr.fromBytesLeModOrder(&randBytes(rnd));
    t0 = now();
    for (pout, 0..) |*o, i| o.* = zk.poseidon.hash(pin[i * 3 ..][0..3]).?;
    const cpu_p = now() - t0;
    t0 = now();
    accel.poseidonBatch(3, pin, pout);
    line("poseidon (3 inputs)", pn, cpu_p, now() - t0);

    const mn = @min(n, 4096);
    const pts = try arena.alloc(bn.G1, mn);
    const ks = try arena.alloc([4]u64, mn);
    for (0..mn) |i| {
        pts[i] = randPoint(rnd);
        var kb = randBytes(rnd);
        kb[31] &= 0x1f;
        ks[i] = Fr.limbsLe(&kb);
    }
    t0 = now();
    _ = Accel.g1MsmCpu(pts, ks);
    const cpu_m = now() - t0;
    t0 = now();
    _ = accel.g1Msm(pts, ks);
    line("g1 msm", mn, cpu_m, now() - t0);
}

// ------------------------------------------------------------------------------------------------
// sweep: every path (one CPU thread, the CPU pool, the GPU on 1..N devices) and the auto choice
// (the installed dispatch table) at the calibration ladder; prints us/op per path and auto/best.

/// CPU pool lanes for the tool: ZUI_SWEEP_THREADS, else every core.
pub fn sweepThreads() usize {
    if (std.c.getenv("ZUI_SWEEP_THREADS")) |v| {
        if (std.fmt.parseInt(usize, std.mem.span(v), 10)) |n| return @max(1, @min(n, 128)) else |_| {}
    }
    return std.Thread.getCpuCount() catch 1;
}

pub const SweepSummary = struct { worst_auto_ratio: f64 = 1.0, rows: usize = 0, over_10pct: usize = 0 };

pub fn sweep(gpa: std.mem.Allocator, accel: *Accel, max_size: usize) !SweepSummary {
    const cal = @import("calibrate.zig");
    const core = @import("core");
    const Path = core.dispatch.Path;
    var paths: [cal.max_paths]Path = undefined;
    var np: usize = 0;
    paths[np] = .cpu1;
    np += 1;
    if (accel.poolLanes() > 1) {
        paths[np] = .pool;
        np += 1;
    }
    for (1..accel.deviceCount() + 1) |k| {
        paths[np] = Path.gpu(k);
        np += 1;
    }
    if (accel.poolLanes() > 1) for (1..accel.deviceCount() + 1) |k| {
        paths[np] = Path.mix(k);
        np += 1;
    };
    var sum: SweepSummary = .{};
    std.debug.print("sweep on {s} x{d}: pool {d} lanes, us/op best of reps (gpu includes host prep); auto = dispatch table ({s})\n", .{ accel.name(), accel.deviceCount(), accel.poolLanes(), if (accel.table.calibrated) "calibrated" else "static" });
    const saved = accel.forced;
    defer accel.forced = saved;
    var nsz: usize = 0;
    while (nsz < cal.sizes.len and cal.sizes[nsz] <= max_size) nsz += 1;
    var in = try SweepInputs.init(gpa, cal.sizes[nsz - 1]);
    defer in.deinit();
    for (0..core.dispatch.op_count) |oi| {
        const op: core.dispatch.Op = @enumFromInt(oi);
        std.debug.print("{s:<9} {s:>6}", .{ @tagName(op), "n" });
        for (paths[0..np]) |p| std.debug.print(" {f:>9}", .{p});
        std.debug.print(" {s:>9} {s:>6} {s:>9}\n", .{ "auto", "pick", "auto/best" });
        var skip: [cal.max_paths]bool = @splat(false);
        for (cal.sizes[0..nsz]) |n| {
            std.debug.print("{s:<9} {d:>6}", .{ "", n });
            var best: f64 = std.math.inf(f64);
            for (paths[0..np], 0..) |p, pi| {
                if (skip[pi] or (p.isMix() and (op == .msm or n < 1000))) {
                    std.debug.print(" {s:>9}", .{"-"});
                    continue;
                }
                accel.forced = p;
                const us = in.usPerOp(accel, op, n);
                best = @min(best, us);
                std.debug.print(" {d:>9.3}", .{us});
                if (!p.isGpu() and n >= 256 and us > 6 * best) skip[pi] = true;
            }
            accel.forced = null;
            const pick = accel.pathFor(op, n);
            const au = in.usPerOp(accel, op, n);
            const ratio = au / best;
            sum.rows += 1;
            sum.worst_auto_ratio = @max(sum.worst_auto_ratio, ratio);
            if (ratio > 1.10) sum.over_10pct += 1;
            std.debug.print(" {d:>9.3} {f:>6} {d:>9.2}\n", .{ au, pick, ratio });
        }
    }
    std.debug.print("sweep summary: rows {d}, auto within 10% of best on {d}, worst auto/best {d:.2}\n", .{ sum.rows, sum.rows - sum.over_10pct, sum.worst_auto_ratio });
    return sum;
}

const SweepInputs = struct {
    arena: std.heap.ArenaAllocator,
    items: []ed25519.BatchItem,
    verdicts: []sig.Verdict,
    pin: []Fr,
    pout: []Fr,
    pts: []bn.G1,
    ks: [][4]u64,
    jout: []bn.G1J,

    fn init(gpa: std.mem.Allocator, max: usize) !SweepInputs {
        var self: SweepInputs = undefined;
        self.arena = .init(gpa);
        errdefer self.arena.deinit();
        const a = self.arena.allocator();
        var prng = std.Random.DefaultPrng.init(11);
        const rnd = prng.random();
        const distinct = @min(max, 4096);
        const pks = try a.alloc([32]u8, distinct);
        const sigs = try a.alloc([64]u8, distinct);
        const msgs = try a.alloc([100]u8, distinct);
        for (0..distinct) |i| {
            const kp = ed25519.KeyPair.fromSeed(&randBytes(rnd));
            rnd.bytes(&msgs[i]);
            pks[i] = kp.pk;
            sigs[i] = kp.sign(&msgs[i]);
        }
        self.items = try a.alloc(ed25519.BatchItem, max);
        for (self.items, 0..) |*it, i| it.* = .{ .pk = &pks[i % distinct], .msg = &msgs[i % distinct], .sig = &sigs[i % distinct] };
        self.verdicts = try a.alloc(sig.Verdict, max);
        self.pin = try a.alloc(Fr, max * 3);
        for (self.pin) |*f| f.* = Fr.fromBytesLeModOrder(&randBytes(rnd));
        self.pout = try a.alloc(Fr, max);
        self.pts = try a.alloc(bn.G1, max);
        self.ks = try a.alloc([4]u64, max);
        self.jout = try a.alloc(bn.G1J, max);
        var base: [64]bn.G1 = undefined;
        for (&base) |*p| p.* = randPoint(rnd);
        for (0..max) |i| {
            self.pts[i] = base[i % 64];
            var kb = randBytes(rnd);
            kb[31] &= 0x1f;
            self.ks[i] = Fr.limbsLe(&kb);
        }
        return self;
    }

    fn deinit(s: *SweepInputs) void {
        s.arena.deinit();
    }

    fn run(in: *SweepInputs, a: *Accel, op: @import("core").dispatch.Op, n: usize) void {
        switch (op) {
            .ed25519 => a.ed25519VerifyEach(in.items[0..n], in.verdicts[0..n]),
            .poseidon => a.poseidonBatch(3, in.pin[0 .. n * 3], in.pout[0..n]),
            .msm => std.mem.doNotOptimizeAway(a.g1Msm(in.pts[0..n], in.ks[0..n])),
            .mul_each => a.g1MulEach(in.pts[0..n], in.ks[0..n], in.jout[0..n]),
        }
    }

    /// Best of reps (warm-up first), us per item.
    fn usPerOp(in: *SweepInputs, a: *Accel, op: @import("core").dispatch.Op, n: usize) f64 {
        in.run(a, op, n);
        const reps: usize = if (n <= 64) 50 else if (n <= 1000) 10 else if (n <= 4096) 5 else 3;
        var best: u64 = std.math.maxInt(u64);
        for (0..reps) |_| {
            const t0 = now();
            in.run(a, op, n);
            best = @min(best, now() - t0);
        }
        return @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)) / 1e3;
    }
};
