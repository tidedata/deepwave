//! The process's signature engine: one CPU pool, the GPU when there is one that passes its
//! self-check, and the dispatch table between them, set up once at startup from the hw plan
//! (core/hw.zig) and used by every batch verification path (sig.batch, the validator's pre-steps,
//! zkLogin and BLS batches through core.pool.shared()).
//!
//! Policy (`--sig-parallel auto`, the default): on when the plan has more than 2 cores, or when a
//! GPU is open and passes the Ed25519 self-check. `--sig-parallel off` (or the hw plan's
//! `threads=1` with no GPU) leaves every path on its one-thread code; `--gpu off` keeps the GPU
//! closed. A GPU is never used for an op that fails the startup known-answer check
//! (calibrate.checkDevices, run on every start, forced paths and cached tables included), and
//! every GPU Ed25519 batch carries canaries (ops.zig) that switch the GPU path off for good when
//! one comes back wrong. Verdicts never depend on the path: sig.batch only lets a path's
//! acceptances skip work in the single path, and the Accel's per-item answers equal the CPU's.
const std = @import("std");
const core = @import("core");
const sig = @import("sig");
const ops = @import("ops.zig");
const calibrate = @import("calibrate.zig");

const Accel = ops.Accel;
const Path = core.dispatch.Path;
const Op = core.dispatch.Op;
const op_count = core.dispatch.op_count;
const Pool = core.pool.Pool;

pub const Parallel = enum {
    auto,
    on,
    off,

    pub fn parse(s: []const u8) ?Parallel {
        return std.meta.stringToEnum(Parallel, s);
    }
};

pub const Options = struct {
    parallel: Parallel = .auto,
    /// null: ZUI_GPU when set, else auto (open a device if there is one).
    gpu: ?ops.Mode = null,
    /// null: core.hw.detect(null) with ZUI_HW applied.
    plan: ?*const core.hw.Plan = null,
    /// Calibration cache directory; null: the deepwave-hw cache dir.
    cache_dir: ?[]const u8 = null,
    /// Every Ed25519 batch on this path (suites, benches): cpu1, pool or gpuN/mixN. Null: the
    /// hw plan's `dispatch=` if any, else the table.
    force: ?Path = null,
    /// Turn on the verdict-neutral sig.fast layer (decoded-key caches, zkLogin proof cache,
    /// multisig batch) with the engine.
    caches: bool = true,
    log: bool = true,
};

pub const Engine = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    on: bool = false,
    /// Why on or off (log line).
    why: []const u8 = "",
    pool: ?*Pool = null,
    own_pool: bool = false,
    accel: Accel,
    /// calibrate.checkDevices per op (all true without a device).
    gpu_ok: [op_count]bool = @splat(true),
    source: calibrate.Source = .static,
    forced: ?Path = null,
    backend: sig.batch.Backend = undefined,
    saved_fast: sig.fast.Config = .{},

    pub fn init(io: std.Io, gpa: std.mem.Allocator, o: Options) std.mem.Allocator.Error!*Engine {
        const e = try gpa.create(Engine);
        e.* = .{ .gpa = gpa, .io = io, .accel = Accel.init(gpa, .off) };
        var plan_buf: core.hw.Plan = undefined;
        const plan: *const core.hw.Plan = o.plan orelse blk: {
            var spec: core.hw.Spec = .{};
            core.hw.parseEnv(&spec, null) catch {};
            const m = core.hw.detect(null);
            plan_buf = core.hw.plan(&m, &spec);
            break :blk &plan_buf;
        };
        if (o.parallel == .off) {
            e.why = "--sig-parallel off";
            return e;
        }
        const gmode: ops.Mode = if (plan.gpu_mode == .off) .off else o.gpu orelse envMode() orelse .auto;
        // the pool: plan lanes (cgroup quota and affinity already counted), unless one is installed
        e.pool = core.pool.shared();
        if (e.pool == null and plan.pool_threads > 1) {
            if (Pool.init(io, gpa, plan.pool_threads)) |p| {
                e.pool = p;
                e.own_pool = true;
            } else |_| {}
        }
        e.accel = Accel.initOpts(gpa, .{ .mode = gmode, .max_devices = plan.gpu_devices orelse 0 });
        e.accel.pool = e.pool;
        const ndev = e.accel.deviceCount();
        if (ndev > 0) e.gpu_ok = calibrate.checkDevices(gpa, &e.accel);
        const gpu_ed = ndev > 0 and e.gpu_ok[@intFromEnum(Op.ed25519)];
        e.on = switch (o.parallel) {
            .on => true,
            .off => unreachable,
            .auto => plan.cores > 2 or gpu_ed,
        };
        e.why = if (o.parallel == .on) "--sig-parallel on" else if (plan.cores > 2) "auto: more than 2 cores" else if (gpu_ed) "auto: GPU passed its self-check" else "auto: 2 cores or fewer and no GPU";
        if (!e.on) {
            e.release();
            return e;
        }
        // dispatch: forced path (made a table so failed ops still never reach the GPU), else the
        // cached or new calibration, else the static table; the self-check result always applies
        e.forced = o.force orelse plan.dispatch;
        if (e.forced) |f| {
            const fp = if (f.isGpu()) (if (ndev > 0) f.withDevices(@min(@max(f.gpuDevices(), 1), ndev)) else Path.pool) else f;
            e.forced = fp;
            e.accel.table = core.dispatch.Table.all(fp);
        } else if (ndev > 0) switch (plan.calibrate) {
            .off => {},
            .auto, .force => e.source = calibrate.autoTable(io, gpa, &e.accel, o.cache_dir, plan.calibrate == .force, .{}),
        };
        calibrate.dropFailed(&e.accel.table, e.gpu_ok);
        if (ndev > 0 and !gpu_ed) e.accel.ed_gpu_bad.store(true, .monotonic);
        e.backend = .{ .ctx = e, .verify_each = verifyEach, .name = if (ndev > 0) @tagName(e.accel.kind) else "pool" };
        return e;
    }

    fn release(e: *Engine) void {
        e.accel.deinit();
        if (e.own_pool) if (e.pool) |p| p.deinit();
        e.pool = null;
        e.own_pool = false;
    }

    pub fn deinit(e: *Engine) void {
        e.release();
        e.gpa.destroy(e);
    }

    /// sig.batch backend: per-item `ed25519.verify` answers on the path the table (or the forced
    /// path) gives for this batch size.
    fn verifyEach(ctx: *anyopaque, items: []const sig.ed25519.BatchItem, out: []sig.Verdict) void {
        const e: *Engine = @ptrCast(@alignCast(ctx));
        e.accel.ed25519VerifyEach(items, out);
    }

    /// The GPU takes Ed25519 batches at some size (open, passed, not tripped).
    pub fn gpuEd25519(e: *const Engine) bool {
        return e.accel.deviceCount() > 0 and e.gpu_ok[@intFromEnum(Op.ed25519)] and !e.accel.ed_gpu_bad.load(.monotonic);
    }

    pub fn lanes(e: *const Engine) usize {
        return if (e.pool) |p| p.lanes() else 1;
    }

    /// One line for the startup log.
    pub fn describe(e: *const Engine, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (!e.on) return w.print("sig: parallel off ({s}): signatures checked one at a time on the calling thread", .{e.why});
        try w.print("sig: parallel on ({s}), pool {d} lanes", .{ e.why, e.lanes() });
        const ndev = e.accel.deviceCount();
        if (ndev == 0) {
            try w.writeAll(", no GPU");
        } else {
            try w.print(", gpu {s} x{d} ({s})", .{ @tagName(e.accel.kind), ndev, e.accel.name() });
            try w.writeAll(", self-check");
            for (e.gpu_ok, 0..) |ok, i| try w.print(" {s}={s}", .{ @tagName(@as(Op, @enumFromInt(i))), if (ok) "ok" else "FAILED" });
        }
        if (e.forced) |f| {
            try w.print(", forced path {f}", .{f});
        } else {
            try w.print(", table {s}, ed25519", .{@tagName(e.source)});
            const t = &e.accel.table.ops[@intFromEnum(Op.ed25519)];
            for (t.steps[0..t.len]) |st| try w.print(" {d}:{f}", .{ st.min_n, st.path });
        }
    }
};

fn envMode() ?ops.Mode {
    const v = std.c.getenv("ZUI_GPU") orelse return null;
    return ops.Mode.parse(std.mem.span(v));
}

var installed: ?*Engine = null;

/// Builds the engine and makes it the process's: core.pool.shared() (when it made the pool),
/// sig.batch's backend and default path, and (with `caches`) the sig.fast layer. Never fails:
/// without memory the process runs with the engine off. Call once, before worker threads start.
pub fn install(io: std.Io, gpa: std.mem.Allocator, o: Options) ?*Engine {
    if (installed != null) uninstall();
    const e = Engine.init(io, gpa, o) catch return null;
    installed = e;
    e.saved_fast = sig.fast.config();
    if (e.on) {
        if (e.own_pool) _ = core.pool.setShared(e.pool);
        sig.batch.setBackend(&e.backend);
        sig.batch.setDefaultPath(.accel);
        if (o.caches) {
            var c = sig.fast.all_on;
            // the verified-signature cache pays a key hash on every single check; the batch
            // paths carry their own accepted sets, so it stays as configured
            c.ed_verified_cache = e.saved_fast.ed_verified_cache;
            sig.fast.configure(c);
        }
    } else {
        sig.batch.setDefaultPath(.cpu1);
    }
    if (o.log) {
        var buf: [512]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        e.describe(&w) catch {};
        std.log.info("{s}", .{w.buffered()});
    }
    return e;
}

pub fn current() ?*Engine {
    return installed;
}

/// Undoes `install` (tests, tools that run several modes in one process).
pub fn uninstall() void {
    const e = installed orelse return;
    installed = null;
    sig.batch.setBackend(null);
    sig.batch.setDefaultPath(.cpu1);
    sig.fast.configure(e.saved_fast);
    if (e.own_pool and core.pool.shared() == e.pool) _ = core.pool.setShared(null);
    e.deinit();
}

test "engine: off, forced pool and auto on a CPU-only plan; verdicts through sig.batch" {
    const gpa = std.testing.allocator;
    var spec: core.hw.Spec = .{};
    spec.gpu = .off;
    spec.cores = 4;
    var m = core.hw.detect(null);
    m.logical_cores = 4;
    const plan = core.hw.plan(&m, &spec);
    {
        const e = install(std.testing.io, gpa, .{ .parallel = .off, .plan = &plan, .log = false }).?;
        defer uninstall();
        try std.testing.expect(!e.on and e.pool == null);
        try std.testing.expectEqual(sig.batch.Path.cpu1, sig.batch.defaultPath());
    }
    {
        const e = install(std.testing.io, gpa, .{ .parallel = .auto, .plan = &plan, .log = false }).?;
        defer uninstall();
        try std.testing.expect(e.on);
        try std.testing.expectEqual(@as(usize, 4), e.lanes());
        try std.testing.expect(core.pool.shared() == e.pool);
        try std.testing.expect(sig.batch.backend() != null);
        // the backend answers as ed25519.verify does
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(9));
        var msgs: [100][32]u8 = undefined;
        var sigs: [100][64]u8 = undefined;
        const pk = kp.public_key.toBytes();
        var items: [100]sig.ed25519.BatchItem = undefined;
        for (0..100) |i| {
            msgs[i] = @splat(@intCast(i));
            sigs[i] = (try kp.sign(&msgs[i], null)).toBytes();
            if (i % 9 == 0) sigs[i][50] ^= 4;
            items[i] = .{ .pk = &pk, .msg = &msgs[i], .sig = &sigs[i] };
        }
        var out: [100]sig.Verdict = undefined;
        const b = sig.batch.backend().?;
        b.verify_each(b.ctx, &items, &out);
        for (items, out) |it, v| try std.testing.expectEqualDeep(sig.ed25519.verify(it.pk, it.msg, it.sig), v);
    }
    try std.testing.expect(core.pool.shared() == null);
    // 2 cores, no GPU: auto stays off
    var m2 = m;
    m2.logical_cores = 2;
    var spec2 = spec;
    spec2.cores = 2;
    const plan2 = core.hw.plan(&m2, &spec2);
    {
        const e = install(std.testing.io, gpa, .{ .plan = &plan2, .log = false }).?;
        defer uninstall();
        try std.testing.expect(!e.on);
    }
}

test "engine on a GPU (ZUI_GPU=auto|metal|cuda): self-check, forced GPU path, canaries quiet, same answers" {
    const want_mode = @import("mode.zig").fromEnv();
    if (want_mode == .off) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const e = install(std.testing.io, gpa, .{ .gpu = want_mode, .force = Path.gpu(8), .log = false, .caches = false }).?;
    defer uninstall();
    if (e.accel.deviceCount() == 0) return error.SkipZigTest;
    try std.testing.expect(e.on and e.gpuEd25519());
    const n = 5000;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(21));
    const pk = kp.public_key.toBytes();
    const msgs = try gpa.alloc([32]u8, n);
    defer gpa.free(msgs);
    const sigs = try gpa.alloc([64]u8, n);
    defer gpa.free(sigs);
    const items = try gpa.alloc(sig.ed25519.BatchItem, n);
    defer gpa.free(items);
    const out = try gpa.alloc(sig.Verdict, n);
    defer gpa.free(out);
    for (0..n) |i| {
        msgs[i] = @splat(@intCast(i % 256));
        msgs[i][31] = @intCast(i >> 8);
        sigs[i] = (try kp.sign(&msgs[i], null)).toBytes();
        if (i % 13 == 0) sigs[i][7] ^= 0x40;
        if (i % 17 == 0) msgs[i][0] ^= 1;
        items[i] = .{ .pk = &pk, .msg = &msgs[i], .sig = &sigs[i] };
    }
    const b = sig.batch.backend().?;
    b.verify_each(b.ctx, items, out);
    for (items, out) |it, v| try std.testing.expectEqualDeep(sig.ed25519.verify(it.pk, it.msg, it.sig), v);
    try std.testing.expectEqual(@as(u64, 0), e.accel.canary_trips.load(.monotonic));
    try std.testing.expect(ops.Stats.get(&e.accel.stats.gpu_items) >= n);
}
