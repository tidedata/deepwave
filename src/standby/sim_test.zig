//! Deterministic simulation of the lease protocol (small): 3 acceptors, 2
//! agents, every message delayed or dropped, links that partition and heal, acceptor restarts
//! (state reloaded from the persisted term and holder only), agent crashes, health flaps, and
//! clock RATES off by up to 1% per node. Every 1 ms of simulated time it asserts the safety
//! property: at most one agent believes it leads, and fencing terms of successive leaders only
//! grow. A failing seed replays exactly: the whole run is a function of the seed.
const std = @import("std");
const lease = @import("lease.zig");
const ms = std.time.ns_per_ms;

const n_acc = 3;
const n_agents = 2;

const Packet = struct { due: u64, to_acceptor: bool, to: u8, from: u8, msg: lease.Msg };

const Clock = struct {
    rate_ppm: i64, // 1_000_000 +- 10_000
    offset: u64,
    fn now(c: Clock, true_ns: u64) u64 {
        return c.offset + @as(u64, @intCast(@divTrunc(@as(i128, true_ns) * c.rate_ppm, 1_000_000)));
    }
};

const World = struct {
    gpa: std.mem.Allocator,
    rng: std.Random.DefaultPrng,
    t_ms: u64 = 0,
    net: std.ArrayList(Packet) = .empty,
    acc: [n_acc]lease.Acceptor = undefined,
    acc_persisted: [n_acc]lease.State = @splat(.{}),
    acc_clock: [n_acc]Clock = undefined,
    agent: [n_agents]lease.Agent = undefined,
    agent_clock: [n_agents]Clock = undefined,
    params: lease.Params,
    blocked: [n_agents][n_acc]bool = @splat(@splat(false)),
    max_led_term: u64 = 0,
    led_ms: u64 = 0,
    avail_ms: u64 = 0,
    acquisitions: u64 = 0,
    drop_pct: u8,
    /// Chaos events happen about once per `calm` times the base period (1: harsh).
    calm: u32 = 1,

    fn init(gpa: std.mem.Allocator, seed: u64, params: lease.Params, drop_pct: u8) !World {
        var w: World = .{ .gpa = gpa, .rng = std.Random.DefaultPrng.init(seed), .params = params, .drop_pct = drop_pct };
        const r = w.rng.random();
        for (0..n_acc) |i| {
            w.acc_clock[i] = .{ .rate_ppm = 1_000_000 + r.intRangeAtMost(i64, -10_000, 10_000), .offset = r.uintLessThan(u64, 1 << 40) };
            w.acc[i] = lease.Acceptor.init(.{ .id = i + 100 }, .{}, w.acc_clock[i].now(0));
            w.acc[i].until_ns = w.acc_clock[i].now(0); // fresh cluster: nothing outstanding
        }
        for (0..n_agents) |i| {
            w.agent_clock[i] = .{ .rate_ppm = 1_000_000 + r.intRangeAtMost(i64, -10_000, 10_000), .offset = r.uintLessThan(u64, 1 << 40) };
            var p = params;
            if (i == 1) p.priority_delay_ms = 2500;
            w.agent[i] = try lease.Agent.init(p, i + 1, n_acc, seed ^ (i + 1));
        }
        return w;
    }

    fn send(w: *World, to_acceptor: bool, to: u8, from: u8, msg: lease.Msg) !void {
        const r = w.rng.random();
        const blocked = if (to_acceptor) w.blocked[from][to] else w.blocked[to][from];
        if (blocked or r.uintLessThan(u8, 100) < w.drop_pct) return;
        const delay = r.uintLessThan(u64, 120) + if (r.uintLessThan(u8, 20) == 0) r.uintLessThan(u64, 900) else 0;
        try w.net.append(w.gpa, .{ .due = w.t_ms + delay, .to_acceptor = to_acceptor, .to = to, .from = from, .msg = msg });
    }

    fn step(w: *World) !void {
        const r = w.rng.random();
        const true_ns = w.t_ms * ms;
        const wall_ms = 1_700_000_000_000 + w.t_ms;
        // chaos
        if (r.uintLessThan(u32, 2500 * w.calm) == 0) { // flip a link
            const a = r.uintLessThan(usize, n_agents);
            const c = r.uintLessThan(usize, n_acc);
            w.blocked[a][c] = !w.blocked[a][c];
        }
        if (r.uintLessThan(u32, 15000) == 0) { // heal everything
            w.blocked = @splat(@splat(false));
        }
        if (r.uintLessThan(u32, 6000 * w.calm) == 0) { // acceptor restarts from its persisted state
            const i = r.uintLessThan(usize, n_acc);
            w.acc[i] = lease.Acceptor.init(.{ .id = i + 100 }, w.acc_persisted[i], w.acc_clock[i].now(true_ns));
        }
        if (r.uintLessThan(u32, 9000 * w.calm) == 0) { // agent crash: all memory gone, same identity
            const i = r.uintLessThan(usize, n_agents);
            var p = w.params;
            if (i == 1) p.priority_delay_ms = 2500;
            w.agent[i] = try lease.Agent.init(p, i + 1, n_acc, r.int(u64));
        }
        if (r.uintLessThan(u32, 4000 * w.calm) == 0) { // health flap
            const i = r.uintLessThan(usize, n_agents);
            if (w.agent[i].healthy) {
                const now = w.agent_clock[i].now(true_ns);
                if (w.agent[i].stepDown(now, wall_ms)) |m| for (0..n_acc) |k| try w.send(true, @intCast(k), @intCast(i), m);
            } else w.agent[i].healthy = true;
        }
        // deliver
        var k: usize = 0;
        while (k < w.net.items.len) {
            const p = w.net.items[k];
            if (p.due > w.t_ms) {
                k += 1;
                continue;
            }
            _ = w.net.swapRemove(k);
            if (p.to_acceptor) {
                const a = &w.acc[p.to];
                const o = a.handle(w.acc_clock[p.to].now(true_ns), wall_ms, p.msg);
                if (o.persist) |s| {
                    w.acc_persisted[p.to] = s;
                    a.markPersisted(s);
                }
                try w.send(false, p.from, p.to, o.reply);
            } else {
                const ag = &w.agent[p.to];
                const ev = ag.onReply(w.agent_clock[p.to].now(true_ns), p.from, p.msg);
                if (ev == .acquired) w.acquisitions += 1;
            }
        }
        // agents run
        var leaders: u8 = 0;
        for (0..n_agents) |i| {
            const ag = &w.agent[i];
            const now = w.agent_clock[i].now(true_ns);
            const st = ag.poll(now, wall_ms);
            if (st.send) |m| for (0..n_acc) |c| try w.send(true, @intCast(c), @intCast(i), m);
            if (ag.takeRelease(now, wall_ms)) |m| for (0..n_acc) |c| try w.send(true, @intCast(c), @intCast(i), m);
            if (ag.isLeader(now)) {
                leaders += 1;
                const t = ag.fence(now);
                try std.testing.expect(t != 0);
                try std.testing.expect(t >= w.max_led_term); // fencing tokens never go back
                w.max_led_term = t;
            }
        }
        try std.testing.expect(leaders <= 1); // no split brain
        if (leaders == 1) w.led_ms += 1;
        // could someone lead? a healthy agent linked to a majority of acceptors
        for (0..n_agents) |i| {
            var up: u8 = 0;
            for (0..n_acc) |c| up += @intFromBool(!w.blocked[i][c]);
            if (w.agent[i].healthy and up >= 2) {
                w.avail_ms += 1;
                break;
            }
        }
        w.t_ms += 1;
    }
};

fn runWith(gpa: std.mem.Allocator, seed: u64, minutes: u64, drop_pct: u8, calm: u32) !World {
    var w = try World.init(gpa, seed, .{}, drop_pct);
    w.calm = calm;
    errdefer w.net.deinit(w.gpa);
    const total = minutes * 60_000;
    while (w.t_ms < total) w.step() catch |e| {
        std.debug.print("lease sim failed: seed {d} ({d} min, drop {d}%, calm {d}) at t={d} ms: {s}\n", .{ seed, minutes, drop_pct, calm, w.t_ms, @errorName(e) });
        return e;
    };
    return w;
}

fn run(seed: u64, minutes: u64, drop_pct: u8, calm: u32) !World {
    return runWith(std.testing.allocator, seed, minutes, drop_pct, calm);
}

test "sim: no split brain, fencing terms grow, someone leads most of the time" {
    var seed: u64 = 1;
    while (seed <= 12) : (seed += 1) {
        var w = try run(seed, 6, 10, 8);
        defer w.net.deinit(w.gpa);
        // liveness: when a healthy agent can reach a majority, someone leads most of that time
        try std.testing.expect(w.led_ms * 100 >= w.avail_ms * 60);
        try std.testing.expect(w.acquisitions >= 1);
    }
}

test "sim: heavy loss still never splits" {
    var seed: u64 = 100;
    while (seed < 106) : (seed += 1) {
        var w = try run(seed, 3, 45, 1);
        w.net.deinit(w.gpa);
    }
}

/// Seed profiles of the sweep: (minutes, drop %, calm). Liveness is only judged on the first.
const profiles = [_]struct { minutes: u64, drop: u8, calm: u32 }{
    .{ .minutes = 6, .drop = 10, .calm = 8 },
    .{ .minutes = 4, .drop = 25, .calm = 2 },
    .{ .minutes = 3, .drop = 45, .calm = 1 },
};

const Sweep = struct {
    next: std.atomic.Value(u64),
    end: u64,
    minutes: ?u64,
    failed: std.atomic.Value(u64) = .init(0),
    slow: std.atomic.Value(u64) = .init(0),
    runs: std.atomic.Value(u64) = .init(0),
    sim_ms: std.atomic.Value(u64) = .init(0),
    acquisitions: std.atomic.Value(u64) = .init(0),
    /// Lowest led/available share (per mille) among the mild-profile seeds.
    min_led_permille: std.atomic.Value(u64) = .init(1000),

    fn worker(sw: *Sweep) void {
        while (true) {
            const seed = sw.next.fetchAdd(1, .monotonic);
            if (seed >= sw.end) return;
            const pr = profiles[seed % profiles.len];
            const minutes = sw.minutes orelse pr.minutes;
            var w = runWith(std.heap.smp_allocator, seed, minutes, pr.drop, pr.calm) catch {
                _ = sw.failed.fetchAdd(1, .monotonic);
                continue;
            };
            defer w.net.deinit(w.gpa);
            _ = sw.runs.fetchAdd(1, .monotonic);
            _ = sw.sim_ms.fetchAdd(w.t_ms, .monotonic);
            _ = sw.acquisitions.fetchAdd(w.acquisitions, .monotonic);
            if (seed % profiles.len == 0 and w.avail_ms > 0) {
                _ = sw.min_led_permille.fetchMin(w.led_ms * 1000 / w.avail_ms, .monotonic);
                if (w.led_ms * 100 < w.avail_ms * 60) {
                    _ = sw.slow.fetchAdd(1, .monotonic);
                    std.debug.print("lease sim liveness (info): seed {d} led {d} ms of {d} ms available\n", .{ seed, w.led_ms, w.avail_ms });
                }
            }
        }
    }
};

fn envU64(key: []const u8, default: ?u64) ?u64 {
    const v = std.testing.environ.getPosix(key) orelse return default;
    return std.fmt.parseInt(u64, v, 10) catch default;
}

// Long sweep, off unless ZUI_STANDBY_SIM_SEEDS is set:
//   ZUI_STANDBY_SIM_SEEDS=5000 [ZUI_STANDBY_SIM_FROM=1000] [ZUI_STANDBY_SIM_THREADS=4]
//   [ZUI_STANDBY_SIM_MINUTES=N] ./zig build test -Dlane=standby -Doptimize=ReleaseFast
// Safety (one leader, fencing terms only grow) must hold on every seed. Liveness on the mild profile
// is reported, not judged: an acceptor restart assumes a full max_lease_ms (60 s) is outstanding and
// an agent crash forgets its lease, so chaos-heavy seeds legitimately lead only about half of the
// time a majority is reachable (the 12-seed unit test above keeps its 60% floor).
test "sim: seed sweep (ZUI_STANDBY_SIM_SEEDS)" {
    const n = envU64("ZUI_STANDBY_SIM_SEEDS", null) orelse return error.SkipZigTest;
    const from = envU64("ZUI_STANDBY_SIM_FROM", 1000).?;
    const threads: usize = @intCast(@max(1, envU64("ZUI_STANDBY_SIM_THREADS", 4).?));
    var sw: Sweep = .{ .next = .init(from), .end = from + n, .minutes = envU64("ZUI_STANDBY_SIM_MINUTES", null) };
    const ts = try std.testing.allocator.alloc(std.Thread, threads);
    defer std.testing.allocator.free(ts);
    for (ts) |*t| t.* = try std.Thread.spawn(.{}, Sweep.worker, .{&sw});
    for (ts) |t| t.join();
    std.debug.print("lease sim sweep: seeds {d}..{d}: {d} runs, {d} failed (safety), {d} simulated hours, {d} acquisitions; mild profile: {d} seeds led under 60% of the available time, lowest {d}.{d}%\n", .{
        from,                                 from + n - 1,                             sw.runs.load(.monotonic), sw.failed.load(.monotonic), sw.sim_ms.load(.monotonic) / 3_600_000,
        sw.acquisitions.load(.monotonic),     sw.slow.load(.monotonic),                 sw.min_led_permille.load(.monotonic) / 10, sw.min_led_permille.load(.monotonic) % 10,
    });
    try std.testing.expectEqual(@as(u64, 0), sw.failed.load(.monotonic));
}
