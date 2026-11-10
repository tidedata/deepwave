//! Tile runtime: one thread per tile, pinned to a core, running `step` in a loop that never
//! takes a lock or allocates. A tile polls its input rings in `step`, does bounded work and
//! publishes to its output rings (ARCHITECTURE.md 7.1). This file holds
//!   - `Link` / `Rx`: a single-producer ring of fragment descriptors (ring.zig Mcache) with
//!     credit flow control from the consumers' progress words (Fseq/Fctl);
//!   - `Tile` / `Group`: the thread, its core pin, its idle policy (spin, then a short sleep) and
//!     its metrics (busy/idle time, fragments, a log2 histogram of the time `step` took while busy).
//! Nothing here knows what a fragment means; the pipelines (src/node/p2p_tiles.zig) do.
const std = @import("std");
const builtin = @import("builtin");
const ring = @import("ring.zig");
const Atomic = std.atomic.Value;

pub const FragMeta = ring.FragMeta;

pub fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    } else {
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
    }
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn sleepNs(ns: u64) void {
    var ts: std.posix.timespec = .{ .sec = @intCast(ns / std.time.ns_per_s), .nsec = @intCast(ns % std.time.ns_per_s) };
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.nanosleep(&ts, null);
    } else {
        _ = std.c.nanosleep(&ts, &ts);
    }
}

/// Pins the calling thread to `cpu` (Linux; elsewhere and on failure: false, the thread floats).
pub fn pinThisThread(cpu: u16) bool {
    if (builtin.os.tag != .linux) return false;
    var set: std.os.linux.cpu_set_t = @splat(0);
    const w = @bitSizeOf(usize);
    if (cpu / w >= set.len) return false;
    set[cpu / w] |= @as(usize, 1) << @intCast(cpu % w);
    std.os.linux.sched_setaffinity(0, &set) catch return false;
    return true;
}

/// Names the calling thread (Linux comm, 15 bytes) so samplers can add up tile CPU.
pub fn nameThisThread(name: []const u8) void {
    if (builtin.os.tag != .linux) return;
    var buf: [16:0]u8 = @splat(0);
    const n = @min(name.len, 15);
    @memcpy(buf[0..n], name[0..n]);
    _ = std.os.linux.prctl(15, @intFromPtr(&buf), 0, 0, 0); // PR_SET_NAME
}

// ---------------------------------------------------------------------------------------------
// Links

/// The producer side of one ring. Only the producing tile calls `publish`/`credit`.
pub const Link = struct {
    lines: []align(64) FragMeta,
    mc: ring.Mcache,
    /// Next sequence number to publish (producer thread only).
    tx_seq: u64 = 0,
    fctl: ring.Fctl,
    gpa: std.mem.Allocator,

    /// `depth`: a power of two. `readers`: progress words of the consumers whose progress limits
    /// the producer (empty: unlimited, consumers that fall behind see an overrun).
    pub fn init(gpa: std.mem.Allocator, depth: usize, readers: []const *const ring.Fseq) !Link {
        const lines = try gpa.alignedAlloc(FragMeta, .@"64", depth);
        return .{ .lines = lines, .mc = ring.Mcache.init(lines, 0), .fctl = .{ .rx = readers, .depth = depth }, .gpa = gpa };
    }

    pub fn deinit(l: *Link) void {
        l.gpa.free(l.lines);
    }

    /// True when a frag can be published without lapping the slowest reader.
    pub inline fn canPublish(l: *Link) bool {
        if (l.fctl.credits == 0) return l.fctl.refresh(l.tx_seq) != 0;
        return true;
    }

    /// Publishes the next frag. Call only after `canPublish`. Returns its sequence number.
    pub inline fn publish(l: *Link, sig: u64, chunk: u32, ctl: u16) u64 {
        const s = l.tx_seq;
        l.mc.publish(s, sig, chunk, 0, ctl, 0, 0);
        l.tx_seq = s +% 1;
        l.fctl.credits -= 1;
        return s;
    }
};

/// One consumer of a `Link`: its position and its progress word.
pub const Rx = struct {
    link: *const Link,
    seq: u64 = 0,
    fseq: ring.Fseq = .{},
    /// Frags lost to an overrun (an unreliable consumer, or a bug): never expected here.
    overruns: u64 = 0,

    /// The next frag in `out`, or false when there is none yet. Does not advance: call `done`.
    pub inline fn peek(rx: *Rx, out: *FragMeta) bool {
        switch (rx.link.mc.poll(rx.seq, out)) {
            .ready => return true,
            .empty => return false,
            .overrun => |s| {
                rx.overruns += 1;
                rx.seq = s;
                return false;
            },
        }
    }

    /// Consumed the frag `peek` returned: publishes progress (returning the producer's credit).
    pub inline fn done(rx: *Rx) void {
        rx.seq +%= 1;
        rx.fseq.update(rx.seq);
    }
};

// ---------------------------------------------------------------------------------------------
// Tiles

pub const Step = enum { idle, busy };

pub const Metrics = struct {
    loops: Atomic(u64) align(64) = .init(0),
    busy_steps: Atomic(u64) = .init(0),
    busy_ns: Atomic(u64) = .init(0),
    idle_ns: Atomic(u64) = .init(0),
    /// Fragments the tile finished (bumped by the tile through `frag()`).
    frags: Atomic(u64) = .init(0),
    max_step_ns: Atomic(u64) = .init(0),
    /// Busy steps by floor(log2(ns)) of their duration.
    hist: [40]Atomic(u64) = @splat(.init(0)),

    pub inline fn frag(m: *Metrics) void {
        _ = m.frags.fetchAdd(1, .monotonic);
    }

    /// The duration (ns) at or below which `q` (0..1) of the busy steps ended, as the top of the
    /// log2 bucket (0 when none ran).
    pub fn quantileNs(m: *const Metrics, q: f64) u64 {
        var total: u64 = 0;
        for (&m.hist) |*h| total += h.load(.monotonic);
        if (total == 0) return 0;
        const want: u64 = @intFromFloat(@ceil(@as(f64, @floatFromInt(total)) * q));
        var acc: u64 = 0;
        for (&m.hist, 0..) |*h, i| {
            acc += h.load(.monotonic);
            if (acc >= want) return @as(u64, 1) << @intCast(i + 1);
        }
        return std.math.maxInt(u64);
    }

    pub fn noteStep(m: *Metrics, ns: u64) void {
        _ = m.busy_steps.fetchAdd(1, .monotonic);
        const b: usize = @min(63 - @clz(@max(ns, 1)), m.hist.len - 1);
        _ = m.hist[b].fetchAdd(1, .monotonic);
        if (ns > m.max_step_ns.load(.monotonic)) m.max_step_ns.store(ns, .monotonic);
    }
};

pub const Config = struct {
    /// Thread name (15 bytes) and log name.
    name: []const u8,
    /// Core to pin to (null: not pinned).
    cpu: ?u16 = null,
    /// Idle steps in a row spun through before sleeping; a tile with `spin` = maxInt never sleeps
    /// (one core at 100%).
    spin: u32 = 4000,
    /// Sleep once spinning has run out.
    sleep_ns: u64 = 50_000,
    stack_size: usize = 16 << 20,
};

pub const Tile = struct {
    cfg: Config,
    ctx: *anyopaque,
    /// One bounded unit of work: .busy when it did some (the loop calls again at once).
    step: *const fn (ctx: *anyopaque) Step,
    /// Runs once on the tile's thread before the first step (null: nothing).
    start: ?*const fn (ctx: *anyopaque) void = null,
    /// Runs once on the tile's thread after the last step.
    finish: ?*const fn (ctx: *anyopaque) void = null,
    metrics: Metrics = .{},
    thread: ?std.Thread = null,
    stop: *const Atomic(bool) = undefined,
    pinned: Atomic(bool) = .init(false),

    fn main(t: *Tile) void {
        nameThisThread(t.cfg.name);
        if (t.cfg.cpu) |c| t.pinned.store(pinThisThread(c), .release);
        if (t.start) |f| f(t.ctx);
        defer if (t.finish) |f| f(t.ctx);
        var idle_run: u32 = 0;
        var mark = nowNs();
        var busy = false;
        while (!t.stop.load(.acquire)) {
            const s0 = if (busy) mark else 0;
            const r = t.step(t.ctx);
            _ = t.metrics.loops.fetchAdd(1, .monotonic);
            switch (r) {
                .busy => {
                    idle_run = 0;
                    const now = nowNs();
                    if (!busy) {
                        _ = t.metrics.idle_ns.fetchAdd(now -| mark, .monotonic);
                        busy = true;
                        mark = now;
                        // the step that just ran started when the idle stretch ended; its time
                        // is not known, count only from the next one
                    } else {
                        t.metrics.noteStep(now -| s0);
                        mark = now;
                    }
                },
                .idle => {
                    if (busy) {
                        const now = nowNs();
                        _ = t.metrics.busy_ns.fetchAdd(now -| mark, .monotonic);
                        busy = false;
                        mark = now;
                    }
                    idle_run +|= 1;
                    if (idle_run < t.cfg.spin) {
                        std.atomic.spinLoopHint();
                    } else {
                        sleepNs(t.cfg.sleep_ns);
                    }
                },
            }
        }
        const now = nowNs();
        if (busy) _ = t.metrics.busy_ns.fetchAdd(now -| mark, .monotonic);
    }
};

/// Tiles started and stopped together.
pub const Group = struct {
    tiles: []const *Tile,
    stop_flag: Atomic(bool) = .init(false),

    pub fn start(g: *Group) !void {
        for (g.tiles) |t| t.stop = &g.stop_flag;
        var started: usize = 0;
        errdefer {
            g.stop_flag.store(true, .release);
            for (g.tiles[0..started]) |t| if (t.thread) |th| th.join();
        }
        for (g.tiles) |t| {
            t.thread = try std.Thread.spawn(.{ .stack_size = t.cfg.stack_size }, Tile.main, .{t});
            started += 1;
        }
    }

    /// Signals every tile and joins them. Safe to call twice.
    pub fn stop(g: *Group) void {
        g.stop_flag.store(true, .release);
        for (g.tiles) |t| if (t.thread) |th| {
            th.join();
            t.thread = null;
        };
    }
};

// ---------------------------------------------------------------------------------------------
// Tests

const testing = std.testing;

const Relay = struct {
    in: ?*Rx = null,
    out: *Link,
    src: u64 = 0, // when `in` is null: frags to generate
    made: u64 = 0,
    sum: u64 = 0,
    t: *Tile = undefined,

    fn step(ctx: *anyopaque) Step {
        const r: *Relay = @ptrCast(@alignCast(ctx));
        if (!r.out.canPublish()) return .idle;
        if (r.in) |in| {
            var m: FragMeta = undefined;
            if (!in.peek(&m)) return .idle;
            _ = r.out.publish(m.sig + 1, m.chunk, 0);
            in.done();
            r.t.metrics.frag();
            return .busy;
        }
        if (r.made >= r.src) return .idle;
        _ = r.out.publish(r.made, 0, 0);
        r.made += 1;
        r.t.metrics.frag();
        return .busy;
    }
};

const Sink = struct {
    in: *Rx,
    n: u64 = 0,
    sum: u64 = 0,
    bad: u64 = 0,
    t: *Tile = undefined,

    fn step(ctx: *anyopaque) Step {
        const s: *Sink = @ptrCast(@alignCast(ctx));
        var m: FragMeta = undefined;
        if (!s.in.peek(&m)) return .idle;
        // frag k left the source as k and was incremented once by the relay
        if (m.sig != s.n + 1) s.bad += 1;
        s.sum +%= m.sig;
        s.n += 1;
        s.in.done();
        s.t.metrics.frag();
        return .busy;
    }
};

test "tile: three-stage pipeline over flow-controlled links, metrics counted" {
    const gpa = testing.allocator;
    // Sink -> Relay -> Source; links need their readers' fseq, so build the Rx first.
    var l2: Link = undefined;
    var l1: Link = undefined;
    var rx1: Rx = .{ .link = &l1 };
    var rx2: Rx = .{ .link = &l2 };
    l1 = try Link.init(gpa, 8, &.{&rx1.fseq});
    defer l1.deinit();
    l2 = try Link.init(gpa, 8, &.{&rx2.fseq});
    defer l2.deinit();
    const n: u64 = 50_000;
    var src: Relay = .{ .out = &l1, .src = n };
    var mid: Relay = .{ .in = &rx1, .out = &l2 };
    var snk: Sink = .{ .in = &rx2 };
    var ts: Tile = .{ .cfg = .{ .name = "t-src", .spin = 100 }, .ctx = &src, .step = Relay.step };
    var tm: Tile = .{ .cfg = .{ .name = "t-mid", .spin = 100 }, .ctx = &mid, .step = Relay.step };
    var tk: Tile = .{ .cfg = .{ .name = "t-sink", .spin = 100 }, .ctx = &snk, .step = Sink.step };
    src.t = &ts;
    mid.t = &tm;
    snk.t = &tk;
    var g: Group = .{ .tiles = &.{ &ts, &tm, &tk } };
    try g.start();
    var waited: u32 = 0;
    while (@atomicLoad(u64, &snk.n, .acquire) < n and waited < 20_000) : (waited += 1) sleepNs(1_000_000);
    g.stop();
    try testing.expectEqual(n, snk.n);
    try testing.expectEqual(@as(u64, 0), snk.bad);
    try testing.expectEqual(n, tm.metrics.frags.load(.monotonic));
    try testing.expect(tm.metrics.busy_steps.load(.monotonic) > 0);
    try testing.expect(tm.metrics.quantileNs(0.5) > 0);
    try testing.expectEqual(@as(u64, 0), rx1.overruns + rx2.overruns);
}

test "tile: link without credit refuses to publish, reader progress returns it" {
    const gpa = testing.allocator;
    var l: Link = undefined;
    var rx: Rx = .{ .link = &l };
    l = try Link.init(gpa, 4, &.{&rx.fseq});
    defer l.deinit();
    for (0..4) |i| {
        try testing.expect(l.canPublish());
        _ = l.publish(i, 0, 0);
    }
    try testing.expect(!l.canPublish());
    var m: FragMeta = undefined;
    try testing.expect(rx.peek(&m));
    rx.done();
    try testing.expect(l.canPublish());
}
