//! How many feed requests an edge keeps in flight at its cores while it catches up.
//!
//! A fixed count is wrong at both ends. Every fetch is a round trip, so `n` requests in flight
//! fetch about `n / RTT` checkpoints a second: with the edge profile's 4, an edge 252 ms from
//! its core caps near 16 a second, a few above chain speed, and needs many
//! hours to reach the tip, while an edge at 90 ms fetches faster than it can apply and gains
//! nothing from more. `Controller` sets the count from what the edge measures:
//!
//!   - grow (by a quarter) while the ordered apply stage is starved: it spent more than
//!     `starved` of the last interval waiting for its next checkpoint;
//!   - if a growth step did not raise the fetch rate (the connection's flow control or the core
//!     is the bound, not the count), take it back and wait before the next try;
//!   - shrink to what the apply rate needs (`rate x call time`, with `headroom`) once the apply
//!     stage is the bottleneck: it waited for less than `fed` of the interval;
//!   - halve at once, and hold, on any failed or refused call and when the core's time to first
//!     byte doubles: the core is someone else's box;
//!   - never below `floor` (the profile's count, one request per fetch thread), never above
//!     `cap` (`--feed-max-inflight`) or the fetch window (a claim is never further ahead of the
//!     follower than the window, so that is all that can be in flight or waiting, and all the
//!     memory the window was sized for);
//!   - at the tip the count is `floor`, exactly: the profile's behaviour, no extra request.
//!
//! Pure state and arithmetic on the caller's clock and counters, so the rules run under a
//! simulated core (the tests below) and the fetcher (node source.zig) only feeds it samples.
const std = @import("std");

pub const Config = struct {
    /// The profile's count (one request per fetch thread): the least, and the tip's.
    floor: u32,
    /// The most (`--feed-max-inflight`). 0: fixed at `floor`, the behaviour before this existed.
    /// The default stays well under a core's feed queue (64 for all its clients together,
    /// native listener `feed_queue`) divided by the edges that may catch up at once: one edge
    /// at 64 could fill the queue and starve every other edge until its first refusal.
    cap: u32 = 16,
    /// The fetch window, in checkpoints.
    window: u32,
    /// The shortest time between two decisions; a decision also waits for two call times, so
    /// each one sees what the last one did.
    interval_ns: u64 = 250 * std.time.ns_per_ms,
    /// Share of an interval the apply stage waited for its next checkpoint, in 1/1000: above
    /// `starved` the count grows, below `fed` it shrinks to what the apply rate needs.
    starved: u32 = 60,
    fed: u32 = 20,
    /// In-flight kept for the apply rate, in 1/1000 of `rate x call time`.
    headroom: u32 = 1500,
    /// Decisions without growth after a back-off, and after a growth step that did not help.
    hold_backoff: u32 = 8,
    hold_plateau: u32 = 16,
};

/// What the fetcher has measured. Counters are totals since the start (monotone).
pub const Sample = struct {
    now_ns: u64,
    /// Checkpoints the follower has applied.
    applied: u64,
    /// Checkpoints fetched from the cores.
    fetched: u64,
    /// Time the ordered apply stage has spent waiting for its next checkpoint.
    stall_ns: u64,
    /// Core calls that failed or were refused (rate limited).
    errors: u64,
    /// Smoothed time from a call's start to its first response byte (0: none measured yet).
    first_byte_ns: u64 = 0,
    /// Smoothed time of a whole call, start to last response byte (0: none measured yet).
    call_ns: u64 = 0,
    /// The fetcher is at the tip (it found a checkpoint the core does not hold yet).
    at_tip: bool = false,
};

pub const Stats = struct {
    grows: u64 = 0,
    shrinks: u64 = 0,
    /// Halvings for an error or a slow core.
    backoffs: u64 = 0,
    /// Growth steps taken back because the fetch rate did not follow.
    plateaus: u64 = 0,
    /// The highest count ever set.
    peak: u32 = 0,
};

pub const Controller = struct {
    cfg: Config,
    /// Requests to keep in flight now.
    target: u32,
    stats: Stats = .{},
    last: ?Sample = null,
    /// The count before the last growth step and the fetch rate then (per second, x1000).
    before_grow: u32 = 0,
    rate_before_grow: u64 = 0,
    grew: bool = false,
    /// Decisions to let pass before the last growth step is judged: the calls in flight when
    /// it was taken were sent with the old count.
    settle: u32 = 0,
    hold: u32 = 0,
    /// The lowest time to first byte seen (the path's round trip plus an idle core's work).
    first_byte_min: u64 = 0,

    pub fn init(cfg: Config) Controller {
        return .{ .cfg = cfg, .target = cfg.floor };
    }

    /// The most the count may be.
    pub fn limit(c: *const Controller) u32 {
        if (c.cfg.cap == 0) return c.cfg.floor;
        return @max(c.cfg.floor, @min(c.cfg.cap, c.cfg.window));
    }

    fn set(c: *Controller, t: u32) void {
        const v = @max(c.cfg.floor, @min(t, c.limit()));
        if (v > c.target) c.stats.grows += 1;
        if (v < c.target) c.stats.shrinks += 1;
        c.target = v;
        c.stats.peak = @max(c.stats.peak, v);
    }

    /// One sample; returns the count to keep in flight from now on.
    pub fn tick(c: *Controller, s: Sample) u32 {
        if (c.cfg.cap == 0) return c.cfg.floor;
        // The tip: the profile's behaviour, at once and whatever the interval.
        if (s.at_tip) {
            if (c.target != c.cfg.floor) c.set(c.cfg.floor);
            c.grew = false;
            c.hold = 0;
            c.last = s;
            return c.target;
        }
        const last = c.last orelse {
            c.last = s;
            return c.target;
        };
        // A failed or refused call backs off at once: no waiting for the interval.
        if (s.errors > last.errors) {
            c.backoff();
            c.last = s;
            return c.target;
        }
        const dt = s.now_ns -| last.now_ns;
        if (dt < @max(c.cfg.interval_ns, 2 * s.call_ns)) return c.target;
        c.last = s;
        const fetch_rate = (s.fetched -| last.fetched) * 1000 * std.time.ns_per_s / dt;
        const apply_rate = (s.applied -| last.applied) * 1000 * std.time.ns_per_s / dt;
        const stalled: u64 = @min(1000, (s.stall_ns -| last.stall_ns) * 1000 / dt);

        // A core that takes twice as long to start answering is loaded: step back.
        if (s.first_byte_ns != 0) {
            if (c.first_byte_min == 0 or s.first_byte_ns < c.first_byte_min) c.first_byte_min = s.first_byte_ns;
            if (s.first_byte_ns > 2 * c.first_byte_min + 50 * std.time.ns_per_ms) {
                c.backoff();
                // the path may have changed for good: the floor follows, slowly
                c.first_byte_min += c.first_byte_min / 50 + 1;
                return c.target;
            }
        }

        if (stalled > c.cfg.starved) {
            if (c.hold > 0) {
                c.hold -= 1;
                c.grew = false;
                return c.target;
            }
            if (c.grew and c.settle > 0) {
                c.settle -= 1;
                return c.target;
            }
            if (c.grew) {
                // The last step added `gain` (1/1000) to the count; less than half of it in the
                // fetch rate means the count is not what bounds the rate.
                const gain: u64 = @as(u64, c.target - c.before_grow) * 1000 / @max(1, c.before_grow);
                if (fetch_rate * 1000 < c.rate_before_grow * (1000 + gain / 2)) {
                    c.set(c.before_grow);
                    c.stats.plateaus += 1;
                    c.hold = c.cfg.hold_plateau;
                    c.grew = false;
                    return c.target;
                }
            }
            c.before_grow = c.target;
            c.rate_before_grow = fetch_rate;
            c.set(c.target + @max(1, c.target / 4));
            c.grew = c.target != c.before_grow;
            c.settle = 1;
            return c.target;
        }
        c.grew = false;
        if (stalled < c.cfg.fed and s.call_ns != 0) {
            // The apply stage is the bottleneck: keep what its rate needs and no more.
            const need = (apply_rate * (s.call_ns / 1000) * c.cfg.headroom / 1000 + 999_999_999) / 1_000_000_000;
            if (need < c.target) c.set(@intCast(@max(need, c.cfg.floor)));
        }
        return c.target;
    }

    fn backoff(c: *Controller) void {
        c.set(c.target / 2);
        c.stats.backoffs += 1;
        c.hold = c.cfg.hold_backoff;
        c.grew = false;
    }

    /// The share of `target` for fetch thread `i` of `n`: the requests it keeps in flight on
    /// its connection (the remainder goes to the first threads).
    pub fn depth(target: u32, i: u32, n: u32) u32 {
        if (n == 0) return 0;
        return @max(1, target / n + @intFromBool(i < target % n));
    }
};

// ------------------------------------------------------------------ simulation (tests)
//
// A scripted core and a scripted apply stage on a simulated clock (1 ms steps), with the
// fetcher's own structure: `conns` connections, each sending the checkpoints it claimed as one
// pipelined call and claiming again when the call's last response is in; claims stay inside
// the window; the apply stage takes checkpoints in order, one every `1 / apply_rate` seconds.

const testing = std.testing;
const ms = std.time.ns_per_ms;

const Sim = struct {
    const max_conns = 8;
    const Call = struct {
        busy: bool = false,
        n: u32 = 0,
        first_seq: u64 = 0,
        sent_ms: u64 = 0,
        first_byte_ms: u64 = 0,
        done_ms: u64 = 0,
    };

    // the script
    /// Round trip to the core.
    rtt_ms: u64,
    /// What the core adds to each response of a call (assembly and transfer), on top of the trip.
    per_response_us: u64 = 1_000,
    /// Checkpoints a second the apply stage can take (x1000).
    apply_per_ks: u64,
    conns: u32 = 4,
    window: u32 = 32,
    /// `--feed-max-inflight` (0: the fixed count).
    cap: u32 = 16,
    /// From `slow_from_ms` to `slow_to_ms` the core takes this much longer to start answering.
    slow_from_ms: u64 = std.math.maxInt(u64),
    slow_to_ms: u64 = 0,
    slow_extra_ms: u64 = 0,
    /// A call sent in `[refuse_from_ms, refuse_to_ms)` is refused (rate limited).
    refuse_from_ms: u64 = std.math.maxInt(u64),
    refuse_to_ms: u64 = 0,
    /// The chain's tip: the core holds checkpoints below it; it moves at `tip_per_ks`.
    tip: u64 = std.math.maxInt(u64) / 2,
    tip_per_ks: u64 = 0,

    // the state
    now_ms: u64 = 0,
    ctl: Controller = undefined,
    calls: [max_conns]Call = @splat(.{}),
    next_claim: u64 = 0,
    /// Fetched and waiting for the apply stage, by `seq % have.len`.
    have: [256]bool = @splat(false),
    applied: u64 = 0,
    fetched: u64 = 0,
    errors: u64 = 0,
    stall_ns: u64 = 0,
    /// When the apply in hand ends (0: none).
    apply_done_us: u64 = 0,
    first_byte_ns: u64 = 0,
    call_ns: u64 = 0,
    at_tip: bool = false,
    tip_frac: u64 = 0,
    // what the tests look at
    max_occupied: u64 = 0,
    max_in_flight: u32 = 0,
    max_in_flight_at_tip: u32 = 0,
    requests: u64 = 0,
    requests_at_tip: u64 = 0,

    fn start(s: *Sim) void {
        s.ctl = Controller.init(.{ .floor = s.conns, .cap = s.cap, .window = s.window });
    }

    fn inFlight(s: *const Sim) u32 {
        var n: u32 = 0;
        for (s.calls[0..s.conns]) |c| if (c.busy) {
            n += c.n;
        };
        return n;
    }

    fn ewma(old: u64, new: u64) u64 {
        return if (old == 0) new else (old * 7 + new) / 8;
    }

    fn step(s: *Sim) !void {
        s.now_ms += 1;
        const now_us = s.now_ms * 1000;
        // the chain goes on
        s.tip_frac += s.tip_per_ks;
        s.tip += s.tip_frac / 1_000_000;
        s.tip_frac %= 1_000_000;
        // responses
        for (s.calls[0..s.conns]) |*c| {
            if (!c.busy or s.now_ms < c.done_ms) continue;
            c.busy = false;
            const refused = c.sent_ms >= s.refuse_from_ms and c.sent_ms < s.refuse_to_ms;
            if (refused) {
                s.errors += 1;
                // the fetcher asks again, one at a time
                s.next_claim = @min(s.next_claim, c.first_seq);
                continue;
            }
            s.first_byte_ns = ewma(s.first_byte_ns, (c.first_byte_ms - c.sent_ms) * ms);
            s.call_ns = ewma(s.call_ns, (c.done_ms - c.sent_ms) * ms);
            for (0..c.n) |k| {
                const seq = c.first_seq + k;
                if (seq >= s.tip) {
                    // not held yet: the tip
                    s.at_tip = true;
                    s.next_claim = @min(s.next_claim, seq);
                    break;
                }
                s.have[seq % s.have.len] = true;
                s.fetched += 1;
            }
        }
        // the apply stage: one checkpoint at a time, in order
        if (s.apply_done_us != 0 and now_us >= s.apply_done_us) {
            s.applied += 1;
            s.apply_done_us = 0;
        }
        if (s.apply_done_us == 0) {
            if (s.have[s.applied % s.have.len]) {
                s.have[s.applied % s.have.len] = false;
                s.apply_done_us = now_us + 1_000_000_000 / s.apply_per_ks;
            } else s.stall_ns += ms;
        }
        // behind the tip again (a run of checkpoints already there)
        if (s.at_tip and s.tip > s.applied + s.window) s.at_tip = false;
        // the controller, then the fetch threads
        const target = s.ctl.tick(.{ .now_ns = s.now_ms * ms, .applied = s.applied, .fetched = s.fetched, .stall_ns = s.stall_ns, .errors = s.errors, .first_byte_ns = s.first_byte_ns, .call_ns = s.call_ns, .at_tip = s.at_tip });
        for (s.calls[0..s.conns], 0..) |*c, i| {
            if (c.busy) continue;
            // at the tip: one request per thread, and only the next checkpoint is asked for
            const d: u32 = if (s.at_tip) 1 else Controller.depth(target, @intCast(i), s.conns);
            const room = (s.applied + s.window) -| s.next_claim;
            // a whole run or nothing (the fetcher's `claimRun`): a connection that took the one
            // free place of a full window would be gone for a round trip with it
            var n: u32 = if (room >= d) d else 0;
            if (s.at_tip) {
                // the frontier poll: one thread asks for the checkpoint after the tip, once per
                // round trip (the others wait for it)
                if (s.inFlight() > 0 or s.next_claim > s.tip) n = 0;
            }
            if (n == 0) continue;
            const slow = s.now_ms >= s.slow_from_ms and s.now_ms < s.slow_to_ms;
            const lead = s.rtt_ms + (if (slow) s.slow_extra_ms else 0);
            c.* = .{ .busy = true, .n = n, .first_seq = s.next_claim, .sent_ms = s.now_ms, .first_byte_ms = s.now_ms + lead + (s.per_response_us + 999) / 1000, .done_ms = s.now_ms + lead + (n * s.per_response_us + 999) / 1000 };
            s.next_claim += n;
            s.requests += n;
            if (s.at_tip) s.requests_at_tip += n;
        }
        // the window holds everything claimed and not yet applied: in flight or waiting
        const occupied = s.next_claim -| s.applied;
        s.max_occupied = @max(s.max_occupied, occupied);
        try testing.expect(occupied <= s.window);
        const fl = s.inFlight();
        s.max_in_flight = @max(s.max_in_flight, fl);
        if (s.at_tip) s.max_in_flight_at_tip = @max(s.max_in_flight_at_tip, fl);
        try testing.expect(fl <= @max(s.ctl.limit(), s.conns));
    }

    fn run(s: *Sim, for_ms: u64) !void {
        const end = s.now_ms + for_ms;
        while (s.now_ms < end) try s.step();
    }

    /// Checkpoints applied a second (x10) over the next `for_ms`.
    fn rate10(s: *Sim, for_ms: u64) !u64 {
        const a0 = s.applied;
        try s.run(for_ms);
        return (s.applied - a0) * 10_000 / for_ms;
    }
};

/// Catch-up rate (x10) after a warm-up, with the fixed count (`cap` 0) or the controller.
fn simRate(rtt_ms: u64, apply_per_s: u64, cap: u32, window: u32, target_out: ?*u32) !u64 {
    var s: Sim = .{ .rtt_ms = rtt_ms, .apply_per_ks = apply_per_s * 1000, .cap = cap, .window = window };
    s.start();
    try s.run(40_000);
    const r = try s.rate10(40_000);
    if (target_out) |t| t.* = s.ctl.target;
    return r;
}

test "in-flight controller: catch-up reaches the apply rate at 20, 90 and 250 ms from the core, where the fixed count stops at 4 requests per round trip" {
    // { RTT ms, apply rate, window, cap }: the edge profile's window is 32, the Mac mini's 128;
    // the cap is the default (16) but for the last two rows, which pass `--feed-max-inflight 64`
    const default_cap = (Config{ .floor = 4, .window = 32 }).cap;
    try testing.expectEqual(@as(u32, 16), default_cap);
    const cases = [_][4]u64{ .{ 20, 34, 32, default_cap }, .{ 90, 34, 32, default_cap }, .{ 250, 34, 32, default_cap }, .{ 20, 100, 32, default_cap }, .{ 90, 100, 32, default_cap }, .{ 250, 100, 32, default_cap }, .{ 250, 100, 32, 64 }, .{ 250, 200, 128, 64 } };
    std.debug.print("in-flight controller, simulated catch-up (checkpoints a second):\n  RTT ms  apply  window  cap  fixed (4)  adaptive  in flight\n", .{});
    for (cases) |cs| {
        const rtt = cs[0];
        const apply = cs[1];
        const window: u32 = @intCast(cs[2]);
        const cap: u32 = @intCast(cs[3]);
        const fixed = try simRate(rtt, apply, 0, window, null);
        var target: u32 = 0;
        const adaptive = try simRate(rtt, apply, cap, window, &target);
        std.debug.print("  {d:>6}  {d:>5}  {d:>6}  {d:>3}  {d:>7}.{d}  {d:>6}.{d}  {d:>9}\n", .{ rtt, apply, window, cap, fixed / 10, fixed % 10, adaptive / 10, adaptive % 10, target });
        // the fixed count: 4 requests per round trip (plus a millisecond each), or the apply rate
        const per_trip = 4 * 10_000 / (rtt + 1);
        try testing.expect(fixed <= @min(apply * 10, per_trip) + 5);
        // the controller: the apply rate, or what the window lets through if that is less. A
        // connection sends its next run when the last one is in and the window has room for a
        // whole run, so the window carries about two thirds of `window / RTT` (250 ms, 100 a
        // second and the edge profile's window of 32: the window is the bound, not the count).
        const through_window = @as(u64, window) * 10_000 / (rtt + 1);
        // and no more than the cap carries: `cap` requests per round trip
        const through_cap = @as(u64, cap) * 10_000 / (rtt + 1);
        const want = @min(apply * 10, @min(through_window * 65 / 100, through_cap * 9 / 10));
        try testing.expect(adaptive >= want * 93 / 100);
        try testing.expect(adaptive <= through_cap + 5 or adaptive <= fixed + 5);
        try testing.expect(adaptive <= apply * 10 + 5);
        // never worse than the fixed count; and where the fixed count already feeds the apply
        // stage, no more in flight than its rate needs with the headroom (the requests a second
        // are the apply rate either way)
        try testing.expect(adaptive + 5 >= fixed);
        if (fixed >= apply * 10 * 97 / 100) try testing.expect(target <= @max(4, (apply * (rtt + 10) * 15 / 10 + 999) / 1000 + 1));
        try testing.expect(target <= @min(cap, window));
    }
}

test "in-flight controller: the count converges (steady within a quarter once the apply stage is fed) and what is claimed never exceeds the window" {
    for ([_]u64{ 20, 90, 250 }) |rtt| {
        var s: Sim = .{ .rtt_ms = rtt, .apply_per_ks = 34_000 };
        s.start();
        try s.run(40_000);
        var lo: u32 = std.math.maxInt(u32);
        var hi: u32 = 0;
        for (0..20_000) |_| {
            try s.step();
            lo = @min(lo, s.ctl.target);
            hi = @max(hi, s.ctl.target);
        }
        try testing.expect(hi <= lo + @max(1, lo / 4) + 1);
        try testing.expect(s.max_occupied <= s.window);
        // in flight at the core: what 34 a second needs at this distance, with headroom
        const need: u32 = @intCast(@max(4, (34 * (rtt + 12) * 15 / 10 + 999) / 1000));
        try testing.expect(hi <= need + need / 4 + 1);
    }
}

test "in-flight controller: a core that slows down or refuses calls is backed off from at once, and the count returns when the core does" {
    // 250 ms away, an apply stage that could take 100 a second, `--feed-max-inflight 64`: the
    // count is high
    var s: Sim = .{ .rtt_ms = 250, .apply_per_ks = 100_000, .cap = 64, .slow_from_ms = 40_000, .slow_to_ms = 60_000, .slow_extra_ms = 600 };
    s.start();
    try s.run(40_000);
    const before = s.ctl.target;
    try testing.expect(before >= 16);
    // the core takes 600 ms longer to start answering, for 20 s
    const backoffs0 = s.ctl.stats.backoffs;
    try s.run(6_000);
    try testing.expect(s.ctl.stats.backoffs > backoffs0);
    try testing.expect(s.ctl.target <= before / 2);
    try s.run(14_000);
    try testing.expect(s.ctl.target <= before / 2);
    // the core is itself again: back to what the apply stage needs
    try s.run(60_000);
    try testing.expect(s.ctl.target >= before * 3 / 4);

    // a refused call (the core's feed queue is full): halved at the next sample
    var r: Sim = .{ .rtt_ms = 250, .apply_per_ks = 100_000, .cap = 64, .refuse_from_ms = 40_000, .refuse_to_ms = 40_300 };
    r.start();
    try r.run(40_000);
    const high = r.ctl.target;
    try r.run(1_000);
    try testing.expect(r.errors > 0);
    try testing.expect(r.ctl.target <= high / 2);
    try testing.expect(r.max_occupied <= r.window);
}

test "in-flight controller: more in flight that does not fetch faster (a connection or a core that is the bound) is taken back" {
    // each response costs 60 ms on the connection: 4 connections carry about 66 a second
    // whatever the count, and the apply stage wants 200
    var s: Sim = .{ .rtt_ms = 100, .per_response_us = 60_000, .apply_per_ks = 200_000, .cap = 64 };
    s.start();
    try s.run(120_000);
    try testing.expect(s.ctl.stats.plateaus > 0);
    // it keeps probing now and then, but does not sit at the cap
    var sum: u64 = 0;
    for (0..60_000) |_| {
        try s.step();
        sum += s.ctl.target;
    }
    try testing.expect(sum / 60_000 < 24);
}

test "in-flight controller: at the tip the count is the profile's, exactly, and the fixed setting (0) never changes it" {
    // 250 ms away, 300 checkpoints behind a chain that moves at 4 a second
    var s: Sim = .{ .rtt_ms = 250, .apply_per_ks = 100_000, .tip = 300, .tip_per_ks = 4_000 };
    s.start();
    // catch-up: more than the profile's 4 in flight
    while (!s.at_tip) {
        try s.step();
        try testing.expect(s.now_ms < 60_000);
    }
    try testing.expect(s.ctl.stats.peak > 4);
    try s.run(2_000);
    s.max_in_flight_at_tip = 0;
    s.requests_at_tip = 0;
    const t0 = s.now_ms;
    try s.run(30_000);
    try testing.expect(s.at_tip);
    try testing.expectEqual(@as(u32, 4), s.ctl.target);
    // one request at a time, as the frontier poll of the fixed fetcher
    try testing.expect(s.max_in_flight_at_tip <= 1);
    var f: Sim = .{ .rtt_ms = 250, .apply_per_ks = 100_000, .tip = 300, .tip_per_ks = 4_000, .cap = 0 };
    f.start();
    while (!f.at_tip) try f.step();
    try f.run(2_000);
    f.requests_at_tip = 0;
    try f.run(s.now_ms - t0);
    // the same load on the core at the tip: one request per round trip (the two runs reach
    // the tip at different moments, so their polls are a phase apart)
    try testing.expect(@max(f.requests_at_tip, s.requests_at_tip) - @min(f.requests_at_tip, s.requests_at_tip) <= 2);
    try testing.expect(s.requests_at_tip <= 30_000 / 250 + 2);
    try testing.expectEqual(@as(u32, 4), f.ctl.target);
    try testing.expectEqual(@as(u64, 0), f.ctl.stats.grows);

    // direct: whatever the samples say, at the tip and with cap 0
    var c = Controller.init(.{ .floor = 4, .cap = 64, .window = 32 });
    c.target = 20;
    try testing.expectEqual(@as(u32, 4), c.tick(.{ .now_ns = 1, .applied = 0, .fetched = 0, .stall_ns = 0, .errors = 0, .at_tip = true }));
    var z = Controller.init(.{ .floor = 4, .cap = 0, .window = 32 });
    for (1..100) |i| try testing.expectEqual(@as(u32, 4), z.tick(.{ .now_ns = i * 1000 * ms, .applied = i, .fetched = i, .stall_ns = i * 900 * ms, .errors = 0, .call_ns = 250 * ms }));
}

test "in-flight controller: bounds and the split over the fetch threads" {
    var c = Controller.init(.{ .floor = 4, .cap = 64, .window = 32 });
    try testing.expectEqual(@as(u32, 32), c.limit()); // the window is the tighter bound
    c = Controller.init(.{ .floor = 4, .cap = 16, .window = 128 });
    try testing.expectEqual(@as(u32, 16), c.limit());
    c = Controller.init(.{ .floor = 8, .cap = 4, .window = 128 });
    try testing.expectEqual(@as(u32, 8), c.limit()); // never below the profile's
    // 10 over 4 threads: 3, 3, 2, 2; the floor: one each
    var sum: u32 = 0;
    for (0..4) |i| sum += Controller.depth(10, @intCast(i), 4);
    try testing.expectEqual(@as(u32, 10), sum);
    try testing.expectEqual(@as(u32, 3), Controller.depth(10, 0, 4));
    try testing.expectEqual(@as(u32, 2), Controller.depth(10, 3, 4));
    for (0..4) |i| try testing.expectEqual(@as(u32, 1), Controller.depth(4, @intCast(i), 4));
    // an error halves at once and holds: starved samples right after do not grow it
    c = Controller.init(.{ .floor = 4, .cap = 64, .window = 64 });
    c.target = 40;
    _ = c.tick(.{ .now_ns = 0, .applied = 0, .fetched = 0, .stall_ns = 0, .errors = 0 });
    try testing.expectEqual(@as(u32, 20), c.tick(.{ .now_ns = 10 * ms, .applied = 0, .fetched = 0, .stall_ns = 0, .errors = 1 }));
    var now: u64 = 10 * ms;
    var stall: u64 = 0;
    for (0..8) |_| {
        now += 300 * ms;
        stall += 290 * ms;
        try testing.expectEqual(@as(u32, 20), c.tick(.{ .now_ns = now, .applied = 0, .fetched = 0, .stall_ns = stall, .errors = 1, .call_ns = 100 * ms }));
    }
    now += 300 * ms;
    stall += 290 * ms;
    try testing.expectEqual(@as(u32, 25), c.tick(.{ .now_ns = now, .applied = 0, .fetched = 0, .stall_ns = stall, .errors = 1, .call_ns = 100 * ms }));
}
