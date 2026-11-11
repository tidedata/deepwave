//! Sender-side congestion control pieces for conn.zig. Each is behind a `Config` switch that is
//! off by default, and with every switch off the connection runs exactly the NewReno in conn.zig.
//! Nothing here changes a byte a peer can tell apart from the old sender: only when datagrams
//! leave and how many may be in flight.
//!
//!   Pacer    RFC 9002 section 7.7: sends are spread over the round trip instead of leaving as
//!            one window-sized burst.
//!   HyStart  RFC 9406 (HyStart++): leaves slow start when the round-trip time rises, before
//!            the bottleneck queue overflows.
//!   Cubic    RFC 9438: the window function quinn and the browsers use.
const std = @import("std");

const ms = std.time.ns_per_ms;
const sec = std.time.ns_per_s;
const inf = std.math.maxInt(u64);

/// A token bucket in bytes, refilled at `gain * cwnd / srtt`. A datagram leaves at once while
/// the bucket holds it. When the bucket is empty the sender waits until it holds everything the
/// window still allows, or is full (not for one datagram), so paced traffic still leaves in
/// runs that one sendmmsg call, and one GSO super-packet, can carry. The bucket holds 2 ms of
/// the window, at least 10 and at most 64 datagrams (the listener's per-pass cap, and one GSO
/// run).
pub const Pacer = struct {
    tokens: u64 = 0,
    capacity: u64 = 0,
    prev: u64 = 0,
    last_cwnd: u64 = 0,
    last_mtu: u64 = 0,
    started: bool = false,

    pub const burst_interval_ns = 2 * ms;
    pub const min_burst = 10;
    pub const max_burst = 64;

    fn capacityFor(srtt: u64, cwnd: u64, mtu: u64) u64 {
        const w: u64 = @min(cwnd, 1 << 32);
        const c = w * burst_interval_ns / @max(srtt, 1);
        return std.math.clamp(c, min_burst * mtu, max_burst * mtu);
    }

    /// null: a datagram (of up to `mtu` bytes) may leave now. Otherwise the time from which the
    /// next run may: when the bucket holds `room` (what the window still allows), at least one
    /// datagram and at most the bucket. `gain_num / gain_den` is the pacing gain (5/4 in
    /// congestion avoidance, 2 in slow start, where the window doubles within the round trip).
    pub fn delay(p: *Pacer, now: u64, srtt: u64, cwnd: u64, mtu: u64, room: u64, gain_num: u64, gain_den: u64) ?u64 {
        if (cwnd != p.last_cwnd or mtu != p.last_mtu or !p.started) {
            p.capacity = capacityFor(srtt, cwnd, mtu);
            if (!p.started) {
                p.started = true;
                p.tokens = p.capacity;
                p.prev = now;
            }
            p.tokens = @min(p.tokens, p.capacity);
            p.last_cwnd = cwnd;
            p.last_mtu = mtu;
        }
        if (p.tokens >= mtu) return null;
        if (srtt == 0 or cwnd == 0) return null;
        // explicit u64: @min with a constant bound would give a narrower type and overflow
        const w: u64 = @min(cwnd, 1 << 32);
        const elapsed: u64 = @min(now -| p.prev, 2 * sec);
        const add: u64 = (w * elapsed / srtt) *| gain_num / gain_den;
        if (add > 0) {
            p.tokens = @min(p.tokens +| add, p.capacity);
            p.prev = now;
        }
        if (p.tokens >= mtu) return null;
        const need = std.math.clamp(room, mtu, p.capacity) - p.tokens;
        const wait: u64 = (srtt *| need / w) *| gain_den / gain_num;
        return now + @max(wait, 1);
    }

    pub fn onSend(p: *Pacer, bytes: u64) void {
        p.tokens -|= bytes;
    }
};

/// HyStart++ (RFC 9406). The caller feeds every ACK of the application space that arrives
/// during the first slow start; `divisor` is the slow-start growth divisor (1, or 4 in
/// conservative slow start) and `exit` says the window has reached congestion avoidance.
pub const HyStart = struct {
    /// The round ends when a packet number at or past this one is acknowledged.
    window_end: ?u64 = null,
    last_min: u64 = inf,
    cur_min: u64 = inf,
    samples: u32 = 0,
    css_baseline: u64 = inf,
    css_rounds: u8 = 0,
    in_css: bool = false,

    pub const min_rtt_thresh = 4 * ms;
    pub const max_rtt_thresh = 16 * ms;
    pub const min_rtt_divisor = 8;
    pub const n_rtt_sample = 8;
    pub const css_growth_divisor = 4;
    pub const css_rounds_max = 5;
    /// Segments one ACK may add to the window when the sender is not paced (RFC 9406 4.3).
    pub const l_unpaced = 8;

    pub const Step = struct { divisor: u8 = 1, exit: bool = false };

    /// `largest_acked` and `next_pn` are packet numbers of the application space; `rtt` is the
    /// round-trip sample this ACK produced, if it produced one.
    pub fn onAck(h: *HyStart, largest_acked: u64, next_pn: u64, rtt: ?u64) Step {
        if (h.window_end == null) h.window_end = next_pn;
        if (rtt) |r| {
            h.cur_min = @min(h.cur_min, r);
            h.samples += 1;
        }
        var step: Step = .{};
        if (!h.in_css) {
            if (h.samples >= n_rtt_sample and h.cur_min != inf and h.last_min != inf) {
                const thresh: u64 = @max(min_rtt_thresh, @min(h.last_min / min_rtt_divisor, max_rtt_thresh));
                if (h.cur_min >= h.last_min +| thresh) {
                    h.css_baseline = h.cur_min;
                    h.in_css = true;
                    h.css_rounds = 0;
                }
            }
        } else if (h.samples >= n_rtt_sample and h.cur_min < h.css_baseline) {
            // the delay went back down: the exit was spurious, slow start resumes
            h.css_baseline = inf;
            h.in_css = false;
        }
        if (largest_acked >= h.window_end.?) {
            // a round is over
            if (h.in_css) {
                h.css_rounds += 1;
                if (h.css_rounds >= css_rounds_max) step.exit = true;
            }
            h.last_min = h.cur_min;
            h.cur_min = inf;
            h.samples = 0;
            h.window_end = next_pn;
        }
        if (h.in_css) step.divisor = css_growth_divisor;
        return step;
    }
};

/// CUBIC (RFC 9438) congestion avoidance and its response to a congestion event. Slow start is
/// the caller's. Windows are in bytes.
pub const Cubic = struct {
    /// Window just before the last reduction (after fast convergence).
    w_max: f64 = 0,
    /// Window just before the last reduction, as it was (RFC 9438 cwnd_prior): the Reno-friendly
    /// estimate grows at `alpha` until it is back there, then by one segment per window.
    w_prior: f64 = 0,
    /// Seconds from the epoch start until the window function reaches `w_max`.
    k: f64 = 0,
    /// Start of the current congestion avoidance epoch (null: starts at the next ACK).
    epoch: ?u64 = null,
    /// The Reno-friendly estimate (RFC 9438 section 4.3).
    w_est: f64 = 0,
    /// Growth below one byte, carried to the next ACK.
    carry: f64 = 0,
    /// Packets sent at or before this time do not grow the window and do not start another
    /// reduction (RFC 9002 section 7.3.2: one reduction per round trip).
    recovery_start: ?u64 = null,

    pub const beta = 0.7;
    pub const c = 0.4;
    const alpha = 3.0 * (1.0 - beta) / (1.0 + beta);

    pub fn inRecovery(cb: *const Cubic, sent_time: u64) bool {
        return if (cb.recovery_start) |t| sent_time <= t else false;
    }

    /// An ACK of `acked` bytes in congestion avoidance. `limited`: the congestion window, not
    /// the application, is what held the sender back (RFC 9438 section 5.8: no growth otherwise).
    pub fn onAck(cb: *Cubic, now: u64, acked: u64, cwnd: *u64, mtu: u64, srtt: u64, limited: bool) void {
        if (!limited) {
            // the window was not used: the next epoch starts from where the window is then
            cb.epoch = null;
            return;
        }
        const m: f64 = @floatFromInt(mtu);
        const w: f64 = @floatFromInt(cwnd.*);
        if (cb.epoch == null) {
            cb.epoch = now;
            cb.w_est = w;
            cb.carry = 0;
            if (w >= cb.w_max) {
                cb.w_max = w;
                cb.k = 0;
            } else cb.k = std.math.cbrt((cb.w_max - w) / (c * m));
        }
        const t = @as(f64, @floatFromInt(now - cb.epoch.?)) / sec;
        const rtt = @as(f64, @floatFromInt(srtt)) / sec;
        const a: f64 = @floatFromInt(acked);
        cb.w_est += @as(f64, if (cb.w_est >= cb.w_prior) 1.0 else alpha) * a * m / w;
        const d = t - cb.k;
        const w_cubic = c * d * d * d * m + cb.w_max;
        var inc: f64 = 0;
        if (w_cubic < cb.w_est) {
            // Reno-friendly region
            if (cb.w_est > w) inc = cb.w_est - w;
        } else {
            const d2 = t + rtt - cb.k;
            const target = std.math.clamp(c * d2 * d2 * d2 * m + cb.w_max, w, 1.5 * w);
            inc = (target - w) / w * a;
        }
        cb.carry += inc;
        if (cb.carry >= 1.0) {
            const whole = @floor(cb.carry);
            cwnd.* += @intFromFloat(whole);
            cb.carry -= whole;
        }
    }

    /// A packet sent at `sent_time` was lost. Returns false when it belongs to the reduction
    /// already made.
    pub fn onCongestion(cb: *Cubic, now: u64, sent_time: u64, cwnd: *u64, ssthresh: *u64, mtu: u64) bool {
        if (cb.inRecovery(sent_time)) return false;
        cb.recovery_start = now;
        const w: f64 = @floatFromInt(cwnd.*);
        cb.w_prior = w;
        // fast convergence (RFC 9438 section 4.7): a flow that lost before regaining its old
        // window gives room to newer flows
        cb.w_max = if (w < cb.w_max) w * (1.0 + beta) / 2.0 else w;
        ssthresh.* = @max(cwnd.* * 7 / 10, 2 * mtu);
        cwnd.* = ssthresh.*;
        cb.epoch = null;
        cb.carry = 0;
        return true;
    }
};

test "pacer: a full bucket leaves at once, an empty one waits for a full refill" {
    var p: Pacer = .{};
    const mtu: u64 = 1200;
    const srtt: u64 = 50 * ms;
    const cwnd: u64 = 120_000; // 100 datagrams
    // capacity: 2 ms of a 100-datagram window per 50 ms is 4 datagrams, so the floor of 10
    var sent: u64 = 0;
    while (p.delay(0, srtt, cwnd, mtu, cwnd, 5, 4) == null) : (sent += 1) p.onSend(mtu);
    try std.testing.expectEqual(@as(u64, 10), sent);
    const t = p.delay(0, srtt, cwnd, mtu, cwnd, 5, 4).?;
    // 10 datagrams at 1.25 * 100 per 50 ms is 4 ms
    try std.testing.expectEqual(@as(u64, 4 * ms), t);
    // asked again a little later, the answer is the same instant
    try std.testing.expectEqual(@as(?u64, t), p.delay(100_000, srtt, cwnd, mtu, cwnd, 5, 4));
    // when the window has room for two datagrams only, the wait is for those two (0.8 ms)
    try std.testing.expectEqual(@as(?u64, 800_000), p.delay(100_000, srtt, cwnd, mtu, 2 * mtu, 5, 4));
    try std.testing.expectEqual(@as(?u64, null), p.delay(t, srtt, cwnd, mtu, cwnd, 5, 4));
    // over one round trip from a full bucket: the bucket plus 1.25 windows, never more
    var q: Pacer = .{};
    var now: u64 = 0;
    var total: u64 = 0;
    while (now <= srtt) {
        if (q.delay(now, srtt, cwnd, mtu, cwnd, 5, 4)) |at| {
            now = at;
            continue;
        }
        q.onSend(mtu);
        total += mtu;
    }
    try std.testing.expect(total <= 10 * mtu + cwnd * 5 / 4 + mtu);
    try std.testing.expect(total >= cwnd);
}

test "pacer: the bucket is 2 ms of the window, capped at 64 datagrams" {
    try std.testing.expectEqual(@as(u64, 10 * 1452), Pacer.capacityFor(100 * ms, 14_520, 1452));
    try std.testing.expectEqual(@as(u64, 60_000), Pacer.capacityFor(20 * ms, 600_000, 1452));
    try std.testing.expectEqual(@as(u64, 64 * 1452), Pacer.capacityFor(100_000, 10 << 20, 1452));
}

test "hystart++: a round whose minimum RTT rises past the threshold enters CSS; five CSS rounds exit" {
    var h: HyStart = .{};
    var pn: u64 = 0;
    // round 1 at 40 ms, round 2 at 40 ms: no exit
    for (0..2) |_| {
        const end = pn + 20;
        while (pn < end) : (pn += 1) {
            const s = h.onAck(pn, end, 40 * ms);
            try std.testing.expectEqual(@as(u8, 1), s.divisor);
            try std.testing.expect(!s.exit);
        }
    }
    try std.testing.expect(!h.in_css);
    // round 3 at 46 ms: 40 / 8 = 5 ms threshold, reached at the round's 8th sample (the first
    // ACK of this batch closes round 2)
    var end = pn + 20;
    var k: u32 = 0;
    while (pn < end) : (pn += 1) {
        const s = h.onAck(pn, end, 46 * ms);
        k += 1;
        try std.testing.expectEqual(@as(u8, if (k >= 9) 4 else 1), s.divisor);
    }
    try std.testing.expect(h.in_css);
    // CSS lasts five round ends, the round that entered it included
    var exited = false;
    var rounds: u32 = 0;
    while (!exited and rounds < 10) : (rounds += 1) {
        end = pn + 20;
        while (pn < end) : (pn += 1) {
            if (h.onAck(pn, end, 47 * ms).exit) exited = true;
        }
    }
    try std.testing.expect(exited);
    try std.testing.expectEqual(@as(u32, 5), rounds);
}

test "hystart++: a CSS round whose RTT falls below the baseline resumes slow start" {
    var h: HyStart = .{};
    var pn: u64 = 0;
    for ([_]u64{ 40, 40, 50 }) |rtt| {
        const end = pn + 20;
        while (pn < end) : (pn += 1) _ = h.onAck(pn, end, rtt * ms);
    }
    try std.testing.expect(h.in_css);
    const end = pn + 20;
    while (pn < end) : (pn += 1) _ = h.onAck(pn, end, 41 * ms);
    try std.testing.expect(!h.in_css);
    // small thresholds are floored at 4 ms and large ones capped at 16 ms
    var g: HyStart = .{};
    pn = 0;
    for ([_]u64{ 400, 400, 415 }) |rtt| {
        const e = pn + 20;
        while (pn < e) : (pn += 1) _ = g.onAck(pn, e, rtt * ms);
    }
    try std.testing.expect(!g.in_css);
    const e = pn + 20;
    while (pn < e) : (pn += 1) _ = g.onAck(pn, e, 432 * ms);
    try std.testing.expect(g.in_css);
}

test "cubic: reduction to 0.7, fast convergence, and the window function regains w_max at K" {
    var cb: Cubic = .{};
    const mtu: u64 = 1200;
    var cwnd: u64 = 100 * mtu;
    var ssthresh: u64 = inf;
    try std.testing.expect(cb.onCongestion(1 * sec, 900 * ms, &cwnd, &ssthresh, mtu));
    try std.testing.expectEqual(@as(u64, 70 * mtu), cwnd);
    try std.testing.expectEqual(cwnd, ssthresh);
    try std.testing.expectEqual(@as(f64, 100 * 1200), cb.w_max);
    // a packet sent before the reduction is part of it
    try std.testing.expect(!cb.onCongestion(1 * sec + 10 * ms, 990 * ms, &cwnd, &ssthresh, mtu));
    try std.testing.expectEqual(@as(u64, 70 * mtu), cwnd);
    // K = cbrt((100 - 70) / 0.4) = 4.217 s: ACK-clocked at a 200 ms round trip (long enough
    // that Reno's estimate stays below) the window is back at w_max there, and above it later
    var now: u64 = 1 * sec + 20 * ms;
    const rtt: u64 = 200 * ms;
    var at_k: u64 = 0;
    while (now < 1 * sec + 20 * ms + 8 * sec) : (now += rtt) {
        // one round: the whole window acknowledged in ten ACKs
        for (0..10) |_| cb.onAck(now, cwnd / 10, &cwnd, mtu, rtt, true);
        if (at_k == 0 and now >= 1 * sec + 20 * ms + 4217 * ms) at_k = cwnd;
    }
    try std.testing.expect(at_k >= 96 * mtu and at_k <= 103 * mtu);
    try std.testing.expect(cwnd > 110 * mtu);
    // a loss below the old maximum: w_max is set under the current window
    cwnd = 80 * mtu;
    cb.w_max = 100 * 1200;
    try std.testing.expect(cb.onCongestion(now, now - 1, &cwnd, &ssthresh, mtu));
    try std.testing.expectApproxEqAbs(@as(f64, 80.0 * 1200.0 * 0.85), cb.w_max, 0.001);
    try std.testing.expectEqual(@as(u64, 56 * mtu), cwnd);
}

test "cubic: after fast convergence the Reno estimate keeps alpha until the window before the loss" {
    var cb: Cubic = .{};
    const mtu: u64 = 1200;
    var cwnd: u64 = 100 * mtu;
    var ssthresh: u64 = inf;
    // an older, larger maximum: fast convergence puts w_max at 85 datagrams, under the 100 the
    // window had when the loss came
    cb.w_max = 200 * 1200;
    try std.testing.expect(cb.onCongestion(0, 0, &cwnd, &ssthresh, mtu));
    try std.testing.expectApproxEqAbs(@as(f64, 85.0 * 1200.0), cb.w_max, 0.001);
    try std.testing.expectEqual(@as(f64, 100 * 1200), cb.w_prior);
    try std.testing.expectEqual(@as(u64, 70 * mtu), cwnd);
    // 45 round trips of 1 ms (the cubic term is still flat, so the window follows the Reno
    // estimate): 0.53 datagrams per round trip all the way, 70 + 45 * 0.53 = 93.8. Switching to
    // one datagram per round trip at w_max (85) would give 102.
    var now: u64 = ms;
    for (0..45) |_| {
        for (0..10) |_| cb.onAck(now, cwnd / 10, &cwnd, mtu, ms, true);
        now += ms;
    }
    try std.testing.expect(cwnd > 93 * mtu and cwnd < 95 * mtu);
}

test "cubic: Reno-friendly growth at a short round trip, none while the application is the limit" {
    var cb: Cubic = .{};
    const mtu: u64 = 1200;
    var cwnd: u64 = 20 * mtu;
    var ssthresh: u64 = inf;
    _ = cb.onCongestion(0, 0, &cwnd, &ssthresh, mtu);
    try std.testing.expectEqual(@as(u64, 14 * mtu), cwnd);
    // application-limited ACKs do not grow the window
    var now: u64 = 10 * ms;
    for (0..100) |_| {
        cb.onAck(now, mtu, &cwnd, mtu, 10 * ms, false);
        now += ms;
    }
    try std.testing.expectEqual(@as(u64, 14 * mtu), cwnd);
    // one round trip of ACKs at 1 ms: Reno's estimate adds alpha (0.53) segments per window
    const before = cwnd;
    for (0..14) |_| cb.onAck(now, mtu, &cwnd, mtu, ms, true);
    try std.testing.expect(cwnd > before + mtu / 3 and cwnd < before + mtu);
}
