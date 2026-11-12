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
//!   Bbr      draft-ietf-ccwg-bbr-07 (BBRv3): a model of the path (delivery rate, minimum round
//!            trip) sets the pacing rate and the window, so random loss does not cap the rate.
const std = @import("std");

const ms = std.time.ns_per_ms;
const sec = std.time.ns_per_s;
const inf = std.math.maxInt(u64);

/// A token bucket in bytes. A datagram leaves at once while the bucket holds it. When the
/// bucket is empty the sender waits until it holds one run, or what the window still allows
/// (not one datagram), so paced traffic still leaves in runs that one sendmmsg call, and one
/// GSO super-packet, can carry.
///
/// Two modes. `delay`: the rate is `gain * cwnd / srtt` and a run is 2 ms of the window, at
/// least 10 and at most 64 datagrams (the listener's per-pass cap, and one GSO run).
/// `delayRate`: BBR's own pacing rate and send quantum.
///
/// The pacer never asks to be woken sooner than `timer_ns` from now. The loops that drive
/// connections (the zui/1 listener, the edge client) block in the kernel in whole milliseconds
/// and poll the socket without blocking for a timer that is due sooner: a pacer deadline a
/// fraction of a millisecond away made the I/O thread spin until it was due, at every run. So
/// that the longer sleep costs no rate, the bucket holds at least what the rate brings in one
/// such wait: what built up while the thread slept leaves with the next run.
///
/// A sender that waits for the bucket and is woken late keeps what the rate brought while it
/// was late, up to `late_max_ns` of it, on top of the bucket. A wake is late when the loop's
/// timer is coarse: a socket receive timeout on Linux is counted in jiffies and fires one to
/// two jiffies after it was set, 4 to 8 ms at HZ=250 for a wait of 1.25 ms. With the bucket as
/// the limit (2 ms of BBR's rate) every such sleep threw away what the rate brought after the
/// first 2 ms, and a paced sender ran at a quarter to a half of its rate. The credit is for a
/// late wake only: a sender that had nothing to send, or that something else held for longer
/// (a full window), starts from the bucket, as before.
pub const Pacer = struct {
    tokens: u64 = 0,
    capacity: u64 = 0,
    prev: u64 = 0,
    started: bool = false,
    /// The last answer was a time to wait for (`due`): the sender has something to send.
    waiting: bool = false,
    due: u64 = 0,
    /// The last answer was "send" and nothing has left since (the sender had nothing).
    granted: bool = false,
    /// Bytes the bucket may hold beyond `capacity` now: the credit of a late wake, until the
    /// sender has used it or has nothing more to send.
    late: u64 = 0,

    pub const burst_interval_ns = 2 * ms;
    pub const min_burst = 10;
    pub const max_burst = 64;
    /// Shortest wait the pacer asks for: just over the millisecond the loops can sleep.
    pub const timer_ns = 1250 * std.time.ns_per_us;
    /// A wake up to this long after the time asked for is a late timer and keeps its credit
    /// (two jiffies at HZ=250, one at HZ=100); a later one is not.
    pub const late_max_ns = 10 * ms;

    fn runFor(srtt: u64, cwnd: u64, mtu: u64) u64 {
        const w: u64 = @min(cwnd, 1 << 32);
        const c = w * burst_interval_ns / @max(srtt, 1);
        return std.math.clamp(c, min_burst * mtu, max_burst * mtu);
    }

    /// null: a datagram (of up to `mtu` bytes) may leave now. Otherwise the time from which the
    /// next run may: when the bucket holds `room` (what the window still allows), at least one
    /// datagram and at most one run. `gain_num / gain_den` is the pacing gain (5/4 in
    /// congestion avoidance, 2 in slow start, where the window doubles within the round trip).
    pub fn delay(p: *Pacer, now: u64, srtt: u64, cwnd: u64, mtu: u64, room: u64, gain_num: u64, gain_den: u64) ?u64 {
        if (srtt == 0 or cwnd == 0) return null;
        // explicit u64: @min with a constant bound would give a narrower type and overflow
        const w: u64 = @min(cwnd, 1 << 32);
        const rate: u64 = @intCast(@min(@as(u128, w) * gain_num * sec / (@as(u128, srtt) * gain_den), 1 << 40));
        const run = runFor(srtt, cwnd, mtu);
        return p.wait(now, rate, mtu, room, run, run);
    }

    /// Rate mode (BBR, whose pacing rate is its own): the bucket fills at `rate` bytes per
    /// second and a run is `quantum` bytes (BBR's send quantum: 1 ms of the rate, at least two
    /// datagrams). The bucket holds at least two quanta.
    pub fn delayRate(p: *Pacer, now: u64, rate: u64, mtu: u64, room: u64, quantum: u64) ?u64 {
        return p.delayBurst(now, rate, mtu, room, quantum, 0);
    }

    /// `delayRate` with a bucket of at least `depth` bytes (`Bbr.burstAllowance`). The bucket
    /// still fills at `rate` only, so what leaves at once after a pause is what the rate
    /// brought during the pause, and never more than `depth`.
    pub fn delayBurst(p: *Pacer, now: u64, rate: u64, mtu: u64, room: u64, quantum: u64, depth: u64) ?u64 {
        const run = @max(quantum, mtu);
        return p.waitDepth(now, rate, mtu, room, run, 2 * run, depth);
    }

    fn wait(p: *Pacer, now: u64, rate: u64, mtu: u64, room: u64, run: u64, min_cap: u64) ?u64 {
        return p.waitDepth(now, rate, mtu, room, run, min_cap, 0);
    }

    fn waitDepth(p: *Pacer, now: u64, rate: u64, mtu: u64, room: u64, run: u64, min_cap: u64, depth: u64) ?u64 {
        const cap: u64 = @max(min_cap, depth, @as(u64, @intCast(@as(u128, rate) * timer_ns / sec)));
        if (!p.started) {
            p.started = true;
            p.tokens = min_cap;
            p.prev = now;
        }
        p.capacity = cap;
        // permission that was not used: the sender had nothing to send, so no late credit
        if (p.granted) p.late = 0;
        p.tokens = @min(p.tokens, @max(cap, p.late));
        if (rate == 0) return null;
        // fill first, so idle time is credited once (never more than the bucket, except for
        // a sender that waited for this and was woken late)
        const elapsed: u64 = @min(now -| p.prev, 2 * sec);
        const add: u64 = @intCast(@as(u128, rate) * elapsed / sec);
        if (add > 0) {
            const lateness = now -| p.due;
            if (p.waiting and lateness <= late_max_ns) p.late = cap + @as(u64, @intCast(@as(u128, rate) * lateness / sec));
            p.tokens = @min(p.tokens +| add, @max(cap, p.late));
            p.prev = now;
        }
        if (p.tokens >= mtu) {
            p.waiting = false;
            p.granted = true;
            return null;
        }
        p.waiting = true;
        p.granted = false;
        p.late = 0;
        const need = std.math.clamp(room, mtu, run) - p.tokens;
        const t: u64 = @intCast(@min(@as(u128, need) * sec / rate, 10 * sec));
        p.due = now + @max(t, timer_ns);
        return p.due;
    }

    pub fn onSend(p: *Pacer, bytes: u64) void {
        p.tokens -|= bytes;
        p.granted = false;
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

/// A windowed maximum over a count of rounds (Kathleen Nichols' filter, as in Linux
/// lib/win_minmax.c): the best, second best and third best sample of the window.
pub const MaxFilter = struct {
    s: [3]Sample = @splat(.{}),

    const Sample = struct { t: u64 = 0, v: u64 = 0 };

    pub fn get(f: *const MaxFilter) u64 {
        return f.s[0].v;
    }

    pub fn update(f: *MaxFilter, win: u64, t: u64, v: u64) u64 {
        const val: Sample = .{ .t = t, .v = v };
        if (v >= f.s[0].v or t - f.s[2].t > win) {
            f.s = @splat(val);
            return v;
        }
        if (v >= f.s[1].v) {
            f.s[1] = val;
            f.s[2] = val;
        } else if (v >= f.s[2].v) f.s[2] = val;
        const dt = t - f.s[0].t;
        if (dt > win) {
            // the best sample left the window: the next best take its place
            f.s[0] = f.s[1];
            f.s[1] = f.s[2];
            f.s[2] = val;
            if (t - f.s[0].t > win) {
                f.s[0] = f.s[1];
                f.s[1] = f.s[2];
                f.s[2] = val;
            }
        } else if (f.s[1].t == f.s[0].t and dt > win / 4) {
            f.s[1] = val;
            f.s[2] = val;
        } else if (f.s[2].t == f.s[1].t and dt > win / 2) {
            f.s[2] = val;
        }
        return f.s[0].v;
    }
};

/// BBR congestion control, draft-ietf-ccwg-bbr-07 ("BBRv3"). Section numbers below are that
/// draft's, and the function names follow its pseudocode. The connection feeds it every packet
/// sent (`onSent`), every packet newly acknowledged (`ackBegin`, `onPacketAcked` each, then
/// `onAck` once per ACK frame) and every packet declared lost (`onPacketLost`, before the
/// `onAck` of the ACK that revealed it, as Linux orders the two). It writes the congestion
/// window through the pointer it is given, and the connection reads `pacing_rate` and
/// `send_quantum` for its pacer.
///
/// Volumes are bytes, rates bytes per second, times nanoseconds; gains are in hundredths.
/// Not implemented: the undo of a spurious loss recovery (5.5.11.2; the connection does not
/// detect spurious losses), the window collapse on a retransmission timeout (5.6.4.4; a QUIC
/// probe timeout is not one, and the connection has no persistent-congestion state), and ECN
/// (3.7: the draft leaves it out as well).
pub const Bbr = struct {
    pub const State = enum { startup, drain, probe_bw_down, probe_bw_cruise, probe_bw_refill, probe_bw_up, probe_rtt };

    // Constants (section 2).
    /// 4 * ln(2): the smallest gain that lets the sending rate double each round (2.5).
    pub const startup_pacing_gain = 277;
    pub const drain_pacing_gain = 50;
    pub const default_cwnd_gain = 200;
    /// The ProbeBW gains (5.3.3.1 to 5.3.3.5 and the table in 5.6.1).
    pub const down_pacing_gain = 90;
    pub const cruise_pacing_gain = 100;
    pub const refill_pacing_gain = 100;
    pub const up_pacing_gain = 125;
    pub const up_cwnd_gain = 225;
    pub const probe_rtt_cwnd_gain = 50;
    pub const pacing_margin_percent = 1;
    /// BBR.LossThresh, 2 percent, as a divisor.
    pub const loss_thresh_div = 50;
    /// BBR.Beta, 0.7.
    pub const beta_num = 7;
    pub const beta_den = 10;
    /// BBR.Headroom, 0.15.
    pub const headroom_percent = 15;
    /// BBR.MinPipeCwnd, in datagrams.
    pub const min_pipe_cwnd = 4;
    pub const extra_acked_filter_len = 10;
    pub const startup_full_loss_cnt = 6;
    /// A round counts as growth when the delivery rate rose by a quarter; three rounds
    /// without growth are a plateau (5.3.1.2).
    pub const full_bw_growth_percent = 125;
    pub const full_bw_rounds = 3;
    pub const min_rtt_filter_len = 10 * sec;
    pub const probe_rtt_duration = 200 * ms;
    /// The wall-clock wait between bandwidth probes is 2 to 3 seconds, and never more rounds
    /// than a Reno flow of this many datagrams would need (5.3.3.8.2).
    pub const probe_wait_base = 2 * sec;
    pub const probe_wait_rand = 1 * sec;
    pub const reno_rounds_max = 63;
    pub const send_quantum_max = 64 << 10;
    /// Sends closer together than this are one burst (paced runs are 1.25 ms apart or more).
    pub const burst_gap = 1 * ms;
    /// A burst bound is tried again after this long (as the path MTU search starts again).
    pub const burst_cap_ttl = 600 * sec;

    /// What `onSent` snapshots for a packet (4.1.2.1.2); the connection keeps it with the
    /// packet and hands it back when the packet is acknowledged or lost.
    pub const Pkt = struct {
        delivered: u64 = 0,
        delivered_time: u64 = 0,
        first_send_time: u64 = 0,
        lost: u64 = 0,
        /// Bytes in flight right after this packet was sent (it included).
        tx_in_flight: u64 = 0,
        app_limited: bool = false,
        /// A quiet sender's burst: bytes that left in one go up to and including this packet
        /// (`burst_gap`). 0 for a sender with a backlog.
        burst: u32 = 0,
    };

    /// The rate sample of one ACK (2.3 and 4.1.2.1.3).
    pub const Rs = struct {
        has_data: bool = false,
        rtt: ?u64 = null,
        newly_acked: u64 = 0,
        prior_delivered: u64 = 0,
        prior_lost: u64 = 0,
        is_app_limited: bool = false,
        send_elapsed: u64 = 0,
        ack_elapsed: u64 = 0,
        last_pn: u64 = 0,
        /// Send time of the newest packet this ACK acknowledged.
        newest_sent: u64 = 0,
        interval: u64 = 0,
        delivered: u64 = 0,
        /// 0: this ACK gave no rate sample.
        delivery_rate: u64 = 0,
        tx_in_flight: u64 = 0,
        lost: u64 = 0,
    };

    /// What the connection knows when an ACK frame has been processed.
    pub const Ack = struct {
        now: u64,
        /// Bytes in flight once this ACK's packets, and the losses it revealed, are taken out.
        inflight: u64,
        /// In-flight bytes this ACK newly acknowledged.
        newly_acked: u64,
        /// The round-trip sample of this ACK, if it gave one.
        rtt: ?u64,
        /// The connection's lifetime minimum and smoothed round-trip time (C.min_rtt, C.srtt).
        min_rtt: u64,
        srtt: u64,
        /// Datagram size (C.SMSS).
        mtu: u64,
    };

    state: State = .startup,
    pacing_gain: u32 = startup_pacing_gain,
    cwnd_gain: u32 = default_cwnd_gain,
    /// Output: bytes per second, and the bytes of one paced run.
    pacing_rate: u64 = 0,
    send_quantum: u64 = 0,
    initial_cwnd: u64 = 0,
    mtu: u64 = 1200,
    /// The pacing rate has been set from a first round-trip sample (5.6.2).
    has_rtt: bool = false,
    rng: u64 = 0,

    // Delivery rate sampling (4.1.2.1.1).
    delivered: u64 = 0,
    delivered_time: u64 = 0,
    first_send_time: u64 = 0,
    /// Not 0: samples are application-limited until `delivered` passes this.
    app_limited: u64 = 0,
    /// Not 0: the application itself had nothing to send (`markAppLimited`, not the mark
    /// ProbeRTT sets on its own low rate), until `delivered` passes this. See `quiet`.
    app_quiet: u64 = 0,
    /// The largest flight the path delivered whole: bytes in flight when a packet left that
    /// was acknowledged with nothing lost in between. A round with loss lowers it as it
    /// lowers the short-term bounds.
    carried: u64 = 0,
    /// A quiet sender's bursts: bytes that left in one go (sends less than `burst_gap`
    /// apart). `burst_ok` is the largest that arrived whole. `burst_cap` bounds what leaves
    /// at once (`burstAllowance`): set when a burst lost its tail in the path's queue
    /// (`noteBurstLoss`), lifted again `burst_cap_ttl` later.
    burst_bytes: u64 = 0,
    burst_last: u64 = 0,
    burst_ok: u64 = 0,
    burst_cap: u64 = inf,
    burst_cap_stamp: u64 = 0,
    /// Packets lost of the burst that left at `burst_lost_at`, and whether the current loss
    /// round saw a burst lose its tail.
    burst_lost_at: u64 = 0,
    burst_lost_n: u32 = 0,
    burst_tail_round: bool = false,
    lost: u64 = 0,
    rs: Rs = .{},

    // Round counting (5.5.1).
    round_count: u64 = 0,
    round_start: bool = false,
    next_round_delivered: u64 = 0,
    idle_restart: bool = false,
    drain_start_round: u64 = 0,
    /// The window was full at some point of the current round, and of the one before
    /// (C.is_cwnd_limited is either).
    limited_now: bool = false,
    limited_prev: bool = false,

    // The model: data rate (2.9.1).
    /// The max filter over two ProbeBW cycles: the cycle before and the current one (5.5.6).
    max_bw_filter: [2]u64 = .{ 0, 0 },
    max_bw: u64 = 0,
    bw_shortterm: u64 = inf,
    bw: u64 = 0,
    // The model: data volume (2.9.2).
    min_rtt: u64 = inf,
    min_rtt_stamp: u64 = 0,
    min_rtt_expired: bool = false,
    extra_acked_interval_start: u64 = 0,
    extra_acked_delivered: u64 = 0,
    extra_acked_filter: MaxFilter = .{},
    extra_acked: u64 = 0,
    max_inflight: u64 = 0,
    inflight_longterm: u64 = inf,
    inflight_shortterm: u64 = inf,
    // Congestion signals (2.10).
    bw_latest: u64 = 0,
    inflight_latest: u64 = 0,
    loss_round_delivered: u64 = 0,
    loss_round_start: bool = false,
    is_loss_in_round: bool = false,
    loss_events_in_round: u32 = 0,
    // Startup (2.13).
    full_bw_reached: bool = false,
    full_bw_now: bool = false,
    full_bw: u64 = 0,
    full_bw_count: u32 = 0,
    // ProbeBW (2.14).
    is_bw_probe_stopping: bool = false,
    check_probe_loss: bool = false,
    bw_probe_up_acked: u64 = 0,
    probe_up_acked_per_inc: u64 = inf,
    bw_probe_up_rounds: u32 = 0,
    rounds_since_probe_up: u64 = 0,
    bw_probe_wait: u64 = 0,
    cycle_stamp: u64 = 0,
    prev_probe_too_high: bool = false,
    prev_probe_precautionary: bool = false,
    // ProbeRTT (2.16).
    probe_rtt_done_stamp: ?u64 = null,
    probe_rtt_round_done: bool = false,
    probe_rtt_cwnd: u64 = inf,
    prior_cwnd: u64 = 0,
    /// Loss recovery as RFC 9002 section 7.3.2 tracks it: from a loss until a packet sent after
    /// it is acknowledged.
    recovery_start: ?u64 = null,

    /// 5.2.1 OnInit. `seed` drives the randomized wait between bandwidth probes.
    pub fn init(now: u64, initial_cwnd: u64, mtu: u64, seed: u64) Bbr {
        var b: Bbr = .{ .initial_cwnd = initial_cwnd, .mtu = mtu, .rng = seed, .min_rtt_stamp = now, .extra_acked_interval_start = now };
        // InitPacingRate: no round-trip time yet, so the nominal rate is the window per 1 ms
        b.pacing_rate = mulDiv(initial_cwnd * startup_pacing_gain / 100, sec, ms);
        b.setSendQuantum();
        return b;
    }

    fn mulDiv(a: u64, m: u64, d: u64) u64 {
        const v = @as(u128, a) * m / d;
        return if (v > inf) inf else @intCast(v);
    }

    fn rand(b: *Bbr) u64 {
        // splitmix64
        b.rng +%= 0x9e3779b97f4a7c15;
        var z = b.rng;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    pub fn inProbeBw(b: *const Bbr) bool {
        return switch (b.state) {
            .probe_bw_down, .probe_bw_cruise, .probe_bw_refill, .probe_bw_up => true,
            else => false,
        };
    }

    pub fn isCwndLimited(b: *const Bbr) bool {
        return b.limited_now or b.limited_prev;
    }

    /// The connection could not send because the window was full.
    pub fn noteCwndLimited(b: *Bbr) void {
        b.limited_now = true;
    }

    // ---------------------------------------------------------------- per packet

    /// A packet of `size` bytes leaves at `now` with `inflight_before` bytes already in flight
    /// (5.2.2 OnTransmit, then 4.1.2.2 OnPacketSent).
    pub fn onSent(b: *Bbr, now: u64, inflight_before: u64, size: u64, cwnd: *u64) Pkt {
        // 5.4.1 HandleRestartFromIdle
        if (inflight_before == 0 and b.app_limited != 0) {
            b.idle_restart = true;
            b.extra_acked_interval_start = now;
            if (b.inProbeBw()) {
                b.setPacingRateWithGain(100);
            } else if (b.state == .probe_rtt) b.checkProbeRttDone(now, cwnd);
        }
        if (inflight_before == 0) {
            b.first_send_time = now;
            b.delivered_time = now;
        }
        if (now -| b.burst_last >= burst_gap or !b.quiet()) b.burst_bytes = 0;
        if (b.quiet()) b.burst_bytes += size;
        b.burst_last = now;
        return .{
            .burst = @intCast(@min(b.burst_bytes, std.math.maxInt(u32))),
            .delivered = b.delivered,
            .delivered_time = b.delivered_time,
            .first_send_time = b.first_send_time,
            .lost = b.lost,
            .tx_in_flight = inflight_before + size,
            .app_limited = b.app_limited != 0,
        };
    }

    /// 4.1.2.4 MarkConnectionAppLimited: the connection had window and pacing budget and
    /// nothing to send. Samples taken until what is in flight now has been delivered may
    /// understate the path.
    pub fn markAppLimited(b: *Bbr, inflight: u64) void {
        b.app_limited = @max(b.delivered + inflight, 1);
        b.app_quiet = b.app_limited;
    }

    /// The sender is limited by its application: it had window and pacing budget and nothing
    /// to send, and what it has sent since has not been delivered past that point. Such a
    /// sender (a response every 250 ms on a connection that is silent in between) never shows
    /// the model the path: a rate sample cannot exceed one burst per round trip, however much
    /// the path carries. Three things follow for it, and only for it:
    ///   - a burst after a pause is not paced from an empty bucket (`burstAllowance`),
    ///   - the window is not bounded below what the path has delivered whole (`carried`),
    ///   - no ProbeRTT: the path is empty of our packets between two bursts anyway, and the
    ///     packets that start a burst measure the round trip without a queue of ours.
    /// A sender with a backlog is not quiet (the mark is passed with the first acknowledgement
    /// of what it sends next, and nothing sets it again), so bulk transfers, and everything
    /// BBR does about congestion and loss, are as they were.
    pub fn quiet(b: *const Bbr) bool {
        return b.app_quiet != 0;
    }

    /// The pacer's bucket for a quiet sender: one minimum round trip of the pacing rate, at
    /// most the window, and at most what the path's queue has shown it takes in one go
    /// (`burst_cap`). 0 otherwise (the bucket is then two send quanta).
    pub fn burstAllowance(b: *const Bbr, cwnd: u64) u64 {
        if (!b.quiet() or b.min_rtt == inf) return 0;
        return @min(mulDiv(b.pacing_rate, b.min_rtt, sec), cwnd, b.burst_cap);
    }

    /// 4.1.2.3 InitRateSample.
    pub fn ackBegin(b: *Bbr) void {
        b.rs = .{};
    }

    /// 4.1.2.3 UpdateRateSample, for each packet an ACK newly acknowledges.
    pub fn onPacketAcked(b: *Bbr, now: u64, p: Pkt, send_time: u64, pn: u64, size: u64) void {
        b.delivered += size;
        b.delivered_time = now;
        // a burst arrived whole up to this packet (nothing lost since it left)
        if (p.lost == b.lost and p.burst > b.burst_ok and p.burst <= b.burst_cap) b.burst_ok = p.burst;
        const rs = &b.rs;
        // IsNewestPacket
        if (!rs.has_data or send_time > b.first_send_time or (send_time == b.first_send_time and pn > rs.last_pn)) {
            rs.has_data = true;
            rs.prior_delivered = p.delivered;
            rs.prior_lost = p.lost;
            rs.is_app_limited = p.app_limited;
            rs.send_elapsed = send_time -| p.first_send_time;
            rs.ack_elapsed = now -| p.delivered_time;
            rs.last_pn = pn;
            rs.newest_sent = send_time;
            rs.tx_in_flight = p.tx_in_flight;
            b.first_send_time = send_time;
        }
    }

    /// A packet sent at `send_time` was declared lost (5.2.4, 5.5.10.2 HandleLostPacket).
    pub fn onPacketLost(b: *Bbr, now: u64, p: Pkt, send_time: u64, size: u64, cwnd: *u64) void {
        b.lost += size;
        // 5.6.4.4 OnEnterFastRecovery: one episode per round trip
        if (b.recovery_start == null or send_time > b.recovery_start.?) {
            b.saveCwnd(cwnd.*);
            b.recovery_start = now;
        }
        // NoteLoss
        if (!b.is_loss_in_round) {
            b.loss_round_delivered = b.delivered;
            b.saveCwnd(cwnd.*);
        }
        b.is_loss_in_round = true;
        b.loss_events_in_round += 1;
        b.noteBurstLoss(now, p, send_time);
        if (!b.check_probe_loss) return; // not a packet sent while probing for bandwidth
        const tx = p.tx_in_flight;
        const lost = b.lost - p.lost; // lost since it was sent, this packet included
        if (!inflightTooHigh(lost, tx)) return;
        // InflightAtLoss: where in this packet the loss rate crossed the threshold
        const inflight_prev = tx -| size;
        const lost_prev = lost -| size;
        const lost_prefix = (inflight_prev -| lost_prev * loss_thresh_div) / (loss_thresh_div - 1);
        b.handleInflightTooHigh(now, p.app_limited, inflight_prev + lost_prefix, cwnd.*);
    }

    /// A packet of a quiet sender's burst (more than an initial window in one go) was lost.
    /// From the third packet lost of one burst, past the largest burst that ever arrived whole
    /// or with more than 2 percent of the flight lost since it left, the burst met the end of
    /// the path's queue: what leaves at once is bounded below that size from now on. One or
    /// two random losses inside a burst change nothing.
    fn noteBurstLoss(b: *Bbr, now: u64, p: Pkt, send_time: u64) void {
        if (p.burst <= b.initial_cwnd) return;
        const same = if (send_time > b.burst_lost_at) send_time - b.burst_lost_at else b.burst_lost_at - send_time;
        if (b.burst_lost_n == 0 or same >= burst_gap) {
            b.burst_lost_at = send_time;
            b.burst_lost_n = 0;
        }
        b.burst_lost_n += 1;
        if (b.burst_lost_n < 3) return;
        var cap: u64 = inf;
        if (p.burst > b.burst_ok) cap = @max(b.burst_ok - b.burst_ok / 8, p.burst / 2);
        if (inflightTooHigh(b.lost - p.lost, p.tx_in_flight)) cap = @min(cap, mulDiv(p.burst, beta_num, beta_den));
        if (cap == inf) return;
        b.burst_tail_round = true;
        if (cap >= b.burst_cap) return;
        b.burst_cap = cap;
        b.burst_cap_stamp = now;
        b.burst_ok = @min(b.burst_ok, cap);
    }

    /// 5.5.10.2 IsInflightTooHigh (QUIC acknowledges ranges, so the second clause never applies).
    fn inflightTooHigh(lost: u64, tx_in_flight: u64) bool {
        return lost *| loss_thresh_div > tx_in_flight;
    }

    fn handleInflightTooHigh(b: *Bbr, now: u64, app_limited: bool, tx_in_flight: u64, cwnd: u64) void {
        b.prev_probe_too_high = true;
        b.check_probe_loss = false; // only react once per bandwidth probe
        if (!app_limited) b.inflight_longterm = @max(tx_in_flight, b.targetInflight(cwnd) * beta_num / beta_den);
        if (b.state == .probe_bw_up) b.startProbeBwDown(now);
    }

    // ---------------------------------------------------------------- per ACK

    /// 5.2.3 UpdateOnACK, after `ackBegin`, `onPacketAcked` for each newly acknowledged packet
    /// and `onPacketLost` for each loss this ACK revealed.
    pub fn onAck(b: *Bbr, a: Ack, cwnd: *u64) void {
        b.mtu = a.mtu;
        const rs = &b.rs;
        rs.rtt = a.rtt;
        rs.newly_acked = a.newly_acked;
        // 4.1.2.3 GenerateRateSample
        if (b.app_limited != 0 and b.delivered > b.app_limited) b.app_limited = 0;
        if (b.app_quiet != 0 and b.delivered > b.app_quiet) b.app_quiet = 0;
        if (b.burst_cap != inf and a.now -| b.burst_cap_stamp > burst_cap_ttl) b.burst_cap = inf;
        if (!rs.has_data) return; // nothing delivered on this ACK
        rs.interval = @max(rs.send_elapsed, rs.ack_elapsed);
        rs.delivered = b.delivered - rs.prior_delivered;
        rs.lost = b.lost - rs.prior_lost;
        if (rs.lost == 0) b.carried = @max(b.carried, rs.tx_in_flight);
        // an interval shorter than the minimum round trip gives no reliable rate
        if (rs.interval != 0 and rs.interval >= a.min_rtt) rs.delivery_rate = mulDiv(rs.delivered, sec, rs.interval);
        // leaving loss recovery restores the window it had (5.6.4.4); the model bounds it below
        if (b.recovery_start) |t| if (rs.newest_sent > t) {
            b.recovery_start = null;
            b.restoreCwnd(cwnd);
        };
        // UpdateModelAndState
        b.updateLatestDeliverySignals();
        b.updateCongestionSignals(cwnd.*);
        b.updateAckAggregation(a.now, cwnd.*);
        b.checkFullBwReached();
        b.checkStartupDone();
        b.checkDrainDone(a);
        b.updateProbeBwCyclePhase(a, cwnd.*);
        b.updateMinRtt(a.now);
        b.checkProbeRtt(a, cwnd);
        b.advanceLatestDeliverySignals();
        b.bw = @min(b.max_bw, b.bw_shortterm); // BoundBWForModel
        // UpdateControlParameters
        if (!b.has_rtt and a.srtt != 0) {
            // 5.6.2 InitPacingRate, now that there is a round-trip time
            b.has_rtt = true;
            b.pacing_rate = mulDiv(cwnd.* * startup_pacing_gain / 100, sec, a.srtt);
        }
        b.setPacingRateWithGain(b.pacing_gain);
        b.setSendQuantum();
        b.setCwnd(a, cwnd);
    }

    // 5.5.10.3
    fn updateLatestDeliverySignals(b: *Bbr) void {
        b.loss_round_start = false;
        b.bw_latest = @max(b.bw_latest, b.rs.delivery_rate);
        b.inflight_latest = @max(b.inflight_latest, b.rs.delivered);
        if (b.rs.prior_delivered >= b.loss_round_delivered) {
            b.loss_round_delivered = b.delivered;
            b.loss_round_start = true;
        }
    }

    fn advanceLatestDeliverySignals(b: *Bbr) void {
        if (!b.loss_round_start) return;
        b.bw_latest = b.rs.delivery_rate;
        b.inflight_latest = b.rs.delivered;
        b.loss_events_in_round = 0;
        b.burst_tail_round = false;
    }

    fn resetCongestionSignals(b: *Bbr) void {
        b.is_loss_in_round = false;
        b.loss_events_in_round = 0;
        b.bw_latest = 0;
        b.inflight_latest = 0;
    }

    fn updateCongestionSignals(b: *Bbr, cwnd: u64) void {
        b.updateMaxBw();
        if (!b.loss_round_start) return; // wait until the end of the round trip
        // a round with loss: what the path carried whole is what it delivered now, or 0.7 of
        // what it carried before
        if (b.is_loss_in_round) b.carried = @max(b.inflight_latest, mulDiv(b.carried, beta_num, beta_den));
        // AdaptLowerBoundsFromCongestion: once per round, and not while probing for bandwidth
        const probing = b.state == .startup or b.state == .probe_bw_refill or b.state == .probe_bw_up;
        if (!probing and b.is_loss_in_round) {
            // InitLowerBounds
            if (b.bw_shortterm == inf) b.bw_shortterm = b.max_bw;
            if (b.inflight_shortterm == inf) b.inflight_shortterm = cwnd;
            // LossLowerBounds
            b.bw_shortterm = @max(b.bw_latest, mulDiv(b.bw_shortterm, beta_num, beta_den));
            b.inflight_shortterm = @max(b.inflight_latest, mulDiv(b.inflight_shortterm, beta_num, beta_den));
        }
        b.is_loss_in_round = false;
    }

    fn resetShortTermModel(b: *Bbr) void {
        b.bw_shortterm = inf;
        b.inflight_shortterm = inf;
    }

    // 5.5.1 and 5.5.5
    fn startRound(b: *Bbr) void {
        b.next_round_delivered = b.delivered;
    }

    fn updateMaxBw(b: *Bbr) void {
        // UpdateRound
        if (b.rs.prior_delivered >= b.next_round_delivered) {
            b.startRound();
            b.round_count += 1;
            b.rounds_since_probe_up += 1;
            b.round_start = true;
            b.limited_prev = b.limited_now;
            b.limited_now = false;
        } else b.round_start = false;
        const rate = b.rs.delivery_rate;
        if (rate > 0 and (rate >= b.max_bw or !b.rs.is_app_limited)) {
            b.max_bw_filter[1] = @max(b.max_bw_filter[1], rate);
            b.max_bw = @max(b.max_bw_filter[0], b.max_bw_filter[1]);
        }
    }

    /// 5.5.6: a ProbeBW cycle is over; the cycle before it leaves the window. (With no sample
    /// in the cycle that just ended the old one is kept, as Linux does.)
    fn advanceMaxBwFilter(b: *Bbr) void {
        if (b.max_bw_filter[1] == 0) return;
        b.max_bw_filter[0] = b.max_bw_filter[1];
        b.max_bw_filter[1] = 0;
        b.max_bw = b.max_bw_filter[0];
    }

    // 5.5.9
    fn updateAckAggregation(b: *Bbr, now: u64, cwnd: u64) void {
        const interval = now -| b.extra_acked_interval_start;
        var expected = mulDiv(b.bw, interval, sec);
        if (b.extra_acked_delivered <= expected) {
            b.extra_acked_delivered = 0;
            b.extra_acked_interval_start = now;
            expected = 0;
        }
        b.extra_acked_delivered += b.rs.newly_acked;
        const extra = @min(b.extra_acked_delivered - expected, cwnd);
        const len: u64 = if (b.full_bw_reached) extra_acked_filter_len else 1;
        b.extra_acked = b.extra_acked_filter.update(len, b.round_count, extra);
    }

    // 5.3.1
    fn enterStartup(b: *Bbr) void {
        b.state = .startup;
        b.pacing_gain = startup_pacing_gain;
        b.cwnd_gain = default_cwnd_gain;
    }

    fn resetFullBw(b: *Bbr) void {
        b.full_bw = 0;
        b.full_bw_count = 0;
        b.full_bw_now = false;
    }

    fn checkFullBwReached(b: *Bbr) void {
        // an ACK without a rate sample says nothing about growth (Linux skips it as well)
        if (b.full_bw_now or !b.round_start or b.rs.is_app_limited or b.rs.delivery_rate == 0) return;
        if (@as(u128, b.rs.delivery_rate) * 100 >= @as(u128, b.full_bw) * full_bw_growth_percent) {
            b.resetFullBw(); // still growing
            b.full_bw = b.rs.delivery_rate;
            return;
        }
        b.full_bw_count += 1;
        b.full_bw_now = b.full_bw_count >= full_bw_rounds;
        if (b.full_bw_now) b.full_bw_reached = true;
    }

    fn checkStartupDone(b: *Bbr) void {
        // 5.3.1.3 CheckStartupHighLoss. (Not for the tail of a quiet sender's burst in the
        // path's queue: that says how much the queue takes in one go, which `burst_cap` now
        // holds, not that the path cannot carry the rate.)
        if (!b.full_bw_reached and b.loss_round_start and b.recovery_start != null and !b.burst_tail_round and
            b.loss_events_in_round >= startup_full_loss_cnt and inflightTooHigh(b.rs.lost, b.rs.tx_in_flight))
        {
            b.full_bw_reached = true;
            b.inflight_longterm = @max(b.bdp(), b.inflight_latest);
        }
        if (b.state == .startup and b.full_bw_reached) {
            // 5.3.2 EnterDrain
            b.state = .drain;
            b.pacing_gain = drain_pacing_gain;
            b.cwnd_gain = default_cwnd_gain;
            b.drain_start_round = b.round_count;
        }
    }

    fn checkDrainDone(b: *Bbr, a: Ack) void {
        if (b.state == .drain and (a.inflight <= b.inflightFor(b.bw, 100) or b.round_count > b.drain_start_round + 3)) {
            // EnterProbeBW
            b.cwnd_gain = default_cwnd_gain;
            b.startProbeBwDown(a.now);
        }
    }

    // 5.3.3.9
    fn startProbeBwDown(b: *Bbr, now: u64) void {
        b.resetCongestionSignals();
        b.probe_up_acked_per_inc = inf; // not growing inflight_longterm
        // PickProbeWait
        b.rounds_since_probe_up = b.rand() & 1;
        b.bw_probe_wait = probe_wait_base + b.rand() % probe_wait_rand;
        b.cycle_stamp = now;
        b.is_bw_probe_stopping = true;
        b.startRound();
        b.state = .probe_bw_down;
        b.pacing_gain = down_pacing_gain;
        b.cwnd_gain = default_cwnd_gain;
    }

    fn startProbeBwCruise(b: *Bbr) void {
        b.state = .probe_bw_cruise;
        b.pacing_gain = cruise_pacing_gain;
        b.cwnd_gain = default_cwnd_gain;
    }

    fn startProbeBwRefill(b: *Bbr) void {
        b.resetShortTermModel();
        b.bw_probe_up_rounds = 0;
        b.bw_probe_up_acked = 0;
        b.prev_probe_precautionary = false;
        b.is_bw_probe_stopping = false;
        b.startRound();
        b.state = .probe_bw_refill;
        b.pacing_gain = refill_pacing_gain;
        b.cwnd_gain = default_cwnd_gain;
    }

    fn startProbeBwUp(b: *Bbr, cwnd: u64) void {
        b.startRound();
        b.resetFullBw();
        b.full_bw = b.rs.delivery_rate;
        b.state = .probe_bw_up;
        b.pacing_gain = up_pacing_gain;
        b.cwnd_gain = up_cwnd_gain;
        b.raiseInflightLongtermSlope(cwnd);
    }

    fn updateProbeBwCyclePhase(b: *Bbr, a: Ack, cwnd: u64) void {
        if (!b.full_bw_reached) return; // only steady state here
        if (b.adaptLongTermModel(a, cwnd)) return; // already decided a transition
        switch (b.state) {
            .probe_bw_down => {
                if (b.isTimeToProbeBw(a.now, cwnd)) return;
                // IsTimeToCruise: there is headroom, and no more in flight than the estimated BDP
                if (a.inflight <= b.inflightWithHeadroom() and a.inflight <= b.inflightFor(b.max_bw, 100)) b.startProbeBwCruise();
            },
            .probe_bw_cruise => _ = b.isTimeToProbeBw(a.now, cwnd),
            .probe_bw_refill => if (b.round_start) {
                // after one round of refilling, probe
                b.check_probe_loss = true;
                b.startProbeBwUp(cwnd);
            },
            .probe_bw_up => if (b.isTimeToGoDown(a.inflight, cwnd)) {
                b.prev_probe_too_high = false; // no high loss (yet)
                b.startProbeBwDown(a.now);
            },
            else => {},
        }
    }

    fn isTimeToProbeBw(b: *Bbr, now: u64, cwnd: u64) bool {
        // IsRenoCoexistenceProbeTime: as many rounds as a Reno flow needs to regain its window
        const reno_rounds = @min(b.targetInflight(cwnd) / b.mtu, reno_rounds_max);
        if (now > b.cycle_stamp + b.bw_probe_wait or b.rounds_since_probe_up >= reno_rounds) {
            b.startProbeBwRefill();
            return true;
        }
        return false;
    }

    fn isTimeToGoDown(b: *Bbr, inflight: u64, cwnd: u64) bool {
        // precautionary probing (5.3.3.6): the last probe lost too much, so this one stops as
        // soon as it is back at the volume that did
        if (b.prev_probe_too_high and inflight >= b.inflight_longterm) {
            b.prev_probe_precautionary = true;
            return true;
        }
        if (b.isCwndLimited() and cwnd >= b.inflight_longterm) {
            b.resetFullBw(); // the rate is held by inflight_longterm
            b.full_bw = b.rs.delivery_rate;
        } else if (b.full_bw_now) return true; // the path's rate is used in full
        return false;
    }

    fn raiseInflightLongtermSlope(b: *Bbr, cwnd: u64) void {
        const growth_this_round = @as(u64, 1) << @intCast(b.bw_probe_up_rounds);
        b.bw_probe_up_rounds = @min(b.bw_probe_up_rounds + 1, 30);
        b.probe_up_acked_per_inc = @max(cwnd / growth_this_round, b.mtu);
    }

    fn probeInflightLongtermUpward(b: *Bbr, cwnd: u64) void {
        if (!b.isCwndLimited() or cwnd < b.inflight_longterm) return; // not using it in full
        b.bw_probe_up_acked += b.rs.newly_acked;
        if (b.bw_probe_up_acked >= b.probe_up_acked_per_inc) {
            const delta = b.bw_probe_up_acked / b.probe_up_acked_per_inc;
            b.bw_probe_up_acked -= delta * b.probe_up_acked_per_inc;
            b.inflight_longterm +|= delta * b.mtu;
        }
        if (b.round_start) b.raiseInflightLongtermSlope(cwnd);
    }

    /// Returns true when it decided a state transition.
    fn adaptLongTermModel(b: *Bbr, a: Ack, cwnd: u64) bool {
        _ = a;
        if (b.is_bw_probe_stopping and b.round_start) {
            // the samples of the bandwidth probe are all in
            b.check_probe_loss = false;
            b.is_bw_probe_stopping = false;
            if (b.inProbeBw() and !b.rs.is_app_limited) b.advanceMaxBwFilter();
            // precautionary probing: the cautious probe saw no excess loss, so probe again in full
            if (b.inProbeBw() and b.prev_probe_precautionary and !b.prev_probe_too_high) {
                b.startProbeBwRefill();
                return true;
            }
        }
        if (!inflightTooHigh(b.rs.lost, b.rs.tx_in_flight)) {
            // the loss rate is safe: the upper bound may rise
            if (b.inflight_longterm == inf) return false;
            if (b.rs.tx_in_flight > b.inflight_longterm) b.inflight_longterm = b.rs.tx_in_flight;
            if (b.state == .probe_bw_up) b.probeInflightLongtermUpward(cwnd);
        }
        return false;
    }

    // 5.3.4
    fn updateMinRtt(b: *Bbr, now: u64) void {
        b.min_rtt_expired = now > b.min_rtt_stamp + min_rtt_filter_len;
        if (b.min_rtt_expired) b.probe_rtt_cwnd = b.bdpMultiple(b.bw, probe_rtt_cwnd_gain);
        if (b.rs.rtt) |r| if (r < b.min_rtt or b.min_rtt_expired) {
            b.min_rtt = r;
            b.min_rtt_stamp = now;
        };
    }

    fn checkProbeRtt(b: *Bbr, a: Ack, cwnd: *u64) void {
        // (not for a quiet sender: `quiet`; the expired minimum was replaced by this ACK's
        // sample in `updateMinRtt`, and the start of the next burst lowers it again)
        if (b.state != .probe_rtt and b.min_rtt_expired and !b.idle_restart and !b.quiet()) {
            b.saveCwnd(cwnd.*);
            // EnterProbeRTT
            b.state = .probe_rtt;
            b.pacing_gain = 100;
            b.cwnd_gain = probe_rtt_cwnd_gain;
            b.probe_rtt_done_stamp = null;
            b.is_bw_probe_stopping = true;
            b.startRound();
        }
        if (b.state == .probe_rtt) {
            // HandleProbeRTT: the low rate of this state is not the path's (nor is it the
            // application's: `app_quiet` is not set)
            b.app_limited = @max(b.delivered + a.inflight, 1);
            if (b.probe_rtt_done_stamp == null and a.inflight <= b.probeRttCwnd()) {
                // hold for the duration and for at least one round
                b.probe_rtt_done_stamp = a.now + probe_rtt_duration;
                b.probe_rtt_round_done = false;
                b.startRound();
            } else if (b.probe_rtt_done_stamp != null) {
                if (b.round_start) b.probe_rtt_round_done = true;
                if (b.probe_rtt_round_done) b.checkProbeRttDone(a.now, cwnd);
            }
        }
        if (b.rs.delivered > 0) b.idle_restart = false;
    }

    fn checkProbeRttDone(b: *Bbr, now: u64, cwnd: *u64) void {
        const done = b.probe_rtt_done_stamp orelse return;
        if (now <= done) return;
        b.min_rtt_stamp = now; // schedule the next ProbeRTT
        b.restoreCwnd(cwnd);
        // 5.3.4.4 ExitProbeRTT
        b.resetShortTermModel();
        if (b.full_bw_reached) {
            b.startProbeBwDown(now);
            b.startProbeBwCruise();
        } else b.enterStartup();
    }

    fn probeRttCwnd(b: *const Bbr) u64 {
        return @max(@min(b.bdpMultiple(b.bw, probe_rtt_cwnd_gain), b.probe_rtt_cwnd), min_pipe_cwnd * b.mtu);
    }

    // 5.6.4.4
    fn saveCwnd(b: *Bbr, cwnd: u64) void {
        if (b.recovery_start == null and b.state != .probe_rtt) {
            b.prior_cwnd = cwnd;
        } else b.prior_cwnd = @max(b.prior_cwnd, cwnd);
    }

    fn restoreCwnd(b: *const Bbr, cwnd: *u64) void {
        cwnd.* = @max(cwnd.*, b.prior_cwnd);
    }

    // 5.6.2 to 5.6.4
    fn setPacingRateWithGain(b: *Bbr, gain: u32) void {
        const rate = mulDiv(b.bw, @as(u64, gain) * (100 - pacing_margin_percent), 100 * 100);
        if (b.full_bw_reached or rate > b.pacing_rate) b.pacing_rate = rate;
    }

    fn setSendQuantum(b: *Bbr) void {
        b.send_quantum = @max(@min(b.pacing_rate / 1000, send_quantum_max), 2 * b.mtu);
    }

    /// BBR.bdp: the estimated bandwidth-delay product (inf before the first round-trip sample).
    pub fn bdp(b: *const Bbr) u64 {
        return if (b.min_rtt == inf) inf else mulDiv(b.bw, b.min_rtt, sec);
    }

    fn bdpMultiple(b: *const Bbr, bw: u64, gain: u32) u64 {
        if (b.min_rtt == inf) return b.initial_cwnd; // no round-trip sample yet
        return mulDiv(mulDiv(bw, b.min_rtt, sec), gain, 100);
    }

    fn quantizationBudget(b: *const Bbr, cap_in: u64) u64 {
        // the offload budget of a QUIC sender is its send quantum (5.5.8.2)
        var cap = @max(cap_in, b.send_quantum, min_pipe_cwnd * b.mtu);
        if (b.state == .probe_bw_up) cap +|= 2 * b.mtu;
        return cap;
    }

    /// Inflight(gain) for the bandwidth `bw`.
    fn inflightFor(b: *const Bbr, bw: u64, gain: u32) u64 {
        return b.quantizationBudget(b.bdpMultiple(bw, gain));
    }

    fn targetInflight(b: *const Bbr, cwnd: u64) u64 {
        return @min(b.bdp(), cwnd);
    }

    fn inflightWithHeadroom(b: *const Bbr) u64 {
        if (b.inflight_longterm == inf) return inf;
        const headroom = @max(b.mtu, mulDiv(b.inflight_longterm, headroom_percent, 100));
        return @max(b.inflight_longterm -| headroom, min_pipe_cwnd * b.mtu);
    }

    fn setCwnd(b: *Bbr, a: Ack, cwnd: *u64) void {
        // UpdateMaxInflight
        b.max_inflight = b.quantizationBudget(b.bdpMultiple(b.bw, b.cwnd_gain) +| b.extra_acked);
        // a quiet sender's model knows its own bursts, not the path: not below what the path
        // has carried (the bounds that loss sets still apply below)
        if (b.quiet()) b.max_inflight = @max(b.max_inflight, b.carried);
        if (b.full_bw_reached) {
            cwnd.* = @min(cwnd.* +| a.newly_acked, b.max_inflight);
        } else if (cwnd.* < b.max_inflight or b.delivered < b.initial_cwnd) {
            cwnd.* +|= a.newly_acked;
        }
        cwnd.* = @max(cwnd.*, min_pipe_cwnd * b.mtu);
        // BoundCwndForProbeRTT
        if (b.state == .probe_rtt) cwnd.* = @min(cwnd.*, b.probeRttCwnd());
        // 5.6.4.7 BoundCwndForModel
        var cap: u64 = inf;
        if (b.inProbeBw() and b.state != .probe_bw_cruise) {
            cap = b.inflight_longterm;
        } else if (b.state == .probe_rtt or b.state == .probe_bw_cruise) cap = b.inflightWithHeadroom();
        cap = @min(cap, b.inflight_shortterm);
        // A quiet sender's losses are the tails of its bursts in the path's queue, and
        // `burst_cap` answers those. The flight bounds would hold its next burst behind the
        // last one's acknowledgements: not below what the path has carried in flight (which
        // a round with loss lowers as well).
        if (b.quiet()) cap = @max(cap, b.carried);
        cap = @max(cap, min_pipe_cwnd * b.mtu);
        cwnd.* = @min(cwnd.*, cap);
    }
};

test "pacer: a full bucket leaves at once, an empty one waits for a whole run, never under 1.25 ms" {
    var p: Pacer = .{};
    const mtu: u64 = 1200;
    const srtt: u64 = 50 * ms;
    const cwnd: u64 = 120_000; // 100 datagrams
    // a run: 2 ms of a 100-datagram window per 50 ms is 4 datagrams, so the floor of 10
    var sent: u64 = 0;
    while (p.delay(0, srtt, cwnd, mtu, cwnd, 5, 4) == null) : (sent += 1) p.onSend(mtu);
    try std.testing.expectEqual(@as(u64, 10), sent);
    const t = p.delay(0, srtt, cwnd, mtu, cwnd, 5, 4).?;
    // 10 datagrams at 1.25 * 100 per 50 ms is 4 ms
    try std.testing.expectEqual(@as(u64, 4 * ms), t);
    // asked again a little later, the answer is the same instant
    try std.testing.expectEqual(@as(?u64, t), p.delay(100_000, srtt, cwnd, mtu, cwnd, 5, 4));
    // when the window has room for two datagrams only, those two would be there in 0.7 ms:
    // the pacer asks for its shortest wait instead (the ACK that opens the window wakes the
    // sender anyway)
    try std.testing.expectEqual(@as(?u64, 100_000 + Pacer.timer_ns), p.delay(100_000, srtt, cwnd, mtu, 2 * mtu, 5, 4));
    try std.testing.expectEqual(@as(?u64, null), p.delay(t, srtt, cwnd, mtu, cwnd, 5, 4));
    // over one round trip from a full bucket: the bucket plus 1.25 windows, never more
    var q: Pacer = .{};
    var now: u64 = 0;
    var total: u64 = 0;
    while (now <= srtt) {
        if (q.delay(now, srtt, cwnd, mtu, cwnd, 5, 4)) |at| {
            try std.testing.expect(at >= now + Pacer.timer_ns);
            now = at;
            continue;
        }
        q.onSend(mtu);
        total += mtu;
    }
    try std.testing.expect(total <= 10 * mtu + cwnd * 5 / 4 + mtu);
    try std.testing.expect(total >= cwnd);
}

test "pacer: a run is 2 ms of the window, 10 to 64 datagrams; the bucket holds 1.25 ms of the rate when that is more" {
    try std.testing.expectEqual(@as(u64, 10 * 1452), Pacer.runFor(100 * ms, 14_520, 1452));
    try std.testing.expectEqual(@as(u64, 60_000), Pacer.runFor(20 * ms, 600_000, 1452));
    try std.testing.expectEqual(@as(u64, 64 * 1452), Pacer.runFor(100_000, 10 << 20, 1452));
    // slow start (gain 2) at 600,000 bytes per 20 ms: a run is 60,000 bytes and would be
    // there after 1 ms; the wait is 1.25 ms, and what that brings (75,000) is kept
    var p: Pacer = .{};
    const mtu: u64 = 1452;
    while (p.delay(0, 20 * ms, 600_000, mtu, 600_000, 2, 1) == null) p.onSend(mtu);
    try std.testing.expectEqual(@as(u64, 75_000), p.capacity);
    try std.testing.expect(p.tokens < mtu);
    try std.testing.expectEqual(@as(?u64, Pacer.timer_ns), p.delay(0, 20 * ms, 600_000, mtu, 600_000, 2, 1));
    try std.testing.expectEqual(@as(?u64, null), p.delay(Pacer.timer_ns, 20 * ms, 600_000, mtu, 600_000, 2, 1));
    try std.testing.expectEqual(@as(u64, 75_000), p.tokens);
}

/// Bytes a sender with unlimited data gets through the pacer in `span` at `rate`, when the loop
/// that drives it wakes `tick` after it went to sleep, whatever wait it asked for (0: at the
/// time asked for): a Linux socket receive timeout, counted in jiffies. A pass sends at most
/// 64 datagrams (the listener's cap).
fn pacedBytes(rate: u64, quantum: u64, tick: u64, span: u64, late_credit: bool) u64 {
    var p: Pacer = .{};
    const mtu: u64 = 1452;
    var now: u64 = 0;
    var sent: u64 = 0;
    while (now < span) {
        var k: usize = 0;
        var at: ?u64 = null;
        while (k < 64) : (k += 1) {
            if (!late_credit) {
                p.waiting = false; // the pacer as it was: the bucket bounds every credit
            }
            at = p.delayRate(now, rate, mtu, 1 << 30, quantum);
            if (at != null) break;
            p.onSend(mtu);
            sent += mtu;
        }
        const t = at orelse {
            now += 10_000; // the burst cap: the next pass follows at once
            continue;
        };
        now = if (tick == 0) t else @max(t, now + tick);
    }
    return sent;
}

test "pacer: a loop that wakes 4 or 8 ms late still sends at the pacing rate" {
    // BBR on a long path: 10 MB/s (80 Mbit/s), a send quantum of 1 ms of the rate
    const rate: u64 = 10_000_000;
    const quantum: u64 = rate / 1000;
    const span: u64 = 2 * sec;
    const want = rate * 2;
    const exact = pacedBytes(rate, quantum, 0, span, true);
    try std.testing.expect(exact * 100 >= want * 98 and exact * 100 <= want * 102);
    // a 250 Hz kernel: the wake comes 4 to 8 ms after a 1.25 ms wait was set
    for ([_]u64{ 4 * ms, 8 * ms }) |tick| {
        const got = pacedBytes(rate, quantum, tick, span, true);
        try std.testing.expect(got * 100 >= want * 97 and got * 100 <= want * 102);
        // with the bucket (2 ms of the rate) as the limit, the rest of each sleep was lost
        const old = pacedBytes(rate, quantum, tick, span, false);
        try std.testing.expect(old * 100 <= want * 55);
    }
    // the same for a window-clocked rate far below: 1 MB/s, runs of two datagrams
    for ([_]u64{ 0, 4 * ms, 8 * ms }) |tick| {
        const got = pacedBytes(1_000_000, 2 * 1452, tick, span, true);
        try std.testing.expect(got * 100 >= 2_000_000 * 97 and got * 100 <= 2_000_000 * 102);
    }
}

test "pacer: the credit of a late wake is for a sender that waited, not for one that was idle" {
    var p: Pacer = .{};
    const mtu: u64 = 1200;
    const rate: u64 = 6_000_000;
    const quantum: u64 = 6000;
    // drain the bucket (two quanta); the sender has more and is told to wait 1.25 ms
    while (p.delayRate(0, rate, mtu, 1 << 20, quantum) == null) p.onSend(mtu);
    try std.testing.expectEqual(@as(u64, 12_000), p.capacity);
    try std.testing.expectEqual(Pacer.timer_ns, p.due);
    // woken at 6 ms instead: the 36,000 bytes of the whole wait are there, three buckets
    var sent: u64 = 0;
    while (p.delayRate(6 * ms, rate, mtu, 1 << 20, quantum) == null) : (sent += 1) p.onSend(mtu);
    try std.testing.expectEqual(@as(u64, 30), sent);
    // called 50 ms after the time asked for: that is no late timer (a full window held the
    // sender, say), and the bucket is the limit
    var r = p.delayRate(56 * ms, rate, mtu, 1 << 20, quantum);
    try std.testing.expectEqual(@as(?u64, null), r);
    try std.testing.expectEqual(p.capacity, p.tokens);
    while (r == null) {
        p.onSend(mtu);
        r = p.delayRate(56 * ms, rate, mtu, 1 << 20, quantum);
    }
    // woken late with nothing to send after all: the credit is there for this pass only
    try std.testing.expectEqual(@as(?u64, null), p.delayRate(64 * ms, rate, mtu, 1 << 20, quantum));
    try std.testing.expect(p.tokens > 3 * p.capacity);
    try std.testing.expectEqual(@as(?u64, null), p.delayRate(64 * ms + 1000, rate, mtu, 1 << 20, quantum));
    try std.testing.expectEqual(p.capacity, p.tokens);
    // and a sender that was idle for a second starts from the bucket, as before
    try std.testing.expectEqual(@as(?u64, null), p.delayRate(2 * sec, rate, mtu, 1 << 20, quantum));
    try std.testing.expectEqual(p.capacity, p.tokens);
}

test "pacer, rate mode: runs at the rate, no wake-up under 1.25 ms; a late timer loses nothing" {
    var p: Pacer = .{};
    const mtu: u64 = 1200;
    const rate: u64 = 6_000_000; // bytes per second: 5 datagrams per ms
    const quantum: u64 = 6000;
    // the bucket starts with two quanta
    var sent: u64 = 0;
    while (p.delayRate(0, rate, mtu, 1 << 20, quantum) == null) : (sent += 1) p.onSend(mtu);
    try std.testing.expectEqual(@as(u64, 10), sent);
    // a quantum would be there after 1 ms: the wait is 1.25 ms, and brings 7,500 bytes
    const t = p.delayRate(0, rate, mtu, 1 << 20, quantum).?;
    try std.testing.expectEqual(Pacer.timer_ns, t);
    // a window with room for two datagrams: the same shortest wait
    try std.testing.expectEqual(@as(?u64, Pacer.timer_ns), p.delayRate(0, rate, mtu, 2 * mtu, quantum));
    sent = 0;
    while (p.delayRate(t, rate, mtu, 1 << 20, quantum) == null) : (sent += 1) p.onSend(mtu);
    try std.testing.expectEqual(@as(u64, 6), sent);
    // woken 0.8 ms late: what built up meanwhile leaves with the run (2.05 ms of the rate)
    const late = p.delayRate(t, rate, mtu, 1 << 20, quantum).? + 800_000;
    sent = 0;
    while (p.delayRate(late, rate, mtu, 1 << 20, quantum) == null) : (sent += 1) p.onSend(mtu);
    try std.testing.expectEqual(@as(u64, 10), sent);
    // a slow rate: a run is the quantum (two datagrams), however long that takes
    var slow: Pacer = .{};
    while (slow.delayRate(0, 100_000, mtu, 1 << 20, 2400) == null) slow.onSend(mtu);
    try std.testing.expectEqual(@as(?u64, 24 * ms), slow.delayRate(0, 100_000, mtu, 1 << 20, 2400));
    // over one second: the rate, give or take the bucket
    var q: Pacer = .{};
    var now: u64 = 0;
    var total: u64 = 0;
    while (now < sec) {
        if (q.delayRate(now, rate, mtu, 1 << 20, quantum)) |at| {
            now = at;
            continue;
        }
        q.onSend(mtu);
        total += mtu;
    }
    try std.testing.expect(total >= rate and total <= rate + 12_000 + mtu);
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

test "max filter: the best sample of the last rounds, then the next best" {
    var f: MaxFilter = .{};
    try std.testing.expectEqual(@as(u64, 50), f.update(10, 1, 50));
    try std.testing.expectEqual(@as(u64, 50), f.update(10, 2, 30));
    try std.testing.expectEqual(@as(u64, 50), f.update(10, 8, 40));
    try std.testing.expectEqual(@as(u64, 70), f.update(10, 9, 70));
    // 70 leaves the window after round 19: the best of what came since takes over
    try std.testing.expectEqual(@as(u64, 70), f.update(10, 15, 20));
    try std.testing.expectEqual(@as(u64, 70), f.update(10, 19, 10));
    try std.testing.expectEqual(@as(u64, 20), f.update(10, 20, 5));
    // a window of one round forgets after two
    var g: MaxFilter = .{};
    _ = g.update(1, 1, 9);
    try std.testing.expectEqual(@as(u64, 9), g.update(1, 2, 3));
    try std.testing.expectEqual(@as(u64, 3), g.update(1, 3, 1));
}

/// A sender run by `Bbr` over one bottleneck (a rate, a tail-drop queue, a two-way propagation
/// delay), in virtual time: every packet is paced at `pacing_rate`, held by the window, and
/// acknowledged on its own. Deterministic: no clock, no randomness but the controller's own.
const TestPath = struct {
    b: Bbr,
    cwnd: u64,
    /// Bottleneck rate in bytes per second, queue in bytes, two-way propagation delay.
    rate: u64,
    queue: u64,
    rtt: u64,
    /// Not 0: the application writes at this many bytes per second (it is the limit).
    app_rate: u64 = 0,
    app_from: u64 = 0,
    app_sent: u64 = 0,
    /// Not 0: every packet with a number divisible by this is lost on the wire.
    drop_every: u64 = 0,
    now: u64 = 0,
    inflight: u64 = 0,
    pn: u64 = 0,
    free_at: u64 = 0,
    next_send: u64 = 0,
    min_rtt: u64 = inf,
    srtt: u64 = 0,
    acked: u64 = 0,
    lost: u64 = 0,
    max_inflight_seen: u64 = 0,
    pkts: std.ArrayList(P) = .empty,
    head: usize = 0,
    /// Every state the controller entered, with the time and the gains it set.
    log: std.ArrayList(Entry) = .empty,

    const mtu: u64 = 1200;
    const P = struct { st: Bbr.Pkt, sent: u64, ack_at: u64, pn: u64, lost: bool };
    const Entry = struct { t: u64, state: Bbr.State, pacing_gain: u32, cwnd_gain: u32, round: u64 };

    fn init(rate: u64, rtt: u64, queue: u64) TestPath {
        return .{ .b = Bbr.init(0, 10 * mtu, mtu, 7), .cwnd = 10 * mtu, .rate = rate, .queue = queue, .rtt = rtt };
    }

    fn deinit(tp: *TestPath) void {
        tp.pkts.deinit(std.testing.allocator);
        tp.log.deinit(std.testing.allocator);
    }

    fn note(tp: *TestPath) !void {
        if (tp.log.items.len > 0 and tp.log.items[tp.log.items.len - 1].state == tp.b.state) return;
        try tp.log.append(std.testing.allocator, .{ .t = tp.now, .state = tp.b.state, .pacing_gain = tp.b.pacing_gain, .cwnd_gain = tp.b.cwnd_gain, .round = tp.b.round_count });
    }

    /// Index in `log` of the first entry of `state` at or after index `from`.
    fn find(tp: *const TestPath, state: Bbr.State, from: usize) ?usize {
        for (tp.log.items[@min(from, tp.log.items.len)..], from..) |e, i| if (e.state == state) return i;
        return null;
    }

    fn appHas(tp: *const TestPath) bool {
        if (tp.app_rate == 0) return true;
        return Bbr.mulDiv(tp.app_rate, tp.now - tp.app_from, sec) >= tp.app_sent + mtu;
    }

    fn run(tp: *TestPath, until: u64) !void {
        const gpa = std.testing.allocator;
        if (tp.log.items.len == 0) try tp.note();
        while (true) {
            const ack_t: u64 = if (tp.head < tp.pkts.items.len) tp.pkts.items[tp.head].ack_at else inf;
            var send_t: u64 = inf;
            if (tp.inflight + mtu > tp.cwnd) {
                tp.b.noteCwndLimited();
            } else if (tp.appHas()) {
                send_t = @max(tp.now, tp.next_send);
            } else {
                // window and pacer would let a packet go and there is none
                if (tp.next_send <= tp.now) tp.b.markAppLimited(tp.inflight);
                const due = tp.app_from + Bbr.mulDiv(tp.app_sent + mtu, sec, tp.app_rate) + 1;
                send_t = @max(due, tp.next_send);
            }
            const t = @min(ack_t, send_t);
            if (t >= until) {
                tp.now = until;
                return;
            }
            tp.now = t;
            if (ack_t <= send_t) {
                const p = tp.pkts.items[tp.head];
                tp.head += 1;
                tp.inflight -= mtu;
                if (p.lost) {
                    tp.lost += mtu;
                    tp.b.onPacketLost(tp.now, p.st, p.sent, mtu, &tp.cwnd);
                } else {
                    const r = tp.now - p.sent;
                    tp.min_rtt = @min(tp.min_rtt, r);
                    tp.srtt = if (tp.srtt == 0) r else (7 * tp.srtt + r) / 8;
                    tp.acked += mtu;
                    tp.b.ackBegin();
                    tp.b.onPacketAcked(tp.now, p.st, p.sent, p.pn, mtu);
                    tp.b.onAck(.{ .now = tp.now, .inflight = tp.inflight, .newly_acked = mtu, .rtt = r, .min_rtt = tp.min_rtt, .srtt = tp.srtt, .mtu = mtu }, &tp.cwnd);
                }
                try tp.note();
                continue;
            }
            // send one packet through the bottleneck
            const st = tp.b.onSent(tp.now, tp.inflight, mtu, &tp.cwnd);
            tp.inflight += mtu;
            tp.max_inflight_seen = @max(tp.max_inflight_seen, tp.inflight);
            tp.app_sent += mtu;
            tp.next_send = @max(tp.now, tp.next_send) + Bbr.mulDiv(mtu, sec, @max(tp.b.pacing_rate, 1));
            const backlog = Bbr.mulDiv(tp.free_at -| tp.now, tp.rate, sec);
            var p: P = .{ .st = st, .sent = tp.now, .ack_at = @max(tp.now, tp.free_at) + tp.rtt, .pn = tp.pn, .lost = backlog + mtu > tp.queue };
            if (!p.lost) {
                tp.free_at = @max(tp.now, tp.free_at) + Bbr.mulDiv(mtu, sec, tp.rate);
                p.ack_at = tp.free_at + tp.rtt;
                if (tp.drop_every != 0 and tp.pn % tp.drop_every == tp.drop_every - 1) p.lost = true;
            }
            tp.pn += 1;
            if (tp.head >= 4096) {
                const rest = tp.pkts.items.len - tp.head;
                std.mem.copyForwards(P, tp.pkts.items[0..rest], tp.pkts.items[tp.head..]);
                tp.pkts.shrinkRetainingCapacity(rest);
                tp.head = 0;
            }
            try tp.pkts.append(gpa, p);
        }
    }

    /// Bytes acknowledged while running for `dur`.
    fn deliveredIn(tp: *TestPath, dur: u64) !u64 {
        const before = tp.acked;
        try tp.run(tp.now + dur);
        return tp.acked - before;
    }
};

// 10 Mbit/s and a 40 ms round trip: a BDP of 50,000 bytes, about 41 datagrams.
const test_rate: u64 = 1_250_000;
const test_rtt: u64 = 40 * ms;
const test_bdp: u64 = 50_000;

test "bbr startup: the rate doubles until three rounds bring no growth, then drain empties the queue" {
    var tp = TestPath.init(test_rate, test_rtt, 4 * test_bdp);
    defer tp.deinit();
    try std.testing.expectEqual(Bbr.State.startup, tp.b.state);
    try std.testing.expectEqual(@as(u32, 277), tp.b.pacing_gain);
    try std.testing.expectEqual(@as(u32, 200), tp.b.cwnd_gain);
    // the pacing rate before any sample: 2.77 initial windows per millisecond
    try std.testing.expectEqual(@as(u64, 12_000 * 277 / 100 * 1000), tp.b.pacing_rate);
    try tp.run(3 * sec);
    const drain = tp.find(.drain, 0).?;
    const d = tp.log.items[drain];
    try std.testing.expectEqual(@as(usize, 1), drain); // straight from startup
    try std.testing.expectEqual(@as(u32, 50), d.pacing_gain);
    try std.testing.expectEqual(@as(u32, 200), d.cwnd_gain);
    try std.testing.expect(tp.b.full_bw_reached);
    try std.testing.expectEqual(@as(u64, 0), tp.lost);
    // the window doubled from 10 datagrams to the path's 41 in about 2 rounds, the delivery
    // rate stopped growing, and three more rounds without growth ended startup: 5 to 9 rounds
    try std.testing.expect(d.round >= 5 and d.round <= 9);
    try std.testing.expect(d.t < 500 * ms);
    // the estimate is the bottleneck's rate, within 3 percent
    try std.testing.expect(tp.b.max_bw >= test_rate * 97 / 100 and tp.b.max_bw <= test_rate * 101 / 100);
    try std.testing.expect(tp.b.min_rtt >= test_rtt and tp.b.min_rtt <= test_rtt + 2 * ms);
    // startup overshot: up to a window of two BDPs was in flight
    try std.testing.expect(tp.max_inflight_seen > test_bdp * 3 / 2);
    // drain ends in ProbeBW_DOWN, within a round or two, once no more than a BDP is in flight
    // (the ACK that ends drain may find the queue gone already and go on to cruise at once)
    const after = tp.log.items[drain + 1];
    try std.testing.expect(after.state == .probe_bw_down or after.state == .probe_bw_cruise);
    try std.testing.expect(tp.inflight <= test_bdp + 4 * TestPath.mtu);
    try std.testing.expect(tp.log.items[drain + 1].t - d.t <= 3 * test_rtt);
    try std.testing.expect(tp.log.items[drain + 1].round <= d.round + 3);
}

test "bbr ProbeBW: down, cruise, refill for one round, up, and down again, with the draft's gains" {
    var tp = TestPath.init(test_rate, test_rtt, 4 * test_bdp);
    defer tp.deinit();
    try tp.run(9 * sec);
    const l = tp.log.items;
    const down = tp.find(.probe_bw_down, 0).?;
    // one whole cycle from the first DOWN
    const order = [_]Bbr.State{ .probe_bw_down, .probe_bw_cruise, .probe_bw_refill, .probe_bw_up, .probe_bw_down };
    const gains = [_][2]u32{ .{ 90, 200 }, .{ 100, 200 }, .{ 100, 200 }, .{ 125, 225 }, .{ 90, 200 } };
    for (order, gains, 0..) |st, g, i| {
        try std.testing.expectEqual(st, l[down + i].state);
        try std.testing.expectEqual(g[0], l[down + i].pacing_gain);
        try std.testing.expectEqual(g[1], l[down + i].cwnd_gain);
    }
    // refill lasts exactly one round
    try std.testing.expectEqual(l[down + 2].round + 1, l[down + 3].round);
    // no loss and no inflight_longterm: the probe ends when three rounds bring no growth
    try std.testing.expect(l[down + 4].round - l[down + 3].round >= 3 and l[down + 4].round - l[down + 3].round <= 5);
    // the wait before a probe is 2 to 3 seconds of wall clock, or as many rounds as a Reno
    // flow of this window needs (41 here, 1.6 s), whichever is first
    const wait = l[down + 2].t - l[down].t;
    try std.testing.expect(wait >= 1 * sec and wait <= 3 * sec + 2 * test_rtt);
    try std.testing.expect(l[down + 2].round - l[down].round <= 43);
    // the cycles repeat, nothing was lost, and the link stayed in use: 95 percent over the
    // next 5 s, which hold a ProbeRTT (cruising paces at 0.99 of the rate)
    try std.testing.expect(tp.find(.probe_bw_up, down + 5) != null);
    try std.testing.expectEqual(@as(u64, 0), tp.lost);
    const got = try tp.deliveredIn(5 * sec);
    try std.testing.expect(got >= 5 * test_rate * 95 / 100 and got <= 5 * test_rate + 2 * test_bdp);
    try std.testing.expect(tp.b.max_bw >= test_rate * 97 / 100 and tp.b.max_bw <= test_rate * 101 / 100);
    // the window is two BDPs (plus the quantization budget), not more
    try std.testing.expect(tp.cwnd >= 2 * test_bdp * 95 / 100 and tp.cwnd <= 2 * test_bdp + 12 * TestPath.mtu);
}

test "bbr ProbeRTT: ten seconds without a new minimum halve the window for 200 ms and a round" {
    var tp = TestPath.init(test_rate, test_rtt, 4 * test_bdp);
    defer tp.deinit();
    try tp.run(9 * sec);
    try std.testing.expect(tp.find(.probe_rtt, 0) == null);
    const cwnd_before = tp.cwnd;
    const min_rtt_before = tp.b.min_rtt;
    // step through the entry
    while (tp.b.state != .probe_rtt) {
        try tp.run(tp.now + ms);
        try std.testing.expect(tp.now < 11 * sec);
    }
    const i = tp.find(.probe_rtt, 0).?;
    const e = tp.log.items[i];
    // the minimum was taken in the first rounds, so it expired a little after 10 s
    try std.testing.expect(e.t > 10 * sec and e.t < 10 * sec + 500 * ms);
    try std.testing.expectEqual(@as(u32, 100), e.pacing_gain);
    try std.testing.expectEqual(@as(u32, 50), e.cwnd_gain);
    // the window is half a BDP now (the floor is 4 datagrams) and what is in flight follows
    try std.testing.expect(tp.cwnd <= test_bdp / 2 + TestPath.mtu and tp.cwnd >= 4 * TestPath.mtu);
    try tp.run(tp.now + 2 * test_rtt);
    try std.testing.expect(tp.inflight <= test_bdp / 2 + TestPath.mtu);
    try std.testing.expectEqual(Bbr.State.probe_rtt, tp.b.state);
    try std.testing.expect(tp.b.app_limited != 0); // its low rate is not a sample of the path
    try tp.run(e.t + sec);
    // it left after at least 200 ms and one round, straight into cruise, and the window is back
    const x = tp.log.items[i + 1];
    try std.testing.expect(x.state == .probe_bw_down or x.state == .probe_bw_cruise);
    try std.testing.expectEqual(Bbr.State.probe_bw_cruise, tp.b.state);
    try std.testing.expect(x.t - e.t >= 200 * ms and x.t - e.t <= 200 * ms + 4 * test_rtt);
    try std.testing.expect(tp.cwnd >= cwnd_before * 9 / 10);
    // the estimates survived: same rate, same (or a fresher, equal) minimum
    try std.testing.expect(tp.b.max_bw >= test_rate * 97 / 100);
    try std.testing.expect(tp.b.min_rtt <= min_rtt_before + ms);
    // the next one is due ten seconds after this one ended, not sooner
    try tp.run(x.t + 9 * sec);
    try std.testing.expect(tp.find(.probe_rtt, i + 1) == null);
    try tp.run(x.t + 11 * sec);
    try std.testing.expect(tp.find(.probe_rtt, i + 1) != null);
}

test "bbr: a sender limited by its application gets a burst allowance and no ProbeRTT; one with a backlog neither" {
    var tp = TestPath.init(test_rate, test_rtt, 4 * test_bdp);
    defer tp.deinit();
    // a bulk transfer: never quiet, the bucket is the two send quanta it was
    try tp.run(3 * sec);
    try std.testing.expect(!tp.b.quiet());
    try std.testing.expectEqual(@as(u64, 0), tp.b.burstAllowance(tp.cwnd));
    // the path delivered a flight of about a BDP and more whole
    try std.testing.expect(tp.b.carried >= test_bdp);
    // the application writes a tenth of the path's rate for 25 s: two minimum round-trip
    // filter lengths, and no ProbeRTT (the path is empty of its packets most of the time)
    tp.app_rate = test_rate / 10;
    tp.app_from = tp.now;
    tp.app_sent = 0;
    const bw = tp.b.max_bw;
    try tp.run(tp.now + 25 * sec);
    try std.testing.expect(tp.b.quiet());
    try std.testing.expect(tp.find(.probe_rtt, 0) == null);
    try std.testing.expectEqual(bw, tp.b.max_bw);
    try std.testing.expect(tp.b.min_rtt <= test_rtt + 2 * ms);
    // what may leave at once after a pause: a minimum round trip of the pacing rate, at most
    // the window; and the window is not under what the path carried
    const allow = tp.b.burstAllowance(tp.cwnd);
    try std.testing.expectEqual(@min(Bbr.mulDiv(tp.b.pacing_rate, tp.b.min_rtt, sec), tp.cwnd), allow);
    try std.testing.expect(allow >= test_bdp * 9 / 10 and allow > 4 * tp.b.send_quantum);
    try std.testing.expect(tp.cwnd >= tp.b.carried and tp.b.carried >= test_bdp);
    // with a backlog again it is an ordinary BBR sender: no allowance, and ProbeRTT is back
    tp.app_rate = 0;
    try tp.run(tp.now + sec);
    try std.testing.expect(!tp.b.quiet());
    try std.testing.expectEqual(@as(u64, 0), tp.b.burstAllowance(tp.cwnd));
    try tp.run(tp.now + 11 * sec);
    try std.testing.expect(tp.find(.probe_rtt, 0) != null);
}

test "bbr: a quiet sender's burst that loses its tail bounds the next bursts; one random loss does not" {
    var cwnd: u64 = 1 << 20;
    var b = Bbr.init(0, 12_000, 1200, 1);
    b.min_rtt = 100 * ms;
    b.markAppLimited(0);
    // 200 packets leave in one go
    var pk: [200]Bbr.Pkt = undefined;
    for (&pk, 0..) |*p, i| p.* = b.onSent(1000, i * 1200, 1200, &cwnd);
    try std.testing.expectEqual(@as(u32, 240_000), pk[199].burst);
    // the first 100 arrive: a burst of 120,000 bytes has arrived whole
    b.ackBegin();
    for (pk[0..100], 0..) |p, i| b.onPacketAcked(101 * ms, p, 1000, i, 1200);
    try std.testing.expectEqual(@as(u64, 120_000), b.burst_ok);
    // one packet lost further on, then a second: that can be chance
    b.onPacketLost(102 * ms, pk[150], 1000, 1200, &cwnd);
    b.onPacketLost(102 * ms, pk[151], 1000, 1200, &cwnd);
    try std.testing.expectEqual(@as(u64, inf), b.burst_cap);
    try std.testing.expect(!b.burst_tail_round);
    // a third of the same burst, past what has arrived whole: its tail met the queue's end.
    // The bound is seven eighths of what arrived whole (never under half the lost position).
    b.onPacketLost(102 * ms, pk[152], 1000, 1200, &cwnd);
    try std.testing.expectEqual(@as(u64, 105_000), b.burst_cap);
    try std.testing.expectEqual(@as(u64, 105_000), b.burst_ok);
    try std.testing.expect(b.burst_tail_round);
    try std.testing.expect(b.quiet() and b.burstAllowance(cwnd) <= 105_000);
    // a sender with a backlog has no bursts in this sense, and no allowance
    b.app_quiet = 0;
    try std.testing.expectEqual(@as(u32, 0), b.onSent(2 * sec, 0, 1200, &cwnd).burst);
    try std.testing.expectEqual(@as(u64, 0), b.burstAllowance(cwnd));
}

test "pacer: a bucket with a depth lets a burst leave at once after a pause, at the rate without one" {
    var p: Pacer = .{};
    const mtu: u64 = 1200;
    const rate: u64 = 2_400_000; // 2,000 datagrams a second
    const quantum: u64 = 2400;
    const depth: u64 = 600_000; // a quarter of a second of the rate
    // straight after the last burst the bucket is empty, whatever its depth: the rate holds
    while (p.delayBurst(0, rate, mtu, 1 << 30, quantum, depth) == null) p.onSend(mtu);
    try std.testing.expect(p.delayBurst(0, rate, mtu, 1 << 30, quantum, depth) != null);
    // a pause of 100 ms brings 240,000 bytes: 200 datagrams leave at once
    var sent: u64 = 0;
    while (p.delayBurst(100 * ms, rate, mtu, 1 << 30, quantum, depth) == null) : (sent += 1) p.onSend(mtu);
    try std.testing.expectEqual(@as(u64, 200), sent);
    // a pause of a second: the depth, not more
    sent = 0;
    while (p.delayBurst(1100 * ms, rate, mtu, 1 << 30, quantum, depth) == null) : (sent += 1) p.onSend(mtu);
    try std.testing.expectEqual(@as(u64, 500), sent);
    // the same pause without a depth (a sender with a backlog): two quanta, as before
    sent = 0;
    while (p.delayBurst(2100 * ms, rate, mtu, 1 << 30, quantum, 0) == null) : (sent += 1) p.onSend(mtu);
    try std.testing.expectEqual(@as(u64, 4), sent);
    // and when the depth goes away while the bucket is full, what it held goes with it
    try std.testing.expectEqual(@as(?u64, null), p.delayBurst(3100 * ms, rate, mtu, 1 << 30, quantum, depth));
    try std.testing.expectEqual(depth, p.tokens);
    try std.testing.expectEqual(@as(?u64, null), p.delayBurst(3100 * ms, rate, mtu, 1 << 30, quantum, 0));
    try std.testing.expectEqual(@as(u64, 2 * quantum), p.tokens);
}

test "bbr: application-limited samples do not lower the bandwidth estimate; a slower path does" {
    var tp = TestPath.init(test_rate, test_rtt, 4 * test_bdp);
    defer tp.deinit();
    try tp.run(3 * sec);
    const bw = tp.b.max_bw;
    try std.testing.expect(bw >= test_rate * 97 / 100);
    // the application writes a tenth of the path's rate for 20 s (several probe cycles and a
    // ProbeRTT long)
    tp.app_rate = test_rate / 10;
    tp.app_from = tp.now;
    tp.app_sent = 0;
    const slow = try tp.deliveredIn(20 * sec);
    try std.testing.expect(slow <= 20 * test_rate / 10 + test_bdp and slow >= 20 * test_rate / 10 * 9 / 10);
    try std.testing.expect(tp.b.app_limited != 0);
    try std.testing.expectEqual(bw, tp.b.max_bw);
    try std.testing.expect(tp.b.bw >= bw * 95 / 100);
    // when it has data again the path is used in full at once
    tp.app_rate = 0;
    const fast = try tp.deliveredIn(sec);
    try std.testing.expect(fast >= test_rate * 93 / 100);
    try std.testing.expectEqual(@as(u64, 0), tp.lost);
    // the same low rate when the path, not the application, is the limit (with a queue of two
    // of its BDPs): the estimate follows once two probe cycles have passed
    tp.rate = test_rate / 10;
    tp.queue = 2 * test_bdp / 10;
    try tp.run(tp.now + 12 * sec);
    try std.testing.expect(tp.b.max_bw <= test_rate / 10 * 105 / 100);
    try std.testing.expect(tp.b.max_bw >= test_rate / 10 * 90 / 100);
}

test "bbr loss response: a round with loss cuts the short-term bounds by at most 0.7; refill lifts them" {
    var b = Bbr.init(0, 12_000, 1200, 1);
    var cwnd: u64 = 100_000;
    b.full_bw_reached = true;
    b.min_rtt = 40 * ms;
    b.max_bw = 1_000_000;
    b.max_bw_filter = .{ 1_000_000, 1_000_000 };
    b.bw = 1_000_000;
    b.startProbeBwDown(0);
    b.startProbeBwCruise();
    b.cycle_stamp = 10 * sec; // no probe during this test
    b.rounds_since_probe_up = 0;
    b.delivered = 500_000;
    b.next_round_delivered = 500_000;
    b.loss_round_delivered = 500_000;
    const mk = struct {
        fn ack(bb: *Bbr, now: u64, cw: *u64, rate_bytes: u64, inflight: u64) void {
            // one ACK that ends a round: `rate_bytes` delivered over the 40 ms before it
            const p: Bbr.Pkt = .{ .delivered = bb.delivered, .delivered_time = now - 40 * ms, .first_send_time = now - 80 * ms, .lost = bb.lost, .tx_in_flight = inflight };
            bb.ackBegin();
            bb.onPacketAcked(now, p, now - 40 * ms, 1, rate_bytes);
            bb.onAck(.{ .now = now, .inflight = inflight, .newly_acked = rate_bytes, .rtt = 40 * ms, .min_rtt = 40 * ms, .srtt = 40 * ms, .mtu = 1200 }, cw);
        }
    };
    // a clean round: no bounds
    mk.ack(&b, 1 * sec, &cwnd, 40_000, 40_000);
    try std.testing.expectEqual(inf, b.bw_shortterm);
    try std.testing.expectEqual(inf, b.inflight_shortterm);
    try std.testing.expectEqual(@as(u64, 1_000_000), b.bw);
    const cwnd0 = cwnd;
    // a round with one loss, in which the path still delivered the full rate: the bounds are
    // set to what was delivered (above 0.7 of the model), so the rate does not move
    b.onPacketLost(1 * sec + ms, .{ .delivered = b.delivered, .tx_in_flight = 40_000 }, 1 * sec, 1200, &cwnd);
    try std.testing.expect(b.is_loss_in_round and b.recovery_start != null);
    try std.testing.expectEqual(cwnd0, cwnd); // a loss alone does not cut the window
    mk.ack(&b, 1 * sec + 40 * ms, &cwnd, 40_000, 40_000);
    try std.testing.expectEqual(@as(u64, 1_000_000), b.bw_shortterm);
    try std.testing.expectEqual(@as(u64, 1_000_000), b.bw);
    try std.testing.expect(b.inflight_shortterm == cwnd0 * 7 / 10 and cwnd == b.inflight_shortterm);
    // rounds with loss in which a quarter of the rate arrived. The sample that ends a round
    // is also the first of the next one's maximum, so the bound follows one round later; then
    // it falls by 0.7 per round and no faster.
    b.onPacketLost(1 * sec + 41 * ms, .{ .delivered = b.delivered, .tx_in_flight = 40_000 }, 1 * sec + 30 * ms, 1200, &cwnd);
    mk.ack(&b, 1 * sec + 80 * ms, &cwnd, 10_000, 10_000);
    try std.testing.expectEqual(@as(u64, 1_000_000), b.bw_shortterm);
    b.onPacketLost(1 * sec + 81 * ms, .{ .delivered = b.delivered, .tx_in_flight = 40_000 }, 1 * sec + 70 * ms, 1200, &cwnd);
    mk.ack(&b, 1 * sec + 120 * ms, &cwnd, 10_000, 10_000);
    try std.testing.expectEqual(@as(u64, 700_000), b.bw_shortterm);
    try std.testing.expectEqual(@as(u64, 700_000), b.bw);
    try std.testing.expect(cwnd <= b.inflight_shortterm and b.inflight_shortterm < cwnd0 * 7 / 10);
    // the pacing rate follows: 0.99 of the bounded rate while cruising
    try std.testing.expectEqual(@as(u64, 700_000 * 99 / 100), b.pacing_rate);
    b.onPacketLost(1 * sec + 121 * ms, .{ .delivered = b.delivered, .tx_in_flight = 40_000 }, 1 * sec + 110 * ms, 1200, &cwnd);
    mk.ack(&b, 1 * sec + 160 * ms, &cwnd, 10_000, 10_000);
    try std.testing.expectEqual(@as(u64, 490_000), b.bw_shortterm);
    // never below what the last round delivered
    for (0..6) |k| {
        b.rounds_since_probe_up = 0; // keep the next probe out of this test
        b.onPacketLost(1 * sec + (161 + 40 * k) * ms, .{ .delivered = b.delivered, .tx_in_flight = 40_000 }, 1 * sec + (150 + 40 * k) * ms, 1200, &cwnd);
        mk.ack(&b, 1 * sec + (200 + 40 * k) * ms, &cwnd, 10_000, 10_000);
    }
    try std.testing.expectEqual(@as(u64, 250_000), b.bw_shortterm);
    try std.testing.expectEqual(@as(u64, 10_000), b.inflight_shortterm);
    // the long-term estimate is untouched, and the next refill starts from it
    try std.testing.expectEqual(@as(u64, 1_000_000), b.max_bw);
    b.startProbeBwRefill();
    try std.testing.expectEqual(inf, b.bw_shortterm);
    try std.testing.expectEqual(inf, b.inflight_shortterm);
    // losses while refilling or probing up do not set the short-term bounds
    b.onPacketLost(2 * sec, .{ .delivered = b.delivered, .tx_in_flight = 40_000 }, 2 * sec - ms, 1200, &cwnd);
    mk.ack(&b, 2 * sec + 40 * ms, &cwnd, 40_000, 40_000);
    try std.testing.expectEqual(inf, b.bw_shortterm);
    try std.testing.expectEqual(@as(u64, 1_000_000), b.bw);
}

test "bbr loss response: more than 2 percent lost in a probe sets inflight_longterm and ends the probe" {
    var b = Bbr.init(0, 12_000, 1200, 1);
    var cwnd: u64 = 100_000;
    b.full_bw_reached = true;
    b.min_rtt = 40 * ms;
    b.max_bw = 1_000_000;
    b.bw = 1_000_000; // a BDP of 40,000
    b.state = .probe_bw_up;
    b.check_probe_loss = true;
    // 1 of 100 datagrams in flight lost: under the threshold, nothing changes
    b.onPacketLost(sec, .{ .lost = 0, .tx_in_flight = 120_000 }, sec - ms, 1200, &cwnd);
    try std.testing.expectEqual(Bbr.State.probe_bw_up, b.state);
    try std.testing.expectEqual(inf, b.inflight_longterm);
    try std.testing.expect(!b.prev_probe_too_high);
    // a third datagram of the same flight lost: 3,600 of 120,000 is over 2 percent. The bound
    // is where the loss rate crossed it inside this packet, never under 0.7 of the target.
    b.onPacketLost(sec, .{ .lost = 0, .tx_in_flight = 120_000 }, sec - ms, 1200, &cwnd);
    b.onPacketLost(sec, .{ .lost = 0, .tx_in_flight = 120_000 }, sec - ms, 1200, &cwnd);
    try std.testing.expectEqual(Bbr.State.probe_bw_down, b.state);
    try std.testing.expect(b.prev_probe_too_high and !b.check_probe_loss);
    // inflight before the packet 118,800, lost before it 2,400: no prefix of it fits, so
    // 118,800 (the target, min(BDP, cwnd) = 40,000, times 0.7 is lower)
    try std.testing.expectEqual(@as(u64, 118_800), b.inflight_longterm);
    try std.testing.expectEqual(@as(u32, 90), b.pacing_gain);
    // further losses of that probe change nothing (one reaction per probe)
    b.onPacketLost(sec, .{ .lost = 0, .tx_in_flight = 60_000 }, sec - ms, 1200, &cwnd);
    try std.testing.expectEqual(@as(u64, 118_800), b.inflight_longterm);
    // a small flight: the 0.7 floor holds the bound up
    var c = Bbr.init(0, 12_000, 1200, 1);
    c.full_bw_reached = true;
    c.min_rtt = 40 * ms;
    c.bw = 1_000_000;
    c.state = .probe_bw_up;
    c.check_probe_loss = true;
    c.onPacketLost(sec, .{ .lost = 0, .tx_in_flight = 12_000 }, sec - ms, 1200, &cwnd);
    try std.testing.expectEqual(@as(u64, 28_000), c.inflight_longterm);
    // the window is bounded by it from the next ACK on (0.85 of it while cruising)
    c.startProbeBwCruise();
    c.delivered = 100_000;
    c.ackBegin();
    c.onPacketAcked(2 * sec, .{ .delivered = 0, .delivered_time = 2 * sec - 40 * ms, .first_send_time = 2 * sec - 80 * ms, .tx_in_flight = 20_000 }, 2 * sec - 40 * ms, 9, 1200);
    c.onAck(.{ .now = 2 * sec, .inflight = 20_000, .newly_acked = 1200, .rtt = 40 * ms, .min_rtt = 40 * ms, .srtt = 40 * ms, .mtu = 1200 }, &cwnd);
    try std.testing.expectEqual(@as(u64, 28_000 - 28_000 * 15 / 100), cwnd);
}

test "bbr on a shallow queue: startup ends on loss, probes find the queue, and loss stays low after" {
    // a queue of a fifth of a BDP: 8 datagrams
    var tp = TestPath.init(test_rate, test_rtt, test_bdp / 5);
    defer tp.deinit();
    try tp.run(2 * sec);
    try std.testing.expect(tp.b.full_bw_reached);
    try std.testing.expect(tp.lost > 0);
    try tp.run(12 * sec);
    // the probes hit the queue's end: the long-term bound is the BDP plus about the queue
    try std.testing.expect(tp.b.inflight_longterm != inf);
    try std.testing.expect(tp.b.inflight_longterm >= test_bdp * 8 / 10 and tp.b.inflight_longterm <= test_bdp + test_bdp / 5 + 6 * TestPath.mtu);
    try std.testing.expect(tp.b.max_bw >= test_rate * 95 / 100 and tp.b.max_bw <= test_rate * 101 / 100);
    // steady state: under 1 percent lost and over 90 percent of the link used, for 10 s. A
    // sender that ignored loss at 1.25 times the rate would lose a fifth.
    const lost0 = tp.lost;
    const got = try tp.deliveredIn(10 * sec);
    const lost = tp.lost - lost0;
    try std.testing.expect(lost * 100 < got);
    try std.testing.expect(got >= 10 * test_rate * 90 / 100);
}

test "bbr: random loss of 1 percent does not hold the rate down; startup high loss needs 6 losses over 2 percent" {
    var tp = TestPath.init(test_rate, test_rtt, 4 * test_bdp);
    defer tp.deinit();
    tp.drop_every = 100;
    try tp.run(3 * sec);
    try std.testing.expect(tp.b.full_bw_reached);
    const got = try tp.deliveredIn(10 * sec);
    // a loss-based sender gets about 1.2 * MSS / (RTT * sqrt(p)) = 0.36 MB/s here
    try std.testing.expect(got >= 10 * test_rate * 85 / 100);
    // CheckStartupHighLoss by hand: in recovery, a loss round ends, 6 losses, over 2 percent
    var b = Bbr.init(0, 12_000, 1200, 1);
    var cwnd: u64 = 60_000;
    b.min_rtt = 40 * ms;
    b.bw = 500_000;
    b.delivered = 100_000;
    for (0..5) |_| b.onPacketLost(sec, .{ .tx_in_flight = 60_000 }, sec - ms, 1200, &cwnd);
    b.ackBegin();
    b.onPacketAcked(sec + ms, .{ .delivered = 100_000, .delivered_time = sec - 40 * ms, .first_send_time = sec - 80 * ms, .tx_in_flight = 60_000 }, sec - 39 * ms, 5, 1200);
    b.onAck(.{ .now = sec + ms, .inflight = 50_000, .newly_acked = 1200, .rtt = 40 * ms, .min_rtt = 40 * ms, .srtt = 40 * ms, .mtu = 1200 }, &cwnd);
    try std.testing.expectEqual(Bbr.State.startup, b.state); // 5 losses: not yet
    for (0..6) |_| b.onPacketLost(sec + 2 * ms, .{ .delivered = b.delivered, .tx_in_flight = 60_000 }, sec + ms, 1200, &cwnd);
    b.ackBegin();
    b.onPacketAcked(sec + 3 * ms, .{ .delivered = b.delivered, .delivered_time = sec - 38 * ms, .first_send_time = sec - 78 * ms, .lost = b.lost - 6 * 1200, .tx_in_flight = 60_000 }, sec + ms, 6, 1200);
    b.onAck(.{ .now = sec + 3 * ms, .inflight = 40_000, .newly_acked = 1200, .rtt = 40 * ms, .min_rtt = 40 * ms, .srtt = 40 * ms, .mtu = 1200 }, &cwnd);
    try std.testing.expect(b.full_bw_reached);
    try std.testing.expectEqual(Bbr.State.drain, b.state);
    try std.testing.expect(b.inflight_longterm != inf);
}
