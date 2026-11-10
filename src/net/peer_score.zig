//! State-sync peer scoring, a port of sui-node 1.83.1:
//!   - `PeerScore`: sui-network/src/state_sync/mod.rs PeerScore (20 samples each of successes and
//!     failures, a 60 s window, failing at a 0.3 failure rate with at least 10 samples in the
//!     window, effective throughput = bytes / response time over the window's successes);
//!   - `order`: PeerBalancer (known peers by throughput-weighted random choice, peers without a
//!     throughput by RTT, unknown peers explored with probability 0.1, failing peers last);
//!   - `Table.maybeReportFailing`: StateSync's maybe_report_failing_peer (a peer failing for 30 s
//!     is reported) plus Discovery's handle_peer_failure_report (configured peers are never
//!     dropped, nor any peer while fewer than 2 are connected; a dropped peer is cooled down for
//!     1 h, during which it is dialed only to reach the 4-connection target);
//!   - `Pinned`: state-sync `pinned-checkpoints` (a summary at a pinned sequence number must have
//!     the pinned digest; a peer serving another is treated as on another chain).
//! Defaults: sui-config/src/p2p.rs (StateSyncConfig, DiscoveryConfig).
//!
//! Time is passed in (monotonic ns) so the tests are deterministic; sui reads Instant::now().
//! zui-specific: pruning of discovered peers that never connect.
const std = @import("std");
const Atomic = std.atomic.Value;

pub const ns_per_ms: u64 = std.time.ns_per_ms;

pub const Config = struct {
    /// StateSyncConfig.peer_scoring_window_ms (60 s).
    window_ns: u64 = 60_000 * ns_per_ms,
    /// StateSyncConfig.peer_failure_rate (0.3).
    failure_rate: f64 = 0.3,
    /// StateSyncConfig.exploration_probability (0.1).
    exploration: f64 = 0.1,
    /// StateSyncConfig.peer_disconnect_threshold_ms (30 s; 0 disables reporting).
    disconnect_threshold_ns: u64 = 30_000 * ns_per_ms,
    /// DiscoveryConfig.peer_failure_cooldown_ms (1 h).
    cooldown_ns: u64 = 3_600_000 * ns_per_ms,
    /// DiscoveryConfig.min_peers_for_disconnect (2).
    min_peers_for_disconnect: usize = 2,
    /// DiscoveryConfig.target_concurrent_connections (4).
    target_connections: usize = 4,
    /// deepwave: a discovered peer that failed this many connects in a row and never connected is
    /// pruned (its thread ends). 0: never prune.
    prune_after_failed_connects: u32 = 6,
};

fn Ring(comptime T: type, comptime cap: usize) type {
    return struct {
        const Self = @This();
        buf: [cap]T = undefined,
        head: usize = 0,
        len: usize = 0,

        /// push_back, then pop_front while over `cap` (VecDeque with MAX_SAMPLES).
        fn push(r: *Self, v: T) void {
            if (r.len == cap) {
                r.buf[r.head] = v;
                r.head = (r.head + 1) % cap;
            } else {
                r.buf[(r.head + r.len) % cap] = v;
                r.len += 1;
            }
        }

        fn at(r: *const Self, i: usize) T {
            return r.buf[(r.head + i) % cap];
        }
    };
}

pub const PeerScore = struct {
    pub const max_samples = 20;
    pub const min_samples_for_failure = 10;
    const Success = struct { at: u64, size: u64, rt_ns: u64 };

    successes: Ring(Success, max_samples) = .{},
    failures: Ring(u64, max_samples) = .{},
    window_ns: u64,
    failure_rate: f64,
    failing_since: ?u64 = null,

    pub fn init(window_ns: u64, failure_rate: f64) PeerScore {
        return .{ .window_ns = window_ns, .failure_rate = failure_rate };
    }

    /// A single success does not clear `failing_since` (sui: the windowed failure rate decides).
    pub fn recordSuccess(s: *PeerScore, now: u64, size: u64, rt_ns: u64) void {
        s.successes.push(.{ .at = now, .size = size, .rt_ns = rt_ns });
    }

    pub fn recordFailure(s: *PeerScore, now: u64) void {
        s.failures.push(now);
    }

    fn inWindow(s: *const PeerScore, now: u64, at: u64) bool {
        return now -| at < s.window_ns;
    }

    pub fn isFailing(s: *const PeerScore, now: u64) bool {
        var f: usize = 0;
        for (0..s.failures.len) |i| f += @intFromBool(s.inWindow(now, s.failures.at(i)));
        var ok: usize = 0;
        for (0..s.successes.len) |i| ok += @intFromBool(s.inWindow(now, s.successes.at(i).at));
        const total = f + ok;
        if (total < min_samples_for_failure) return false;
        const rate = @as(f64, @floatFromInt(f)) / @as(f64, @floatFromInt(total));
        return rate >= s.failure_rate;
    }

    /// Starts the consistently-failing clock when the windowed rate crosses the threshold and
    /// clears it only when the rate drops back below.
    pub fn updateFailingState(s: *PeerScore, now: u64) void {
        if (s.isFailing(now)) {
            if (s.failing_since == null) s.failing_since = now;
        } else s.failing_since = null;
    }

    pub fn resetFailingSince(s: *PeerScore) void {
        s.failing_since = null;
    }

    pub fn consistentlyFailing(s: *const PeerScore, now: u64, threshold_ns: u64) bool {
        const since = s.failing_since orelse return false;
        return now -| since >= threshold_ns;
    }

    /// Bytes per second over the window's successes (null: no bytes or no time).
    pub fn effectiveThroughput(s: *const PeerScore, now: u64) ?f64 {
        var size: u64 = 0;
        var time: u64 = 0;
        for (0..s.successes.len) |i| {
            const x = s.successes.at(i);
            if (!s.inWindow(now, x.at)) continue;
            size += x.size;
            time += x.rt_ns;
        }
        if (size == 0 or time == 0) return null;
        return @as(f64, @floatFromInt(size)) / (@as(f64, @floatFromInt(time)) / std.time.ns_per_s);
    }
};

// ------------------------------------------------------------------ balancer

/// What the balancer needs to know about a peer (sui: PeerStateSyncInfo plus the connection).
pub const PeerInfo = struct {
    connected: bool,
    on_same_chain: bool = true,
    height: u64,
    lowest: u64 = 0,
    /// Connection round trip (ns; maxInt: not measured yet).
    rtt_ns: u64 = std.math.maxInt(u64),
};

pub const RequestType = enum { summary, content };

const Cand = struct { idx: u8, w: f64 };

/// sui PeerBalancer, run to exhaustion: peer indices in the order it would yield them for a
/// request of checkpoint `seq`. `scores[i]` is null for a peer without a score (no samples yet).
/// Returns how many indices were written to `out`.
pub fn order(
    scores: []const ?*const PeerScore,
    infos: []const PeerInfo,
    now: u64,
    req: RequestType,
    seq: u64,
    exploration: f64,
    rng: std.Random,
    out: []u8,
) usize {
    std.debug.assert(scores.len == infos.len and infos.len <= 256);
    var known_buf: [256]Cand = undefined;
    var unknown_buf: [256]Cand = undefined;
    var failing_buf: [256]u8 = undefined;
    var nk: usize = 0;
    var nu: usize = 0;
    var nf: usize = 0;
    for (infos, scores, 0..) |info, sc, i| {
        if (!info.on_same_chain or !info.connected) continue;
        const idx: u8 = @intCast(i);
        if (sc) |s| {
            if (s.isFailing(now)) {
                failing_buf[nf] = idx;
                nf += 1;
                continue;
            }
            if (s.effectiveThroughput(now)) |t| {
                known_buf[nk] = .{ .idx = idx, .w = t };
                nk += 1;
                continue;
            }
        }
        unknown_buf[nu] = .{ .idx = idx, .w = @floatFromInt(info.rtt_ns) };
        nu += 1;
    }
    std.sort.insertion(Cand, unknown_buf[0..nu], {}, struct {
        fn lt(_: void, a: Cand, b: Cand) bool {
            return a.w < b.w;
        }
    }.lt);
    var known = std.ArrayList(Cand).initBuffer(&known_buf);
    known.items.len = nk;
    var unknown = std.ArrayList(Cand).initBuffer(&unknown_buf);
    unknown.items.len = nu;
    var failing = std.ArrayList(u8).initBuffer(&failing_buf);
    failing.items.len = nf;

    const eligible = struct {
        fn f(info: PeerInfo, r: RequestType, s: u64) bool {
            return switch (r) {
                .summary => info.height >= s,
                .content => info.height >= s and info.lowest <= s,
            };
        }
    }.f;

    var n: usize = 0;
    while (n < out.len) {
        var has_known = false;
        for (known.items) |c| has_known = has_known or eligible(infos[c.idx], req, seq);
        var has_unknown = false;
        for (unknown.items) |c| has_unknown = has_unknown or eligible(infos[c.idx], req, seq);
        const explore = has_unknown and (!has_known or rng.float(f64) < exploration);
        if (explore) {
            // select_by_rtt: the first eligible unknown peer (sorted by RTT).
            for (unknown.items, 0..) |c, k| if (eligible(infos[c.idx], req, seq)) {
                out[n] = c.idx;
                n += 1;
                _ = unknown.orderedRemove(k);
                break;
            };
            continue;
        }
        if (has_known) {
            // select_by_throughput: weighted random over the eligible known peers.
            var total: f64 = 0;
            for (known.items) |c| if (eligible(infos[c.idx], req, seq)) {
                total += c.w;
            };
            var pick = rng.float(f64) * total;
            var chosen: ?usize = null;
            var last: usize = 0;
            for (known.items, 0..) |c, k| if (eligible(infos[c.idx], req, seq)) {
                last = k;
                pick -= c.w;
                if (pick <= 0) {
                    chosen = k;
                    break;
                }
            };
            const k = chosen orelse last;
            out[n] = known.items[k].idx;
            n += 1;
            _ = known.orderedRemove(k);
            continue;
        }
        // select_failing: the first eligible failing peer.
        const pos = for (failing.items, 0..) |idx, k| {
            if (eligible(infos[idx], req, seq)) break k;
        } else break;
        out[n] = failing.items[pos];
        n += 1;
        _ = failing.orderedRemove(pos);
    }
    return n;
}

// ------------------------------------------------------------------ pinned checkpoints

/// state-sync `pinned-checkpoints`: (sequence number, summary digest), sorted by sequence number.
pub const Pinned = struct {
    pub const Entry = struct { seq: u64, digest: [32]u8 };
    pub const Verdict = enum { not_pinned, match, mismatch };

    items: []const Entry = &.{},

    /// Sorts `items` in place (sui sorts the config list once at start).
    pub fn init(items: []Entry) Pinned {
        std.sort.pdq(Entry, items, {}, struct {
            fn lt(_: void, a: Entry, b: Entry) bool {
                return a.seq < b.seq;
            }
        }.lt);
        return .{ .items = items };
    }

    pub fn check(p: Pinned, seq: u64, digest: *const [32]u8) Verdict {
        var lo: usize = 0;
        var hi: usize = p.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (p.items[mid].seq < seq) lo = mid + 1 else hi = mid;
        }
        if (lo == p.items.len or p.items[lo].seq != seq) return .not_pinned;
        return if (std.mem.eql(u8, &p.items[lo].digest, digest)) .match else .mismatch;
    }
};

// ------------------------------------------------------------------ table

pub const SpinLock = struct {
    v: Atomic(u32) = .init(0),
    pub fn lock(l: *SpinLock) void {
        while (l.v.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    pub fn unlock(l: *SpinLock) void {
        l.v.store(0, .release);
    }
};

pub const max_peers = 64;
const cache_len = 8;
const Cached = struct { seq: u64 = std.math.maxInt(u64), ns: u64 = 0, pos: [max_peers]u8 = @splat(255) };

pub const TableStats = struct {
    /// Peers reported as consistently failing (sui inc_peers_reported_for_failure).
    reported: Atomic(u64) = .init(0),
    /// Reports that dropped the peer and started its cooldown.
    dropped: Atomic(u64) = .init(0),
    /// Reports ignored: a configured (seed) peer, or too few peers connected.
    kept: Atomic(u64) = .init(0),
    /// Discovered peers pruned after failing every connect.
    pruned: Atomic(u64) = .init(0),
    /// Summaries rejected by a pinned checkpoint (the peer is then off-chain).
    pinned_rejects: Atomic(u64) = .init(0),
    successes: Atomic(u64) = .init(0),
    failures: Atomic(u64) = .init(0),
};

/// Per-peer scores and connection policy for up to `max_peers` peers, indexed like p2p.zig's
/// peer threads. Thread safe (one short spin lock).
pub const Table = struct {
    cfg: Config = .{},
    lock: SpinLock = .{},
    scores: [max_peers]PeerScore = undefined,
    has_score: [max_peers]bool = @splat(false),
    /// Configured peers (seeds): never dropped (sui is_trusted_peer).
    trusted: [max_peers]bool = @splat(false),
    off_chain: [max_peers]bool = @splat(false),
    cooldown_since: [max_peers]?u64 = @splat(null),
    /// Set by a report: the peer's thread disconnects and clears it.
    drop: [max_peers]Atomic(bool) = @splat(.init(false)),
    failed_connects: [max_peers]u32 = @splat(0),
    ever_connected: [max_peers]bool = @splat(false),
    stats: TableStats = .{},
    // Cached balancer orders (`rank`), one per checkpoint, by `seq % cache_len`.
    cache: [cache_len]Cached = @splat(.{}),
    seed: u64 = 0x5c0e_5c0e,

    fn invalidate(t: *Table) void {
        for (&t.cache) |*c| c.seq = std.math.maxInt(u64);
    }

    fn scoreOf(t: *Table, peer: usize) *PeerScore {
        if (!t.has_score[peer]) {
            t.scores[peer] = .init(t.cfg.window_ns, t.cfg.failure_rate);
            t.has_score[peer] = true;
        }
        return &t.scores[peer];
    }

    pub fn recordSuccess(t: *Table, peer: usize, size: u64, rt_ns: u64, now: u64) void {
        if (peer >= max_peers) return;
        t.lock.lock();
        defer t.lock.unlock();
        if (t.off_chain[peer]) return;
        t.scoreOf(peer).recordSuccess(now, size, rt_ns);
        _ = t.stats.successes.fetchAdd(1, .monotonic);
    }

    pub fn recordFailure(t: *Table, peer: usize, now: u64) void {
        if (peer >= max_peers) return;
        t.lock.lock();
        defer t.lock.unlock();
        if (t.off_chain[peer]) return;
        t.scoreOf(peer).recordFailure(now);
        _ = t.stats.failures.fetchAdd(1, .monotonic);
    }

    pub fn throughput(t: *Table, peer: usize, now: u64) ?f64 {
        t.lock.lock();
        defer t.lock.unlock();
        return if (t.has_score[peer]) t.scores[peer].effectiveThroughput(now) else null;
    }

    pub fn isFailing(t: *Table, peer: usize, now: u64) bool {
        t.lock.lock();
        defer t.lock.unlock();
        return t.has_score[peer] and t.scores[peer].isFailing(now);
    }

    /// sui LostPeer: the peer's score goes with the connection.
    /// A connection slot that now holds another peer (p2p.zig's rotating discovered slots):
    /// everything known about the previous one is forgotten.
    pub fn resetPeer(t: *Table, peer: usize) void {
        if (peer >= max_peers) return;
        t.lock.lock();
        defer t.lock.unlock();
        t.has_score[peer] = false;
        t.trusted[peer] = false;
        t.off_chain[peer] = false;
        t.cooldown_since[peer] = null;
        t.drop[peer].store(false, .release);
        t.failed_connects[peer] = 0;
        t.ever_connected[peer] = false;
        t.invalidate();
    }

    pub fn lostPeer(t: *Table, peer: usize) void {
        if (peer >= max_peers) return;
        t.lock.lock();
        defer t.lock.unlock();
        t.has_score[peer] = false;
        t.invalidate();
    }

    /// sui mark_peer_as_not_on_same_chain: excluded from every choice, score removed, and its
    /// connection dropped.
    pub fn markOffChain(t: *Table, peer: usize) void {
        if (peer >= max_peers) return;
        t.lock.lock();
        defer t.lock.unlock();
        t.off_chain[peer] = true;
        t.has_score[peer] = false;
        t.drop[peer].store(true, .release);
        t.invalidate();
    }

    pub fn isOffChain(t: *Table, peer: usize) bool {
        return peer < max_peers and @atomicLoad(bool, &t.off_chain[peer], .monotonic);
    }

    /// sui find_peer_to_report_for_failure (after update_failing_states): the same-chain peer
    /// consistently failing for the longest, at least `threshold`.
    pub fn findPeerToReport(t: *Table, now: u64, threshold_ns: u64) ?usize {
        var best: ?usize = null;
        var best_age: u64 = 0;
        for (0..max_peers) |i| {
            if (!t.has_score[i] or t.off_chain[i]) continue;
            const s = &t.scores[i];
            if (!s.consistentlyFailing(now, threshold_ns)) continue;
            const age = now -| s.failing_since.?;
            if (best == null or age > best_age) {
                best = i;
                best_age = age;
            }
        }
        return best;
    }

    /// One state-sync tick: StateSync maybe_report_failing_peer, then Discovery
    /// handle_peer_failure_report. Returns the peer dropped (its `drop` flag is set and its
    /// cooldown started), if any. `connected`: peers connected now.
    pub fn maybeReportFailing(t: *Table, now: u64, connected: usize) ?usize {
        if (t.cfg.disconnect_threshold_ns == 0) return null;
        t.lock.lock();
        defer t.lock.unlock();
        for (0..max_peers) |i| if (t.has_score[i]) t.scores[i].updateFailingState(now);
        const peer = t.findPeerToReport(now, t.cfg.disconnect_threshold_ns) orelse return null;
        // So the peer is not re-reported every tick; it must fail another full threshold.
        t.scores[peer].resetFailingSince();
        _ = t.stats.reported.fetchAdd(1, .monotonic);
        if (t.trusted[peer] or connected < t.cfg.min_peers_for_disconnect) {
            _ = t.stats.kept.fetchAdd(1, .monotonic);
            return null;
        }
        t.drop[peer].store(true, .release);
        t.cooldown_since[peer] = now;
        t.invalidate();
        _ = t.stats.dropped.fetchAdd(1, .monotonic);
        return peer;
    }

    /// The peer's thread saw its drop flag (and disconnects).
    pub fn takeDrop(t: *Table, peer: usize) bool {
        return peer < max_peers and t.drop[peer].swap(false, .acq_rel);
    }

    pub fn onCooldown(t: *Table, peer: usize, now: u64) bool {
        t.lock.lock();
        defer t.lock.unlock();
        return t.onCooldownLocked(peer, now);
    }

    fn onCooldownLocked(t: *Table, peer: usize, now: u64) bool {
        const since = t.cooldown_since[peer] orelse return false;
        if (now -| since >= t.cfg.cooldown_ns) {
            t.cooldown_since[peer] = null; // expired: back to preferred
            return false;
        }
        return true;
    }

    /// Discovery handle_tick: a peer on cooldown is dialed only to fill the connection target
    /// (cooldown peers are deprioritized, not blocked); an off-chain peer never.
    pub fn mayDial(t: *Table, peer: usize, now: u64, connected: usize) bool {
        if (peer >= max_peers) return true;
        t.lock.lock();
        defer t.lock.unlock();
        if (t.off_chain[peer]) return false;
        if (!t.onCooldownLocked(peer, now)) return true;
        return connected < t.cfg.target_connections;
    }

    /// Records a connect attempt. True: prune the peer (a discovered peer that never connected
    /// and failed `prune_after_failed_connects` times in a row).
    pub fn noteConnect(t: *Table, peer: usize, ok: bool) bool {
        if (peer >= max_peers) return false;
        t.lock.lock();
        defer t.lock.unlock();
        if (ok) {
            t.failed_connects[peer] = 0;
            t.ever_connected[peer] = true;
            return false;
        }
        t.failed_connects[peer] +|= 1;
        const limit = t.cfg.prune_after_failed_connects;
        if (limit == 0 or t.trusted[peer] or t.ever_connected[peer]) return false;
        if (t.failed_connects[peer] < limit) return false;
        _ = t.stats.pruned.fetchAdd(1, .monotonic);
        return true;
    }

    /// Position of `peer` in the balancer's order for content request `seq` among the peers
    /// `view` reports (`view.count()`, `view.info(j)`), or `max_peers` when it is not eligible.
    /// The order is computed once per checkpoint (refreshed every `refresh_ns`) with an RNG seeded
    /// by the sequence number, so every peer thread sees the same order for a checkpoint while
    /// exploration still varies between checkpoints.
    pub fn rank(t: *Table, peer: usize, seq: u64, now: u64, view: anytype) usize {
        const refresh_ns = 100 * ns_per_ms;
        t.lock.lock();
        defer t.lock.unlock();
        const c = &t.cache[seq % cache_len];
        if (c.seq != seq or now -| c.ns >= refresh_ns) {
            const n = @min(view.count(), max_peers);
            var infos: [max_peers]PeerInfo = undefined;
            var sc: [max_peers]?*const PeerScore = undefined;
            for (0..n) |j| {
                infos[j] = view.info(j);
                infos[j].on_same_chain = infos[j].on_same_chain and !t.off_chain[j];
                sc[j] = if (t.has_score[j]) &t.scores[j] else null;
            }
            var prng = std.Random.DefaultPrng.init(seq ^ t.seed);
            var out: [max_peers]u8 = undefined;
            const got = order(sc[0..n], infos[0..n], now, .content, seq, t.cfg.exploration, prng.random(), &out);
            c.pos = @splat(255);
            for (out[0..got], 0..) |idx, k| c.pos[idx] = @intCast(k);
            c.seq = seq;
            c.ns = now;
        }
        if (peer >= max_peers) return max_peers;
        const pos = c.pos[peer];
        return if (pos == 255) max_peers else pos;
    }
};

// ------------------------------------------------------------------ tests (mirror sui's)

const testing = std.testing;
const s_ns = std.time.ns_per_s;
const win: u64 = 60 * s_ns;

test "peer score throughput calculation (sui test_peer_score_throughput_calculation)" {
    var s = PeerScore.init(win, 0.3);
    const now: u64 = 1000 * s_ns;
    try testing.expect(s.effectiveThroughput(now) == null);
    try testing.expect(!s.isFailing(now));
    s.recordSuccess(now, 100, 1 * s_ns);
    try testing.expectApproxEqAbs(@as(f64, 100), s.effectiveThroughput(now).?, 0.01);
    s.recordSuccess(now, 200, 2 * s_ns);
    try testing.expectApproxEqAbs(@as(f64, 100), s.effectiveThroughput(now).?, 0.01);
    s.recordSuccess(now, 500, 1 * s_ns);
    try testing.expectApproxEqAbs(@as(f64, 200), s.effectiveThroughput(now).?, 0.01);
}

test "peer score failure tracking (sui test_peer_score_failure_tracking)" {
    var s = PeerScore.init(win, 0.3);
    const now: u64 = 1000 * s_ns;
    try testing.expect(!s.isFailing(now));
    for (0..7) |_| s.recordSuccess(now, 100, s_ns);
    s.recordFailure(now);
    s.recordFailure(now);
    try testing.expect(!s.isFailing(now)); // 2/9, below 10 samples
    s.recordSuccess(now, 100, s_ns);
    try testing.expect(!s.isFailing(now)); // 2/10
    s.recordFailure(now);
    try testing.expect(!s.isFailing(now)); // 3/11
    s.recordFailure(now);
    try testing.expect(s.isFailing(now)); // 4/12
}

test "peer score samples outside the window and the 20-sample cap" {
    var s = PeerScore.init(win, 0.3);
    const t0: u64 = 1000 * s_ns;
    for (0..10) |_| s.recordFailure(t0);
    try testing.expect(s.isFailing(t0));
    try testing.expect(!s.isFailing(t0 + win)); // all aged out
    for (0..30) |_| s.recordSuccess(t0, 10, s_ns);
    try testing.expectEqual(@as(usize, 20), s.successes.len);
    try testing.expectApproxEqAbs(@as(f64, 10), s.effectiveThroughput(t0).?, 0.01);
    s.recordSuccess(t0, 0, 0);
    try testing.expectEqual(@as(usize, 20), s.successes.len);
    var z = PeerScore.init(win, 0.3);
    z.recordSuccess(t0, 0, s_ns);
    try testing.expect(z.effectiveThroughput(t0) == null); // no bytes
    z.recordSuccess(t0, 5, 0);
    z = PeerScore.init(win, 0.3);
    z.recordSuccess(t0, 5, 0);
    try testing.expect(z.effectiveThroughput(t0) == null); // no time
}

test "peer heights score recording (sui test_peer_heights_score_recording)" {
    var t: Table = .{};
    const now: u64 = 1000 * s_ns;
    try testing.expect(t.throughput(0, now) == null);
    try testing.expect(!t.isFailing(0, now));
    t.recordSuccess(0, 100, s_ns, now);
    try testing.expectApproxEqAbs(@as(f64, 100), t.throughput(0, now).?, 0.01);
    t.recordSuccess(0, 200, s_ns, now);
    try testing.expectApproxEqAbs(@as(f64, 150), t.throughput(0, now).?, 0.01);
    for (0..6) |_| t.recordSuccess(0, 100, s_ns, now);
    t.recordFailure(0, now);
    t.recordFailure(0, now);
    try testing.expect(!t.isFailing(0, now));
    t.recordFailure(0, now);
    t.recordFailure(0, now);
    try testing.expect(t.isFailing(0, now));
}

test "peer balancer sorts by throughput (sui test_peer_balancer_sorts_by_throughput)" {
    const now: u64 = 1000 * s_ns;
    var slow = PeerScore.init(win, 0.3);
    slow.recordSuccess(now, 100, 10 * s_ns); // 10 B/s
    var fast = PeerScore.init(win, 0.3);
    fast.recordSuccess(now, 1000, s_ns); // 1000 B/s
    const scores = [_]?*const PeerScore{ &slow, &fast };
    const infos = [_]PeerInfo{ .{ .connected = true, .height = 10 }, .{ .connected = true, .height = 10 } };
    // Weighted random: the fast peer comes first in ~99% of draws; count over many seeds.
    var first_fast: usize = 0;
    for (0..1000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var out: [4]u8 = undefined;
        const n = order(&scores, &infos, now, .summary, 0, 0.1, prng.random(), &out);
        try testing.expectEqual(@as(usize, 2), n);
        if (out[0] == 1) first_fast += 1;
    }
    try testing.expect(first_fast >= 970);
}

test "peer balancer: unknown by RTT, exploration, failing last, eligibility" {
    const now: u64 = 1000 * s_ns;
    var known = PeerScore.init(win, 0.3);
    known.recordSuccess(now, 1000, s_ns);
    var bad = PeerScore.init(win, 0.3);
    for (0..10) |_| bad.recordFailure(now);
    const scores = [_]?*const PeerScore{ null, null, &known, &bad, null, null };
    const infos = [_]PeerInfo{
        .{ .connected = true, .height = 10, .rtt_ns = 50 * ns_per_ms },
        .{ .connected = true, .height = 10, .rtt_ns = 5 * ns_per_ms },
        .{ .connected = true, .height = 10 },
        .{ .connected = true, .height = 10 },
        .{ .connected = false, .height = 10, .rtt_ns = 1 }, // not connected
        .{ .connected = true, .height = 3, .rtt_ns = 1 }, // below the requested checkpoint
    };
    // Exploration 0: the known peer, then unknown by RTT (no known left), then failing.
    var prng = std.Random.DefaultPrng.init(7);
    var out: [8]u8 = undefined;
    var n = order(&scores, &infos, now, .content, 5, 0, prng.random(), &out);
    try testing.expectEqualSlices(u8, &.{ 2, 1, 0, 3 }, out[0..n]);
    // Exploration 1: unknown peers (by RTT) before the known one.
    n = order(&scores, &infos, now, .content, 5, 1, prng.random(), &out);
    try testing.expectEqualSlices(u8, &.{ 1, 0, 2, 3 }, out[0..n]);
    // Content: a peer whose lowest is above the checkpoint is not eligible.
    var infos2 = infos;
    infos2[2].lowest = 6;
    n = order(&scores, &infos2, now, .content, 5, 0, prng.random(), &out);
    try testing.expectEqualSlices(u8, &.{ 1, 0, 3 }, out[0..n]);
    // Off-chain peers are never chosen.
    infos2[1].on_same_chain = false;
    n = order(&scores, &infos2, now, .summary, 5, 0, prng.random(), &out);
    try testing.expectEqualSlices(u8, &.{ 2, 0, 3 }, out[0..n]);
    // Exploration 0.1 over many checkpoints: the unknown peer leads about 10% of the time.
    var explored: usize = 0;
    for (0..2000) |seed| {
        var p2 = std.Random.DefaultPrng.init(seed);
        n = order(&scores, &infos, now, .content, 5, 0.1, p2.random(), &out);
        if (out[0] == 1) explored += 1;
    }
    try testing.expect(explored > 120 and explored < 290);
}

test "peer score failing-since tracking (sui test_peer_score_failing_since_tracking)" {
    var s = PeerScore.init(win, 0.3);
    var now: u64 = 1000 * s_ns;
    try testing.expect(s.failing_since == null);
    s.updateFailingState(now);
    try testing.expect(s.failing_since == null);
    for (0..7) |_| s.recordSuccess(now, 100, s_ns);
    for (0..4) |_| s.recordFailure(now);
    try testing.expect(s.isFailing(now));
    s.updateFailingState(now);
    const first = s.failing_since.?;
    now += 10 * ns_per_ms;
    s.updateFailingState(now);
    try testing.expectEqual(first, s.failing_since.?);
    s.recordSuccess(now, 100, s_ns); // 8 + 4: 33%, still failing
    try testing.expect(s.isFailing(now));
    s.updateFailingState(now);
    try testing.expectEqual(first, s.failing_since.?);
    for (0..6) |_| s.recordSuccess(now, 100, s_ns); // 14 + 4: 22%
    try testing.expect(!s.isFailing(now));
    s.updateFailingState(now);
    try testing.expect(s.failing_since == null);
}

test "peer score consistently failing (sui test_peer_score_consistently_failing)" {
    var s = PeerScore.init(win, 0.3);
    const now: u64 = 1000 * s_ns;
    try testing.expect(!s.consistentlyFailing(now, 50 * ns_per_ms));
    for (0..7) |_| s.recordSuccess(now, 100, s_ns);
    for (0..4) |_| s.recordFailure(now);
    s.updateFailingState(now);
    try testing.expect(s.failing_since != null);
    try testing.expect(!s.consistentlyFailing(now, s_ns));
    try testing.expect(s.consistentlyFailing(now, 0));
    try testing.expect(s.consistentlyFailing(now + 60 * ns_per_ms, 50 * ns_per_ms));
}

fn failingScore(now: u64, since: u64) PeerScore {
    var s = PeerScore.init(win, 0.3);
    for (0..7) |_| s.recordSuccess(now, 100, s_ns);
    for (0..4) |_| s.recordFailure(now);
    s.failing_since = since;
    return s;
}

test "find peer to report for failure (sui test_find_peer_to_report_for_failure)" {
    var t: Table = .{};
    const now: u64 = 1000 * s_ns;
    try testing.expect(t.findPeerToReport(now, s_ns) == null);
    t.scores[0] = failingScore(now, now - 120 * s_ns);
    t.has_score[0] = true;
    t.scores[1] = failingScore(now, now - 30 * s_ns);
    t.has_score[1] = true;
    try testing.expectEqual(@as(?usize, 0), t.findPeerToReport(now, 10 * s_ns));
    try testing.expectEqual(@as(?usize, 0), t.findPeerToReport(now, 60 * s_ns));
    try testing.expect(t.findPeerToReport(now, 200 * s_ns) == null);
}

test "find peer to report respects same chain (sui test_find_peer_to_report_respects_same_chain)" {
    var t: Table = .{};
    const now: u64 = 1000 * s_ns;
    t.scores[0] = failingScore(now, now - 600 * s_ns);
    t.has_score[0] = true;
    t.off_chain[1] = true;
    t.scores[1] = failingScore(now, now - 900 * s_ns);
    t.has_score[1] = true;
    try testing.expectEqual(@as(?usize, 0), t.findPeerToReport(now, 10 * s_ns));
}

test "lost peer clears scores (sui test_lost_peer_clears_scores)" {
    var t: Table = .{};
    const now: u64 = 1000 * s_ns;
    t.recordSuccess(0, 100, s_ns, now);
    try testing.expect(t.has_score[0]);
    t.lostPeer(0);
    try testing.expect(!t.has_score[0]);
    try testing.expect(t.throughput(0, now) == null);
    try testing.expect(!t.isFailing(0, now));
}

test "report: 30 s of failing drops the peer and starts a 1 h cooldown (sui peer_failure_report_adds_cooldown)" {
    var t: Table = .{};
    var now: u64 = 1000 * s_ns;
    for (0..10) |_| t.recordFailure(3, now);
    try testing.expect(t.maybeReportFailing(now, 5) == null); // clock starts
    now += 29 * s_ns;
    for (0..10) |_| t.recordFailure(3, now);
    try testing.expect(t.maybeReportFailing(now, 5) == null);
    now += 1 * s_ns;
    try testing.expectEqual(@as(?usize, 3), t.maybeReportFailing(now, 5));
    try testing.expect(t.takeDrop(3));
    try testing.expect(!t.takeDrop(3));
    try testing.expect(t.onCooldown(3, now));
    // Reset after a report: not reported again on the next tick.
    try testing.expect(t.maybeReportFailing(now, 5) == null);
    // Cooldown peers are deprioritized, not blocked (sui cooldown_peers_deprioritized_in_handle_tick).
    try testing.expect(!t.mayDial(3, now, 4));
    try testing.expect(t.mayDial(3, now, 3));
    // Expired cooldown moves the peer back (sui expired_cooldown_moves_peer_to_preferred).
    try testing.expect(t.mayDial(3, now + 3600 * s_ns, 10));
    try testing.expect(!t.onCooldown(3, now + 3600 * s_ns));
}

test "report: configured peers and too few connections keep the peer (sui configured peer, min_peers_for_disconnect)" {
    var t: Table = .{};
    var now: u64 = 1000 * s_ns;
    t.trusted[1] = true;
    for (0..10) |_| t.recordFailure(1, now);
    _ = t.maybeReportFailing(now, 5);
    now += 31 * s_ns;
    for (0..10) |_| t.recordFailure(1, now);
    try testing.expect(t.maybeReportFailing(now, 5) == null);
    try testing.expect(!t.onCooldown(1, now));
    try testing.expectEqual(@as(u64, 1), t.stats.kept.load(.monotonic));
    for (0..10) |_| t.recordFailure(2, now);
    _ = t.maybeReportFailing(now, 1);
    now += 31 * s_ns;
    for (0..10) |_| t.recordFailure(2, now);
    try testing.expect(t.maybeReportFailing(now, 1) == null); // 1 connected < 2
    try testing.expect(!t.onCooldown(2, now));
    t.cfg.disconnect_threshold_ns = 0;
    try testing.expect(t.maybeReportFailing(now + 100 * s_ns, 10) == null); // disabled
}

test "prune discovered peers that never connect" {
    var t: Table = .{};
    t.trusted[0] = true;
    for (0..5) |_| try testing.expect(!t.noteConnect(5, false));
    try testing.expect(t.noteConnect(5, false));
    for (0..10) |_| try testing.expect(!t.noteConnect(0, false)); // seeds are never pruned
    try testing.expect(!t.noteConnect(6, true));
    for (0..10) |_| try testing.expect(!t.noteConnect(6, false)); // connected once: kept
}

test "pinned checkpoints" {
    var items = [_]Pinned.Entry{ .{ .seq = 9, .digest = @splat(9) }, .{ .seq = 2, .digest = @splat(2) } };
    const p = Pinned.init(&items);
    try testing.expectEqual(Pinned.Verdict.match, p.check(2, &@as([32]u8, @splat(2))));
    try testing.expectEqual(Pinned.Verdict.mismatch, p.check(9, &@as([32]u8, @splat(2))));
    try testing.expectEqual(Pinned.Verdict.not_pinned, p.check(5, &@as([32]u8, @splat(2))));
    try testing.expectEqual(Pinned.Verdict.not_pinned, (Pinned{}).check(5, &@as([32]u8, @splat(2))));
    var t: Table = .{};
    t.recordSuccess(4, 10, s_ns, s_ns);
    t.markOffChain(4);
    try testing.expect(t.isOffChain(4));
    try testing.expect(t.takeDrop(4));
    try testing.expect(!t.mayDial(4, s_ns, 0));
    t.recordSuccess(4, 10, s_ns, s_ns);
    try testing.expect(!t.has_score[4]);
}

test "rank: one cached order per checkpoint" {
    const View = struct {
        infos: []const PeerInfo,
        fn count(v: @This()) usize {
            return v.infos.len;
        }
        fn info(v: @This(), j: usize) PeerInfo {
            return v.infos[j];
        }
    };
    var t: Table = .{};
    t.cfg.exploration = 0;
    const infos = [_]PeerInfo{
        .{ .connected = true, .height = 10, .rtt_ns = 30 },
        .{ .connected = true, .height = 10, .rtt_ns = 10 },
        .{ .connected = true, .height = 4, .rtt_ns = 1 },
        .{ .connected = false, .height = 10, .rtt_ns = 1 },
    };
    const v: View = .{ .infos = &infos };
    const now: u64 = 1000 * s_ns;
    try testing.expectEqual(@as(usize, 0), t.rank(1, 5, now, v));
    try testing.expectEqual(@as(usize, 1), t.rank(0, 5, now, v));
    try testing.expectEqual(@as(usize, max_peers), t.rank(2, 5, now, v));
    try testing.expectEqual(@as(usize, max_peers), t.rank(3, 5, now, v));
    // A peer with a throughput leads (exploration 0).
    t.recordSuccess(0, 1000, s_ns, now);
    t.invalidate();
    try testing.expectEqual(@as(usize, 0), t.rank(0, 5, now, v));
}
