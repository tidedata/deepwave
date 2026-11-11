//! When an edge leaves its cores for the fallback source, and when it returns (docs/EDGE.md
//! section 10). The node's zui1 source asks `Switch` which side to fetch from and reports what
//! each core call did; `Prober` asks the cores for a hello while the edge is on the fallback.
//! Nothing here fetches a checkpoint or trusts one: whichever side serves a checkpoint, the
//! follower verifies it.
//!
//! The rules, with the default numbers (`Tuning`):
//!
//!  1. Fall back when no core has answered for `fail_after_ms` (3 s) while the edge was asking.
//!     An answer is a feed or a "not held yet"; a refused or timed-out connection, a request
//!     that stalls and a server error are not. The clock starts at the first unanswered call and
//!     any answer stops it, so one slow or failed request never switches. Every core call is
//!     bounded by the same deadline (client.zig `fetchBlobBy`), so the switch happens at 3 s,
//!     not after the pool's own 5 s connect and 20 s request timeouts.
//!  2. Fall back at once when waiting cannot help: every core's hello lacks the feed feature or
//!     names another chain, every core answered PRUNED for the checkpoint, or the core closed
//!     the connection saying it is shutting down (a restart) and no other core answered.
//!  3. Fall back when the cores are behind: the lowest checkpoint the edge waits for has been
//!     "not held yet" for `behind_after_ms` (3 s) and the fallback has it (asked at most once
//!     per `behind_check_ms`, 1 s). A quiet chain (the fallback has nothing either) changes nothing.
//!  4. On the fallback, the cores are probed every `probe_ms` (500 ms) over a connection the
//!     prober keeps: at connect, hello (feed feature, chain, lowest held at or below what the
//!     edge needs next); then one small request per probe, "do you hold the highest checkpoint
//!     the edge has fetched" (the core is at or ahead of the edge), which must be answered
//!     within `probe_reply_ms` (500 ms; three hello round trips when that is longer, for a core
//!     far away, at most 1.5 s). An outage of `probe_ms + probe_reply_ms` (1 s) or more
//!     therefore always shows as a failed probe, whatever its phase. While the cores' hello says
//!     they cannot serve this edge at all (no feed feature, another chain), the probe is a new
//!     connection every `probe_idle_ms` (5 s): an edge can follow by its fallback for days.
//!  5. Return to the cores when every probe was good for `back_after_ms` (5 s) without a break.
//!     One bad probe starts the count again, so a core that is up and down every second never
//!     gets the edge back.
//!  6. A fall within `flap_window_ms` (60 s) of the last return doubles the next return's wait
//!     (5, 10, 20, 40, 80 s, `back_max_ms`); a core that then held for 60 s resets it.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const client = @import("client.zig");

pub const Mode = enum(u8) { core = 0, fallback = 1 };

/// Why the edge left the cores (the switch log line and `zui_edge_fallback_reason`).
pub const Reason = enum(u8) {
    /// No answer for `fail_after_ms`: refused, timed out or stalled.
    silent,
    /// Every core's hello lacks the edge feed feature (a core without `--edge-feed`).
    no_feed,
    wrong_chain,
    /// The core closed the connection with zui/1 `shutdown`.
    shutdown,
    /// Below every core's retention.
    pruned,
    /// The cores do not hold a checkpoint the fallback has.
    behind,
};

pub const Tuning = struct {
    fail_after_ms: u32 = 3_000,
    behind_after_ms: u32 = 3_000,
    behind_check_ms: u32 = 1_000,
    probe_ms: u32 = 500,
    /// A probe's request must be answered within this (one round trip on a kept connection).
    probe_reply_ms: u32 = 500,
    /// Connecting the prober to one core (handshake and hello).
    probe_timeout_ms: u32 = 1_500,
    /// Probe spacing while the cores' hello says they cannot serve this edge at all (no feed
    /// feature, another chain). Only a restart of the core changes that, and each such probe is
    /// a new connection: an edge that follows by its fallback for days must not knock twice a second.
    probe_idle_ms: u32 = 5_000,
    back_after_ms: u32 = 5_000,
    flap_window_ms: u32 = 60_000,
    back_max_ms: u32 = 80_000,
    /// Pause between tries of a core that fails at once, inside the `fail_after_ms` grace.
    retry_ms: u32 = 100,
};

pub const Stats = struct {
    /// Switches each way.
    to_fallback: Atomic(u64) = .init(0),
    to_core: Atomic(u64) = .init(0),
    /// Checkpoints fetched from each side.
    from_core: Atomic(u64) = .init(0),
    from_fallback: Atomic(u64) = .init(0),
    probes: Atomic(u64) = .init(0),
    probes_ok: Atomic(u64) = .init(0),
    /// Fallback existence checks made because the cores did not hold a checkpoint (rule 3).
    behind_checks: Atomic(u64) = .init(0),
};

const ms: u64 = std.time.ns_per_ms;
const none: u64 = std.math.maxInt(u64);

/// The switch state. Thread safe; every method takes the caller's monotonic `now` (ns), so the
/// rules run under a test clock.
pub const Switch = struct {
    t: Tuning = .{},
    /// Switch lines are logged (off in rule tests).
    log: bool = true,
    stats: Stats = .{},
    mode_: Atomic(u8) = .init(@intFromEnum(Mode.core)),
    /// When the current mode began.
    since_ns: Atomic(u64) = .init(0),
    /// Start of the first core call since the last answer that got none (0: the cores answer).
    bad_since: Atomic(u64) = .init(0),
    /// The last reason for a fall (`Reason`), for the gauge.
    reason: Atomic(u8) = .init(@intFromEnum(Reason.silent)),
    /// The edge's position, kept by the fetch path: the highest checkpoint fetched from either
    /// side (0: none yet) and the lowest it still needs (`none`: unknown).
    have: Atomic(u64) = .init(0),
    need: Atomic(u64) = .init(none),
    mu: std.atomic.Mutex = .unlocked,
    // under `mu`:
    /// The lowest checkpoint the cores answered "not held" for and since when (rule 3).
    wait_seq: u64 = none,
    wait_since: u64 = 0,
    last_behind_check: u64 = 0,
    /// A fetcher is asking the fallback now (`coreMissed` said so; `behindChecked` clears it).
    behind_busy: bool = false,
    /// Start of the current run of good probes (0: none).
    good_since: u64 = 0,
    /// The wait before the next return (rule 6).
    back_after_cur_ms: u32 = 0,
    /// When the edge last returned to the cores (0: never).
    last_back: u64 = 0,

    fn lock(s: *Switch) void {
        while (!s.mu.tryLock()) std.atomic.spinLoopHint();
    }

    pub fn mode(s: *const Switch) Mode {
        return @enumFromInt(s.mode_.load(.acquire));
    }

    pub fn lastReason(s: *const Switch) Reason {
        return @enumFromInt(s.reason.load(.monotonic));
    }

    /// The wait the next return needs (rule 6), in ms.
    pub fn backAfterMs(s: *Switch) u32 {
        s.lock();
        defer s.mu.unlock();
        return if (s.back_after_cur_ms == 0) s.t.back_after_ms else s.back_after_cur_ms;
    }

    /// The deadline of a core call that starts at `t0` (rule 1): the grace runs from the first
    /// unanswered call, not from each retry.
    pub fn deadline(s: *const Switch, t0: u64) u64 {
        const b = s.bad_since.load(.acquire);
        return (if (b != 0) @min(b, t0) else t0) + @as(u64, s.t.fail_after_ms) * ms;
    }

    fn noteHave(s: *Switch, seq: u64) void {
        var cur = s.have.load(.monotonic);
        while (seq > cur) cur = s.have.cmpxchgWeak(cur, seq, .monotonic, .monotonic) orelse return;
    }

    /// A core answered (a feed, or "not held yet"): the grace clock stops.
    pub fn coreAnswered(s: *Switch) void {
        if (s.bad_since.load(.monotonic) != 0) s.bad_since.store(0, .release);
    }

    /// Checkpoint `seq` was fetched (from the side `from`).
    pub fn fetched(s: *Switch, from: Mode, seq: u64) void {
        _ = (if (from == .core) &s.stats.from_core else &s.stats.from_fallback).fetchAdd(1, .monotonic);
        s.noteHave(seq);
        if (from == .core) s.coreAnswered();
        s.lock();
        defer s.mu.unlock();
        if (s.wait_seq == seq) s.wait_seq = none;
    }

    /// A core call got no answer; `t0` is when the caller's run of unanswered tries began. True
    /// when the edge is on the fallback now (this call switched, or another thread did); false:
    /// still inside the grace, try the cores again. A `why` other than silent is rule 2.
    pub fn coreFailed(s: *Switch, now: u64, t0: u64, why: Reason, seq: u64) bool {
        if (s.mode() == .fallback) return true;
        _ = s.bad_since.cmpxchgStrong(0, @max(t0, 1), .acq_rel, .monotonic);
        // The caller's own run counts too: another thread's answer (for another checkpoint)
        // clears the shared clock, and must not keep this checkpoint waiting on the cores.
        const shared = s.bad_since.load(.acquire);
        const since = if (shared == 0) t0 else @min(shared, t0);
        const immediate = why != .silent;
        if (!immediate and now -| since < @as(u64, s.t.fail_after_ms) * ms) return false;
        s.fall(now, why, seq, now -| since);
        return true;
    }

    /// The cores answered "not held" for `seq`. True when the caller should now ask the
    /// fallback whether it has `seq` (rule 3), report a yes with `behind`, and in any case call
    /// `behindChecked` when it has the answer (one such question is out at a time, so a
    /// fallback that is slow to answer holds one fetcher, not all of them).
    pub fn coreMissed(s: *Switch, now: u64, seq: u64) bool {
        s.coreAnswered();
        if (s.mode() == .fallback) return false;
        s.lock();
        defer s.mu.unlock();
        // the checkpoint waited for was applied meanwhile (another writer delivered it)
        const need = s.need.load(.monotonic);
        if (s.wait_seq != none and need != none and s.wait_seq < need) s.wait_seq = none;
        if (s.wait_seq == none or seq < s.wait_seq) {
            s.wait_seq = seq;
            s.wait_since = now;
            return false;
        }
        if (seq != s.wait_seq) return false;
        if (now -| s.wait_since < @as(u64, s.t.behind_after_ms) * ms) return false;
        if (s.last_behind_check != 0 and now -| s.last_behind_check < @as(u64, s.t.behind_check_ms) * ms) return false;
        if (s.behind_busy) return false;
        s.behind_busy = true;
        s.last_behind_check = now;
        _ = s.stats.behind_checks.fetchAdd(1, .monotonic);
        return true;
    }

    /// The caller of a `coreMissed` that returned true has its answer from the fallback.
    pub fn behindChecked(s: *Switch) void {
        s.lock();
        defer s.mu.unlock();
        s.behind_busy = false;
    }

    /// The fallback holds `seq`, which the cores have not held for `behind_after_ms` (or, with
    /// `why` pruned, never will).
    pub fn behind(s: *Switch, now: u64, seq: u64, why: Reason) void {
        if (s.mode() == .fallback) return;
        var waited: u64 = 0;
        {
            s.lock();
            defer s.mu.unlock();
            if (s.wait_seq == seq) waited = now -| s.wait_since;
        }
        s.fall(now, why, seq, waited);
    }

    fn fall(s: *Switch, now: u64, why: Reason, seq: u64, waited_ns: u64) void {
        var back_ms: u32 = undefined;
        {
            s.lock();
            defer s.mu.unlock();
            if (s.mode() == .fallback) return;
            // rule 6: a fall soon after a return makes the next return wait longer
            if (s.last_back != 0 and now -| s.last_back < @as(u64, s.t.flap_window_ms) * ms) {
                const cur = if (s.back_after_cur_ms == 0) s.t.back_after_ms else s.back_after_cur_ms;
                s.back_after_cur_ms = @min(cur *| 2, @max(s.t.back_max_ms, s.t.back_after_ms));
            } else s.back_after_cur_ms = s.t.back_after_ms;
            back_ms = s.back_after_cur_ms;
            s.good_since = 0;
            s.wait_seq = none;
            s.reason.store(@intFromEnum(why), .monotonic);
            s.since_ns.store(now, .monotonic);
            s.mode_.store(@intFromEnum(Mode.fallback), .release);
        }
        const k = s.stats.to_fallback.fetchAdd(1, .monotonic) + 1;
        if (s.log) std.log.warn("edge source: zui1 -> fallback at checkpoint {d}: {s} ({d} ms without an answer; switch {d}); probing the cores every {d} ms, back after {d} ms healthy", .{ seq, reasonText(why), waited_ns / ms, k, s.t.probe_ms, back_ms });
    }

    /// The result of one probe round at `now`: `bad` null when a core is healthy and at or
    /// ahead of the edge. True when this probe returned the edge to the cores (rule 5).
    pub fn probed(s: *Switch, now: u64, bad: ?Reason) bool {
        _ = s.stats.probes.fetchAdd(1, .monotonic);
        if (bad == null) _ = s.stats.probes_ok.fetchAdd(1, .monotonic);
        var healthy_ns: u64 = 0;
        var away_ns: u64 = 0;
        {
            s.lock();
            defer s.mu.unlock();
            if (s.mode() != .fallback) return false;
            if (bad != null) {
                s.good_since = 0;
                return false;
            }
            if (s.good_since == 0) s.good_since = @max(now, 1);
            const want: u64 = @as(u64, if (s.back_after_cur_ms == 0) s.t.back_after_ms else s.back_after_cur_ms) * ms;
            healthy_ns = now -| s.good_since;
            if (healthy_ns < want) return false;
            away_ns = now -| s.since_ns.load(.monotonic);
            s.good_since = 0;
            s.last_back = @max(now, 1);
            s.wait_seq = none;
            s.bad_since.store(0, .release);
            s.since_ns.store(now, .monotonic);
            s.mode_.store(@intFromEnum(Mode.core), .release);
        }
        const k = s.stats.to_core.fetchAdd(1, .monotonic) + 1;
        if (s.log) std.log.info("edge source: fallback -> zui1 at checkpoint {d}: cores healthy for {d} ms ({d} ms on the fallback, {d} checkpoints from it so far; switch {d})", .{ s.have.load(.monotonic), healthy_ns / ms, away_ns / ms, s.stats.from_fallback.load(.monotonic), k });
        return true;
    }
};

pub fn reasonText(r: Reason) []const u8 {
    return switch (r) {
        .silent => "no core answered",
        .no_feed => "no core serves the edge feed (hello without the feature; a core without --edge-feed)",
        .wrong_chain => "the cores serve another chain",
        .shutdown => "the core is shutting down",
        .pruned => "below every core's retention",
        .behind => "the cores do not hold it and the fallback does",
    };
}

/// The reason a pool error stands for (rule 2 for the definite ones).
pub fn reasonOf(e: client.Error) Reason {
    return switch (e) {
        error.NoEdgeFeed => .no_feed,
        error.WrongChain => .wrong_chain,
        else => .silent,
    };
}

/// The clock of every time here and in client.zig (deadlines, `shutdown_ns`).
pub fn nowNs(io: Io) u64 {
    return @intCast(Io.Clock.awake.now(io).toNanoseconds());
}

/// Probes the cores while the edge is on the fallback (rule 4) and tells the switch. One thread;
/// it keeps one connection per core while probing and closes them when the edge is back.
pub const Prober = struct {
    gpa: Allocator,
    io: Io,
    sw: *Switch,
    specs: []client.Spec,
    conns: []?*client.Conn,
    /// Probes sent on each connection since its hello.
    sent: []u32,
    chain_id: ?[32]u8 = null,
    stopping: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,

    /// A kept connection says hello again after this many probes (the core's lowest held moves).
    const rehello_every = 16;

    pub fn init(gpa: Allocator, io: Io, sw: *Switch, specs: []const client.Spec, chain_id: ?[32]u8) Allocator.Error!*Prober {
        const p = try gpa.create(Prober);
        errdefer gpa.destroy(p);
        const own = try gpa.dupe(client.Spec, specs);
        errdefer gpa.free(own);
        const conns = try gpa.alloc(?*client.Conn, own.len);
        errdefer gpa.free(conns);
        @memset(conns, null);
        const sent = try gpa.alloc(u32, own.len);
        @memset(sent, 0);
        p.* = .{ .gpa = gpa, .io = io, .sw = sw, .specs = own, .conns = conns, .sent = sent, .chain_id = chain_id };
        return p;
    }

    pub fn start(p: *Prober) !void {
        p.thread = try std.Thread.spawn(.{ .stack_size = 1 << 20 }, run, .{p});
    }

    /// Stops the thread (within one connect's budget).
    pub fn stop(p: *Prober) void {
        p.stopping.store(true, .release);
        if (p.thread) |th| th.join();
        p.thread = null;
    }

    pub fn deinit(p: *Prober) void {
        p.stop();
        p.closeAll();
        p.gpa.free(p.conns);
        p.gpa.free(p.sent);
        p.gpa.free(p.specs);
        p.gpa.destroy(p);
    }

    fn closeAll(p: *Prober) void {
        for (p.conns) |*c| if (c.*) |x| {
            x.close();
            c.* = null;
        };
    }

    fn run(p: *Prober) void {
        var next: u64 = 0;
        while (!p.stopping.load(.acquire)) {
            const now = nowNs(p.io);
            if (p.sw.mode() != .fallback) {
                if (next != 0) p.closeAll();
                next = 0;
            } else if (now >= next) {
                const bad = p.probeOnce();
                if (p.stopping.load(.acquire)) break;
                _ = p.sw.probed(nowNs(p.io), bad);
                const idle = if (bad) |why| why == .no_feed or why == .wrong_chain else false;
                next = now + @as(u64, if (idle) @max(p.sw.t.probe_idle_ms, p.sw.t.probe_ms) else p.sw.t.probe_ms) * ms;
                continue;
            }
            p.io.sleep(.fromMilliseconds(@intCast(@max(1, @min(20, p.sw.t.probe_ms / 4)))), .awake) catch {};
        }
        p.closeAll();
    }

    /// One round over the cores: null when one of them is healthy and at or ahead of the edge,
    /// else why the last one tried is not.
    pub fn probeOnce(p: *Prober) ?Reason {
        var arena = std.heap.ArenaAllocator.init(p.gpa);
        defer arena.deinit();
        var last: Reason = .silent;
        for (0..p.specs.len) |i| {
            if (p.stopping.load(.acquire)) return last;
            _ = arena.reset(.retain_capacity);
            if (p.probeCore(arena.allocator(), i)) |why| last = why else return null;
        }
        return last;
    }

    fn drop(p: *Prober, i: usize) void {
        if (p.conns[i]) |c| c.close();
        p.conns[i] = null;
    }

    /// How long a probe's request may take on a connection whose hello took `hello_ms`:
    /// `probe_reply_ms`, or three such round trips on a long path (a far core must not look
    /// dead for being far), and never more than a connect's budget.
    pub fn replyBudgetMs(t: *const Tuning, hello_ms: u64) u64 {
        return @max(1, @min(@max(@as(u64, t.probe_reply_ms), 3 * hello_ms), @max(t.probe_reply_ms, t.probe_timeout_ms)));
    }

    fn probeCore(p: *Prober, a: Allocator, i: usize) ?Reason {
        const t = &p.sw.t;
        if (p.conns[i]) |c| if (!c.alive()) p.drop(i);
        const have = p.sw.have.load(.monotonic);
        const need = p.sw.need.load(.monotonic);
        // Every probe is one real round trip, so a core that died since the last one cannot
        // pass on what it said then: the hello on a new connection, then "do you hold `have`",
        // with a hello in its place now and then (the core's lowest held moves) and while the
        // edge has fetched nothing yet.
        var fresh = false;
        if (p.conns[i] == null) {
            const by = nowNs(p.io) + @as(u64, t.probe_timeout_ms) * ms;
            const c = client.Conn.connect(p.gpa, p.io, p.specs[i], t.probe_timeout_ms) catch return .silent;
            p.conns[i] = c;
            p.sent[i] = 0;
            c.first_byte_by = by;
            const h0 = nowNs(p.io);
            c.doHello(a) catch {
                p.drop(i);
                return .silent;
            };
            c.first_byte_by = client.Pool.no_deadline;
            c.request_timeout_ms = replyBudgetMs(t, (nowNs(p.io) - h0) / ms);
            fresh = true;
        } else if (have == 0 or p.sent[i] >= rehello_every) {
            p.sent[i] = 0;
            p.conns[i].?.doHello(a) catch {
                p.drop(i);
                return .silent;
            };
            fresh = true;
        }
        const c = p.conns[i].?;
        // What only a restart of the core changes: the next probe connects again to see it.
        if (c.hello.features & client.feature_edge_feed == 0) {
            p.drop(i);
            return .no_feed;
        }
        if (p.chain_id) |want| if (!std.mem.eql(u8, &want, &c.hello.chain_id)) {
            p.drop(i);
            return .wrong_chain;
        };
        // what the edge needs next must still be on the core
        if (need != none and c.hello.lowest > need) return .pruned;
        if (need == none and have != 0 and c.hello.lowest > have) return .pruned;
        if (have == 0) return null;
        // at or ahead of the edge: it holds the newest checkpoint the edge has. (On the round
        // of a hello this is a second request; the hello's own height is only a claim.)
        if (!fresh) p.sent[i] += 1;
        const held = c.hasCheckpoint(a, have) catch {
            p.drop(i);
            return .silent;
        };
        return if (held) null else .behind;
    }
};

// ------------------------------------------------------------------ tests (rules, test clock)

const testing = std.testing;
const sec: u64 = std.time.ns_per_s;

fn testSwitch() Switch {
    return .{ .log = false };
}

test "fallback switch: a core silent for 3 s falls back; one failed request does not; any answer restarts the grace" {
    var s = testSwitch();
    const t0: u64 = 100 * sec;
    // one failed request, then an answer 200 ms later: no switch, and the clock is cleared
    try testing.expect(!s.coreFailed(t0 + 10 * ms, t0, .silent, 7));
    try testing.expectEqual(t0 + 3 * sec, s.deadline(t0 + 50 * ms));
    s.coreAnswered();
    try testing.expectEqual(Mode.core, s.mode());
    try testing.expectEqual(t0 + 10 * sec + 3 * sec, s.deadline(t0 + 10 * sec));
    // failures at 0, 1, 2 s keep the first start; 2.99 s is inside the grace, 3 s is not
    const t1 = t0 + 20 * sec;
    try testing.expect(!s.coreFailed(t1 + 5 * ms, t1, .silent, 8));
    try testing.expect(!s.coreFailed(t1 + 1 * sec, t1 + 900 * ms, .silent, 8));
    try testing.expect(!s.coreFailed(t1 + 2990 * ms, t1 + 2 * sec, .silent, 8));
    try testing.expectEqual(@as(u64, 0), s.stats.to_fallback.load(.monotonic));
    try testing.expect(s.coreFailed(t1 + 3 * sec, t1 + 2990 * ms, .silent, 8));
    try testing.expectEqual(Mode.fallback, s.mode());
    try testing.expectEqual(@as(u64, 1), s.stats.to_fallback.load(.monotonic));
    try testing.expectEqual(Reason.silent, s.lastReason());
    // other threads that fail afterwards are told to use the fallback, and nothing is counted twice
    try testing.expect(s.coreFailed(t1 + 3 * sec + ms, t1, .silent, 9));
    try testing.expectEqual(@as(u64, 1), s.stats.to_fallback.load(.monotonic));
}

test "fallback switch: no feed feature, another chain, a shutdown and a pruned checkpoint fall back at once" {
    for ([_]Reason{ .no_feed, .wrong_chain, .shutdown }) |why| {
        var s = testSwitch();
        try testing.expect(s.coreFailed(5 * sec + ms, 5 * sec, why, 3));
        try testing.expectEqual(Mode.fallback, s.mode());
        try testing.expectEqual(why, s.lastReason());
    }
    var s = testSwitch();
    s.behind(5 * sec, 3, .pruned);
    try testing.expectEqual(Mode.fallback, s.mode());
    try testing.expectEqual(Reason.pruned, s.lastReason());
    try testing.expectEqual(Reason.no_feed, reasonOf(error.NoEdgeFeed));
    try testing.expectEqual(Reason.wrong_chain, reasonOf(error.WrongChain));
    try testing.expectEqual(Reason.silent, reasonOf(error.HandshakeFailed));
    try testing.expectEqual(Reason.silent, reasonOf(error.Timeout));
}

test "fallback switch: cores that do not hold the wanted checkpoint for 3 s make the edge ask the fallback, once a second" {
    var s = testSwitch();
    const t0: u64 = 50 * sec;
    // the tip: each checkpoint misses for a few polls, then arrives; never a check
    var seq: u64 = 1000;
    var now = t0;
    while (seq < 1040) : (seq += 1) {
        for (0..5) |_| {
            try testing.expect(!s.coreMissed(now, seq));
            now += 50 * ms;
        }
        s.fetched(.core, seq);
    }
    try testing.expectEqual(@as(u64, 0), s.stats.behind_checks.load(.monotonic));
    // a core that stops advancing: the first check comes 3 s after the first miss, then every second
    const stuck = seq;
    const m0 = now;
    var checks: u32 = 0;
    var first_check: u64 = 0;
    while (now < m0 + 6 * sec) : (now += 50 * ms) {
        // a later checkpoint missing too does not restart or steal the wait
        _ = s.coreMissed(now, stuck + 1);
        if (s.coreMissed(now, stuck)) {
            checks += 1;
            if (first_check == 0) first_check = now;
            // while the question is out, nobody else asks
            try testing.expect(!s.coreMissed(now + 2 * sec, stuck));
            s.behindChecked();
        }
    }
    try testing.expectEqual(m0 + 3 * sec, first_check);
    try testing.expectEqual(@as(u32, 3), checks); // at 3, 4 and 5 s
    try testing.expectEqual(Mode.core, s.mode()); // the fallback had nothing either: a quiet chain
    // the fallback has it: switch
    s.behind(now, stuck, .behind);
    try testing.expectEqual(Mode.fallback, s.mode());
    try testing.expectEqual(Reason.behind, s.lastReason());
    try testing.expect(!s.coreMissed(now + sec, stuck));
    // a checkpoint another writer delivered (the follower is past it) no longer holds the wait
    var s2 = testSwitch();
    try testing.expect(!s2.coreMissed(t0, 500));
    s2.need.store(501, .monotonic);
    try testing.expect(!s2.coreMissed(t0 + 10 * sec, 501)); // a new wait starts here
    try testing.expect(s2.coreMissed(t0 + 13 * sec, 501));
}

test "fallback switch: back after 5 s of good probes without a break; a core up and down every second never gets the edge back" {
    var s = testSwitch();
    const t0: u64 = 10 * sec;
    try testing.expect(s.coreFailed(t0 + 3 * sec, t0, .silent, 1));
    var now = t0 + 3 * sec;
    // two minutes of a core that is up one second and down the next, probed every 500 ms: an
    // outage of a second always fails a probe (rule 4), here the two that fall inside it
    var i: u32 = 0;
    while (i < 240) : (i += 1) {
        now += 500 * ms;
        try testing.expect(!s.probed(now, if (i % 4 < 2) null else .silent));
    }
    try testing.expectEqual(Mode.fallback, s.mode());
    try testing.expectEqual(@as(u64, 1), s.stats.to_fallback.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), s.stats.to_core.load(.monotonic));
    try testing.expectEqual(@as(u64, 120), s.stats.probes_ok.load(.monotonic));
    // and the worst phase: one failed probe in every two seconds is enough
    i = 0;
    while (i < 240) : (i += 1) {
        now += 500 * ms;
        try testing.expect(!s.probed(now, if (i % 4 != 3) null else .silent));
    }
    try testing.expectEqual(@as(u64, 0), s.stats.to_core.load(.monotonic));
    // four good seconds, a bad probe, then five good seconds: back only at the end of the second run
    for (0..5) |_| {
        now += sec;
        try testing.expect(!s.probed(now, null));
    }
    now += sec;
    try testing.expect(!s.probed(now, .behind));
    for (0..5) |_| {
        now += sec;
        try testing.expect(!s.probed(now, null));
    }
    now += sec;
    try testing.expect(s.probed(now, null));
    try testing.expectEqual(Mode.core, s.mode());
    try testing.expectEqual(@as(u64, 1), s.stats.to_core.load(.monotonic));
    // back on the cores the grace starts clean
    try testing.expectEqual(now + 3 * sec, s.deadline(now));
}

test "fallback switch: a fall soon after a return doubles the wait, up to 80 s; a core that held a minute resets it" {
    var s = testSwitch();
    var now: u64 = 10 * sec;
    const Run = struct {
        /// Falls at `at`, then probes good every second; returns how long the return took.
        fn cycle(sw: *Switch, at: *u64) !u64 {
            try testing.expect(sw.coreFailed(at.* + 3 * sec, at.*, .silent, 1));
            at.* += 3 * sec;
            const fell = at.*;
            while (true) {
                at.* += sec;
                if (sw.probed(at.*, null)) return at.* - fell;
                if (at.* - fell > 600 * sec) return error.TestUnexpectedResult;
            }
        }
    };
    // the first return: one probe to start the run, then 5 s
    try testing.expectEqual(6 * sec, try Run.cycle(&s, &now));
    // a core that fails again 2 s after each return: 10, 20, 40, 80, 80
    for ([_]u64{ 10, 20, 40, 80, 80 }) |want| {
        now += 2 * sec;
        try testing.expectEqual((want + 1) * sec, try Run.cycle(&s, &now));
        try testing.expectEqual(Mode.core, s.mode());
    }
    try testing.expectEqual(@as(u64, 6), s.stats.to_fallback.load(.monotonic));
    // 24 falls an hour at most once the wait is 80 s; and after a minute on the cores, 5 s again
    now += 61 * sec;
    try testing.expectEqual(6 * sec, try Run.cycle(&s, &now));
    try testing.expectEqual(@as(u32, 5_000), s.backAfterMs());
}

test "fallback prober: a probe's reply budget is 500 ms, more on a long path, never above the connect budget" {
    const d: Tuning = .{};
    try testing.expectEqual(@as(u64, 500), Prober.replyBudgetMs(&d, 2)); // same site
    try testing.expectEqual(@as(u64, 500), Prober.replyBudgetMs(&d, 90)); // a 90 ms round trip
    try testing.expectEqual(@as(u64, 750), Prober.replyBudgetMs(&d, 250)); // a 250 ms round trip
    try testing.expectEqual(@as(u64, 1_500), Prober.replyBudgetMs(&d, 900));
}

test "fallback switch: position and counters" {
    var s = testSwitch();
    s.fetched(.core, 10);
    s.fetched(.fallback, 12);
    s.fetched(.core, 11);
    try testing.expectEqual(@as(u64, 12), s.have.load(.monotonic));
    try testing.expectEqual(@as(u64, 2), s.stats.from_core.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), s.stats.from_fallback.load(.monotonic));
    // a probe result while on the cores changes nothing
    try testing.expect(!s.probed(sec, null));
    try testing.expectEqual(@as(u64, 0), s.stats.to_core.load(.monotonic));
}
