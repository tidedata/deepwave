//! Unit tests of an edge's stop: SIGTERM while it follows a core over zui/1 (node.zig
//! `gracefulStop`, `shutdownThreads` and `deinit`; source.zig `requestStop`).
//!
//! Found on a live edge (2026-11-10): stopped in catch-up, it logged two `fetch N:
//! SourceUnavailable; retry in 100 ms` lines, ran into the stop deadline and exited without
//! closing the store; the next start checked every page of the live table (156 s). What these
//! tests hold the stop to:
//!   - it never waits on the network: a core that stopped answering, a response half received,
//!     a switch to the fallback just made (the prober inside a probe of the dead core) and the
//!     idle poll at the tip all end within a second, where they used to end at a timeout;
//!   - the checkpoint in hand is committed whole and none of the checked ones behind it is
//!     started;
//!   - the fetch threads do not take the stop for a source error (no error counted, no retry);
//!   - the store closes cleanly: the next open finds a clean close (no page check, nothing
//!     replayed) and exactly the checkpoints the follower applied;
//!   - with a core upstream (`--core-upstream`, edge/forward.zig) the same holds: a forwarded
//!     stream does not hold the drain, a forwarded call the core never answers holds it for
//!     `--drain-ms` and no longer (the server then closes its connection and the call ends with
//!     it), and the forwarder's threads are gone before the store closes.
//! The edge, the core, the link between them and the bucket are edge_fallback_tests.zig's; the
//! stop is `stopEdge`, the node's own calls in the node's order. Everything needs the corpus
//! (`$ZUI_CORPUS`) and skips without it. Every wait and join is bounded: with the fixes undone
//! each call still ends at the pool's own timeouts and the test fails on its time limit.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const Atomic = std.atomic.Value;
const store = @import("store");
const sync = @import("sync");
const edge = @import("edge");
const serve = @import("serve");
const rpc_exec = @import("rpc_exec");
const fx = @import("edge_fallback_tests.zig");
const source_mod = @import("source.zig");
const node_mod = @import("node.zig");

const io = testing.io;
const Mode = edge.fallback.Mode;
const first = fx.first;
const ms: u64 = std.time.ns_per_ms;

/// Checkpoints on the core (and in the bucket) before the edge starts: the edge is this far
/// behind, in catch-up for the whole test.
const behind: u64 = 160;
/// Every apply takes this much longer, so the fetchers and the workers stay ahead of the
/// ordered stage: the window is full of checked checkpoints, as in a real catch-up.
const apply_ms: u32 = 25;
/// The stop up to the store close must take less than this (ms). With the fixes it is the
/// checkpoint in hand plus a few thread joins; without them, the timeouts named in each test.
const stop_limit_ms: u64 = 1_000;

const Stop = struct {
    /// Applies begun between the stop request and the follower's return.
    applied_after: usize,
    follower_ms: u64,
    fetch_ms: u64,
    /// The join of the forwarder's threads (0 without a core upstream).
    forwarder_ms: u64,
    prober_ms: u64,
    close_ms: u64,

    fn beforeClose(s: Stop) u64 {
        return s.follower_ms + s.fetch_ms + s.forwarder_ms + s.prober_ms;
    }
};

/// What the node does with an edge on SIGTERM, in its order, each step timed.
fn stopEdge(e: *fx.Edge) !Stop {
    return stopEdgeWith(e, null);
}

/// `stopEdge` for an edge with a core upstream: `fwd` is its forwarder (after the drain, which
/// the caller runs: `Front.drain`).
fn stopEdgeWith(e: *fx.Edge, fwd: ?*edge.forward.Forwarder) !Stop {
    const at = e.n.load(.acquire);
    const t0 = fx.nowNs();
    // gracefulStop: the follower, and with it everything that fetches
    e.follower.stop();
    source_mod.requestStop(&e.fetcher, &e.src, e.prober);
    // Node.run: the follower returns
    if (e.run_thread) |t| t.join();
    e.run_thread = null;
    const t1 = fx.nowNs();
    const after = e.n.load(.acquire) - at;
    // shutdownThreads: the flags again (every way out comes through here), then the join
    source_mod.requestStop(&e.fetcher, &e.src, e.prober);
    if (fwd) |f| f.requestStop();
    e.fetcher.stop();
    const t2 = fx.nowNs();
    if (fwd) |f| f.stop();
    const t2f = fx.nowNs();
    // deinit: the prober, the store close
    if (e.prober) |p| p.deinit();
    e.prober = null;
    const t3 = fx.nowNs();
    try e.closeStore();
    const t4 = fx.nowNs();
    return .{ .applied_after = after, .follower_ms = (t1 - t0) / ms, .fetch_ms = (t2 - t1) / ms, .forwarder_ms = (t2f - t2) / ms, .prober_ms = (t3 - t2f) / ms, .close_ms = (t4 - t3) / ms };
}

fn report(what: []const u8, s: Stop) void {
    std.debug.print("edge stop ({s}): follower {d} ms, fetch threads {d} ms, prober {d} ms, store close {d} ms; {d} applies begun after the stop\n", .{ what, s.follower_ms, s.fetch_ms, s.prober_ms, s.close_ms, s.applied_after });
}

/// The stop was quick and nothing of it shows as a failure.
fn expectQuick(what: []const u8, e: *fx.Edge, s: Stop) !void {
    errdefer report(what, s);
    try testing.expectEqual(@as(?anyerror, null), e.run_err);
    try testing.expect(s.beforeClose() < stop_limit_ms);
    // the one in hand, or the one the ordered stage had just turned to
    try testing.expect(s.applied_after <= 1);
}

/// The store the stopped edge left: closed cleanly, holding exactly the applied checkpoints.
fn expectCleanReopen(w: *fx.World, e: *fx.Edge, name: []const u8) !void {
    const next = e.follower.applied_next.load(.acquire);
    try testing.expect(next > first);
    const count = next - first;
    // every apply that began was committed, each once and in order: none half applied
    try testing.expectEqual(count, @as(u64, e.n.load(.acquire)));
    try e.expectPrefix(count);
    var pb: [600]u8 = undefined;
    var cfg = fx.store_cfg;
    cfg.dir = try std.fmt.bufPrint(&pb, "{s}/{s}/store", .{ w.root_path, name });
    const h = try store.openDir(w.gpa, io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    // not the recovery of an unclean end: no page check of the live table, no log replay
    try testing.expect(h.store.stats.open_clean);
    try testing.expectEqual(@as(u64, 0), h.store.stats.replayed_groups);
    try testing.expectEqual(@as(?u64, next - 1), h.store.committed());
    var snap = h.store.snapshot();
    defer snap.release();
    try testing.expectEqual(@as(?u64, next - 1), snap.highestCommitted());
    try testing.expect((try snap.checkpointChecked(next - 1)) != null);
    try testing.expect((try snap.checkpointChecked(next)) == null);
}

/// Checked checkpoints waiting in the follower's window behind the ordered stage.
fn waiting(f: *sync.Follower) u64 {
    const next = f.applied_next.load(.acquire);
    var n: u64 = 0;
    for (0..f.slots.len) |k| {
        const s = next + k;
        if (f.slots[s % f.slots.len].ready.load(.acquire) == s + 1) n += 1;
    }
    return n;
}

fn waitWaiting(f: *sync.Follower, want: u64, limit_ms: u64) bool {
    const t0 = fx.nowNs();
    while (waiting(f) < want) {
        if (fx.nowNs() - t0 > limit_ms * ms) return false;
        fx.sleepMs(1);
    }
    return true;
}

/// An edge in catch-up from the core: `behind` checkpoints to go, a dozen applied, the window
/// full of checked checkpoints.
fn catchingUp(w: *fx.World, fallback: bool, tuning: edge.fallback.Tuning) !*fx.Edge {
    return catchingUpWith(w, fallback, tuning, null);
}

/// `catchingUp` with the feed's in-flight control (pipelined calls) when `fl` is given.
fn catchingUpWith(w: *fx.World, fallback: bool, tuning: edge.fallback.Tuning, fl: ?*source_mod.InFlight) !*fx.Edge {
    try w.coreUp(true);
    try w.publish(behind);
    const e = try w.edge_("edge", fallback, tuning);
    errdefer e.destroy();
    e.apply_delay_ms.store(apply_ms, .release);
    e.fetcher.inflight = fl;
    try e.follow();
    try fx.must(e.waitCommitted(12, 30_000), "waitCommitted(12, 30_000)", e);
    try testing.expect(waitWaiting(e.follower, 3, 10_000));
    try testing.expect(e.committed() < behind / 2);
    return e;
}

test "edge stop: in catch-up from a core, a stop ends after the checkpoint in hand, the fetch threads see no source error, and the store closes cleanly (the next open is not the recovery of an unclean end)" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const e = try catchingUp(&w, true, .{}); // the shipped rules
    defer e.destroy();
    try testing.expect(waiting(e.follower) >= 3); // mid-window
    const s = try stopEdge(e);
    report("catch-up", s);
    try expectQuick("catch-up", e, s);
    // The stop is not a word about the source: no fetch error (the live edge logged two
    // `SourceUnavailable; retry in 100 ms` lines here), no switch, still on the core.
    try testing.expectEqual(@as(u64, 0), e.fetcher.stats.errors.load(.acquire));
    try testing.expectEqual(@as(u64, 0), e.fetcher.stats.transient_errors.load(.acquire));
    try testing.expectEqual(@as(u64, 0), e.stats().to_fallback.load(.monotonic));
    try testing.expectEqual(Mode.core, e.fb.?.sw.mode());
    try testing.expectEqual(@as(u64, 0), e.stats().from_fallback.load(.monotonic));
    try expectCleanReopen(&w, e, "edge");
}

test "edge stop: a core that stopped answering does not hold the stop (with the fallback: not for the 3 s grace; without one: not for the pool's 20 s request timeout)" {
    for ([_]bool{ true, false }) |fallback| {
        var w: fx.World = undefined;
        try w.init();
        defer w.deinit();
        const e = try catchingUp(&w, fallback, if (fallback) .{} else fx.quick);
        defer e.destroy();
        // the core's box goes dark: every fetch thread is now inside a call that gets no answer
        w.link.down.store(true, .release);
        fx.sleepMs(300);
        const s = try stopEdge(e);
        report(if (fallback) "silent core, fallback on" else "silent core, fallback off", s);
        try expectQuick("silent core", e, s);
        if (fallback) {
            // inside the grace: the stop did not make it a switch
            try testing.expectEqual(@as(u64, 0), e.stats().to_fallback.load(.monotonic));
            try testing.expectEqual(Mode.core, e.fb.?.sw.mode());
        }
        try testing.expectEqual(@as(u64, 0), e.fetcher.stats.errors.load(.acquire));
        try expectCleanReopen(&w, e, "edge");
    }
}

test "edge stop: a core cut off in the middle of its responses does not hold the stop (not for the 3 s a stalled response is given)" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const e = try catchingUp(&w, true, .{});
    defer e.destroy();
    // the link dies 25 datagrams from now: inside the feed responses under way
    w.link.cut_in.store(25, .release);
    const t0 = fx.nowNs();
    while (!w.link.down.load(.acquire)) {
        try testing.expect(fx.nowNs() - t0 < 10_000 * ms);
        fx.sleepMs(1);
    }
    fx.sleepMs(100);
    const s = try stopEdge(e);
    report("core cut mid-response", s);
    try expectQuick("core cut mid-response", e, s);
    try testing.expectEqual(@as(u64, 0), e.stats().to_fallback.load(.monotonic));
    try expectCleanReopen(&w, e, "edge");
}

test "edge stop: right after a switch to the fallback, with the prober inside a probe of the dead core, the stop does not wait for the probe" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    // a probe of a silent core takes 4 s and the next one follows at once: after the switch
    // the prober is inside a connect practically all the time
    var t = fx.quick;
    t.probe_timeout_ms = 4_000;
    t.probe_ms = 20;
    const e = try catchingUp(&w, true, t);
    defer e.destroy();
    w.link.down.store(true, .release);
    try fx.must(e.waitMode(.fallback, t.fail_after_ms + 3_000), "waitMode(.fallback)", e);
    // following from the bucket now
    const t0 = fx.nowNs();
    while (e.stats().from_fallback.load(.monotonic) == 0) {
        try testing.expect(fx.nowNs() - t0 < 10_000 * ms);
        fx.sleepMs(1);
    }
    fx.sleepMs(150);
    const s = try stopEdge(e);
    report("just switched to the fallback", s);
    try expectQuick("just switched to the fallback", e, s);
    try testing.expectEqual(@as(u64, 1), e.stats().to_fallback.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), e.stats().to_core.load(.monotonic));
    try expectCleanReopen(&w, e, "edge");
}

test "edge stop: during the grace of a switch in progress (quick rules, the fetch threads between tries of a dead core), the stop is not counted as the core's failure" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    // a long grace: the stop comes well inside it, with the fetch threads retrying the core
    var t = fx.quick;
    t.fail_after_ms = 6_000;
    const e = try catchingUp(&w, true, t);
    defer e.destroy();
    w.link.down.store(true, .release);
    fx.sleepMs(500);
    try testing.expectEqual(Mode.core, e.fb.?.sw.mode());
    const s = try stopEdge(e);
    report("switch in progress", s);
    try expectQuick("switch in progress", e, s);
    try testing.expectEqual(@as(u64, 0), e.stats().to_fallback.load(.monotonic));
    try testing.expectEqual(Mode.core, e.fb.?.sw.mode());
    try expectCleanReopen(&w, e, "edge");
}

test "edge stop: with many feed requests in flight (pipelined calls, 12 at once), a stop is as quick and as clean, with the core answering and with the core cut off mid-response" {
    for ([_]bool{ false, true }) |cut| {
        var w: fx.World = undefined;
        try w.init();
        defer w.deinit();
        // 12 in flight over the 3 fetch threads: 4 requests in each call
        var fl = source_mod.InFlight.init(12, 64, 16);
        const e = try catchingUpWith(&w, true, .{}, &fl);
        defer e.destroy();
        try testing.expect(fl.calls.load(.acquire) > 0);
        try testing.expect(fl.peak.load(.acquire) >= 8);
        if (cut) {
            w.link.cut_in.store(40, .release);
            const t0 = fx.nowNs();
            while (!w.link.down.load(.acquire)) {
                try testing.expect(fx.nowNs() - t0 < 10_000 * ms);
                fx.sleepMs(1);
            }
            fx.sleepMs(100);
        }
        const s = try stopEdge(e);
        report(if (cut) "pipelined, core cut mid-response" else "pipelined", s);
        try expectQuick("pipelined", e, s);
        try testing.expectEqual(@as(u32, 0), fl.now.load(.acquire));
        try testing.expectEqual(@as(u64, 0), e.stats().to_fallback.load(.monotonic));
        if (!cut) try testing.expectEqual(@as(u64, 0), e.fetcher.stats.errors.load(.acquire));
        try expectCleanReopen(&w, e, "edge");
    }
}

test "edge feed in flight: a catch-up through pipelined calls applies every checkpoint once and in order, and at the tip the fetch threads ask one request at a time again" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    try w.coreUp(true);
    try w.publish(120);
    const e = try w.edge_("edge", true, .{});
    defer e.destroy();
    var fl = source_mod.InFlight.init(12, 64, 16);
    e.fetcher.inflight = &fl;
    try e.follow();
    try fx.must(e.waitCommitted(120, 60_000), "waitCommitted(120, 60_000)", e);
    // the catch-up came through pipelined calls, several requests each
    const calls = fl.calls.load(.acquire);
    try testing.expect(calls > 0);
    try testing.expect(fl.fetched.load(.acquire) >= 100);
    try testing.expect(fl.fetched.load(.acquire) >= 2 * calls);
    try testing.expect(fl.peak.load(.acquire) >= 8);
    // never more claimed than the window, whatever the count asked for
    try testing.expect(fl.peak.load(.acquire) <= 16);
    // the tip: the core does not hold the next checkpoint yet
    const t0 = fx.nowNs();
    while (e.fetcher.frontier.load(.acquire) == std.math.maxInt(u64)) {
        try testing.expect(fx.nowNs() - t0 < 10_000 * ms);
        fx.sleepMs(1);
    }
    fx.sleepMs(100);
    const at_tip = fl.calls.load(.acquire);
    var n: u64 = 121;
    while (n <= 128) : (n += 1) {
        try w.publish(n);
        try fx.must(e.waitCommitted(n, 20_000), "waitCommitted(n, 20_000)", e);
        fx.sleepMs(30);
    }
    // no pipelined call at the tip: the profile's behaviour
    try testing.expectEqual(at_tip, fl.calls.load(.acquire));
    try testing.expectEqual(@as(u32, 0), fl.now.load(.acquire));
    try testing.expectEqual(@as(u32, 12), fl.ctl.target);
    try testing.expectEqual(Mode.core, e.fb.?.sw.mode());
    try testing.expectEqual(@as(u64, 0), e.stats().from_fallback.load(.monotonic));
    e.follower.stop();
    try e.expectOrdered(128);
}

test "edge stop: at the tip (the fetch threads in the idle poll) the stop is quick and clean" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    try w.coreUp(true);
    const e = try w.edge_("edge", true, .{});
    defer e.destroy();
    try e.follow();
    try w.publish(8);
    try fx.must(e.waitCommitted(8, 20_000), "waitCommitted(8, 20_000)", e);
    // nothing new: the frontier thread polls the core, the others wait for it
    fx.sleepMs(300);
    try testing.expect(e.fetcher.stats.misses.load(.acquire) > 0);
    const s = try stopEdge(e);
    report("tip", s);
    try expectQuick("tip", e, s);
    try testing.expectEqual(@as(usize, 0), s.applied_after);
    try testing.expectEqual(@as(u64, 0), e.fetcher.stats.errors.load(.acquire));
    try testing.expectEqual(@as(u64, 8), e.committed());
    try expectCleanReopen(&w, e, "edge");
}

test "fetch stage stop: a fetch thread asleep in its retry backoff ends at once, whatever the source (the backoff grows to 10 s, more than the node's stop deadline)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var nb: [32]u8 = undefined;
    // a source every read of which fails: the checkpoints are directories
    try tmp.dir.createDir(io, "src", .default_dir);
    const src_dir = try tmp.dir.openDir(io, "src", .{});
    defer src_dir.close(io);
    for (100..104) |s| try src_dir.createDir(io, try std.fmt.bufPrint(&nb, "{d}.chk", .{s}), .default_dir);
    try tmp.dir.createDir(io, "spool", .default_dir);
    const spool = try tmp.dir.openDir(io, "spool", .{ .iterate = true });
    defer spool.close(io);
    const src: source_mod.Source = .{ .gpa = testing.allocator, .io = io, .kind = .{ .dir = src_dir } };
    var applied: Atomic(u64) = .init(100);
    // the first retry waits 4 s (as a thread deep in its backoff would): the test's bound
    var f: source_mod.Fetcher = .{ .gpa = testing.allocator, .io = io, .source = &src, .spool = spool, .next = .init(100), .applied_next = &applied, .window = 16, .poll_ms = 1, .to = 103, .retry_ms = 4_000 };
    try f.start(2);
    var waited: u32 = 0;
    while (f.stats.transient_errors.load(.acquire) < 2 and waited < 5000) : (waited += 1) fx.sleepMs(1);
    const errors = f.stats.transient_errors.load(.acquire);
    fx.sleepMs(50); // both threads are asleep in the backoff now
    const t0 = fx.nowNs();
    source_mod.requestStop(&f, &src, null);
    f.stop();
    const took = (fx.nowNs() - t0) / ms;
    try testing.expectEqual(@as(u64, 2), errors);
    try testing.expect(took < 500);
    // and the stop added no error of its own
    try testing.expectEqual(@as(u64, 2), f.stats.errors.load(.acquire));
}

test "stop deadline: once a signal armed it, the store close gets its own longer deadline; without a signal no timer is armed" {
    // no signal (the node ends at --to or on a fatal error): nothing to re-arm
    try testing.expectEqual(@as(u32, 0), node_mod.signals.load(.acquire));
    node_mod.closeDeadline();
    try testing.expectEqual(@as(c_uint, 0), std.c.alarm(0));
    // a signal came and the stop deadline (8 s) runs; the stop reaches the store close
    node_mod.signals.store(1, .release);
    defer node_mod.signals.store(0, .release);
    _ = std.c.alarm(8);
    node_mod.closeDeadline();
    const left = std.c.alarm(0); // read and cancel: no SIGALRM reaches the test
    try testing.expect(node_mod.closeDeadlineS() >= 60);
    try testing.expect(left > 8 and left <= node_mod.closeDeadlineS());
}

test "edge feed in flight: the default cap is 16, well under a core's feed queue of 64 for all its clients; 64 stays reachable by the flag" {
    const spec: node_mod.Zui1Spec = .{ .cores = "" };
    try testing.expectEqual(@as(u32, 16), spec.max_inflight);
    try testing.expectEqual(@as(u32, 16), (edge.inflight.Config{ .floor = 4, .window = 32 }).cap);
    // the edge profile (4 fetch threads, window 32): 4 to 16 by default, 4 to 32 with the flag at 64
    var d = source_mod.InFlight.init(4, spec.max_inflight, 32);
    try testing.expectEqual(@as(u32, 16), d.ctl.limit());
    var f = source_mod.InFlight.init(4, 64, 32);
    try testing.expectEqual(@as(u32, 32), f.ctl.limit());
    try testing.expectEqual(@as(u32, 4), d.target.load(.acquire));
    try testing.expectEqual(@as(u32, 4), f.target.load(.acquire));
}

// ------------------------------------------------------------------ with a core upstream

const h2 = serve.h2;
const forward = edge.forward;
const grpc = rpc_exec.live.grpc_client;
const sys = std.heap.smp_allocator;
const p_info = "/sui.rpc.v2.LedgerService/GetServiceInfo";
const p_epoch = "/sui.rpc.v2.LedgerService/GetEpoch";
const p_subscribe = "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints";

/// The core's sui.rpc.v2 port as an edge's forwarder meets it: GetServiceInfo is answered (the
/// forwarder's read of the core's floor), a subscription sends a message every 10 ms for as long
/// as its caller listens, and every other call is never answered.
const UpCore = struct {
    /// False: the test is over, every held call returns.
    var open: Atomic(bool) = .init(true);
    /// Unary calls held in the handler right now (they stay in the h2 server's job count).
    var holding: Atomic(u32) = .init(0);
    var streams_ended: Atomic(u32) = .init(0);

    fn call(_: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        if (std.mem.eql(u8, req.path, p_info)) {
            // GetServiceInfoResponse { lowest_available_checkpoint = 6: 1 }
            rs.message(&.{ 0x30, 1 }) catch return .internal;
            return .ok;
        }
        if (std.mem.eql(u8, req.path, p_subscribe)) {
            if (serve.lh_service.ListPump.attachTest(req.stream_id, req.body, subscription)) return .deferred;
            return .unavailable;
        }
        _ = holding.fetchAdd(1, .acq_rel);
        defer _ = holding.fetchSub(1, .acq_rel);
        while (open.load(.acquire) and !rs.cancelled()) fx.sleepMs(5);
        return .cancelled;
    }

    fn subscription(_: *serve.lh_service.ListPump, _: std.mem.Allocator, rs: *h2.ResponseStream) h2.Status {
        while (open.load(.acquire) and !rs.cancelled()) {
            rs.message("checkpoint") catch break;
            fx.sleepMs(10);
        }
        _ = streams_ended.fetchAdd(1, .acq_rel);
        return .cancelled;
    }

    const unit: u8 = 0;
    const handler: h2.Handler = .{ .ctx = @constCast(&unit), .call = call };
};

/// What the h2 runtime has open, process-wide (`waitDrained` looks at the same three).
const Load = struct {
    conns: u32,
    jobs: u32,
    pumps: u32,

    fn now() Load {
        const st = &h2.server.stats;
        return .{ .conns = st.conns.load(.acquire), .jobs = st.jobs.load(.acquire), .pumps = st.pumps.load(.acquire) };
    }

    /// The least seen over 60 ms: the forwarder's reads of the core's floor come and go.
    fn idle() Load {
        var least = now();
        for (0..30) |_| {
            fx.sleepMs(2);
            const l = now();
            least = .{ .conns = @min(least.conns, l.conns), .jobs = @min(least.jobs, l.jobs), .pumps = @min(least.pumps, l.pumps) };
        }
        return least;
    }
};

/// An h2 server on loopback: the core's sui.rpc.v2 port, or the edge's `--serve` port with the
/// forwarding handler in front. `grace_ms` is what a stopped server gives its open streams
/// (the node: `--drain-ms`).
const Front = struct {
    listener: Io.net.Server,
    port: u16,
    stop_flag: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    handler: h2.Handler,
    grace_ms: u64,
    /// When `drain` began (`fx.nowNs`).
    drain_at: u64 = 0,
    /// Connections `drain` had to close itself (`h2.server.forceClose`).
    forced: u32 = 0,

    /// A connection thread with nothing to do looks at the stop flag once a second
    /// (h2/server.zig), so a drain with idle connections takes up to this long.
    const conn_tick_ms: u64 = 1000;

    fn start(handler: h2.Handler, grace_ms: u64) !*Front {
        const s = try sys.create(Front);
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        s.* = .{ .listener = try addr.listen(io, .{ .reuse_address = true }), .port = 0, .handler = handler, .grace_ms = grace_ms };
        s.port = s.listener.socket.address.getPort();
        s.thread = try std.Thread.spawn(.{}, run, .{s});
        return s;
    }
    fn run(s: *Front) void {
        h2.serveBlocking(sys, io, &s.listener, .{ .poll_accept = true, .stop_grace_ns = s.grace_ms * ms }, s.handler, &s.stop_flag) catch {};
    }

    /// The node's `gracefulStop` up to the end of its drain (node.zig `drainRpc`, the steps of
    /// `h2.server.drainThenForce`): the server stops taking calls, the forwarded streams end
    /// with the local ones, and the stop waits until nothing of this server is open any more
    /// (`idle`: what was open before its clients came; the calls the core still holds are the
    /// core's) for `--drain-ms` + 1 s. What is left then has its socket shut down and 1 s to
    /// leave. Returns how long it all took (ms), null when something was still open after
    /// that: a call still running in a handler (the node then flushes the store and does not
    /// close it).
    /// The forced close is the server's, for every connection in the process: here that
    /// includes the core's end of the forwarder's upstream connection, which on a real edge is
    /// another box's.
    fn drain(s: *Front, fwd: *forward.Forwarder, idle: Load) ?u64 {
        const t0 = fx.nowNs();
        s.drain_at = t0;
        s.stop_flag.store(true, .release);
        fwd.endStreams();
        if (!waitIdle(idle, t0 + (s.grace_ms + 1000) * ms)) {
            s.forced = h2.server.forceClose();
            if (!waitIdle(idle, fx.nowNs() + 1000 * ms)) return null;
        }
        return (fx.nowNs() - t0) / ms;
    }

    fn waitIdle(idle: Load, until_ns: u64) bool {
        while (true) {
            const l = Load.now();
            if (l.conns <= idle.conns and l.pumps <= idle.pumps and l.jobs <= idle.jobs + UpCore.holding.load(.acquire)) return true;
            if (fx.nowNs() >= until_ns) return false;
            fx.sleepMs(2);
        }
    }

    fn stop(s: *Front) void {
        s.stop_flag.store(true, .release);
        if (s.thread) |t| t.join();
        s.listener.deinit(io);
        sys.destroy(s);
    }
};

/// A client of the edge that stays on its call when the server says GOAWAY, as gRPC clients do:
/// the node's own h2 client with a raw call (a stream, or a unary call without a deadline).
const Client = struct {
    conn: *grpc.Conn,
    slot: u32 = 0,
    bytes: Atomic(u64) = .init(0),
    done: Atomic(bool) = .init(false),
    /// When the call ended (`fx.nowNs`).
    done_at: Atomic(u64) = .init(0),
    code: Atomic(u8) = .init(255),

    fn open(port: u16, path: []const u8) !*Client {
        const c = try sys.create(Client);
        c.* = .{ .conn = try grpc.Conn.open(sys, io, .{ .host = "127.0.0.1", .port = port, .security = .plain }) };
        c.conn.startOpts(&c.slot, path, "", .{ .ctx = c, .done = onDone }, 0, .{ .raw = .{ .on_data = onData } });
        return c;
    }
    fn onData(ctx: *anyopaque, _: u64, bytes: []const u8) void {
        const c: *Client = @ptrCast(@alignCast(ctx));
        _ = c.bytes.fetchAdd(bytes.len, .monotonic);
    }
    fn onDone(ctx: *anyopaque, _: u64, r: grpc.Result) void {
        const c: *Client = @ptrCast(@alignCast(ctx));
        switch (r) {
            .ok => {},
            .status => |st| c.code.store(st.code, .release),
        }
        c.done_at.store(fx.nowNs(), .release);
        c.done.store(true, .release);
    }
    fn close(c: *Client) void {
        c.conn.retain();
        c.conn.release();
        readerGone(c.conn);
        sys.destroy(c);
    }
};

/// Waits for the reader thread of a closed h2 client connection the caller retained, and drops
/// that reference.
fn readerGone(conn: *grpc.Conn) void {
    var i: u32 = 0;
    while (i < 5000) : (i += 1) {
        conn.mu.lockUncancelable(io);
        const gone = conn.reader_done;
        conn.mu.unlock(io);
        if (gone) break;
        fx.sleepMs(1);
    }
    conn.unref();
}

/// The forwarder of the edge under test, for the follower's commit hook (node.zig `onCommitted`).
var commit_fwd: ?*forward.Forwarder = null;
fn onCommittedFwd(_: *anyopaque, _: u64) void {
    if (commit_fwd) |f| f.noteApplied();
}
// node.zig `fwdKnownTip`, `fwdSilentNs`
fn fwdKnownTip(ctx: *anyopaque) ?u64 {
    const e: *fx.Edge = @ptrCast(@alignCast(ctx));
    return e.fetcher.tipKnown();
}
fn fwdSilentNs(ctx: *anyopaque) u64 {
    const e: *fx.Edge = @ptrCast(@alignCast(ctx));
    return e.fetcher.silentNs();
}

test "edge stop with a core upstream (--core-upstream): in catch-up, with every call forwarded, a forwarded stream does not hold the drain, a forwarded call the core never answers holds it for --drain-ms and no longer, the forwarder's threads end before the store closes, and the store closes cleanly" {
    const Case = enum { stream, unanswered_call };
    for ([_]Case{ .stream, .unanswered_call }) |case| {
        // --drain-ms: long where nothing may wait for it, short where a call sits it out
        const drain_ms: u64 = if (case == .stream) 5000 else 400;
        var w: fx.World = undefined;
        try w.init();
        defer w.deinit();
        UpCore.open.store(true, .release);
        UpCore.streams_ended.store(0, .release);
        const core_rpc = try Front.start(UpCore.handler, 50);
        defer {
            core_rpc.stop();
            _ = h2.server.waitDrained(3 * std.time.ns_per_s);
        }
        defer UpCore.open.store(false, .release);

        // the edge, as `catchingUp` makes it, with the forwarder wired as node.zig wires it
        try w.coreUp(true);
        try w.publish(behind);
        const e = try w.edge_("edge", true, .{});
        defer e.destroy();
        e.apply_delay_ms.store(apply_ms, .release);
        var svc: serve.service.Service = .{ .gpa = testing.allocator, .store = e.st, .chain_id = @splat(0), .json = false, .display = false, .lowest_checkpoint = first };
        defer svc.deinit();
        var gt = try forward.GrpcTransport.init(sys, io, .{ .host = "127.0.0.1", .port = core_rpc.port, .security = .plain });
        const f = try forward.Forwarder.create(testing.allocator, io, &svc, gt.transport(), .{ .tick_ms = 10, .floor_refresh_ms = 20 });
        defer {
            f.destroy();
            const conn = gt.up.conn;
            if (conn) |c| c.retain();
            gt.deinit();
            if (conn) |c| readerGone(c);
        }
        f.source = .{ .ctx = e, .known_tip = fwdKnownTip, .silent_ns = fwdSilentNs };
        commit_fwd = f;
        defer commit_fwd = null;
        e.follower.observer.?.on_committed = onCommittedFwd;
        try f.start();
        try e.follow();
        try fx.must(e.waitCommitted(12, 30_000), "waitCommitted(12, 30_000)", e);
        try testing.expect(waitWaiting(e.follower, 3, 10_000));
        try testing.expect(e.committed() < behind / 2);
        // the forwarder read the core's floor over its upstream connection; far behind its
        // core, the edge passes every call on
        {
            const t0 = fx.nowNs();
            while (serve.service.reportedLowest(&svc) != 1) {
                try testing.expect(fx.nowNs() - t0 < 5_000 * ms);
                fx.sleepMs(2);
            }
        }
        try testing.expectEqual(edge.route.GuardState.tripped, f.guardState());

        const idle = Load.idle();
        const front = try Front.start(f.handler(), drain_ms);
        defer front.stop();
        const c = try Client.open(front.port, if (case == .stream) p_subscribe else p_epoch);
        defer c.close();
        {
            // the call is with the core
            const t0 = fx.nowNs();
            while (if (case == .stream) c.bytes.load(.acquire) == 0 else UpCore.holding.load(.acquire) == 0) {
                try testing.expect(fx.nowNs() - t0 < 5_000 * ms);
                fx.sleepMs(2);
            }
        }
        try testing.expect(!c.done.load(.acquire));

        // SIGTERM. The drain first:
        const drained = front.drain(f, idle);
        // then the follower, the fetch threads, the forwarder's threads, the prober, the store
        const s = try stopEdgeWith(e, f);
        const what = if (case == .stream) "core upstream, a forwarded stream open" else "core upstream, a forwarded call unanswered";
        report(what, s);
        const ended: ?u64 = if (c.done.load(.acquire)) (c.done_at.load(.acquire) -| front.drain_at) / ms else null;
        std.debug.print("edge stop ({s}): drain {?d} ms of --drain-ms {d} ({d} connections closed by the server), the client's call ended {?d} ms into it; forwarder threads {d} ms\n", .{ what, drained, drain_ms, front.forced, ended, s.forwarder_ms });
        // drained: the node closes its store (not drained, it only flushes it)
        try testing.expect(drained != null);
        switch (case) {
            .stream => {
                // the stream ended when the drain began, with a status, and the drain did not
                // wait for --drain-ms: only for its connection's thread to look at the stop flag
                try testing.expect(c.done.load(.acquire));
                try testing.expect((c.done_at.load(.acquire) -| front.drain_at) / ms < stop_limit_ms / 2);
                try testing.expectEqual(@as(u8, 1), c.code.load(.acquire));
                try testing.expect(drained.? < Front.conn_tick_ms + stop_limit_ms / 2);
                // and the core's stream was cancelled with it
                const t0 = fx.nowNs();
                while (UpCore.streams_ended.load(.acquire) == 0) {
                    try testing.expect(fx.nowNs() - t0 < 1_000 * ms);
                    fx.sleepMs(2);
                }
            },
            .unanswered_call => {
                // A call in flight is given the drain. The core never answers, so its
                // connection is closed for it: by its own thread once the grace is over (as
                // the thread's poll sees it), or by the server when the drain is (`forced`).
                // The call looks at its client every 20 ms and ends with the connection:
                // nothing is left running in a handler (`drained` above), the store closes.
                try testing.expect(drained.? >= drain_ms - 50);
                try testing.expect(c.done.load(.acquire));
            },
        }
        try expectQuick(what, e, s);
        try testing.expect(s.forwarder_ms < 100);
        try testing.expectEqual(@as(u64, 0), e.fetcher.stats.errors.load(.acquire));
        // the store is closed: several tick periods later nothing of the forwarder has gone
        // back to it (its threads were joined before the close; a late one reads freed memory)
        fx.sleepMs(60);
        try expectCleanReopen(&w, e, "edge");
    }
}
