//! p2p-only follow mode (`deepwave run --p2p-only --p2p ...`): no bucket, no S3, no stream.
//! Summaries and contents come only from peers, every checkpoint is executed locally
//! (p2p_exec.zig) and verified by the follower as with any source. The fetcher stays only as
//! the spool and its claim API (no fetch threads), so p2p.zig is unchanged in shape.
//!
//! What changes when nothing else will deliver a checkpoint (p2p.zig calls these hooks only with
//! `P2p.p2p_only`):
//!   - a fallback is retried, never left to another source: first in order (no level-parallel
//!     run) on a fresh snapshot, then with contents fetched again (another peer may answer), then
//!     in order with a backoff growing to 30 s; a summary that does not link is dropped and asked
//!     for again by number. Every retry is logged at error level, and a stall is logged every 10 s;
//!   - contents requests that failed 3 times (`failed`) are reset after a second;
//!   - a summary gap (a None answer to the by-number request) is asked
//!     for again every second.
//! Counted for the exit summary: fallbacks, mismatches (a fallback whose result differs from the
//! certified one), retries, recovered checkpoints, the longest stall.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const p2p = @import("p2p.zig");
const px = @import("p2p_exec.zig");
const source = @import("source.zig");
const Atomic = std.atomic.Value;

/// Error level (the retries must be loud), warn under the test runner (which fails on error logs).
fn loud(comptime fmt: []const u8, args: anytype) void {
    if (@import("builtin").is_test) std.log.warn(fmt, args) else std.log.err(fmt, args);
}

pub const Stats = struct {
    fallbacks: Atomic(u64) = .init(0),
    /// Fallbacks whose execution result differs from the certified effects or events.
    mismatches: Atomic(u64) = .init(0),
    retries: Atomic(u64) = .init(0),
    /// Checkpoints delivered after at least one retry.
    recovered: Atomic(u64) = .init(0),
    refetches: Atomic(u64) = .init(0),
    /// Summaries dropped and asked for again (no chain link).
    resummaries: Atomic(u64) = .init(0),
    /// Contents fetches reset after 3 failures, and summary gaps asked for again.
    unstuck: Atomic(u64) = .init(0),
    gap_retries: Atomic(u64) = .init(0),
    /// Longest time the follower's next checkpoint did not move (ms).
    max_stall_ms: Atomic(u64) = .init(0),
};

pub const State = struct {
    stats: Stats = .{},
    /// The checkpoint being retried, its retries and when its next build may start.
    seq: u64 = std.math.maxInt(u64),
    tries: u32 = 0,
    first_ms: u64 = 0,
    next_ms: u64 = 0,
    // Progress watch (exec thread only).
    watch_seq: u64 = std.math.maxInt(u64),
    watch_ms: u64 = 0,
    warned_ms: u64 = 0,
    last_tick_ms: u64 = 0,
    gap_ms: u64 = 0,
};

/// The fallback is a result that differs from the certified one (not something deepwave cannot run).
fn isMismatch(why: []const u8) bool {
    // p2p_exec's checks of deepwave's result against the certified effects and events.
    for ([_][]const u8{ "effects differ", "events digest differs", "certified events", "zui events", "output object" }) |k| {
        if (std.mem.startsWith(u8, why, k)) return true;
    }
    return false;
}

const Action = enum { serial, refetch, resummary, wait };

fn actionFor(why: []const u8, tries: u32) Action {
    const eq = struct {
        fn f(a: []const u8, b: []const u8) bool {
            return std.mem.eql(u8, a, b);
        }
    }.f;
    if (eq(why, "chain link differs") or eq(why, "summary does not parse") or eq(why, "no previous digest")) return .resummary;
    if (eq(why, "contents do not parse") or eq(why, "contents digest differs")) return .refetch;
    if (eq(why, "epoch parameters unknown") or eq(why, "previous checkpoint not stored")) return .wait;
    // Execution: in order first; then contents again (and in order); then in order with backoff.
    return if (tries == 2) .refetch else .serial;
}

fn backoffMs(tries: u32) u64 {
    const shift: u6 = @intCast(@min(tries -| 1, 7));
    return @min(@as(u64, 250) << shift, 30_000);
}

/// Exec thread, after a fallback on `seq` (`why`: its reason). The slot stays done (so the exec
/// thread does not pick it again) until `tick` releases it after the backoff.
pub fn onFallback(p: *p2p.P2p, seq: u64, why: []const u8) void {
    const st = &p.only;
    const now = source.wallMs();
    _ = st.stats.fallbacks.fetchAdd(1, .monotonic);
    if (isMismatch(why)) _ = st.stats.mismatches.fetchAdd(1, .monotonic);
    if (st.seq != seq) {
        st.seq = seq;
        st.tries = 0;
        st.first_ms = now;
    }
    st.tries += 1;
    _ = st.stats.retries.fetchAdd(1, .monotonic);
    const act = actionFor(why, st.tries);
    st.next_ms = now + backoffMs(st.tries);
    loud("p2p-only: checkpoint {d} not built ({s}); nothing else delivers it: retry {d} ({s}) in {d} ms", .{ seq, why, st.tries, @tagName(act), st.next_ms - now });
    if (std.mem.eql(u8, why, "input object not in the store")) diagnoseMissing(p, seq);
    p.lock.lockUncancelable(p.io);
    defer p.lock.unlock(p.io);
    const slot = &p.slots[seq % p.slots.len];
    if (slot.seq != seq) return;
    slot.serial = true;
    switch (act) {
        // Held (done) until `tick` releases it after the backoff.
        .serial, .wait => slot.done = true,
        .refetch => {
            _ = st.stats.refetches.fetchAdd(1, .monotonic);
            p.gpa.free(slot.full);
            slot.full = &.{};
            slot.state = .none;
            slot.tries = 0;
            slot.done = false;
        },
        .resummary => {
            _ = st.stats.resummaries.fetchAdd(1, .monotonic);
            p.gpa.free(slot.cert);
            p.gpa.free(slot.full);
            slot.* = .{};
            p.gap_req[seq % p.gap_req.len] = std.math.maxInt(u64);
        },
    }
}

/// Exec thread, after `seq` was built and delivered.
pub fn onDelivered(p: *p2p.P2p, seq: u64) void {
    const st = &p.only;
    if (st.seq != seq) return;
    _ = st.stats.recovered.fetchAdd(1, .monotonic);
    std.log.warn("p2p-only: checkpoint {d} built after {d} retries ({d} ms)", .{ seq, st.tries, source.wallMs() -| st.first_ms });
    st.seq = std.math.maxInt(u64);
    st.tries = 0;
}

/// Exec thread, while it has nothing ready: keeps the follower's next checkpoint moving.
pub fn tick(p: *p2p.P2p) void {
    const st = &p.only;
    const now = source.wallMs();
    if (now -| st.last_tick_ms < 20) return;
    st.last_tick_ms = now;
    const lo = p.fetcher.applied_next.load(.acquire);
    if (lo != st.watch_seq) {
        if (st.watch_seq != std.math.maxInt(u64)) {
            const stalled = now -| st.watch_ms;
            var m = st.stats.max_stall_ms.load(.monotonic);
            while (stalled > m) m = st.stats.max_stall_ms.cmpxchgWeak(m, stalled, .monotonic, .monotonic) orelse break;
        }
        st.watch_seq = lo;
        st.watch_ms = now;
        st.warned_ms = now;
        st.gap_ms = now;
    }
    if (!p.fetcher.wants(lo)) return; // in the spool already
    p.lock.lockUncancelable(p.io);
    defer p.lock.unlock(p.io);
    const slot = &p.slots[lo % p.slots.len];
    if (slot.seq == lo) {
        // Done but not in the spool (`wants` above): a fallback. Build it again once its backoff
        // ran out (a checkpoint after `lo` that failed meanwhile is released when it becomes `lo`).
        if (slot.done and (st.seq != lo or now >= st.next_ms)) slot.done = false;
        if (slot.state == .failed and now -| slot.fetch_ms >= 1000) {
            _ = st.stats.unstuck.fetchAdd(1, .monotonic);
            slot.state = .none;
            slot.tries = 0;
            slot.fetch_mask = 0;
            slot.inflight = 0;
        }
    } else if (now -| st.gap_ms >= 1000) {
        // No summary yet: let the peers ask for it by number again (a None answer marks it once).
        st.gap_ms = now;
        if (p.gap_req[lo % p.gap_req.len] == lo) {
            p.gap_req[lo % p.gap_req.len] = std.math.maxInt(u64);
            _ = st.stats.gap_retries.fetchAdd(1, .monotonic);
        }
    }
    if (now -| st.warned_ms >= 10_000) {
        st.warned_ms = now;
        loud("p2p-only: no progress at checkpoint {d} for {d} s (summary {s}, contents {s}, {d} peers up, retries {d})", .{
            lo,                                                                     (now -| st.watch_ms) / 1000,
            if (slot.seq == lo) "seen" else "not seen",                             if (slot.seq != lo) "-" else @tagName(slot.state),
            p.stats.peers_up.load(.monotonic), if (st.seq == lo) st.tries else 0,
        });
    }
}

/// "input object not in the store": which object, and what the store holds for it. Seen once per
/// restart in race mode while another source's copy of the same
/// checkpoint was being committed (`other source` below says whether one had it).
fn diagnoseMissing(p: *p2p.P2p, seq: u64) void {
    var arena = std.heap.ArenaAllocator.init(p.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    p.lock.lockUncancelable(p.io);
    const slot = &p.slots[seq % p.slots.len];
    const full = if (slot.seq == seq) a.dupe(u8, slot.full) catch &.{} else &.{};
    const parent = slot.parent;
    p.lock.unlock(p.io);
    if (full.len == 0) return;
    const fc = px.splitFull(a, full) catch return;
    var snap = p.st.snapshot();
    defer snap.release();
    for (fc.txs, 0..) |t, i| {
        const fx = bcs.decode(types.TransactionEffects, a, t.effects) catch return;
        const v2 = switch (fx) {
            .V2 => |v| v,
            .V1 => return,
        };
        for (v2.changed_objects) |c| switch (c[1].input_state) {
            .Exist => |e| {
                const id = &c[0].@"0".@"0";
                const ver = e[0][0].@"0";
                if (snap.objectAt(id, ver) != null) continue;
                const live = snap.liveObject(id);
                loud("p2p-only: checkpoint {d} tx {d}: input {x} version {d} not in the store at {?d}; live version {?d}; pipelined {}; other source has it {}", .{
                    seq, i, id.*, ver, snap.highestCommitted(), if (live) |l| l.version else null, parent, !p.fetcher.wants(seq),
                });
                return;
            },
            .NotExist => {},
        };
    }
    loud("p2p-only: checkpoint {d}: every input object is in the store now (a transient read at build time)", .{seq});
}

pub fn printSummary(p: *p2p.P2p, rejected: bool) void {
    const x = &p.only.stats;
    std.log.info("p2p-only: fallbacks {d} (mismatches {d}), retries {d}, recovered {d}, refetches {d}, summaries asked again {d}, fetches unstuck {d}, gap retries {d}, longest stall {d} ms, follower rejects {d}", .{
        x.fallbacks.load(.monotonic), x.mismatches.load(.monotonic), x.retries.load(.monotonic),     x.recovered.load(.monotonic),     x.refetches.load(.monotonic),
        x.resummaries.load(.monotonic), x.unstuck.load(.monotonic),  x.gap_retries.load(.monotonic), x.max_stall_ms.load(.monotonic), @intFromBool(rejected),
    });
}

/// Peer scoring counters (every p2p run, p2p-only or not).
pub fn printScores(p: *p2p.P2p) void {
    const ps = &p.scores.stats;
    std.log.info("p2p peers: {d} samples ok, {d} failed; {d} reported failing ({d} dropped and cooled down, {d} kept: seed or too few peers), {d} pruned (never connected), {d} pinned-checkpoint rejects", .{
        ps.successes.load(.monotonic), ps.failures.load(.monotonic), ps.reported.load(.monotonic), ps.dropped.load(.monotonic), ps.kept.load(.monotonic), ps.pruned.load(.monotonic), ps.pinned_rejects.load(.monotonic),
    });
}

/// `--p2p-pinned SEQ:DIGEST[,...]` (digest in base58, as sui's config writes it).
pub fn parsePinned(a: std.mem.Allocator, text: []const u8) ![]@import("net").peer_score.Pinned.Entry {
    const Entry = @import("net").peer_score.Pinned.Entry;
    var out: std.ArrayList(Entry) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, ',');
    while (it.next()) |tok| {
        const t = std.mem.trim(u8, tok, " ");
        const colon = std.mem.indexOfScalar(u8, t, ':') orelse return error.BadPinned;
        const seq = std.fmt.parseInt(u64, t[0..colon], 10) catch return error.BadPinned;
        const d = @import("serve").b58.decode32(t[colon + 1 ..]) orelse return error.BadPinned;
        try out.append(a, .{ .seq = seq, .digest = d });
    }
    return out.toOwnedSlice(a);
}

test "p2p-only: actions and backoff" {
    try std.testing.expectEqual(Action.serial, actionFor("input object not in the store", 1));
    try std.testing.expectEqual(Action.refetch, actionFor("input object not in the store", 2));
    try std.testing.expectEqual(Action.serial, actionFor("input object not in the store", 3));
    try std.testing.expectEqual(Action.resummary, actionFor("chain link differs", 1));
    try std.testing.expectEqual(Action.refetch, actionFor("contents digest differs", 1));
    try std.testing.expectEqual(Action.wait, actionFor("epoch parameters unknown", 1));
    try std.testing.expect(isMismatch("effects differ (ProgrammableTransaction)"));
    try std.testing.expect(isMismatch("zui events, certified none"));
    try std.testing.expect(!isMismatch("package not in corpus"));
    try std.testing.expect(!isMismatch("chain link differs"));
    try std.testing.expect(!isMismatch("contents digest differs"));
    try std.testing.expectEqual(@as(u64, 250), backoffMs(1));
    try std.testing.expectEqual(@as(u64, 500), backoffMs(2));
    try std.testing.expectEqual(@as(u64, 30_000), backoffMs(9));
    try std.testing.expectEqual(@as(u64, 30_000), backoffMs(100));
}

test "p2p-only: pinned list" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const got = try parsePinned(arena.allocator(), "0:4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S, 7:4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S");
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqual(@as(u64, 7), got[1].seq);
    try std.testing.expectError(error.BadPinned, parsePinned(arena.allocator(), "7"));
    try std.testing.expectError(error.BadPinned, parsePinned(arena.allocator(), "x:abc"));
}

test "p2p-only: retry state machine without a network (fallback, backoff, refetch, re-summary, unstick, gap retry)" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var applied_next: Atomic(u64) = .init(100);
    const f = try gpa.create(source.Fetcher);
    defer gpa.destroy(f);
    f.* = .{ .gpa = gpa, .io = io, .source = undefined, .spool = tmp.dir, .next = .init(100), .applied_next = &applied_next, .window = 64, .poll_ms = 25, .to = std.math.maxInt(u64) };
    try f.start(0); // p2p-only: no fetch threads
    defer f.stop();
    var p: p2p.P2p = .{ .gpa = gpa, .io = io, .st = undefined, .fetcher = f, .peers = &.{}, .key = undefined, .hooks = .{ .ctx = undefined, .params = undefined }, .exec_threads = 1, .p2p_only = true };
    try p.init();
    defer p.stop();
    const st = &p.only;

    // A built checkpoint whose execution fell back: held, then released after the backoff.
    const slot = &p.slots[100 % p.slots.len];
    p.gpa.free(slot.cert);
    p.gpa.free(slot.full);
    slot.* = .{ .seq = 100, .cert = try gpa.dupe(u8, "cert"), .full = try gpa.dupe(u8, "full"), .state = .ready };
    onFallback(&p, 100, "ptb: Unsupported");
    try testing.expect(slot.done and slot.serial and slot.state == .ready);
    try testing.expectEqual(@as(u32, 1), st.tries);
    tick(&p);
    try testing.expect(slot.done); // backoff (250 ms) not over
    st.next_ms = 0;
    st.last_tick_ms = 0;
    tick(&p);
    try testing.expect(!slot.done); // released: the exec thread builds it again, in order

    // Second failure: contents asked for again (another peer may answer), not held.
    onFallback(&p, 100, "ptb: Unsupported");
    try testing.expect(!slot.done and slot.state == .none and slot.full.len == 0);
    try testing.expectEqual(@as(u64, 1), st.stats.refetches.load(.monotonic));

    // Built at last.
    slot.outcome = .delivered;
    onDelivered(&p, 100);
    try testing.expectEqual(@as(u64, 1), st.stats.recovered.load(.monotonic));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), st.seq);

    // A summary that does not link: dropped, and the by-number request re-armed.
    p.gpa.free(slot.cert);
    p.gpa.free(slot.full);
    slot.* = .{ .seq = 100, .cert = try gpa.dupe(u8, "cert"), .full = try gpa.dupe(u8, "full"), .state = .ready };
    p.gap_req[100 % p.gap_req.len] = 100;
    onFallback(&p, 100, "chain link differs");
    try testing.expect(slot.seq == std.math.maxInt(u64));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), p.gap_req[100 % p.gap_req.len]);
    try testing.expectEqual(@as(u64, 1), st.stats.resummaries.load(.monotonic));

    // No summary for the next checkpoint: the gap request is re-armed every second.
    p.gap_req[100 % p.gap_req.len] = 100;
    st.gap_ms = 0;
    st.last_tick_ms = 0;
    tick(&p);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), p.gap_req[100 % p.gap_req.len]);
    try testing.expectEqual(@as(u64, 1), st.stats.gap_retries.load(.monotonic));

    // Contents that failed 3 times: fetched again.
    p.gpa.free(slot.cert);
    p.gpa.free(slot.full);
    slot.* = .{ .seq = 100, .cert = try gpa.dupe(u8, "cert"), .state = .failed, .tries = 3, .fetch_ms = 0 };
    st.last_tick_ms = 0;
    tick(&p);
    try testing.expect(slot.state == .none and slot.tries == 0);
    try testing.expectEqual(@as(u64, 1), st.stats.unstuck.load(.monotonic));

    // A later checkpoint that failed while pipelined is released once it is next.
    const s101 = &p.slots[101 % p.slots.len];
    p.gpa.free(s101.cert);
    p.gpa.free(s101.full);
    s101.* = .{ .seq = 101, .cert = try gpa.dupe(u8, "cert"), .full = try gpa.dupe(u8, "full"), .state = .ready };
    onFallback(&p, 101, "effects differ (ProgrammableTransaction)");
    try testing.expect(s101.done);
    try testing.expectEqual(@as(u64, 1), st.stats.mismatches.load(.monotonic));
    st.seq = 999; // another checkpoint was retried since
    applied_next.store(101, .release);
    st.last_tick_ms = 0;
    tick(&p);
    try testing.expect(!s101.done);

    // In the spool already: nothing to do.
    try tmp.dir.writeFile(io, .{ .sub_path = "101.chk", .data = "x" });
    s101.done = true;
    st.last_tick_ms = 0;
    tick(&p);
    try testing.expect(s101.done);
    try testing.expectEqual(@as(u64, 4), st.stats.fallbacks.load(.monotonic));
    printSummary(&p, false);
    printScores(&p);
}
