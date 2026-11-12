//! The re-ask of read sets (docs/EDGE.md 12.7): an edge that keeps read sets asks its core
//! again for the lists of a checkpoint whose feed came without them.
//!
//! Why. A core that builds checkpoints over p2p holds no final read set for one until its lists
//! were compared with sui-node's copy (reconcile.zig), about 0.2 s after the build. An edge at
//! the tip asks within about 100 ms of the build, so most tip checkpoints arrive without, and
//! their reads under `effects`, `balance_changes` and `objects` went to the core for as long
//! as the edge kept them.
//!
//! What. A feed answered with READ_SETS asked and `present` 0 (`Source.poolFetch`, the
//! pipelined sink) puts its checkpoint here, with the core that served it. The core is asked
//! again at the times of `schedule_ms` after the feed (`Pool.fetchReadSets`: the feed again,
//! with READ_SETS; the feed is dropped) until it has them; after the last "none" the checkpoint
//! is given up and stays forwarded. A checkpoint not committed here yet is not asked. Lists
//! that come are checked exactly as at apply, against the stored checkpoint
//! (`History.planLate`), and written with the mark into the next commit group
//! (`History.stageLate`); the checkpoint counts as settled once that group took them
//! (`History.late_hook`). A connection that is not free is not waited for: the fetch threads
//! come first, and the item is looked at again a moment later.
const std = @import("std");
const Io = std.Io;
const edge = @import("edge");
const store = @import("store");
const convert = @import("convert.zig");
const history = @import("history.zig");
const Atomic = std.atomic.Value;
const GaveUp = edge.client.ReadSetsGaveUp;

/// When each re-ask goes, in ms after the feed that came without read sets. The core settles a
/// p2p-built checkpoint about 0.2 s after the build (its reconcile ticks every 100 ms), so the
/// first two catch nearly all. 2 s and 5 s catch a slow reconcile; 11 s is past the core's 10 s
/// bucket fallback. Cheap: each is one feed, for the few checkpoints still without.
pub const schedule_ms = [_]u64{ 250, 600, 2_000, 5_000, 11_000 };

comptime {
    std.debug.assert(schedule_ms.len == edge.client.read_sets_attempts);
}

pub const Config = struct {
    /// `schedule_ms`; tests scale it down. At most `edge.client.read_sets_attempts` entries,
    /// ascending.
    schedule: []const u64 = &schedule_ms,
    /// An item whose asks cannot be sent this long after its feed (no free connection, failed
    /// calls, not committed here) is given up. Past the last attempt, with room for its retries.
    give_up_ms: u64 = schedule_ms[schedule_ms.len - 1] + 2_000,
    /// A pool busy this long for one ask: a free connection to another core than the one that
    /// served the feed is taken (`Pool.fetchReadSets` `other_ok`).
    other_core_after_ms: u64 = 500,
    /// Items waiting at most; one beyond is given up at once.
    max_items: usize = 1024,
    /// Only a checkpoint at most this far under the highest one the cores claimed or served is
    /// asked again. A core settles a p2p-built checkpoint within seconds; one far under its
    /// tip without a read set (history from before its switch was on, met while catching up)
    /// has none for good, and asking would only double the catch-up's feed traffic. Measured
    /// once, when the feed comes; an item is never dropped for the window later.
    near: u64 = 64,
};

pub const ReAsk = struct {
    gpa: std.mem.Allocator,
    io: Io,
    pool: *edge.client.Pool,
    hist: *history.History,
    st: *store.Store,
    cfg: Config = .{},
    mu: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(Item) = .empty,
    /// Lists planned and waiting for the next commit group (`History.late_hook` settles them).
    staged: std.ArrayList(Staged) = .empty,
    stop_flag: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    /// What `planLate` made of the lists that came (tests and the metrics).
    outcomes: [@typeInfo(history.LateOutcome).@"enum".field_names.len]Atomic(u64) = @splat(.init(0)),
    /// Checkpoints given up with the core saying "none" at every attempt, logged at most once a
    /// minute (re-ask thread only).
    unsettled_log: [3]u64 = undefined,
    unsettled_n: usize = 0,
    unsettled_more: u64 = 0,
    last_log_ns: u64 = 0,

    const Item = struct {
        seq: u64,
        noted_ns: u64,
        due_ns: u64,
        /// 1-based: which re-ask is next.
        attempt: u8,
        /// The core that served the feed (null: unknown).
        core: ?u32,
        /// Since when this ask met a busy pool (0: it did not).
        busy_since: u64 = 0,
        /// Why it would be given up now, if its time ran out: what the last try met.
        last: GaveUp = .no_conn,
    };

    const Staged = struct { seq: u64, attempt: u8 };

    fn now(r: *const ReAsk) u64 {
        return @intCast(Io.Clock.awake.now(r.io).toNanoseconds());
    }

    fn lock(r: *ReAsk) void {
        while (!r.mu.tryLock()) std.atomic.spinLoopHint();
    }

    fn giveUp(r: *ReAsk, why: GaveUp) void {
        r.pool.stats.gaveUp(why);
    }

    fn dueOf(r: *const ReAsk, noted: u64, attempt: u8) u64 {
        return noted + r.cfg.schedule[attempt - 1] * std.time.ns_per_ms;
    }

    /// Checkpoint `seq` came from a core without its read sets although they were asked for.
    /// Idempotent per checkpoint.
    pub fn note(r: *ReAsk, seq: u64) void {
        var top = r.pool.highest_seen.load(.monotonic);
        for (r.pool.hints) |*h| top = @max(top, h.load(.monotonic));
        if (seq + r.cfg.near < top) return r.giveUp(.window);
        const core = r.pool.servedBy(seq);
        const t = r.now();
        r.lock();
        defer r.mu.unlock();
        for (r.items.items) |it| if (it.seq == seq) return;
        for (r.staged.items) |it| if (it.seq == seq) return;
        if (r.items.items.len >= r.cfg.max_items or r.cfg.schedule.len == 0) return r.giveUp(.@"error");
        r.items.append(r.gpa, .{ .seq = seq, .noted_ns = t, .due_ns = r.dueOf(t, 1), .attempt = 1, .core = core }) catch r.giveUp(.@"error");
    }

    pub fn pending(r: *ReAsk) usize {
        r.lock();
        defer r.mu.unlock();
        return r.items.items.len + r.staged.items.len;
    }

    /// Checkpoint `seq` has a re-ask to come or lists waiting for the next commit group: its
    /// mark may come within moments (the forwarder's hold, edge/forward.zig).
    pub fn isPending(r: *ReAsk, seq: u64) bool {
        r.lock();
        defer r.mu.unlock();
        for (r.items.items) |it| if (it.seq == seq) return true;
        for (r.staged.items) |it| if (it.seq == seq) return true;
        return false;
    }

    /// `edge.forward.ReadSetHold` over this re-ask.
    pub fn holdHook(r: *ReAsk) edge.forward.ReadSetHold {
        return .{ .ctx = r, .pending = holdPending };
    }

    fn holdPending(ctx: *anyopaque, seq: u64) bool {
        const r: *ReAsk = @ptrCast(@alignCast(ctx));
        return r.isPending(seq);
    }

    pub fn start(r: *ReAsk) !void {
        r.hist.late_hook = .{ .ctx = r, .done = lateDone };
        r.thread = try std.Thread.spawn(.{}, run, .{r});
    }

    pub fn requestStop(r: *ReAsk) void {
        r.stop_flag.store(true, .release);
    }

    pub fn stop(r: *ReAsk) void {
        r.requestStop();
        if (r.thread) |t| t.join();
        r.thread = null;
    }

    pub fn deinit(r: *ReAsk) void {
        r.stop();
        if (r.hist.late_hook) |hk| if (hk.ctx == @as(*anyopaque, r)) {
            r.hist.late_hook = null;
        };
        r.items.deinit(r.gpa);
        r.staged.deinit(r.gpa);
    }

    fn run(r: *ReAsk) void {
        while (!r.stop_flag.load(.acquire)) {
            if (!r.step()) r.io.sleep(.fromMilliseconds(10), .awake) catch return;
        }
    }

    /// Takes the earliest item that is due and asks for it. False: none was due.
    pub fn step(r: *ReAsk) bool {
        const t = r.now();
        r.flushLog(t);
        const item = blk: {
            r.lock();
            defer r.mu.unlock();
            var best: ?usize = null;
            for (r.items.items, 0..) |it, i| if (it.due_ns <= t and (best == null or it.due_ns < r.items.items[best.?].due_ns)) {
                best = i;
            };
            const i = best orelse return false;
            break :blk r.items.swapRemove(i);
        };
        r.ask(item, t);
        return true;
    }

    /// The same attempt again at `due`, unless the item's time is over: then given up for
    /// `it.last`.
    fn later(r: *ReAsk, it: Item, due: u64) void {
        if (due -| it.noted_ns > r.cfg.give_up_ms * std.time.ns_per_ms) return r.giveUp(it.last);
        r.lock();
        defer r.mu.unlock();
        var x = it;
        x.due_ns = due;
        r.items.append(r.gpa, x) catch r.giveUp(.@"error");
    }

    /// History's late hook (follower thread): the plan of `seq` went into a commit group with
    /// its mark (`marked`), or was dropped unmarked.
    fn lateDone(ctx: *anyopaque, seq: u64, marked: bool) void {
        const r: *ReAsk = @ptrCast(@alignCast(ctx));
        const attempt: u8 = blk: {
            r.lock();
            defer r.mu.unlock();
            for (r.staged.items, 0..) |it, i| if (it.seq == seq) {
                _ = r.staged.swapRemove(i);
                break :blk it.attempt;
            };
            break :blk 0;
        };
        if (attempt == 0) return; // not ours (or noted twice)
        if (marked) r.settled(attempt) else r.giveUp(.dropped);
    }

    fn settled(r: *ReAsk, attempt: u8) void {
        _ = r.pool.stats.read_sets_settled[@min(attempt, edge.client.read_sets_attempts) - 1].fetchAdd(1, .monotonic);
    }

    fn committed(r: *ReAsk) ?u64 {
        var snap = r.st.snapshot();
        defer snap.release();
        return snap.highestCommitted();
    }

    fn ask(r: *ReAsk, it_in: Item, t: u64) void {
        var it = it_in;
        // Not committed here yet: lists that came now could not be checked (`planLate` would
        // say `not_yet`, and the feed was spent). Looked at again in 20 ms.
        const c = r.committed();
        if (c == null or c.? < it.seq) {
            it.last = .@"error";
            return r.later(it, t + 20 * std.time.ns_per_ms);
        }
        var arena = std.heap.ArenaAllocator.init(r.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const other_ok = it.busy_since != 0 and t -| it.busy_since >= r.cfg.other_core_after_ms * std.time.ns_per_ms;
        const ans = r.pool.fetchReadSets(a, it.seq, it.core, other_ok, t + 2 * std.time.ns_per_s) catch |e| switch (e) {
            error.Closed => return, // stopping
            else => edge.client.Pool.ReadSetsAnswer.failed,
        };
        if (ans != .busy) it.busy_since = 0;
        switch (ans) {
            // nothing was asked, or the call failed: the same ask a moment later
            .busy => {
                if (it.busy_since == 0) it.busy_since = t;
                it.last = .no_conn;
                r.later(it, t + 20 * std.time.ns_per_ms);
            },
            .failed => {
                it.last = .@"error";
                r.later(it, t + 100 * std.time.ns_per_ms);
            },
            .none => |n| {
                it.last = if (n.other_core) .other_core else .unsettled;
                if (it.attempt >= r.cfg.schedule.len) return r.gaveUpNone(it);
                it.attempt += 1;
                r.later(it, @max(r.dueOf(it.noted_ns, it.attempt), t + 20 * std.time.ns_per_ms));
            },
            .held => |h| {
                var aux: std.ArrayList(u8) = .empty;
                defer aux.deinit(r.gpa);
                convert.auxOfLists(&aux, r.gpa, h.lists) catch return r.giveUp(.@"error");
                // staged first, so the follower's hook finds it whenever the group takes it
                r.lock();
                const room = if (r.staged.append(r.gpa, .{ .seq = it.seq, .attempt = it.attempt })) true else |_| false;
                r.mu.unlock();
                if (!room) return r.giveUp(.@"error");
                const out = r.hist.planLate(r.gpa, r.st, it.seq, h.contents, aux.items) catch |e| {
                    r.unstage(it.seq);
                    std.log.warn("edge read sets: checkpoint {d}: the late lists: {s}", .{ it.seq, @errorName(e) });
                    return r.giveUp(.@"error");
                };
                _ = r.outcomes[@intFromEnum(out)].fetchAdd(1, .monotonic);
                switch (out) {
                    // counted when the commit group takes them (`lateDone`)
                    .staged => {},
                    .already => {
                        r.unstage(it.seq);
                        r.settled(it.attempt);
                    },
                    .not_yet => {
                        r.unstage(it.seq);
                        r.later(it, t + 50 * std.time.ns_per_ms);
                    },
                    // the lists fail a check against the stored checkpoint: it stays forwarded
                    .mismatch, .rejected, .incomplete, .gone => {
                        r.unstage(it.seq);
                        std.log.debug("edge read sets: checkpoint {d}: late lists {s}", .{ it.seq, @tagName(out) });
                        r.giveUp(.dropped);
                    },
                }
            },
        }
    }

    fn unstage(r: *ReAsk, seq: u64) void {
        r.lock();
        defer r.mu.unlock();
        for (r.staged.items, 0..) |it, i| if (it.seq == seq) {
            _ = r.staged.swapRemove(i);
            return;
        };
    }

    fn gaveUpNone(r: *ReAsk, it: Item) void {
        r.giveUp(it.last);
        if (it.last != .unsettled) return;
        if (r.unsettled_n < r.unsettled_log.len) {
            r.unsettled_log[r.unsettled_n] = it.seq;
            r.unsettled_n += 1;
        } else r.unsettled_more += 1;
        r.flushLog(r.now());
    }

    /// At most once a minute: up to 3 checkpoints given up with the serving core saying "none"
    /// at every attempt, for its owner to look up (`readSetHeld` there).
    fn flushLog(r: *ReAsk, t: u64) void {
        if (r.unsettled_n == 0) return;
        if (r.last_log_ns != 0 and t -| r.last_log_ns < 60 * std.time.ns_per_s) return;
        r.last_log_ns = t;
        const s = r.unsettled_log[0..r.unsettled_n];
        var buf: [96]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        for (s, 0..) |seq, i| w.print("{s}{d}", .{ if (i == 0) "" else ", ", seq }) catch break;
        std.log.warn("edge read sets: gave up on checkpoint(s) {s} (and {d} more since the last line): the core that served each said none at all {d} re-asks, the last {d} ms after the feed", .{ w.buffered(), r.unsettled_more, r.cfg.schedule.len, r.cfg.schedule[r.cfg.schedule.len - 1] });
        r.unsettled_n = 0;
        r.unsettled_more = 0;
    }
};
