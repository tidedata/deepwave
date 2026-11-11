//! Shares of one bounded work queue between clients: the zui/1 listener's edge feed queue
//! (jobs.zig, docs/EDGE.md section 4).
//!
//! The queue holds at most `cap` entries, queued and running together, for every client at once.
//! First come, first served lets one client that pipelines (an edge catching up keeps up to 16
//! feed requests in flight) fill it, and everyone else is refused or waits behind its backlog.
//! Here every client with work in flight has a share: `cap` divided by the number of such
//! clients, never under `min_share`.
//!
//!   - Below `cap` nothing is refused: a client takes what the others leave unused.
//!   - At `cap` a client at or over its share is refused. A client under its share is let in,
//!     and the newest queued entry of the client furthest over its own share gives its place up
//!     (the caller answers that entry as refused). When all that client holds above its share
//!     is already running, nothing can be taken back, and the newcomer is let in above `cap`:
//!     by less than `workers` entries, until those jobs end.
//!   - A free worker takes the oldest entry of the client with the fewest entries running, and
//!     among equals of the one served longest ago. A client waits for one job to end, not for
//!     the backlog queued before it.
//!
//! With one client this is the plain queue: its share is `cap`, it is refused at `cap`, and its
//! entries run in the order they came.
//!
//! A client under its share is never refused while another is over its own, as long as the
//! shares fit the queue (clients x `min_share` <= `cap`). Past that the queue is simply full.
//!
//! Pure state and arithmetic: the caller holds its own lock around every call.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

/// Who an entry is accounted to (listener.zig `feedClient`).
pub const Key = u128;

/// Why a push was refused, or a queued entry answered as refused: its client holds more than
/// its share of a full queue, or the queue is full and nobody holds more than a share.
pub const Reason = enum { over_share, full };

/// What a queue looks like now and what it has refused, for the metrics endpoint (`publish`).
pub const Stats = struct {
    /// Entries queued or running (what `cap` bounds).
    depth: Atomic(u64) = .init(0),
    /// Clients with an entry queued or running (the divisor of the share).
    clients: Atomic(u64) = .init(0),
    /// Clients with an entry waiting for a worker.
    clients_waiting: Atomic(u64) = .init(0),
    /// The most entries one client has queued or running.
    client_depth_max: Atomic(u64) = .init(0),
    refused_over_share: Atomic(u64) = .init(0),
    refused_full: Atomic(u64) = .init(0),

    /// Prometheus text: `<prefix>_queue_*` gauges and `<prefix>_refused{reason}` counters.
    pub fn render(s: *const Stats, w: *std.Io.Writer, comptime prefix: []const u8) !void {
        inline for (.{ "depth", "clients", "clients_waiting", "client_depth_max" }) |name| {
            try w.print("# TYPE " ++ prefix ++ "_queue_" ++ name ++ " gauge\n" ++ prefix ++ "_queue_" ++ name ++ " {d}\n", .{@field(s, name).load(.monotonic)});
        }
        try w.writeAll("# TYPE " ++ prefix ++ "_refused counter\n");
        try w.print(prefix ++ "_refused{{reason=\"over_share\"}} {d}\n", .{s.refused_over_share.load(.monotonic)});
        try w.print(prefix ++ "_refused{{reason=\"full\"}} {d}\n", .{s.refused_full.load(.monotonic)});
    }
};

pub fn Queue(comptime T: type) type {
    return struct {
        const Q = @This();

        /// Entries, queued plus running, at which a push is refused or takes another's place.
        cap: usize,
        /// Threads that run entries: what the queue may hold above `cap` stays under this.
        workers: usize,
        /// The least a share is, however many clients there are.
        min_share: usize = 2,
        /// Queued entries, oldest first.
        entries: std.ArrayList(Entry) = .empty,
        /// Every client with an entry queued or running.
        clients: std.ArrayList(Client) = .empty,
        /// Queued plus running.
        inflight: usize = 0,
        /// The clock of `Client.served`.
        turn: u64 = 0,
        refused_over_share: u64 = 0,
        refused_full: u64 = 0,

        pub const Entry = struct { client: Key, item: T };

        pub const Client = struct {
            key: Key,
            queued: u32 = 0,
            running: u32 = 0,
            /// `turn` when it last got a worker, or when it came: the tie-break of `pop`.
            served: u64,

            pub fn depth(c: Client) usize {
                return @as(usize, c.queued) + c.running;
            }
        };

        pub const Push = union(enum) {
            queued,
            /// Queued, in the place of this queued entry of a client over its share: the caller
            /// answers it as refused.
            evicted: T,
            refused: Reason,
        };

        /// Frees the queue's own memory; the queued items are the caller's.
        pub fn deinit(q: *Q, gpa: Allocator) void {
            q.entries.deinit(gpa);
            q.clients.deinit(gpa);
        }

        fn find(q: *const Q, key: Key) ?usize {
            for (q.clients.items, 0..) |c, i| if (c.key == key) return i;
            return null;
        }

        /// The share of each of `n` clients with work in flight.
        pub fn share(q: *const Q, n: usize) usize {
            return @max(@max(q.min_share, 1), q.cap / @max(n, 1));
        }

        fn refuse(q: *Q, why: Reason) Push {
            switch (why) {
                .over_share => q.refused_over_share += 1,
                .full => q.refused_full += 1,
            }
            return .{ .refused = why };
        }

        /// Queues `item` for client `key`, or says why not.
        pub fn push(q: *Q, gpa: Allocator, key: Key, item: T) Push {
            const ci = q.find(key);
            const mine: usize = if (ci) |i| q.clients.items[i].depth() else 0;
            // room for the entry and its client before anything changes
            q.entries.ensureUnusedCapacity(gpa, 1) catch return q.refuse(.full);
            q.clients.ensureUnusedCapacity(gpa, 1) catch return q.refuse(.full);
            var evicted: ?T = null;
            if (q.inflight >= q.cap) {
                const sh = q.share(q.clients.items.len + @intFromBool(ci == null));
                if (mine >= sh) return q.refuse(if (mine > sh) .over_share else .full);
                var over = false; // someone else holds more than a share
                var victim: ?usize = null; // the one furthest over that still has an entry queued
                for (q.clients.items, 0..) |c, i| {
                    if (c.key == key or c.depth() <= sh) continue;
                    over = true;
                    if (c.queued > 0 and (victim == null or c.depth() > q.clients.items[victim.?].depth())) victim = i;
                }
                if (victim) |vi| {
                    evicted = q.takeNewest(vi);
                } else if (!over or q.inflight >= q.cap + q.workers) return q.refuse(.full);
            }
            const c = if (ci) |i| &q.clients.items[i] else blk: {
                q.turn += 1;
                q.clients.appendAssumeCapacity(.{ .key = key, .served = q.turn });
                break :blk &q.clients.items[q.clients.items.len - 1];
            };
            c.queued += 1;
            q.inflight += 1;
            q.entries.appendAssumeCapacity(.{ .client = key, .item = item });
            return if (evicted) |v| .{ .evicted = v } else .queued;
        }

        /// The newest queued entry of client `vi`, which holds more than its share (so it keeps
        /// at least one entry and stays in `clients`).
        fn takeNewest(q: *Q, vi: usize) T {
            const c = &q.clients.items[vi];
            var i = q.entries.items.len - 1;
            while (q.entries.items[i].client != c.key) i -= 1;
            c.queued -= 1;
            q.inflight -= 1;
            q.refused_over_share += 1;
            return q.entries.orderedRemove(i).item;
        }

        /// The next entry for a free worker, or null. It counts as running until `finish`.
        pub fn pop(q: *Q) ?Entry {
            if (q.entries.items.len == 0) return null;
            var best: usize = 0;
            var at: usize = 0;
            if (q.clients.items.len > 1) {
                var b: ?usize = null;
                for (q.clients.items, 0..) |c, i| {
                    if (c.queued == 0) continue;
                    if (b) |x| {
                        const o = q.clients.items[x];
                        if (c.running > o.running or (c.running == o.running and c.served > o.served)) continue;
                    }
                    b = i;
                }
                best = b.?;
                const k = q.clients.items[best].key;
                while (q.entries.items[at].client != k) at += 1;
            }
            const c = &q.clients.items[best];
            c.queued -= 1;
            c.running += 1;
            q.turn += 1;
            c.served = q.turn;
            return q.entries.orderedRemove(at);
        }

        /// A popped entry of client `key` is done.
        pub fn finish(q: *Q, key: Key) void {
            const i = q.find(key) orelse return;
            const c = &q.clients.items[i];
            c.running -= 1;
            q.inflight -= 1;
            if (c.depth() == 0) _ = q.clients.swapRemove(i);
        }

        /// Takes queued entry `i` out and gives its place back (its connection is gone).
        pub fn remove(q: *Q, i: usize) T {
            const e = q.entries.orderedRemove(i);
            const ci = q.find(e.client).?;
            const c = &q.clients.items[ci];
            c.queued -= 1;
            q.inflight -= 1;
            if (c.depth() == 0) _ = q.clients.swapRemove(ci);
            return e.item;
        }

        /// Copies the gauges and the refusal counts to `s`.
        pub fn publish(q: *const Q, s: *Stats) void {
            var waiting: u64 = 0;
            var deepest: u64 = 0;
            for (q.clients.items) |c| {
                if (c.queued > 0) waiting += 1;
                deepest = @max(deepest, c.depth());
            }
            s.depth.store(q.inflight, .monotonic);
            s.clients.store(q.clients.items.len, .monotonic);
            s.clients_waiting.store(waiting, .monotonic);
            s.client_depth_max.store(deepest, .monotonic);
            s.refused_over_share.store(q.refused_over_share, .monotonic);
            s.refused_full.store(q.refused_full, .monotonic);
        }
    };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn nowNs() u64 {
    return @intCast(std.Io.Clock.awake.now(testing.io).toNanoseconds());
}

/// A queue and its worker threads in virtual time: a test says which worker ends its job, and a
/// free worker takes the next entry at once. Items are numbers the test gives out.
const Sim = struct {
    const Q = Queue(u32);
    q: Q,
    run: [16]?Q.Entry = @splat(null),
    /// When each worker took its job (a count of jobs started).
    since: [16]u64 = @splat(0),
    /// Every item in the order the workers took them.
    order: std.ArrayList(Q.Entry) = .empty,
    /// Items answered as refused after they were queued.
    evicted: std.ArrayList(u32) = .empty,

    fn init(cap: usize, workers: usize) Sim {
        return .{ .q = .{ .cap = cap, .workers = workers } };
    }

    fn deinit(s: *Sim) void {
        s.q.deinit(testing.allocator);
        s.order.deinit(testing.allocator);
        s.evicted.deinit(testing.allocator);
    }

    fn fill(s: *Sim) !void {
        for (s.run[0..s.q.workers], 0..) |*w, i| {
            if (w.* != null) continue;
            w.* = s.q.pop() orelse return;
            try s.order.append(testing.allocator, w.*.?);
            s.since[i] = s.order.items.len;
        }
    }

    /// The worker whose job started first: the next to end when every job takes the same time.
    fn oldest(s: *const Sim) usize {
        var best: ?usize = null;
        for (s.run[0..s.q.workers], 0..) |w, i| {
            if (w != null and (best == null or s.since[i] < s.since[best.?])) best = i;
        }
        return best.?;
    }

    /// True when the item was queued.
    fn push(s: *Sim, key: Key, item: u32) !bool {
        switch (s.q.push(testing.allocator, key, item)) {
            .refused => return false,
            .queued => {},
            .evicted => |v| try s.evicted.append(testing.allocator, v),
        }
        try s.fill();
        return true;
    }

    /// Worker `w` ends its job; returns whose it was.
    fn end(s: *Sim, w: usize) !Key {
        const e = s.run[w].?;
        s.run[w] = null;
        s.q.finish(e.client);
        try s.fill();
        return e.client;
    }

    fn depth(s: *const Sim, key: Key) usize {
        return if (s.q.find(key)) |i| s.q.clients.items[i].depth() else 0;
    }

    /// The accounting adds up.
    fn check(s: *const Sim) !void {
        var queued: usize = 0;
        var running: usize = 0;
        for (s.q.clients.items) |c| {
            try testing.expect(c.depth() > 0);
            queued += c.queued;
            running += c.running;
        }
        var busy: usize = 0;
        for (s.run) |w| busy += @intFromBool(w != null);
        try testing.expectEqual(s.q.entries.items.len, queued);
        try testing.expectEqual(busy, running);
        try testing.expectEqual(s.q.inflight, queued + running);
        try testing.expect(s.q.inflight < s.q.cap + @max(s.q.workers, 1));
    }
};

test "feed shares: one client with 64 queued, a second with one: served when the first job ends, never refused" {
    var s = Sim.init(64, 4);
    defer s.deinit();
    const greedy: Key = 1;
    const tip: Key = 2;
    for (0..64) |i| try testing.expect(try s.push(greedy, @intCast(i)));
    // alone, the first client is refused where the plain queue refused it: at 64
    try testing.expect(!try s.push(greedy, 64));
    try testing.expectEqual(@as(u64, 1), s.q.refused_full);
    try testing.expectEqual(@as(usize, 4), s.order.items.len);
    // the second client is let in; the first one's newest queued request is the one refused
    try testing.expect(try s.push(tip, 1000));
    try testing.expectEqualSlices(u32, &.{63}, s.evicted.items);
    try testing.expectEqual(@as(u64, 1), s.q.refused_over_share);
    try testing.expectEqual(@as(usize, 64), s.q.inflight);
    try s.check();
    // one job ends: the worker takes the second client's request, not the 59 queued before it
    try testing.expectEqual(greedy, try s.end(2));
    try testing.expectEqual(@as(u32, 1000), s.order.items[4].item);
    // and again, each time it comes back, while the first client keeps pushing
    for (0..40) |i| {
        _ = try s.push(greedy, 2000 + @as(u32, @intCast(i)));
        const before = s.order.items.len;
        try testing.expect(try s.push(tip, 3000 + @as(u32, @intCast(i))));
        // its last request is running or done, so this one is the only one it has queued
        var w: usize = 0;
        while (s.run[w].?.client != greedy) w += 1;
        _ = try s.end(w);
        try testing.expectEqual(tip, s.order.items[before].client);
        // its request ends too, before the next round
        w = 0;
        while (s.run[w].?.client != tip) w += 1;
        _ = try s.end(w);
        try s.check();
    }
    // the first client's own requests still run in the order they came
    var last: ?u32 = null;
    for (s.order.items) |e| if (e.client == greedy) {
        if (last) |l| try testing.expect(e.item > l);
        last = e.item;
    };
}

test "feed shares: three clients under contention converge to equal depth and equal service" {
    var s = Sim.init(64, 4);
    defer s.deinit();
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    var next: u32 = 0;
    // the first has the whole queue before the others come
    for (0..64) |_| {
        try testing.expect(try s.push(1, next));
        next += 1;
    }
    var served: [4]u32 = @splat(0);
    var refused: [4]u32 = @splat(0);
    for (0..1200) |round| {
        if (round == 600) served = @splat(0);
        // every client asks for more than it gets, in a different order each round
        const first = rnd.uintLessThan(u8, 3);
        for (0..3) |k| {
            const key: Key = 1 + (first + k) % 3;
            for (0..2) |_| {
                const under = s.depth(key) < s.q.share(3);
                const ok = try s.push(key, next);
                next += 1;
                if (!ok) refused[@intCast(key)] += 1;
                // under its share a client is never refused
                if (round > 0) try testing.expect(ok or !under);
            }
        }
        try s.check();
        // every job takes the same time
        const key = try s.end(s.oldest());
        served[@intCast(key)] += 1;
    }
    // a third of the queue each (64 / 3 = 21, one of them holds the odd entry)
    for (1..4) |k| {
        const d = s.depth(@intCast(k));
        try testing.expect(d >= 20 and d <= 22);
    }
    // and a third of the service each over the last 600 jobs
    for (1..4) |k| try testing.expect(served[k] >= 199 and served[k] <= 201);
    // what was refused was refused to all three
    for (1..4) |k| try testing.expect(refused[k] > 0);
}

test "feed shares: a client that leaves gives its queued entries back" {
    var s = Sim.init(64, 4);
    defer s.deinit();
    for (0..40) |i| try testing.expect(try s.push(1, @intCast(i)));
    for (0..24) |i| try testing.expect(try s.push(2, 100 + @as(u32, @intCast(i))));
    try testing.expect(!try s.push(1, 998));
    // client 1 disconnects: its 36 queued entries leave, its 4 running jobs end on their own
    var i = s.q.entries.items.len;
    var gone: usize = 0;
    while (i > 0) {
        i -= 1;
        if (s.q.entries.items[i].client == 1) {
            _ = s.q.remove(i);
            gone += 1;
        }
    }
    try testing.expectEqual(@as(usize, 36), gone);
    try testing.expectEqual(@as(usize, 28), s.q.inflight);
    try s.check();
    // the room is there for the other client at once
    try testing.expect(try s.push(2, 999));
    for (0..4) |w| _ = try s.end(w);
    try testing.expectEqual(@as(usize, 1), s.q.clients.items.len);
    try testing.expectEqual(@as(usize, 0), s.depth(1));
    while (s.q.inflight > 0) for (0..4) |w| {
        if (s.run[w] != null) _ = try s.end(w);
    };
    try testing.expectEqual(@as(usize, 0), s.q.clients.items.len);
    try testing.expectEqual(@as(usize, 0), s.q.entries.items.len);
    // a client whose only entries were queued is forgotten when they leave
    s.run = @splat(null);
    s.q.workers = 0;
    try testing.expect(try s.push(3, 1));
    try testing.expect(try s.push(3, 2));
    _ = s.q.remove(1);
    _ = s.q.remove(0);
    try testing.expectEqual(@as(usize, 0), s.q.clients.items.len);
    try testing.expectEqual(@as(usize, 0), s.q.inflight);
}

test "feed shares: one client gets the plain queue: refused at the limit, served in order" {
    var prng = std.Random.DefaultPrng.init(11);
    const rnd = prng.random();
    for ([_]usize{ 64, 5, 1 }) |cap| {
        var s = Sim.init(cap, 4);
        defer s.deinit();
        // the queue before shares: a list, a count of queued plus running, refusal at `cap`
        var plain: std.ArrayList(u32) = .empty;
        defer plain.deinit(testing.allocator);
        var plain_inflight: usize = 0;
        var plain_running: usize = 0;
        var plain_order: std.ArrayList(u32) = .empty;
        defer plain_order.deinit(testing.allocator);
        var next: u32 = 0;
        for (0..4000) |_| {
            if (rnd.uintLessThan(u8, 5) < 3) {
                const want = plain_inflight < cap;
                if (want) {
                    try plain.append(testing.allocator, next);
                    plain_inflight += 1;
                }
                try testing.expectEqual(want, try s.push(9, next));
                next += 1;
            } else {
                const w = rnd.uintLessThan(usize, 4);
                if (s.run[w] != null) {
                    _ = try s.end(w);
                    plain_inflight -= 1;
                    plain_running -= 1;
                }
            }
            while (plain_running < 4 and plain.items.len > 0) {
                try plain_order.append(testing.allocator, plain.orderedRemove(0));
                plain_running += 1;
            }
            try testing.expectEqual(plain_inflight, s.q.inflight);
            try s.check();
        }
        try testing.expect(s.q.refused_full > 0);
        try testing.expectEqual(@as(u64, 0), s.q.refused_over_share);
        try testing.expectEqual(@as(usize, 0), s.evicted.items.len);
        try testing.expectEqual(plain_order.items.len, s.order.items.len);
        for (plain_order.items, s.order.items) |a, b| try testing.expectEqual(a, b.item);
    }
}

test "feed shares: no client under its share is refused while another is over its own" {
    var prng = std.Random.DefaultPrng.init(23);
    const rnd = prng.random();
    // (queue, workers, clients): the shares fit the queue in each (clients x 2 <= queue)
    for ([_][3]usize{ .{ 64, 4, 2 }, .{ 64, 4, 9 }, .{ 64, 4, 32 }, .{ 16, 8, 5 }, .{ 8, 8, 4 }, .{ 12, 16, 3 } }) |cfg| {
        var s = Sim.init(cfg[0], cfg[1]);
        defer s.deinit();
        const nclients = cfg[2];
        var next: u32 = 0;
        var let_in_full: usize = 0;
        var owner: std.ArrayList(Key) = .empty; // of each item
        defer owner.deinit(testing.allocator);
        for (0..6000) |step| {
            // some clients push far more often than others
            const pick = rnd.uintLessThan(usize, nclients * 3);
            const key: Key = 1 + (if (pick < nclients) pick else pick % @max(1, nclients / 3));
            if (rnd.uintLessThan(u8, 8) < 5 or step < cfg[0]) {
                const n = s.q.clients.items.len + @intFromBool(s.q.find(key) == null);
                const sh = s.q.share(n);
                const mine = s.depth(key);
                const full = s.q.inflight >= s.q.cap;
                var over = false;
                var most: usize = 0;
                for (s.q.clients.items) |c| if (c.key != key and c.depth() > sh) {
                    over = true;
                    if (c.queued > 0) most = @max(most, c.depth());
                };
                const evicted_before = s.evicted.items.len;
                try owner.append(testing.allocator, key);
                const ok = try s.push(key, next);
                next += 1;
                if (!full) try testing.expect(ok);
                if (full and mine >= sh) try testing.expect(!ok);
                if (full and mine < sh and over) {
                    try testing.expect(ok);
                    let_in_full += 1;
                }
                // a place is only ever taken from the client furthest over its share
                if (s.evicted.items.len > evicted_before) {
                    try testing.expect(full and mine < sh and most > sh);
                    try testing.expectEqual(most - 1, s.depth(owner.items[s.evicted.items[evicted_before]]));
                }
            } else {
                const w = rnd.uintLessThan(usize, cfg[1]);
                if (s.run[w] != null) _ = try s.end(w);
            }
            try s.check();
        }
        try testing.expect(let_in_full > 0);
    }
}

test "feed shares: the metrics text" {
    var q: Queue(u32) = .{ .cap = 4, .workers = 1 };
    defer q.deinit(testing.allocator);
    for (0..4) |i| try testing.expect(q.push(testing.allocator, 1, @intCast(i)) == .queued);
    _ = q.pop().?;
    try testing.expect(q.push(testing.allocator, 1, 4) == .refused);
    try testing.expect(q.push(testing.allocator, 2, 5) == .evicted);
    var s: Stats = .{};
    q.publish(&s);
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try s.render(&w, "zui_native_feed");
    try testing.expectEqualStrings(
        \\# TYPE zui_native_feed_queue_depth gauge
        \\zui_native_feed_queue_depth 4
        \\# TYPE zui_native_feed_queue_clients gauge
        \\zui_native_feed_queue_clients 2
        \\# TYPE zui_native_feed_queue_clients_waiting gauge
        \\zui_native_feed_queue_clients_waiting 2
        \\# TYPE zui_native_feed_queue_client_depth_max gauge
        \\zui_native_feed_queue_client_depth_max 3
        \\# TYPE zui_native_feed_refused counter
        \\zui_native_feed_refused{reason="over_share"} 1
        \\zui_native_feed_refused{reason="full"} 1
        \\
    , w.buffered());
}

test "feed shares: at the tip (one request per client, workers free) the queue adds nanoseconds" {
    const gpa = testing.allocator;
    const rounds = 20_000;
    const nclients = 16;
    var q: Queue(u32) = .{ .cap = 64, .workers = 4 };
    defer q.deinit(gpa);
    var stats: Stats = .{};
    var plain: std.ArrayList(u32) = .empty;
    defer plain.deinit(gpa);
    var sink: u64 = 0;
    // 15 other clients have a request running; this one's comes, runs and ends
    for (1..nclients) |k| {
        try testing.expect(q.push(gpa, k, 0) == .queued);
        _ = q.pop().?;
    }
    const t0 = nowNs();
    for (0..rounds) |i| {
        try plain.append(gpa, @intCast(i));
        sink += plain.orderedRemove(0);
    }
    const t1 = nowNs();
    for (0..rounds) |i| {
        const key: Key = 100 + i % 7;
        if (q.push(gpa, key, @intCast(i)) != .queued) return error.TestUnexpectedResult;
        q.publish(&stats);
        sink += q.pop().?.item;
        q.publish(&stats);
        q.finish(key);
        q.publish(&stats);
    }
    const per = (nowNs() - t1) / rounds;
    const plain_ns = t1 - t0;
    try testing.expectEqual(@as(usize, nclients - 1), q.inflight);
    if (std.c.getenv("ZUI_FEED_BENCH") != null)
        std.debug.print("feed shares, tip path, {d} clients in flight: push + pop + finish + gauges {d} ns a request; plain list {d} ns ({d})\n", .{ nclients, per, plain_ns / rounds, sink & 1 });
    // a feed is assembled in hundreds of microseconds: this must stay far under one
    try testing.expect(per < 20_000);
}
