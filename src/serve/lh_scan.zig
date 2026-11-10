//! Filtered ledger-history scans: sui-inverted-index `eval_bitmap_query_bucket_iter` (iter.rs,
//! the synchronous DNF evaluator with its shared bucket budget, first-bucket reservation,
//! leapfrog targets and drain-probe seeks) and sui-rpc-api `bitmap_scan.rs`
//! (`drain_bitmap_hits_with_budget`, `PendingBitmapBucket`). Bucket rows are charged exactly as
//! the Rust evaluator charges them, so SCAN_LIMIT frontiers land on the same positions.
const std = @import("std");
const Allocator = std.mem.Allocator;
const history = @import("history");

pub const Bucket = history.Bucket;
pub const tx_bucket_size: u64 = 65_536;
pub const event_bucket_size: u64 = 1 << 28;
const drain_probe_rows: u64 = 2;

/// One DNF term over deduplicated leaf indexes.
pub const Term = struct {
    includes: []const usize,
    excludes: []const usize,
    unsatisfiable: bool = false,
};

/// A parsed filter: unique dimension keys plus terms that reference them (`build_term_specs`).
pub const Query = struct {
    keys: []const []const u8,
    terms: []Term,
};

pub const Source = struct {
    ctx: *const anyopaque,
    buckets: *const fn (ctx: *const anyopaque, key: []const u8) []const Bucket,
    /// The dense tx universe (`TxUniverse`, tag 9): synthesized full buckets.
    universe_ok: bool,
};

const Budget = struct {
    initial: u64,
    remaining: u64,
    fn tryTake(b: *Budget) bool {
        if (b.remaining == 0) return false;
        b.remaining -= 1;
        return true;
    }
    fn takeFirst(b: *Budget) void {
        b.remaining -|= 1;
    }
    fn evaluated(b: *const Budget) u64 {
        return b.initial -| b.remaining;
    }
};

const LeafItem = union(enum) { bucket: Bucket, exhausted };

/// A stored-bucket iterator over [start_bucket, end_bucket) in one direction, with seek.
const BucketIter = struct {
    list: []const Bucket,
    universe: ?[]const u32,
    lo_b: u64,
    hi_b: u64, // exclusive
    asc: bool,
    // stored: index of the next candidate (asc) or one past it (desc)
    idx: usize,
    // universe: next bucket id (asc) or one past it (desc)
    next_u: u64,
    empty: bool,

    fn init(list: []const Bucket, universe: ?[]const u32, range: [2]u64, bs: u64, asc: bool) BucketIter {
        if (range[0] >= range[1]) return .{ .list = list, .universe = universe, .lo_b = 0, .hi_b = 0, .asc = asc, .idx = 0, .next_u = 0, .empty = true };
        const lo_b = range[0] / bs;
        const hi_b = (range[1] - 1) / bs + 1;
        var it = BucketIter{ .list = list, .universe = universe, .lo_b = lo_b, .hi_b = hi_b, .asc = asc, .idx = 0, .next_u = 0, .empty = false };
        it.seek(if (asc) lo_b else hi_b - 1);
        return it;
    }
    fn lowerBound(list: []const Bucket, id: u64) usize {
        var lo: usize = 0;
        var hi: usize = list.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (list[mid].id < id) lo = mid + 1 else hi = mid;
        }
        return lo;
    }
    /// Next bucket is the first at or past `bucket` in scan direction.
    fn seek(it: *BucketIter, bucket: u64) void {
        if (it.empty) return;
        if (it.universe != null) {
            it.next_u = if (it.asc) @max(bucket, it.lo_b) else @min(bucket, it.hi_b - 1) + 1;
            return;
        }
        if (it.asc) {
            it.idx = lowerBound(it.list, @max(bucket, it.lo_b));
        } else {
            const b = @min(bucket, it.hi_b - 1);
            it.idx = lowerBound(it.list, b +| 1); // one past the last id <= b
        }
    }
    fn next(it: *BucketIter) ?Bucket {
        if (it.empty) return null;
        if (it.universe) |u| {
            if (it.asc) {
                if (it.next_u >= it.hi_b) return null;
                defer it.next_u += 1;
                return .{ .id = it.next_u, .bits = u };
            }
            if (it.next_u <= it.lo_b) return null;
            it.next_u -= 1;
            return .{ .id = it.next_u, .bits = u };
        }
        if (it.asc) {
            if (it.idx >= it.list.len or it.list[it.idx].id >= it.hi_b) return null;
            defer it.idx += 1;
            return it.list[it.idx];
        }
        if (it.idx == 0 or it.list[it.idx - 1].id < it.lo_b) return null;
        it.idx -= 1;
        return it.list[it.idx];
    }
};

const Leaf = struct {
    iter: BucketIter,
    first_pending: bool = true,
    exhausted: bool = false,
    peeked: ??LeafItem = null,
    drained: u64 = 0,

    fn pull(l: *Leaf, budget: *Budget) ?LeafItem {
        if (l.exhausted) return null;
        const b = l.iter.next() orelse return null;
        if (l.first_pending) {
            budget.takeFirst();
            l.first_pending = false;
        } else if (!budget.tryTake()) {
            l.exhausted = true;
            return .exhausted;
        }
        return .{ .bucket = b };
    }
    fn peek(l: *Leaf, budget: *Budget) ?LeafItem {
        if (l.peeked == null) l.peeked = l.pull(budget);
        return l.peeked.?;
    }
    fn next(l: *Leaf, budget: *Budget) ?LeafItem {
        if (l.peeked) |p| {
            l.peeked = null;
            return p;
        }
        return l.pull(budget);
    }
    fn seekBucket(l: *Leaf, bucket: u64) void {
        l.peeked = null;
        l.iter.seek(bucket);
    }
};

const Head = union(enum) { bucket: u64, eof, err };

pub const Out = union(enum) {
    item: struct { bucket: u64, bits: []const u32 },
    scan_limit: u64,
};

fn boundIn(a: u64, b: u64, asc: bool) u64 {
    return if (asc) @min(a, b) else @max(a, b);
}
fn advanceIn(a: u64, b: u64, asc: bool) u64 {
    return if (asc) @max(a, b) else @min(a, b);
}
fn strictlyBefore(a: u64, b: u64, asc: bool) bool {
    return if (asc) a < b else a > b;
}
fn bucketEdges(bucket: u64, bs: u64, range: [2]u64, asc: bool) [2]u64 {
    const s = bucket *| bs;
    const e = s +| bs;
    return if (asc) .{ @max(s, range[0]), @min(e, range[1]) } else .{ @min(e, range[1]), @max(s, range[0]) };
}

/// `eval_bitmap_query_bucket_iter` (unpaced; the fullnode pacing never emits a watermark the
/// drain loop uses, so only items and the scan-limit stop come out).
pub const Evaluator = struct {
    arena: Allocator,
    leaves: []Leaf,
    terms: []Term,
    budget: Budget,
    range: [2]u64,
    bs: u64,
    asc: bool,
    unreferenced: []bool,
    front: []u64,
    done: bool = false,
    queue: [2]Out = undefined,
    q_len: usize = 0,
    q_at: usize = 0,

    pub fn init(arena: Allocator, src: Source, q: Query, range: [2]u64, bs: u64, asc: bool, budget: u64, universe: ?[]const u32) !Evaluator {
        const leaves = try arena.alloc(Leaf, q.keys.len);
        for (q.keys, leaves) |k, *l| {
            const is_universe = src.universe_ok and k.len > 0 and k[0] == 9;
            l.* = .{ .iter = BucketIter.init(if (is_universe) &.{} else src.buckets(src.ctx, k), if (is_universe) universe else null, range, bs, asc) };
        }
        const terms = try arena.dupe(Term, q.terms);
        const unref = try arena.alloc(bool, leaves.len);
        @memset(unref, false);
        const front = try arena.alloc(u64, leaves.len);
        @memset(front, if (asc) range[0] else range[1]);
        return .{ .arena = arena, .leaves = leaves, .terms = terms, .budget = .{ .initial = budget, .remaining = budget }, .range = range, .bs = bs, .asc = asc, .unreferenced = unref, .front = front };
    }

    pub fn evaluated(e: *const Evaluator) u64 {
        return e.budget.evaluated();
    }

    pub fn next(e: *Evaluator) !?Out {
        while (true) {
            if (e.q_at < e.q_len) {
                defer e.q_at += 1;
                return e.queue[e.q_at];
            }
            if (e.done) return null;
            e.q_len = 0;
            e.q_at = 0;
            try e.round();
        }
    }

    fn push(e: *Evaluator, o: Out) void {
        e.queue[e.q_len] = o;
        e.q_len += 1;
    }

    fn round(e: *Evaluator) !void {
        const n = e.leaves.len;
        const asc = e.asc;
        const terminus = if (asc) e.range[1] else e.range[0];
        const class = try e.arena.alloc(?Head, n);
        @memset(class, null);
        for (0..n) |i| {
            if (e.unreferenced[i]) continue;
            if (e.leaves[i].peek(&e.budget)) |it| switch (it) {
                .bucket => |b| {
                    const pre = bucketEdges(b.id, e.bs, e.range, asc)[0];
                    e.front[i] = advanceIn(e.front[i], pre, asc);
                    class[i] = .{ .bucket = b.id };
                },
                .exhausted => class[i] = .err,
            } else {
                e.front[i] = advanceIn(e.front[i], terminus, asc);
                class[i] = .eof;
            }
        }
        for (e.terms) |*t| {
            if (t.unsatisfiable) continue;
            for (t.includes) |i| if (class[i] != null and class[i].? == .eof) {
                t.unsatisfiable = true;
                break;
            };
        }
        // recompute_unreferenced
        {
            const referenced = try e.arena.alloc(bool, n);
            @memset(referenced, false);
            for (e.terms) |t| {
                if (t.unsatisfiable) continue;
                for ([_][]const usize{ t.includes, t.excludes }) |list| for (list) |i| {
                    if (!e.unreferenced[i] and !(class[i] != null and class[i].? == .eof)) referenced[i] = true;
                };
            }
            for (0..n) |i| if (!referenced[i]) {
                e.unreferenced[i] = true;
            };
        }
        const targets = try e.skipTargets(class);
        for (targets, 0..) |t, i| if (t) |tg| {
            const pre = bucketEdges(tg, e.bs, e.range, asc)[0];
            e.front[i] = advanceIn(e.front[i], pre, asc);
        };
        var had_error = false;
        for (0..n) |i| {
            if (!e.unreferenced[i] and class[i] != null and class[i].? == .err) {
                _ = e.leaves[i].next(&e.budget);
                had_error = true;
            }
        }
        var any_active = false;
        var floor_pos: u64 = 0;
        for (0..n) |i| if (!e.unreferenced[i]) {
            floor_pos = if (any_active) boundIn(floor_pos, e.front[i], asc) else e.front[i];
            any_active = true;
        };
        if (!any_active) {
            e.done = true;
            return;
        }
        if (had_error) {
            e.done = true;
            e.push(.{ .scan_limit = floor_pos });
            return;
        }
        for (0..n) |i| if (targets[i] == null) {
            e.leaves[i].drained = 0;
        };
        var eval_bucket: ?u64 = null;
        var lagging_target: ?u64 = null;
        for (0..n) |i| {
            if (e.unreferenced[i]) continue;
            if (targets[i]) |tg| {
                lagging_target = if (lagging_target) |lt| boundIn(lt, tg, asc) else tg;
                continue;
            }
            if (class[i]) |c| if (c == .bucket) {
                eval_bucket = if (eval_bucket) |eb| boundIn(eb, c.bucket, asc) else c.bucket;
            };
        }
        const eb = eval_bucket orelse return error.Internal; // Rust: expect("a least term candidate leaf is not lagging")
        const evaluate = if (lagging_target) |lt| strictlyBefore(eb, lt, asc) else true;
        if (evaluate) {
            const post = bucketEdges(eb, e.bs, e.range, asc)[1];
            const snapshot = try e.arena.alloc(?[]const u32, n);
            @memset(snapshot, null);
            for (0..n) |i| {
                if (!e.unreferenced[i] and targets[i] == null and class[i] != null and class[i].? == .bucket and class[i].?.bucket == eb) {
                    e.front[i] = advanceIn(e.front[i], post, asc);
                    if (e.leaves[i].next(&e.budget)) |it| switch (it) {
                        .bucket => |b| snapshot[i] = b.bits,
                        .exhausted => {},
                    };
                }
            }
            var result: ?[]const u32 = null;
            for (e.terms) |t| {
                if (t.unsatisfiable) continue;
                const r = try evalTerm(e.arena, t, snapshot) orelse continue;
                result = if (result) |acc| try unionBits(e.arena, acc, r) else r;
            }
            if (result) |bits| e.push(.{ .item = .{ .bucket = eb, .bits = bits } });
        }
        for (0..n) |i| {
            if (e.unreferenced[i]) continue;
            const tg = targets[i] orelse continue;
            const l = &e.leaves[i];
            while (true) {
                const pk = l.peek(&e.budget) orelse break;
                const dead = switch (pk) {
                    .bucket => |b| strictlyBefore(b.id, tg, asc),
                    .exhausted => false,
                };
                if (!dead) break;
                if (l.drained >= drain_probe_rows) {
                    l.seekBucket(tg);
                    break;
                }
                _ = l.next(&e.budget);
                l.drained += 1;
            }
        }
    }

    /// `leaf_skip_targets`.
    fn skipTargets(e: *Evaluator, class: []const ?Head) ![]?u64 {
        const asc = e.asc;
        const not_before = try e.arena.alloc(?u64, e.terms.len);
        for (e.terms, not_before) |t, *nb| {
            nb.* = null;
            if (t.unsatisfiable) continue;
            for (t.includes) |i| if (class[i]) |c| if (c == .bucket) {
                nb.* = if (nb.*) |x| advanceIn(x, c.bucket, asc) else c.bucket;
            };
        }
        const out = try e.arena.alloc(?u64, class.len);
        for (class, 0..) |c, i| {
            out[i] = null;
            if (e.unreferenced[i]) continue;
            const head = if (c) |h| (if (h == .bucket) h.bucket else continue) else continue;
            var target: ?u64 = null;
            var poisoned = false;
            for (e.terms, 0..) |t, ti| {
                if (t.unsatisfiable) continue;
                const refs = std.mem.indexOfScalar(usize, t.includes, i) != null or std.mem.indexOfScalar(usize, t.excludes, i) != null;
                if (!refs) continue;
                const nb = not_before[ti] orelse {
                    poisoned = true;
                    break;
                };
                target = if (target) |x| boundIn(x, nb, asc) else nb;
            }
            if (poisoned) continue;
            if (target) |tg| if (strictlyBefore(head, tg, asc)) {
                out[i] = tg;
            };
        }
        return out;
    }
};

fn evalTerm(arena: Allocator, t: Term, snapshot: []const ?[]const u32) !?[]const u32 {
    var acc: ?[]const u32 = null;
    for (t.includes) |i| {
        const b = snapshot[i] orelse return null;
        acc = if (acc) |a| try intersect(arena, a, b) else b;
    }
    var a = acc orelse return null;
    for (t.excludes) |i| if (snapshot[i]) |b| {
        a = try subtract(arena, a, b);
    };
    return if (a.len > 0) a else null;
}

fn intersect(arena: Allocator, a: []const u32, b: []const u32) ![]const u32 {
    var out = try arena.alloc(u32, @min(a.len, b.len));
    var i: usize = 0;
    var j: usize = 0;
    var n: usize = 0;
    while (i < a.len and j < b.len) {
        if (a[i] < b[j]) i += 1 else if (a[i] > b[j]) j += 1 else {
            out[n] = a[i];
            n += 1;
            i += 1;
            j += 1;
        }
    }
    return out[0..n];
}

fn subtract(arena: Allocator, a: []const u32, b: []const u32) ![]const u32 {
    var out = try arena.alloc(u32, a.len);
    var j: usize = 0;
    var n: usize = 0;
    for (a) |x| {
        while (j < b.len and b[j] < x) j += 1;
        if (j < b.len and b[j] == x) continue;
        out[n] = x;
        n += 1;
    }
    return out[0..n];
}

fn unionBits(arena: Allocator, a: []const u32, b: []const u32) ![]const u32 {
    var out = try arena.alloc(u32, a.len + b.len);
    var i: usize = 0;
    var j: usize = 0;
    var n: usize = 0;
    while (i < a.len or j < b.len) {
        const x = if (j >= b.len or (i < a.len and a[i] <= b[j])) blk: {
            const v = a[i];
            if (j < b.len and b[j] == v) j += 1;
            i += 1;
            break :blk v;
        } else blk: {
            const v = b[j];
            j += 1;
            break :blk v;
        };
        out[n] = x;
        n += 1;
    }
    return out[0..n];
}

// ---------------------------------------------------------------- drain (bitmap_scan.rs)

pub const Pending = struct {
    bucket: u64,
    bits: []const u32,
    rem: [2]u64,

    fn init(bucket: u64, bits: []const u32, range: [2]u64, bs: u64) ?Pending {
        const s = bucket * bs;
        const e = s + bs;
        const rem = [2]u64{ @max(range[0], s), @min(range[1], e) };
        if (rem[0] >= rem[1] or bits.len == 0) return null;
        return .{ .bucket = bucket, .bits = bits, .rem = rem };
    }
    fn nextSeq(p: *const Pending, bs: u64, asc: bool) ?u64 {
        if (p.rem[0] >= p.rem[1]) return null;
        const base = p.bucket * bs;
        const lo: u32 = @intCast(p.rem[0] - base);
        const hi: u32 = @intCast(p.rem[1] - base); // exclusive (fits: bucket sizes are <= 2^28)
        // first bit >= lo
        var a: usize = 0;
        var b: usize = p.bits.len;
        while (a < b) {
            const m = a + (b - a) / 2;
            if (p.bits[m] < lo) a = m + 1 else b = m;
        }
        const first = a;
        a = first;
        b = p.bits.len;
        while (a < b) {
            const m = a + (b - a) / 2;
            if (p.bits[m] < hi) a = m + 1 else b = m;
        }
        const end = a; // one past the last bit < hi
        if (first >= end) return null;
        return base + (if (asc) p.bits[first] else p.bits[end - 1]);
    }
    fn hasHits(p: *const Pending, bs: u64, asc: bool) bool {
        return p.nextSeq(bs, asc) != null;
    }
    fn drainInto(p: *Pending, out: *std.ArrayList(u64), arena: Allocator, hit_limit: usize, bs: u64, asc: bool) !void {
        while (out.items.len < hit_limit) {
            const seq = p.nextSeq(bs, asc) orelse break;
            try out.append(arena, seq);
            p.rem = remainingAfter(p.rem, seq, asc) orelse .{ 0, 0 };
        }
    }
};

pub fn remainingAfter(r: [2]u64, pos: u64, asc: bool) ?[2]u64 {
    const rem: [2]u64 = if (asc) .{ pos +| 1, r[1] } else .{ r[0], pos };
    return if (rem[0] < rem[1]) rem else null;
}

pub const Drained = struct {
    items: []const u64,
    pending: ?Pending,
    next_range: ?[2]u64,
    buckets_scanned: u64,
    scan_limit_frontier: ?u64,
};

/// `drain_bitmap_hits_with_budget` + `drain_watermarked_buckets`.
pub fn drain(arena: Allocator, src: Source, q: Query, bs: u64, pending_in: ?Pending, range_in: ?[2]u64, asc: bool, hit_limit: usize, budget: usize, universe: ?[]const u32) !Drained {
    if (hit_limit == 0) return .{ .items = &.{}, .pending = pending_in, .next_range = range_in, .buckets_scanned = 0, .scan_limit_frontier = null };
    var pending = pending_in;
    var next_range = range_in;
    var ev: ?Evaluator = null;
    var iter_range: [2]u64 = .{ 0, 0 };
    var out: std.ArrayList(u64) = .empty;
    var frontier: ?u64 = null;
    while (out.items.len < hit_limit) {
        if (pending) |*pb| {
            var b = pb.*;
            pending = null;
            try b.drainInto(&out, arena, hit_limit, bs, asc);
            if (b.hasHits(bs, asc)) {
                pending = b;
                break;
            }
            continue;
        }
        const scan_range = next_range orelse break;
        if (ev == null) {
            iter_range = scan_range;
            ev = try Evaluator.init(arena, src, q, scan_range, bs, asc, budget, universe);
        }
        const o = try ev.?.next() orelse {
            next_range = null;
            break;
        };
        switch (o) {
            .item => |it| {
                const rem: [2]u64 = if (asc) .{ @max((it.bucket + 1) * bs, iter_range[0]), iter_range[1] } else .{ iter_range[0], @min(it.bucket * bs, iter_range[1]) };
                next_range = if (rem[0] < rem[1]) rem else null;
                pending = Pending.init(it.bucket, it.bits, iter_range, bs);
            },
            .scan_limit => |f| {
                frontier = f;
                if (asc) {
                    const rem = [2]u64{ @max(f, iter_range[0]), iter_range[1] };
                    next_range = if (rem[0] < rem[1]) rem else null;
                } else {
                    next_range = remainingAfter(iter_range, f, false);
                }
                break;
            },
        }
    }
    return .{
        .items = out.items,
        .pending = pending,
        .next_range = next_range,
        .buckets_scanned = if (ev) |*e| e.evaluated() else 0,
        .scan_limit_frontier = frontier,
    };
}

test "evaluator single leaf charges every bucket" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const bits = [_]u32{ 1, 5 };
    const list = [_]Bucket{ .{ .id = 0, .bits = &bits }, .{ .id = 2, .bits = &bits }, .{ .id = 3, .bits = &bits } };
    const Ctx = struct {
        fn get(ctx: *const anyopaque, key: []const u8) []const Bucket {
            _ = key;
            const l: *const [3]Bucket = @ptrCast(@alignCast(ctx));
            return l;
        }
    };
    var terms = [_]Term{.{ .includes = &.{0}, .excludes = &.{} }};
    const q = Query{ .keys = &.{"\x01k"}, .terms = &terms };
    const d = try drain(arena, .{ .ctx = &list, .buckets = Ctx.get, .universe_ok = true }, q, 16, null, .{ 0, 64 }, true, 100, 2, null);
    try std.testing.expectEqualSlices(u64, &.{ 1, 5, 33 }, d.items[0..3]);
    try std.testing.expect(d.scan_limit_frontier != null);
}
