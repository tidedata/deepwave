//! In-place parallel sort of u64 values (lane index-fast): `LiveScan.init` sorts every live-table
//! location of a mainnet store (773M values, 6.2 GB) before a snapshot write, a state hash or a
//! conservation scan; one thread took about a minute for it.
//!
//! American-flag partition (in place, one thread, two passes) into `buckets` value ranges of
//! [min, max], then the buckets are sorted on `threads` threads, a bucket that holds more than its
//! share partitioned again (skew: most locations of a restored store are in one segment). No
//! second array: the memory is the input plus the bucket counters.
const std = @import("std");

const fanout = 1024;
/// Below this a range is sorted directly.
const direct = 1 << 16;

const Spin = struct {
    v: std.atomic.Value(u32) = .init(0),
    fn lock(l: *Spin) void {
        while (l.v.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn unlock(l: *Spin) void {
        l.v.store(0, .release);
    }
};

const Range = struct { lo: usize, hi: usize, depth: u8 };

const Work = struct {
    items: []u64,
    lock: Spin = .{},
    stack: std.ArrayList(Range) = .empty,
    busy: usize = 0,
    gpa: std.mem.Allocator,
    big: usize,
    failed: bool = false,

    fn pop(w: *Work) ?Range {
        while (true) {
            w.lock.lock();
            if (w.stack.pop()) |r| {
                w.busy += 1;
                w.lock.unlock();
                return r;
            }
            const idle = w.busy == 0 or w.failed;
            w.lock.unlock();
            if (idle) return null;
            std.atomic.spinLoopHint();
        }
    }

    fn run(w: *Work) void {
        while (w.pop()) |r| {
            w.one(r);
            w.lock.lock();
            w.busy -= 1;
            w.lock.unlock();
        }
    }

    fn one(w: *Work, r: Range) void {
        const s = w.items[r.lo..r.hi];
        if (s.len <= direct or s.len <= w.big or r.depth >= 4) {
            std.mem.sortUnstable(u64, s, {}, std.sort.asc(u64));
            return;
        }
        var bounds: [fanout + 1]usize = undefined;
        if (!partition(s, &bounds)) {
            // every value equal: sorted
            return;
        }
        w.lock.lock();
        defer w.lock.unlock();
        for (0..fanout) |b| {
            if (bounds[b + 1] - bounds[b] < 2) continue;
            w.stack.append(w.gpa, .{ .lo = r.lo + bounds[b], .hi = r.lo + bounds[b + 1], .depth = r.depth + 1 }) catch {
                // no memory for the stack: sort this bucket here (still correct)
                std.mem.sortUnstable(u64, w.items[r.lo + bounds[b] .. r.lo + bounds[b + 1]], {}, std.sort.asc(u64));
            };
        }
    }
};

fn bucketOf(v: u64, min: u64, span: u128) usize {
    return @intCast((@as(u128, v - min) * fanout) / span);
}

/// Partitions `s` in place by value into `fanout` ascending ranges; `bounds[b]..bounds[b+1]` is
/// bucket b. False when every value is equal (nothing to do).
fn partition(s: []u64, bounds: *[fanout + 1]usize) bool {
    var min: u64 = std.math.maxInt(u64);
    var max: u64 = 0;
    for (s) |v| {
        min = @min(min, v);
        max = @max(max, v);
    }
    if (min == max) return false;
    const span: u128 = @as(u128, max - min) + 1;
    var counts: [fanout]usize = @splat(0);
    for (s) |v| counts[bucketOf(v, min, span)] += 1;
    var next: [fanout]usize = undefined;
    bounds[0] = 0;
    for (0..fanout) |b| {
        next[b] = bounds[b];
        bounds[b + 1] = bounds[b] + counts[b];
    }
    // cycle each value to its bucket (American flag sort)
    for (0..fanout) |b| {
        while (next[b] < bounds[b + 1]) {
            var v = s[next[b]];
            var d = bucketOf(v, min, span);
            while (d != b) {
                const t = s[next[d]];
                s[next[d]] = v;
                next[d] += 1;
                v = t;
                d = bucketOf(v, min, span);
            }
            s[next[b]] = v;
            next[b] += 1;
        }
    }
    return true;
}

/// Sorts `items` ascending on up to `threads` threads (1: `std.mem.sortUnstable`).
pub fn sortU64(gpa: std.mem.Allocator, items: []u64, threads: usize) void {
    if (threads <= 1 or items.len < 4 * direct) {
        std.mem.sortUnstable(u64, items, {}, std.sort.asc(u64));
        return;
    }
    var w: Work = .{ .items = items, .gpa = gpa, .big = 0 };
    defer w.stack.deinit(gpa);
    // a bucket at or under twice its even share is sorted, not partitioned again
    w.big = 0;
    w.stack.append(gpa, .{ .lo = 0, .hi = items.len, .depth = 0 }) catch {
        std.mem.sortUnstable(u64, items, {}, std.sort.asc(u64));
        return;
    };
    // the first partition runs alone; its buckets then go to every thread
    if (w.pop()) |r| {
        w.one(r);
        w.busy -= 1;
    }
    w.big = items.len / (threads * 8);
    var ts: [64]?std.Thread = @splat(null);
    const nt = @min(threads, ts.len);
    for (ts[0 .. nt - 1]) |*t| t.* = std.Thread.spawn(.{ .stack_size = 1 << 20 }, Work.run, .{&w}) catch null;
    w.run();
    for (ts[0 .. nt - 1]) |t| if (t) |x| x.join();
}

test "psort: equals a plain sort on random, skewed, duplicate-heavy and tiny inputs" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(9);
    const r = prng.random();
    for ([_]usize{ 0, 1, 7, 300_000, 1_100_000 }) |n| {
        for (0..4) |shape| {
            const a = try gpa.alloc(u64, n);
            defer gpa.free(a);
            for (a, 0..) |*v, i| v.* = switch (shape) {
                0 => r.int(u64),
                // most values in one narrow range, a few far away (a restored store's locations)
                1 => if (i % 97 == 0) r.int(u64) else (5 << 56) + r.uintLessThan(u64, 1 << 30),
                2 => r.uintLessThan(u64, 5),
                else => 42,
            };
            const b = try gpa.dupe(u64, a);
            defer gpa.free(b);
            std.mem.sortUnstable(u64, b, {}, std.sort.asc(u64));
            sortU64(gpa, a, 4);
            try std.testing.expectEqualSlices(u64, b, a);
        }
    }
}
