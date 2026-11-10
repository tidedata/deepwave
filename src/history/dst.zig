//! Deterministic simulation tests of the on-disk history index: synthetic checkpoints (no corpus
//! needed) against a plain in-memory model, with prunes, clean reopens, crash injection at every
//! persistence step (torn log records included), resets at holes and backfill adoption.
//! `ZUI_HISTORY_DST_SEEDS=<n>` runs more seeds (default 12).
const std = @import("std");
const root = @import("root.zig");
const Index = root.Index;

const seg_txs = root.seg.seg_txs;

const Cp = struct {
    seq: u64,
    first_tx: u64,
    digests: [][32]u8,
    evc: []u32,
    keys: [][]const u8,
    tx: []struct { u32, u32 },
    ev: []struct { u32, u32, u32 },
};

/// Deterministic synthetic chain: checkpoints of 0..max_tx transactions starting near a segment
/// boundary, keys drawn from small pools so buckets repeat across segments.
const Chain = struct {
    a: std.mem.Allocator,
    cps: std.ArrayList(Cp) = .empty,

    fn gen(a: std.mem.Allocator, seed: u64, n: usize, first_cp: u64, first_tx: u64, max_tx: u32) !Chain {
        var c: Chain = .{ .a = a };
        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();
        var tx = first_tx;
        for (0..n) |i| {
            const ntx: u32 = if (rnd.uintLessThan(u32, 8) == 0) 0 else rnd.uintLessThan(u32, max_tx + 1);
            var keys: std.ArrayList([]const u8) = .empty;
            var kmap: std.StringHashMapUnmanaged(u32) = .empty;
            var txe: std.ArrayList(struct { u32, u32 }) = .empty;
            var eve: std.ArrayList(struct { u32, u32, u32 }) = .empty;
            const digests = try a.alloc([32]u8, ntx);
            const evc = try a.alloc(u32, ntx);
            for (0..ntx) |t| {
                var d: [32]u8 = undefined;
                std.mem.writeInt(u64, d[0..8], std.hash.Wyhash.hash(seed, std.mem.asBytes(&(tx + t))), .little);
                std.mem.writeInt(u64, d[8..16], tx + t, .little);
                @memset(d[16..], @truncate(t));
                digests[t] = d;
                const nk = 1 + rnd.uintLessThan(u32, 4);
                for (0..nk) |_| {
                    const k = try poolKey(a, rnd, 0);
                    try txe.append(a, .{ try keyId(a, &keys, &kmap, k), @intCast(t) });
                }
                const ne = rnd.uintLessThan(u32, 4);
                evc[t] = ne;
                for (0..ne) |e| {
                    const nek = 1 + rnd.uintLessThan(u32, 2);
                    for (0..nek) |_| {
                        const k = try poolKey(a, rnd, 1);
                        try eve.append(a, .{ try keyId(a, &keys, &kmap, k), @intCast(t), @intCast(e) });
                    }
                }
            }
            try c.cps.append(a, .{ .seq = first_cp + i, .first_tx = tx, .digests = digests, .evc = evc, .keys = keys.items, .tx = txe.items, .ev = eve.items });
            tx += ntx;
        }
        return c;
    }

    fn poolKey(a: std.mem.Allocator, rnd: std.Random, space: u1) ![]const u8 {
        const kind = rnd.uintLessThan(u8, 3);
        const pool: u32 = switch (kind) {
            0 => 8, // hot keys (every segment)
            1 => 200,
            else => 100_000, // mostly unique (objects)
        };
        const v = rnd.uintLessThan(u32, pool);
        return std.fmt.allocPrint(a, "{c}{d}-{d}", .{ @as(u8, if (space == 0) 1 else 6) + kind, kind, v });
    }

    fn keyId(a: std.mem.Allocator, keys: *std.ArrayList([]const u8), m: *std.StringHashMapUnmanaged(u32), k: []const u8) !u32 {
        const g = try m.getOrPut(a, k);
        if (!g.found_existing) {
            g.value_ptr.* = @intCast(keys.items.len);
            try keys.append(a, k);
        }
        return g.value_ptr.*;
    }

    fn add(c: *const Chain, ix: *Index, i: usize) !void {
        const x = &c.cps.items[i];
        try ix.addRows(x.seq, x.first_tx, x.digests, x.evc, x.keys, x.tx, x.ev);
    }

    fn txEnd(c: *const Chain, i: usize) u64 {
        const x = &c.cps.items[i];
        return x.first_tx + x.digests.len;
    }
};

/// The model's view of checkpoints `lo_i ..= hi_i` (chain indexes) with tx floor `floor_tx`.
const Model = struct {
    a: std.mem.Allocator,
    /// space -> key -> sorted positions (tx_seq, or packed event seq).
    sp: [2]std.StringHashMapUnmanaged(std.ArrayList(u64)) = .{ .empty, .empty },

    fn build(a: std.mem.Allocator, c: *const Chain, hi_i: usize) !Model {
        var m: Model = .{ .a = a };
        for (c.cps.items[0 .. hi_i + 1]) |*x| {
            var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
            for (x.tx) |e| {
                const pos = x.first_tx + e[1];
                const key = std.hash.Wyhash.hash(pos, x.keys[e[0]]);
                if ((try seen.getOrPut(a, key)).found_existing) continue;
                try m.put(0, x.keys[e[0]], pos);
            }
            for (x.ev) |e| try m.put(1, x.keys[e[0]], root.encodeEventSeq(x.first_tx + e[1], e[2]));
        }
        for (&m.sp) |*s| {
            var it = s.valueIterator();
            while (it.next()) |l| {
                std.mem.sort(u64, l.items, {}, std.sort.asc(u64));
                var w: usize = 0;
                for (l.items, 0..) |v, i| {
                    if (i > 0 and v == l.items[w - 1]) continue;
                    l.items[w] = v;
                    w += 1;
                }
                l.items.len = w;
            }
        }
        return m;
    }
    fn put(m: *Model, si: usize, key: []const u8, pos: u64) !void {
        const g = try m.sp[si].getOrPut(m.a, key);
        if (!g.found_existing) g.value_ptr.* = .empty;
        try g.value_ptr.append(m.a, pos);
    }
};

fn checkAgainst(a: std.mem.Allocator, ix: *Index, c: *const Chain, lo_i: usize, hi_i: usize, floor_tx: u64) !void {
    const lo = c.cps.items[lo_i].seq;
    const hi = c.cps.items[hi_i].seq;
    ix.publish(hi);
    var r = ix.reader();
    defer r.release();
    const rg = r.range() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(lo, rg.lo);
    try std.testing.expectEqual(hi, rg.hi);
    for (c.cps.items[lo_i .. hi_i + 1], lo_i..) |*x, i| {
        const t = r.checkpointTxs(x.seq).?;
        try std.testing.expectEqual(x.first_tx, t.first);
        try std.testing.expectEqual(@as(u64, x.digests.len), t.count);
        for (x.digests, x.evc, 0..) |*d, evn, k| {
            if (k % 7 != 0 and k + 1 != x.digests.len) continue;
            const tx = x.first_tx + k;
            const row = r.txRow(tx) orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(x.seq, row.checkpoint);
            try std.testing.expectEqual(@as(u32, @intCast(k)), row.tx_offset);
            try std.testing.expectEqual(evn, row.event_count);
            try std.testing.expectEqualSlices(u8, d, &row.digest);
            try std.testing.expectEqual(@as(?u64, tx), r.txSeqOfDigest(d));
        }
        _ = i;
    }
    if (lo_i > 0) {
        const prev = &c.cps.items[lo_i - 1];
        if (prev.digests.len > 0) try std.testing.expect(r.txRow(prev.first_tx) == null);
        try std.testing.expect(r.checkpointTxs(prev.seq) == null);
    }
    var model = try Model.build(a, c, hi_i);
    const sizes = [2]u64{ root.tx_bucket_size, root.event_bucket_size };
    const floors = [2]u64{ floor_tx, root.encodeEventSeq(floor_tx, 0) };
    for (&model.sp, 0..) |*s, si| {
        var it = s.iterator();
        while (it.next()) |kv| {
            // Every hot and medium key; one in 16 of the mostly unique ones.
            const k = kv.key_ptr.*;
            if (k[0] == 3 or k[0] == 8) if (std.hash.Wyhash.hash(1, k) % 16 != 0) continue;
            const got = r.buckets(@enumFromInt(si), k);
            var want: std.ArrayList(u64) = .empty;
            for (kv.value_ptr.items) |p| if ((p / sizes[si] + 1) * sizes[si] > floors[si]) try want.append(a, p);
            var flat: std.ArrayList(u64) = .empty;
            var prev_id: ?u64 = null;
            for (got) |b| {
                if (prev_id) |p| try std.testing.expect(b.id > p);
                prev_id = b.id;
                try std.testing.expect(b.bits.len > 0);
                for (b.bits) |bit| try flat.append(a, b.id * sizes[si] + bit);
            }
            try std.testing.expectEqualSlices(u64, want.items, flat.items);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), r.buckets(.tx, "\x01nope").len);
}

fn tmpPath(a: std.mem.Allocator, tmp: *std.testing.TmpDir, sub: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, sub });
}

fn seedCount() u64 {
    const v = std.c.getenv("ZUI_HISTORY_DST_SEEDS") orelse return 12;
    return std.fmt.parseInt(u64, std.mem.span(v), 10) catch 12;
}

test "dst: crashes at every persistence step, prunes and reopens keep the index equal to the model" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const nseeds = seedCount();
    var total_crashes: usize = 0;
    for (0..nseeds) |seed| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        var prng = std.Random.DefaultPrng.init(seed * 7919 + 1);
        const rnd = prng.random();
        const ncp = 120 + rnd.uintLessThan(usize, 120);
        const first_tx = 3 * seg_txs - 1 - rnd.uintLessThan(u64, 20_000);
        const chain = try Chain.gen(a, seed, ncp, 1_000_000 + seed * 100_000, first_tx, 1500 + rnd.uintLessThan(u32, 1500));
        const dir = try tmpPath(a, &tmp, try std.fmt.allocPrint(a, "s{d}", .{seed}));
        const log_mode: root.LogMode = if (seed % 3 == 2) .nosync else .sync;

        var fault: root.Fault = .{ .left = 0, .rng = std.Random.DefaultPrng.init(seed) };
        var ix = try Index.initOpts(gpa, io, dir, .{ .log = log_mode });
        var next: usize = 0; // chain index of the next checkpoint to add
        var lo_i: usize = 0;
        var crashes: usize = 0;
        while (next < chain.cps.items.len) {
            const op = rnd.uintLessThan(u32, 100);
            if (op < 6 and next > 0) {
                // crash somewhere in the next few persistence steps
                fault = .{ .left = 1 + rnd.uintLessThan(u64, 40), .rng = std.Random.DefaultPrng.init(seed + next) };
                ix.fault = &fault;
                const floor_before = lo_i;
                var prune_to: ?usize = null;
                const crashed = blk: {
                    var k: usize = 0;
                    while (k < 8 and next < chain.cps.items.len) : (k += 1) {
                        if (rnd.uintLessThan(u32, 5) == 0 and next > lo_i + 2) {
                            const to = lo_i + 1 + rnd.uintLessThan(usize, next - lo_i - 1);
                            prune_to = to;
                            ix.tryPruneBelow(chain.cps.items[to].seq) catch |e| {
                                try std.testing.expectEqual(error.Crash, e);
                                break :blk true;
                            };
                            lo_i = to;
                            prune_to = null;
                        }
                        chain.add(ix, next) catch |e| {
                            try std.testing.expectEqual(error.Crash, e);
                            break :blk true;
                        };
                        next += 1;
                    }
                    break :blk false;
                };
                ix.fault = null;
                ix.deinit();
                ix = try Index.initOpts(gpa, io, dir, .{ .log = log_mode });
                if (crashed) crashes += 1;
                // Durable: everything acked (with a fsync'd or page-cache log; kill -9 keeps
                // the page cache). The in-flight checkpoint may or may not have landed.
                const hi = ix.indexedHi().?;
                const acked = chain.cps.items[next - 1].seq;
                try std.testing.expect(hi == acked or (crashed and hi == acked + 1));
                if (hi == acked + 1) next += 1;
                // A crashed prune landed or not.
                const got_lo = ix.indexedLo().?;
                if (prune_to) |to| {
                    try std.testing.expect(got_lo == chain.cps.items[floor_before].seq or got_lo == chain.cps.items[to].seq or got_lo == chain.cps.items[lo_i].seq);
                } else try std.testing.expectEqual(chain.cps.items[lo_i].seq, got_lo);
                lo_i = got_lo - chain.cps.items[0].seq;
                try checkAgainst(a, ix, &chain, lo_i, next - 1, chain.cps.items[lo_i].first_tx);
            } else if (op < 10 and next > lo_i + 2) {
                const to = lo_i + 1 + rnd.uintLessThan(usize, next - lo_i - 1);
                try ix.tryPruneBelow(chain.cps.items[to].seq);
                lo_i = to;
            } else if (op < 13 and next > 0) {
                ix.deinit();
                ix = try Index.initOpts(gpa, io, dir, .{ .log = log_mode });
                try checkAgainst(a, ix, &chain, lo_i, next - 1, chain.cps.items[lo_i].first_tx);
            } else {
                try chain.add(ix, next);
                next += 1;
            }
        }
        try checkAgainst(a, ix, &chain, lo_i, next - 1, chain.cps.items[lo_i].first_tx);
        // The heap holds the open segment only: the rest is mapped.
        if (chain.txEnd(next - 1) / seg_txs > chain.cps.items[lo_i].first_tx / seg_txs) try std.testing.expect(ix.segmentCount() >= 1);
        const h1 = try ix.contentHash();
        ix.deinit();
        ix = try Index.initOpts(gpa, io, dir, .{ .log = log_mode });
        try std.testing.expectEqual(h1, try ix.contentHash());
        // Same checkpoints in memory, same prune: same content.
        {
            const mem = try Index.init(gpa, io, null);
            defer mem.deinit();
            for (0..next) |i| try chain.add(mem, i);
            try mem.tryPruneBelow(chain.cps.items[lo_i].seq);
            try std.testing.expectEqual(h1, try mem.contentHash());
        }
        ix.deinit();
        total_crashes += crashes;
    }
    try std.testing.expect(total_crashes > 0);
}

test "dst: a hole resets; adopt swaps in a backfill (memory or staging) durably" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const chain = try Chain.gen(a, 99, 160, 5_000, 2 * seg_txs - 7_000, 2500);
    const want = blk: {
        const m = try Index.init(gpa, io, null);
        defer m.deinit();
        for (0..chain.cps.items.len) |i| try chain.add(m, i);
        break :blk try m.contentHash();
    };
    for ([_]bool{ false, true }) |staged| {
        const dir = try tmpPath(a, &tmp, if (staged) "live-staged" else "live-mem");
        const sdir = try tmpPath(a, &tmp, if (staged) "live-staged/backfill" else "unused");
        {
            const live = try Index.init(gpa, io, dir);
            defer live.deinit();
            // started late: a hole from the first few to 120 resets it
            for (0..3) |i| try chain.add(live, i);
            try chain.add(live, 120);
            try std.testing.expectEqual(chain.cps.items[120].seq, live.indexedLo().?);
            const g = live.generation();
            const bf = if (staged) try Index.openStaging(gpa, io, sdir) else try Index.init(gpa, io, null);
            defer bf.deinit();
            for (0..80) |i| try chain.add(bf, i);
            if (staged) {
                // the staging index survives a restart at its last rotation
                try bf.saveStaging();
                const again = try Index.openStaging(gpa, io, sdir);
                defer again.deinit();
                try std.testing.expectEqual(chain.cps.items[79].seq, again.indexedHi().?);
            }
            // catch the backfill up to the live index's tip, adopt, then go on
            const bf2 = if (staged) try Index.openStaging(gpa, io, sdir) else bf;
            defer if (staged) bf2.deinit();
            for (80..121) |i| try chain.add(bf2, i);
            try live.adopt(bf2);
            try std.testing.expect(live.generation() > g);
            try std.testing.expectEqual(chain.cps.items[0].seq, live.indexedLo().?);
            for (121..chain.cps.items.len) |i| try chain.add(live, i);
            try std.testing.expectEqual(want, try live.contentHash());
        }
        const again = try Index.init(gpa, io, dir);
        defer again.deinit();
        try std.testing.expectEqual(want, try again.contentHash());
        try checkAgainst(a, again, &chain, 0, chain.cps.items.len - 1, chain.cps.items[0].first_tx);
    }
}

test "dst: legacy in-memory index files are dropped on open" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "h");
    try tmp.dir.writeFile(io, .{ .sub_path = "h/snapshot.bin", .data = "ZUIHIST1xxxxxxxx" });
    try tmp.dir.writeFile(io, .{ .sub_path = "h/log.bin", .data = "ZUIHLOG2xxxxxxxxxxxxxxxx" });
    var pb: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&pb, ".zig-cache/tmp/{s}/h", .{tmp.sub_path});
    const ix = try Index.init(gpa, io, dir);
    defer ix.deinit();
    try std.testing.expect(ix.indexedHi() == null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "h/snapshot.bin", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "h/log.bin", .{}));
}

/// `s<seg>.seg` files in the live generation of the index at `dir` (CURRENT names it).
fn segFiles(a: std.mem.Allocator, io: std.Io, dir: []const u8) !usize {
    var cb: [64]u8 = undefined;
    const cur = std.mem.trim(u8, try std.Io.Dir.cwd().readFile(io, try std.fmt.allocPrint(a, "{s}/CURRENT", .{dir}), &cb), " \n");
    var gd = try std.Io.Dir.cwd().openDir(io, try std.fmt.allocPrint(a, "{s}/{s}", .{ dir, cur }), .{ .iterate = true });
    defer gd.close(io);
    var n: usize = 0;
    var it = gd.iterate();
    while (try it.next(io)) |e| {
        if (e.kind == .file and e.name.len > 1 and e.name[0] == 's' and std.mem.endsWith(u8, e.name, ".seg")) n += 1;
    }
    return n;
}

test "dst: a reopen replays at most the open segment's records, the heap holds one segment, prune unlinks whole segments" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // ~6 segments of transactions.
    const n = 600;
    const chain = try Chain.gen(a, 4242, n, 7_000_000, seg_txs - 100, 1500);
    const dir = try tmpPath(a, &tmp, "bounded");
    const last_seg = chain.txEnd(n - 1) / seg_txs;
    const first_seg = chain.cps.items[0].first_tx / seg_txs;
    try std.testing.expect(last_seg >= first_seg + 4);
    var mem_heap: u64 = 0;
    {
        const mem = try Index.init(gpa, io, null);
        defer mem.deinit();
        for (0..n) |i| try chain.add(mem, i);
        mem_heap = mem.memoryBytes();
    }
    var h1: u64 = 0;
    {
        const ix = try Index.init(gpa, io, dir);
        defer ix.deinit();
        for (0..n) |i| try chain.add(ix, i);
        try std.testing.expectEqual(@as(usize, @intCast(last_seg - first_seg)), ix.segmentCount());
        try std.testing.expect(ix.memoryBytes() < mem_heap);
        h1 = try ix.contentHash();
        // kill -9: no close-time flush (deinit writes nothing).
    }
    // The checkpoints after the last rotation: the only ones a reopen may replay.
    var tail: u64 = 0;
    for (0..n) |i| {
        if (chain.txEnd(i) >= last_seg * seg_txs) tail += 1;
    }
    {
        const ix = try Index.init(gpa, io, dir);
        defer ix.deinit();
        try std.testing.expect(ix.stats.replayed <= tail);
        try std.testing.expect(ix.stats.replayed < n / 2);
        try std.testing.expectEqual(h1, try ix.contentHash());
        try std.testing.expectEqual(chain.cps.items[n - 1].seq, ix.indexedHi().?);
        try checkAgainst(a, ix, &chain, 0, n - 1, chain.cps.items[0].first_tx);

        // Prune to the first checkpoint that starts two segments up: exactly the two lowest
        // segments go, files included; nothing is rewritten.
        var cut: usize = 0;
        while (chain.cps.items[cut].first_tx < (first_seg + 2) * seg_txs) cut += 1;
        const segs_before = ix.segmentCount();
        const files_before = try segFiles(a, io, dir);
        try std.testing.expectEqual(segs_before, files_before);
        const flushes = ix.stats.flushes;
        try ix.tryPruneBelow(chain.cps.items[cut].seq);
        try std.testing.expectEqual(segs_before - 2, ix.segmentCount());
        try std.testing.expectEqual(files_before - 2, try segFiles(a, io, dir));
        try std.testing.expectEqual(flushes, ix.stats.flushes);
        try checkAgainst(a, ix, &chain, cut, n - 1, chain.cps.items[cut].first_tx);
    }
    // The prune is durable: a reopen starts at the floor.
    {
        const ix = try Index.init(gpa, io, dir);
        defer ix.deinit();
        var cut: usize = 0;
        while (chain.cps.items[cut].first_tx < (first_seg + 2) * seg_txs) cut += 1;
        try std.testing.expectEqual(chain.cps.items[cut].seq, ix.indexedLo().?);
        try checkAgainst(a, ix, &chain, cut, n - 1, chain.cps.items[cut].first_tx);
    }
}
