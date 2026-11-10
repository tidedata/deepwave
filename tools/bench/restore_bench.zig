//! Restore-shaped store bench and chunk-codec level study (lane fast-compress).
//!
//!   deepwave-store-bench levels  SEG...                 chunk codec study: deepwave's encoder and the C
//!                                                  encoder at several levels, one thread, on the
//!                                                  fixture's history chunks and on base-shaped
//!                                                  chunks of its objects
//!   deepwave-store-bench restore DIR OBJECTS SEG...     objects/s of Batch.putBase + Store.commit into
//!                                                  a fresh store at DIR (bulk live, as the node's
//!                                                  snapshot restore), OBJECTS objects drawn from
//!                                                  the fixture's object records (ids re-keyed)
//!
//! SEG: compressed segments (ZUISEGC1) of a deepwave store, e.g. the getcp fixture's seg/*.log.
//! restore env: COMPRESS=0 writes raw segments; THREADS=N sets compress_threads; ZUI_ZSTD=std
//! uses deepwave's own encoder; ZUI_ZSTD_LEVEL=N the C level; SYNC=none|data (default data).
const std = @import("std");
const store = @import("store");
const bcs = @import("bcs");
const types = @import("types");
const chunk = store.chunk;
const format = store.format;
const zstd_c = store.zstd_c;

fn now() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn mbs(bytes: u64, ns: u64) f64 {
    return @as(f64, @floatFromInt(bytes)) / 1e6 / (@as(f64, @floatFromInt(ns)) / 1e9);
}

fn ratio(a: u64, b: u64) f64 {
    return @as(f64, @floatFromInt(a)) / @as(f64, @floatFromInt(@max(b, 1)));
}

/// exec/objects.zig storeKey (the node's codec), copied so the bench links no execution code.
fn storeKey(raw: []const u8) ?store.ObjKey {
    var r = bcs.Reader.init(raw);
    const tag = r.uleb32() catch return null;
    switch (tag) {
        0 => {
            bcs.skip(types.MoveObjectType, &r) catch return null;
            _ = r.boolean() catch return null;
            const version = r.int(u64) catch return null;
            const n = r.length() catch return null;
            if (n < 32) return null;
            const c = r.bytes(32) catch return null;
            return .{ .id = c[0..32].*, .version = version };
        },
        1 => {
            const id = r.bytes(32) catch return null;
            const version = r.int(u64) catch return null;
            return .{ .id = id[0..32].*, .version = version };
        },
        else => return null,
    }
}

const Obj = struct { bytes: []const u8, id_off: usize, version: u64 };

/// A logical chunk and where it sits (segment epoch, logical offset): codec 2 needs both.
const SChunk = struct { d: []u8, epoch: u64, ls: u64 };

const Fixture = struct {
    /// Decoded logical chunks of the segments (history-shaped data, as written by catch-up).
    chunks: std.ArrayList(SChunk) = .empty,
    logical: u64 = 0,
    /// Object records found in them (distinct ids), as BCS bytes with the id's offset.
    objs: std.ArrayList(Obj) = .empty,
    obj_bytes: u64 = 0,
};

fn loadFixture(gpa: std.mem.Allocator, io: std.Io, segs: []const []const u8) !Fixture {
    var fx: Fixture = .{};
    var seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
    for (segs) |path| {
        const data = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .unlimited);
        defer gpa.free(data);
        if (data.len < 4096 or !std.mem.eql(u8, data[0..8], chunk.file_magic)) return error.NotCompressedSegment;
        const epoch = std.mem.readInt(u64, data[8..16], .little);
        var p: usize = 4096;
        var next_ls: u64 = 0;
        while (p + 32 <= data.len) {
            const ls = std.mem.readInt(u64, data[p + 8 ..][0..8], .little);
            const ll = std.mem.readInt(u32, data[p + 16 ..][0..4], .little);
            const bl = std.mem.readInt(u32, data[p + 20 ..][0..4], .little);
            const codec = data[p + 24];
            // Codec 3 needs the segment's dictionary file: those chunks are skipped here.
            if (ls != next_ls or ll == 0 or codec > 2 or p + 32 + @as(usize, bl) > data.len) {
                const np = std.mem.alignForward(usize, p + 1, 4096);
                if (np >= data.len) break;
                p = np;
                continue;
            }
            next_ls = ls + ll;
            const e: chunk.Entry = .{ .ls = ls, .phys = p, .ll = ll, .bl = bl, .codec = codec };
            const out = try gpa.alloc(u8, ll);
            try chunk.decode(e, epoch, null, data[p + 32 ..][0..bl], out);
            try fx.chunks.append(gpa, .{ .d = out, .epoch = epoch, .ls = ls });
            fx.logical += ll;
            p = std.mem.alignForward(usize, p + 32 + bl, 8);
        }
    }
    // Object records: whole records only (a record never straddles chunks of one group, and a
    // group is a run of whole chunks).
    for (fx.chunks.items) |sc| {
        const c = sc.d;
        var q: usize = 0;
        while (q + format.short_len <= c.len) {
            const h = format.short(c[q..]);
            if (h.size == 0 and @intFromEnum(h.kind) == 0) break; // group padding
            const n = format.lenOf(h.kind, h.size);
            if (q + n > c.len) break;
            const rec = c[q..][0 .. format.hdrLen(h.kind) + h.size];
            const bytes: ?[]const u8 = switch (h.kind) {
                .object => rec[format.header_len + @sizeOf(format.ObjectFixed) ..],
                .object_c => rec[format.short_len..],
                else => null,
            };
            q += n;
            const b = bytes orelse continue;
            const k = storeKey(b) orelse continue;
            const gop = try seen.getOrPut(gpa, k.id);
            if (gop.found_existing) continue;
            const off = std.mem.indexOf(u8, b, &k.id) orelse continue;
            try fx.objs.append(gpa, .{ .bytes = b, .id_off = off, .version = k.version });
            fx.obj_bytes += b.len;
        }
    }
    std.debug.print("fixture: {d} chunks, {d} MiB logical; {d} distinct objects, {d} MiB, mean {d} B\n", .{ fx.chunks.items.len, fx.logical >> 20, fx.objs.items.len, fx.obj_bytes >> 20, fx.obj_bytes / @max(fx.objs.items.len, 1) });
    return fx;
}

/// Base-shaped chunks: the objects as compact records (short header ++ bytes, padded to 8), cut
/// at about 256 KiB, as a restore commit group's chunks.
fn baseChunks(gpa: std.mem.Allocator, fx: *const Fixture) !std.ArrayList(SChunk) {
    var out: std.ArrayList(SChunk) = .empty;
    var cur: std.ArrayList(u8) = .empty;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    for (fx.objs.items) |o| {
        try buf.resize(gpa, format.lenOf(.object_c, o.bytes.len));
        const n = format.write(buf.items, format.loc(1, 4096 + cur.items.len), .object_c, 0, 0, 0, &.{o.bytes});
        try cur.appendSlice(gpa, buf.items[0..n]);
        if (cur.items.len >= 256 << 10) try out.append(gpa, .{ .d = try cur.toOwnedSlice(gpa), .epoch = 1, .ls = 4096 });
    }
    if (cur.items.len > 0) try out.append(gpa, .{ .d = try cur.toOwnedSlice(gpa), .epoch = 1, .ls = 4096 }) else cur.deinit(gpa);
    return out;
}

fn study(gpa: std.mem.Allocator, name: []const u8, chunks: []const SChunk) !void {
    var logical: u64 = 0;
    var maxll: usize = 0;
    for (chunks) |c| {
        logical += c.d.len;
        maxll = @max(maxll, c.d.len);
    }
    const dst = try gpa.alloc(u8, maxll);
    defer gpa.free(dst);
    const dec = try gpa.alloc(u8, maxll);
    defer gpa.free(dec);
    const el = try gpa.alloc(u8, maxll);
    defer gpa.free(el);
    var cz: zstd_c.Compressor = .{};
    defer cz.deinit();
    var elidable: usize = 0;
    for (chunks) |c| {
        if (chunk.elideSums(c.d, el[0..c.d.len], c.epoch, c.ls)) elidable += 1;
    }
    std.debug.print("\n{s}: {d} chunks, {d} MiB logical, {d} chunks allow codec 2\n", .{ name, chunks.len, logical >> 20, elidable });
    std.debug.print("  {s:<16} {s:>9} {s:>8} {s:>12}\n", .{ "encoder", "MB/s", "ratio", "decode MB/s" });
    const levels = [_]i32{ 99, -1, 1, 3, 5, 7, 9 };
    for (levels) |l| for ([_]bool{ false, true }) |elide| {
        if (l == 99 and elide) continue;
        zstd_c.enabled = l != 99;
        if (l != 99) zstd_c.level = l;
        var best: u64 = std.math.maxInt(u64);
        var body: u64 = 0;
        const reps: usize = if (l == 99) 1 else 2;
        for (0..reps) |_| {
            body = 0;
            const t0 = now();
            for (chunks) |c| {
                if (c.d.len <= 17) {
                    body += c.d.len;
                    continue;
                }
                var in: []const u8 = c.d;
                if (elide and chunk.elideSums(c.d, el[0..c.d.len], c.epoch, c.ls)) in = el[0..c.d.len];
                const n = (try chunk.compressInto(&cz, in, dst[0 .. c.d.len - 17])) orelse c.d.len;
                body += chunk.frameSpan(n);
            }
            best = @min(best, now() - t0);
        }
        // decode speed of this level's frames (C decoder, plus the checksum restore for codec 2),
        // and a correctness check
        var dec_ns: u64 = 0;
        for (chunks) |c| {
            if (c.d.len <= 17) continue;
            var codec: u32 = 1;
            var in: []const u8 = c.d;
            if (elide and chunk.elideSums(c.d, el[0..c.d.len], c.epoch, c.ls)) {
                in = el[0..c.d.len];
                codec = 2;
            }
            const n = (try chunk.compressInto(&cz, in, dst[0 .. c.d.len - 17])) orelse continue;
            const e: chunk.Entry = .{ .ls = c.ls, .phys = 0, .ll = @intCast(c.d.len), .bl = @intCast(n), .codec = codec };
            const t0 = now();
            try chunk.decode(e, c.epoch, null, dst[0..n], dec[0..c.d.len]);
            dec_ns += now() - t0;
            if (!std.mem.eql(u8, c.d, dec[0..c.d.len])) return error.Mismatch;
        }
        var lb: [24]u8 = undefined;
        const label = if (l == 99) "zui (std)" else try std.fmt.bufPrint(&lb, "C {d}{s}", .{ l, if (elide) " codec 2" else "" });
        std.debug.print("  {s:<16} {d:>9.0} {d:>8.3} {d:>12.0}\n", .{ label, mbs(logical, best), ratio(logical, body), mbs(logical, dec_ns) });
    };
    zstd_c.enabled = true;
}

const bench_codec: store.Codec = .{ .key = storeKey };

fn restore(gpa: std.mem.Allocator, io: std.Io, dir: []const u8, count: u64, fx: *const Fixture) !void {
    if (fx.objs.items.len == 0) return error.NoObjects;
    const env = struct {
        fn get(k: [*:0]const u8) ?[]const u8 {
            return if (std.c.getenv(k)) |v| std.mem.span(v) else null;
        }
    }.get;
    var cfg: store.Config = .{ .dir = dir, .codec = bench_codec };
    if (env("COMPRESS")) |v| cfg.compress = !std.mem.eql(u8, v, "0");
    if (env("THREADS")) |v| cfg.compress_threads = try std.fmt.parseInt(u32, v, 10);
    const sync: store.SyncMode = if (env("SYNC")) |v| (if (std.mem.eql(u8, v, "none")) .none else .data) else .data;
    cfg.max_live_objects = std.math.ceilPowerOfTwo(u64, count * 2) catch 1 << 30;
    std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    const h = try store.openDir(gpa, io, &cfg, .{ .sync = sync });
    defer h.io.deinit();
    defer h.store.deinit();
    const st = h.store;
    try st.bulkLiveBegin();

    const maxb = blk: {
        var m: usize = 0;
        for (fx.objs.items) |o| m = @max(m, o.bytes.len);
        break :blk m;
    };
    const tmp = try gpa.alloc(u8, maxb);
    defer gpa.free(tmp);
    var group: u64 = 0;
    var b: ?*store.Batch = null;
    var bytes: u64 = 0;
    var commit_ns: u64 = 0;
    const t0 = now();
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const o = fx.objs.items[i % fx.objs.items.len];
        const round = i / fx.objs.items.len;
        @memcpy(tmp[0..o.bytes.len], o.bytes);
        // A distinct id per round: the round number over the id's last 8 bytes.
        const idp = tmp[o.id_off..][0..32];
        const last = std.mem.readInt(u64, idp[24..32], .little);
        std.mem.writeInt(u64, idp[24..32], last ^ (round *% 0x9e3779b97f4a7c15), .little);
        const raw = tmp[0..o.bytes.len];
        // The restore's workers compute digests off the commit thread; compact records do not
        // store them.
        const d: [32]u8 = @splat(0);
        while (true) {
            if (b == null) b = try st.begin(group, 0);
            b.?.putBase(idp, o.version, &d, raw) catch |err| switch (err) {
                error.BatchFull, error.SegmentFull => {
                    const c0 = now();
                    try st.commit(b.?);
                    commit_ns += now() - c0;
                    b = null;
                    group += 1;
                    continue;
                },
                else => return err,
            };
            break;
        }
        bytes += raw.len;
    }
    if (b) |x| {
        const c0 = now();
        try st.commit(x);
        commit_ns += now() - c0;
    }
    const t1 = now();
    const s = st.stats;
    const secs = @as(f64, @floatFromInt(t1 - t0)) / 1e9;
    std.debug.print("restore: {d} objects ({d} MiB of object bytes) in {d} groups, {d:.2} s ({d:.2} s in commit): {d:.0} objects/s, {d:.0} MB/s of objects; compress {}, threads {d}, codec {s} level {d}; logical {d} MiB, physical {d} MiB, ratio {d:.3}\n", .{
        count,                                      bytes >> 20,                group + 1, secs, @as(f64, @floatFromInt(commit_ns)) / 1e9,
        @as(f64, @floatFromInt(count)) / secs,      mbs(bytes, t1 - t0),        cfg.compress, st.enc.threads,
        if (zstd_c.use()) "C" else "zui (std)",     zstd_c.level,               s.bytes_appended >> 20,
        s.bytes_written_phys >> 20,                 ratio(s.bytes_appended, s.bytes_written_phys),
    });
}

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.c_allocator;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3) return error.Usage;
    _ = zstd_c.use();
    if (std.mem.eql(u8, args[1], "levels")) {
        var fx = try loadFixture(gpa, io, args[2..]);
        try study(gpa, "history chunks (fixture as written by catch-up)", fx.chunks.items);
        var bc = try baseChunks(gpa, &fx);
        defer bc.deinit(gpa);
        try study(gpa, "base chunks (fixture objects as compact records, 256 KiB)", bc.items);
    } else if (std.mem.eql(u8, args[1], "restore")) {
        if (args.len < 5) return error.Usage;
        var fx = try loadFixture(gpa, io, args[4..]);
        try restore(gpa, io, args[2], try std.fmt.parseInt(u64, args[3], 10), &fx);
    } else return error.Usage;
}
