//! `deepwave du DIR [--kinds EPOCH [SAMPLE_MIB]]`: where a node's disk goes, per component
//! (lane disk-fit). Read-only; safe on a running node (it opens files read-only and reads only
//! dir files, frame headers and, with --kinds, a sample of one segment's chunks).
//!
//! Every file under DIR (the node's data dir: store/, state-index/, rpc/, ledger-history/,
//! node/, ...) goes to one component; each line shows the bytes allocated on disk (st_blocks:
//! what `du` and the disk budget see; age-out's punched holes and sparse tables count as
//! freed) and the apparent size (`ls -l`). Segments get a line each: format (raw or
//! compressed), and for compressed ones the logical bytes their dir file covers, so the line
//! shows the compression ratio (logical / allocated).
//!
//! `--kinds EPOCH [SAMPLE_MIB]` (default 1024): decodes up to SAMPLE_MIB logical bytes of segment
//! EPOCH from its start and splits them by record kind: records, logical bytes, and the
//! physical bytes of each chunk shared out by its kinds' logical bytes (an estimate: a chunk
//! compresses as a whole), plus the chunk codecs seen.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const store = @import("store");
const chunk = store.chunk;
const format = store.format;

const Comp = enum {
    seg,
    dir,
    side,
    age,
    dicts,
    live,
    journal,
    runs,
    store_other,
    state_index,
    rpc,
    ledger_history,
    node,
    other,

    fn label(c: Comp) []const u8 {
        return switch (c) {
            .seg => "store: segments (seg/*.log)",
            .dir => "store: chunk dirs (index/*.dir)",
            .side => "store: age-out sidecars (index/*.side)",
            .age => "store: age logs (index/*.age)",
            .dicts => "store: history dictionaries (index/*.zd)",
            .live => "store: live table (index/live-*.tbl)",
            .journal => "store: live-table journal (index/live.jnl)",
            .runs => "store: version/tx runs (index/*.run)",
            .store_other => "store: other (meta, spill, tmp)",
            .state_index => "StateService index (state-index/)",
            .rpc => "rpc index (rpc/)",
            .ledger_history => "ledger-history index (ledger-history/)",
            .node => "node (spool, epochs, trust, markers)",
            .other => "other",
        };
    }
};

const Sum = struct { files: u64 = 0, alloc: u64 = 0, apparent: u64 = 0 };

const SegInfo = struct {
    epoch: u64,
    compressed: bool,
    alloc: u64,
    apparent: u64,
    /// Compressed: logical end of the dir file's trusted prefix (0 if no dir). Raw: its size.
    logical: u64,
    chunks: u64,
    codec: [chunk.max_codec + 1]u64,
};

fn allocatedOf(f: Io.File) u64 {
    const h = f.handle;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(h, "", linux.AT.EMPTY_PATH, .{ .BLOCKS = true }, &st)) != .SUCCESS) return 0;
        return st.blocks * 512;
    }
    var st: std.c.Stat = undefined;
    if (std.c.fstat(h, &st) != 0) return 0;
    return @as(u64, @intCast(st.blocks)) * 512;
}

fn classify(path: []const u8) Comp {
    const top_end = std.mem.indexOfScalar(u8, path, '/') orelse path.len;
    const top = path[0..top_end];
    const base = std.fs.path.basename(path);
    if (std.mem.eql(u8, top, "store")) {
        if (std.mem.startsWith(u8, path, "store/seg/") and std.mem.endsWith(u8, base, ".log")) return .seg;
        if (std.mem.startsWith(u8, path, "store/index/")) {
            if (std.mem.endsWith(u8, base, ".dir")) return .dir;
            if (std.mem.endsWith(u8, base, ".side")) return .side;
            if (std.mem.endsWith(u8, base, ".age")) return .age;
            if (std.mem.endsWith(u8, base, ".zd")) return .dicts;
            if (std.mem.startsWith(u8, base, "live-") and std.mem.endsWith(u8, base, ".tbl")) return .live;
            if (std.mem.eql(u8, base, "live.jnl")) return .journal;
            if (std.mem.endsWith(u8, base, ".run")) return .runs;
        }
        return .store_other;
    }
    if (std.mem.eql(u8, top, "state-index")) return .state_index;
    if (std.mem.eql(u8, top, "rpc")) return .rpc;
    if (std.mem.eql(u8, top, "ledger-history")) return .ledger_history;
    if (std.mem.eql(u8, top, "node")) return .node;
    return .other;
}

fn gb(x: u64) f64 {
    return @as(f64, @floatFromInt(x)) / 1e9;
}

/// Reads a compressed segment's dir file (store/index/<e>.dir) and fills logical/chunks/codec.
fn dirStats(gpa: std.mem.Allocator, io: Io, root: Io.Dir, info: *SegInfo) void {
    var nb: [64]u8 = undefined;
    const name = std.fmt.bufPrint(&nb, "store/index/{d:0>8}.dir", .{info.epoch}) catch return;
    const img = root.readFileAlloc(io, name, gpa, .unlimited) catch return;
    defer gpa.free(img);
    var ents: std.ArrayList(chunk.Entry) = .empty;
    defer ents.deinit(gpa);
    _ = chunk.trustedPrefix(img, info.epoch, std.math.maxInt(u64), &ents, gpa) catch return;
    for (ents.items) |e| info.codec[@min(chunk.codecOf(e.codec), chunk.max_codec)] += 1;
    info.chunks = ents.items.len;
    info.logical = if (ents.items.len == 0) 0 else ents.items[ents.items.len - 1].end();
}

pub fn run(gpa: std.mem.Allocator, io: Io, args: []const []const u8) !u8 {
    var stdout_buf: [4096]u8 = undefined;
    var fw = Io.File.stdout().writer(io, &stdout_buf);
    const w = &fw.interface;
    defer w.flush() catch {};
    if (args.len < 1) {
        try w.print("usage: deepwave du DIR [--kinds EPOCH [SAMPLE_MIB]]\n", .{});
        return 2;
    }
    const dir_path = args[0];
    const cwd = Io.Dir.cwd();
    var root = cwd.openDir(io, dir_path, .{ .iterate = true }) catch |e| {
        try w.print("du: cannot open {s}: {s}\n", .{ dir_path, @errorName(e) });
        return 1;
    };
    defer root.close(io);

    if (args.len >= 3 and std.mem.eql(u8, args[1], "--kinds")) {
        const epoch = try std.fmt.parseInt(u64, args[2], 10);
        const sample: u64 = (if (args.len >= 4) try std.fmt.parseInt(u64, args[3], 10) else 1024) << 20;
        return kinds(gpa, io, root, w, epoch, sample);
    }

    var sums: [std.enums.values(Comp).len]Sum = @splat(.{});
    var segs: std.ArrayList(SegInfo) = .empty;
    defer segs.deinit(gpa);
    var others: std.StringArrayHashMapUnmanaged(Sum) = .empty;
    defer {
        for (others.keys()) |k| gpa.free(k);
        others.deinit(gpa);
    }

    var walker = try root.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| {
        if (e.kind != .file) continue;
        const f = root.openFile(io, e.path, .{}) catch continue;
        defer f.close(io);
        const st = f.stat(io) catch continue;
        const alloc = allocatedOf(f);
        const comp = classify(e.path);
        const s = &sums[@intFromEnum(comp)];
        s.files += 1;
        s.alloc += alloc;
        s.apparent += st.size;
        if (comp == .other) {
            const top_end = std.mem.indexOfScalar(u8, e.path, '/') orelse e.path.len;
            const gop = try others.getOrPut(gpa, e.path[0..top_end]);
            if (!gop.found_existing) {
                gop.key_ptr.* = try gpa.dupe(u8, e.path[0..top_end]);
                gop.value_ptr.* = .{};
            }
            gop.value_ptr.files += 1;
            gop.value_ptr.alloc += alloc;
            gop.value_ptr.apparent += st.size;
        }
        if (comp == .seg) {
            const base = std.fs.path.basename(e.path);
            const ep = std.fmt.parseInt(u64, base[0 .. base.len - 4], 10) catch continue;
            var magic: [8]u8 = @splat(0);
            _ = f.readPositionalAll(io, &magic, 0) catch 0;
            var info: SegInfo = .{ .epoch = ep, .compressed = std.mem.eql(u8, &magic, chunk.file_magic), .alloc = alloc, .apparent = st.size, .logical = st.size, .chunks = 0, .codec = @splat(0) };
            if (info.compressed) {
                info.logical = 0;
                dirStats(gpa, io, root, &info);
            }
            try segs.append(gpa, info);
        }
    }
    std.mem.sort(SegInfo, segs.items, {}, struct {
        fn lt(_: void, a: SegInfo, b: SegInfo) bool {
            return a.epoch < b.epoch;
        }
    }.lt);

    try w.print("deepwave du {s}   (GB = 1e9 bytes; allocated = on disk, st_blocks)\n\n", .{dir_path});
    try w.print("{s:<44} {s:>8} {s:>12} {s:>12}\n", .{ "component", "files", "allocated GB", "apparent GB" });
    var store_sum: Sum = .{};
    var index_sum: Sum = .{};
    var total: Sum = .{};
    for (std.enums.values(Comp)) |c| {
        const s = sums[@intFromEnum(c)];
        if (s.files > 0 and c != .other) try w.print("{s:<44} {d:>8} {d:>12.3} {d:>12.3}\n", .{ c.label(), s.files, gb(s.alloc), gb(s.apparent) });
        switch (c) {
            .seg, .dir, .side, .age, .dicts, .live, .journal, .runs, .store_other => {
                store_sum.files += s.files;
                store_sum.alloc += s.alloc;
                store_sum.apparent += s.apparent;
            },
            .state_index, .rpc, .ledger_history => {
                index_sum.files += s.files;
                index_sum.alloc += s.alloc;
                index_sum.apparent += s.apparent;
            },
            else => {},
        }
        total.files += s.files;
        total.alloc += s.alloc;
        total.apparent += s.apparent;
    }
    for (others.keys(), others.values()) |k, s| {
        var lb: [64]u8 = undefined;
        const l = std.fmt.bufPrint(&lb, "other: {s}", .{k[0..@min(k.len, 40)]}) catch "other";
        try w.print("{s:<44} {d:>8} {d:>12.3} {d:>12.3}\n", .{ l, s.files, gb(s.alloc), gb(s.apparent) });
    }
    try w.print("{s:<44} {d:>8} {d:>12.3} {d:>12.3}\n", .{ "= store (everything under store/)", store_sum.files, gb(store_sum.alloc), gb(store_sum.apparent) });
    try w.print("{s:<44} {d:>8} {d:>12.3} {d:>12.3}\n", .{ "= indexes (state-index, rpc, ledger-history)", index_sum.files, gb(index_sum.alloc), gb(index_sum.apparent) });
    try w.print("{s:<44} {d:>8} {d:>12.3} {d:>12.3}\n", .{ "= total", total.files, gb(total.alloc), gb(total.apparent) });

    if (segs.items.len > 0) {
        try w.print("\n{s:>8} {s:<10} {s:>12} {s:>12} {s:>12} {s:>7} {s:>9} {s:>22}\n", .{ "segment", "format", "allocated GB", "apparent GB", "logical GB", "ratio", "chunks", "codec 0/1/2/3 (stored/zstd/elided/dict)" });
        var la: u64 = 0;
        var ll: u64 = 0;
        for (segs.items) |sg| {
            const ratio = if (sg.alloc == 0) 0 else @as(f64, @floatFromInt(sg.logical)) / @as(f64, @floatFromInt(sg.alloc));
            la += sg.alloc;
            ll += sg.logical;
            if (sg.compressed) {
                try w.print("{d:>8} {s:<10} {d:>12.3} {d:>12.3} {d:>12.3} {d:>7.3} {d:>9} {d:>10}/{d}/{d}/{d}\n", .{ sg.epoch, "compressed", gb(sg.alloc), gb(sg.apparent), gb(sg.logical), ratio, sg.chunks, sg.codec[0], sg.codec[1], sg.codec[2], sg.codec[3] });
            } else {
                try w.print("{d:>8} {s:<10} {d:>12.3} {d:>12.3} {d:>12.3} {d:>7.3}\n", .{ sg.epoch, "raw", gb(sg.alloc), gb(sg.apparent), gb(sg.logical), ratio });
            }
        }
        try w.print("{s:>8} {s:<10} {d:>12.3} {s:>12} {d:>12.3} {d:>7.3}\n", .{ "all", "", gb(la), "", gb(ll), if (la == 0) 0 else @as(f64, @floatFromInt(ll)) / @as(f64, @floatFromInt(la)) });
        try w.print("(logical of a compressed segment: what its dir file covers; frames written after the last dir append are not counted)\n", .{});
    }
    return 0;
}

const nkinds = 11;

fn kindName(k: usize) []const u8 {
    return switch (k) {
        1 => "segment",
        2 => "checkpoint",
        3 => "tx",
        4 => "object",
        5 => "remove",
        6 => "commit",
        7 => "object_c",
        8 => "link",
        9 => "xref",
        10 => "hole",
        else => "padding/other",
    };
}

/// `--kinds`: logical bytes by record kind over the first `sample` logical bytes of a segment,
/// with each chunk's physical bytes shared out by its kinds' logical bytes.
fn kinds(gpa: std.mem.Allocator, io: Io, root: Io.Dir, w: *Io.Writer, epoch: u64, sample: u64) !u8 {
    var nb: [64]u8 = undefined;
    const sname = try std.fmt.bufPrint(&nb, "store/seg/{d:0>8}.log", .{epoch});
    const f = root.openFile(io, sname, .{}) catch |e| {
        try w.print("du: cannot open {s}: {s}\n", .{ sname, @errorName(e) });
        return 1;
    };
    defer f.close(io);
    var side: ?Io.File = blk: {
        var sb: [64]u8 = undefined;
        const n = std.fmt.bufPrint(&sb, "store/index/{d:0>8}.side", .{epoch}) catch break :blk null;
        break :blk root.openFile(io, n, .{}) catch null;
    };
    defer if (side) |*s| s.close(io);
    var magic: [8]u8 = @splat(0);
    _ = try f.readPositionalAll(io, &magic, 0);
    const compressed = std.mem.eql(u8, &magic, chunk.file_magic);

    var recs: [nkinds]u64 = @splat(0);
    var logical: [nkinds]u64 = @splat(0);
    var phys: [nkinds]f64 = @splat(0);
    var codecs: [chunk.max_codec + 1]u64 = @splat(0);
    var bad_frames: u64 = 0;
    var total_logical: u64 = 0;
    var total_phys: u64 = 0;

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(gpa);

    if (compressed) {
        var db: [64]u8 = undefined;
        const dname = try std.fmt.bufPrint(&db, "store/index/{d:0>8}.dir", .{epoch});
        const img = root.readFileAlloc(io, dname, gpa, .unlimited) catch |e| {
            try w.print("du: {s}: {s} (the dir file is needed for --kinds)\n", .{ dname, @errorName(e) });
            return 1;
        };
        defer gpa.free(img);
        var ents: std.ArrayList(chunk.Entry) = .empty;
        defer ents.deinit(gpa);
        _ = try chunk.trustedPrefix(img, epoch, std.math.maxInt(u64), &ents, gpa);
        // History dictionaries (codec 3 frames).
        const dicts = try chunk.Dicts.create(gpa);
        defer dicts.destroy(gpa);
        zd: {
            var zb: [64]u8 = undefined;
            const zname = std.fmt.bufPrint(&zb, "store/index/{d:0>8}.zd", .{epoch}) catch break :zd;
            const zimg = root.readFileAlloc(io, zname, gpa, .unlimited) catch break :zd;
            defer gpa.free(zimg);
            _ = try chunk.dictsTrusted(zimg, epoch, dicts, gpa);
        }
        for (ents.items) |en| {
            if (en.ls >= sample) break;
            try raw.resize(gpa, chunk.frame_len + en.bl);
            const src: Io.File = if (chunk.isSide(en.phys)) (side orelse {
                bad_frames += 1;
                continue;
            }) else f;
            _ = src.readPositionalAll(io, raw.items, en.phys & ~chunk.side_bit) catch {
                bad_frames += 1;
                continue;
            };
            // Age-out may have moved this chunk to the sidecar (the age log says where); a frame
            // that no longer checks here is counted and skipped.
            const ce = chunk.checkFrame(en.phys & ~chunk.side_bit, raw.items) catch {
                bad_frames += 1;
                continue;
            };
            try buf.resize(gpa, ce.ll);
            chunk.decode(ce, epoch, dicts, raw.items[chunk.frame_len..][0..ce.bl], buf.items) catch {
                bad_frames += 1;
                continue;
            };
            codecs[@min(chunk.codecOf(ce.codec), chunk.max_codec)] += 1;
            const span = chunk.frameSpan(ce.bl);
            total_phys += span;
            total_logical += ce.ll;
            var per: [nkinds]u64 = @splat(0);
            tally(buf.items, &recs, &per);
            for (0..nkinds) |k| {
                logical[k] += per[k];
                phys[k] += @as(f64, @floatFromInt(span)) * @as(f64, @floatFromInt(per[k])) / @as(f64, @floatFromInt(@max(ce.ll, 1)));
            }
        }
    } else {
        const size = (try f.stat(io)).size;
        const n: usize = @intCast(@min(size, sample));
        try buf.resize(gpa, n);
        _ = try f.readPositionalAll(io, buf.items, 0);
        var per: [nkinds]u64 = @splat(0);
        tally(buf.items, &recs, &per);
        for (0..nkinds) |k| {
            logical[k] += per[k];
            phys[k] += @floatFromInt(per[k]);
        }
        total_logical = n;
        total_phys = n;
    }

    try w.print("segment {d} ({s}), first {d} MiB logical: {d} MiB logical in {d} MiB physical (ratio {d:.3}); chunks by codec 0/1/2/3: {d}/{d}/{d}/{d}; frames skipped {d}\n\n", .{
        epoch,                       if (compressed) "compressed" else "raw", sample >> 20, total_logical >> 20, total_phys >> 20,
        @as(f64, @floatFromInt(total_logical)) / @as(f64, @floatFromInt(@max(total_phys, 1))),
        codecs[0],                   codecs[1],                               codecs[2], codecs[3], bad_frames,
    });
    try w.print("{s:<14} {s:>12} {s:>12} {s:>8} {s:>14} {s:>8}\n", .{ "kind", "records", "logical MiB", "avg B", "est. phys MiB", "share" });
    for (0..nkinds) |k| {
        if (logical[k] == 0) continue;
        const pm = phys[k] / 1048576.0;
        try w.print("{s:<14} {d:>12} {d:>12.1} {d:>8} {d:>14.1} {d:>7.1}%\n", .{
            kindName(k),
            recs[k],
            @as(f64, @floatFromInt(logical[k])) / 1048576.0,
            if (recs[k] == 0) 0 else logical[k] / recs[k],
            pm,
            100.0 * phys[k] / @as(f64, @floatFromInt(@max(total_phys, 1))),
        });
    }
    return 0;
}

/// Adds the records of the logical bytes `d` (whole records from a record boundary; group
/// padding and anything that does not parse counts as kind 0) to `recs` and `per`.
fn tally(d: []const u8, recs: *[nkinds]u64, per: *[nkinds]u64) void {
    var p: usize = 0;
    while (p + format.short_len <= d.len) {
        const h = format.short(d[p..]);
        const k: usize = @intFromEnum(h.kind);
        if (k == 0 or k >= nkinds) {
            // Padding up to the next 4096 boundary (a raw segment's group end), then go on.
            const next = std.mem.alignForward(usize, p + 1, format.block);
            per[0] += @min(next, d.len) - p;
            p = next;
            continue;
        }
        const n = format.lenOf(h.kind, h.size);
        if (n > d.len - p) {
            per[0] += d.len - p;
            return;
        }
        recs[k] += 1;
        per[k] += n;
        p += n;
    }
    per[0] += d.len -| p;
}

test "du: classify" {
    try std.testing.expectEqual(Comp.seg, classify("store/seg/00001304.log"));
    try std.testing.expectEqual(Comp.dir, classify("store/index/00001304.dir"));
    try std.testing.expectEqual(Comp.dicts, classify("store/index/00001304.zd"));
    try std.testing.expectEqual(Comp.live, classify("store/index/live-00000002.tbl"));
    try std.testing.expectEqual(Comp.journal, classify("store/index/live.jnl"));
    try std.testing.expectEqual(Comp.runs, classify("store/index/00001304-0000.run"));
    try std.testing.expectEqual(Comp.store_other, classify("store/meta"));
    try std.testing.expectEqual(Comp.state_index, classify("state-index/index/139.tbl"));
    try std.testing.expectEqual(Comp.node, classify("node/spool/1.chk"));
    try std.testing.expectEqual(Comp.other, classify("trust/x"));
}
