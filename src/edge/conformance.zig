//! Edge lane suite `edge-feed` (docs/EDGE.md): for every corpus checkpoint, the feed a core would
//! send (built from the blob's own ranges: summary, contents, per transaction the envelope,
//! effects, events and output objects) goes through encode, decode, plain and dictionary zstd
//! frames and `toBlob`, and the rebuilt blob must (1) index with the same ranges, byte for byte,
//! in every part an edge keeps, (2) have empty input objects, (3) pass the output-object check
//! against its effects, and (4) hash to the summary's contents digest. That is what the follower
//! checks first on an edge, so a pass here means a feed loses nothing verification needs.
//! There is no Mysten side: the feed is deepwave's own format, the corpus is the truth for the bytes.
const std = @import("std");
const harness = @import("harness");
const types = @import("types");
const hash = @import("hash");
const checkpoint = @import("checkpoint");
const edgewire = @import("edgewire");
const feed = edgewire.feed;
const dict = edgewire.dict;
const index = types.index;

pub const suites = [_]harness.Suite{
    .{
        .name = "edge-feed",
        .lane = "edge",
        .doc = "corpus checkpoint -> edge feed -> zstd (plain and dictionary) -> rebuilt blob: same parts, empty inputs, outputs verify against effects",
        .run = run,
    },
};

const max_blob = 1 << 30;

const hist_len = 8;

/// The last few feeds a worker saw (page-allocator copies), newest replaces oldest.
const Hist = struct {
    slots: [hist_len]?[]u8 = @splat(null),
    at: usize = 0,

    fn push(h: *Hist, b: []const u8) void {
        const copy = std.heap.page_allocator.dupe(u8, b[0..@min(b.len, 64 << 10)]) catch return;
        if (h.slots[h.at]) |old| std.heap.page_allocator.free(old);
        h.slots[h.at] = copy;
        h.at = (h.at + 1) % hist_len;
    }
};
threadlocal var tl_hist: Hist = .{};

threadlocal var tl_a: ?*index.CheckpointIndex = null;
threadlocal var tl_b: ?*index.CheckpointIndex = null;

fn scratchIndex(slot: *?*index.CheckpointIndex) !*index.CheckpointIndex {
    if (slot.* == null) {
        const p = try std.heap.page_allocator.create(index.CheckpointIndex);
        p.* = try index.CheckpointIndex.init(std.heap.page_allocator);
        slot.* = p;
    }
    return slot.*.?;
}

/// Bytes over the whole run: full blobs, raw feeds, plain zstd frames. And, like a core that keeps
/// ONE dictionary for the life of the process (edgefeed.zig), only for the checkpoints after a
/// worker's dictionary exists: their raw feeds, plain frames and dictionary frames. The dictionary
/// is built once per worker from its first `hist_len` feeds and never rebuilt, so the gain it
/// reports is the one a long-running core gets, not that of a fresh sample per checkpoint.
var sum_blob = std.atomic.Value(u64).init(0);
var sum_feed = std.atomic.Value(u64).init(0);
var sum_plain = std.atomic.Value(u64).init(0);
var sum_feed_d = std.atomic.Value(u64).init(0);
var sum_plain_d = std.atomic.Value(u64).init(0);
var sum_dict = std.atomic.Value(u64).init(0);
threadlocal var tl_dict: ?dict.Dictionary = null;

fn run(ctx: *harness.Ctx) !void {
    try ctx.forEachFile("chk", ".chk", {}, file);
    const b = sum_blob.load(.monotonic);
    if (b == 0) return;
    try ctx.stdout.print("edge-feed bytes: blobs {d}, feeds {d} ({d:.1}% of blobs), plain zstd {d} ({d:.1}%)\n", .{
        b,
        sum_feed.load(.monotonic),
        100.0 * @as(f64, @floatFromInt(sum_feed.load(.monotonic))) / @as(f64, @floatFromInt(b)),
        sum_plain.load(.monotonic),
        100.0 * @as(f64, @floatFromInt(sum_plain.load(.monotonic))) / @as(f64, @floatFromInt(b)),
    });
    const fd = sum_feed_d.load(.monotonic);
    if (fd == 0) return;
    const pd = sum_plain_d.load(.monotonic);
    const dd = sum_dict.load(.monotonic);
    try ctx.stdout.print("with one dictionary per worker (first {d} feeds, never rebuilt), on the checkpoints after it: feeds {d}, plain zstd {d} ({d:.1}% of feeds), dictionary zstd {d} ({d:.1}% of feeds, {d:.1}% smaller than plain)\n", .{
        hist_len,
        fd,
        pd,
        100.0 * @as(f64, @floatFromInt(pd)) / @as(f64, @floatFromInt(fd)),
        dd,
        100.0 * @as(f64, @floatFromInt(dd)) / @as(f64, @floatFromInt(fd)),
        100.0 * (1.0 - @as(f64, @floatFromInt(dd)) / @as(f64, @floatFromInt(pd))),
    });
}

fn file(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const item = name[0 .. name.len - ".chk".len];
    var c = ctx.check(item);
    defer _ = c.finish();
    const a = ctx.scratch();
    const blob = ctx.readFile(try std.fmt.allocPrint(a, "chk/{s}", .{name}), max_blob) catch |e| return c.failf("read: {s}", .{@errorName(e)});
    const ia = try scratchIndex(&tl_a);
    index.indexCheckpointData(blob, ia) catch |e| return c.failf("index: {s}", .{@errorName(e)});

    // the feed a core builds
    const txs = try a.alloc(feed.TxIn, ia.tx_count);
    for (txs, 0..) |*t, i| {
        const x = ia.txAt(i);
        const objs = try a.alloc([]const u8, x.out_count);
        for (objs, ia.objs[x.out_first..][0..x.out_count]) |*o, r| o.* = r.slice(blob);
        t.* = .{ .tx = x.transaction.slice(blob), .effects = x.effects.slice(blob), .events = if (x.events) |e| e.slice(blob) else null, .objects = objs };
    }
    var raw: std.ArrayList(u8) = .empty;
    try feed.encode(&raw, a, 0, blob[ia.summary.o .. ia.sig.o + ia.sig.n], ia.contents.slice(blob), txs);

    // through the frames: plain, and with a dictionary sampled from earlier feeds
    const plain = try dict.compress(a, null, raw.items);
    const back0 = try dict.decompress(a, null, plain);
    c.bytes("plain zstd frame", raw.items, back0);
    // One dictionary per worker, built once from the first `hist_len` feeds it saw and kept (a
    // core's dictionary lives as long as its process). Checkpoints after that are compressed with
    // it; before that there is none, and they only go through the plain frame.
    const hist = &tl_hist;
    if (tl_dict == null and hist.slots[hist_len - 1] != null) {
        var samples: [hist_len][]const u8 = undefined;
        for (hist.slots, 0..) |m, i| samples[i] = m.?;
        const dc = try dict.build(a, &samples, dict.default_dict);
        tl_dict = dict.Dictionary.init(std.heap.page_allocator, dc, 3) catch |e| return c.failf("dictionary: {s}", .{@errorName(e)});
    }
    var wire = plain;
    if (tl_dict) |*d| {
        const dframe = try dict.compress(a, d, raw.items);
        const back1 = try dict.decompress(a, d, dframe);
        c.bytes("dictionary zstd frame", raw.items, back1);
        _ = sum_feed_d.fetchAdd(raw.items.len, .monotonic);
        _ = sum_plain_d.fetchAdd(plain.len, .monotonic);
        _ = sum_dict.fetchAdd(dframe.len, .monotonic);
        wire = dframe;
    }
    hist.push(raw.items);
    _ = sum_blob.fetchAdd(blob.len, .monotonic);
    _ = sum_feed.fetchAdd(raw.items.len, .monotonic);
    _ = sum_plain.fetchAdd(plain.len, .monotonic);
    const back_final = if (tl_dict) |*d| try dict.decompress(a, d, wire) else back0;

    var f = feed.decode(a, back_final) catch |e| return c.failf("decode: {s}", .{@errorName(e)});
    var blob2: std.ArrayList(u8) = .empty;
    try feed.toBlob(&blob2, a, &f);
    const ib = try scratchIndex(&tl_b);
    index.indexCheckpointData(blob2.items, ib) catch |e| return c.failf("rebuilt blob does not index: {s}", .{@errorName(e)});

    c.bytes("summary", ia.summary.slice(blob), ib.summary.slice(blob2.items));
    c.bytes("signature", ia.sig.slice(blob), ib.sig.slice(blob2.items));
    c.bytes("contents", ia.contents.slice(blob), ib.contents.slice(blob2.items));
    if (ia.tx_count != ib.tx_count) return c.failf("tx count {d} vs {d}", .{ ia.tx_count, ib.tx_count });
    for (0..ia.tx_count) |i| {
        const x = ia.txAt(i);
        const y = ib.txAt(i);
        if (!std.mem.eql(u8, x.transaction.slice(blob), y.transaction.slice(blob2.items))) return c.failf("tx {d}: envelope differs", .{i});
        if (!std.mem.eql(u8, x.effects.slice(blob), y.effects.slice(blob2.items))) return c.failf("tx {d}: effects differ", .{i});
        const ex = if (x.events) |e| e.slice(blob) else null;
        const ey = if (y.events) |e| e.slice(blob2.items) else null;
        if ((ex == null) != (ey == null) or (ex != null and !std.mem.eql(u8, ex.?, ey.?))) return c.failf("tx {d}: events differ", .{i});
        if (y.in_count != 0) return c.failf("tx {d}: rebuilt blob has input objects", .{i});
        if (x.out_count != y.out_count) return c.failf("tx {d}: output count {d} vs {d}", .{ i, x.out_count, y.out_count });
        for (0..x.out_count) |k| {
            const p = ia.objs[x.out_first + k].slice(blob);
            const q = ib.objs[y.out_first + k].slice(blob2.items);
            if (!std.mem.eql(u8, p, q)) return c.failf("tx {d}: output object {d} differs", .{ i, k });
        }
    }

    // what the follower runs first
    var chk = checkpoint.ObjectChecker.init(std.heap.page_allocator);
    defer chk.deinit();
    const v = try chk.verifyOutputObjects(ib, blob2.items);
    if (v != .ok) c.failf("rebuilt blob: output objects against effects: {s}", .{@tagName(v)});
    const cd = hash.blake2b256(&.{ "CheckpointContents::", ib.contents.slice(blob2.items) });
    const summary = try @import("bcs").decode(types.CheckpointSummary, a, ib.summary.slice(blob2.items));
    c.bytes("contents digest", &summary.content_digest.@"0".@"0", &cd);
}
