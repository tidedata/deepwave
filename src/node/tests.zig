//! Unit tests of the node lane (trust, source, convert, history, snapshot, execute-mode gas price).
//! Tests that need the corpus (`$ZUI_CORPUS`) skip without it.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const store = @import("store");
const types = @import("types");
const protocol = @import("protocol");
const exec = @import("exec");
const sync = @import("sync");
const trust = @import("trust.zig");
const source_mod = @import("source.zig");
const convert = @import("convert.zig");
const history = @import("history.zig");
const snapshot = @import("snapshot.zig");
const execute = @import("execute.zig");
const lhfill = @import("lhfill.zig");
const removal_log = @import("removal_log.zig");
const lhist = @import("history");
const p2p_exec = @import("p2p_exec.zig");
const sigorder = @import("sigorder.zig");
const netguard = @import("netguard.zig");
const bcs = @import("bcs");
const statehash = @import("statehash.zig");
const sig = @import("sig");

fn corpus() ?[]const u8 {
    const p = std.c.getenv("ZUI_CORPUS") orelse return null;
    return std.mem.span(p);
}

fn tmpPath(tmp: *testing.TmpDir, buf: []u8) ![]const u8 {
    const n = try tmp.dir.realPath(testing.io, buf);
    return buf[0..n];
}

fn readCorpus(gpa: std.mem.Allocator, rel: []const u8) ![]u8 {
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&pb, "{s}/{s}", .{ c, rel });
    return Io.Dir.cwd().readFileAlloc(testing.io, path, gpa, .limited(1 << 30)) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
}

// ------------------------------------------------------------------ trust

test "trust: epoch file round trip, with and without epoch parameters" {
    // `.iterate`: trust.save fsyncs the directory, which fails with EBADF on Linux's O_PATH handles
    // (the node opens its epochs dir the same way).
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const keys = [_][96]u8{ @splat(1), @splat(2) };
    const stakes = [_]u64{ 7, 9 };
    const e: trust.EpochInfo = .{ .epoch = 41, .protocol_version = 140, .keys = &keys, .stakes = &stakes, .rgp = 100, .start_ms = 1794009944668 };
    try trust.save(testing.io, tmp.dir, &e);
    const got = (try trust.load(a, testing.io, tmp.dir, 41)).?;
    try testing.expectEqual(@as(u64, 140), got.protocol_version);
    try testing.expectEqualSlices([96]u8, &keys, got.keys);
    try testing.expectEqualSlices(u64, &stakes, got.stakes);
    try testing.expectEqual(@as(?u64, 100), got.rgp);
    try testing.expectEqual(@as(?u64, 1794009944668), got.start_ms);
    // Round 1 files carry no rgp/start_ms.
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "42.json", .data = "{\"epoch\":42,\"pv\":141,\"keys\":[],\"stakes\":[]}\n" });
    const old = (try trust.load(a, testing.io, tmp.dir, 42)).?;
    try testing.expectEqual(@as(?u64, null), old.rgp);
    // A file whose epoch does not match its name is refused.
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "43.json", .data = "{\"epoch\":44,\"pv\":141,\"keys\":[],\"stakes\":[]}\n" });
    try testing.expectError(error.BadEpochFile, trust.load(a, testing.io, tmp.dir, 43));
    try testing.expectEqual(@as(?trust.EpochInfo, null), try trust.load(a, testing.io, tmp.dir, 99));
    const hs = (try trust.highestSaved(a, testing.io, tmp.dir, 43)).?;
    try testing.expectEqual(@as(u64, 42), hs.epoch);
}

fn corpusWalker(gpa: std.mem.Allocator, a: std.mem.Allocator, src: *const source_mod.Source, srcs: *[1]*const source_mod.Source) !trust.Walker {
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    srcs[0] = src;
    var w: trust.Walker = .{ .gpa = gpa, .io = testing.io, .sources = srcs, .log = false };
    w.index = try trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c}));
    return w;
}

test "trust: walk from genesis; a wrong end-of-epoch hint fails instead of planting a committee" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    const chk = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk.close(testing.io);
    const src: source_mod.Source = .{ .gpa = gpa, .io = testing.io, .kind = .{ .dir = chk } };
    var srcs: [1]*const source_mod.Source = undefined;
    var w = try corpusWalker(gpa, a, &src, &srcs);
    const genesis = try readCorpus(gpa, "vectors/bls-cert/upstream/genesis.blob");
    defer gpa.free(genesis);
    const good = try w.walk(a, genesis, null, 5, std.math.maxInt(u64));
    try testing.expectEqual(@as(u64, 5), good.epoch);
    try testing.expect(good.keys.len > 0);
    try testing.expect(good.start_ms != null);
    // Point epoch 2's end at epoch 3's end: the certificate is checked with committee 2 and the
    // summary's epoch must be 2, so the walk fails.
    const last = try a.dupe(?u64, w.index.last);
    last[2] = last[3];
    w.index.last = last;
    try testing.expectError(error.UntrustedCheckpoint, w.walk(a, genesis, null, 5, std.math.maxInt(u64)));
}

test "trust: a parallel prefetch walk equals the serial walk, and a wrong hint still fails" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    const chk = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk.close(testing.io);
    const src: source_mod.Source = .{ .gpa = gpa, .io = testing.io, .kind = .{ .dir = chk } };
    var srcs: [1]*const source_mod.Source = undefined;
    var w = try corpusWalker(gpa, a, &src, &srcs);
    const genesis = try readCorpus(gpa, "vectors/bls-cert/upstream/genesis.blob");
    defer gpa.free(genesis);
    const target: u64 = @min(200, w.index.last.len);
    const serial = try w.walk(a, genesis, null, target, std.math.maxInt(u64));
    w.parallel = 8;
    const par = try w.walk(a, genesis, null, target, std.math.maxInt(u64));
    try testing.expectEqual(serial.epoch, par.epoch);
    try testing.expectEqual(serial.protocol_version, par.protocol_version);
    try testing.expectEqualSlices([96]u8, serial.keys, par.keys);
    try testing.expectEqualSlices(u64, serial.stakes, par.stakes);
    try testing.expectEqual(serial.rgp, par.rgp);
    try testing.expectEqual(serial.start_ms, par.start_ms);
    // Resumed from a saved committee (a short walk) gives the same answer.
    const mid = try w.walk(a, genesis, null, target / 2, std.math.maxInt(u64));
    const resumed = try w.walk(a, genesis, mid, target, std.math.maxInt(u64));
    try testing.expectEqualSlices([96]u8, serial.keys, resumed.keys);
    // A wrong hint in the prefetched range: the certificate is still checked in order.
    const last = try a.dupe(?u64, w.index.last);
    last[40] = last[41];
    w.index.last = last;
    try testing.expectError(error.UntrustedCheckpoint, w.walk(a, genesis, null, target, std.math.maxInt(u64)));
}

test "trust: epoch parameters of every corpus end-of-epoch checkpoint equal the epoch index" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    const L = struct { epoch: u64, last: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };
    const text = try readCorpus(gpa, "epochs.jsonl");
    defer gpa.free(text);
    var lines: std.ArrayList(L) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        try lines.append(a, try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true }));
    }
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var checked: usize = 0;
    var no_event: usize = 0;
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    // Every epoch change in the corpus index (epochs.jsonl comes from Mysten's RPC).
    for (lines.items[0 .. lines.items.len - 1], 0..) |l, i| {
        const next = lines.items[i + 1];
        const last = l.last orelse continue;
        const blob = Io.Dir.cwd().readFileAlloc(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk/{d}.chk", .{ c, last }), gpa, .limited(1 << 30)) catch continue;
        defer gpa.free(blob);
        _ = tmp.reset(.retain_capacity);
        const p = try trust.epochParamsOfBlob(tmp.allocator(), blob, &idx);
        try testing.expectEqual(next.start_ms, p.start_ms);
        // No SystemEpochInfoEvent (safe mode): the node keeps the previous epoch's price.
        try testing.expectEqual(next.rgp, p.rgp orelse l.rgp);
        if (p.rgp == null) no_event += 1;
        checked += 1;
    }
    try testing.expect(checked > 1000);
    try testing.expect(no_event < 4);
}

// ------------------------------------------------------------------ source

test "source: latest() finds the highest sequence by doubling and bisection" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var nb: [32]u8 = undefined;
    for (1000..1138) |s| try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.chk", .{s}), .data = "" });
    const src: source_mod.Source = .{ .gpa = testing.allocator, .io = testing.io, .kind = .{ .dir = tmp.dir } };
    try testing.expectEqual(@as(u64, 1137), try src.latest(1000));
    try testing.expectEqual(@as(u64, 1137), try src.latest(1137));
    try testing.expectError(error.SourceMissing, src.latest(999));
    try testing.expect(!source_mod.isTransient(error.WrongCheckpoint));
    try testing.expect(!source_mod.isTransient(error.BadData));
    try testing.expect(source_mod.isTransient(error.ConnectionResetByPeer));
}

test "source: a fetcher that falls behind the tip fetches in parallel again" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var nb: [32]u8 = undefined;
    for (100..400) |s| try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.chk", .{s}), .data = "x" });
    try tmp.dir.createDir(testing.io, "spool", .default_dir);
    const spool = try tmp.dir.openDir(testing.io, "spool", .{ .iterate = true });
    defer spool.close(testing.io);
    const src: source_mod.Source = .{ .gpa = testing.allocator, .io = testing.io, .kind = .{ .dir = tmp.dir } };
    var applied: std.atomic.Value(u64) = .init(100);
    var f: source_mod.Fetcher = .{ .gpa = testing.allocator, .io = testing.io, .source = &src, .spool = spool, .next = .init(100), .applied_next = &applied, .window = 1000, .poll_ms = 1, .to = 399 };
    // As after a miss at the tip: one poller at a time.
    f.frontier.store(100, .release);
    try f.start(4);
    var waited: u32 = 0;
    while (f.stats.fetched.load(.acquire) < 300 and waited < 5000) : (waited += 1) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    f.stop();
    try testing.expectEqual(@as(u64, 300), f.stats.fetched.load(.acquire));
    try testing.expectEqual(@as(u64, 0), f.stats.misses.load(.acquire));
    try testing.expect(f.stats.behind.load(.acquire) >= 1);
    try testing.expectEqual(std.math.maxInt(u64), f.frontier.load(.acquire));
}

test "source: at the tip, a burst of checkpoints is fetched by lookahead tries, and every checkpoint arrives once" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var nb: [32]u8 = undefined;
    try tmp.dir.createDir(testing.io, "spool", .default_dir);
    const spool = try tmp.dir.openDir(testing.io, "spool", .{ .iterate = true });
    defer spool.close(testing.io);
    const src: source_mod.Source = .{ .gpa = testing.allocator, .io = testing.io, .kind = .{ .dir = tmp.dir } };
    var applied: std.atomic.Value(u64) = .init(100);
    var f: source_mod.Fetcher = .{ .gpa = testing.allocator, .io = testing.io, .source = &src, .spool = spool, .next = .init(100), .applied_next = &applied, .window = 1000, .poll_ms = 2, .to = 159, .lookahead = 4, .behind_hits = 1000 };
    try f.start(6);
    // The source publishes in bursts of 6 every 20 ms; the node is at the tip throughout.
    var s: u64 = 100;
    while (s < 160) : (s += 6) {
        for (s..s + 6) |q| try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.chk", .{q}), .data = "x" });
        testing.io.sleep(.fromMilliseconds(20), .awake) catch {};
    }
    var waited: u32 = 0;
    while (f.stats.fetched.load(.acquire) < 60 and waited < 5000) : (waited += 1) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    f.stop();
    try testing.expectEqual(@as(u64, 60), f.stats.fetched.load(.acquire));
    for (100..160) |q| _ = try spool.statFile(testing.io, try std.fmt.bufPrint(&nb, "{d}.chk", .{q}), .{});
    // Bursts were fetched in parallel, not one request at a time.
    try testing.expect(f.stats.lookahead_hits.load(.acquire) > 0);
}

test "source: a frontier left on an already fetched checkpoint moves on" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var nb: [32]u8 = undefined;
    for (100..400) |s| try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.chk", .{s}), .data = "x" });
    try tmp.dir.createDir(testing.io, "spool", .default_dir);
    const spool = try tmp.dir.openDir(testing.io, "spool", .{ .iterate = true });
    defer spool.close(testing.io);
    // 150 and 151 were fetched by requests that returned before an earlier miss lowered the
    // frontier; that miss's own hit then left the frontier on 150, which no thread owns.
    for (150..152) |s| try spool.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.chk", .{s}), .data = "x" });
    const src: source_mod.Source = .{ .gpa = testing.allocator, .io = testing.io, .kind = .{ .dir = tmp.dir } };
    var applied: std.atomic.Value(u64) = .init(140);
    var f: source_mod.Fetcher = .{ .gpa = testing.allocator, .io = testing.io, .source = &src, .spool = spool, .next = .init(152), .applied_next = &applied, .window = 1000, .poll_ms = 1, .to = 399 };
    f.frontier.store(150, .release);
    try f.start(4);
    var waited: u32 = 0;
    while (f.stats.fetched.load(.acquire) < 248 and waited < 5000) : (waited += 1) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    f.stop();
    try testing.expectEqual(@as(u64, 248), f.stats.fetched.load(.acquire));
}

// ------------------------------------------------------------------ convert

fn pbField(out: *std.ArrayList(u8), gpa: std.mem.Allocator, num: u32, payload: []const u8) !void {
    try pbVarint(out, gpa, (@as(u64, num) << 3) | 2);
    try pbVarint(out, gpa, payload.len);
    try out.appendSlice(gpa, payload);
}
fn pbVarint(out: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u64) !void {
    var x = v;
    while (x >= 0x80) : (x >>= 7) try out.append(gpa, @as(u8, @truncate(x)) | 0x80);
    try out.append(gpa, @truncate(x));
}
/// A `Bcs`-holder message: field 1 = Bcs { value = 2 }.
fn holder(gpa: std.mem.Allocator, value: []const u8) ![]u8 {
    var bcs_msg: std.ArrayList(u8) = .empty;
    defer bcs_msg.deinit(gpa);
    try pbField(&bcs_msg, gpa, 2, value);
    var h: std.ArrayList(u8) = .empty;
    try pbField(&h, gpa, 1, bcs_msg.items);
    return h.toOwnedSlice(gpa);
}

test "convert: repeated scalar and message fields merge like prost" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var p: std.ArrayList(u8) = .empty;
    defer p.deinit(gpa);
    const s1 = try holder(gpa, "first");
    defer gpa.free(s1);
    const s2 = try holder(gpa, "second");
    defer gpa.free(s2);
    try pbField(&p, gpa, 3, s1); // summary
    try pbField(&p, gpa, 3, s2); // summary again: merged, the last bcs value wins
    // signature twice: epoch from the first, bytes from the second (message merge).
    var sig1: std.ArrayList(u8) = .empty;
    defer sig1.deinit(gpa);
    try pbVarint(&sig1, gpa, (1 << 3) | 0);
    try pbVarint(&sig1, gpa, 77);
    var sig2: std.ArrayList(u8) = .empty;
    defer sig2.deinit(gpa);
    try pbField(&sig2, gpa, 2, "sig-bytes");
    try pbField(&p, gpa, 4, sig1.items);
    try pbField(&p, gpa, 4, sig2.items);
    // one transaction whose effects carry two loaded runtime objects
    var refm: std.ArrayList(u8) = .empty;
    defer refm.deinit(gpa);
    try pbField(&refm, gpa, 1, "0x2");
    try pbVarint(&refm, gpa, (2 << 3) | 0);
    try pbVarint(&refm, gpa, 9);
    var eff: std.ArrayList(u8) = .empty;
    defer eff.deinit(gpa);
    try pbField(&eff, gpa, 15, refm.items);
    try pbField(&eff, gpa, 15, refm.items);
    var tx: std.ArrayList(u8) = .empty;
    defer tx.deinit(gpa);
    try pbField(&tx, gpa, 4, eff.items);
    try pbField(&p, gpa, 6, tx.items);
    const parsed = try convert.parse(arena.allocator(), p.items);
    try testing.expectEqualStrings("second", parsed.summary.?);
    try testing.expectEqual(@as(u64, 77), parsed.sig.epoch);
    try testing.expectEqualStrings("sig-bytes", parsed.sig.signature);
    try testing.expectEqual(@as(usize, 1), parsed.txs.items.len);
    try testing.expectEqual(@as(usize, 2), parsed.txs.items[0].loaded.items.len);
}

test "convert: content signatures, V1 with fewer signature lists than transactions, V2 alias versions" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    // V1: 2 transactions, 1 signature list of 1 signature (3 bytes).
    var v1: std.ArrayList(u8) = .empty;
    defer v1.deinit(gpa);
    try v1.appendSlice(gpa, &.{ 0, 2 });
    for (0..4) |_| {
        try v1.append(gpa, 32);
        try v1.appendSlice(gpa, &@as([32]u8, @splat(5)));
    }
    try v1.appendSlice(gpa, &.{ 1, 1, 3, 0xaa, 0xbb, 0xcc });
    const s1 = try convert.contentSignaturesForTest(a, v1.items);
    try testing.expectEqual(@as(usize, 1), s1.len); // zip: min(2 transactions, 1 list)
    try testing.expectEqualSlices(u8, &.{ 1, 3, 0xaa, 0xbb, 0xcc }, s1[0].raw.?);
    // V2: 1 transaction with 2 signatures, one with an alias version (dropped in the envelope).
    var v2: std.ArrayList(u8) = .empty;
    defer v2.deinit(gpa);
    try v2.appendSlice(gpa, &.{ 1, 1 });
    for (0..2) |_| {
        try v2.append(gpa, 32);
        try v2.appendSlice(gpa, &@as([32]u8, @splat(6)));
    }
    try v2.appendSlice(gpa, &.{ 2, 2, 0x11, 0x22, 0 });
    try v2.appendSlice(gpa, &.{ 1, 0x33, 1 });
    try v2.appendSlice(gpa, &@as([8]u8, @splat(0)));
    const s2 = try convert.contentSignaturesForTest(a, v2.items);
    try testing.expectEqual(@as(usize, 1), s2.len);
    try testing.expectEqual(@as(usize, 2), s2[0].parts.len);
    try testing.expectEqualSlices(u8, &.{ 2, 0x11, 0x22 }, s2[0].parts[0]);
    try testing.expectEqualSlices(u8, &.{ 1, 0x33 }, s2[0].parts[1]);
}

test "convert: a source's own signature order is kept only when it is the contents' signatures" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sa = [_]u8{ 0, 0xa1, 0xa2 };
    const sb = [_]u8{ 1, 0xb1 };
    // V1 list [A, B]: count 2, then each signature length-prefixed
    const v1: convert.SigList = .{ .raw = &[_]u8{ 2, 3, 0, 0xa1, 0xa2, 2, 1, 0xb1 } };
    // V2 parts [A, B]
    const v2: convert.SigList = .{ .parts = &.{ &[_]u8{ 3, 0, 0xa1, 0xa2 }, &[_]u8{ 2, 1, 0xb1 } } };
    for ([_]convert.SigList{ v1, v2 }) |s| {
        try testing.expect(try convert.txSignaturesForTest(a, &.{ &sb, &sa }, s)); // sponsor first: kept
        try testing.expect(try convert.txSignaturesForTest(a, &.{ &sa, &sb }, s));
        try testing.expect(!try convert.txSignaturesForTest(a, &.{}, s)); // none rendered: contents
        try testing.expect(!try convert.txSignaturesForTest(a, &.{&sa}, s)); // one missing
        try testing.expect(!try convert.txSignaturesForTest(a, &.{ &sa, &sa }, s)); // not a multiset match
        try testing.expect(!try convert.txSignaturesForTest(a, &.{ &sa, &[_]u8{ 1, 0xb2 } }, s)); // foreign
    }
}

test "convert: aux records of a corpus checkpoint parse, and corrupt ones are refused" {
    const gpa = testing.allocator;
    const z = readCorpus(gpa, "binpb-done/342451160.binpb.zst") catch |e| return e;
    defer gpa.free(z);
    const proto = try convert.unzstd(gpa, z, 1 << 30);
    defer gpa.free(proto);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    // The fetch path's direct decode gives the same bytes.
    try testing.expectEqual(@as(?u64, null), convert.zstdContentSize(z)); // streamed frame
    try testing.expectEqualSlices(u8, proto, try convert.unzstdArena(arena.allocator(), z, 1 << 30));
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    const seq = try convert.protoToChkAux(gpa, arena.allocator(), proto, &blob, &aux);
    try testing.expectEqual(@as(u64, 342451160), seq);
    const x = try convert.Aux.parse(arena.allocator(), aux.items);
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    try types.indexCheckpointData(blob.items, &idx);
    try testing.expectEqual(@as(usize, idx.tx_count), x.loaded.len);
    // The same blob as protoToChk.
    var blob2: std.ArrayList(u8) = .empty;
    defer blob2.deinit(gpa);
    _ = try convert.protoToChk(gpa, arena.allocator(), proto, &blob2);
    try testing.expectEqualSlices(u8, blob2.items, blob.items);
    try testing.expectError(error.BadAux, convert.Aux.parse(arena.allocator(), aux.items[0 .. aux.items.len - 1]));
    try testing.expectError(error.BadAux, convert.Aux.parse(arena.allocator(), "ZUIAUX00"));
}

// ------------------------------------------------------------------ convert: signature order

/// Checkpoint 343111673 from fullnode.mainnet.sui.io's GetCheckpoint with the stream's fields
/// (no objects or events): `sequence_number, summary.bcs, signature, contents.bcs,
/// transactions.transaction.bcs, transactions.effects.bcs, transactions.signatures.bcs`.
/// Transaction 21 (E7yjPX2E3vCrihF1PLvozejauMBSLi6HdgmXZJt9GgwQ) is sponsored and was submitted
/// as [sponsor (secp256k1), sender (ed25519)]; the contents certify [sender, sponsor].
const sigorder_proto = @embedFile("testdata/sigorder-343111673.binpb");
/// sui-node 1.83.1's GetTransaction `signatures` for E7yj... on a production node (2026-11-08), in order.
const sigorder_sui_node = [_][]const u8{
    "014685afc38a32a99b587da789147cd6c389e4cf1ec0bcd798c65b6d2ccf3ebd331d3a212821f129c5bcf06d7fe9c9d3803a09c1f5c273b3e306cd63724b15521d0295e8840129ad8968724518d25f45dfdc29ef7a98efd80799c098df63b9f789fe",
    "0089de0b09a821d278909e89c52ad16c1ddc0e40fc958af7c6297cdda44e3c67fc64fd13a0bab77d11cd62a3cd2849e15e949d20cb41db40bdf937de5d33e87100c0fa2d9c33bf2b110bde70bef8b6a6f3d9d23e2c9bee4a94b48ed512544990a0",
};

fn blobSigs(a: std.mem.Allocator, idx: *types.CheckpointIndex, blob: []const u8, tx: usize) ![]const []const u8 {
    try types.indexCheckpointData(blob, idx);
    const t = idx.txs[tx];
    const out = try a.alloc([]const u8, t.sig_count);
    for (out, idx.sigs[t.sig_first..][0..t.sig_count]) |*o, r| {
        var rd = bcs.Reader.init(r.slice(blob));
        o.* = try rd.bytes(try rd.length());
    }
    return out;
}

test "convert: a full node's transaction signature order is kept when it permutes the certified signatures (sponsored E7yj...)" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var want: [2][]const u8 = undefined;
    for (&want, sigorder_sui_node) |*w, hex| {
        const b = try a.alloc(u8, hex.len / 2);
        _ = try std.fmt.hexToBytes(b, hex);
        w.* = b;
    }

    // Stream proto: sui-node's order (sponsor first).
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    try testing.expectEqual(@as(u64, 343111673), try convert.protoToChk(gpa, a, sigorder_proto, &blob));
    const got = try blobSigs(a, &idx, blob.items, 21);
    try testing.expectEqual(@as(usize, 2), got.len);
    for (want, got) |w, g| try testing.expectEqualSlices(u8, w, g);

    // Contents order (the bucket, or sui-types' conversion): sender first.
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &plain, null, .{ .tx_signature_order = false });
    const certified = try blobSigs(a, &idx, plain.items, 21);
    try testing.expectEqualSlices(u8, want[1], certified[0]);
    try testing.expectEqualSlices(u8, want[0], certified[1]);
    // Same length, and the only bytes that differ are the two signatures of transaction 21.
    try testing.expectEqual(plain.items.len, blob.items.len);
    try types.indexCheckpointData(blob.items, &idx);
    const t21 = idx.txs[21];
    const lo = idx.sigs[t21.sig_first].o;
    const hi = idx.sigs[t21.sig_first + 1].o + idx.sigs[t21.sig_first + 1].n;
    try testing.expectEqualSlices(u8, plain.items[0..lo], blob.items[0..lo]);
    try testing.expectEqualSlices(u8, plain.items[hi..], blob.items[hi..]);
    // Every other transaction keeps the same signatures either way (all equal to the contents').
    for (0..idx.tx_count) |i| {
        if (i == 21) continue;
        const x = try blobSigs(a, &idx, blob.items, i);
        const y = try blobSigs(a, &idx, plain.items, i);
        try testing.expectEqual(x.len, y.len);
        for (x, y) |p, q| try testing.expectEqualSlices(u8, p, q);
    }

    // A proto signature the contents do not certify: the contents order, never the proto's bytes.
    const bad = try a.dupe(u8, sigorder_proto);
    const at = std.mem.lastIndexOf(u8, bad, want[0]).?; // the transaction's copy (after contents)
    bad[at + 10] ^= 1;
    var tampered: std.ArrayList(u8) = .empty;
    defer tampered.deinit(gpa);
    _ = try convert.protoToChk(gpa, a, bad, &tampered);
    try testing.expectEqualSlices(u8, plain.items, tampered.items);
}

// ------------------------------------------------------------------ signature order: bucket overlay

fn pbReadVarint(b: []const u8, i: *usize) !u64 {
    var r: u64 = 0;
    var shift: u6 = 0;
    while (i.* < b.len) {
        const x = b[i.*];
        i.* += 1;
        r |= @as(u64, x & 0x7f) << shift;
        if (x < 0x80) return r;
        if (shift >= 63) return error.Malformed;
        shift += 7;
    }
    return error.Malformed;
}

fn pbPutVarint(a: std.mem.Allocator, out: *std.ArrayList(u8), v_in: u64) !void {
    var v = v_in;
    while (v >= 0x80) : (v >>= 7) try out.append(a, @as(u8, @truncate(v)) | 0x80);
    try out.append(a, @truncate(v));
}

fn pbPutLen(a: std.mem.Allocator, out: *std.ArrayList(u8), field: u64, bytes: []const u8) !void {
    try pbPutVarint(a, out, (field << 3) | 2);
    try pbPutVarint(a, out, bytes.len);
    try out.appendSlice(a, bytes);
}

/// One protobuf field: its number, and the bytes of the whole field (key included) and of a
/// length-delimited payload.
const PbField = struct { number: u64, whole: []const u8, payload: []const u8 };

fn pbFields(a: std.mem.Allocator, b: []const u8) ![]PbField {
    var out: std.ArrayList(PbField) = .empty;
    var i: usize = 0;
    while (i < b.len) {
        const start = i;
        const key = try pbReadVarint(b, &i);
        var payload: []const u8 = &.{};
        switch (key & 7) {
            0 => _ = try pbReadVarint(b, &i),
            1 => i += 8,
            5 => i += 4,
            2 => {
                const n = try pbReadVarint(b, &i);
                payload = b[i..][0..n];
                i += n;
            },
            else => return error.Malformed,
        }
        try out.append(a, .{ .number = key >> 3, .whole = b[start..i], .payload = payload });
    }
    return out.items;
}

/// A Checkpoint proto as Mysten's bucket serves it: every transaction's `signatures` (field 3 of
/// ExecutedTransaction, field 6 of Checkpoint) removed.
fn bucketProto(a: std.mem.Allocator, proto: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (try pbFields(a, proto)) |f| {
        if (f.number != 6) {
            try out.appendSlice(a, f.whole);
            continue;
        }
        var tx: std.ArrayList(u8) = .empty;
        for (try pbFields(a, f.payload)) |tf| if (tf.number != 3) try tx.appendSlice(a, tf.whole);
        try pbPutLen(a, &out, 6, tx.items);
    }
    return out.items;
}

/// What `GetCheckpoint { read_mask: sequence_number, transactions.signatures.bcs }` answers:
/// `seq`, then each transaction with only its signatures (the first `max_tx`).
fn overlayProto(a: std.mem.Allocator, proto: []const u8, seq: u64, max_tx: usize) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try pbPutVarint(a, &out, 1 << 3);
    try pbPutVarint(a, &out, seq);
    var n: usize = 0;
    for (try pbFields(a, proto)) |f| {
        if (f.number != 6) continue;
        if (n == max_tx) break;
        n += 1;
        var tx: std.ArrayList(u8) = .empty;
        for (try pbFields(a, f.payload)) |tf| if (tf.number == 3) try tx.appendSlice(a, tf.whole);
        try pbPutLen(a, &out, 6, tx.items);
    }
    return out.items;
}

test "convert: a bucket checkpoint takes the submitted signature order from a GetCheckpoint signatures overlay" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const seq: u64 = 343111673;

    // sui-node's order (the full node proto as served) and the contents order.
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    _ = try convert.protoToChk(gpa, a, sigorder_proto, &want);
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &plain, null, .{ .tx_signature_order = false });
    try testing.expect(!std.mem.eql(u8, want.items, plain.items));

    const bucket = try bucketProto(a, sigorder_proto);
    // The bucket proto wants an overlay (transaction 21 is sponsored); the full node's does not.
    try testing.expect(try convert.wantsSigOrder(a, bucket));
    try testing.expect(!try convert.wantsSigOrder(a, sigorder_proto));

    // Without an overlay: the contents order (what main stored for bucket-filled checkpoints).
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    _ = try convert.protoToChk(gpa, a, bucket, &got);
    try testing.expectEqualSlices(u8, plain.items, got.items);

    // With the overlay: byte-equal to sui-node's.
    const ov = try overlayProto(a, sigorder_proto, seq, std.math.maxInt(usize));
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = ov });
    try testing.expectEqualSlices(u8, want.items, got.items);
    // The aux record is the same either way.
    var aux_a: std.ArrayList(u8) = .empty;
    defer aux_a.deinit(gpa);
    var aux_b: std.ArrayList(u8) = .empty;
    defer aux_b.deinit(gpa);
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &got, &aux_a, .{});
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, &aux_b, .{ .sig_overlay = ov });
    try testing.expectEqualSlices(u8, aux_a.items, aux_b.items);

    // The option off ignores the overlay (stream-check's comparison).
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = ov, .tx_signature_order = false });
    try testing.expectEqualSlices(u8, plain.items, got.items);

    // An overlay for another checkpoint is ignored.
    const other = try overlayProto(a, sigorder_proto, seq + 1, std.math.maxInt(usize));
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = other });
    try testing.expectEqualSlices(u8, plain.items, got.items);
    try testing.expect(convert.overlaySigsForTest(a, other, seq) == null);

    // A short overlay (transaction 21 missing): the contents order.
    const short = try overlayProto(a, sigorder_proto, seq, 21);
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = short });
    try testing.expectEqualSlices(u8, plain.items, got.items);

    // A signature the contents do not certify: the contents order, never the overlay's bytes.
    const bad = try a.dupe(u8, ov);
    var sui_sig: [200]u8 = undefined;
    const s0 = try std.fmt.hexToBytes(&sui_sig, sigorder_sui_node[0]);
    const at = std.mem.indexOf(u8, bad, s0).?;
    bad[at + 10] ^= 1;
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = bad });
    try testing.expectEqualSlices(u8, plain.items, got.items);

    // Garbage: ignored, the conversion still succeeds.
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = &.{ 0xff, 0xff } });
    try testing.expectEqualSlices(u8, plain.items, got.items);

    // The full node's own list wins over an overlay (the overlay only fills absent lists).
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &got, null, .{ .sig_overlay = other });
    try testing.expectEqualSlices(u8, want.items, got.items);
}

test "source: decodeOrdered asks the stream node for a bucket checkpoint's signature order" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const seq: u64 = 343111673;
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    _ = try convert.protoToChk(gpa, a, sigorder_proto, &want);
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &plain, null, .{ .tx_signature_order = false });

    // The bucket proto in a raw-block zstd frame (single segment, 4-byte content size).
    const bucket = try bucketProto(a, sigorder_proto);
    try testing.expect(bucket.len < 128 << 10);
    var z: std.ArrayList(u8) = .empty;
    try z.appendSlice(a, &.{ 0x28, 0xB5, 0x2F, 0xFD, 0xA0 });
    var fcs: [4]u8 = undefined;
    std.mem.writeInt(u32, &fcs, @intCast(bucket.len), .little);
    try z.appendSlice(a, &fcs);
    const bh: u24 = @intCast(1 | (bucket.len << 3));
    try z.appendSlice(a, &.{ @truncate(bh), @truncate(bh >> 8), @truncate(bh >> 16) });
    try z.appendSlice(a, bucket);

    // The stream node: a grpc-web GetCheckpoint answer carrying the overlay.
    const ov = try overlayProto(a, sigorder_proto, seq, std.math.maxInt(usize));
    var msg: std.ArrayList(u8) = .empty;
    try pbPutLen(a, &msg, 1, ov); // GetCheckpointResponse.checkpoint
    var body: std.ArrayList(u8) = .empty;
    var h: [5]u8 = .{ 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, h[1..5], @intCast(msg.items.len), .big);
    try body.appendSlice(a, &h);
    try body.appendSlice(a, msg.items);
    const trailer = "grpc-status:0\r\n";
    h = .{ 0x80, 0, 0, 0, 0 };
    std.mem.writeInt(u32, h[1..5], trailer.len, .big);
    try body.appendSlice(a, &h);
    try body.appendSlice(a, trailer);
    const reply = try std.fmt.allocPrint(a, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n{s}", .{ body.items.len, body.items });
    var srv: netguard.TestServer = undefined;
    try srv.start(testing.io, reply);
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var o = sigorder.Overlay.init(gpa, testing.io, srv.url(&ub), 20);
    defer o.deinit();

    const src: source_mod.Source = .{ .gpa = gpa, .io = testing.io, .kind = .none };
    var sc = source_mod.Scratch.init(gpa);
    defer sc.deinit(gpa);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    // No overlay configured: the contents order.
    try sc.raw.appendSlice(gpa, z.items);
    try src.decodeOrdered(&sc, seq, &blob, null);
    try testing.expectEqualSlices(u8, plain.items, blob.items);
    // With it: sui-node's order, one request.
    try src.decodeOrdered(&sc, seq, &blob, &o);
    try testing.expectEqualSlices(u8, want.items, blob.items);
    try testing.expectEqual(@as(u64, 1), o.stats.served.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), srv.accepts.load(.monotonic));
    // Over budget: no request, the contents order.
    o.pace = .{ .interval_ns = std.time.ns_per_s * 3600, .burst = 1, .tat = .init(std.math.maxInt(u64) / 2) };
    try src.decodeOrdered(&sc, seq, &blob, &o);
    try testing.expectEqualSlices(u8, plain.items, blob.items);
    try testing.expectEqual(@as(u64, 1), o.stats.throttled.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), srv.accepts.load(.monotonic));
}

test "p2p: a peer's transaction copy is accepted only when its signatures permute the certified ones" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(testing.allocator);
    _ = try convert.protoToChkOpts(testing.allocator, a, sigorder_proto, &blob, null, .{ .tx_signature_order = false });
    var idx = try types.CheckpointIndex.init(testing.allocator);
    defer idx.deinit(testing.allocator);
    try types.indexCheckpointData(blob.items, &idx);
    const t = idx.txs[21];
    const env = t.transaction.slice(blob.items); // [sender, sponsor]: the contents order
    const s0 = idx.sigs[t.sig_first].slice(blob.items);
    const s1 = idx.sigs[t.sig_first + 1].slice(blob.items);
    const head = env[0 .. env.len - s0.len - s1.len - 1];
    // V2 certified list: (signature, None) each.
    const certified = try std.mem.concat(a, u8, &.{ &.{2}, s0, &.{0}, s1, &.{0} });
    const swapped = try std.mem.concat(a, u8, &.{ head, &.{2}, s1, s0 });
    try testing.expect(try p2p_exec.samePermutation(a, env, certified, true));
    try testing.expect(try p2p_exec.samePermutation(a, swapped, certified, true));
    const one = try std.mem.concat(a, u8, &.{ head, &.{1}, s0 });
    try testing.expect(!try p2p_exec.samePermutation(a, one, certified, true));
    const twice = try std.mem.concat(a, u8, &.{ head, &.{2}, s0, s0 });
    try testing.expect(!try p2p_exec.samePermutation(a, twice, certified, true));
    const flipped = try a.dupe(u8, swapped);
    flipped[flipped.len - 5] ^= 1;
    try testing.expect(!try p2p_exec.samePermutation(a, flipped, certified, true));
    // V1 list: no alias versions.
    const v1 = try std.mem.concat(a, u8, &.{ &.{2}, s0, s1 });
    try testing.expect(try p2p_exec.samePermutation(a, swapped, v1, false));
}

// ------------------------------------------------------------------ store: historical records

test "history: a historical version is readable but never live" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 10, .segment_reserve = 1 << 20 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const id: [32]u8 = @splat(1);
    const id2: [32]u8 = @splat(2);
    const d: [32]u8 = @splat(9);
    const b = try h.store.begin(10, 1);
    try b.putObject(&id, 7, &d, "seven");
    try b.putHistorical(&id, 5, &d, "five");
    try b.putHistorical(&id2, 3, &d, "only-historical");
    try h.store.commit(b);
    const b2 = try h.store.begin(11, 1);
    try b2.putHistorical(&id, 6, &d, "six");
    try h.store.commit(b2);
    var snap = h.store.snapshot();
    defer snap.release();
    try testing.expectEqualStrings("seven", snap.liveObject(&id).?.bytes);
    try testing.expectEqualStrings("five", snap.objectAt(&id, 5).?);
    try testing.expectEqualStrings("six", snap.objectAt(&id, 6).?);
    try testing.expect(snap.liveObject(&id2) == null);
    try testing.expectEqualStrings("only-historical", snap.objectAt(&id2, 3).?);
    try testing.expectEqual(@as(u64, 1), h.store.liveCount());
}

fn tKey(bytes: []const u8) ?store.ObjKey {
    if (bytes.len < 40) return null;
    return .{ .id = bytes[0..32].*, .version = std.mem.readInt(u64, bytes[32..40], .little) };
}

fn tObj(buf: []u8, id: u8, version: u64, payload: []const u8) []const u8 {
    buf[0..32].* = @splat(id);
    std.mem.writeInt(u64, buf[32..40], version, .little);
    @memcpy(buf[40..][0..payload.len], payload);
    return buf[0 .. 40 + payload.len];
}

/// What history.onBatch does for one input version of a transaction in `b`'s checkpoint.
fn histInput(st: *store.Store, b: *store.Batch, id: u8, version: u64, consumed: bool, payload: []const u8) !bool {
    var snap = st.snapshot();
    defer snap.release();
    const k: [32]u8 = @splat(id);
    switch (try history.inputAction(&snap, b.epoch, &k, version, consumed)) {
        .present => return false,
        .xref => |target| try b.putXref(&k, version, target),
        .copy => {
            var buf: [128]u8 = undefined;
            const raw = tObj(&buf, id, version, payload);
            try b.putHistorical(&k, version, &store.objectDigest(raw), raw);
        },
    }
    return true;
}

fn putLive(b: *store.Batch, base: bool, id: u8, version: u64, payload: []const u8) !void {
    var buf: [128]u8 = undefined;
    const raw = tObj(&buf, id, version, payload);
    const k: [32]u8 = @splat(id);
    if (base) try b.putBase(&k, version, &store.objectDigest(raw), raw) else try b.putObject(&k, version, &store.objectDigest(raw), raw);
}

test "history: a transaction's input versions stay readable after the epochs that wrote them age out and are cleaned" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 10, .segment_reserve = 1 << 20, .codec = .{ .key = tKey }, .clean_record_bytes = 64 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const st = h.store;
    // Epoch 0: a restored set (compact records: X=1, Y=2, plus 100 others), end-of-epoch checkpoint 10.
    {
        const b = try st.begin(0, 0);
        try putLive(b, true, 1, 3, "x3");
        try putLive(b, true, 2, 3, "y3");
        for (0..100) |i| try putLive(b, true, @intCast(100 + i), 3, "filler-object");
        try st.commit(b);
        const c = try st.begin(10, 0);
        try c.checkpoint("s10", "c");
        try st.commit(c);
    }
    // Epoch 1, checkpoint 11: a transaction mutates X (3 -> 11) and reads Y; creates Z=3.
    {
        const b = try st.begin(11, 1);
        try b.checkpoint("s11", "c");
        try testing.expect(try histInput(st, b, 1, 3, true, "x3")); // superseded here: an xref
        try testing.expect(!try histInput(st, b, 2, 3, false, "y3")); // stays live: no copy
        try putLive(b, false, 1, 11, "x11");
        try putLive(b, false, 3, 11, "z11");
        try st.commit(b);
    }
    // Checkpoint 12 (same epoch): the xref of X@3 is already in epoch 1.
    {
        const b = try st.begin(12, 1);
        try b.checkpoint("s12", "c");
        try testing.expect(!try histInput(st, b, 1, 3, true, "x3"));
        try st.commit(b);
    }
    // Epoch 2, checkpoint 13: mutates Z (written in epoch 1) and Y (restored).
    {
        const b = try st.begin(13, 2);
        try b.checkpoint("s13", "c");
        try testing.expect(try histInput(st, b, 3, 11, true, "z11"));
        try testing.expect(try histInput(st, b, 2, 3, true, "y3"));
        try putLive(b, false, 3, 13, "z13");
        try putLive(b, false, 2, 13, "y13");
        try st.commit(b);
    }
    {
        const b = try st.begin(14, 3);
        try b.checkpoint("s14", "c");
        try st.commit(b);
    }
    // Window 1..3: epoch 0 (the restored segment) ages out. Checkpoint 11's inputs still read.
    _ = try st.ageOut(1);
    {
        var snap = st.snapshot();
        defer snap.release();
        try testing.expectEqualSlices(u8, "x3", snap.objectAt(&@as([32]u8, @splat(1)), 3).?[40..]);
        try testing.expectEqualSlices(u8, "y3", snap.objectAt(&@as([32]u8, @splat(2)), 3).?[40..]);
        try testing.expectEqual(@as(?u64, 11), snap.lowestCheckpoint());
    }
    // Window 2..3: epoch 1 ages out and, being sparse, is cleaned away. Checkpoint 13's inputs
    // (Z@11 was written in epoch 1, Y@3 restored in epoch 0) still read.
    _ = try st.ageOut(2);
    var dropped: u64 = 0;
    var versions: u64 = 0;
    var steps: usize = 0;
    while (true) : (steps += 1) {
        try testing.expect(steps < 1000);
        const r = try st.cleanStep(1 << 16);
        dropped += r.segments_dropped;
        versions += r.versions_carried;
        if (r.idle) break;
    }
    try testing.expectEqual(@as(u64, 1), dropped);
    // Z@11's bytes were only in epoch 1; checkpoint 13's xref (epoch 2) names them: carried.
    try testing.expectEqual(@as(u64, 1), versions);
    try testing.expectEqual(@as(u64, 1), st.agedSegments().count); // the dense restored one
    var snap = st.snapshot();
    defer snap.release();
    try testing.expectEqualSlices(u8, "z11", snap.objectAt(&@as([32]u8, @splat(3)), 11).?[40..]);
    try testing.expectEqualSlices(u8, "y3", snap.objectAt(&@as([32]u8, @splat(2)), 3).?[40..]);
    try testing.expectEqualSlices(u8, "x11", snap.liveObject(&@as([32]u8, @splat(1))).?.bytes[40..]);
    try testing.expect(snap.objectAt(&@as([32]u8, @splat(1)), 3) == null); // its transaction left the window
    // Window 3: checkpoint 13's xrefs leave it, and with them Z@11 (the carried copy keeps its
    // xref's retention, not its own segment's) and Y@3 (still in the dense restored segment).
    _ = try st.ageOut(3);
    var snap3 = st.snapshot();
    defer snap3.release();
    try testing.expect(snap3.objectAt(&@as([32]u8, @splat(3)), 11) == null);
    try testing.expect(snap3.objectAt(&@as([32]u8, @splat(2)), 3) == null);
    try testing.expectEqualSlices(u8, "z13", snap3.liveObject(&@as([32]u8, @splat(3))).?.bytes[40..]);
    try testing.expectEqualSlices(u8, "y13", snap3.liveObject(&@as([32]u8, @splat(2))).?.bytes[40..]);
}

test "snapshot: a snapshot-started store reports lowest available S + 1, like sui-node" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 10, .segment_reserve = 1 << 20 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const st = h.store;
    {
        const b = try st.begin(500, 9); // the restored end-of-epoch checkpoint S = 500, without the record
        try b.checkpoint("s500", "c");
        try st.commit(b);
    }
    {
        var snap = st.snapshot();
        defer snap.release();
        try testing.expectEqual(@as(?u64, 500), snapshot.lowestAvailable(&snap, null));
        try testing.expectEqual(@as(?u64, 501), snapshot.lowestAvailable(&snap, 9)); // marker fallback
        try testing.expectEqual(@as(?u64, 500), snapshot.lowestAvailable(&snap, 8));
    }
    {
        const b = try st.begin(501, 10);
        try b.checkpoint("s501", "c");
        try b.highestPruned(500);
        try st.commit(b);
    }
    var snap = st.snapshot();
    defer snap.release();
    try testing.expectEqual(@as(?u64, 501), snapshot.lowestAvailable(&snap, null));
    try testing.expectEqual(@as(?u64, 501), snapshot.lowestAvailable(&snap, 9));
    try testing.expect(snap.checkpoint(500) != null); // held, but not served
}

test "history: loaded runtime object list layout" {
    const Ref = @import("serve").objset.Ref;
    try testing.expectEqual(@as(usize, history.entry_len), @sizeOf(Ref));
    try testing.expectEqual(@as(usize, 0), @offsetOf(Ref, "version"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(Ref, "id"));
    try testing.expectEqual(@sizeOf(history.LoadedEntry), @sizeOf(Ref));
}

test "history: historical versions stay out of the live set after the store reopens (recovery)" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const path = try tmpPath(&tmp, &pb);
    const id: [32]u8 = @splat(1);
    const id2: [32]u8 = @splat(2);
    const d: [32]u8 = @splat(9);
    {
        var cfg: store.Config = .{ .dir = path, .max_live_objects = 1 << 10, .segment_reserve = 1 << 20 };
        const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .data });
        defer h.io.deinit();
        defer h.store.deinit();
        const b = try h.store.begin(10, 1);
        try b.putObject(&id, 7, &d, "seven");
        try b.putHistorical(&id, 5, &d, "five");
        try b.putHistorical(&id2, 3, &d, "only-historical");
        try h.store.commit(b);
        const b2 = try h.store.begin(11, 1);
        try b2.putHistorical(&id, 9, &d, "nine-historical");
        try h.store.commit(b2);
    }
    var cfg: store.Config = .{ .dir = path, .max_live_objects = 1 << 10, .segment_reserve = 1 << 20 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .data });
    defer h.io.deinit();
    defer h.store.deinit();
    var snap = h.store.snapshot();
    defer snap.release();
    // A historical record newer than the live version must not become the live one on replay.
    try testing.expectEqualStrings("seven", snap.liveObject(&id).?.bytes);
    try testing.expectEqualStrings("nine-historical", snap.objectAt(&id, 9).?);
    try testing.expectEqualStrings("five", snap.objectAt(&id, 5).?);
    try testing.expect(snap.liveObject(&id2) == null);
    try testing.expectEqualStrings("only-historical", snap.objectAt(&id2, 3).?);
    try testing.expectEqual(@as(u64, 1), h.store.liveCount());
}

test "node: an interrupted snapshot restore without --snapshot refuses to start and keeps the store" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const path = try tmpPath(&tmp, &pb);
    try tmp.dir.createDirPath(testing.io, "node");
    try tmp.dir.createDirPath(testing.io, "store");
    const nd = try tmp.dir.openDir(testing.io, "node", .{ .iterate = true });
    defer nd.close(testing.io);
    try snapshot.writeMarker(testing.io, nd, .loading, 1303);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "store/sentinel", .data = "x" });
    const node_mod = @import("node.zig");
    try testing.expectError(error.SnapshotRestoreInterrupted, node_mod.Node.init(gpa, testing.io, .{ .dir = path, .source = .{ .dir = path } }));
    _ = try tmp.dir.statFile(testing.io, "store/sentinel", .{});
    try testing.expectEqual(snapshot.Marker.loading, (try snapshot.readMarker(testing.io, nd)).state);
}

// ------------------------------------------------------------------ snapshot

fn sampleObjects(gpa: std.mem.Allocator, a: std.mem.Allocator) ![]const []const u8 {
    const blob = try readCorpus(gpa, "chk/342451160.chk");
    defer gpa.free(blob);
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    try types.indexCheckpointData(blob, &idx);
    var out: std.ArrayList([]const u8) = .empty;
    var seen: std.AutoHashMapUnmanaged(exec.objects.Key, void) = .empty;
    for (0..idx.tx_count) |i| {
        const t = idx.txAt(i);
        for (idx.objs[t.in_first..][0 .. t.in_count + t.out_count]) |r| {
            const raw = r.slice(blob);
            const k = try exec.objects.keyOf(raw);
            if ((try seen.getOrPut(a, k)).found_existing) continue;
            try out.append(a, try a.dupe(u8, raw));
        }
    }
    return out.items;
}

test "snapshot: write, read back, and refuse tampering" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const objs = try sampleObjects(gpa, a);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try snapshot.writeSnapshot(gpa, testing.io, tmp.dir, 7, objs, 5);
    const ep = try tmp.dir.openDir(testing.io, "epoch_7", .{});
    defer ep.close(testing.io);
    const mbytes = try ep.readFileAlloc(testing.io, "MANIFEST", a, .limited(1 << 20));
    const m = try snapshot.parseManifest(a, mbytes);
    try testing.expectEqual(@as(u64, 7), m.epoch);
    const parts = try m.partitions(a);
    try testing.expectEqual((objs.len + 4) / 5, parts.len);
    var acc: @import("sig").Ecmh = .{};
    var n: usize = 0;
    var nb: [64]u8 = undefined;
    for (parts) |p| {
        const ob = try ep.readFileAlloc(testing.io, p.obj.?.name(&nb), a, .limited(1 << 30));
        const rb = try ep.readFileAlloc(testing.io, p.ref.?.name(&nb), a, .limited(1 << 30));
        var c: snapshot.Checked = .{};
        defer c.deinit(gpa);
        try snapshot.checkPartition(gpa, p, ob, rb, &c);
        n += c.entries.items.len;
        acc.add(&c.acc);
        // Damage: one object byte (checksum), then with a matching checksum (ref mismatch).
        const bad = try a.dupe(u8, ob);
        bad[bad.len - 1] ^= 1;
        var c2: snapshot.Checked = .{};
        defer c2.deinit(gpa);
        try testing.expectError(error.ObjectFileChecksum, snapshot.checkPartition(gpa, p, bad, rb, &c2));
        var p2 = p;
        var h = @import("hash").Sha3_256.init();
        h.update(bad);
        h.final(&p2.obj.?.sha3);
        try testing.expect(std.meta.isError(snapshot.checkPartition(gpa, p2, bad, rb, &c2)));
    }
    try testing.expectEqual(objs.len, n);
    try testing.expectEqualSlices(u8, &root, &acc.digest());
    // A damaged manifest is refused.
    const bad_m = try a.dupe(u8, mbytes);
    bad_m[10] ^= 1;
    try testing.expectError(error.ManifestChecksum, snapshot.parseManifest(a, bad_m));
}

test "snapshot: sortForStore groups objects by type, keeps every entry, wrapped last" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const objs = try sampleObjects(gpa, a);
    var es: std.ArrayList(snapshot.Entry) = .empty;
    defer es.deinit(gpa);
    var wid: [32]u8 = @splat(0xab);
    try es.append(gpa, .{ .wrapped = .{ .id = wid, .version = 3 } });
    for (objs) |raw| {
        const k = try exec.objects.keyOf(raw);
        try es.append(gpa, .{ .object = .{ .bytes = raw, .id = k.id, .version = k.version, .digest = @splat(0) } });
    }
    wid[0] = 1;
    try es.append(gpa, .{ .wrapped = .{ .id = wid, .version = 4 } });
    // The entries as a multiset of (id, version) (sample objects may share an id).
    const Key = struct { id: [32]u8, version: u64 };
    var before: std.AutoHashMapUnmanaged(Key, u32) = .empty;
    for (es.items) |e| {
        const k: Key = switch (e) {
            .object => |o| .{ .id = o.id, .version = o.version },
            .wrapped => |w| .{ .id = w.id, .version = w.version },
        };
        const g = try before.getOrPut(a, k);
        g.value_ptr.* = if (g.found_existing) g.value_ptr.* + 1 else 1;
    }
    const n_before = es.items.len;
    var keys: std.ArrayList(snapshot.SortKey) = .empty;
    defer keys.deinit(gpa);
    var seen: std.DynamicBitSetUnmanaged = .{};
    defer seen.deinit(gpa);
    try snapshot.sortForStore(gpa, es.items, &keys, &seen);
    try testing.expectEqual(n_before, es.items.len);
    var class_prev: u8 = 0;
    var ty_prev: []const u8 = &.{};
    var types_seen: usize = 0;
    for (es.items) |e| {
        var class: u8 = 2;
        var ty: []const u8 = &.{};
        switch (e) {
            .object => |o| {
                const c = before.getPtr(.{ .id = o.id, .version = o.version }).?;
                try testing.expect(c.* > 0);
                c.* -= 1;
                const v = try exec.objects.ObjectView.parse(o.bytes);
                class = if (v.is_package) 1 else 0;
                if (!v.is_package) ty = o.bytes[1 .. v.version_at - 1];
            },
            .wrapped => |w| {
                const c = before.getPtr(.{ .id = w.id, .version = w.version }).?;
                try testing.expect(c.* > 0);
                c.* -= 1;
            },
        }
        try testing.expect(class >= class_prev);
        if (class == 0 and class_prev == 0) {
            try testing.expect(std.mem.order(u8, ty_prev, ty) != .gt);
            if (!std.mem.eql(u8, ty_prev, ty)) types_seen += 1;
        }
        class_prev = class;
        ty_prev = ty;
    }
    try testing.expect(types_seen > 1);
    try testing.expect(es.items[es.items.len - 1] == .wrapped and es.items[es.items.len - 2] == .wrapped);
}

// ------------------------------------------------------------------ execute mode: gas price

test "execute: the reference gas price caps an aborted transaction's gas price (protocol 90+)" {
    // The node passes the epoch's verified reference gas price (trust.epochParamsOfBlob, 100 on
    // mainnet in epochs 1303/1304). An aborted transaction priced at 200x RGP is charged at 100x
    // RGP: the same computation cost as a successful transaction priced at 100x. With RGP 0 (what
    // round 1 passed) the cap would be 0 and execute mode would report a false mismatch.
    const cfg = try protocol.get(141, .mainnet);
    try testing.expect(cfg.getOpt("max_gas_price_rgp_factor_for_aborted_transactions") != null);
    const factor = cfg.getOpt("max_gas_price_rgp_factor_for_aborted_transactions").?;
    const rgp: u64 = 100;
    const budget: u64 = 5_000_000_000;
    const used_units: u64 = 10_000;
    const Run = struct {
        fn cost(c: *const protocol.ProtocolConfig, price: u64, r: u64, aborted: bool, units: u64, b: u64) !u64 {
            var g = try exec.gas.SuiGasStatus.initWithBudget(c, b, price, r);
            try g.move.deductGas(exec.gas.MoveGasStatus.toInternalUnits(units));
            _ = try g.bucketizeComputation(aborted);
            return g.summary().computation_cost;
        }
    };
    const capped = try Run.cost(cfg, 2 * factor * rgp, rgp, true, used_units, budget);
    const at_cap = try Run.cost(cfg, factor * rgp, rgp, false, used_units, budget);
    try testing.expect(capped > 0);
    try testing.expectEqual(at_cap, capped);
    const uncapped = try Run.cost(cfg, 2 * factor * rgp, rgp, false, used_units, budget);
    try testing.expect(uncapped > capped);
    try testing.expectEqual(@as(u64, 0), try Run.cost(cfg, 2 * factor * rgp, 0, true, used_units, budget));
}

test "execute: Move-call, system and prologue transactions of corpus checkpoints run through exec and match" {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    // Epoch 1304's protocol, reference gas price and start (epochs.jsonl, Mysten RPC).
    const L = struct { epoch: u64, pv: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };
    const text = try readCorpus(gpa, "epochs.jsonl");
    defer gpa.free(text);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var meta: ?L = null;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len > 0) {
        const l = try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true });
        if (l.epoch == 1304) meta = l;
    };
    const m = meta orelse return error.SkipZigTest;
    const pkg_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/packages", .{c}), .{}) catch return error.SkipZigTest;
    defer pkg_dir.close(testing.io);
    const chk_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk_dir.close(testing.io);
    const idx = try trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c}));
    var x = try execute.Executor.init(gpa, testing.io, h.store, tmp.dir);
    defer x.deinit();
    x.pkg_dir = pkg_dir;
    try testing.expect(x.seedSystemPackages(chk_dir, idx.last, 1305) > 0);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    var seq: u64 = 342451162;
    while (seq < 342451172) : (seq += 1) {
        const z = readCorpus(gpa, try std.fmt.bufPrint(&pb, "binpb-done/{d}.binpb.zst", .{seq})) catch return error.SkipZigTest;
        defer gpa.free(z);
        _ = arena.reset(.retain_capacity);
        const proto = try convert.unzstd(gpa, z, 1 << 30);
        defer gpa.free(proto);
        blob.clearRetainingCapacity();
        aux.clearRetainingCapacity();
        try testing.expectEqual(seq, try convert.protoToChkAux(gpa, arena.allocator(), proto, &blob, &aux));
        try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&pb, "{d}.aux", .{seq}), .data = aux.items });
        x.checkpoint(seq, 1304, m.pv.?, .{ .rgp = m.rgp, .start_ms = m.start_ms }, blob.items);
    }
    const st = &x.stats;
    try testing.expectEqual(@as(u64, 0), st.mismatched.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), st.errors.load(.monotonic));
    try testing.expect(st.ran_move.load(.monotonic) > 0);
    try testing.expect(st.ran_system.load(.monotonic) > 0);
    try testing.expect(st.ran_ccp.load(.monotonic) > 0);
    try testing.expectEqual(st.executed.load(.monotonic), st.matched.load(.monotonic));
}

test "execute: a settlement's child deleted by an earlier transaction of the checkpoint reads as none, not the store's stale version" {
    // Checkpoint 342452223: accumulator field 0x8f81d515810b... was created at 912304889 (an
    // earlier checkpoint's settlement), an earlier transaction of this checkpoint deleted it, and
    // settlement tx 38 (bound 912305083) must read none (Rust read_child_object). A store as of
    // the previous checkpoint still holds 912304889 live; reading it made the effects differ.
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    const seq: u64 = 342452223;
    var pb: [512]u8 = undefined;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const L = struct { epoch: u64, pv: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };
    const text = try readCorpus(gpa, "epochs.jsonl");
    defer gpa.free(text);
    var meta: ?L = null;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len > 0) {
        const l = try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true });
        if (l.epoch == 1304) meta = l;
    };
    const m = meta orelse return error.SkipZigTest;
    const pkg_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/packages", .{c}), .{}) catch return error.SkipZigTest;
    defer pkg_dir.close(testing.io);
    const chk_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk_dir.close(testing.io);
    const eidx = try trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c}));

    const z = readCorpus(gpa, try std.fmt.bufPrint(&pb, "binpb-done/{d}.binpb.zst", .{seq})) catch return error.SkipZigTest;
    defer gpa.free(z);
    const proto = try convert.unzstd(gpa, z, 1 << 30);
    defer gpa.free(proto);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    try testing.expectEqual(seq, try convert.protoToChkAux(gpa, a, proto, &blob, &aux));
    try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&pb, "{d}.aux", .{seq}), .data = aux.items });

    // The store as of the previous checkpoint: the field live at 912304889 (the deleting
    // transaction's input carries those bytes).
    var cidx = try types.CheckpointIndex.init(gpa);
    defer cidx.deinit(gpa);
    try types.indexCheckpointData(blob.items, &cidx);
    const field_prefix = [_]u8{ 0x8f, 0x81, 0xd5, 0x15, 0x81, 0x0b };
    var planted = false;
    const b = try h.store.begin(seq - 1, 1304);
    for (0..cidx.tx_count) |i| {
        const t = cidx.txAt(i);
        for (cidx.objs[t.in_first..][0..t.in_count]) |r| {
            const raw = r.slice(blob.items);
            const k = try exec.objects.keyOf(raw);
            if (!planted and std.mem.startsWith(u8, &k.id, &field_prefix) and k.version == 912304889) {
                try b.putObject(&k.id, k.version, &sync.verify.objectDigest(raw), raw);
                planted = true;
            }
        }
    }
    try h.store.commit(b);
    try testing.expect(planted);

    var x = try execute.Executor.init(gpa, testing.io, h.store, tmp.dir);
    defer x.deinit();
    x.pkg_dir = pkg_dir;
    try testing.expect(x.seedSystemPackages(chk_dir, eidx.last, 1305) > 0);
    x.checkpoint(seq, 1304, m.pv.?, .{ .rgp = m.rgp, .start_ms = m.start_ms }, blob.items);
    const st = &x.stats;
    try testing.expectEqual(@as(u64, 0), st.mismatched.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), st.errors.load(.monotonic));
    try testing.expect(st.ran_system.load(.monotonic) > 0);
    try testing.expectEqual(st.executed.load(.monotonic), st.matched.load(.monotonic));
}

/// Runs checkpoints `from..to` (epoch 1304, archive protos) through an executor on an empty store.
/// `deny`: load the corpus deny-list state (--deny-state); `complete`: claim the full live set.
fn onThread(deny: bool, complete: bool, out: *DenyOut) !void {
    const T = struct {
        fn run(d: bool, c: bool, o: *DenyOut, r: *?anyerror) void {
            runDenyCase(d, c, o) catch |e| {
                r.* = e;
            };
        }
    };
    var res: ?anyerror = null;
    const t = try std.Thread.spawn(.{}, T.run, .{ deny, complete, out, &res });
    t.join();
    if (res) |e| return e;
}

const DenyOut = struct { gaps: u64 = 0, executed: u64 = 0, mismatched: u64 = 0, errors: u64 = 0 };

fn runDenyCase(deny: bool, complete: bool, out: *DenyOut) !void {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const L = struct { epoch: u64, pv: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };
    const text = try readCorpus(gpa, "epochs.jsonl");
    defer gpa.free(text);
    var meta: ?L = null;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len > 0) {
        const l = try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true });
        if (l.epoch == 1304) meta = l;
    };
    const m = meta orelse return error.SkipZigTest;
    const pkg_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/packages", .{c}), .{}) catch return error.SkipZigTest;
    defer pkg_dir.close(testing.io);
    const chk_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk_dir.close(testing.io);
    const eidx = try trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c}));
    var x = try execute.Executor.init(gpa, testing.io, h.store, tmp.dir);
    defer x.deinit();
    x.pkg_dir = pkg_dir;
    _ = x.seedSystemPackages(chk_dir, eidx.last, 1305);
    if (deny) _ = x.loadDenyState(try std.fmt.bufPrint(&pb, "{s}/deny/objects.bin.zst", .{c})) catch return error.SkipZigTest;
    if (complete) x.complete_from = 0;
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    var seq: u64 = 342451162;
    while (seq < 342451182) : (seq += 1) {
        const z = readCorpus(gpa, try std.fmt.bufPrint(&pb, "binpb-done/{d}.binpb.zst", .{seq})) catch return error.SkipZigTest;
        defer gpa.free(z);
        const proto = try convert.unzstd(gpa, z, 1 << 30);
        defer gpa.free(proto);
        blob.clearRetainingCapacity();
        aux.clearRetainingCapacity();
        _ = try convert.protoToChkAux(gpa, a, proto, &blob, &aux);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&pb, "{d}.aux", .{seq}), .data = aux.items });
        x.checkpoint(seq, 1304, m.pv.?, .{ .rgp = m.rgp, .start_ms = m.start_ms }, blob.items);
    }
    out.gaps = 0;
    for (x.whys.keys(), x.whys.values()) |k, v| if (std.mem.startsWith(u8, k, "deny list state not available")) {
        out.gaps += v;
    };
    out.executed = x.stats.executed.load(.monotonic);
    out.mismatched = x.stats.mismatched.load(.monotonic);
    out.errors = x.stats.errors.load(.monotonic);
}

test "execute: deny-list reads without the full live set are a gap (verify-only), never a guess; --deny-state or a full live set answers them" {
    // Each case on its own thread: exec's per-thread package caches are keyed by the packages
    // store's address, which a second executor on this stack would reuse.
    var bare: DenyOut = .{};
    try onThread(false, false, &bare);
    // Regulated-coin transfers (USDC) read the 0x403 per-type config: an empty store cannot say
    // whether it exists, so those transactions stay verify-only instead of guessing "not denied".
    try testing.expect(bare.gaps > 0);
    try testing.expectEqual(@as(u64, 0), bare.mismatched);
    try testing.expectEqual(@as(u64, 0), bare.errors);
    var seeded: DenyOut = .{};
    try onThread(true, false, &seeded);
    try testing.expectEqual(@as(u64, 0), seeded.gaps);
    try testing.expectEqual(bare.executed + bare.gaps, seeded.executed);
    try testing.expectEqual(@as(u64, 0), seeded.mismatched);
    try testing.expectEqual(@as(u64, 0), seeded.errors);
}

const ParOut = struct { executed: u64 = 0, matched: u64 = 0, mismatched: u64 = 0, errors: u64 = 0, unsupported: u64 = 0, reruns: u64 = 0, done_seq: u64 = 0 };

/// Checkpoints 342451162..342451182 through an executor with `threads` pipeline threads (0: one at
/// a time on this thread), each checkpoint committed to the store right after it is submitted, as
/// the follower does: execution must see the store as of the previous checkpoint, never later.
fn runPipelineCase(threads: u32, out: *ParOut) !void {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 16, .segment_reserve = 1 << 26 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const L = struct { epoch: u64, pv: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };
    const text = try readCorpus(gpa, "epochs.jsonl");
    defer gpa.free(text);
    var meta: ?L = null;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len > 0) {
        const l = try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true });
        if (l.epoch == 1304) meta = l;
    };
    const m = meta orelse return error.SkipZigTest;
    const pkg_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/packages", .{c}), .{}) catch return error.SkipZigTest;
    defer pkg_dir.close(testing.io);
    const chk_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk_dir.close(testing.io);
    const eidx = try trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c}));
    var x = try execute.Executor.init(gpa, testing.io, h.store, tmp.dir);
    defer x.deinit();
    x.pkg_dir = pkg_dir;
    _ = x.seedSystemPackages(chk_dir, eidx.last, 1305);
    _ = x.loadDenyState(try std.fmt.bufPrint(&pb, "{s}/deny/objects.bin.zst", .{c})) catch return error.SkipZigTest;
    try x.start(threads, 4);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    var cidx = try types.CheckpointIndex.init(gpa);
    defer cidx.deinit(gpa);
    var seq: u64 = 342451162;
    while (seq < 342451182) : (seq += 1) {
        const z = readCorpus(gpa, try std.fmt.bufPrint(&pb, "binpb-done/{d}.binpb.zst", .{seq})) catch return error.SkipZigTest;
        defer gpa.free(z);
        const proto = try convert.unzstd(gpa, z, 1 << 30);
        defer gpa.free(proto);
        blob.clearRetainingCapacity();
        aux.clearRetainingCapacity();
        _ = try convert.protoToChkAux(gpa, a, proto, &blob, &aux);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&pb, "{d}.aux", .{seq}), .data = aux.items });
        x.submit(seq, 1304, m.pv.?, .{ .rgp = m.rgp, .start_ms = m.start_ms }, blob.items);
        // Commit the checkpoint's outputs (later checkpoints' jobs must not see them early).
        try types.indexCheckpointData(blob.items, &cidx);
        const b = try h.store.begin(seq, 1304);
        for (0..cidx.tx_count) |i| {
            const t = cidx.txAt(i);
            for (cidx.objs[t.out_first..][0..t.out_count]) |r| {
                const raw = r.slice(blob.items);
                const k = try exec.objects.keyOf(raw);
                try b.putObject(&k.id, k.version, &sync.verify.objectDigest(raw), raw);
            }
        }
        try h.store.commit(b);
        // The spool drops the archive record once the checkpoint commits.
        try tmp.dir.deleteFile(testing.io, try std.fmt.bufPrint(&pb, "{d}.aux", .{seq}));
    }
    x.drain();
    const st = &x.stats;
    out.* = .{ .executed = st.executed.load(.monotonic), .matched = st.matched.load(.monotonic), .mismatched = st.mismatched.load(.monotonic), .errors = st.errors.load(.monotonic), .unsupported = st.unsupported.load(.monotonic), .reruns = st.reruns.load(.monotonic), .done_seq = st.done_seq.load(.monotonic) };
}

fn pipelineOnThread(threads: u32, out: *ParOut) !void {
    const T = struct {
        fn run(n: u32, o: *ParOut, r: *?anyerror) void {
            runPipelineCase(n, o) catch |e| {
                r.* = e;
            };
        }
    };
    var res: ?anyerror = null;
    const t = try std.Thread.spawn(.{ .stack_size = 64 << 20 }, T.run, .{ threads, out, &res });
    t.join();
    if (res) |e| return e;
}

test "execute: the parallel pipeline gives the same verdicts as one transaction at a time" {
    var serial: ParOut = .{};
    try pipelineOnThread(0, &serial);
    var par: ParOut = .{};
    try pipelineOnThread(4, &par);
    try testing.expect(serial.executed > 0);
    try testing.expectEqual(@as(u64, 0), serial.mismatched);
    try testing.expectEqual(@as(u64, 0), serial.errors);
    try testing.expectEqual(serial.executed, par.executed);
    try testing.expectEqual(serial.matched, par.matched);
    try testing.expectEqual(serial.unsupported, par.unsupported);
    try testing.expectEqual(@as(u64, 0), par.mismatched);
    try testing.expectEqual(@as(u64, 0), par.errors);
    try testing.expectEqual(@as(u64, 0), par.reruns);
    try testing.expectEqual(@as(u64, 342451181), par.done_seq);
}

test "zstd: the vendored table-driven decoder equals std's on archive protos" {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    var dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/binpb-done", .{c}), .{ .iterate = true }) catch return error.SkipZigTest;
    defer dir.close(testing.io);
    var it = dir.iterate();
    var n: usize = 0;
    while (try it.next(testing.io)) |e| {
        if (!std.mem.endsWith(u8, e.name, ".binpb.zst")) continue;
        const z = try dir.readFileAlloc(testing.io, e.name, gpa, .limited(1 << 30));
        defer gpa.free(z);
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const got = try convert.unzstdArena(arena.allocator(), z, 1 << 30);
        var in: std.Io.Reader = .fixed(z);
        var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{});
        var w: std.Io.Writer.Allocating = .init(gpa);
        defer w.deinit();
        _ = try d.reader.streamRemaining(&w.writer);
        try testing.expectEqualSlices(u8, w.written(), got);
        n += 1;
        if (n == 300) break;
    }
    try testing.expect(n > 0);
}

// ------------------------------------------------------------------ state hash at the end of epoch

test "state hash: forced epoch boundary on a corpus end-of-epoch checkpoint: equal, stored, reloaded; a planted object is caught" {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var pb: [512]u8 = undefined;
    const eidx = trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c})) catch return error.SkipZigTest;
    const epoch: u64 = 1303;
    if (epoch >= eidx.last.len) return error.SkipZigTest;
    const seq = eidx.last[@intCast(epoch)] orelse return error.SkipZigTest;
    const blob = try readCorpus(a, try std.fmt.bufPrint(&pb, "chk/{d}.chk", .{seq}));
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    try types.indexCheckpointData(blob, &idx);
    const checked = switch (try sync.verify.check(a, blob, &idx)) {
        .ok => |x| x,
        .bad => return error.TestUnexpectedResult,
    };
    try testing.expect(checked.end_of_epoch != null);
    const pv = 140; // epoch 1303 (epochs.jsonl)

    // The live set before the checkpoint, as a restore would leave it (any multiset will do), and
    // the root after it, computed apart from the checker.
    var base: sig.Ecmh = .{};
    base.insert("live object set at the end of epoch 1302 (test)");
    var expect = base;
    {
        var out: exec.state_hash.CheckpointHash = .{};
        try exec.state_hash.accumulateCheckpoint(a, exec.state_hash.pathFor(try protocol.get(pv, .mainnet)), blob, &idx, &out);
        expect.add(&out.acc);
    }
    const want = expect.digest();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 16, .segment_reserve = 1 << 26 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();

    // 1. Equal at the boundary; the new root is committed with the checkpoint.
    var k = try statehash.Checker.init(gpa, .verify_only);
    defer k.deinit();
    k.running = base;
    k.expect_root = want;
    const b = try h.store.begin(seq, epoch);
    try testing.expectEqual(statehash.Verdict.ok, try k.onBatch(seq, &checked, blob, b, pv));
    try h.store.commit(b);
    try testing.expectEqual(@as(u64, 1), k.stats.checks_ok.load(.monotonic));
    try testing.expectEqualSlices(u8, &want, &k.running.?.digest());

    // 2. A restart reads the root back at the last committed checkpoint.
    {
        var k2 = try statehash.Checker.init(gpa, .verify_only);
        defer k2.deinit();
        var snap = h.store.snapshot();
        defer snap.release();
        k2.load(&snap, seq);
        try testing.expectEqualSlices(u8, &want, &k2.running.?.digest());
        var k3 = try statehash.Checker.init(gpa, .verify_only);
        defer k3.deinit();
        k3.load(&snap, seq - 1);
        try testing.expect(k3.running == null);
    }

    // 3. A planted object in the live set: caught at the boundary, the root is dropped and the
    //    checker stays quiet afterwards (verify-only until the next restore).
    var bad = base;
    bad.insert("planted object (test)");
    var k4 = try statehash.Checker.init(gpa, .verify_only);
    defer k4.deinit();
    k4.running = bad;
    k4.expect_root = want;
    k4.quiet = true;
    const b2 = try h.store.begin(seq + 1, epoch);
    try testing.expectEqual(statehash.Verdict.mismatch, try k4.onBatch(seq, &checked, blob, b2, pv));
    h.store.abort(b2);
    try testing.expectEqual(@as(u64, 1), k4.stats.failed.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), k4.stats.mismatches.load(.monotonic));
    try testing.expect(k4.running == null);

    // 4. Without a test root, the checkpoint's certified ECMH commitment is the one compared.
    var k5 = try statehash.Checker.init(gpa, .verify_only);
    defer k5.deinit();
    k5.running = base;
    k5.quiet = true;
    const b3 = try h.store.begin(seq + 1, epoch);
    try testing.expectEqual(statehash.Verdict.mismatch, try k5.onBatch(seq, &checked, blob, b3, pv));
    h.store.abort(b3);
    var commitment: ?[32]u8 = null;
    for (checked.end_of_epoch.?.epochCommitments) |cm| switch (cm) {
        .ECMHLiveObjectSetDigest => |d| commitment = d.digest.@"0",
        else => {},
    };
    try testing.expect(commitment != null);
    try testing.expect(!std.mem.eql(u8, &commitment.?, &want));
}

test "transport limits: node.zig serves with sui-node 1.83.1's values" {
    const node = @import("node.zig");
    const o = node.sui_node_limits;
    try testing.expectEqual(@as(u32, 200), o.h2.max_streams);
    try testing.expectEqual(@as(usize, 4 << 20), o.h2.max_request_bytes);
    try testing.expectEqual(@as(?u64, 60 * std.time.ns_per_s), o.h2.default_timeout_ns);
    try testing.expectEqual(@as(usize, 4 << 20), o.web.max_request_bytes);
    try testing.expectEqual(@as(?u64, 60 * std.time.ns_per_s), o.web.default_timeout_ns);
    try testing.expectEqual(@as(u64, 30 * std.time.ns_per_s), o.web.idle_ns);
    try testing.expectEqual(@as(?u64, 4 * 3600 * std.time.ns_per_s), o.max_age_ns);
    try testing.expectEqual(@as(u64, 600 * std.time.ns_per_s), o.age_grace_ns);
    try testing.expectEqual(@as(?u64, null), o.keepalive_ns);
    try testing.expectEqual(@as(u31, 128), node.listen_backlog);
    const cfg: node.Config = .{ .dir = "", .source = .{ .dir = "" } };
    try testing.expectEqual(o.h2.max_streams, cfg.serve_opts.h2.max_streams);
    try testing.expectEqual(o.h2.default_timeout_ns, cfg.serve_opts.h2.default_timeout_ns);
}

/// Writes a corpus checkpoint into `st` the way the follower and history writer do, as far as the
/// ledger-history backfill reads it: the checkpoint record, every transaction record, output
/// objects as live versions and input objects as historical versions.
fn storeBlob(st: *store.Store, a: std.mem.Allocator, blob: []const u8) !u64 {
    const cp = try bcs.decode(types.CheckpointData, a, blob[1..]);
    const sum = &cp.checkpoint_summary.data;
    const b = try st.begin(sum.sequence_number, sum.epoch);
    try b.checkpoint(try bcs.encodeAlloc(@TypeOf(cp.checkpoint_summary), a, &cp.checkpoint_summary), try bcs.encodeAlloc(types.CheckpointContents, a, &cp.checkpoint_contents));
    for (cp.transactions, 0..) |*t, i| {
        const dg: types.ExecutionDigests = switch (cp.checkpoint_contents) {
            .V1 => |v| v.transactions[i],
            .V2 => |v| v.transactions[i].digest,
        };
        const ev: ?[]const u8 = if (t.events) |*e| try bcs.encodeAlloc(types.TransactionEvents, a, e) else null;
        try b.transaction(&dg.transaction.@"0".@"0", &dg.effects.@"0".@"0", try bcs.encodeAlloc(@TypeOf(t.transaction), a, &t.transaction), try bcs.encodeAlloc(types.TransactionEffects, a, &t.effects), ev);
        for ([2][]const types.Object{ t.input_objects, t.output_objects }, 0..) |list, out| for (list) |*o| {
            const id: [32]u8, const ver: u64 = switch (o.data) {
                .Move => |m| .{ m.contents[0..32].*, m.version.@"0" },
                .Package => |pk| .{ pk.id.@"0".@"0", pk.version.@"0" },
            };
            const raw = try bcs.encodeAlloc(types.Object, a, o);
            const d = store.objectDigest(raw);
            if (out == 1) try b.putObject(&id, ver, &d, raw) else try b.putHistorical(&id, ver, &d, raw);
        };
    }
    try st.commit(b);
    return sum.sequence_number;
}

test "ledger-history backfill: more loaders than ring slots never share a slot (drop-in r2 SEGV in ArenaAllocator under lhfill worker)" {
    // deepwave 72c7914 on the epoch-1304 restore crashed 1 s after "history: backfilling the
    // ledger-history index for checkpoints 342814415..343266015 (12 loaders)": loaders for seq
    // and seq + ring both saw the slot empty and reset the same arena. A ring of 2 slots with 8
    // loaders over mainnet checkpoints 342456120.. makes that reuse constant.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const root_dir = try tmpPath(&tmp, &pb);
    const sdir = try std.fmt.allocPrint(a, "{s}/store", .{root_dir});
    var cfg: store.Config = .{ .dir = sdir, .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const want = try lhist.Index.init(gpa, testing.io, null);
    defer want.deinit();
    var seqs: [12]u64 = undefined;
    for (&seqs, 0..) |*s, i| {
        var nb: [64]u8 = undefined;
        const blob = try readCorpus(a, try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{342456120 + i}));
        s.* = try storeBlob(h.store, a, blob);
        try want.addCheckpoint(s.*, blob);
    }
    const want_hash = try want.contentHash();
    for (0..20) |_| {
        const bf = try lhfill.Backfill.startRing(gpa, testing.io, h.store, seqs[0], seqs[11], 8, 2);
        while (bf.status() == .running) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        const out = try bf.finish(seqs[11]);
        try testing.expectEqual(want_hash, try out.contentHash());
        bf.destroy();
    }
}

test "ledger-history backfill: an index built from the store equals one built while following, and adopt swaps it in durably" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var blobs: [12][]const u8 = undefined;
    for (&blobs, 0..) |*b, i| {
        var nb: [64]u8 = undefined;
        b.* = try readCorpus(a, try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{342456120 + i}));
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const root_dir = try tmpPath(&tmp, &pb);
    const sdir = try std.fmt.allocPrint(a, "{s}/store", .{root_dir});
    var cfg: store.Config = .{ .dir = sdir, .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    // The reference: an index fed the blobs as the follower would.
    const want = try lhist.Index.init(gpa, testing.io, null);
    defer want.deinit();
    var seqs: [12]u64 = undefined;
    for (blobs, &seqs) |b, *s| {
        s.* = try storeBlob(h.store, a, b);
        try want.addCheckpoint(s.*, b);
    }
    const want_hash = try want.contentHash();

    // Backfill the first nine from the store; the commit path takes the rest at the swap.
    const bf = try lhfill.Backfill.start(gpa, testing.io, h.store, seqs[0], seqs[8], 3);
    while (bf.status() == .running) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    try testing.expectEqual(lhfill.Status.ready, bf.status());
    try testing.expectEqual(@as(u64, 0), bf.counters.missing_objects.load(.monotonic));

    // The live index started late (at the eleventh checkpoint), persisted on disk.
    const hdir = try std.fmt.allocPrint(a, "{s}/lh", .{root_dir});
    {
        const live = try lhist.Index.init(gpa, testing.io, hdir);
        defer live.deinit();
        try live.addCheckpoint(seqs[10], blobs[10]);
        // The commit path, before indexing the twelfth: catch up to the eleventh, swap, index.
        const out = try bf.finish(seqs[11] - 1);
        try live.adopt(out);
        bf.destroy();
        try live.addCheckpoint(seqs[11], blobs[11]);
        try testing.expectEqual(seqs[0], live.indexedLo().?);
        try testing.expectEqual(want_hash, try live.contentHash());
    }
    // Reopened from its snapshot and log: the same state.
    const again = try lhist.Index.init(gpa, testing.io, hdir);
    defer again.deinit();
    try testing.expectEqual(want_hash, try again.contentHash());
}

test "ledger-history backfill: resumes from its on-disk staging watermark after a crash; a crash inside adopt keeps the live index and the staging state" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var blobs: [12][]const u8 = undefined;
    for (&blobs, 0..) |*b, i| {
        var nb: [64]u8 = undefined;
        b.* = try readCorpus(a, try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{342456120 + i}));
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const root_dir = try tmpPath(&tmp, &pb);
    const sdir = try std.fmt.allocPrint(a, "{s}/store", .{root_dir});
    var cfg: store.Config = .{ .dir = sdir, .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const want = try lhist.Index.init(gpa, testing.io, null);
    defer want.deinit();
    var seqs: [12]u64 = undefined;
    for (blobs, &seqs) |b, *s| {
        s.* = try storeBlob(h.store, a, b);
        try want.addCheckpoint(s.*, b);
    }
    const want_hash = try want.contentHash();
    const staging = try std.fmt.allocPrint(a, "{s}/lh/backfill", .{root_dir});
    const hdir = try std.fmt.allocPrint(a, "{s}/lh", .{root_dir});

    // A staging dir that does not fit (starts above the requested low end) is built again.
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, h.store, seqs[2], seqs[3], .{ .workers = 2, .staging = staging });
        while (bf.status() == .running) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        bf.destroy();
    }
    // Run 1: crash right after the third save (one save, a rotation, per checkpoint): the
    // watermark is seqs[2].
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, h.store, seqs[0], seqs[8], .{ .workers = 2, .staging = staging, .save_every_ns = 0, .stop_after_saves = 3 });
        try testing.expectEqual(@as(?u64, null), bf.resumed_at);
        while (bf.thread != null and bf.status() == .running and !bf.cancel.load(.acquire)) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        if (bf.thread) |t| t.join();
        bf.thread = null;
        try testing.expectEqual(lhfill.Status.running, bf.status());
        // kill -9: nothing more is written (no destroy-time save).
        bf.staged = false;
        bf.destroy();
    }
    // Torn tmp files from a save in flight (CURRENT and the generation's meta) are ignored.
    {
        var cb: [64]u8 = undefined;
        const cur = std.mem.trim(u8, try Io.Dir.cwd().readFile(testing.io, try std.fmt.allocPrint(a, "{s}/CURRENT", .{staging}), &cb), " \n");
        try Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = try std.fmt.allocPrint(a, "{s}/CURRENT.tmp", .{staging}), .data = "torn" });
        try Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = try std.fmt.allocPrint(a, "{s}/{s}/meta.tmp", .{ staging, cur }), .data = "torn" });
        // The staging index is on disk with no per-checkpoint log.
        var gd = try Io.Dir.cwd().openDir(testing.io, try std.fmt.allocPrint(a, "{s}/{s}", .{ staging, cur }), .{ .iterate = true });
        defer gd.close(testing.io);
        var it = gd.iterate();
        while (try it.next(testing.io)) |en| try testing.expect(!std.mem.startsWith(u8, en.name, "log-"));
    }
    // Run 2 resumes at seqs[3] and ends equal to a full build. The adopt crashes before the
    // staging generation moves (inside the staging index's final rotation): the live index keeps
    // its state and the staging dir its last save.
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, h.store, seqs[0], seqs[8], .{ .workers = 3, .staging = staging });
        try testing.expectEqual(@as(?u64, seqs[3]), bf.resumed_at);
        while (bf.status() == .running) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        try testing.expect(bf.counters.checkpoints.load(.monotonic) <= seqs[11] - seqs[3] + 1);
        const live = try lhist.Index.init(gpa, testing.io, hdir);
        defer live.deinit();
        try live.addCheckpoint(seqs[10], blobs[10]);
        const g0 = live.generation();
        const out = try bf.finish(seqs[11] - 1);
        var fault: lhist.Fault = .{ .left = 1, .rng = std.Random.DefaultPrng.init(7) };
        out.fault = &fault;
        try testing.expectError(error.Crash, live.adopt(out));
        out.fault = null;
        bf.destroy();
        try testing.expectEqual(g0, live.generation());
        try testing.expectEqual(seqs[10], live.indexedLo().?);
    }
    // Reopened: the old live state (from seqs[10]); the staging dir resumes past seqs[8]; the
    // adopt now lands and is durable when it returns (the node then drops the staging dir).
    {
        const live = try lhist.Index.init(gpa, testing.io, hdir);
        defer live.deinit();
        try testing.expectEqual(seqs[10], live.indexedLo().?);
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, h.store, seqs[0], seqs[9], .{ .workers = 2, .staging = staging });
        try testing.expect(bf.resumed_at.? > seqs[8]);
        while (bf.status() == .running) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        const out = try bf.finish(seqs[11] - 1);
        try live.adopt(out);
        bf.destroy();
        try testing.expectEqual(live.generation(), live.persistedGeneration());
        // The staging generation was moved into the live root: nothing is left to resume from.
        try testing.expectError(error.FileNotFound, Io.Dir.cwd().access(testing.io, try std.fmt.allocPrint(a, "{s}/CURRENT", .{staging}), .{}));
        try live.addCheckpoint(seqs[11], blobs[11]);
        try testing.expectEqual(want_hash, try live.contentHash());
    }
    // A kill -9 right after: the reopen has the adopted window plus the logged tip.
    const again = try lhist.Index.init(gpa, testing.io, hdir);
    defer again.deinit();
    try testing.expectEqual(seqs[0], again.indexedLo().?);
    try testing.expectEqual(seqs[11], again.indexedHi().?);
    try testing.expectEqual(want_hash, try again.contentHash());
}

test "removal-prior index: the store derivation equals the one from the checkpoint's objects, and survives a reopen" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const root_dir = try tmpPath(&tmp, &pb);
    var cfg: store.Config = .{ .dir = try std.fmt.allocPrint(a, "{s}/store", .{root_dir}), .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const path = try std.fmt.allocPrint(a, "{s}/node/removed-prior.log", .{root_dir});
    var want: removal_log.Map = .empty;
    defer want.deinit(gpa);
    var map: removal_log.Map = .empty;
    defer map.deinit(gpa);
    var log = try removal_log.Log.open(gpa, testing.io, path, &map);
    var total: usize = 0;
    for (0..12) |i| {
        var nb: [64]u8 = undefined;
        const blob = try readCorpus(a, try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{342456120 + i}));
        const seq = try storeBlob(h.store, a, blob);
        // The executor's rule (noteRemovals), from the checkpoint's objects.
        const cp = try bcs.decode(types.CheckpointData, a, blob[1..]);
        for (cp.transactions) |*t| {
            const lamport = switch (t.effects) {
                .V2 => |v| v.lamport_version.@"0",
                .V1 => continue,
            };
            ins: for (t.input_objects) |*o| {
                const m = switch (o.data) {
                    .Move => |m| m,
                    .Package => continue,
                };
                if (o.owner != .ObjectOwner) continue;
                for (t.output_objects) |*q| switch (q.data) {
                    .Move => |qm| if (std.mem.eql(u8, qm.contents[0..32], m.contents[0..32])) continue :ins,
                    .Package => {},
                };
                try want.put(gpa, .{ .id = m.contents[0..32].*, .version = lamport }, m.version.@"0");
            }
        }
        var snap = h.store.snapshot();
        defer snap.release();
        var list: std.ArrayList(removal_log.Entry) = .empty;
        defer list.deinit(gpa);
        try testing.expect(try removal_log.fromStore(gpa, a, &snap, seq, &list));
        for (list.items) |e| try map.put(gpa, .{ .id = e.id, .version = e.version }, e.prior);
        try log.appendCheckpoint(gpa, seq, list.items);
        total += list.items.len;
    }
    log.close();
    std.debug.print("removal-prior: {d} child removals in 12 corpus checkpoints\n", .{total});
    try testing.expectEqual(want.count(), map.count());
    var it = want.iterator();
    while (it.next()) |e| try testing.expectEqual(e.value_ptr.*, map.get(e.key_ptr.*).?);
    // Reopened (a restart, or a kill -9: the records were written, not fsync'd): the same map.
    var again: removal_log.Map = .empty;
    defer again.deinit(gpa);
    var l2 = try removal_log.Log.open(gpa, testing.io, path, &again);
    defer l2.close();
    try testing.expectEqual(map.count(), again.count());
    // The watermark is the last mark (written with removals, or every mark_every checkpoints);
    // the checkpoints after it are derived from the store again at open (openPriorLog).
    try testing.expect(l2.wm.? >= 342456120 and l2.wm.? <= 342456131);
}
