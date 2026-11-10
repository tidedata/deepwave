//! Reviewer suites that check the corpus itself, before any lane relies on it.
//!
//! `corpus` (one item per blob, plus one per epoch and one per orphan):
//!   - chk/<seq>.chk starts with the BCS blob tag and has truth/checkpoint/<seq>.jsonl.zst;
//!   - the truth header names this seq and the blob length, its tx count matches kinds/sigs and
//!     the Transaction lines, and its epoch agrees with epochs.jsonl (Mysten's GetEpoch index):
//!     first <= seq <= last, eoe exactly at the epoch's last checkpoint, next_pv equal to the
//!     next epoch's protocol version;
//!   - manifest.jsonl has the same header (plus "cov");
//!   - every other line has the dumper's exact shape, a known kind and a byte range inside the
//!     blob, and where it has a digest the bytes hash to it (Blake2b256 of "<Kind>::" ++ raw);
//!   - `epoch/<e>`: every completed epoch has its first and last checkpoint in the corpus;
//!   - `plan/<part>`: every seq in plan/{c1,dense,targeted}.txt is present, and no blob is unplanned;
//!   - no truth file or manifest line without its blob.
//! `corpus-chain` (one item per adjacent pair seq, seq+1 both present):
//!   the later summary's previous_digest is the earlier summary's digest, the epoch advances
//!   exactly after an end-of-epoch checkpoint, and network_total_transactions grows by the
//!   later checkpoint's tx count.
const std = @import("std");
const harness = @import("root.zig");
const truth = @import("truth.zig");

pub const suites = [_]harness.Suite{
    .{
        .name = "corpus",
        .lane = "reviewer",
        .doc = "every chk blob has well-formed truth agreeing with manifest.jsonl and epochs.jsonl; epochs complete",
        .run = runCorpus,
        .bench = benchBlake,
        .baselines = &.{.{ .name = "blob-blake2b", .argv = &.{ "{dumper}", "bench", "blob-blake2b" } }},
    },
    .{
        .name = "corpus-chain",
        .lane = "reviewer",
        .doc = "adjacent checkpoints chain: previous_digest, epoch step, network_total_transactions",
        .run = runChain,
    },
};

const max_blob = 1 << 30;
const max_truth = 1 << 32;

pub const Epoch = struct { epoch: u64, first: u64, last: ?u64, pv: u64 };

/// epochs.jsonl from the corpus root, indexed by epoch number.
pub fn loadEpochs(ctx: *harness.Ctx, arena: std.mem.Allocator) ![]Epoch {
    const text = try ctx.corpus.readFileAlloc(ctx.io, "epochs.jsonl", arena, .limited(64 << 20));
    var list: std.ArrayList(Epoch) = .empty;
    var it = harness.lines(text);
    while (it.next()) |line| {
        const e = try std.json.parseFromSliceLeaky(Epoch, arena, line, .{ .ignore_unknown_fields = true });
        if (e.epoch != list.items.len) return error.EpochsNotContiguous;
        try list.append(arena, e);
    }
    return list.items;
}

const CorpusState = struct {
    epochs: []const Epoch,
    /// seq -> manifest line
    manifest: *const std.AutoHashMapUnmanaged(u64, []const u8),
};

fn seqOf(name: []const u8) ?u64 {
    const dot = std.mem.indexOfScalar(u8, name, '.') orelse return null;
    return std.fmt.parseInt(u64, name[0..dot], 10) catch null;
}

fn runCorpus(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const epochs = try loadEpochs(ctx, arena);
    const manifest_text = try ctx.corpus.readFileAlloc(ctx.io, "manifest.jsonl", arena, .limited(16 << 30));
    var manifest: std.AutoHashMapUnmanaged(u64, []const u8) = .empty;
    var dup_manifest: ?u64 = null;
    var it = harness.lines(manifest_text);
    while (it.next()) |line| {
        const k = "\"seq\":";
        const at = std.mem.indexOf(u8, line, k) orelse return error.ManifestLineWithoutSeq;
        var end = at + k.len;
        while (end < line.len and std.ascii.isDigit(line[end])) end += 1;
        const seq = try std.fmt.parseInt(u64, line[at + k.len .. end], 10);
        const gop = try manifest.getOrPut(arena, seq);
        if (gop.found_existing) dup_manifest = seq;
        gop.value_ptr.* = line;
    }

    const chk = try ctx.listFiles("chk", ".chk");
    defer ctx.freeNames(chk);
    var present: std.AutoHashMapUnmanaged(u64, void) = .empty;
    for (chk) |n| if (seqOf(n)) |s| try present.put(arena, s, {});

    const state: CorpusState = .{ .epochs = epochs, .manifest = &manifest };
    try ctx.forEachName(chk, &state, checkBlob);

    // Completed epochs: first and last checkpoint present.
    for (epochs) |e| {
        if (ctx.done()) break;
        const last = e.last orelse continue;
        var buf: [32]u8 = undefined;
        const id = try std.fmt.bufPrint(&buf, "epoch/{d}", .{e.epoch});
        if (!ctx.selected(id)) continue;
        var c = ctx.check(id);
        if (!present.contains(e.first)) c.failf("first checkpoint {d} missing", .{e.first});
        if (!present.contains(last)) c.failf("last checkpoint {d} missing", .{last});
        _ = c.finish();
    }

    // The corpus is exactly its plan: every planned seq present, no unplanned blob.
    var planned: std.AutoHashMapUnmanaged(u64, void) = .empty;
    for ([_][]const u8{ "c1", "dense", "targeted" }) |part| {
        var buf: [32]u8 = undefined;
        const id = try std.fmt.bufPrint(&buf, "plan/{s}", .{part});
        if (!ctx.selected(id)) continue;
        const path = try std.fmt.allocPrint(arena, "plan/{s}.txt", .{part});
        const text = ctx.corpus.readFileAlloc(ctx.io, path, arena, .limited(1 << 30)) catch |e| {
            ctx.fail(id, "read {s}: {s}", .{ path, @errorName(e) });
            continue;
        };
        var c = ctx.check(id);
        var missing: u64 = 0;
        var pit = harness.lines(text);
        while (pit.next()) |line| {
            const s = std.fmt.parseInt(u64, std.mem.trim(u8, line, " \r"), 10) catch {
                c.failf("bad line {s}", .{line});
                break;
            };
            try planned.put(arena, s, {});
            if (!present.contains(s)) {
                missing += 1;
                if (missing <= 5) c.failf("planned checkpoint {d} missing", .{s});
            }
        }
        if (missing > 5) c.failf("{d} planned checkpoints missing in total", .{missing});
        _ = c.finish();
    }
    for (chk) |n| {
        const s = seqOf(n) orelse continue;
        if (!planned.contains(s)) ctx.fail(n, "blob is not in plan/*.txt (add it to tools/corpus/targeted.txt with a reason)", .{});
    }

    // Orphans: truth files and manifest lines without a blob.
    const truths = try ctx.listFiles("truth/checkpoint", ".jsonl.zst");
    defer ctx.freeNames(truths);
    for (truths) |n| {
        const s = seqOf(n) orelse continue;
        if (!present.contains(s)) ctx.fail(n, "orphan truth file (no chk/{d}.chk)", .{s});
    }
    var mit = manifest.keyIterator();
    while (mit.next()) |s| if (!present.contains(s.*)) ctx.fail("manifest", "orphan manifest line for seq {d}", .{s.*});
    if (dup_manifest) |s| ctx.fail("manifest", "seq {d} appears twice", .{s});
}

fn checkBlob(state: *const CorpusState, ctx: *harness.Ctx, name: []const u8) !void {
    const seq_text = name[0 .. name.len - ".chk".len];
    var c = ctx.check(seq_text);
    defer _ = c.finish();
    errdefer c.failures += 1;
    const seq = std.fmt.parseInt(u64, seq_text, 10) catch return c.failf("file name is not a sequence number", .{});
    const blob = ctx.readFile(try std.fmt.allocPrint(ctx.scratch(), "chk/{s}", .{name}), max_blob) catch |e|
        return c.failf("read blob: {s}", .{@errorName(e)});
    if (blob.len == 0 or blob[0] != 1) return c.failf("blob does not start with the BCS blob tag 0x01", .{});
    const text = ctx.readZstd(try std.fmt.allocPrint(ctx.scratch(), "truth/checkpoint/{s}.jsonl.zst", .{seq_text}), max_truth) catch |e|
        return c.failf("read truth: {s}", .{@errorName(e)});

    var it = harness.lines(text);
    const header_line = it.next() orelse return c.failf("empty truth file", .{});
    const h = truth.parseHeader(ctx.scratch(), header_line) catch |e| return c.failf("header: {s}", .{@errorName(e)});
    c.eql("header seq", seq, h.seq);
    c.eql("header len", @as(u64, blob.len), h.len);
    c.eql("kinds per tx", h.txs, @as(u64, h.kinds.len));
    c.eql("sigs per tx", h.txs, @as(u64, h.sigs.len));

    if (h.epoch >= state.epochs.len) {
        c.failf("epoch {d} not in epochs.jsonl", .{h.epoch});
    } else {
        const e = state.epochs[h.epoch];
        if (seq < e.first or (e.last != null and seq > e.last.?))
            c.failf("seq outside epoch {d} [{d}, {?d}]", .{ h.epoch, e.first, e.last });
        c.eql("eoe at the epoch's last checkpoint", e.last != null and e.last.? == seq, h.eoe);
        if (h.eoe and h.epoch + 1 < state.epochs.len) c.eql("next_pv", @as(?u64, state.epochs[h.epoch + 1].pv), h.next_pv);
        if (!h.eoe) c.eql("next_pv without eoe", @as(?u64, null), h.next_pv);
    }

    if (state.manifest.get(seq)) |m| {
        const body = header_line[0 .. header_line.len - 1];
        if (!std.mem.startsWith(u8, m, body) or !std.mem.startsWith(u8, m[body.len..], ",\"cov\":["))
            c.text("manifest line vs truth header", header_line, m);
    } else c.failf("no manifest line", .{});

    var n_lines: u64 = 0;
    var n_tx: u64 = 0;
    var first_summary = false;
    while (it.next()) |line| : (n_lines += 1) {
        const l = truth.parseLine(line) catch return c.failf("line {d} is malformed", .{n_lines + 2});
        if (!truth.isKind(l.k)) return c.failf("line {d}: unknown kind {s}", .{ n_lines + 2, l.k });
        _ = l.raw(blob) catch return c.failf("line {d} ({s}) range {d}+{d} past blob end {d}", .{ n_lines + 2, l.p, l.o, l.n, blob.len });
        if (n_lines == 0) first_summary = std.mem.eql(u8, l.k, "CheckpointSummary") and l.o == 1 and l.d != null and l.sd != null;
        if (l.d) |d| {
            // Integrity: the blob bytes must hash to the digest Mysten computed (BcsSignable:
            // Blake2b256(TypeName ++ "::" ++ BCS)), so a corrupted blob or a truth file paired
            // with the wrong blob fails here and never reaches a lane suite.
            const want = truth.digestBytes(32, d) catch return c.failf("line {d}: digest is not 32 bytes of hex", .{n_lines + 2});
            var got: [32]u8 = undefined;
            var hasher: std.crypto.hash.blake2.Blake2b256 = .init(.{});
            hasher.update(l.k);
            hasher.update("::");
            hasher.update(l.raw(blob) catch unreachable);
            hasher.final(&got);
            if (!std.mem.eql(u8, &want, &got)) c.failf("{s}: blob bytes do not hash to the truth digest", .{l.p});
        }
        if (std.mem.eql(u8, l.k, "Transaction")) n_tx += 1;
    }
    if (!first_summary) c.failf("first object line is not the summary at offset 1 with d and sd", .{});
    c.eql("Transaction lines", h.txs, n_tx);
}

const Summary = struct {
    epoch: u64,
    sequence_number: u64,
    network_total_transactions: u64,
    previous_digest: ?[]const u8 = null,
};

const SummaryFacts = struct { s: Summary, d: []const u8, eoe: bool, txs: u64 };

fn summaryFacts(ctx: *harness.Ctx, seq: u64) !SummaryFacts {
    const path = try std.fmt.allocPrint(ctx.scratch(), "truth/checkpoint/{d}.jsonl.zst", .{seq});
    const text = try ctx.readZstd(path, max_truth);
    var it = harness.lines(text);
    const h = try truth.parseHeader(ctx.scratch(), it.next() orelse return error.EmptyTruth);
    const l = try truth.parseLine(it.next() orelse return error.EmptyTruth);
    if (!std.mem.eql(u8, l.k, "CheckpointSummary")) return error.NoSummaryLine;
    const s = try std.json.parseFromSliceLeaky(Summary, ctx.scratch(), l.t orelse return error.NoTree, .{ .ignore_unknown_fields = true });
    return .{ .s = s, .d = l.d orelse return error.NoDigest, .eoe = h.eoe, .txs = h.txs };
}

fn runChain(ctx: *harness.Ctx) !void {
    const chk = try ctx.listFiles("chk", ".chk");
    defer ctx.freeNames(chk);
    var pairs: std.ArrayList([]const u8) = .empty;
    defer {
        for (pairs.items) |p| ctx.gpa.free(p);
        pairs.deinit(ctx.gpa);
    }
    var prev: ?u64 = null;
    for (chk) |n| {
        const s = seqOf(n) orelse continue;
        if (prev) |p| if (p + 1 == s) try pairs.append(ctx.gpa, try std.fmt.allocPrint(ctx.gpa, "{d}->{d}", .{ p, s }));
        prev = s;
    }
    try ctx.forEachName(pairs.items, {}, checkPair);
}

fn checkPair(_: void, ctx: *harness.Ctx, id: []const u8) !void {
    var c = ctx.check(id);
    defer _ = c.finish();
    errdefer c.failures += 1;
    const arrow = std.mem.indexOf(u8, id, "->").?;
    const a = std.fmt.parseInt(u64, id[0..arrow], 10) catch unreachable;
    const fa = summaryFacts(ctx, a) catch |e| return c.failf("truth of {d}: {s}", .{ a, @errorName(e) });
    const fb = summaryFacts(ctx, a + 1) catch |e| return c.failf("truth of {d}: {s}", .{ a + 1, @errorName(e) });
    c.eql("sequence_number", a + 1, fb.s.sequence_number);
    const pd = fb.s.previous_digest orelse return c.failf("previous_digest is null", .{});
    if (pd.len != 66 or !std.mem.startsWith(u8, pd, "0x")) return c.failf("previous_digest is not 0x + 32 bytes", .{});
    c.text("previous_digest", fa.d, pd[2..]);
    c.eql("epoch step", fa.s.epoch + @intFromBool(fa.eoe), fb.s.epoch);
    c.eql("network_total_transactions", fa.s.network_total_transactions + fb.txs, fb.s.network_total_transactions);
}

/// Reference bench for the harness itself: std Blake2b256 over every whole input blob, compared
/// with fastcrypto's Blake2b256 on the same blobs (`zui-dumper bench blob-blake2b`).
fn benchBlake(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const names = ctx.benchInputs();
    const blobs = try arena.alloc([]const u8, names.len);
    var bytes: u64 = 0;
    for (names, blobs) |n, *b| {
        b.* = try ctx.corpus.readFileAlloc(ctx.io, n, arena, .limited(max_blob));
        bytes += b.len;
    }
    const S = struct {
        fn pass(bs: []const []const u8) !void {
            for (bs) |b| {
                var out: [32]u8 = undefined;
                std.crypto.hash.blake2.Blake2b256.hash(b, &out, .{});
                std.mem.doNotOptimizeAway(&out);
            }
        }
    };
    try ctx.benchPasses("blob-blake2b", "byte", bytes, @as([]const []const u8, blobs), S.pass);
}
