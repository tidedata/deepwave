//! Conformance suites of the bcs-types lane (CONTRACTS.md section 3.3) that run on checkpoint
//! truth: `bcs`, `bcs-checkpoint`, `digests`, and the registry check `bcs-format`.
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const core = @import("core");
const gen = @import("gen.zig");
const hand = @import("hand.zig");
const digest = @import("digest.zig");
const index = @import("index.zig");
const format_suite = @import("format_suite.zig");
const truth = harness.truth;

pub const suites = [_]harness.Suite{
    .{
        .name = "bcs",
        .lane = "bcs-types",
        .doc = "every truth line: decode raw[o..o+n], re-encode byte-exact, tree text equals Rust",
        .run = runBcs,
        .bench = benchDecode,
        .baselines = &.{
            .{ .name = "decode", .argv = &.{ "{dumper}", "bench", "decode" } },
            .{ .name = "roundtrip", .argv = &.{ "{dumper}", "bench", "roundtrip" } },
        },
    },
    .{
        .name = "bcs-checkpoint",
        .lane = "bcs-types",
        .doc = "whole CheckpointData blob decodes and re-encodes byte-exact; the one-pass index equals the truth line table",
        .run = runCheckpoint,
        .bench = benchIndex,
    },
    .{
        .name = "digests",
        .lane = "bcs-types",
        .doc = "every d/sd field: type digests and intent-signing digests equal Rust",
        .run = runDigests,
        .bench = benchDigests,
        .baselines = &.{.{ .name = "digests", .argv = &.{ "{dumper}", "bench", "digests" } }},
    },
    .{
        .name = "bcs-format",
        .lane = "bcs-types",
        .doc = "Zig type shapes equal the serde-reflection registry spec/sui-format-1.83.1.yaml.snap",
        .run = format_suite.run,
    },
};

const max_blob = 1 << 30;
const max_truth = 1 << 32;

const Envelope = hand.Envelope;
const CertifiedSummary = Envelope(gen.CheckpointSummary, gen.AuthorityQuorumSignInfo);
const TransactionEnvelope = Envelope(gen.SenderSignedData, gen.EmptySignInfo);

/// Truth kind -> Zig type.
const kind_types = .{
    .{ "CheckpointSummary", gen.CheckpointSummary },
    .{ "AuthorityStrongQuorumSignInfo", gen.AuthorityQuorumSignInfo },
    .{ "CertifiedCheckpointSummary", CertifiedSummary },
    .{ "CheckpointContents", gen.CheckpointContents },
    .{ "TransactionData", gen.TransactionData },
    .{ "GenericSignature", gen.GenericSignature },
    .{ "MultiSig", gen.MultiSig },
    .{ "MultiSigLegacy", hand.MultiSigLegacyOf(gen.CompressedSignature) },
    .{ "ZkLoginAuthenticator", hand.ZkLoginAuthenticator },
    .{ "PasskeyAuthenticator", hand.RawPasskeyAuthenticator },
    .{ "Transaction", TransactionEnvelope },
    .{ "TransactionEffects", gen.TransactionEffects },
    .{ "TransactionEvents", gen.TransactionEvents },
    .{ "Object", gen.Object },
};

fn truthFile(ctx: *harness.Ctx, name: []const u8) !struct { seq_text: []const u8, blob: []const u8, text: []const u8 } {
    const seq_text = name[0 .. name.len - ".jsonl.zst".len];
    const blob = try ctx.readFile(try std.fmt.allocPrint(ctx.scratch(), "chk/{s}.chk", .{seq_text}), max_blob);
    const text = try ctx.readZstd(try std.fmt.allocPrint(ctx.scratch(), "truth/checkpoint/{s}", .{name}), max_truth);
    return .{ .seq_text = seq_text, .blob = blob, .text = text };
}

fn runBcs(ctx: *harness.Ctx) !void {
    try ctx.forEachFile("truth/checkpoint", ".jsonl.zst", {}, bcsFile);
}

fn bcsFile(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const f = truthFile(ctx, name) catch |e| {
        ctx.fail(name, "read: {s}", .{@errorName(e)});
        return;
    };
    var it = harness.lines(f.text);
    _ = it.next() orelse {
        ctx.fail(name, "empty truth file", .{});
        return;
    };
    while (it.next()) |line| {
        const l = truth.parseLine(line) catch {
            ctx.fail(name, "malformed truth line", .{});
            return;
        };
        const id = try std.fmt.allocPrint(ctx.scratch(), "{s}/{s}", .{ f.seq_text, l.p });
        const raw = l.raw(f.blob) catch {
            ctx.fail(id, "range outside the blob", .{});
            continue;
        };
        checkLine(ctx, id, l, raw);
    }
}

fn checkLine(ctx: *harness.Ctx, id: []const u8, l: truth.Line, raw: []const u8) void {
    inline for (kind_types) |kt| {
        if (std.mem.eql(u8, l.k, kt[0])) {
            checkOne(kt[1], ctx, id, l, raw);
            return;
        }
    }
    ctx.fail(id, "kind {s} has no Zig type", .{l.k});
}

fn checkOne(comptime T: type, ctx: *harness.Ctx, id: []const u8, l: truth.Line, raw: []const u8) void {
    var c = ctx.check(id);
    defer _ = c.finish();
    const arena = ctx.scratch();
    const v = bcs.decode(T, arena, raw) catch |e| return c.failf("decode {s}: {s}", .{ l.k, @errorName(e) });
    const re = bcs.encodeAlloc(T, arena, &v) catch |e| return c.failf("encode: {s}", .{@errorName(e)});
    c.bytes("re-encoded bytes", raw, re);
    if (bcs.encodedLen(T, &v) != raw.len) c.failf("encodedLen {d} != {d}", .{ bcs.encodedLen(T, &v), raw.len });
    if (l.t) |want| {
        const got = bcs.tree.renderAlloc(T, arena, &v) catch |e| return c.failf("tree: {s}", .{@errorName(e)});
        c.text("tree text", want, got);
    }
}

// ---------------------------------------------------------------- bcs-checkpoint

threadlocal var tl_index: ?index.CheckpointIndex = null;

fn workerIndex(ctx: *harness.Ctx) !*index.CheckpointIndex {
    if (tl_index == null) tl_index = try index.CheckpointIndex.init(std.heap.page_allocator);
    _ = ctx;
    return &tl_index.?;
}

fn runCheckpoint(ctx: *harness.Ctx) !void {
    try ctx.forEachFile("truth/checkpoint", ".jsonl.zst", {}, checkpointFile);
}

fn expectRange(c: *harness.Check, what: []const u8, l: truth.Line, r: index.Range) void {
    if (l.o != r.o or l.n != r.n) c.failf("{s}: truth {d}+{d}, index {d}+{d}", .{ what, l.o, l.n, r.o, r.n });
}

fn checkpointFile(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const seq_text = name[0 .. name.len - ".jsonl.zst".len];
    var c = ctx.check(seq_text);
    defer _ = c.finish();
    const f = truthFile(ctx, name) catch |e| return c.failf("read: {s}", .{@errorName(e)});
    const arena = ctx.scratch();
    const blob = f.blob;
    if (blob.len == 0 or blob[0] != 1) return c.failf("bad blob tag", .{});

    // Whole CheckpointData decode and re-encode.
    const v = bcs.decode(gen.CheckpointData, arena, blob[1..]) catch |e| return c.failf("decode CheckpointData: {s}", .{@errorName(e)});
    const re = bcs.encodeAlloc(gen.CheckpointData, arena, &v) catch |e| return c.failf("encode: {s}", .{@errorName(e)});
    c.bytes("CheckpointData re-encoded", blob[1..], re);

    // One-pass index vs the truth table.
    const idx = workerIndex(ctx) catch |e| return c.failf("index alloc: {s}", .{@errorName(e)});
    index.indexCheckpointData(blob, idx) catch |e| return c.failf("indexCheckpointData: {s}", .{@errorName(e)});
    var it = harness.lines(f.text);
    const hline = it.next() orelse return c.failf("empty truth", .{});
    const h = truth.parseHeader(arena, hline) catch |e| return c.failf("header: {s}", .{@errorName(e)});
    c.eql("tx count", h.txs, @as(u64, idx.tx_count));
    c.eql("tx count vs decoded", @as(u64, v.transactions.len), @as(u64, idx.tx_count));
    var seen: u64 = 0;
    while (it.next()) |line| {
        const l = truth.parseLine(line) catch return c.failf("malformed truth line", .{});
        if (!std.mem.endsWith(u8, l.p, ".inner")) seen += 1;
        matchLine(&c, idx, l);
    }
    // Every index entry must be a truth line (inner lines are derived from sig lines).
    var expect: u64 = 4; // summary, sig, cert, contents
    for (idx.txs[0..idx.tx_count]) |tx| {
        expect += 3 + tx.sig_count + @as(u64, if (tx.events != null) 1 else 0) + tx.in_count + tx.out_count;
    }
    c.eql("number of truth lines vs index entries", expect, seen);
}

/// Parses "tx[3].sig[1].inner" style paths and compares the range with the index.
fn matchLine(c: *harness.Check, idx: *const index.CheckpointIndex, l: truth.Line) void {
    const p = l.p;
    if (std.mem.eql(u8, p, "summary")) return expectRange(c, p, l, idx.summary);
    if (std.mem.eql(u8, p, "summary.sig")) return expectRange(c, p, l, idx.sig);
    if (std.mem.eql(u8, p, "summary.cert")) {
        return expectRange(c, p, l, .{ .o = idx.summary.o, .n = idx.sig.o + idx.sig.n - idx.summary.o });
    }
    if (std.mem.eql(u8, p, "contents")) return expectRange(c, p, l, idx.contents);
    if (!std.mem.startsWith(u8, p, "tx[")) return c.failf("unknown path {s}", .{p});
    const close = std.mem.indexOfScalar(u8, p, ']') orelse return c.failf("bad path {s}", .{p});
    const i = std.fmt.parseInt(usize, p[3..close], 10) catch return c.failf("bad path {s}", .{p});
    if (i >= idx.tx_count) return c.failf("{s}: tx index out of range", .{p});
    const tx = idx.txs[i];
    const rest = p[close + 1 ..];
    if (std.mem.eql(u8, rest, ".data")) return expectRange(c, p, l, tx.data);
    if (std.mem.eql(u8, rest, ".transaction")) return expectRange(c, p, l, tx.transaction);
    if (std.mem.eql(u8, rest, ".effects")) return expectRange(c, p, l, tx.effects);
    if (std.mem.eql(u8, rest, ".events")) {
        const e = tx.events orelse return c.failf("{s}: truth has events, index has none", .{p});
        return expectRange(c, p, l, e);
    }
    const which: enum { sig, in, out } = if (std.mem.startsWith(u8, rest, ".sig[")) .sig else if (std.mem.startsWith(u8, rest, ".in[")) .in else if (std.mem.startsWith(u8, rest, ".out[")) .out else return c.failf("unknown path {s}", .{p});
    const open = std.mem.indexOfScalar(u8, rest, '[').? + 1;
    const e2 = std.mem.indexOfScalar(u8, rest, ']') orelse return c.failf("bad path {s}", .{p});
    const j = std.fmt.parseInt(usize, rest[open..e2], 10) catch return c.failf("bad path {s}", .{p});
    const tail = rest[e2 + 1 ..];
    switch (which) {
        .sig => {
            if (j >= tx.sig_count) return c.failf("{s}: sig index out of range", .{p});
            const r = idx.sigs[tx.sig_first + j];
            if (tail.len == 0) return expectRange(c, p, l, r);
            if (!std.mem.eql(u8, tail, ".inner")) return c.failf("unknown path {s}", .{p});
            // Inner = after the ULEB length prefix and the flag byte.
            var k: u32 = 1;
            while (k <= 5 and bcs.ulebLen(r.n - k) != k) k += 1;
            expectRange(c, p, l, .{ .o = r.o + k + 1, .n = r.n - k - 1 });
        },
        .in, .out => {
            const cnt = if (which == .in) tx.in_count else tx.out_count;
            const first = if (which == .in) tx.in_first else tx.out_first;
            if (j >= cnt) return c.failf("{s}: object index out of range", .{p});
            expectRange(c, p, l, idx.objs[first + j]);
        },
    }
}

// ---------------------------------------------------------------- digests

fn runDigests(ctx: *harness.Ctx) !void {
    try ctx.forEachFile("truth/checkpoint", ".jsonl.zst", {}, digestFile);
}

/// Serde name used in the digest prefix, per truth kind.
fn digestName(comptime k: []const u8) ?[]const u8 {
    return if (std.mem.eql(u8, k, "CheckpointSummary")) "CheckpointSummary" else if (std.mem.eql(u8, k, "CheckpointContents")) "CheckpointContents" else if (std.mem.eql(u8, k, "TransactionData")) "TransactionData" else if (std.mem.eql(u8, k, "TransactionEffects")) "TransactionEffects" else if (std.mem.eql(u8, k, "TransactionEvents")) "TransactionEvents" else if (std.mem.eql(u8, k, "Object")) "Object" else null;
}

fn digestFile(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const f = truthFile(ctx, name) catch |e| {
        ctx.fail(name, "read: {s}", .{@errorName(e)});
        return;
    };
    var it = harness.lines(f.text);
    _ = it.next();
    var sig_epoch: ?u64 = null;
    var summary_raw: ?[]const u8 = null;
    var summary_sd: ?[]const u8 = null;
    while (it.next()) |line| {
        const l = truth.parseLine(line) catch {
            ctx.fail(name, "malformed truth line", .{});
            return;
        };
        const raw = l.raw(f.blob) catch {
            ctx.fail(try std.fmt.allocPrint(ctx.scratch(), "{s}/{s}", .{ f.seq_text, l.p }), "range outside the blob", .{});
            continue;
        };
        if (std.mem.eql(u8, l.k, "AuthorityStrongQuorumSignInfo") and raw.len >= 8) sig_epoch = std.mem.readInt(u64, raw[0..8], .little);
        if (l.d == null and l.sd == null) continue;
        const id = try std.fmt.allocPrint(ctx.scratch(), "{s}/{s}", .{ f.seq_text, l.p });
        var c = ctx.check(id);
        if (l.d) |d| {
            var matched = false;
            inline for (kind_types) |kt| {
                if (comptime digestName(kt[0])) |dn| {
                    if (!matched and std.mem.eql(u8, l.k, kt[0])) {
                        matched = true;
                        c.digestHex("digest d", d, &digest.digestOf(dn, raw));
                    }
                }
            }
            if (!matched) c.failf("kind {s} has d but no digest rule", .{l.k});
        }
        if (l.sd) |sd| {
            if (std.mem.eql(u8, l.k, "TransactionData")) {
                c.digestHex("signing digest sd", sd, &digest.transactionSigningDigest(raw));
            } else if (std.mem.eql(u8, l.k, "CheckpointSummary")) {
                summary_raw = raw;
                summary_sd = sd;
            } else c.failf("kind {s} has sd but no rule", .{l.k});
        }
        _ = c.finish();
        if (summary_raw != null and sig_epoch == null) {
            // the signature line follows the summary; checked below once we have its epoch
        }
    }
    if (summary_raw) |raw| {
        const id = try std.fmt.allocPrint(ctx.scratch(), "{s}/summary.sd", .{f.seq_text});
        var c = ctx.check(id);
        if (sig_epoch) |ep| {
            c.digestHex("checkpoint signing digest sd", summary_sd.?, &digest.checkpointSigningDigest(raw, ep));
        } else c.failf("no summary.sig line", .{});
        _ = c.finish();
    }
}

// ---------------------------------------------------------------- bench

const BenchState = struct { blobs: []const []const u8, txs: u64 };

fn loadBench(ctx: *harness.Ctx, arena: std.mem.Allocator) !BenchState {
    const names = ctx.benchInputs();
    const blobs = try arena.alloc([]const u8, names.len);
    var txs: u64 = 0;
    for (names, blobs) |n, *b| {
        b.* = try ctx.corpus.readFileAlloc(ctx.io, n, arena, .limited(max_blob));
        // tx count is the last uleb before the per-tx data; get it from the index
        var idx = try index.CheckpointIndex.init(std.heap.page_allocator);
        defer idx.deinit(std.heap.page_allocator);
        try index.indexCheckpointData(b.*, &idx);
        txs += idx.tx_count;
    }
    return .{ .blobs = blobs, .txs = txs };
}

fn benchDecode(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const st = try loadBench(ctx, arena_state.allocator());
    const S = struct {
        fn pass(b: []const []const u8) !void {
            var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer scratch.deinit();
            for (b) |blob| {
                _ = scratch.reset(.retain_capacity);
                const v = try bcs.decode(gen.CheckpointData, scratch.allocator(), blob[1..]);
                std.mem.doNotOptimizeAway(&v);
            }
        }
        fn roundtrip(b: []const []const u8) !void {
            var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer scratch.deinit();
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(std.heap.page_allocator);
            for (b) |blob| {
                _ = scratch.reset(.retain_capacity);
                const v = try bcs.decode(gen.CheckpointData, scratch.allocator(), blob[1..]);
                try out.resize(std.heap.page_allocator, blob.len);
                var w = bcs.Writer.init(out.items);
                try bcs.encode(gen.CheckpointData, &v, &w);
                std.mem.doNotOptimizeAway(w.written().ptr);
            }
        }
    };
    try ctx.benchPasses("decode", "tx", st.txs, st.blobs, S.pass);
    try ctx.benchPasses("roundtrip", "tx", st.txs, st.blobs, S.roundtrip);
}

fn benchIndex(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const st = try loadBench(ctx, arena_state.allocator());
    const S = struct {
        fn pass(b: []const []const u8) !void {
            var idx = try index.CheckpointIndex.init(std.heap.page_allocator);
            defer idx.deinit(std.heap.page_allocator);
            for (b) |blob| {
                try index.indexCheckpointData(blob, &idx);
                std.mem.doNotOptimizeAway(&idx);
            }
        }
    };
    try ctx.benchPasses("index", "tx", st.txs, st.blobs, S.pass);
}

fn benchDigests(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const st = try loadBench(ctx, arena);
    const S = struct {
        fn pass(b: []const []const u8) !void {
            var idx = try index.CheckpointIndex.init(std.heap.page_allocator);
            defer idx.deinit(std.heap.page_allocator);
            for (b) |blob| {
                try index.indexCheckpointData(blob, &idx);
                var acc: u8 = 0;
                const sum = digest.checkpointSummaryDigest(idx.summary.slice(blob));
                acc ^= sum[0];
                const con = digest.checkpointContentsDigest(idx.contents.slice(blob));
                acc ^= con[0];
                // Every value of the checkpoint goes through the multi-buffer Blake2b kernel in one pass.
                const cap = 3 * idx.tx_count + idx.obj_total;
                const items = try std.heap.page_allocator.alloc(digest.Item, cap);
                defer std.heap.page_allocator.free(items);
                const parts = try std.heap.page_allocator.alloc([2][]const u8, cap);
                defer std.heap.page_allocator.free(parts);
                const inputs = try std.heap.page_allocator.alloc([]const []const u8, cap);
                defer std.heap.page_allocator.free(inputs);
                const outs = try std.heap.page_allocator.alloc([32]u8, cap);
                defer std.heap.page_allocator.free(outs);
                var n: usize = 0;
                for (idx.txs[0..idx.tx_count]) |tx| {
                    items[n] = .{ .prefix = digest.prefixOf("TransactionData"), .raw = tx.data.slice(blob) };
                    items[n + 1] = .{ .prefix = digest.prefixOf("TransactionEffects"), .raw = tx.effects.slice(blob) };
                    n += 2;
                    if (tx.events) |e| {
                        items[n] = .{ .prefix = digest.prefixOf("TransactionEvents"), .raw = e.slice(blob) };
                        n += 1;
                    }
                }
                for (idx.objs[0..idx.obj_total]) |o| {
                    items[n] = .{ .prefix = digest.prefixOf("Object"), .raw = o.slice(blob) };
                    n += 1;
                }
                digest.digestMixed(items[0..n], parts[0..n], inputs[0..n], outs[0..n]);
                for (outs[0..n]) |o| acc ^= o[0];
                std.mem.doNotOptimizeAway(acc);
            }
        }
    };
    try ctx.benchPasses("digests", "tx", st.txs, st.blobs, S.pass);
}
