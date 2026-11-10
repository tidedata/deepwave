//! Conformance suites of the checkpoint-verify lane (CONTRACTS.md section 3.3).
//!
//!   committee          vectors/checkpoint-verify/committees.jsonl (one committee per epoch, from
//!                      Mysten's `Committee::new` over the genesis system state and every
//!                      end-of-epoch `next_epoch_committee`) and synth.jsonl (`Committee::new` on
//!                      inputs the chain never produced). Items: one per epoch, one per synthetic
//!                      case, and `chain/<epoch>`: the committee chain walked from genesis, each
//!                      epoch's end-of-epoch certificate verified under the committee deepwave derived.
//!   checkpoint-verify  vectors/checkpoint-verify/verify/<epoch>.jsonl: every corpus checkpoint
//!                      (real) and 20 to 30 mutated or re-chained variants each, with the verdict
//!                      of the full sui-types verification path. Deepwave applies the same byte
//!                      mutation to the blob, derives every committee itself (genesis blob, then
//!                      end-of-epoch data of the previous epoch) and must return the same verdict.
//!
//! Truth tool and formats: tools/truth/checkpoint-verify/README.md.
const std = @import("std");
const harness = @import("harness");
const core = @import("core");
const types = @import("types");
const hash = @import("hash");
const root = @import("root.zig");
const committee_mod = @import("committee.zig");
const genesis = @import("genesis.zig");
const verify = @import("verify.zig");
const summary_mod = @import("summary.zig");
const Committee = committee_mod.Committee;
const Member = committee_mod.Member;

pub const suites = [_]harness.Suite{
    .{
        .name = "checkpoint-verify",
        .lane = "checkpoint-verify",
        .doc = "verdict for every corpus checkpoint and its generated negatives (epochs, signers, signature, contents, digests, user signatures, chain steps, byte flips) equals sui-types",
        .run = runVerify,
        .bench = benchVerify,
        .baselines = &.{
            .{ .name = "verify-cert", .argv = &.{ "{release}/zui-truth-checkpoint", "bench", "verify-cert" } },
            .{ .name = "verify-data", .argv = &.{ "{release}/zui-truth-checkpoint", "bench", "verify-data" } },
        },
    },
    .{
        .name = "committee",
        .lane = "checkpoint-verify",
        .doc = "committee of every epoch (genesis blob, then each end-of-epoch next_epoch_committee) and Committee::new edge cases equal sui-types; the chain of end-of-epoch certificates verifies",
        .run = runCommittee,
        .bench = benchCommittee,
        .baselines = &.{
            .{ .name = "committee-prepare", .argv = &.{ "{release}/zui-truth-checkpoint", "bench", "committee-prepare" } },
        },
        .inputs = .{ .dir = "vectors/checkpoint-verify", .suffix = "committees.jsonl" },
    },
};

const genesis_path = "vectors/bls-cert/upstream/genesis.blob";

// ---------------------------------------------------------------------------------------------
// shared pieces

fn hexAlloc(a: std.mem.Allocator, s: []const u8) ![]u8 {
    return core.hex.decodeAlloc(a, s);
}

/// Index scratch arrays, one set per thread: address space only, pages are committed on use.
threadlocal var tl_index: ?types.CheckpointIndex = null;
fn threadIndex() !*types.CheckpointIndex {
    if (tl_index == null) tl_index = try types.CheckpointIndex.init(std.heap.page_allocator);
    return &tl_index.?;
}

const EpochLine = struct { epoch: u64, first: u64, last: ?u64 = null };

/// Committees as deepwave derives them: epoch 0 from the genesis blob, epoch e from the end-of-epoch
/// checkpoint of e - 1. Built on demand and kept for the run.
const Store = struct {
    mu: std.Io.Mutex = .init,
    arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator),
    genesis_blob: []const u8,
    /// Last checkpoint of every completed epoch (the end-of-epoch checkpoint), by epoch.
    last: []const ?u64,
    cache: []?*const Committee,

    fn init(ctx: *harness.Ctx) !*Store {
        const a = ctx.gpa;
        const st = try a.create(Store);
        st.* = .{ .genesis_blob = undefined, .last = undefined, .cache = undefined };
        const pa = st.arena.allocator();
        st.genesis_blob = try ctx.corpus.readFileAlloc(ctx.io, genesis_path, pa, .limited(64 << 20));
        const text = try ctx.corpus.readFileAlloc(ctx.io, "epochs.jsonl", pa, .limited(64 << 20));
        var last: std.ArrayList(?u64) = .empty;
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            const e = try std.json.parseFromSliceLeaky(EpochLine, ctx.scratch(), line, .{ .ignore_unknown_fields = true });
            if (e.epoch != last.items.len) return error.EpochIndexGap;
            try last.append(pa, e.last);
        }
        st.last = last.items;
        st.cache = try pa.alloc(?*const Committee, last.items.len + 1);
        @memset(st.cache, null);
        return st;
    }

    fn deinit(st: *Store, ctx: *harness.Ctx) void {
        st.arena.deinit();
        ctx.gpa.destroy(st);
    }

    /// The committee of `epoch`.
    fn get(st: *Store, ctx: *harness.Ctx, epoch: u64) !*const Committee {
        st.mu.lockUncancelable(ctx.io);
        defer st.mu.unlock(ctx.io);
        return st.getLocked(ctx, epoch);
    }

    fn getLocked(st: *Store, ctx: *harness.Ctx, epoch: u64) !*const Committee {
        if (epoch >= st.cache.len) return error.NoSuchEpoch;
        if (st.cache[epoch]) |c| return c;
        const pa = st.arena.allocator();
        const c = try pa.create(Committee);
        if (epoch == 0) {
            c.* = try genesis.genesisCommittee(pa, st.genesis_blob);
        } else {
            const seq = st.last[epoch - 1] orelse return error.NoEndOfEpochCheckpoint;
            const path = try std.fmt.allocPrint(ctx.scratch(), "chk/{d}.chk", .{seq});
            const blob = try ctx.corpus.readFileAlloc(ctx.io, path, ctx.scratch(), .limited(1 << 30));
            // a third index: callers hold the other two while they ask for a committee
            const idx = try threadIndexStore();
            try types.indexCheckpointData(blob, idx);
            const s = try summary_mod.Summary.parse(idx.summary.slice(blob));
            c.* = try root.nextCommittee(pa, s);
        }
        st.cache[epoch] = c;
        return c;
    }
};

// ---------------------------------------------------------------------------------------------
// checkpoint-verify

const VerifyLine = struct {
    seq: u64,
    case: []const u8,
    mut: struct {
        xor: ?[]const [2]u64 = null,
        splice: ?[]const std.json.Value = null,
        drop_last_tx: ?bool = null,
    },
    committee: ?u64 = null,
    prev: ?struct { digest: []const u8, seq: u64, epoch: u64, eoe: bool } = null,
    verdict: []const u8,
    what: ?[]const u8 = null,
    index: ?u32 = null,
};

fn runVerify(ctx: *harness.Ctx) !void {
    const st = try Store.init(ctx);
    defer st.deinit(ctx);
    try ctx.forEachFile("vectors/checkpoint-verify/verify", ".jsonl", st, verifyFile);
}

fn verdictText(a: std.mem.Allocator, v: verify.Verdict) ![]const u8 {
    return switch (v) {
        .digest_mismatch => |d| std.fmt.allocPrint(a, "digest_mismatch/{s}/{d}", .{ @tagName(d.what), d.index }),
        else => @tagName(v),
    };
}

fn uleb(a: std.mem.Allocator, out: *std.ArrayList(u8), n: usize) !void {
    var x = n;
    while (true) {
        const b: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x == 0) return out.append(a, b);
        try out.append(a, b | 0x80);
    }
}

/// The truth tool's `apply`: xors, then splice, then dropping the last transaction. `idx` is the
/// index of the unmutated blob (it gives the layout the tool used).
fn mutate(a: std.mem.Allocator, blob: []const u8, m: anytype, idx: *const types.CheckpointIndex) ![]const u8 {
    var b = try a.dupe(u8, blob);
    if (m.xor) |xs| for (xs) |x| {
        if (x[0] >= b.len) return error.MutationOutOfRange;
        b[x[0]] ^= @intCast(x[1]);
    };
    if (m.splice) |sp| {
        if (sp.len != 3) return error.BadSplice;
        const off: usize = @intCast(sp[0].integer);
        const del: usize = @intCast(sp[1].integer);
        const ins = try hexAlloc(a, sp[2].string);
        if (off + del > b.len) return error.MutationOutOfRange;
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(a, b[0..off]);
        try out.appendSlice(a, ins);
        try out.appendSlice(a, b[off + del ..]);
        b = out.items;
    }
    if (m.drop_last_tx orelse false) {
        const n: usize = idx.tx_count;
        if (n == 0) return error.NoTransactionToDrop;
        const count_off: usize = idx.contents.o + idx.contents.n;
        const last_start: usize = idx.txs[n - 1].transaction.o;
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(a, b[0..count_off]);
        try uleb(a, &out, n - 1);
        try out.appendSlice(a, b[count_off + bcsUlebLen(n) .. last_start]);
        b = out.items;
    }
    return b;
}

fn bcsUlebLen(n: usize) usize {
    var l: usize = 1;
    var x = n;
    while (x >= 0x80) : (x >>= 7) l += 1;
    return l;
}

fn verifyFile(st: *Store, ctx: *harness.Ctx, name: []const u8) !void {
    const epoch = std.fmt.parseInt(u64, name[0 .. name.len - ".jsonl".len], 10) catch return error.BadFileName;
    const a = ctx.scratch();
    const path = try std.fmt.allocPrint(a, "vectors/checkpoint-verify/verify/{s}", .{name});
    const text = try ctx.readFile(path, 512 << 20);
    const idx = try threadIndex();
    const idx2 = try threadIndex2();
    var cur_seq: ?u64 = null;
    var blob: []const u8 = &.{};
    var it = std.mem.splitScalar(u8, text, '\n');
    var line_arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer line_arena.deinit();
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (ctx.done()) return;
        _ = line_arena.reset(.retain_capacity);
        const la = line_arena.allocator();
        const v = try std.json.parseFromSliceLeaky(VerifyLine, la, line, .{ .ignore_unknown_fields = true });
        const id = try std.fmt.allocPrint(la, "{d}/{s}", .{ v.seq, v.case });
        if (!ctx.selected(id)) continue;
        if (cur_seq == null or cur_seq.? != v.seq) {
            const bp = try std.fmt.allocPrint(la, "chk/{d}.chk", .{v.seq});
            blob = try ctx.readFile(bp, 1 << 30);
            cur_seq = v.seq;
        }
        const got = oneCase(st, ctx, la, epoch, &v, blob, idx, idx2) catch |e| {
            ctx.fail(id, "error {s}", .{@errorName(e)});
            continue;
        };
        var want: []const u8 = v.verdict;
        if (v.what) |w| want = try std.fmt.allocPrint(la, "{s}/{s}/{d}", .{ v.verdict, w, v.index.? });
        _ = ctx.expectText(id, "verdict", want, got);
    }
}

threadlocal var tl_index_store: ?types.CheckpointIndex = null;
fn threadIndexStore() !*types.CheckpointIndex {
    if (tl_index_store == null) tl_index_store = try types.CheckpointIndex.init(std.heap.page_allocator);
    return &tl_index_store.?;
}

threadlocal var tl_index2: ?types.CheckpointIndex = null;
fn threadIndex2() !*types.CheckpointIndex {
    if (tl_index2 == null) tl_index2 = try types.CheckpointIndex.init(std.heap.page_allocator);
    return &tl_index2.?;
}

fn oneCase(st: *Store, ctx: *harness.Ctx, la: std.mem.Allocator, epoch: u64, v: *const VerifyLine, blob: []const u8, idx: *types.CheckpointIndex, idx2: *types.CheckpointIndex) ![]const u8 {
    const c = try st.get(ctx, v.committee orelse epoch);
    var prev_storage: verify.Prev = undefined;
    var prev: ?*const verify.Prev = null;
    if (v.prev) |p| {
        prev_storage = .{ .digest = undefined, .sequence_number = p.seq, .epoch = p.epoch, .end_of_epoch = p.eoe };
        try core.hex.decode(&prev_storage.digest, p.digest);
        prev = &prev_storage;
    }
    var bytes = blob;
    const mutated = v.mut.xor != null or v.mut.splice != null or (v.mut.drop_last_tx orelse false);
    if (mutated) {
        try types.indexCheckpointData(blob, idx);
        bytes = try mutate(la, blob, v.mut, idx);
    }
    if (std.mem.startsWith(u8, v.case, "obj-")) {
        // apply mode: output objects against effects
        types.indexCheckpointData(bytes, idx2) catch return verdictText(la, .decode);
        if (!verify.decodeChecks(bytes, idx2)) return verdictText(la, .decode);
        var chk = root.ObjectChecker.init(std.heap.page_allocator);
        defer chk.deinit();
        return verdictText(la, try chk.verifyOutputObjects(idx2, bytes));
    }
    const verdict = verify.verifyBlob(c, bytes, idx2, prev);
    return verdictText(la, verdict);
}

// bench

const BenchSet = struct {
    blobs: []const []const u8,
    committees: []const *const Committee,
    summaries: []const types.index.Range,
    sigs: []const types.index.Range,
};

fn benchVerify(ctx: *harness.Ctx) !void {
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const st = try Store.init(ctx);
    defer st.deinit(ctx);
    const inputs = ctx.benchInputs();
    const blobs = try a.alloc([]const u8, inputs.len);
    const comms = try a.alloc(*const Committee, inputs.len);
    const sums = try a.alloc(types.index.Range, inputs.len);
    const sigs = try a.alloc(types.index.Range, inputs.len);
    const idx = try threadIndex();
    var txs: u64 = 0;
    for (inputs, blobs, comms, sums, sigs) |p, *b, *c, *sr, *gr| {
        b.* = try ctx.corpus.readFileAlloc(ctx.io, p, a, .limited(1 << 30));
        try types.indexCheckpointData(b.*, idx);
        const s = try summary_mod.Summary.parse(idx.summary.slice(b.*));
        c.* = try st.get(ctx, s.epoch);
        sr.* = idx.summary;
        gr.* = idx.sig;
        txs += idx.tx_count;
    }
    const set: BenchSet = .{ .blobs = blobs, .committees = comms, .summaries = sums, .sigs = sigs };
    // the certificate check alone, on already located summary and signature (Rust: decoded)
    try ctx.benchPasses("verify-cert", "cert", blobs.len, set, struct {
        fn f(x: BenchSet) !void {
            for (x.blobs, x.committees, x.summaries, x.sigs) |b, c, sr, gr| {
                const v = verify.verifyCertifiedSummary(c, .{ .summary = sr.slice(b), .sig = gr.slice(b) });
                if (v != .ok) {
                    std.debug.print("bench cert verdict {s}\n", .{@tagName(v)});
                    return error.BenchCertRejected;
                }
            }
        }
    }.f);
    // validate the whole blob, then the chain-less verification of everything in it
    try ctx.benchPasses("verify-data", "tx", txs, set, struct {
        fn f(x: BenchSet) !void {
            const ix = try threadIndex();
            for (x.blobs, x.committees) |b, c| {
                const v = verify.verifyBlob(c, b, ix, null);
                if (v != .ok) return error.BenchBlobRejected;
            }
        }
    }.f);
}

// ---------------------------------------------------------------------------------------------
// committee

const CommitteeLine = struct {
    epoch: u64,
    keys: []const []const u8,
    stakes: []const u64,
    total: u64,
    quorum: u64,
    validity: u64,
    src: []const u8,
    eoe_seq: ?u64 = null,
};

const SynthLine = struct {
    id: []const u8,
    epoch: u64,
    rights: []const std.json.Value,
    verdict: []const u8,
    keys: ?[]const []const u8 = null,
    stakes: ?[]const u64 = null,
    total: ?u64 = null,
    quorum: ?u64 = null,
    validity: ?u64 = null,
    /// A certificate under this line's committee and the verdict of Mysten's
    /// `verify_authority_signatures` on it.
    cert: ?struct { summary: []const u8, sig: []const u8, verdict: []const u8 } = null,
};

/// A JSON stake: u64 values past i64 arrive as number strings.
fn jsonU64(v: std.json.Value) !u64 {
    return switch (v) {
        .integer => |i| std.math.cast(u64, i) orelse error.BadSynthStake,
        .number_string => |t| std.fmt.parseInt(u64, t, 10),
        else => error.BadSynthStake,
    };
}

fn runCommittee(ctx: *harness.Ctx) !void {
    const st = try Store.init(ctx);
    defer st.deinit(ctx);
    const text = try ctx.corpus.readFileAlloc(ctx.io, "vectors/checkpoint-verify/committees.jsonl", ctx.gpa, .limited(256 << 20));
    defer ctx.gpa.free(text);
    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(ctx.gpa);
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |l| if (l.len != 0) try lines.append(ctx.gpa, l);
    const State = struct { st: *Store, lines: []const []const u8 };
    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |n| ctx.gpa.free(n);
        names.deinit(ctx.gpa);
    }
    try names.append(ctx.gpa, try ctx.gpa.dupe(u8, "synth"));
    try names.append(ctx.gpa, try ctx.gpa.dupe(u8, "chain"));
    for (0..lines.items.len) |i| try names.append(ctx.gpa, try std.fmt.allocPrint(ctx.gpa, "epoch/{d}", .{i}));
    const state: State = .{ .st = st, .lines = lines.items };
    try ctx.forEachName(names.items, state, struct {
        fn f(s: State, c: *harness.Ctx, name: []const u8) !void {
            if (std.mem.eql(u8, name, "synth")) return synthItems(c);
            if (std.mem.eql(u8, name, "chain")) return chainItem(s.st, c);
            const e = try std.fmt.parseInt(usize, name["epoch/".len..], 10);
            return epochItem(s.st, c, s.lines[e]);
        }
    }.f);
}

fn epochItem(st: *Store, ctx: *harness.Ctx, line: []const u8) !void {
    const a = ctx.scratch();
    const cl = try std.json.parseFromSliceLeaky(CommitteeLine, a, line, .{ .ignore_unknown_fields = true });
    const id = try std.fmt.allocPrint(a, "epoch/{d}", .{cl.epoch});
    if (!ctx.selected(id)) return;
    const got = st.get(ctx, cl.epoch) catch |e| {
        ctx.fail(id, "error {s}", .{@errorName(e)});
        return;
    };
    var c = ctx.check(id);
    compareCommittee(&c, a, got, cl.epoch, cl.keys, cl.stakes, cl.total, cl.quorum, cl.validity);
    _ = c.finish();
}

fn compareCommittee(c: *harness.Check, a: std.mem.Allocator, got: *const Committee, epoch: u64, keys: []const []const u8, stakes: []const u64, total: u64, quorum: u64, validity: u64) void {
    c.eql("epoch", epoch, got.epoch);
    c.eql("members", keys.len, got.members.len);
    c.eql("total", total, got.total_stake);
    c.eql("quorum", quorum, got.quorum_threshold);
    c.eql("validity", validity, got.validity_threshold);
    if (keys.len != got.members.len) return;
    for (keys, stakes, got.members, 0..) |k, s, m, i| {
        const want = hexAlloc(a, k) catch {
            c.failf("member {d}: truth key is not hex", .{i});
            return;
        };
        if (!std.mem.eql(u8, want, &m.name)) {
            c.failf("member {d}: key differs", .{i});
            return;
        }
        if (s != m.stake) {
            c.failf("member {d}: stake {d}, truth {d}", .{ i, m.stake, s });
            return;
        }
    }
}

fn synthItems(ctx: *harness.Ctx) !void {
    const a = ctx.scratch();
    const text = try ctx.readFile("vectors/checkpoint-verify/synth.jsonl", 64 << 20);
    var it = std.mem.splitScalar(u8, text, '\n');
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    while (it.next()) |line| {
        if (line.len == 0) continue;
        _ = arena.reset(.retain_capacity);
        const la = arena.allocator();
        const v = try std.json.parseFromSliceLeaky(SynthLine, la, line, .{ .ignore_unknown_fields = true });
        const id = try std.fmt.allocPrint(a, "synth/{s}", .{v.id});
        if (!ctx.selected(id)) continue;
        const rights = try la.alloc(Member, v.rights.len);
        for (v.rights, rights) |r, *m| {
            const kb = try hexAlloc(la, r.array.items[0].string);
            if (kb.len != 96) return error.BadSynthKey;
            m.name = kb[0..96].*;
            m.stake = try jsonU64(r.array.items[1]);
        }
        const res = Committee.init(la, v.epoch, rights);
        if (std.mem.eql(u8, v.verdict, "panic")) {
            if (res) |_| ctx.fail(id, "Mysten panics, zui built a committee", .{}) else |_| ctx.pass(id);
            continue;
        }
        const got = res catch |e| {
            ctx.fail(id, "Mysten builds the committee, zui: {s}", .{@errorName(e)});
            continue;
        };
        var c = ctx.check(id);
        compareCommittee(&c, la, &got, v.epoch, v.keys.?, v.stakes.?, v.total.?, v.quorum.?, v.validity.?);
        if (v.cert) |cert| {
            const verdict = verify.verifyCertifiedSummary(&got, .{ .summary = try hexAlloc(la, cert.summary), .sig = try hexAlloc(la, cert.sig) });
            c.text("cert verdict", cert.verdict, try verdictText(la, verdict));
        }
        _ = c.finish();
    }
}

/// Walks the chain from genesis: the end-of-epoch certificate of every completed epoch must
/// verify under the committee deepwave derived for that epoch (and the next committee comes from
/// that same, now trusted, checkpoint).
fn chainItem(st: *Store, ctx: *harness.Ctx) !void {
    const idx = try threadIndex();
    var e: u64 = 0;
    while (e < st.last.len) : (e += 1) {
        const seq = st.last[e] orelse continue;
        const a = ctx.scratch();
        const id = try std.fmt.allocPrint(a, "chain/{d}", .{e});
        if (!ctx.selected(id)) continue;
        if (ctx.done()) return;
        const c = st.get(ctx, e) catch |err| {
            ctx.fail(id, "committee: {s}", .{@errorName(err)});
            continue;
        };
        const path = try std.fmt.allocPrint(a, "chk/{d}.chk", .{seq});
        const blob = ctx.readFile(path, 1 << 30) catch {
            ctx.skip(id, "end-of-epoch checkpoint not in the corpus");
            continue;
        };
        const v = verify.verifyBlob(c, blob, idx, null);
        if (v != .ok) {
            ctx.fail(id, "end-of-epoch checkpoint {d} verdict {s}", .{ seq, try verdictText(a, v) });
            continue;
        }
        // the checkpoint is trusted: its next committee must be the one deepwave builds for e + 1
        const s = try summary_mod.Summary.parse(idx.summary.slice(blob));
        if (s.next_committee == null or s.epoch != e) {
            ctx.fail(id, "checkpoint {d} is not the end of epoch {d}", .{ seq, e });
            continue;
        }
        ctx.pass(id);
    }
}

fn benchCommittee(ctx: *harness.Ctx) !void {
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const text = try ctx.corpus.readFileAlloc(ctx.io, "vectors/checkpoint-verify/committees.jsonl", a, .limited(256 << 20));
    var all: std.ArrayList([]const Member) = .empty;
    var n_keys: u64 = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const cl = try std.json.parseFromSliceLeaky(CommitteeLine, a, line, .{ .ignore_unknown_fields = true });
        const ms = try a.alloc(Member, cl.keys.len);
        for (cl.keys, cl.stakes, ms) |k, s, *m| {
            m.name = (try hexAlloc(a, k))[0..96].*;
            m.stake = s;
        }
        try all.append(a, ms);
        n_keys += ms.len;
    }
    var prep = std.heap.ArenaAllocator.init(ctx.gpa);
    defer prep.deinit();
    const State = struct { all: []const []const Member, arena: *std.heap.ArenaAllocator };
    try ctx.benchPasses("committee-prepare", "key", n_keys, State{ .all = all.items, .arena = &prep }, struct {
        fn f(s: State) !void {
            for (s.all, 0..) |ms, e| {
                _ = s.arena.reset(.retain_capacity);
                const c = try Committee.init(s.arena.allocator(), e, ms);
                std.mem.doNotOptimizeAway(&c);
            }
        }
    }.f);
}
