//! Stage 5 of the validator speed bench: checkpoint building from real committed transaction
//! sets. For every checkpoint of `bench/val-bench/ckpt.list` whose predecessor is in the corpus,
//! deepwave's builder (checkpoints/create.zig, causal_order.zig) gets the recorded effects (as the
//! bytes its store holds), the user signatures, the randomness rounds and the previous summary,
//! and builds contents and summary, timed per checkpoint: effects views, causal order of every
//! commit group (fed reversed), contents, summary, BCS and digests. Same work as
//! tools/truth/val-bench `ckpt` (sui-core's CausalOrder + CheckpointContents/CheckpointSummary).
//! Output per checkpoint "<seq> <contents digest> <summary digest> <order ok>"; the bytes are
//! also checked against the recorded mainnet checkpoint.
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const common = @import("common.zig");
const cps = @import("../checkpoints/root.zig");

const Allocator = std.mem.Allocator;
const ev = cps.effects_view;
const create = cps.create;
const causal = cps.causal_order;
const replay = @import("../checkpoints/replay.zig");
const builder = cps.builder;

const Ckpt = struct {
    seq: u64,
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    timestamp_ms: u64,
    prev: types.CheckpointSummary,
    prev_bcs: []const u8,
    raw_effects: []const []const u8,
    classes: []const builder.TxClass,
    sigs: []const []const create.SigEntry,
    rounds: []const u64,
    eoe: ?types.EndOfEpochData,
    want_contents: []const u8,
    want_summary: []const u8,
};

fn isPrologue(c: builder.TxClass) bool {
    return c == .consensus_commit_prologue;
}
fn isSettlement(c: builder.TxClass) bool {
    return c == .programmable_system;
}

/// The timed part. Returns the output line in `w` and whether contents/summary equal the recorded.
fn build(a: Allocator, c: *const Ckpt, w: ?*std.Io.Writer, recorded_ok: ?*bool) !void {
    const n = c.raw_effects.len;
    const views = try a.alloc(ev.View, n);
    for (c.raw_effects, views) |r, *v| v.* = try ev.View.parse(a, r);
    // causal order per commit group (as replay.zig and the Rust side)
    var order_ok = true;
    const has_random = for (c.classes) |k| {
        if (k == .randomness_state_update) break true;
    } else false;
    const has_settlement = for (c.classes) |k| {
        if (isSettlement(k)) break true;
    } else false;
    if (!c.cfg.feature_flags.disable_effects_tx_dependencies and !(has_random and !has_settlement)) {
        const body_end = if (c.eoe != null) n - 1 else n;
        var start: usize = 0;
        var i: usize = 0;
        while (i <= body_end) : (i += 1) {
            const boundary = i == body_end or (i > start and isPrologue(c.classes[i]));
            if (!boundary) continue;
            if (i > start) {
                var end = i;
                while (end > start and isSettlement(c.classes[end - 1])) end -= 1;
                const group = views[start..end];
                const ccp_first = group.len > 0 and isPrologue(c.classes[start]);
                const rev = try a.alloc(ev.View, group.len);
                const keep: usize = if (ccp_first) 1 else 0;
                if (ccp_first) rev[0] = group[0];
                for (group[keep..], 0..) |g, k| rev[group.len - 1 - k] = g;
                const got = try causal.orderForCheckpoint(a, rev, ccp_first, false);
                for (got, group) |g, x| order_ok = order_ok and std.mem.eql(u8, &g.tx, &x.tx);
            }
            start = i;
        }
    }
    const last = create.LastBuilt.fromSummary(&c.prev, types.digest.checkpointSummaryDigest(c.prev_bcs), null);
    var eoe_in: ?create.EndOfEpoch = null;
    var rolling: ?ev.GasSummary = null;
    if (c.eoe) |e| {
        const committee = try a.alloc(create.CommitteeEntry, e.nextEpochCommittee.len);
        for (e.nextEpochCommittee, committee) |m, *o| o.* = .{ .name = m[0].@"0", .stake = m[1] };
        var root: [32]u8 = @splat(0);
        for (e.epochCommitments) |cm| switch (cm) {
            .ECMHLiveObjectSetDigest => |d| root = d.digest.@"0",
            else => {},
        };
        eoe_in = .{ .next_committee = committee, .next_protocol_version = e.nextEpochProtocolVersion.@"0", .root_state_digest = root };
        rolling = create.rollingGas(last, c.epoch, create.gasOf(views[0 .. n - 1]));
    }
    const created = try create.create(a, .{
        .cfg = c.cfg,
        .epoch = c.epoch,
        .seq = c.seq,
        .timestamp_ms = c.timestamp_ms,
        .last = last,
        .effects = views,
        .signatures = c.sigs,
        .randomness_rounds = c.rounds,
        .end_of_epoch = eoe_in,
        .rolling_gas = rolling,
    });
    if (w) |out| try out.print("{d} {x} {x} {d}\n", .{ c.seq, &created.contents_digest, &created.summary_digest, @intFromBool(order_ok) });
    if (recorded_ok) |r| r.* = std.mem.eql(u8, created.contents_bcs, c.want_contents) and std.mem.eql(u8, created.summary_bcs, c.want_summary);
}

const Par = struct {
    gpa: Allocator,
    items: []const Ckpt,
};

fn buildPar(p: *const Par, i: usize) void {
    var arena: std.heap.ArenaAllocator = .init(p.gpa);
    defer arena.deinit();
    build(arena.allocator(), &p.items[i], null, null) catch {};
}

pub fn run(ctx: *harness.Ctx) anyerror!void {
    const gpa = ctx.gpa;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const files = try common.readList(ctx, a, "ckpt");
    const epochs = try harness.corpus_suite.loadEpochs(ctx, a);
    var list: std.ArrayList(Ckpt) = .empty;
    var skipped: usize = 0;
    for (files) |rel| {
        const seq = try common.seqOf(rel);
        const prev_rel = try std.fmt.allocPrint(a, "chk/{d}.chk", .{seq -| 1});
        const prev_blob = ctx.corpus.readFileAlloc(ctx.io, prev_rel, a, .limited(1 << 31)) catch {
            skipped += 1;
            continue;
        };
        if (seq == 0) {
            skipped += 1;
            continue;
        }
        const blob = try ctx.corpus.readFileAlloc(ctx.io, rel, a, .limited(1 << 31));
        const cp = try bcs.decode(types.CheckpointData, a, blob[1..]);
        const prev_cp = try bcs.decode(types.CheckpointData, a, prev_blob[1..]);
        const summary = &cp.checkpoint_summary.data;
        const cfg = protocol.get(epochs[summary.epoch].pv, .mainnet) catch {
            skipped += 1;
            continue;
        };
        if (!cfg.feature_flags.prepend_prologue_tx_in_consensus_commit_in_checkpoints) {
            skipped += 1;
            continue;
        }
        const n = cp.transactions.len;
        const raw = try a.alloc([]const u8, n);
        const classes = try a.alloc(builder.TxClass, n);
        var rounds: std.ArrayList(u64) = .empty;
        for (cp.transactions, raw, classes) |*t, *r, *k| {
            r.* = try bcs.encodeAlloc(types.TransactionEffects, a, &t.effects);
            const st = t.transaction.data.@"0".element();
            const kind = switch (st.intent_message.value) {
                .V1 => |*v| &v.kind,
            };
            k.* = replay.classOf(kind);
            switch (k.*) {
                .randomness_state_update => |rr| try rounds.append(a, rr),
                else => {},
            }
        }
        const sigs = try a.alloc([]const create.SigEntry, n);
        switch (cp.checkpoint_contents) {
            .V1 => |c| for (c.user_signatures, sigs) |s, *o| {
                const l = try a.alloc(create.SigEntry, s.len);
                for (s, l) |x, *y| y.* = .{ x, null };
                o.* = l;
            },
            .V2 => |c| for (c.transactions, sigs) |t, *o| {
                o.* = t.user_signatures;
            },
        }
        try list.append(a, .{
            .seq = seq,
            .cfg = cfg,
            .epoch = summary.epoch,
            .timestamp_ms = summary.timestamp_ms,
            .prev = prev_cp.checkpoint_summary.data,
            .prev_bcs = try bcs.encodeAlloc(types.CheckpointSummary, a, &prev_cp.checkpoint_summary.data),
            .raw_effects = raw,
            .classes = classes,
            .sigs = sigs,
            .rounds = rounds.items,
            .eoe = summary.end_of_epoch_data,
            .want_contents = try bcs.encodeAlloc(types.CheckpointContents, a, &cp.checkpoint_contents),
            .want_summary = try bcs.encodeAlloc(types.CheckpointSummary, a, summary),
        });
    }
    const items = list.items;
    var outw: std.Io.Writer.Allocating = .init(a);
    var bad_recorded: usize = 0;
    var ntx: u64 = 0;
    for (items) |*c| {
        var scratch: std.heap.ArenaAllocator = .init(gpa);
        defer scratch.deinit();
        var ok = false;
        try build(scratch.allocator(), c, &outw.writer, &ok);
        if (!ok) bad_recorded += 1;
        ntx += c.raw_effects.len;
    }
    const mine = outw.written();
    const dg = common.digestHex(mine);
    const best = try a.alloc(u64, items.len);
    @memset(best, std.math.maxInt(u64));
    for (0..3) |_| for (items, best) |*c, *b| {
        var scratch: std.heap.ArenaAllocator = .init(gpa);
        defer scratch.deinit();
        const t0 = common.now(ctx.io);
        try build(scratch.allocator(), c, null, null);
        b.* = @min(b.*, common.since(ctx.io, t0));
    };
    var wall: u64 = 0;
    for (best) |x| wall += x;
    const extra = try std.fmt.allocPrint(a, ",\"txs\":{d},\"recorded_mismatch\":{d},\"skipped\":{d}", .{ ntx, bad_recorded, skipped });
    common.emit(ctx, .{ .stage = "ckpt", .case = "all", .mode = "build", .threads = 1, .unit = "checkpoint", .items = best, .count = items.len, .wall_ns = wall, .out = &dg, .extra = extra });
    const par: Par = .{ .gpa = gpa, .items = items };
    for ([_]usize{ 1, 4 }) |threads| {
        const w = common.parWall(ctx.io, items.len, threads, 3, &par, buildPar);
        common.emit(ctx, .{ .stage = "ckpt", .case = "all", .mode = "build-par", .threads = threads, .unit = "checkpoint", .count = items.len, .wall_ns = w, .out = &dg });
    }
    if (bad_recorded != 0) ctx.detail("ckpt: {d} checkpoints differ from the recorded mainnet bytes\n", .{bad_recorded});
    _ = try common.compareOut(ctx, a, "ckpt", mine);
}
