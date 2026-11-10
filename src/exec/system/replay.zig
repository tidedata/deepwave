//! exec-replay for system transactions: runs `system.execute` against the checkpoint's input
//! objects, the corpus packages and the children part, and compares effects, events and every
//! output object byte for byte with the certified ones.
const std = @import("std");
const harness = @import("harness");
const types = @import("types");
const protocol = @import("protocol");
/// The corpus these suites replay ($ZUI_CORPUS) is mainnet history.
const corpus_chain: protocol.Chain = .mainnet;
const sys = @import("root.zig");
const objects = @import("../objects.zig");
const packages = @import("../packages.zig");
const replay = @import("../replay.zig");

const Allocator = std.mem.Allocator;

pub const children_path = "vectors/exec-replay/children-system.bin.zst";

/// `read_child_object` answers from `zui-truth-exec-system children` (CONTRACTS 6.4.2):
/// (parent, child, bound) -> object bytes or none. Also carries each epoch's reference gas
/// price and start timestamp (epochs.jsonl) for the TxContext of system Move calls.
pub const Children = struct {
    map: std.AutoHashMapUnmanaged(Key, ?[]const u8) = .empty,
    epochs: []const EpochMeta = &.{},

    pub const Key = struct { parent: [32]u8, child: [32]u8, bound: u64 };

    pub const EpochMeta = struct { epoch: u64, rgp: u64 = 0, start_ms: u64 = 0 };

    pub fn load(ctx: *harness.Ctx, arena: Allocator) !Children {
        var c: Children = .{};
        if (ctx.corpus.readFileAlloc(ctx.io, "epochs.jsonl", arena, .limited(64 << 20))) |text| {
            var list: std.ArrayList(EpochMeta) = .empty;
            var it = harness.lines(text);
            while (it.next()) |line| {
                const e = try std.json.parseFromSliceLeaky(EpochMeta, arena, line, .{ .ignore_unknown_fields = true });
                if (e.epoch != list.items.len) return error.EpochsNotContiguous;
                try list.append(arena, e);
            }
            c.epochs = list.items;
        } else |_| {}
        const z = ctx.corpus.readFileAlloc(ctx.io, children_path, arena, .limited(1 << 32)) catch return c;
        const raw = try harness.decompressZstd(arena, z, 1 << 34);
        var at: usize = 0;
        while (at < raw.len) {
            if (raw.len - at < 73) return error.Truncated;
            var k: Key = undefined;
            k.parent = raw[at..][0..32].*;
            k.child = raw[at + 32 ..][0..32].*;
            k.bound = std.mem.readInt(u64, raw[at + 64 ..][0..8], .little);
            const present = raw[at + 72];
            at += 73;
            if (present == 0) {
                try c.map.put(arena, k, null);
                continue;
            }
            if (raw.len - at < 4) return error.Truncated;
            const n = std.mem.readInt(u32, raw[at..][0..4], .little);
            at += 4;
            if (raw.len - at < n) return error.Truncated;
            try c.map.put(arena, k, raw[at..][0..n]);
            at += n;
        }
        return c;
    }
};

const Src = struct {
    ins: []const []const u8,
    views: []const objects.ObjectView,
    pkgs: *const packages.Store,
    children: *const Children,
    epoch: u64,

    /// The checkpoint's input objects, then (a shared input the transaction read without a
    /// change, which the checkpoint does not carry) the children part's exact-version entries.
    fn input(p: *const anyopaque, id: *const [32]u8, version: u64) ?[]const u8 {
        const s: *const Src = @ptrCast(@alignCast(p));
        for (s.views) |*v| if (std.mem.eql(u8, &v.id, id) and v.version == version) return v.raw;
        const got = s.children.map.get(.{ .parent = @splat(0), .child = id.*, .bound = version }) orelse return null;
        return got;
    }

    /// The transaction's input objects carry every child it changed, at the version it read;
    /// a child read without a change comes from the children part.
    fn child(p: *const anyopaque, parent: *const [32]u8, id: *const [32]u8, bound: u64) error{NotAvailable}!?[]const u8 {
        const s: *const Src = @ptrCast(@alignCast(p));
        for (s.views) |*v| if (std.mem.eql(u8, &v.id, id) and v.version <= bound) return v.raw;
        return s.children.map.get(.{ .parent = parent.*, .child = id.*, .bound = bound }) orelse error.NotAvailable;
    }

    fn package(p: *const anyopaque, id: *const [32]u8) ?[]const u8 {
        const s: *const Src = @ptrCast(@alignCast(p));
        return s.pkgs.get(id, s.epoch);
    }
};

const Prepared = struct {
    env: sys.Env,
    versions: []const sys.InputVersion,
    src: *const Src,

    fn source(p: *const Prepared) sys.Source {
        return .{ .ctx = p.src, .input = Src.input, .child = Src.child, .package = Src.package };
    }
};

/// The transaction's inputs as a node would hand them over: the checkpoint's input objects,
/// the shared versions consensus assigned (the read-only ones from the certified effects), the
/// epoch's packages and the children part.
fn prepare(
    arena: Allocator,
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    blob: []const u8,
    idx: *const types.CheckpointIndex,
    tx: *const types.index.Tx,
    pkgs: *const packages.Store,
    children: *const Children,
) error{ OutOfMemory, BadInput }!Prepared {
    const ins = try arena.alloc([]const u8, tx.in_count);
    const views = try arena.alloc(objects.ObjectView, tx.in_count);
    var versions: std.ArrayList(sys.InputVersion) = .empty;
    for (idx.objs[tx.in_first..][0..tx.in_count], ins, views) |r, *o, *v| {
        o.* = r.slice(blob);
        v.* = objects.ObjectView.parse(o.*) catch return error.BadInput;
        try versions.append(arena, .{ .id = v.id, .version = v.version });
    }
    // Consensus assigns shared input versions; a shared input read without a change is not
    // among the checkpoint's objects, and its certified effects carry the version
    // (ReadOnlyRoot), as `ExecInput.assigned_versions` does in a node.
    const fx = @import("bcs").decode(types.TransactionEffects, arena, tx.effects.slice(blob)) catch return error.BadInput;
    if (fx == .V2) for (fx.V2.unchanged_consensus_objects) |u| switch (u[1]) {
        .ReadOnlyRoot => |r| try versions.append(arena, .{ .id = u[0].@"0".@"0", .version = r[0].@"0" }),
        else => {},
    };
    const src = try arena.create(Src);
    src.* = .{ .ins = ins, .views = views, .pkgs = pkgs, .children = children, .epoch = epoch };
    var env: sys.Env = .{ .cfg = cfg, .epoch = epoch };
    if (epoch < children.epochs.len) {
        env.rgp = children.epochs[epoch].rgp;
        env.epoch_start_ms = children.epochs[epoch].start_ms;
    }
    return .{ .env = env, .versions = versions.items, .src = src };
}

pub fn check(
    ctx: *harness.Ctx,
    arena: Allocator,
    id: []const u8,
    cfg: ?*const protocol.ProtocolConfig,
    epoch: u64,
    blob: []const u8,
    idx: *const types.CheckpointIndex,
    tx: *const types.index.Tx,
    data: *const types.TransactionDataV1,
    pkgs: *const packages.Store,
    children: *const Children,
    skips: *replay.SkipTally,
) replay.Outcome {
    const c = cfg orelse {
        ctx.skip(id, "no protocol config for the epoch");
        return .skip;
    };
    const p = prepare(arena, c, epoch, blob, idx, tx, pkgs, children) catch |e| switch (e) {
        error.OutOfMemory => return .skip,
        error.BadInput => {
            ctx.fail(id, "input object or certified effects do not parse", .{});
            return .fail;
        },
    };
    const res = sys.execute(arena, &p.env, tx.data.slice(blob), data, p.versions, p.source()) catch |e| {
        ctx.fail(id, "system: {s}", .{@errorName(e)});
        return .fail;
    };
    const out = switch (res) {
        .unsupported => |why| {
            skips.add(ctx.io, why);
            ctx.skip(id, why);
            return .skip;
        },
        .done => |o| o,
    };
    const want_fx = tx.effects.slice(blob);
    if (!std.mem.eql(u8, want_fx, out.effects)) {
        ctx.fail(id, "effects differ (zui {d} bytes, certified {d} bytes): {s}", .{ out.effects.len, want_fx.len, replay.effectsDiff(arena, out.effects, want_fx) });
        return .fail;
    }
    const want_ev: ?[]const u8 = if (tx.events) |r| r.slice(blob) else null;
    if ((want_ev == null) != (out.events == null)) {
        ctx.fail(id, "events: certified {s}, zui {s}", .{ if (want_ev == null) "none" else "some", if (out.events == null) "none" else "some" });
        return .fail;
    }
    if (want_ev) |w| if (!std.mem.eql(u8, w, out.events.?)) {
        ctx.fail(id, "events bytes differ", .{});
        return .fail;
    };
    if (out.written.len != tx.out_count) {
        ctx.fail(id, "{d} output objects, certified {d}", .{ out.written.len, tx.out_count });
        return .fail;
    }
    for (idx.objs[tx.out_first..][0..tx.out_count]) |r| {
        const want = r.slice(blob);
        const k = objects.keyOf(want) catch {
            ctx.fail(id, "certified output object does not parse", .{});
            return .fail;
        };
        const got = for (out.written) |w| {
            if (std.mem.eql(u8, &w.id, &k.id)) break w.bytes;
        } else {
            ctx.fail(id, "output object missing", .{});
            return .fail;
        };
        if (!std.mem.eql(u8, got, want)) {
            ctx.fail(id, "output object bytes differ", .{});
            return .fail;
        }
    }
    ctx.pass(id);
    return .pass;
}

const BenchTx = struct { p: Prepared, raw: []const u8, data: *const types.TransactionDataV1 };

/// Same selection as `zui-truth-exec-system bench system`: the transactions `system.handles`
/// (settlement, randomness, authenticator) of the bench checkpoints at protocol 119 and later.
/// Timed: `system.execute` to effects, events and written object bytes, inputs prepared
/// outside the timed region (Rust: `execute_transaction_to_effects` likewise).
pub fn bench(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const epochs = try harness.corpus_suite.loadEpochs(ctx, arena);
    const last = try arena.alloc(?u64, epochs.len);
    for (epochs, last) |e, *l| l.* = e.last;
    const pkgs = try arena.create(packages.Store);
    pkgs.* = try packages.load(ctx, arena, last);
    const children = try arena.create(Children);
    children.* = try Children.load(ctx, arena);
    var list: std.ArrayList(BenchTx) = .empty;
    for (ctx.benchInputs()) |name| {
        const blob = try ctx.corpus.readFileAlloc(ctx.io, name, arena, .limited(1 << 30));
        const cp = try @import("bcs").decode(types.CheckpointData, arena, blob[1..]);
        const epoch = cp.checkpoint_summary.data.epoch;
        if (epochs[epoch].pv < 119) continue;
        const cfg = try protocol.get(epochs[epoch].pv, corpus_chain);
        var full = try types.CheckpointIndex.init(std.heap.page_allocator);
        defer full.deinit(std.heap.page_allocator);
        try types.indexCheckpointData(blob, &full);
        const idx = try arena.create(types.CheckpointIndex);
        idx.* = full;
        idx.txs = try arena.dupe(types.index.Tx, full.txs[0..full.tx_count]);
        idx.objs = try arena.dupe(types.index.Range, full.objs[0..full.obj_total]);
        for (cp.transactions, 0..) |*t, i| {
            const data = &t.transaction.data.@"0".element().intent_message.value.V1;
            if (!sys.handles(&data.kind)) continue;
            const tx = &idx.txs[i];
            var p = try prepare(arena, cfg, epoch, blob, idx, tx, pkgs, children);
            // Rust's bench hands the digest over too (`execute_transaction_to_effects`).
            p.env.tx_digest = types.digest.transactionDataDigest(tx.data.slice(blob));
            try list.append(arena, .{ .p = p, .raw = tx.data.slice(blob), .data = data });
        }
    }
    const S = struct {
        fn pass(txs: []const BenchTx) !void {
            var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer scratch.deinit();
            for (txs) |*b| {
                _ = scratch.reset(.retain_capacity);
                const r = try sys.execute(scratch.allocator(), &b.p.env, b.raw, b.data, b.p.versions, b.p.source());
                if (r != .done) return error.BenchTransactionUnsupported;
                std.mem.doNotOptimizeAway(r);
            }
        }
    };
    try ctx.benchPasses("system", "tx", list.items.len, @as([]const BenchTx, list.items), S.pass);
}
