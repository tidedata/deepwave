//! `exec-move-synth`: synthetic execution vectors made by Mysten's executor
//! (`zui-truth-exec synth`, `vectors/exec-move-synth/vectors.jsonl.zst`) for paths the corpus
//! does not reach: the coin deny list v2 (an address denied for a regulated coin through a
//! `Coin<T>` write or a `Balance<T>` accumulator event, the global pause, epoch-gated settings),
//! references across commands, Publish, and Upgrade of packages the tool published first (those
//! package objects travel in `objects` and are laid over the corpus packages for that vector).
//!
//! Each vector carries the transaction, its input objects, the latest objects the executor read
//! outside the inputs, and Rust's effects, events and written objects. deepwave runs it through the
//! Move-call executor (item `<name>/move`) and, for coin-only transactions, also through the coin
//! executor (`<name>/coin`); effects and events must be byte-exact and the written objects the
//! same set of byte strings. The Move-call executor reads shared input versions from the given
//! effects (the scheduler input, as in exec-replay).
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
/// The corpus these suites replay ($ZUI_CORPUS) is mainnet history.
const corpus_chain: protocol.Chain = .mainnet;
const objects = @import("../objects.zig");
const packages = @import("../packages.zig");
const coin_ptb = @import("../coin_ptb.zig");
const classify = @import("../classify.zig");
const replay = @import("../replay.zig");
const ptb = @import("root.zig");
const versions = @import("../versions/root.zig");

pub const path = "vectors/exec-move-synth/vectors.jsonl.zst";
/// Vectors made by a newer release's executor (protocol 142: `clock/...`, the implicit Clock),
/// carrying that release's system packages in their objects. Optional: older truth has none.
pub const path_v142 = "vectors/exec-move-synth/vectors-v142.jsonl.zst";

const Line = struct {
    name: []const u8,
    pv: u64,
    epoch: u64,
    rgp: u64,
    start_ms: u64,
    tx: []const u8,
    objects: []const []const u8,
    latest: []const []const u8,
    effects: []const u8,
    events: ?[]const u8,
    written: []const []const u8,
    /// Runtime-loaded objects the transaction did not write (`unchanged_loaded_runtime_objects`).
    loaded: ?[]const struct { id: []const u8, version: u64 } = null,
    /// The transaction digest Rust ran with, when it is not the data's digest (vectors whose
    /// commands name a package id the transaction itself creates).
    digest: ?[]const u8 = null,
};

const Store = struct {
    objs: std.AutoHashMapUnmanaged(objects.Key, []const u8) = .empty,
    latest: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty,

    fn get(p: *const anyopaque, id: *const [32]u8, version: u64) ?[]const u8 {
        const s: *const Store = @ptrCast(@alignCast(p));
        return s.objs.get(.{ .id = id.*, .version = version });
    }
    fn getLatest(p: *const anyopaque, id: *const [32]u8) ?[]const u8 {
        const s: *const Store = @ptrCast(@alignCast(p));
        return s.latest.get(id.*);
    }
    fn lookup(s: *const Store) coin_ptb.ObjectLookup {
        return .{ .ctx = s, .get = get, .latest = getLatest };
    }
};

fn unhex(arena: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try arena.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

pub fn run(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const epochs = try harness.corpus_suite.loadEpochs(ctx, arena);
    const last = try arena.alloc(?u64, epochs.len);
    for (epochs, last) |e, *l| l.* = e.last;
    const pkgs = try packages.load(ctx, arena, last);
    inline for (.{ path, path_v142 }) |file| {
        const optional = comptime std.mem.eql(u8, file, path_v142);
        if (ctx.corpus.readFileAlloc(ctx.io, file, arena, .limited(1 << 30))) |z| {
            const text = try harness.decompressZstd(arena, z, 1 << 31);
            try runLines(ctx, arena, text, &pkgs);
        } else |e| {
            if (!(optional and e == error.FileNotFound)) ctx.fail("vectors", "read {s}: {s}", .{ file, @errorName(e) });
        }
    }
}

fn runLines(ctx: *harness.Ctx, arena: std.mem.Allocator, text: []const u8, pkgs: *const packages.Store) !void {
    var it = harness.lines(text);
    while (it.next()) |line| {
        ctx.nextItem();
        const a = ctx.scratch();
        const v = std.json.parseFromSliceLeaky(Line, a, line, .{}) catch |e| {
            ctx.fail("vectors", "line: {s}", .{@errorName(e)});
            continue;
        };
        inline for (.{ "move", "coin" }) |path_name| {
            const item = try std.fmt.allocPrint(a, "{s}/{s}", .{ v.name, path_name });
            if (ctx.selected(item)) checkOne(ctx, a, arena, item, &v, pkgs, comptime std.mem.eql(u8, path_name, "coin")) catch |e| ctx.fail(item, "{s}", .{@errorName(e)});
        }
    }
}

/// `run_arena` outlives every vector: a vector with packages gets its own package store there,
/// at an address no other vector's store reuses (the per-thread package cache keys on it).
fn checkOne(ctx: *harness.Ctx, a: std.mem.Allocator, run_arena: std.mem.Allocator, item: []const u8, v: *const Line, corpus_pkgs: *const packages.Store, coin: bool) !void {
    const cfg = try protocol.get(v.pv, corpus_chain);
    const tx_raw = try unhex(a, v.tx);
    const td = try bcs.decode(types.TransactionData, a, tx_raw);
    const data = &td.V1;
    if (coin and classify.classify(&data.kind) != .ptb_coin_transfer) return; // no coin item
    var store: Store = .{};
    var own: ?*packages.Store = null;
    for (v.objects) |h| {
        const raw = try unhex(a, h);
        const ov = try objects.ObjectView.parse(raw);
        if (!ov.is_package) {
            try store.objs.put(a, ov.key(), raw);
            continue;
        }
        // a package the vector published first (upgrade vectors): over the corpus packages
        const o = own orelse blk: {
            const n = try run_arena.create(packages.Store);
            n.* = .{ .user = try corpus_pkgs.user.clone(run_arena), .system = try corpus_pkgs.system.clone(run_arena), .loaded = corpus_pkgs.loaded };
            own = n;
            break :blk n;
        };
        if (packages.isSystemPackage(&ov.id)) {
            // a newer release's system package (its framework): visible from this epoch, after the corpus writes
            const gop = try o.system.getOrPut(run_arena, ov.id);
            var list: std.ArrayList(packages.SystemWrite) = if (gop.found_existing) try gop.value_ptr.clone(run_arena) else .empty;
            try list.append(run_arena, .{ .epoch = v.epoch, .raw = try run_arena.dupe(u8, raw) });
            gop.value_ptr.* = list;
            continue;
        }
        try o.user.put(run_arena, ov.id, try run_arena.dupe(u8, raw));
    }
    const pkgs: *const packages.Store = own orelse corpus_pkgs;
    for (v.latest) |h| {
        const raw = try unhex(a, h);
        try store.latest.put(a, (try objects.keyOf(raw)).id, raw);
    }
    const want_fx = try unhex(a, v.effects);
    const want_ev: ?[]const u8 = if (v.events) |e| try unhex(a, e) else null;
    var got_ev: ?[]const u8 = null;
    // DevInspect (`track_results`) rerun of the Move path: effects and events must not change,
    // and a successful transaction tracks one result per command
    var tracked: ?ptb.Outcome = null;
    const out: coin_ptb.Output = if (coin) blk: {
        const r = try coin_ptb.execute(a, cfg, v.epoch, 0, tx_raw, data, store.lookup());
        switch (r) {
            .unsupported => |why| return ctx.skip(item, why),
            .done => |o| break :blk o,
        }
    } else blk: {
        const fx = try bcs.decode(types.TransactionEffects, a, want_fx);
        var digest: ?[32]u8 = null;
        if (v.digest) |h| {
            var d: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&d, h);
            digest = d;
        }
        // the vector's packages are the whole store Rust ran with
        const env: ptb.Env = .{ .gpa = std.heap.page_allocator, .cfg = cfg, .pv = v.pv, .epoch = v.epoch, .epoch_start_ms = v.start_ms, .rgp = v.rgp, .pkgs = pkgs, .authoritative_packages = true, .tx_digest = digest };
        var loaded: std.ArrayList(ptb.Ref) = .empty;
        if (v.loaded) |ls| for (ls) |l| {
            var id: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&id, l.id);
            try loaded.append(a, .{ .id = id, .version = l.version });
        };
        const r = try ptb.execute(a, env, tx_raw, data, .{ .objs = store.lookup(), .effects = &fx.V2, .unchanged_loaded = loaded.items });
        switch (r) {
            .unsupported => |why| return ctx.skip(item, why),
            .done => |o| {
                got_ev = o.events;
                // the dynamic cuts do not model tracking (`.unsupported` by design): static only
                if (versions.executorOf(cfg) != .dynamic)
                    tracked = try ptb.execute(a, env, tx_raw, data, .{ .objs = store.lookup(), .effects = &fx.V2, .unchanged_loaded = loaded.items, .track_results = true });
                break :blk .{ .effects = o.effects, .written = o.written };
            },
        }
    };
    var c = ctx.check(item);
    if (!std.mem.eql(u8, want_fx, out.effects)) c.failf("effects differ: {s}", .{replay.effectsDiff(a, out.effects, want_fx)});
    if (!coin) {
        if (want_ev) |w| {
            if (got_ev) |g| c.bytes("events", w, g) else c.failf("Rust has events, zui none", .{});
        } else if (got_ev != null) c.failf("zui has events, Rust none", .{});
    }
    if (tracked) |t| switch (t) {
        .unsupported => |why| c.failf("DevInspect rerun unsupported: {s}", .{why}),
        .done => |o| {
            if (!std.mem.eql(u8, o.effects, out.effects)) c.failf("DevInspect rerun effects differ: {s}", .{replay.effectsDiff(a, o.effects, out.effects)});
            const same_ev = if (o.events) |x| (if (got_ev) |y| std.mem.eql(u8, x, y) else false) else got_ev == null;
            if (!same_ev) c.failf("DevInspect rerun events differ", .{});
            const fx = try bcs.decode(types.TransactionEffects, a, o.effects);
            const ok = switch (fx) {
                .V2 => |x| x.status == .Success,
                .V1 => |x| x.status == .Success,
            };
            if (ok) {
                const n_cmds = switch (data.kind) {
                    .ProgrammableTransaction => |pt| pt.commands.len,
                    else => 0,
                };
                if (o.command_results) |cr| {
                    // typed commands: the signed ones plus injected withdrawal conversions
                    if (cr.len < n_cmds) c.failf("DevInspect results: {d} for {d} commands", .{ cr.len, n_cmds });
                } else c.failf("DevInspect results missing on success", .{});
            } else if (o.command_results != null) c.failf("DevInspect results on a failed transaction", .{});
        },
    };
    if (out.written.len != v.written.len) c.failf("written count: zui {d}, Rust {d}", .{ out.written.len, v.written.len });
    for (v.written) |h| {
        const want = try unhex(a, h);
        const k = try objects.keyOf(want);
        const got = for (out.written) |w| {
            if (std.mem.eql(u8, &w.id, &k.id)) break w.bytes;
        } else {
            c.failf("written object missing", .{});
            continue;
        };
        c.bytes("written object", want, got);
    }
    _ = c.finish();
}
