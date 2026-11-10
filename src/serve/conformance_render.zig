//! `render-json` suite: object `json`/`display`/OBJ_MASK and checkpoint event `json` against
//! sui-node 1.83.1 (tools/truth/render/capture.py, from a production sui-node).
//!
//! `$ZUI_CORPUS/vectors/render-json/`:
//! - `pinned.kv`: object id -> BCS(Object) at the version the truth was read at (render input);
//! - `live.kv`: object id -> live BCS(Object) (packages, Display objects, dynamic fields the
//!   renderer loads; an empty value records "not found");
//! - `objects.kv`: id ++ tag -> sui-node's `Object` message for BatchGetObjects with that version
//!   under mask tag 0 `["json"]`, 1 `["display"]`, 2 an explorer's OBJ_MASK;
//! - `cp.kv`: be64 seq ++ 0 -> Checkpoint with `transactions.events.bcs` (input), ++ 1 -> the
//!   Checkpoint under an explorer stream mask's event fields (truth).
//! - `levents.kv`: `E` ++ base58 digest ++ `/` ++ event index ++ `/` ++ mask tag -> sui-node's
//!   ListEvents `Event` message under `lev_masks[tag]` (0: every field, 1: an indexer client's
//!   mask); `T` ++ base58 digest -> BCS(TransactionEvents) (input). `levents-live.kv` adds the
//!   packages those events need (`capture.py lsevents`, `capture.py fill levents-live.kv`).
//! Records are `u32le klen, key, u32le vlen, value`, later records win. Ids the renderer asked
//! for but the capture lacks are written to `sessions/render/missing.txt` (`capture.py fill`
//! fetches them); items that hit one are skipped.
const std = @import("std");
const Allocator = std.mem.Allocator;
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const proto = @import("proto.zig");
const mask = @import("mask.zig");
const movelayout = @import("movelayout.zig");
const render_object = @import("render_object.zig");
const render_tx = @import("render_tx.zig");
const render_json = @import("render_json.zig");
const typestr = @import("typestr.zig");
const lh_service = @import("lh_service.zig");
const b58 = @import("b58.zig");
const history = @import("history");

const dir = "vectors/render-json";

pub const obj_masks = [_][]const u8{
    "json",
    "display",
    "object_id,version,digest,owner,object_type,has_public_transfer,previous_transaction,storage_rebate,json,display",
};
const mask_names = [_][]const u8{ "json", "display", "obj" };
/// capture.py LEV_MASKS.
const lev_masks = [_][]const u8{
    "package_id,module,sender,event_type,contents,json,checkpoint,transaction_digest,transaction_index,event_index",
    "sender,event_type,json,contents,checkpoint,transaction_digest,event_index",
};
const lev_names = [_][]const u8{ "full", "pp" };
const ev_mask = "events.package_id,events.module,events.sender,events.event_type,events.json";

const KV = std.StringHashMapUnmanaged([]const u8);

fn loadKv(ctx: *harness.Ctx, gpa: Allocator, name: []const u8, out: *KV) !void {
    const path = try std.fmt.allocPrint(gpa, dir ++ "/{s}", .{name});
    const b = ctx.corpus.readFileAlloc(ctx.io, path, gpa, .limited(4 << 30)) catch |e| switch (e) {
        error.FileNotFound => return,
        else => return e,
    };
    var i: usize = 0;
    while (i + 4 <= b.len) {
        const kl = std.mem.readInt(u32, b[i..][0..4], .little);
        const k = b[i + 4 ..][0..kl];
        i += 4 + kl;
        const vl = std.mem.readInt(u32, b[i..][0..4], .little);
        const v = b[i + 4 ..][0..vl];
        i += 4 + vl;
        try out.put(gpa, k, v);
    }
}

/// Objects by id from `live.kv`; ids it lacks are collected for `capture.py fill`.
pub const Source = struct {
    live: *const KV,
    missing: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
    gpa: Allocator,

    pub fn get(ctx: *const anyopaque, id: *const [32]u8) ?[]const u8 {
        const s: *Source = @ptrCast(@alignCast(@constCast(ctx)));
        if (s.live.get(id)) |v| return if (v.len == 0) null else v;
        s.missing.put(s.gpa, id.*, {}) catch {};
        return null;
    }
};

/// Counts misses while one item renders (the source is shared; items run on one thread here).
const ItemSource = struct {
    src: *Source,
    misses: usize = 0,
    fn get(ctx: *const anyopaque, id: *const [32]u8) ?[]const u8 {
        const s: *ItemSource = @ptrCast(@alignCast(@constCast(ctx)));
        const v = Source.get(s.src, id);
        if (v == null and !s.src.live.contains(id)) s.misses += 1;
        return v;
    }
    fn packages(s: *ItemSource) movelayout.PackageSource {
        return .{ .ctx = s, .get = get };
    }
};

const objdisplay = @import("objdisplay.zig");

pub fn run(ctx: *harness.Ctx) !void {
    // everything the run keeps lives in one arena (the inputs are ~100 MB)
    var run_arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer run_arena.deinit();
    const gpa = run_arena.allocator();
    var live: KV = .empty;
    var pinned: KV = .empty;
    var objs: KV = .empty;
    var cps: KV = .empty;
    try loadKv(ctx, gpa, "live.kv", &live);
    try loadKv(ctx, gpa, "pinned.kv", &pinned);
    try loadKv(ctx, gpa, "objects.kv", &objs);
    try loadKv(ctx, gpa, "cp.kv", &cps);
    var lev: KV = .empty;
    try loadKv(ctx, gpa, "levents.kv", &lev);
    try loadKv(ctx, gpa, "levents-live.kv", &live);
    var src: Source = .{ .live = &live, .gpa = gpa };

    // objects, by id then mask
    var keys: std.ArrayList([]const u8) = .empty;
    var it = objs.keyIterator();
    while (it.next()) |k| try keys.append(gpa, k.*);
    std.mem.sort([]const u8, keys.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    for (keys.items) |k| {
        if (ctx.done()) break;
        const id = k[0..32];
        const tag = k[32];
        var ib: [128]u8 = undefined;
        const item = try std.fmt.bufPrint(&ib, "obj/{x}/{s}", .{ id, mask_names[tag] });
        if (!ctx.selected(item)) continue;
        ctx.nextItem();
        const arena = ctx.scratch();
        const raw = pinned.get(id) orelse {
            ctx.skip(item, "no pinned BCS");
            continue;
        };
        var isrc: ItemSource = .{ .src = &src };
        var res = movelayout.Resolver.init(arena, isrc.packages());
        var rctx: render_object.Ctx = .{ .resolver = &res };
        rctx.display = try objdisplay.Hook.create(arena, isrc.packages());
        var tree = try mask.Tree.parse(arena, obj_masks[tag]);
        var cap: usize = raw.len * 4 + 4096;
        const got = while (true) : (cap *= 2) {
            const buf = try arena.alloc(u8, cap);
            var w = proto.Writer.init(buf);
            render_object.writeObjectCtx(arena, &w, tree.mask(), raw, &rctx) catch |e| switch (e) {
                error.NoSpace => continue,
                else => return e,
            };
            break w.bytesWritten();
        };
        if (isrc.misses > 0) {
            ctx.skip(item, "an object the renderer loads is not captured yet (capture.py fill)");
            continue;
        }
        _ = ctx.expectBytes(item, "Object message", objs.get(k).?, got);
    }

    // checkpoints: event json with one budget per checkpoint
    var cpkeys: std.ArrayList(u64) = .empty;
    var cit = cps.keyIterator();
    while (cit.next()) |k| if (k.len == 9 and k.*[8] == 0) try cpkeys.append(gpa, std.mem.readInt(u64, k.*[0..8], .big));
    std.mem.sort(u64, cpkeys.items, {}, std.sort.asc(u64));
    for (cpkeys.items) |seq| {
        if (ctx.done()) break;
        var ib: [64]u8 = undefined;
        const item = try std.fmt.bufPrint(&ib, "cp/{d}", .{seq});
        if (!ctx.selected(item)) continue;
        ctx.nextItem();
        const arena = ctx.scratch();
        var kb: [9]u8 = undefined;
        std.mem.writeInt(u64, kb[0..8], seq, .big);
        kb[8] = 0;
        const input = cps.get(&kb).?;
        kb[8] = 1;
        const truth = cps.get(&kb) orelse {
            ctx.skip(item, "no truth record");
            continue;
        };
        const in_txs = try fieldsOf(arena, input, 6);
        const want_txs = try fieldsOf(arena, truth, 6);
        var c = ctx.check(item);
        if (in_txs.len != want_txs.len) {
            c.failf("{d} transactions in the input, {d} in the truth", .{ in_txs.len, want_txs.len });
            _ = c.finish();
            continue;
        }
        var isrc: ItemSource = .{ .src = &src };
        var res = movelayout.Resolver.init(arena, isrc.packages());
        var budget: usize = render_json.default_response_budget;
        const rctx: render_object.Ctx = .{ .resolver = &res, .json_budget = &budget };
        var tree = try mask.Tree.parse(arena, ev_mask);
        for (in_txs, want_txs, 0..) |tin, twant, ti| {
            const ev_in = try fieldOf(tin, 5);
            const ev_want = try fieldOf(twant, 5);
            if (ev_in == null) {
                if (ev_want != null) c.failf("tx {d}: truth has events, input has none", .{ti});
                continue;
            }
            const bcs_msg = (try fieldOf(ev_in.?, 1)) orelse return error.BadVector;
            const ev_raw = (try fieldOf(bcs_msg, 2)) orelse &.{};
            const ev = try bcs.decode(types.TransactionEvents, arena, ev_raw);
            var cap: usize = ev_raw.len * 8 + 4096;
            const got = while (true) : (cap *= 2) {
                const save = budget;
                const buf = try arena.alloc(u8, cap);
                var w = proto.Writer.init(buf);
                render_tx.writeEventsCtx(arena, &w, 5, tree.mask(), ev_raw, ev, null, &rctx) catch |e| switch (e) {
                    error.NoSpace => {
                        budget = save;
                        continue;
                    },
                    else => return e,
                };
                break w.bytesWritten();
            };
            // the truth carries the TransactionEvents message body; ours is wrapped as field 5
            var r = proto.Reader.init(got);
            const f = (try r.next()).?;
            var wb: [32]u8 = undefined;
            const what = try std.fmt.bufPrint(&wb, "tx {d} events", .{ti});
            c.bytes(what, ev_want orelse &.{}, f.data);
        }
        if (isrc.misses > 0) {
            ctx.skip(item, "an object the renderer loads is not captured yet (capture.py fill)");
            continue;
        }
        _ = c.finish();
    }

    // ListEvents items (lh_service.writeListEvent): render.rs render_event_to_proto with an empty
    // ObjectSet and a fresh json budget per event, then the ledger position fields
    var evkeys: std.ArrayList([]const u8) = .empty;
    var eit = lev.keyIterator();
    while (eit.next()) |k| if (k.len > 4 and k.*[0] == 'E') try evkeys.append(gpa, k.*);
    std.mem.sort([]const u8, evkeys.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    for (evkeys.items) |k| {
        if (ctx.done()) break;
        const tag = k[k.len - 1];
        if (tag >= lev_masks.len) return error.BadVector;
        var parts = std.mem.splitScalar(u8, k[1 .. k.len - 2], '/');
        const dg_text = parts.next() orelse return error.BadVector;
        const idx = std.fmt.parseInt(u32, parts.next() orelse return error.BadVector, 10) catch return error.BadVector;
        var ib: [160]u8 = undefined;
        const item = try std.fmt.bufPrint(&ib, "lev/{s}/{d}/{s}", .{ dg_text, idx, lev_names[tag] });
        if (!ctx.selected(item)) continue;
        ctx.nextItem();
        const arena = ctx.scratch();
        // positions from the every-field record of the same event
        var fk: std.ArrayList(u8) = .empty;
        try fk.appendSlice(arena, k[0 .. k.len - 1]);
        try fk.append(arena, 0);
        const full = lev.get(fk.items) orelse {
            ctx.skip(item, "no every-field record (positions)");
            continue;
        };
        const tk = try std.mem.concat(arena, u8, &.{ "T", dg_text });
        const ev_raw = lev.get(tk) orelse {
            ctx.skip(item, "no transaction events record");
            continue;
        };
        const ev = try bcs.decode(types.TransactionEvents, arena, ev_raw);
        var c = ctx.check(item);
        if (idx >= ev.data.len) {
            c.failf("event {d} of a transaction with {d}", .{ idx, ev.data.len });
            _ = c.finish();
            continue;
        }
        var fr = proto.Reader.init(full);
        var row: history.TxRow = .{ .tx_seq = 0, .digest = b58.decode32(dg_text) orelse return error.BadVector, .checkpoint = 0, .tx_offset = 0, .event_count = @intCast(ev.data.len) };
        while (try fr.next()) |f| switch (f.number) {
            7 => row.checkpoint = f.varint,
            9 => row.tx_offset = @intCast(f.varint),
            else => {},
        };
        var isrc: ItemSource = .{ .src = &src };
        var res = movelayout.Resolver.init(arena, isrc.packages());
        const rctx: render_object.Ctx = .{ .resolver = &res };
        var tree = try mask.Tree.parse(arena, lev_masks[tag]);
        var cap: usize = ev.data[idx].contents.len * 8 + 4096;
        const got = while (true) : (cap *= 2) {
            const buf = try arena.alloc(u8, cap);
            var w = proto.Writer.init(buf);
            lh_service.writeListEvent(arena, &w, tree.mask(), ev.data[idx], row, idx, &rctx) catch |e| switch (e) {
                error.NoSpace => continue,
                else => return e,
            };
            break w.bytesWritten();
        };
        if (isrc.misses > 0) {
            ctx.skip(item, "an object the renderer loads is not captured yet (capture.py fill levents-live.kv)");
            continue;
        }
        // ours is the response's field 1; the truth is the Event message body
        var r = proto.Reader.init(got);
        c.bytes("Event message", lev.get(k).?, (try r.next()).?.data);
        _ = c.finish();
    }

    // report ids to fetch
    if (src.missing.count() > 0) {
        var out: std.ArrayList(u8) = .empty;
        var mit = src.missing.keyIterator();
        while (mit.next()) |id| try out.print(gpa, "0x{x}\n", .{id});
        std.Io.Dir.cwd().createDirPath(ctx.io, try std.fmt.allocPrint(gpa, "{s}/sessions/render", .{ctx.corpus_path})) catch {};
        const p = try std.fmt.allocPrint(gpa, "{s}/sessions/render/missing.txt", .{ctx.corpus_path});
        std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = p, .data = out.items }) catch {};
        try ctx.stderr.print("render-json: {d} objects missing from the capture, listed in {s}\n", .{ src.missing.count(), p });
    }
}

fn fieldsOf(arena: Allocator, msg: []const u8, num: u32) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var r = proto.Reader.init(msg);
    while (try r.next()) |f| if (f.number == num) try out.append(arena, f.data);
    return out.items;
}

fn fieldOf(msg: []const u8, num: u32) !?[]const u8 {
    var r = proto.Reader.init(msg);
    var last: ?[]const u8 = null;
    while (try r.next()) |f| if (f.number == num) {
        last = f.data;
    };
    return last;
}
