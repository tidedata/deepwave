//! Suite `rpc-events`: SubscriptionService.SubscribeEvents and filtered LedgerService.ListCheckpoints
//! replayed against deepwave over a real h2c socket (the deepwave runtime, h2/server.zig; client in
//! loopback.zig) and compared with sui-node 1.83.1 captures.
//!
//! Vectors: `src/serve/vectors/rpc-surface/` (or $ZUI_RPC_SURFACE_VECTORS):
//!   localnet/chk/<seq>.chk               the capture localnet's checkpoints
//!   localnet/loaded.jsonl                each transaction's unchanged_loaded_runtime_objects (the .chk
//!                                        form drops them; `zui-dumper loaded`), served as the node
//!                                        serves its archive-sourced lists; optional
//!   subscribe-events/cases.jsonl, list-checkpoints/cases.jsonl
//! Each case runs on a node holding the localnet checkpoints up to the capture's tip (its response
//! header `x-sui-checkpoint-height`, else `context.tip`, else every checkpoint): a store and a
//! history index built from `chk/`, the service, its subscription hub and the router. A
//! subscription case then publishes the following checkpoints one at a time, as the node's
//! watcher does, until the stream has as many messages as the capture (or the checkpoints run
//! out), and the client closes. A case whose tip is below the node's builds a fresh node.
//!
//! Byte-equal (brief): http status, the response header set (without `date`, `server-timing` and
//! any names in `context.volatile_headers`), every message payload byte for byte, grpc-status,
//! grpc-message and grpc-status-details-bin. Headers and trailers are compared as one set with the
//! grpc-* trailer fields split out, so a trailers-only reply compares the same either way.
const std = @import("std");
const Allocator = std.mem.Allocator;
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const history = @import("history");
const checkpoint = @import("checkpoint");
const h2 = @import("h2/root.zig");
const service = @import("service.zig");
const subscribe = @import("subscribe.zig");
const objset = @import("objset.zig");
const loopback = @import("loopback.zig");

const default_root = "src/serve/vectors/rpc-surface";
const features = [_][]const u8{ "list-checkpoints", "subscribe-events" };
const max_blob = 1 << 30;

const Chk = struct { seq: u64, blob: []const u8 };

pub fn run(ctx: *harness.Ctx) !void {
    return runFeatures(ctx, "rpc-events", &features);
}

/// Replays the captures of `feats` (subdirectories of the rpc-surface vectors holding a
/// cases.jsonl) as suite `suite`; items are `<feature>/<case name>`. Suite rpc-proof
/// (conformance_proof.zig) runs `proof/` through it.
pub fn runFeatures(ctx: *harness.Ctx, suite: []const u8, feats: []const []const u8) !void {
    const gpa = ctx.gpa;
    var keep = std.heap.ArenaAllocator.init(gpa);
    defer keep.deinit();
    const ka = keep.allocator();
    const root: []const u8 = if (std.c.getenv("ZUI_RPC_SURFACE_VECTORS")) |p| std.mem.span(p) else default_root;
    const cwd = std.Io.Dir.cwd();

    const chks = loadChks(ka, ctx.io, cwd, root) catch |e| {
        ctx.skip(suite, "no localnet/chk/ vectors yet");
        ctx.detail("{s}: {s}/localnet/chk: {s}\n", .{ suite, root, @errorName(e) });
        return;
    };
    if (chks.len == 0) return ctx.skip(suite, "localnet/chk/ is empty");
    var loaded: LoadedMap = .{};
    loadLoaded(ka, ctx.io, cwd, root, chks, &loaded) catch |e| {
        ctx.fail(suite, "localnet/loaded.jsonl: {s}", .{@errorName(e)});
        loaded = .{};
    };

    var cases: std.ArrayList(Case) = .empty;
    for (feats) |feat| {
        const p = try std.fmt.allocPrint(ka, "{s}/{s}/cases.jsonl", .{ root, feat });
        const text = cwd.readFileAlloc(ctx.io, p, ka, .limited(max_blob)) catch |e| {
            ctx.detail("{s}: {s}: {s} (no cases for {s} yet)\n", .{ suite, p, @errorName(e), feat });
            continue;
        };
        var lines = std.mem.splitScalar(u8, text, '\n');
        var n: usize = 0;
        while (lines.next()) |line| {
            const l = std.mem.trim(u8, line, " \r\t");
            if (l.len == 0) continue;
            const v = std.json.parseFromSliceLeaky(std.json.Value, ka, l, .{}) catch {
                ctx.fail(feat, "line {d} of cases.jsonl is not JSON", .{n + 1});
                continue;
            };
            try cases.append(ka, try Case.of(ka, feat, v));
            n += 1;
        }
    }
    if (cases.items.len == 0) return ctx.skip(suite, "no cases yet");

    var world: ?*World = null;
    defer if (world) |w| w.deinit();
    for (cases.items) |*c| {
        if (ctx.done()) break;
        if (!ctx.selected(c.item)) continue;
        ctx.nextItem();
        const want_tip = c.tip orelse chks[chks.len - 1].seq;
        if (world) |w| if (w.tip == null or w.tip.? > want_tip or w.dirty) {
            w.deinit();
            world = null;
        };
        if (world == null) world = try World.init(ctx, chks, &loaded, suite);
        const w = world.?;
        w.ingestTo(want_tip) catch |e| {
            ctx.fail(c.item, "building the node to checkpoint {d}: {s}", .{ want_tip, @errorName(e) });
            w.dirty = true;
            continue;
        };
        if (w.tip == null or w.tip.? != want_tip) {
            if (want_tip <= chks[chks.len - 1].seq) {
                ctx.skip(c.item, "the capture's tip is not among localnet/chk/");
                continue;
            }
            c.status_only = true;
            w.dirty = true; // its node holds every checkpoint; the next case starts afresh
        }
        applyVariant(ka, ctx.io, root, w, c.variant);
        runCase(ctx, w, c) catch |e| {
            ctx.fail(c.item, "replay: {s}", .{@errorName(e)});
            w.dirty = true;
        };
    }
}

fn loadChks(a: Allocator, io: std.Io, cwd: std.Io.Dir, root: []const u8) ![]const Chk {
    const sub = try std.fmt.allocPrint(a, "{s}/localnet/chk", .{root});
    const names = try harness.listFilesIn(a, io, cwd, sub, ".chk");
    var out: std.ArrayList(Chk) = .empty;
    for (names) |nm| {
        const seq = harness.leadingNumber(nm) orelse continue;
        const blob = try cwd.readFileAlloc(io, try std.fmt.allocPrint(a, "{s}/{s}", .{ sub, nm }), a, .limited(max_blob));
        try out.append(a, .{ .seq = seq, .blob = blob });
    }
    std.mem.sort(Chk, out.items, {}, struct {
        fn lt(_: void, x: Chk, y: Chk) bool {
            return x.seq < y.seq;
        }
    }.lt);
    return out.items;
}

/// Transaction digest to its unchanged_loaded_runtime_objects (the node's per-transaction list,
/// archive-sourced: node.zig `loadedOf`). Built once before any node starts, read-only after.
const LoadedMap = struct {
    map: std.AutoHashMapUnmanaged([32]u8, []const objset.Ref) = .empty,

    fn get(ctx: *const anyopaque, _: *const store.Snapshot, dg: *const [32]u8, _: u64) []const objset.Ref {
        const m: *const LoadedMap = @ptrCast(@alignCast(ctx));
        return m.map.get(dg.*) orelse &.{};
    }
    fn source(m: *const LoadedMap) ?service.LoadedSource {
        if (m.map.count() == 0) return null;
        return .{ .ctx = m, .get = get };
    }
};

/// `localnet/loaded.jsonl` lines `{"checkpoint":S,"tx":I,"loaded":[["0x<id>",V],...]}`, keyed by
/// the digest of transaction I of checkpoint S in `chks`. A missing file leaves `out` empty.
fn loadLoaded(a: Allocator, io: std.Io, cwd: std.Io.Dir, root: []const u8, chks: []const Chk, out: *LoadedMap) !void {
    const p = try std.fmt.allocPrint(a, "{s}/localnet/loaded.jsonl", .{root});
    const text = cwd.readFileAlloc(io, p, a, .limited(max_blob)) catch |e| switch (e) {
        error.FileNotFound => return,
        else => return e,
    };
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const l = std.mem.trim(u8, line, " \r\t");
        if (l.len == 0) continue;
        const v = try std.json.parseFromSliceLeaky(std.json.Value, a, l, .{});
        if (v != .object) return error.BadLine;
        const seq = try jsonU64(v.object.get("checkpoint"));
        const ti = try jsonU64(v.object.get("tx"));
        const list = v.object.get("loaded") orelse return error.BadLine;
        if (list != .array) return error.BadLine;
        const refs = try a.alloc(objset.Ref, list.array.items.len);
        for (list.array.items, refs) |e, *r| {
            if (e != .array or e.array.items.len != 2 or e.array.items[0] != .string) return error.BadLine;
            r.* = .{ .id = try parseId(e.array.items[0].string), .version = try jsonU64(e.array.items[1]) };
        }
        const chk = findChk(chks, seq) orelse continue; // past the shipped chk range
        const cpd = try bcs.decode(types.CheckpointData, a, chk.blob[1..]);
        if (ti >= cpd.transactions.len) return error.BadLine;
        const dg = switch (cpd.transactions[@intCast(ti)].effects) {
            .V1 => |fx| fx.transaction_digest.@"0".@"0",
            .V2 => |fx| fx.transaction_digest.@"0".@"0",
        };
        try out.map.put(a, dg, refs);
    }
}

fn jsonU64(v: ?std.json.Value) !u64 {
    const x = v orelse return error.BadLine;
    if (x != .integer or x.integer < 0) return error.BadLine;
    return @intCast(x.integer);
}

/// `0x` + up to 64 hex digits (left-padded), as sui.rpc.v2 renders an object id.
fn parseId(text: []const u8) ![32]u8 {
    if (!std.mem.startsWith(u8, text, "0x") or text.len < 3 or text.len > 66) return error.BadLine;
    var hex: [64]u8 = @splat('0');
    @memcpy(hex[64 - (text.len - 2) ..], text[2..]);
    var id: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&id, &hex) catch return error.BadLine;
    return id;
}

fn findChk(chks: []const Chk, seq: u64) ?Chk {
    var lo: usize = 0;
    var hi: usize = chks.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (chks[mid].seq < seq) lo = mid + 1 else hi = mid;
    }
    return if (lo < chks.len and chks[lo].seq == seq) chks[lo] else null;
}

test "rpc-events parseId: full and short object ids" {
    const full = try parseId("0xea4eb77f2a5a8ba172de0c4d2c51be91686ec84fdccd9a9dadd3ba7674bac468");
    try std.testing.expectEqual(@as(u8, 0xea), full[0]);
    try std.testing.expectEqual(@as(u8, 0x68), full[31]);
    const short = try parseId("0x5");
    try std.testing.expectEqual(@as(u8, 0), short[0]);
    try std.testing.expectEqual(@as(u8, 5), short[31]);
    try std.testing.expectError(error.BadLine, parseId("ea4e"));
    try std.testing.expectError(error.BadLine, parseId("0xzz"));
}

// ---------------------------------------------------------------- cases

const Expected = struct {
    http_status: []const u8,
    headers: []const [2][]const u8,
    trailers_only: ?bool,
    messages: []const loopback.Message,
    trailers: []const [2][]const u8,
};

const Case = struct {
    item: []const u8,
    subscription: bool,
    path: []const u8,
    req_headers: []const [2][]const u8,
    req_messages: []const []const u8,
    tip: ?u64,
    /// Variant `noidx` (configs/noidx.yaml: rpc without enable-indexing): no ledger-history index.
    no_index: bool,
    variant: []const u8,
    /// The capture's tip lies past localnet/chk/ (the sub-limit streams ran past the shipped
    /// range): only the status is compared.
    status_only: bool = false,
    want: Expected,
    volatile_headers: []const []const u8,

    fn of(a: Allocator, feat: []const u8, v: std.json.Value) !Case {
        const o = v.object;
        const name = str(o.get("name")) orelse "unnamed";
        const resp = (o.get("resp") orelse return error.NoResp).object;
        var c: Case = .{
            .item = try std.fmt.allocPrint(a, "{s}/{s}", .{ feat, name }),
            .subscription = std.mem.eql(u8, feat, "subscribe-events"),
            .path = str(o.get("path")) orelse "",
            .req_headers = try pairs(a, o.get("req_headers")),
            .req_messages = try b64List(a, o.get("req_messages_b64")),
            .tip = null,
            .no_index = std.mem.eql(u8, str(o.get("variant")) orelse "", "noidx"),
            .variant = str(o.get("variant")) orelse "",
            .want = .{
                .http_status = try numText(a, resp.get("http_status")),
                .headers = try pairs(a, resp.get("headers")),
                .trailers_only = if (resp.get("trailers_only")) |t| (if (t == .bool) t.bool else null) else null,
                .messages = try messagesOf(a, resp),
                .trailers = try pairs(a, resp.get("trailers")),
            },
            .volatile_headers = &.{},
        };
        for (c.want.headers) |kv| if (std.mem.eql(u8, kv[0], "x-sui-checkpoint-height")) {
            c.tip = std.fmt.parseInt(u64, kv[1], 10) catch null;
        };
        if (o.get("context")) |cx| if (cx == .object) {
            // a subscription's start tick names the checkpoint before entry: the tip it opened at
            if (c.subscription) if (cx.object.get("stream_start_seq")) |t| if (t == .integer and t.integer > 0) {
                c.tip = @intCast(t.integer - 1);
            };
            if (c.tip == null) if (cx.object.get("tip")) |t| if (t == .integer) {
                c.tip = @intCast(t.integer);
            };
            if (cx.object.get("volatile_headers")) |vh| if (vh == .array) {
                var l: std.ArrayList([]const u8) = .empty;
                for (vh.array.items) |x| if (str(x)) |s| try l.append(a, s);
                c.volatile_headers = l.items;
            };
        };
        return c;
    }
};

fn str(v: ?std.json.Value) ?[]const u8 {
    const x = v orelse return null;
    return if (x == .string) x.string else null;
}

fn numText(a: Allocator, v: ?std.json.Value) ![]const u8 {
    const x = v orelse return "";
    return switch (x) {
        .integer => |i| try std.fmt.allocPrint(a, "{d}", .{i}),
        .string => |s| s,
        else => "",
    };
}

fn pairs(a: Allocator, v: ?std.json.Value) ![]const [2][]const u8 {
    const x = v orelse return &.{};
    if (x != .object) return &.{};
    var out: std.ArrayList([2][]const u8) = .empty;
    var it = x.object.iterator();
    while (it.next()) |e| {
        const val: []const u8 = switch (e.value_ptr.*) {
            .string => |s| s,
            .integer => |i| try std.fmt.allocPrint(a, "{d}", .{i}),
            .null => continue,
            else => continue,
        };
        try out.append(a, .{ try std.ascii.allocLowerString(a, e.key_ptr.*), val });
    }
    return out.items;
}

fn b64(a: Allocator, s: []const u8) ![]const u8 {
    const d = std.base64.standard.Decoder;
    const out = try a.alloc(u8, try d.calcSizeForSlice(s));
    try d.decode(out, s);
    return out;
}

fn b64List(a: Allocator, v: ?std.json.Value) ![]const []const u8 {
    const x = v orelse return &.{};
    if (x != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (x.array.items) |e| switch (e) {
        .string => |s| try out.append(a, try b64(a, s)),
        .object => |ob| try out.append(a, try b64(a, str(ob.get("b64")) orelse str(ob.get("payload_b64")) orelse "")),
        else => {},
    };
    return out.items;
}

/// `messages_b64`: strings, or objects `{ "b64", "compressed" }`; a top-level `compressed: true`
/// marks every message.
fn messagesOf(a: Allocator, resp: std.json.ObjectMap) ![]const loopback.Message {
    const all_compressed = if (resp.get("compressed")) |c| c == .bool and c.bool else false;
    const x = resp.get("messages_b64") orelse return &.{};
    if (x != .array) return &.{};
    var out: std.ArrayList(loopback.Message) = .empty;
    defer if (resp.get("compressed_flags")) |cf| if (cf == .array) for (cf.array.items) |i| {
        if (i == .integer and i.integer >= 0 and i.integer < out.items.len) out.items[@intCast(i.integer)].compressed = true;
    };
    for (x.array.items) |e| switch (e) {
        .string => |s| try out.append(a, .{ .compressed = all_compressed, .payload = try b64(a, s) }),
        .object => |ob| try out.append(a, .{
            .compressed = all_compressed or (if (ob.get("compressed")) |c| c == .bool and c.bool else false),
            .payload = try b64(a, str(ob.get("b64")) orelse str(ob.get("payload_b64")) orelse ""),
        }),
        else => {},
    };
    return out.items;
}

// ---------------------------------------------------------------- the node

/// Commits one `.chk` CheckpointData blob to `st` as the follower does: the checkpoint and its
/// digest, each transaction with its effects and events, and every output object.
pub fn ingestBlob(gpa: Allocator, st: *store.Store, idx: *types.index.CheckpointIndex, blob: []const u8) !struct { seq: u64, digest: [32]u8 } {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    if (blob.len == 0 or blob[0] != 1) return error.BadBlob;
    try types.index.indexCheckpointData(blob, idx);
    const cpd = try bcs.decode(types.CheckpointData, a, blob[1..]);
    const seq = cpd.checkpoint_summary.data.sequence_number;
    var snap = st.snapshot();
    var snap_held = true;
    defer if (snap_held) snap.release();
    var put: std.AutoHashMapUnmanaged(objset.Key, void) = .empty;
    const b = try st.begin(seq, cpd.checkpoint_summary.data.epoch);
    errdefer st.abort(b);
    try b.checkpoint(blob[idx.summary.o .. idx.sig.o + idx.sig.n], idx.contents.slice(blob));
    const digest = checkpoint.verify.summaryDigest(idx.summary.slice(blob));
    try b.checkpointDigest(&digest);
    const contents = try bcs.decode(types.CheckpointContents, a, idx.contents.slice(blob));
    for (0..idx.tx_count) |i| {
        const t = idx.txAt(i);
        const dg: [2][32]u8 = switch (contents) {
            .V1 => |v| .{ v.transactions[i].transaction.@"0".@"0", v.transactions[i].effects.@"0".@"0" },
            .V2 => |v| .{ v.transactions[i].digest.transaction.@"0".@"0", v.transactions[i].digest.effects.@"0".@"0" },
        };
        try b.transaction(&dg[0], &dg[1], t.transaction.slice(blob), t.effects.slice(blob), if (t.events) |e| e.slice(blob) else null);
        // inputs the store has not seen (a store that starts mid-chain)
        for (idx.objs[t.in_first..][0..t.in_count]) |r| {
            const raw = r.slice(blob);
            const k = try objset.headKey(raw);
            if (put.contains(k)) continue;
            const version = std.mem.readInt(u64, k[32..40], .little);
            if (snap.objectAt(k[0..32], version) != null) continue;
            try b.putObject(k[0..32], version, &store.objectDigest(raw), raw);
            try put.put(a, k, {});
        }
        for (idx.objs[t.out_first..][0..t.out_count]) |r| {
            const raw = r.slice(blob);
            const k = try objset.headKey(raw);
            try b.putObject(k[0..32], std.mem.readInt(u64, k[32..40], .little), &store.objectDigest(raw), raw);
            try put.put(a, k, {});
        }
    }
    snap.release();
    snap_held = false;
    try st.commit(b);
    return .{ .seq = seq, .digest = digest };
}

const World = struct {
    gpa: Allocator,
    io: std.Io,
    dir: []u8,
    h: struct { store: *store.Store, io: *store.RealIo },
    ix: *history.Index,
    svc: service.Service,
    hub: subscribe.Hub,
    server: std.Io.net.Server,
    port: u16,
    thread: std.Thread,
    stopping: std.atomic.Value(bool) = .init(false),
    chks: []const Chk,
    next: usize = 0,
    tip: ?u64 = null,
    /// A replay failed midway: the next case gets a fresh node.
    dirty: bool = false,
    idx: types.index.CheckpointIndex,

    fn init(ctx: *harness.Ctx, chks: []const Chk, loaded: *const LoadedMap, suite: []const u8) !*World {
        const gpa = ctx.gpa;
        const w = try gpa.create(World);
        errdefer gpa.destroy(w);
        const dir = try std.fmt.allocPrint(gpa, "{s}/sessions/serve/{d}-{s}", .{ ctx.corpus_path, std.c.getpid(), suite });
        std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
        var cfg: store.Config = .{ .dir = dir, .max_live_objects = 1 << 18, .max_object_versions = 1 << 18, .max_transactions = 1 << 16, .max_checkpoints = 1 << 14, .max_batch_bytes = 1 << 30, .max_batch_objects = 1 << 18, .max_segments = 64, .segment_reserve = 1 << 28, .seed = 7 };
        const h = try store.openDir(gpa, ctx.io, &cfg, .{ .sync = .none });
        w.* = .{
            .gpa = gpa,
            .io = ctx.io,
            .dir = dir,
            .h = .{ .store = h.store, .io = h.io },
            .ix = try history.Index.init(gpa, ctx.io, null),
            .svc = undefined,
            .hub = undefined,
            .server = undefined,
            .port = 0,
            .thread = undefined,
            .chks = chks,
            .idx = try types.index.CheckpointIndex.init(gpa),
        };
        w.svc = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0), .history = w.ix, .chain = .unknown, .chain_name = "unknown", .lowest_checkpoint = 0, .loaded = loaded.source() }; // a localnet's chain id names no known chain
        w.hub = subscribe.Hub.init(gpa, ctx.io, &w.svc);
        w.svc.hub = &w.hub;
        var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        w.server = try addr.listen(ctx.io, .{ .reuse_address = true });
        w.port = w.server.socket.address.getPort();
        w.thread = try std.Thread.spawn(.{}, serveLoop, .{w});
        return w;
    }

    fn serveLoop(w: *World) void {
        while (!w.stopping.load(.acquire)) {
            const st = w.server.accept(w.io) catch return;
            if (w.stopping.load(.acquire)) {
                st.close(w.io);
                return;
            }
            h2.server.serveStreamOpts(w.gpa, w.io, st, .{}, w.svc.handler());
        }
    }

    fn deinit(w: *World) void {
        w.stopping.store(true, .release);
        var addr = std.Io.net.IpAddress.parseIp4("127.0.0.1", w.port) catch unreachable;
        if (addr.connect(w.io, .{ .mode = .stream })) |c| c.close(w.io) else |_| {}
        w.thread.join();
        w.server.deinit(w.io);
        _ = waitIdle(&w.hub, 2000, 0);
        w.hub.deinit();
        w.svc.deinit();
        w.ix.deinit();
        w.h.store.deinit();
        w.h.io.deinit();
        std.Io.Dir.cwd().deleteTree(w.io, w.dir) catch {};
        w.idx.deinit(w.gpa);
        w.gpa.free(w.dir);
        w.gpa.destroy(w);
    }

    fn ingestTo(w: *World, tip: u64) !void {
        while (w.next < w.chks.len and w.chks[w.next].seq <= tip) _ = try w.ingestNext();
    }

    /// Commits the next checkpoint to the store and the history index; null when none is left.
    fn ingestNext(w: *World) !?u64 {
        if (w.next >= w.chks.len) return null;
        const c = w.chks[w.next];
        const r = try ingestBlob(w.gpa, w.h.store, &w.idx, c.blob);
        const seq = r.seq;
        const blob = c.blob;
        const digest = r.digest;
        try w.ix.addCheckpoint(seq, blob);
        w.ix.publish(seq);
        if (seq == 0) w.svc.chain_id = digest;
        w.tip = seq;
        w.next += 1;
        return seq;
    }
};

/// The variant's subscription knobs (configs/<variant>.yaml `subscription-max-subscribers`,
/// `subscription-watermark-interval`), else the defaults.
fn applyVariant(a: Allocator, io: std.Io, root: []const u8, w: *World, variant: []const u8) void {
    w.hub.max_subscribers = subscribe.default_max_subscribers;
    w.hub.watermark_interval = subscribe.default_watermark_interval;
    const p = std.fmt.allocPrint(a, "{s}/configs/{s}.yaml", .{ root, variant }) catch return;
    const text = std.Io.Dir.cwd().readFileAlloc(io, p, a, .limited(1 << 20)) catch return;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        const t = std.mem.trim(u8, l, " \r\t");
        const colon = std.mem.indexOfScalar(u8, t, ':') orelse continue;
        const v = std.fmt.parseInt(u32, std.mem.trim(u8, t[colon + 1 ..], " "), 10) catch continue;
        if (std.mem.eql(u8, t[0..colon], "subscription-max-subscribers")) w.hub.max_subscribers = v;
        if (std.mem.eql(u8, t[0..colon], "subscription-watermark-interval")) w.hub.watermark_interval = v;
    }
}

fn waitIdle(hub: *subscribe.Hub, ms: u32, baseline: u64) bool {
    var waited: u32 = 0;
    while (hub.stats.subscribers.load(.monotonic) > baseline) : (waited += 10) {
        if (waited >= ms) return false;
        @import("h2/sock.zig").sleepMs(10);
    }
    return true;
}

/// The subscription driver: once the stream is registered, each tick commits and publishes the
/// next checkpoint (what the node's watcher does after a commit).
const Driver = struct {
    w: *World,
    /// Subscribers open before the call (a held slot).
    baseline: u64 = 0,
    waited: u32 = 0,
    failed: ?anyerror = null,
    fn tick(p: *anyopaque) bool {
        const d: *Driver = @ptrCast(@alignCast(p));
        if (d.failed != null) return false;
        if (d.w.hub.stats.subscribers.load(.monotonic) <= d.baseline) {
            d.waited += 1;
            return d.waited < 40; // ~2 s for the subscriber to register (an error reply ends sooner)
        }
        const seq = (d.w.ingestNext() catch |e| {
            d.failed = e;
            return false;
        }) orelse return false;
        d.w.hub.publish(seq);
        return true;
    }
};

// ---------------------------------------------------------------- one case

const trailer_names = [_][]const u8{ "grpc-status", "grpc-message", "grpc-status-details-bin" };

fn isTrailerName(n: []const u8) bool {
    for (trailer_names) |t| if (std.mem.eql(u8, n, t)) return true;
    return false;
}

fn isVolatile(c: *const Case, n: []const u8) bool {
    if (std.mem.eql(u8, n, "date") or std.mem.eql(u8, n, "server-timing")) return true;
    for (c.volatile_headers) |v| if (std.ascii.eqlIgnoreCase(v, n)) return true;
    return false;
}

fn find(list: []const [2][]const u8, name: []const u8) ?[]const u8 {
    for (list) |kv| if (std.mem.eql(u8, kv[0], name)) return kv[1];
    return null;
}

fn runCase(ctx: *harness.Ctx, w: *World, c: *const Case) !void {
    const a = ctx.scratch();
    w.svc.history = if (c.no_index) null else w.ix;
    defer w.svc.history = w.ix;
    // sub-limit/second-subscriber*: the capture's first subscriber was still open
    var holder: ?*subscribe.Sub = null;
    if (std.mem.indexOf(u8, c.item, "second-subscriber") != null) holder = try w.hub.holdSlot(.events);
    defer if (holder) |h| w.hub.releaseHeld(h);
    var drv: Driver = .{ .w = w, .baseline = if (holder != null) 1 else 0 };
    const opts: loopback.StreamOptions = if (c.subscription)
        .{ .max_messages = c.want.messages.len, .tick = .{ .ctx = &drv, .f = Driver.tick } }
    else
        .{};
    const rep = try loopback.call(a, ctx.io, w.port, c.path, c.req_headers, c.req_messages, opts);
    if (c.subscription) {
        // the client closed; the next case starts once the hub let the subscriber go
        if (!waitIdle(&w.hub, 3000, drv.baseline)) w.dirty = true;
        if (drv.failed) |e| return e;
        // the node moved past the capture's tip: the next case rebuilds it if it needs a lower one
    }

    var ck = ctx.check(c.item);
    ck.text("http status", c.want.http_status, rep.status);
    if (c.status_only) {
        for (trailer_names) |n| ck.text(n, find(c.want.trailers, n) orelse find(c.want.headers, n) orelse "", find(rep.trailers.items, n) orelse find(rep.headers.items, n) orelse "");
        _ = ck.finish();
        return;
    }
    // headers (grpc-* trailer fields split out of either block)
    var got_all: std.ArrayList([2][]const u8) = .empty;
    try got_all.appendSlice(a, rep.headers.items);
    try got_all.appendSlice(a, rep.trailers.items);
    var want_all: std.ArrayList([2][]const u8) = .empty;
    try want_all.appendSlice(a, c.want.headers);
    try want_all.appendSlice(a, c.want.trailers);
    for (want_all.items) |kv| {
        if (isTrailerName(kv[0]) or isVolatile(c, kv[0])) continue;
        const got = find(got_all.items, kv[0]) orelse {
            ck.failf("header {s}: missing (sui-node: {s})", .{ kv[0], kv[1] });
            continue;
        };
        ck.text(try std.fmt.allocPrint(a, "header {s}", .{kv[0]}), kv[1], got);
    }
    for (got_all.items) |kv| {
        if (isTrailerName(kv[0]) or isVolatile(c, kv[0])) continue;
        if (find(want_all.items, kv[0]) == null) ck.failf("header {s}: zui sends it ({s}), sui-node does not", .{ kv[0], kv[1] });
    }
    if (c.want.trailers_only) |to| if (to != rep.trailers_only) ck.failf("trailers-only: sui-node {}, zui {}", .{ to, rep.trailers_only });
    // messages
    if (c.want.messages.len != rep.messages.items.len) ck.failf("messages: sui-node {d}, zui {d}", .{ c.want.messages.len, rep.messages.items.len });
    for (c.want.messages, 0..) |m, i| {
        if (i >= rep.messages.items.len) break;
        const g = rep.messages.items[i];
        const what = try std.fmt.allocPrint(a, "message {d}", .{i});
        ck.bytes(what, try plain(a, m), try plain(a, g));
    }
    // trailers (only for a stream that ended: a subscription the client closed has none)
    if (!c.subscription or find(want_all.items, "grpc-status") != null) for (trailer_names) |n| {
        const want = find(want_all.items, n) orelse "";
        const got = find(got_all.items, n) orelse "";
        ck.text(n, want, got);
    };
    if (!ck.ok()) if (std.c.getenv("ZUI_RPCEV_DUMP")) |dd| for (rep.messages.items, 0..) |m, i| {
        const p = try std.fmt.allocPrint(a, "{s}/{s}-{d}.bin", .{ std.mem.span(dd), std.fs.path.basename(c.item), i });
        std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = p, .data = try plain(a, m) }) catch {};
    };
    if (!ck.ok()) ctx.detail("rpc-events: {s}: zui sent {d} messages, ended {}, reset {?d}\n", .{ c.item, rep.messages.items.len, rep.ended, rep.reset });
    _ = ck.finish();
}

/// A message's payload with gzip undone (both sides compare uncompressed bytes).
fn plain(a: Allocator, m: loopback.Message) ![]const u8 {
    if (!m.compressed or m.payload.len < 2 or m.payload[0] != 0x1f or m.payload[1] != 0x8b) return m.payload;
    var in: std.Io.Reader = .fixed(m.payload);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var d: std.compress.flate.Decompress = .init(&in, .gzip, &window);
    var out: std.Io.Writer.Allocating = .init(a);
    _ = try d.reader.streamRemaining(&out.writer);
    return out.written();
}
