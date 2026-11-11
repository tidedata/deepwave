//! Conformance of edge forwarding (docs/EDGE.md section 11): a core and an edge built from it
//! through the real feed, and the grpc-v2 request shapes sent to both.
//!
//! - The core: corpus checkpoints applied the way a node applies them (`store.ops`), with every
//!   object its transactions read (the archive's input objects) and a loaded-object list per
//!   transaction: a node with read sets. It serves sui.rpc.v2 on loopback and the edge feed on
//!   zui/1.
//! - The edge: the node's own fetch path and follower (`edge_fallback_tests.zig`'s fixture)
//!   over that feed, so its store is what a feed builds: no input objects, no loaded lists.
//!   In front of its service sits `edge.forward.Forwarder`, with the core as its upstream.
//!
//! The diff: every request goes to the core's handler and to the edge's forwarding handler, and
//! status, message bytes, grpc-message and status details must be equal. The requests are the
//! grpc-v2 suite's (`$ZUI_CORPUS/vectors/grpc-v2*/masks*.txt` on every checkpoint, transaction and
//! object of the window, singly and in batches) plus focused cases for each routing rule the
//! window alone would not reach. A second pass asks the edge's store without forwarding, one read
//! mask path at a time: every path whose answer differs from the core's must be one the routing
//! forwards, which is how the list of fields that need read sets is checked for completeness.
//!
//! What this run does and does not show (it prints the numbers; read them with the result):
//! - It is a sample: `ZUI_EDGE_FWD_COUNT` checkpoints of the dense window, every n-th
//!   transaction and object. `json` and `display` are off, and neither node has a StateService,
//!   rpc or ledger-history index, an executor or a name service.
//! - The core is built from `chk/` blobs, which lack some objects transactions read. Where the
//!   core itself cannot answer (every GetCheckpoint under an object-set mask, and part of the
//!   transactions under `effects`), the diff compares the core's error with the same error
//!   relayed: equal, and silent about the data. The report line counts, per routing outcome,
//!   how many compared answers were successes on the core.
//! - The core's loaded-object list is made up (one object it holds, for every transaction): it
//!   shows that the field differs and is forwarded, not what real lists contain.
//! - So the completeness pass proves this much: every difference seen is on a path the routing
//!   forwards. A core with real read sets (archive protos, `--read-sets`) is a test machine's run.
//!
//! Needs the corpus (`$ZUI_CORPUS`); skips without it. `ZUI_EDGE_FWD_COUNT` (checkpoints,
//! default 24) and `ZUI_EDGE_FWD_STRIDE` (every n-th transaction and object, default 3) size it;
//! a large test machine runs it wide.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const Atomic = std.atomic.Value;
const store = @import("store");
const types = @import("types");
const serve = @import("serve");
const edge = @import("edge");
const native = @import("native");
const fx = @import("edge_fallback_tests.zig");

const io = testing.io;
const h2 = serve.h2;
const proto = serve.proto;
const loopback = serve.loopback;
const service = serve.service;
const forward = edge.forward;
const route = edge.route;
const sys = std.heap.smp_allocator;
const first = fx.first;
const ms: u64 = std.time.ns_per_ms;

const ledger = "/sui.rpc.v2.LedgerService/";
const p_checkpoint = ledger ++ "GetCheckpoint";
const p_tx = ledger ++ "GetTransaction";
const p_txs = ledger ++ "BatchGetTransactions";
const p_object = ledger ++ "GetObject";
const p_objects = ledger ++ "BatchGetObjects";
const p_info = ledger ++ "GetServiceInfo";
const p_epoch = ledger ++ "GetEpoch";

fn envU(name: [*:0]const u8, default: u64) u64 {
    const p = std.c.getenv(name) orelse return default;
    return std.fmt.parseInt(u64, std.mem.span(p), 10) catch default;
}

/// A node's sui.rpc.v2 port on loopback.
const Rpc = struct {
    listener: Io.net.Server,
    port: u16,
    stop_flag: Atomic(bool) = .init(false),
    thread: std.Thread,
    handler: h2.Handler,

    fn start(handler: h2.Handler) !*Rpc {
        const s = try sys.create(Rpc);
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        s.* = .{ .listener = try addr.listen(io, .{ .reuse_address = true }), .port = 0, .thread = undefined, .handler = handler };
        s.port = s.listener.socket.address.getPort();
        s.thread = try std.Thread.spawn(.{}, run, .{s});
        return s;
    }
    fn run(s: *Rpc) void {
        h2.serveBlocking(sys, io, &s.listener, .{ .poll_accept = true, .stop_grace_ns = 50 * ms }, s.handler, &s.stop_flag) catch {};
    }
    fn stop(s: *Rpc) void {
        s.stop_flag.store(true, .release);
        s.thread.join();
        _ = h2.server.waitDrained(3 * std.time.ns_per_s);
        s.listener.deinit(io);
        sys.destroy(s);
    }
};

/// What the window holds, for building requests.
const Window = struct {
    const Tx = struct { digest: [32]u8, seq: u64, sigs: usize };
    const Obj = struct { id: [32]u8, version: u64 };
    txs: std.ArrayList(Tx) = .empty,
    /// Objects written in the window (the last version of each is its live one).
    outs: std.ArrayList(Obj) = .empty,
    /// Objects only read in the window, at versions written before it: a feed never carries them.
    ins: std.ArrayList(Obj) = .empty,
    /// One object the core holds, named by its loaded-object list for every transaction.
    loaded: [1]serve.objset.Ref = undefined,
    have_loaded: bool = false,
};

/// The core's loaded-object lists (serve.service.LoadedSource): every transaction "loaded" one
/// object the core holds. The corpus blobs carry no such list, and an edge never has one.
fn loadedOf(ctx: *const anyopaque, _: *const store.Snapshot, _: *const [32]u8, _: u64) []const serve.objset.Ref {
    const w: *const Window = @ptrCast(@alignCast(ctx));
    return if (w.have_loaded) &w.loaded else &.{};
}

/// One corpus checkpoint into the core's store as a node with read sets holds it: the objects
/// its transactions read that the store does not have yet (oldest version first), then the
/// checkpoint's own operations.
fn storeFull(st: *store.Store, a: std.mem.Allocator, win: *Window, blob: []const u8, ops_bytes: []const u8, idx: *types.index.CheckpointIndex) !void {
    var cp = try store.ops.parse(a, ops_bytes, blob);
    const b = try st.begin(cp.seq, cp.epoch);
    errdefer st.abort(b);
    try types.index.indexCheckpointData(blob, idx);
    const Extra = struct { id: [32]u8, version: u64, raw: []const u8 };
    var extras: std.ArrayList(Extra) = .empty;
    {
        var snap = st.snapshot();
        defer snap.release();
        for (idx.objs[0..idx.obj_total]) |o| {
            const raw = o.slice(blob);
            const k = try serve.objset.headKey(raw);
            const id = k[0..32].*;
            const version = std.mem.readInt(u64, k[32..40], .little);
            if (snap.objectAt(&id, version) != null) continue;
            var written = false;
            for (cp.txs) |t| for (t.puts) |p| {
                if (p.version == version and std.mem.eql(u8, p.id, &id)) written = true;
            };
            if (!written) try extras.append(a, .{ .id = id, .version = version, .raw = raw });
        }
    }
    std.mem.sort(Extra, extras.items, {}, struct {
        fn lt(_: void, x: Extra, y: Extra) bool {
            const o = std.mem.order(u8, &x.id, &y.id);
            return if (o == .eq) x.version < y.version else o == .lt;
        }
    }.lt);
    for (extras.items, 0..) |x, i| {
        if (i > 0 and extras.items[i - 1].version == x.version and std.mem.eql(u8, &extras.items[i - 1].id, &x.id)) continue;
        try b.putObject(&x.id, x.version, &types.digest.objectDigest(x.raw), x.raw);
        try win.ins.append(sys, .{ .id = x.id, .version = x.version });
        if (!win.have_loaded) {
            win.loaded[0] = .{ .id = x.id, .version = x.version };
            win.have_loaded = true;
        }
    }
    try store.ops.apply(b, &cp);
    // the checkpoint digest index, as the follower writes it (GetCheckpoint by digest)
    try b.checkpointDigest(&@import("hash").blake2b256(&.{ "CheckpointSummary::", idx.summary.slice(blob) }));
    try st.commit(b);
    for (cp.txs) |t| {
        const sp = try service.splitEnvelope(a, t.tx);
        try win.txs.append(sys, .{ .digest = t.digest.*, .seq = cp.seq, .sigs = sp.sigs.len });
        for (t.puts) |p| try win.outs.append(sys, .{ .id = p.id.*, .version = p.version });
    }
}

// ---------------------------------------------------------------- request builders

fn maskInto(w: *proto.Writer, field: u32, mask: ?[]const u8) !void {
    const text = mask orelse return;
    const m = try w.begin(field, 256);
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |p| if (p.len > 0) try w.string(1, p);
    try w.end(m);
}

fn idText(buf: *[66]u8, id: *const [32]u8) []const u8 {
    return std.fmt.bufPrint(buf, "0x{x}", .{id}) catch unreachable;
}

const Req = struct {
    a: std.mem.Allocator,

    fn writer(r: Req) !proto.Writer {
        return proto.Writer.init(try r.a.alloc(u8, 64 << 10));
    }
    fn checkpoint(r: Req, seq: ?u64, digest: ?[]const u8, mask: ?[]const u8) ![]const u8 {
        var w = try r.writer();
        if (seq) |s| try w.uint(1, s);
        if (digest) |d| try w.string(2, d);
        try maskInto(&w, 3, mask);
        return w.bytesWritten();
    }
    fn tx(r: Req, digest: *const [32]u8, mask: ?[]const u8) ![]const u8 {
        var w = try r.writer();
        var db: [serve.b58.max_len_32]u8 = undefined;
        try w.string(1, serve.b58.encode32(&db, digest));
        try maskInto(&w, 2, mask);
        return w.bytesWritten();
    }
    fn txs(r: Req, digests: []const [32]u8, mask: ?[]const u8) ![]const u8 {
        var w = try r.writer();
        for (digests) |*d| {
            var db: [serve.b58.max_len_32]u8 = undefined;
            try w.string(1, serve.b58.encode32(&db, d));
        }
        try maskInto(&w, 2, mask);
        return w.bytesWritten();
    }
    fn objectInto(w: *proto.Writer, field: ?u32, id: *const [32]u8, version: ?u64) !void {
        var ib: [66]u8 = undefined;
        const m = if (field) |f| try w.begin(f, 128) else null;
        try w.string(1, idText(&ib, id));
        if (version) |v| try w.uint(2, v);
        if (m) |mm| try w.end(mm);
    }
    fn object(r: Req, id: *const [32]u8, version: ?u64, mask: ?[]const u8) ![]const u8 {
        var w = try r.writer();
        try objectInto(&w, null, id, version);
        try maskInto(&w, 3, mask);
        return w.bytesWritten();
    }
    fn objects(r: Req, items: []const Window.Obj, versioned: bool, mask: ?[]const u8) ![]const u8 {
        var w = try r.writer();
        for (items) |*o| try objectInto(&w, 1, &o.id, if (versioned) o.version else null);
        try maskInto(&w, 2, mask);
        return w.bytesWritten();
    }
};

fn sameReply(x: loopback.Reply, y: loopback.Reply) bool {
    return x.status == y.status and std.mem.eql(u8, x.message, y.message) and std.mem.eql(u8, x.grpc_message, y.grpc_message) and std.mem.eql(u8, x.details, y.details);
}

/// The bytes of the length-delimited field at `path` (last occurrence at each level).
fn nested(msg: []const u8, path: []const u32) ?[]const u8 {
    var cur = msg;
    for (path) |n| {
        var found: ?[]const u8 = null;
        var r = proto.Reader.init(cur);
        while (r.next() catch return null) |fld| if (fld.number == n) {
            found = proto.Reader.bytesOf(fld) catch return null;
        };
        cur = found orelse return null;
    }
    return cur;
}

fn masksFile(a: std.mem.Allocator, sub: []const u8) ![]const []const u8 {
    var pb: [600]u8 = undefined;
    const path = try std.fmt.bufPrint(&pb, "{s}/vectors/{s}", .{ try fx.corpus(), sub });
    const text = Io.Dir.cwd().readFileAlloc(io, path, a, .limited(1 << 20)) catch return error.SkipZigTest;
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len > 0) try out.append(a, line);
    return out.items;
}

const Diff = struct {
    arena: std.heap.ArenaAllocator,
    core_h: h2.Handler,
    edge_h: h2.Handler,
    total: u64 = 0,
    differences: u64 = 0,
    shown: u32 = 0,
    /// The forwarder under test, to attribute each request to how it was routed.
    fwd: ?*forward.Forwarder = null,
    /// Per outcome (index 0: served locally; 1 + reason: forwarded for that reason): requests,
    /// and how many of them the core answered with a success. A request the core answers with
    /// an error is still compared, but equal errors say nothing about the data.
    asked: [1 + route.Reason.count]u64 = @splat(0),
    core_ok: [1 + route.Reason.count]u64 = @splat(0),
    unrouted: u64 = 0,

    fn routed(d: *const Diff) [1 + route.Reason.count]u64 {
        var out: [1 + route.Reason.count]u64 = @splat(0);
        const f = d.fwd orelse return out;
        for (&f.metrics.methods) |*pm| {
            out[0] += pm.served_local.load(.monotonic);
            for (&pm.forwarded, 0..) |*c, i| out[1 + i] += c.load(.monotonic);
        }
        return out;
    }

    fn check(d: *Diff, path: []const u8, body: []const u8) !void {
        const a = d.arena.allocator();
        const want = try loopback.unary(a, d.core_h, path, body);
        const before = d.routed();
        const got = try loopback.unary(a, d.edge_h, path, body);
        const after = d.routed();
        d.total += 1;
        var bucket: ?usize = null;
        for (before, after, 0..) |x, y, i| if (y > x) {
            bucket = i;
        };
        if (bucket) |i| {
            d.asked[i] += 1;
            if (want.status == 0) d.core_ok[i] += 1;
        } else d.unrouted += 1; // the edge's own paths (health, unknown methods)
        if (sameReply(want, got)) return;
        d.differences += 1;
        if (d.shown < 12) {
            d.shown += 1;
            std.debug.print("edge-forward DIFFERENCE {s} request {x}\n  core: status {d} \"{s}\" {d} message bytes, {d} detail bytes\n  edge: status {d} \"{s}\" {d} message bytes, {d} detail bytes\n", .{ path, body[0..@min(body.len, 96)], want.status, want.grpc_message, want.message.len, want.details.len, got.status, got.grpc_message, got.message.len, got.details.len });
        }
    }
    fn round(d: *Diff) void {
        _ = d.arena.reset(.retain_capacity);
    }
};

/// Read mask paths asked one at a time in the completeness pass: every field of the message
/// (a path selects its whole subtree), and the paths the default masks use.
const tx_paths = [_][]const u8{ "digest", "transaction", "signatures", "effects", "events", "checkpoint", "timestamp", "balance_changes", "objects", "effects.status", "effects.unchanged_loaded_runtime_objects", "effects.changed_objects", "effects.bcs", "transaction.bcs", "signatures.bcs", "events.bcs", "objects.objects.bcs", "*" };
const cp_paths = [_][]const u8{ "sequence_number", "digest", "summary", "signature", "contents", "transactions", "objects", "transactions.digest", "transactions.transaction", "transactions.signatures", "transactions.effects", "transactions.events", "transactions.checkpoint", "transactions.timestamp", "transactions.balance_changes", "transactions.objects", "transactions.effects.unchanged_loaded_runtime_objects", "objects.objects.bcs", "*" };
const obj_paths = [_][]const u8{ "object_id", "version", "digest", "owner", "object_type", "has_public_transfer", "contents", "package", "previous_transaction", "storage_rebate", "balance", "bcs", "*" };

test "edge forward conformance: the grpc-v2 requests answered by a core and by an edge built from its feed, with forwarding, are equal; every field a feed-built store answers differently is forwarded" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const count = envU("ZUI_EDGE_FWD_COUNT", 24);
    const stride: usize = @intCast(@max(1, envU("ZUI_EDGE_FWD_STRIDE", 3)));
    const a = w.arena.allocator();
    const cp_masks = try masksFile(a, "grpc-v2/masks.txt");
    const tx_masks = try masksFile(a, "grpc-v2-tx/masks.txt");
    const obj_masks = try masksFile(a, "grpc-v2-tx/masks-obj.txt");

    // ---- the core: `count` checkpoints, read sets and all
    var win: Window = .{};
    defer {
        win.txs.deinit(sys);
        win.outs.deinit(sys);
        win.ins.deinit(sys);
    }
    {
        const ops_dir = try fx.corpusDir("vectors/store-replay/ops");
        defer ops_dir.close(io);
        var idx = try types.index.CheckpointIndex.init(testing.allocator);
        defer idx.deinit(testing.allocator);
        var scratch = std.heap.ArenaAllocator.init(testing.allocator);
        defer scratch.deinit();
        for (0..count) |i| {
            _ = scratch.reset(.retain_capacity);
            const sa = scratch.allocator();
            const blob = try fx.readSeq(sa, w.core.chk, first + i, ".chk");
            const ops_bytes = try fx.readSeq(sa, ops_dir, first + i, ".ops");
            try storeFull(w.core.st, sa, &win, blob, ops_bytes, &idx);
        }
        w.core.have = first + count - 1;
    }
    w.core.svc.json = false;
    w.core.svc.display = false;
    w.core.svc.lowest_checkpoint = first;
    w.core.svc.loaded = .{ .ctx = &win, .get = loadedOf };
    try w.coreUp(true);
    const core_rpc = try Rpc.start(w.core.svc.handler());
    defer core_rpc.stop();

    // ---- the edge: the same checkpoints through the feed and the follower
    const e = try w.edge_("forward", false, fx.quick);
    defer e.destroy();
    try e.follow();
    try fx.must(e.waitCommitted(count, 120_000), "the edge applied the window", e);
    var edge_svc: service.Service = .{ .gpa = testing.allocator, .store = e.st, .chain_id = @splat(0), .json = false, .display = false, .lowest_checkpoint = first };
    defer edge_svc.deinit();
    var gt = try forward.GrpcTransport.init(sys, io, .{ .host = "127.0.0.1", .port = core_rpc.port, .security = .plain });
    const f = try forward.Forwarder.create(testing.allocator, io, &edge_svc, gt.transport(), .{ .ahead_wait_ms = 30, .hold_ms = 20 });
    defer {
        f.destroy();
        const conn = gt.up.conn;
        if (conn) |c| c.retain();
        gt.deinit();
        if (conn) |c| {
            var i: u32 = 0;
            while (i < 5000) : (i += 1) {
                c.mu.lockUncancelable(io);
                const gone = c.reader_done;
                c.mu.unlock(io);
                if (gone) break;
                fx.sleepMs(1);
            }
            c.unref();
        }
    }
    // a healthy edge at its core's tip, which knows its core's floor
    f.observe(h2.meta.monoNs(), .{ .lag = 0, .source_age_ns = 0 });
    fx.sleepMs(25);
    f.observe(h2.meta.monoNs(), .{ .lag = 0, .source_age_ns = 0 });
    try testing.expectEqual(route.GuardState.ok, f.guardState());
    f.refreshFloor(h2.meta.monoNs());
    try testing.expectEqual(first, service.reportedLowest(&edge_svc));

    var d: Diff = .{ .arena = std.heap.ArenaAllocator.init(testing.allocator), .core_h = w.core.svc.handler(), .edge_h = f.handler(), .fwd = f };
    defer d.arena.deinit();
    const rq: Req = .{ .a = d.arena.allocator() };
    const tip = first + count - 1;

    // ---- pass 1: completeness. The edge's store alone (no forwarding), one mask path at a
    // time: where it answers differently from the core, the routing must forward.
    var differing_tx: [tx_paths.len]u32 = @splat(0);
    var differing_cp: [cp_paths.len]u32 = @splat(0);
    // how many of the core's own answers were successes (a difference only shows where the core
    // can answer: the corpus blobs lack some objects a transaction read, and the core then
    // fails as the edge does)
    var core_ok_tx: [tx_paths.len]u32 = @splat(0);
    var core_ok_cp: [cp_paths.len]u32 = @splat(0);
    var asked_tx: u32 = 0;
    var first_tx_err: []const u8 = "";
    var first_cp_err: []const u8 = "";
    // distinct "unable to fetch object ObjectKey(..)" texts the core gave, up to a cap
    var lacking: std.StringHashMapUnmanaged(u32) = .empty;
    defer {
        var it = lacking.keyIterator();
        while (it.next()) |k| sys.free(k.*);
        lacking.deinit(sys);
    }
    defer sys.free(first_tx_err);
    defer sys.free(first_cp_err);
    var asked_local: u64 = 0;
    {
        const local_h = edge_svc.handler();
        const la = d.arena.allocator();
        var i: usize = 0;
        while (i < win.txs.items.len) : (i += stride) {
            const t = &win.txs.items[i];
            for (tx_paths, 0..) |p, k| {
                const body = try rq.tx(&t.digest, p);
                const want = try loopback.unary(la, d.core_h, p_tx, body);
                const got = try loopback.unary(la, local_h, p_tx, body);
                asked_local += 1;
                if (want.status == 0) core_ok_tx[k] += 1;
                if (want.status != 0 and std.mem.eql(u8, p, "effects")) {
                    if (first_tx_err.len == 0) first_tx_err = try sys.dupe(u8, want.grpc_message);
                    // the object named, without the transaction it was read for
                    const key = want.grpc_message[0 .. std.mem.indexOf(u8, want.grpc_message, " for transaction") orelse want.grpc_message.len];
                    if (lacking.getPtr(key)) |n| n.* += 1 else if (lacking.count() < 4096) try lacking.put(sys, try sys.dupe(u8, key), 1);
                }
                if (!sameReply(want, got)) differing_tx[k] += 1;
            }
            asked_tx += 1;
            d.round();
        }
        for (0..count) |c| {
            for (cp_paths, 0..) |p, k| {
                const body = try rq.checkpoint(first + c, null, p);
                const want = try loopback.unary(la, d.core_h, p_checkpoint, body);
                const got = try loopback.unary(la, local_h, p_checkpoint, body);
                asked_local += 1;
                if (want.status == 0) core_ok_cp[k] += 1;
                if (want.status != 0 and first_cp_err.len == 0 and std.mem.eql(u8, p, "transactions.effects")) first_cp_err = try sys.dupe(u8, want.grpc_message);
                if (!sameReply(want, got)) differing_cp[k] += 1;
            }
            d.round();
        }
        // objects the window wrote are the same bytes on both, under every object field
        i = 0;
        while (i < win.outs.items.len) : (i += stride * 4) {
            const o = &win.outs.items[i];
            for (obj_paths) |p| {
                const body = try rq.object(&o.id, o.version, p);
                const want = try loopback.unary(la, d.core_h, p_object, body);
                const got = try loopback.unary(la, local_h, p_object, body);
                asked_local += 1;
                try testing.expect(sameReply(want, got));
            }
            d.round();
        }
    }
    var n_differing: u32 = 0;
    std.debug.print("edge-forward completeness ({d} checkpoints, {d} transactions, {d} local-only answers): read mask paths a feed-built store answers differently from its core:\n", .{ count, win.txs.items.len, asked_local });
    for (tx_paths, differing_tx, core_ok_tx) |p, n, ok| if (n > 0) {
        n_differing += 1;
        std.debug.print("  ExecutedTransaction {s}: {d} of {d} transactions ({d} answered OK by the core)\n", .{ p, n, asked_tx, ok });
        // ... and every one of them is a path the routing sends to the core
        try testing.expect(route.maskNeeds(.transaction, &.{p}).object_set);
    };
    for (cp_paths, differing_cp, core_ok_cp) |p, n, ok| if (n > 0) {
        n_differing += 1;
        std.debug.print("  Checkpoint {s}: {d} of {d} checkpoints ({d} answered OK by the core)\n", .{ p, n, count, ok });
        try testing.expect(route.maskNeeds(.checkpoint, &.{p}).object_set);
    };
    for (cp_paths, differing_cp, core_ok_cp) |p, n, ok| if (n == 0 and route.maskNeeds(.checkpoint, &.{p}).object_set)
        std.debug.print("  (Checkpoint {s}: no difference; the core answered {d} of {d} OK)\n", .{ p, ok, count });
    // what the fixture core itself could not answer, and why (the limit of this pass)
    std.debug.print("edge-forward fixture core: first error under GetTransaction effects: \"{s}\"; under GetCheckpoint transactions.effects: \"{s}\"; {d} distinct objects named as missing by the core over the sampled transactions\n", .{ first_tx_err, first_cp_err, lacking.count() });
    {
        var it = lacking.iterator();
        var shown: u32 = 0;
        while (it.next()) |kv| : (shown += 1) {
            if (shown == 8) break;
            std.debug.print("  core lacks: {s} ({d} sampled transactions)\n", .{ kv.key_ptr.*, kv.value_ptr.* });
        }
    }
    // the fixture must show the difference at all (the core has read sets, the edge has none)
    try testing.expect(n_differing > 0);
    for (tx_paths, differing_tx) |p, n| if (std.mem.eql(u8, p, "effects.unchanged_loaded_runtime_objects")) try testing.expect(n > 0);

    // ---- pass 2: the diff, with forwarding
    // checkpoints: every mask, by number; the default mask; by digest; latest
    for (0..count) |c| {
        const seq = first + c;
        try d.check(p_checkpoint, try rq.checkpoint(seq, null, null));
        for (cp_masks) |m| try d.check(p_checkpoint, try rq.checkpoint(seq, null, m));
        const head = try loopback.unary(d.arena.allocator(), d.core_h, p_checkpoint, try rq.checkpoint(seq, null, "digest"));
        if (nested(head.message, &.{ 1, 2 })) |dg| {
            try d.check(p_checkpoint, try rq.checkpoint(null, dg, null));
            try d.check(p_checkpoint, try rq.checkpoint(null, dg, "summary,contents,transactions.digest"));
        }
        d.round();
    }
    try d.check(p_checkpoint, try rq.checkpoint(null, null, null));
    for (cp_masks) |m| try d.check(p_checkpoint, try rq.checkpoint(null, null, m));
    // transactions: every mask, singly; then each checkpoint's as one batch
    {
        var i: usize = 0;
        while (i < win.txs.items.len) : (i += stride) {
            const t = &win.txs.items[i];
            try d.check(p_tx, try rq.tx(&t.digest, null));
            for (tx_masks) |m| try d.check(p_tx, try rq.tx(&t.digest, m));
            d.round();
        }
        // every transaction with two or more signatures, under masks that render them
        var multi: u32 = 0;
        for (win.txs.items) |*t| if (t.sigs > 1) {
            multi += 1;
            try d.check(p_tx, try rq.tx(&t.digest, "digest,signatures"));
            try d.check(p_tx, try rq.tx(&t.digest, "signatures.bcs"));
            try d.check(p_checkpoint, try rq.checkpoint(t.seq, null, "transactions.signatures"));
            d.round();
        };
        std.debug.print("edge-forward: {d} transactions with two or more signatures in the window\n", .{multi});
        var batch: std.ArrayList([32]u8) = .empty;
        defer batch.deinit(sys);
        var at: usize = 0;
        while (at < win.txs.items.len) {
            batch.clearRetainingCapacity();
            const seq = win.txs.items[at].seq;
            while (at < win.txs.items.len and win.txs.items[at].seq == seq and batch.items.len < 200) : (at += 1) try batch.append(sys, win.txs.items[at].digest);
            try d.check(p_txs, try rq.txs(batch.items, null));
            for (tx_masks) |m| try d.check(p_txs, try rq.txs(batch.items, m));
            // one digest nobody has: the whole batch is the core's to answer
            try batch.append(sys, @splat(0x5a));
            try d.check(p_txs, try rq.txs(batch.items, "digest,checkpoint"));
            d.round();
        }
    }
    // objects: latest and at the written version, every mask; batches of both kinds
    {
        var i: usize = 0;
        while (i < win.outs.items.len) : (i += stride * 2) {
            const o = &win.outs.items[i];
            try d.check(p_object, try rq.object(&o.id, null, null));
            for (obj_masks) |m| {
                try d.check(p_object, try rq.object(&o.id, null, m));
                try d.check(p_object, try rq.object(&o.id, o.version, m));
            }
            // a version before the one written (the core may hold it as an input), one after
            if (o.version > 1) try d.check(p_object, try rq.object(&o.id, o.version - 1, null));
            d.round();
        }
        i = 0;
        while (i + 16 <= win.outs.items.len) : (i += 16 * stride) {
            for (obj_masks) |m| {
                try d.check(p_objects, try rq.objects(win.outs.items[i..][0..16], false, m));
                try d.check(p_objects, try rq.objects(win.outs.items[i..][0..16], true, m));
            }
            d.round();
        }
        // objects only ever read in the window: the core holds them, the feed never carried them
        i = 0;
        while (i < win.ins.items.len) : (i += stride * 2) {
            const o = &win.ins.items[i];
            try d.check(p_object, try rq.object(&o.id, null, null));
            try d.check(p_object, try rq.object(&o.id, o.version, "object_id,version,digest,bcs"));
            d.round();
        }
        if (win.ins.items.len >= 4 and win.outs.items.len >= 4) {
            var mixed: [8]Window.Obj = undefined;
            @memcpy(mixed[0..4], win.outs.items[0..4]);
            @memcpy(mixed[4..8], win.ins.items[0..4]);
            try d.check(p_objects, try rq.objects(&mixed, true, null));
            try d.check(p_objects, try rq.objects(&mixed, false, "*"));
        }
    }
    // focused: each rule the window alone does not reach
    {
        const unknown: [32]u8 = @splat(0x77);
        var db: [serve.b58.max_len_32]u8 = undefined;
        const unknown_b58 = serve.b58.encode32(&db, &unknown);
        // negative answers: unknown digests and ids go to the core at once
        try d.check(p_tx, try rq.tx(&unknown, null));
        try d.check(p_tx, try rq.tx(&unknown, "effects"));
        try d.check(p_checkpoint, try rq.checkpoint(null, unknown_b58, null));
        try d.check(p_object, try rq.object(&unknown, null, null));
        try d.check(p_object, try rq.object(&unknown, 7, null));
        // below every floor, and far ahead of every tip (the wait, then the core's NOT_FOUND)
        try d.check(p_checkpoint, try rq.checkpoint(first - 1, null, null));
        try d.check(p_checkpoint, try rq.checkpoint(0, null, "summary"));
        try d.check(p_checkpoint, try rq.checkpoint(tip + 1, null, null));
        try d.check(p_checkpoint, try rq.checkpoint(std.math.maxInt(u64), null, null));
        if (win.outs.items.len > 0) {
            const o = &win.outs.items[win.outs.items.len - 1];
            try d.check(p_object, try rq.object(&o.id, o.version + 1000, null));
        }
        // requests that are wrong by themselves: the edge's own answer, equal to the core's
        try d.check(p_checkpoint, "\x08");
        try d.check(p_checkpoint, try rq.checkpoint(first, null, "no_such_field"));
        try d.check(p_checkpoint, try rq.checkpoint(null, "not base58 !", null));
        try d.check(p_tx, "");
        try d.check(p_tx, "\x0a\x03abc");
        try d.check(p_tx, try rq.tx(&unknown, "nope.nope"));
        try d.check(p_object, "");
        try d.check(p_object, "\x0a\x02zz");
        try d.check(p_objects, "");
        try d.check(p_txs, "");
        // the rest of the surface, as these two nodes have it configured
        try d.check(p_info, "");
        try d.check(p_epoch, "");
        try d.check(p_epoch, "\x08\x01");
        inline for (.{
            "/sui.rpc.v2.StateService/GetBalance",                         "/sui.rpc.v2.StateService/ListOwnedObjects",
            "/sui.rpc.v2.StateService/ListDynamicFields",                  "/sui.rpc.v2.StateService/GetCoinInfo",
            "/sui.rpc.v2.StateService/ListBalances",                       "/sui.rpc.v2.MovePackageService/GetPackage",
            "/sui.rpc.v2.MovePackageService/GetDatatype",                  "/sui.rpc.v2.MovePackageService/GetFunction",
            "/sui.rpc.v2.MovePackageService/ListPackageVersions",          "/sui.rpc.v2.NameService/LookupName",
            "/sui.rpc.v2.NameService/ReverseLookupName",                   "/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction",
            "/sui.rpc.v2.TransactionExecutionService/SimulateTransaction", "/sui.rpc.v2.SignatureVerificationService/VerifySignature",
            "/sui.rpc.v2alpha.ProofService/GetCheckpointObjectProof",      "/sui.rpc.v2.LedgerService/ListCheckpoints",
            "/sui.rpc.v2.LedgerService/ListTransactions",                  "/sui.rpc.v2.LedgerService/ListEvents",
            "/sui.rpc.v2.LedgerService/NoSuchMethod",                      "/grpc.health.v1.Health/Check",
        }) |path| {
            try d.check(path, "");
            try d.check(path, "\x0a\x040x05");
        }
        d.round();
    }
    // the edge's floor above the core's: history under it is the core's, and equal
    {
        const floor = first + count / 2;
        edge_svc.lowest_checkpoint = floor;
        defer edge_svc.lowest_checkpoint = first;
        const before = f.metrics.methods[@intFromEnum(route.Method.get_checkpoint)].forwarded[@intFromEnum(route.Reason.below_floor)].load(.monotonic);
        for (0..count) |c| {
            try d.check(p_checkpoint, try rq.checkpoint(first + c, null, "sequence_number,digest,summary,contents"));
            d.round();
        }
        var i: usize = 0;
        while (i < win.txs.items.len) : (i += stride * 4) {
            try d.check(p_tx, try rq.tx(&win.txs.items[i].digest, "digest,transaction,checkpoint"));
            d.round();
        }
        const after = f.metrics.methods[@intFromEnum(route.Method.get_checkpoint)].forwarded[@intFromEnum(route.Reason.below_floor)].load(.monotonic);
        try testing.expectEqual(@as(u64, count / 2), after - before);
        // GetServiceInfo still reports the core's lowest checkpoint: what a client can ask for
        try d.check(p_info, "");
    }

    const diff_total = d.total;
    const diff_differences = d.differences;

    // ---- the guard: an edge behind its core answers nothing itself, and its streams close
    {
        var hub = serve.subscribe.Hub.init(testing.allocator, io, &edge_svc);
        edge_svc.hub = &hub;
        try hub.start();
        const front = try Rpc.start(f.handler());
        defer {
            front.stop();
            hub.stop();
            edge_svc.hub = null;
            hub.deinit();
        }
        // a local SubscribeCheckpoints stream is open when the edge falls behind
        const Trip = struct {
            fwd: *forward.Forwarder,
            hub: *serve.subscribe.Hub,
            done: bool = false,
            fn tick(ctx: *anyopaque) bool {
                const t: *@This() = @ptrCast(@alignCast(ctx));
                if (t.done) return false;
                if (t.hub.stats.subscribers.load(.monotonic) == 0) return true; // not admitted yet
                t.fwd.observe(h2.meta.monoNs(), .{ .lag = 40, .source_age_ns = 0 });
                t.done = true;
                return false;
            }
        };
        var trip: Trip = .{ .fwd = f, .hub = &hub };
        const sub = try loopback.call(d.arena.allocator(), io, front.port, "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", &.{}, &.{""}, .{ .idle_ms = 4000, .tick = .{ .ctx = &trip, .f = Trip.tick } });
        try testing.expect(trip.done);
        try testing.expect(sub.ended);
        var status: []const u8 = "";
        for (sub.trailers.items) |kv| if (std.mem.eql(u8, kv[0], "grpc-status")) {
            status = kv[1];
        };
        try testing.expectEqualStrings("14", status);
        try testing.expectEqual(route.GuardState.tripped, f.guardState());
        try testing.expectEqual(@as(u64, 1), f.metrics.streams_closed.load(.monotonic));
        // tripped: everything is the core's answer, the locally answerable too
        const local_before = f.metrics.methods[@intFromEnum(route.Method.get_checkpoint)].served_local.load(.monotonic);
        for (0..@min(count, 6)) |c| {
            try d.check(p_checkpoint, try rq.checkpoint(first + c, null, "sequence_number,digest,summary"));
            try d.check(p_info, "");
            d.round();
        }
        if (win.outs.items.len > 0) try d.check(p_object, try rq.object(&win.outs.items[0].id, null, "*"));
        try testing.expectEqual(local_before, f.metrics.methods[@intFromEnum(route.Method.get_checkpoint)].served_local.load(.monotonic));
        // back within the limit, after the hold: local again
        f.observe(h2.meta.monoNs(), .{ .lag = 1, .source_age_ns = 0 });
        fx.sleepMs(25);
        f.observe(h2.meta.monoNs(), .{ .lag = 1, .source_age_ns = 0 });
        try testing.expectEqual(route.GuardState.ok, f.guardState());
        try d.check(p_checkpoint, try rq.checkpoint(tip, null, "sequence_number,digest,summary"));
        try testing.expectEqual(local_before + 1, f.metrics.methods[@intFromEnum(route.Method.get_checkpoint)].served_local.load(.monotonic));
    }

    // ---- read-after-write, mode `reads`: a read of what a pending transaction wrote waits for
    // the edge to apply it, and the answer the edge then gives itself is the core's.
    // The next corpus checkpoint plays the executed transactions: its transactions are recorded
    // as an execute through the edge records them (digest and written object ids), the core
    // checkpoints it 200 ms later, and the edge gets it from the feed.
    {
        try f.start();
        const next = first + count;
        var scratch = std.heap.ArenaAllocator.init(testing.allocator);
        defer scratch.deinit();
        const sa = scratch.allocator();
        const ops_dir = try fx.corpusDir("vectors/store-replay/ops");
        defer ops_dir.close(io);
        const blob = try fx.readSeq(sa, w.core.chk, next, ".chk");
        const ops_bytes = try fx.readSeq(sa, ops_dir, next, ".ops");
        const cp = try store.ops.parse(sa, ops_bytes, blob);
        const now = h2.meta.monoNs();
        var written: std.ArrayList([32]u8) = .empty;
        var recorded: u32 = 0;
        for (cp.txs) |t| {
            var ids: std.ArrayList([32]u8) = .empty;
            for (t.puts) |p| try ids.append(sa, p.id.*);
            if (ids.items.len == 0) continue;
            try testing.expect(f.pending.addWrites(t.digest, now, now + 5 * std.time.ns_per_s, .{ .objects = ids.items }));
            try written.appendSlice(sa, ids.items);
            recorded += 1;
        }
        try testing.expect(written.items.len > 0);
        const Later = struct {
            st: *store.Store,
            win: *Window,
            blob: []const u8,
            ops: []const u8,
            failed: bool = false,
            fn run(l: *@This()) void {
                fx.sleepMs(200);
                var arena = std.heap.ArenaAllocator.init(sys);
                defer arena.deinit();
                var idx = types.index.CheckpointIndex.init(sys) catch {
                    l.failed = true;
                    return;
                };
                defer idx.deinit(sys);
                storeFull(l.st, arena.allocator(), l.win, l.blob, l.ops, &idx) catch {
                    l.failed = true;
                };
            }
        };
        var later: Later = .{ .st = w.core.st, .win = &win, .blob = blob, .ops = ops_bytes };
        const local_before = f.metrics.methods[@intFromEnum(route.Method.get_object)].served_local.load(.monotonic);
        const waits_before = f.metrics.raw_read_wait.n.load(.monotonic);
        const t0 = h2.meta.monoNs();
        var th = try std.Thread.spawn(.{}, Later.run, .{&later});
        var asked: u32 = 0;
        var ok: u32 = 0;
        var first_ms: u64 = 0;
        const step = @max(1, written.items.len / 12);
        var i: usize = 0;
        while (i < written.items.len) : (i += step) {
            const body = try rq.object(&written.items[i], null, "object_id,version,digest,owner,object_type,bcs");
            // the edge first: it waits for its follower; then the core, which has checkpointed it
            const got = try loopback.unary(d.arena.allocator(), d.edge_h, p_object, body);
            if (asked == 0) first_ms = (h2.meta.monoNs() - t0) / ms;
            const want = try loopback.unary(d.arena.allocator(), d.core_h, p_object, body);
            asked += 1;
            if (want.status == 0) ok += 1;
            if (!sameReply(want, got)) {
                std.debug.print("edge-forward read-after-write DIFFERENCE object {x}: core status {d}, edge status {d}\n", .{ &written.items[i], want.status, got.status });
                return error.ReadAfterWaitDiffers;
            }
            d.round();
        }
        th.join();
        try testing.expect(!later.failed);
        w.core.have = next;
        // a batch of them, after the fact: local and equal
        try d.check(p_objects, try rq.objects(win.outs.items[win.outs.items.len - @min(8, win.outs.items.len) ..], false, "object_id,version,digest"));
        const local_after = f.metrics.methods[@intFromEnum(route.Method.get_object)].served_local.load(.monotonic);
        const waited = f.metrics.raw_read_wait.n.load(.monotonic) - waits_before;
        std.debug.print("edge-forward read-after-write: {d} transactions of checkpoint {d} recorded as pending ({d} written objects); the first read waited {d} ms for the edge to apply it; {d} reads asked, {d} answered OK by the core, {d} served by the edge itself after the wait, {d} reads waited, 0 differences\n", .{ recorded, next, written.items.len, first_ms, asked, ok, local_after - local_before, waited });
        try testing.expect(first_ms >= 150);
        try testing.expect(waited >= 1);
        try testing.expect(ok > 0 and local_after - local_before >= ok);
        var settle: u32 = 0;
        while (!f.pending.idle() and settle < 2000) : (settle += 10) fx.sleepMs(10);
        try testing.expect(f.pending.idle());
    }

    // ---- the report
    var local_total: u64 = 0;
    var fwd_total: u64 = 0;
    var by_reason: [route.Reason.count]u64 = @splat(0);
    std.debug.print("edge-forward conformance by method (served locally / forwarded by reason):\n", .{});
    for (route.paths) |pe| {
        const pm = &f.metrics.methods[@intFromEnum(pe.method)];
        const l = pm.served_local.load(.monotonic);
        var fw: u64 = 0;
        var line: [400]u8 = undefined;
        var lw: Io.Writer = .fixed(&line);
        inline for (comptime std.meta.fieldNames(route.Reason), 0..) |name, i| {
            const n = pm.forwarded[i].load(.monotonic);
            fw += n;
            by_reason[i] += n;
            if (n > 0) lw.print(" {s}={d}", .{ name, n }) catch {};
        }
        if (l + fw == 0) continue;
        local_total += l;
        fwd_total += fw;
        std.debug.print("  {s}: local {d}, forwarded {d}{s}\n", .{ pe.path, l, fw, lw.buffered() });
    }
    std.debug.print("edge-forward conformance: {d} requests in the diff, {d} differences; with the guard cases {d} requests, {d} differences; routed calls: {d} served locally, {d} forwarded (", .{ diff_total, diff_differences, d.total, d.differences, local_total, fwd_total });
    inline for (comptime std.meta.fieldNames(route.Reason), 0..) |name, i| std.debug.print("{s}{s} {d}", .{ if (i == 0) "" else ", ", name, by_reason[i] });
    std.debug.print(")\n", .{});
    std.debug.print("edge-forward diff by routing outcome (requests / of which the core answered with a success):\n  served locally: {d} / {d}\n", .{ d.asked[0], d.core_ok[0] });
    inline for (comptime std.meta.fieldNames(route.Reason), 0..) |name, i| {
        if (d.asked[1 + i] > 0) std.debug.print("  forwarded {s}: {d} / {d}\n", .{ name, d.asked[1 + i], d.core_ok[1 + i] });
    }
    std.debug.print("  the edge's own paths (not routed): {d}\n", .{d.unrouted});
    inline for (comptime std.meta.fieldNames(route.Reason), 0..) |name, i| {
        if (d.asked[1 + i] > 0 and d.core_ok[1 + i] == 0) std.debug.print("edge-forward: reason {s}: the core answered none of its {d} requests with a success here; only status, message and details were compared for it\n", .{ name, d.asked[1 + i] });
    }
    try testing.expectEqual(@as(u64, 0), d.differences);
    // the comparisons that carry data must stay comparisons of data: local answers, and the
    // read-set forwards of transactions
    try testing.expect(d.core_ok[0] * 10 >= d.asked[0] * 9);
    try testing.expect(d.core_ok[1 + @intFromEnum(route.Reason.needs_read_sets)] > 0);
    try testing.expect(d.core_ok[1 + @intFromEnum(route.Reason.negative)] > 0);
    // every rule was reached
    try testing.expect(local_total > 0);
    inline for (.{ route.Reason.policy, route.Reason.below_floor, route.Reason.ahead, route.Reason.negative, route.Reason.needs_read_sets, route.Reason.lag_guard, route.Reason.list_paging }) |r| {
        if (by_reason[@intFromEnum(r)] == 0) {
            std.debug.print("edge-forward: no request was forwarded for reason {s}\n", .{@tagName(r)});
            return error.RuleNotExercised;
        }
    }
}
