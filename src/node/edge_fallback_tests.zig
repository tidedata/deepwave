//! Unit tests of the edge fallback (`--edge-fallback`, docs/EDGE.md section 10; source.zig
//! `EdgeFallback`, edge/fallback.zig).
//!
//! The edge under test is the node's own fetch path, built the way node.zig builds it: the core
//! pool, the fallback switch and its prober, the fetch-ahead stage, the follower and a store. The
//! core is the real zui/1 listener and dispatcher over a store of corpus checkpoints, on
//! loopback. Between them sits `Link`, a UDP relay that can go silent (a dead box, a cut link):
//! that is the failure no listener stop can show, because a stopping listener says goodbye.
//! The fallback is a directory, either of archive protos (what the bucket serves) or of blobs.
//! Everything needs the corpus (`$ZUI_CORPUS`) and skips without it.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const Atomic = std.atomic.Value;
const store = @import("store");
const types = @import("types");
const bcs = @import("bcs");
const sync = @import("sync");
const net = @import("net");
const native = @import("native");
const serve = @import("serve");
const edge = @import("edge");
const checkpoint = @import("checkpoint");
const trust = @import("trust.zig");
const source_mod = @import("source.zig");
const node_mod = @import("node.zig");

const io = testing.io;
const Mode = edge.fallback.Mode;
const Reason = edge.fallback.Reason;
const ms: u64 = std.time.ns_per_ms;

/// First checkpoint of the corpus' consecutive run (epoch 1303), in `chk/` and `binpb-done/`.
const first: u64 = 342446161;
const epoch: u64 = 1303;

/// Short rules for the tests that only need the order of events, not the default numbers.
const quick: edge.fallback.Tuning = .{ .fail_after_ms = 400, .behind_after_ms = 400, .behind_check_ms = 100, .probe_ms = 100, .probe_reply_ms = 150, .probe_timeout_ms = 300, .probe_idle_ms = 200, .back_after_ms = 500, .flap_window_ms = 60_000, .back_max_ms = 8_000, .retry_ms = 20 };

fn corpus() ![]const u8 {
    const p = std.c.getenv("ZUI_CORPUS") orelse return error.SkipZigTest;
    return std.mem.span(p);
}

fn corpusDir(sub: []const u8) !Io.Dir {
    var pb: [512]u8 = undefined;
    return Io.Dir.cwd().openDir(io, try std.fmt.bufPrint(&pb, "{s}/{s}", .{ try corpus(), sub }), .{}) catch return error.SkipZigTest;
}

fn readSeq(a: std.mem.Allocator, dir: Io.Dir, seq: u64, ext: []const u8) ![]u8 {
    var nb: [64]u8 = undefined;
    return dir.readFileAlloc(io, try std.fmt.bufPrint(&nb, "{d}{s}", .{ seq, ext }), a, .limited(1 << 30)) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
}

/// The committee of `epoch`, from the end-of-epoch checkpoint before it (the test's trust root).
fn committee(a: std.mem.Allocator) !sync.Committee {
    var pb: [512]u8 = undefined;
    const idx = trust.EpochIndex.load(a, io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{try corpus()})) catch return error.SkipZigTest;
    const eoe = idx.last[epoch - 1] orelse return error.SkipZigTest;
    const chk = try corpusDir("chk");
    defer chk.close(io);
    const blob = try readSeq(a, chk, eoe, ".chk");
    const cert = try trust.blobCert(blob);
    const s = try checkpoint.Summary.parse(cert.summary);
    const cm = try checkpoint.nextCommittee(a, s);
    const info = try trust.EpochInfo.fromCheckpoint(a, &cm, s.next_protocol_version);
    return info.syncCommittee(a);
}

fn nowNs() u64 {
    return edge.fallback.nowNs(io);
}

fn sleepMs(n: u64) void {
    io.sleep(.fromMilliseconds(@intCast(n)), .awake) catch {};
}

const store_cfg: store.Config = .{
    .retention_epochs = 2,
    .max_live_objects = 1 << 17,
    .max_object_versions = 1 << 19,
    .max_transactions = 1 << 17,
    .max_checkpoints = 1 << 12,
    .max_batch_bytes = 128 << 20,
    .max_batch_objects = 1 << 17,
    .max_segments = 256,
    .segment_reserve = 1 << 28,
};

// ------------------------------------------------------------------ the link

/// A UDP relay on loopback between the edge and the core. `down`: every datagram is dropped,
/// both ways (a box that died without a word). The core's port can change (a restarted core).
const Link = struct {
    front: Io.net.Socket,
    fus: net.udpio.Sock,
    core_port: Atomic(u16) = .init(0),
    down: Atomic(bool) = .init(false),
    stopping: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    clients: [96]Client = @splat(.{}),
    rx: net.udpio.RxBatch = .{},
    tx: net.udpio.TxBatch = .{},

    const Client = struct {
        used: bool = false,
        addr: Io.net.IpAddress = undefined,
        sock: Io.net.Socket = undefined,
        us: net.udpio.Sock = undefined,
        last: u64 = 0,
    };

    fn create(gpa: std.mem.Allocator) !*Link {
        const l = try gpa.create(Link);
        errdefer gpa.destroy(l);
        var lo: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
        const sock = try Io.net.IpAddress.bind(&lo, io, .{ .mode = .dgram });
        l.* = .{ .front = sock, .fus = .init(sock.handle) };
        l.thread = try std.Thread.spawn(.{}, run, .{l});
        return l;
    }

    fn destroy(l: *Link, gpa: std.mem.Allocator) void {
        l.stopping.store(true, .release);
        if (l.thread) |t| t.join();
        for (&l.clients) |*c| if (c.used) c.sock.close(io);
        l.front.close(io);
        gpa.destroy(l);
    }

    /// What the edge dials.
    fn spec(l: *const Link, key: [32]u8) edge.client.Spec {
        return .{ .addr = .{ .ip4 = Io.net.Ip4Address.loopback(l.front.address.getPort()) }, .key = key };
    }

    fn same(a: *const Io.net.IpAddress, b: *const Io.net.IpAddress) bool {
        return a.* == .ip4 and b.* == .ip4 and a.ip4.port == b.ip4.port and std.mem.eql(u8, &a.ip4.bytes, &b.ip4.bytes);
    }

    fn clientFor(l: *Link, from: *const Io.net.IpAddress, now: u64) ?*Client {
        var free: ?*Client = null;
        for (&l.clients) |*c| {
            if (c.used and same(&c.addr, from)) return c;
            if (c.used and now -| c.last > 3000 * ms) {
                c.sock.close(io);
                c.used = false;
            }
            if (!c.used and free == null) free = c;
        }
        const c = free orelse return null;
        var lo: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
        const sock = Io.net.IpAddress.bind(&lo, io, .{ .mode = .dgram }) catch return null;
        c.* = .{ .used = true, .addr = from.*, .sock = sock, .us = .init(sock.handle), .last = now };
        return c;
    }

    fn run(l: *Link) void {
        while (!l.stopping.load(.acquire)) {
            var moved: usize = 0;
            const now = nowNs();
            const port = l.core_port.load(.acquire);
            const dropping = l.down.load(.acquire) or port == 0;
            const n = l.rx.recv(&l.fus, false);
            moved += n;
            for (0..n) |i| {
                const from = l.rx.from(i);
                const c = l.clientFor(&from, now) orelse continue;
                c.last = now;
                if (dropping) continue;
                const d = l.rx.data(i);
                const to: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(port) };
                @memcpy(l.tx.slot()[0..d.len], d);
                l.tx.commit(d.len, &to);
                l.tx.flush(&c.us);
            }
            for (&l.clients) |*c| {
                if (!c.used) continue;
                const k = l.rx.recv(&c.us, false);
                moved += k;
                if (dropping) continue;
                for (0..k) |i| {
                    const d = l.rx.data(i);
                    @memcpy(l.tx.slot()[0..d.len], d);
                    l.tx.commit(d.len, &c.addr);
                    if (l.tx.full()) l.tx.flush(&l.fus);
                }
                l.tx.flush(&l.fus);
            }
            if (moved == 0) io.sleep(.fromNanoseconds(200_000), .awake) catch {};
        }
    }
};

// ------------------------------------------------------------------ the core

/// A core: corpus checkpoints in a store, served over zui/1 by the node's listener and
/// dispatcher, with or without the edge feed.
const Core = struct {
    gpa: std.mem.Allocator,
    st: *store.Store,
    sio: *store.RealIo,
    svc: serve.service.Service,
    dicts: native.dicts.Dicts,
    feeder: native.edgefeed.Feeder,
    disp: native.dispatch.Dispatcher,
    cert: native.cert.Cert,
    listener: ?*native.listener.Listener = null,
    chk: Io.Dir,
    /// Highest checkpoint stored (`first - 1`: none).
    have: u64 = first - 1,

    const id_seed: [32]u8 = @splat(9);

    fn key() [32]u8 {
        return (std.crypto.sign.Ed25519.KeyPair.generateDeterministic(id_seed) catch unreachable).public_key.toBytes();
    }

    fn create(gpa: std.mem.Allocator, dir: []const u8) !*Core {
        const c = try gpa.create(Core);
        errdefer gpa.destroy(c);
        var cfg = store_cfg;
        cfg.dir = dir;
        const h = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
        const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        c.* = .{
            .gpa = gpa,
            .st = h.store,
            .sio = h.io,
            .svc = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0) },
            .dicts = native.dicts.Dicts.init(gpa),
            .feeder = undefined,
            .disp = undefined,
            .cert = native.cert.generate(try P256.KeyPair.generateDeterministic(@splat(6)), @splat(1), 1_800_000_000, 14, "zui"),
            .chk = try corpusDir("chk"),
        };
        c.feeder = native.edgefeed.Feeder.init(&c.dicts);
        c.disp = .{ .svc = &c.svc, .dicts = &c.dicts };
        return c;
    }

    fn destroy(c: *Core) void {
        c.stop();
        c.svc.deinit();
        c.dicts.deinit();
        c.st.deinit();
        c.sio.deinit();
        c.chk.close(io);
        c.gpa.destroy(c);
    }

    /// Starts listening (a new port each time). `feed`: with `--edge-feed`.
    fn start(c: *Core, feed: bool) !u16 {
        c.stop();
        c.disp.edge = if (feed) &c.feeder else null;
        const l = try native.listener.Listener.start(c.gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = id_seed, .cert = &c.cert }, &c.disp);
        c.listener = l;
        return l.address().getPort();
    }

    /// Stops listening the way a node does: every client is told (CONNECTION_CLOSE, `shutdown`).
    fn stop(c: *Core) void {
        if (c.listener) |l| l.stop();
        c.listener = null;
    }

    /// Stores corpus checkpoints up to `upto` (inclusive), as the follower would.
    fn advance(c: *Core, upto: u64) !void {
        var arena = std.heap.ArenaAllocator.init(c.gpa);
        defer arena.deinit();
        while (c.have < upto) {
            _ = arena.reset(.retain_capacity);
            const a = arena.allocator();
            const blob = try readSeq(a, c.chk, c.have + 1, ".chk");
            try storeBlob(c.st, a, blob);
            c.have += 1;
        }
    }
};

/// One checkpoint blob into `st`: the checkpoint record, every transaction, the output objects.
fn storeBlob(st: *store.Store, a: std.mem.Allocator, blob: []const u8) !void {
    const cp = try bcs.decode(types.CheckpointData, a, blob[1..]);
    const sum = &cp.checkpoint_summary.data;
    const b = try st.begin(sum.sequence_number, sum.epoch);
    errdefer st.abort(b);
    try b.checkpoint(try bcs.encodeAlloc(@TypeOf(cp.checkpoint_summary), a, &cp.checkpoint_summary), try bcs.encodeAlloc(types.CheckpointContents, a, &cp.checkpoint_contents));
    for (cp.transactions, 0..) |*t, i| {
        const dg: types.ExecutionDigests = switch (cp.checkpoint_contents) {
            .V1 => |v| v.transactions[i],
            .V2 => |v| v.transactions[i].digest,
        };
        const ev: ?[]const u8 = if (t.events) |*e| try bcs.encodeAlloc(types.TransactionEvents, a, e) else null;
        try b.transaction(&dg.transaction.@"0".@"0", &dg.effects.@"0".@"0", try bcs.encodeAlloc(@TypeOf(t.transaction), a, &t.transaction), try bcs.encodeAlloc(types.TransactionEffects, a, &t.effects), ev);
        for (t.output_objects) |*o| {
            const id: [32]u8, const ver: u64 = switch (o.data) {
                .Move => |m| .{ m.contents[0..32].*, m.version.@"0" },
                .Package => |pk| .{ pk.id.@"0".@"0", pk.version.@"0" },
            };
            const raw = try bcs.encodeAlloc(types.Object, a, o);
            const d = store.objectDigest(raw);
            try b.putObject(&id, ver, &d, raw);
        }
    }
    try st.commit(b);
}

// ------------------------------------------------------------------ the bucket

/// The fallback as a directory that fills over time, like the bucket at the tip.
const Bucket = struct {
    dir: Io.Dir,
    chk: Io.Dir,
    have: u64 = first - 1,

    fn publish(b: *Bucket, gpa: std.mem.Allocator, upto: u64) !void {
        var nb: [64]u8 = undefined;
        var tb: [64]u8 = undefined;
        while (b.have < upto) {
            const blob = try readSeq(gpa, b.chk, b.have + 1, ".chk");
            defer gpa.free(blob);
            const tmp = try std.fmt.bufPrint(&tb, ".{d}.part", .{b.have + 1});
            try b.dir.writeFile(io, .{ .sub_path = tmp, .data = blob });
            try b.dir.rename(tmp, b.dir, try std.fmt.bufPrint(&nb, "{d}.chk", .{b.have + 1}), io);
            b.have += 1;
        }
    }
};

// ------------------------------------------------------------------ the edge

const Edge = struct {
    gpa: std.mem.Allocator,
    st: *store.Store,
    sio: *store.RealIo,
    spool: Io.Dir,
    arch: sync.archive.Archive,
    pool: *edge.client.Pool,
    fb: ?*source_mod.EdgeFallback = null,
    prober: ?*edge.fallback.Prober = null,
    src: source_mod.Source,
    fetcher: source_mod.Fetcher,
    follower: *sync.Follower,
    run_thread: ?std.Thread = null,
    run_err: ?anyerror = null,
    /// Sequence numbers in the order the follower applied them.
    seqs: [512]u64 = undefined,
    n: Atomic(usize) = .init(0),

    const Opts = struct {
        /// `<tmp>/<name>` holds the store and the spool.
        root: Io.Dir,
        root_path: []const u8,
        name: []const u8,
        specs: []const edge.client.Spec,
        /// The fallback directory; null: `--edge-fallback off`.
        fallback: ?Io.Dir,
        tuning: edge.fallback.Tuning = quick,
        committee: sync.Committee,
    };

    fn create(gpa: std.mem.Allocator, o: Opts) !*Edge {
        const e = try gpa.create(Edge);
        errdefer gpa.destroy(e);
        var pb: [600]u8 = undefined;
        var cfg = store_cfg;
        cfg.dir = try std.fmt.bufPrint(&pb, "{s}/{s}/store", .{ o.root_path, o.name });
        var sb: [128]u8 = undefined;
        try o.root.createDirPath(io, try std.fmt.bufPrint(&sb, "{s}/spool", .{o.name}));
        const h = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
        const spool = try o.root.openDir(io, try std.fmt.bufPrint(&sb, "{s}/spool", .{o.name}), .{});
        const pool = try edge.client.Pool.init(gpa, io, o.specs, 2);
        e.* = .{
            .gpa = gpa,
            .st = h.store,
            .sio = h.io,
            .spool = spool,
            .arch = .{ .dir = spool },
            .pool = pool,
            .src = .{ .gpa = gpa, .io = io, .kind = .{ .zui1 = pool } },
            .fetcher = undefined,
            .follower = undefined,
        };
        // as node.zig's initEdgeFallback
        if (o.fallback) |dir| {
            const fb = try gpa.create(source_mod.EdgeFallback);
            fb.* = .{ .src = .{ .gpa = gpa, .io = io, .kind = .{ .dir = dir } }, .sw = .{ .t = o.tuning, .log = false } };
            fb.sw.since_ns.store(nowNs(), .monotonic);
            e.fb = fb;
            e.src.edge_fb = fb;
            pool.stall_ms = o.tuning.fail_after_ms;
            e.prober = try edge.fallback.Prober.init(gpa, io, &fb.sw, o.specs, null);
            try e.prober.?.start();
        }
        e.follower = try sync.Follower.init(gpa, io, e.st, .{ .archive = &e.arch }, .{ .mode = .apply, .workers = 2, .window = 8, .poll_ms = 50 }, .{ .committee = o.committee, .first_seq = first });
        e.follower.observer = .{ .ctx = e, .on_checkpoint = onCheckpoint };
        if (e.fb) |fb| fb.applied_next = &e.follower.applied_next;
        e.fetcher = .{
            .gpa = gpa,
            .io = io,
            .source = &e.src,
            .spool = spool,
            .next = .init(first),
            .applied_next = &e.follower.applied_next,
            .window = 16,
            .poll_ms = 10,
            .to = std.math.maxInt(u64),
            // kept: the tests compare the blobs the follower was handed
            .keep = true,
            .on_spooled = .{ .ctx = e.follower, .call = spooled },
        };
        return e;
    }

    fn spooled(ctx: *anyopaque, seq: u64) void {
        const f: *sync.Follower = @ptrCast(@alignCast(ctx));
        f.notify(seq);
    }

    fn onCheckpoint(ctx: *anyopaque, seq: u64, _: *const sync.verify.Checked, _: []const u8) void {
        const e: *Edge = @ptrCast(@alignCast(ctx));
        const i = e.n.load(.monotonic);
        if (i < e.seqs.len) e.seqs[i] = seq;
        e.n.store(i + 1, .release);
    }

    fn follow(e: *Edge) !void {
        try e.fetcher.start(3);
        e.run_thread = try std.Thread.spawn(.{}, runMain, .{e});
    }

    fn runMain(e: *Edge) void {
        e.follower.run(null) catch |err| {
            e.run_err = err;
        };
    }

    /// Checkpoints the store has committed (the follower counts one in `n` before its commit).
    fn committed(e: *Edge) u64 {
        const next = e.follower.applied_next.load(.acquire);
        return next - first;
    }

    fn waitCommitted(e: *Edge, count: u64, limit_ms: u64) bool {
        const t0 = nowNs();
        while (e.committed() < count) {
            if (e.run_err != null or nowNs() - t0 > limit_ms * ms) return false;
            sleepMs(2);
        }
        return true;
    }

    fn waitMode(e: *Edge, m: Mode, limit_ms: u64) bool {
        const t0 = nowNs();
        while (e.fb.?.sw.mode() != m) {
            if (nowNs() - t0 > limit_ms * ms) return false;
            sleepMs(2);
        }
        return true;
    }

    fn stats(e: *Edge) *edge.fallback.Stats {
        return &e.fb.?.sw.stats;
    }

    /// Every checkpoint applied once, in order, from `first`: no gap, no duplicate. Call after
    /// `follower.stop()`.
    fn expectOrdered(e: *Edge, count: u64) !void {
        if (e.run_thread) |t| t.join();
        e.run_thread = null;
        try testing.expectEqual(@as(?anyerror, null), e.run_err);
        try testing.expectEqual(count, @as(u64, e.n.load(.acquire)));
        try e.expectPrefix(count);
        var snap = e.st.snapshot();
        defer snap.release();
        try testing.expectEqual(@as(?u64, first + count - 1), snap.highestCommitted());
    }

    /// The first `count` checkpoints applied are `first..`, each once, in order.
    fn expectPrefix(e: *Edge, count: u64) !void {
        try testing.expect(e.n.load(.acquire) >= count);
        for (e.seqs[0..@intCast(count)], 0..) |s, i| try testing.expectEqual(first + i, s);
    }

    fn destroy(e: *Edge) void {
        e.follower.stop();
        if (e.run_thread) |t| t.join();
        if (e.fb) |fb| fb.stopping.store(true, .release);
        e.fetcher.stop();
        if (e.prober) |p| p.deinit();
        e.follower.deinit();
        if (e.fb) |fb| e.gpa.destroy(fb);
        e.pool.deinit();
        e.st.deinit();
        e.sio.deinit();
        e.spool.close(io);
        e.gpa.destroy(e);
    }
};

/// A core behind a link, a bucket directory and a temporary root: what every test starts from.
const World = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    tmp: testing.TmpDir,
    root_path: []const u8,
    core: *Core,
    link: *Link,
    bucket: Bucket,
    committee: sync.Committee,

    fn init(w: *World) !void {
        const gpa = testing.allocator;
        w.gpa = gpa;
        w.arena = .init(gpa);
        errdefer w.arena.deinit();
        const a = w.arena.allocator();
        w.committee = try committee(a);
        w.tmp = testing.tmpDir(.{});
        errdefer w.tmp.cleanup();
        var pb: [512]u8 = undefined;
        const n = try w.tmp.dir.realPath(io, &pb);
        w.root_path = try a.dupe(u8, pb[0..n]);
        try w.tmp.dir.createDirPath(io, "bucket");
        w.bucket = .{ .dir = try w.tmp.dir.openDir(io, "bucket", .{}), .chk = try corpusDir("chk") };
        w.core = try Core.create(gpa, try std.fmt.allocPrint(a, "{s}/core", .{w.root_path}));
        w.link = try Link.create(gpa);
    }

    fn deinit(w: *World) void {
        w.link.destroy(w.gpa);
        w.core.destroy();
        w.bucket.dir.close(io);
        w.bucket.chk.close(io);
        w.tmp.cleanup();
        w.arena.deinit();
    }

    /// Starts the core and points the link at it.
    fn coreUp(w: *World, feed: bool) !void {
        w.link.core_port.store(try w.core.start(feed), .release);
    }

    /// The same checkpoints on the core and in the bucket, as at the tip.
    fn publish(w: *World, count: u64) !void {
        try w.core.advance(first + count - 1);
        try w.bucket.publish(w.gpa, first + count - 1);
    }

    fn edge_(w: *World, name: []const u8, fallback: bool, tuning: edge.fallback.Tuning) !*Edge {
        const specs = [_]edge.client.Spec{w.link.spec(Core.key())};
        return Edge.create(w.gpa, .{ .root = w.tmp.dir, .root_path = w.root_path, .name = name, .specs = &specs, .fallback = if (fallback) w.bucket.dir else null, .tuning = tuning, .committee = w.committee });
    }
};

// ------------------------------------------------------------------ tests

test "edge fallback: the core goes silent mid-follow; the edge is on the bucket 3 s later, applies every checkpoint once and in order, and is back on the core 5 s after it answers again (default rules)" {
    var w: World = undefined;
    try w.init();
    defer w.deinit();
    try w.coreUp(true);
    const d: edge.fallback.Tuning = .{}; // the shipped numbers: 3 s, probes every second, 5 s
    const e = try w.edge_("edge", true, d);
    defer e.destroy();
    try e.follow();

    // at the tip, on the core
    try w.publish(8);
    try must(e.waitCommitted(8, 20_000), "waitCommitted(8, 20_000)", e);
    try testing.expectEqual(Mode.core, e.fb.?.sw.mode());
    try testing.expectEqual(@as(u64, 0), e.stats().from_fallback.load(.monotonic));
    try testing.expect(e.stats().from_core.load(.monotonic) >= 8);

    // the core's box goes dark; the chain goes on
    w.link.down.store(true, .release);
    const t_down = nowNs();
    try w.publish(16);
    try must(e.waitMode(.fallback, d.fail_after_ms + 2_000), "waitMode(.fallback, d.fail_after_ms + 2_000)", e);
    const fell = e.fb.?.sw.since_ns.load(.monotonic);
    // not before the grace was over, and not long after it
    try testing.expect(fell -| t_down >= (d.fail_after_ms - 150) * ms);
    try testing.expect(fell -| t_down <= (d.fail_after_ms + 1_500) * ms);
    try testing.expectEqual(Reason.silent, e.fb.?.sw.lastReason());
    try must(e.waitCommitted(16, 20_000), "waitCommitted(16, 20_000)", e);
    try testing.expectEqual(@as(u64, 1), e.stats().to_fallback.load(.monotonic));
    try testing.expect(e.stats().from_fallback.load(.monotonic) >= 8);
    // still dark: the edge keeps following from the bucket
    try w.publish(20);
    try must(e.waitCommitted(20, 20_000), "waitCommitted(20, 20_000)", e);
    try testing.expectEqual(Mode.fallback, e.fb.?.sw.mode());

    // the core is back: the edge returns after 5 s of good probes, not at the first one
    w.link.down.store(false, .release);
    const t_up = nowNs();
    try must(e.waitMode(.core, d.back_after_ms + d.probe_ms + 3_000), "waitMode(.core, d.back_after_ms + d.probe_ms + 3_000)", e);
    try testing.expect(nowNs() - t_up >= d.back_after_ms * ms);
    try testing.expectEqual(@as(u64, 1), e.stats().to_core.load(.monotonic));
    const from_fb = e.stats().from_fallback.load(.monotonic);
    const from_core = e.stats().from_core.load(.monotonic);
    try w.publish(28);
    try must(e.waitCommitted(28, 20_000), "waitCommitted(28, 20_000)", e);
    try testing.expectEqual(from_fb, e.stats().from_fallback.load(.monotonic));
    try testing.expect(e.stats().from_core.load(.monotonic) >= from_core + 8);
    try testing.expectEqual(@as(u64, 1), e.stats().to_fallback.load(.monotonic));

    e.follower.stop();
    try e.expectOrdered(28);
}

test "edge fallback: an edge starts with no core reachable, finds the tip and follows from the bucket, then attaches to the core when it appears" {
    var w: World = undefined;
    try w.init();
    defer w.deinit();
    // no core at all yet: the link has nowhere to send
    try w.bucket.publish(w.gpa, first + 9);
    const e = try w.edge_("edge", true, quick);
    defer e.destroy();
    // start-up: the tip search and the first checkpoint read (node.zig computeAnchor,
    // newestSnapshotEpoch) go through the same source and must not fail
    const t0 = nowNs();
    try testing.expectEqual(first + 9, try e.src.latest(first));
    try testing.expect(nowNs() - t0 >= (quick.fail_after_ms - 100) * ms);
    try testing.expectEqual(Mode.fallback, e.fb.?.sw.mode());
    var sc = source_mod.Scratch.init(w.gpa);
    defer sc.deinit(w.gpa);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(w.gpa);
    try testing.expectEqual(source_mod.Result.ok, try e.src.fetch(&sc, first + 9, &buf));
    try testing.expectEqual(first + 9, (try checkpoint.Summary.parse((try trust.blobCert(buf.items)).summary)).sequence_number);

    try e.follow();
    try must(e.waitCommitted(10, 20_000), "waitCommitted(10, 20_000)", e);
    try testing.expectEqual(@as(u64, 0), e.stats().from_core.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), e.stats().to_fallback.load(.monotonic));

    // the core appears, at the edge's height: the edge attaches
    try w.core.advance(first + 9);
    try w.coreUp(true);
    try must(e.waitMode(.core, quick.back_after_ms + 3_000), "waitMode(.core, quick.back_after_ms + 3_000)", e);
    try w.publish(16);
    try must(e.waitCommitted(16, 20_000), "waitCommitted(16, 20_000)", e);
    try testing.expect(e.stats().from_core.load(.monotonic) >= 6);
    try testing.expectEqual(@as(u64, 1), e.stats().to_core.load(.monotonic));
    e.follower.stop();
    try e.expectOrdered(16);
}

test "edge fallback: a core whose hello lacks the feed feature is a fallback at once, not a hard failure; with the fallback off it is today's error" {
    var w: World = undefined;
    try w.init();
    defer w.deinit();
    try w.publish(6);
    try w.coreUp(false); // a core without --edge-feed

    // off: exactly what an edge did before (NoEdgeFeed, surfaced as SourceUnavailable)
    {
        const off = try w.edge_("off", false, quick);
        defer off.destroy();
        try testing.expectError(error.SourceUnavailable, off.src.latest(first));
        var sc = source_mod.Scratch.init(w.gpa);
        defer sc.deinit(w.gpa);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(w.gpa);
        try testing.expectError(error.SourceUnavailable, off.src.fetchRaw(&sc, first, &buf));
    }

    // a long grace, so only the hello's own answer can explain a fast switch
    var slow = quick;
    slow.fail_after_ms = 6_000;
    const e = try w.edge_("edge", true, slow);
    defer e.destroy();
    const t0 = nowNs();
    try testing.expectEqual(first + 5, try e.src.latest(first));
    // the hello is an answer: no grace to wait out
    try testing.expect(nowNs() - t0 < 3_000 * ms);
    try testing.expectEqual(Mode.fallback, e.fb.?.sw.mode());
    try testing.expectEqual(Reason.no_feed, e.fb.?.sw.lastReason());
    try e.follow();
    try must(e.waitCommitted(6, 20_000), "waitCommitted(6, 20_000)", e);
    // probes see the same hello: the edge stays where it is
    sleepMs(quick.back_after_ms + 3 * quick.probe_idle_ms);
    try testing.expectEqual(Mode.fallback, e.fb.?.sw.mode());
    const probes = e.stats().probes.load(.monotonic);
    try testing.expect(probes >= 2);
    // and they are spaced out: a core without the feed is asked every `probe_idle_ms`, not every `probe_ms`
    try testing.expect(probes <= 2 + (quick.back_after_ms + 3 * quick.probe_idle_ms + 2_000) / quick.probe_idle_ms);
    try testing.expectEqual(@as(u64, 0), e.stats().probes_ok.load(.monotonic));

    // the core is restarted with --edge-feed: the edge attaches
    try w.coreUp(true);
    try must(e.waitMode(.core, quick.back_after_ms + 3_000), "waitMode(.core, quick.back_after_ms + 3_000)", e);
    try w.publish(10);
    try must(e.waitCommitted(10, 20_000), "waitCommitted(10, 20_000)", e);
    try testing.expect(e.stats().from_core.load(.monotonic) >= 4);
    e.follower.stop();
    try e.expectOrdered(10);
}

test "edge fallback: a core that says it is shutting down is left at once; a core that falls behind is left when the bucket has the checkpoint" {
    var w: World = undefined;
    try w.init();
    defer w.deinit();
    try w.coreUp(true);
    // a long grace, so only the shutdown notice can explain a fast switch
    var slow = quick;
    slow.fail_after_ms = 6_000;
    const e = try w.edge_("edge", true, slow);
    defer e.destroy();
    try e.follow();
    try w.publish(6);
    try must(e.waitCommitted(6, 20_000), "waitCommitted(6, 20_000)", e);
    try testing.expectEqual(Mode.core, e.fb.?.sw.mode());

    // a restart: the listener stops and tells its clients
    w.core.stop();
    try w.bucket.publish(w.gpa, first + 9);
    try must(e.waitMode(.fallback, 2_000), "waitMode(.fallback, 2_000)", e);
    try testing.expectEqual(Reason.shutdown, e.fb.?.sw.lastReason());
    try must(e.waitCommitted(10, 20_000), "waitCommitted(10, 20_000)", e);

    // it comes back, but without the checkpoints it missed: not at or ahead of the edge
    try w.coreUp(true);
    sleepMs(slow.back_after_ms + 5 * slow.probe_ms);
    try testing.expectEqual(Mode.fallback, e.fb.?.sw.mode());
    try testing.expectEqual(@as(u64, 0), e.stats().to_core.load(.monotonic));
    // caught up: the edge returns
    try w.core.advance(first + 9);
    try must(e.waitMode(.core, slow.back_after_ms + 3_000), "waitMode(.core, slow.back_after_ms + 3_000)", e);

    // then the core stops advancing (alive, answering "not held") while the bucket goes on
    try w.bucket.publish(w.gpa, first + 13);
    try must(e.waitMode(.fallback, slow.behind_after_ms + 3_000), "waitMode(.fallback, slow.behind_after_ms + 3_000)", e);
    try testing.expectEqual(Reason.behind, e.fb.?.sw.lastReason());
    try must(e.waitCommitted(14, 20_000), "waitCommitted(14, 20_000)", e);
    try testing.expect(e.stats().behind_checks.load(.monotonic) >= 1);
    e.follower.stop();
    try e.expectOrdered(14);
}

/// `ok`, or the test fails saying where the edge stood (a bare expect would only give a line
/// number, and the test runner's trace is full of other tests' handled errors).
fn must(ok: bool, comptime what: []const u8, e: *Edge) !void {
    if (ok) return;
    const fb = e.fb orelse {
        std.debug.print("edge fallback test: {s} FAILED: no fallback, {d} committed, follower error {any}\n", .{ what, e.committed(), e.run_err });
        return error.TestUnexpectedResult;
    };
    const st = &fb.sw.stats;
    std.debug.print("edge fallback test: {s} FAILED: source {s}, {d} falls (last: {s}), {d} returns, next return after {d} ms, {d} committed, {d} from the cores, {d} from the fallback, {d} probes ({d} good), follower error {any}\n", .{
        what,                          @tagName(fb.sw.mode()),            st.to_fallback.load(.monotonic), @tagName(fb.sw.lastReason()),  st.to_core.load(.monotonic), fb.sw.backAfterMs(), e.committed(),
        st.from_core.load(.monotonic), st.from_fallback.load(.monotonic), st.probes.load(.monotonic),      st.probes_ok.load(.monotonic), e.run_err,
    });
    return error.TestUnexpectedResult;
}

test "edge fallback: a core that is up and down faster than the rules never gets the edge back; one that just outlasts them gets it back once, then waits double" {
    var w: World = undefined;
    try w.init();
    defer w.deinit();
    try w.coreUp(true);
    // 800 ms of grace, probes every 100 ms answered within 150 ms, 500 ms of good probes to return
    var t = quick;
    t.fail_after_ms = 800;
    const e = try w.edge_("edge", true, t);
    defer e.destroy();
    try e.follow();
    try w.publish(4);
    try must(e.waitCommitted(4, 20_000), "the first checkpoints", e);

    // short outages well inside the grace (100 ms of 800): no switch at all
    for (0..4) |_| {
        w.link.down.store(true, .release);
        sleepMs(100);
        w.link.down.store(false, .release);
        sleepMs(300);
    }
    try must(e.stats().to_fallback.load(.monotonic) == 0 and e.fb.?.sw.mode() == .core, "no switch for outages inside the grace", e);

    // a real outage: one switch
    w.link.down.store(true, .release);
    try must(e.waitMode(.fallback, t.fail_after_ms + 2_000), "a switch for an outage past the grace", e);
    // 6 s of a core that is up 300 ms and down 450 ms (8 times), the chain moving all the
    // while. Every outage is longer than a probe and its reply time (250 ms), so each one fails
    // a probe, and the return needs 500 ms of good probes in a row: there is none.
    var published: u64 = 4;
    for (0..8) |_| {
        w.link.down.store(false, .release);
        sleepMs(300);
        w.link.down.store(true, .release);
        published += 1;
        try w.publish(published);
        sleepMs(450);
    }
    try must(e.waitCommitted(published, 20_000), "following from the bucket through the flaps", e);
    try must(e.fb.?.sw.mode() == .fallback and e.stats().to_fallback.load(.monotonic) == 1 and e.stats().to_core.load(.monotonic) == 0, "no return to a core that never holds for 500 ms", e);

    // a core that is up 900 ms and down 1200 ms outlasts both rules: it gets the edge back
    // once (500 ms of good probes), loses it again (800 ms), and from then on must hold 1 s,
    // then 2 s: no more returns
    for (0..4) |_| {
        w.link.down.store(false, .release);
        sleepMs(900);
        w.link.down.store(true, .release);
        published += 1;
        try w.publish(published);
        sleepMs(1_200);
    }
    try must(e.waitCommitted(published, 20_000), "following through the slow flaps", e);
    try must(e.stats().to_core.load(.monotonic) <= 2 and e.stats().to_fallback.load(.monotonic) <= 3, "at most one more return than the damping allows", e);
    // every fall after a return made the next return wait longer
    if (e.stats().to_fallback.load(.monotonic) >= 2) try must(e.fb.?.sw.backAfterMs() >= 2 * t.back_after_ms, "a doubled wait after a fall that followed a return", e);

    // steady again: the edge comes home, whatever the wait has grown to
    w.link.down.store(false, .release);
    try must(e.waitMode(.core, t.back_max_ms + 4_000), "the return to a steady core", e);
    published += 2;
    try w.publish(published);
    try must(e.waitCommitted(published, 20_000), "following from the core again", e);
    e.follower.stop();
    try e.expectOrdered(published);
}

/// The feed a node would serve of `seq` from `st` (every stored part of the checkpoint: the
/// certified summary, contents, each envelope, effects, events and output object).
fn servedFeed(a: std.mem.Allocator, st: *store.Store, seq: u64) ![]const u8 {
    var snap = st.snapshot();
    defer snap.release();
    var out: std.ArrayList(u8) = .empty;
    try testing.expect(try native.edgefeed.assemble(a, &snap, seq, &out));
    return out.items;
}

/// The whole zui/1 response to `get_checkpoint` with every part asked for, from `st`.
fn servedCheckpoint(a: std.mem.Allocator, st: *store.Store, seq: u64) ![]const u8 {
    var svc: serve.service.Service = .{ .gpa = testing.allocator, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    var disp: native.dispatch.Dispatcher = .{ .svc = &svc };
    var body: std.ArrayList(u8) = .empty;
    const w: native.proto.W = .{ .gpa = a, .out = &body };
    try w.uleb(1);
    try w.int(u64, seq);
    try w.u8_(native.proto.part_contents | native.proto.part_tx | native.proto.part_effects | native.proto.part_events);
    var out: std.ArrayList(u8) = .empty;
    disp.handle(a, .{ .method = .get_checkpoint, .flags = 0, .body = body.items }, null, &out);
    return out.items;
}

test "edge fallback: the same checkpoints through the feed, through the bucket's archive protos and through blobs give the same blobs to the follower, the same stored records and the same served bytes" {
    var w: World = undefined;
    try w.init();
    defer w.deinit();
    const count: u64 = 24;
    try w.core.advance(first + count - 1);
    try w.coreUp(true);
    const a = w.arena.allocator();

    // A: the feed only (fallback off, the edge of today)
    const ea = try w.edge_("feed", false, quick);
    defer ea.destroy();
    try ea.follow();
    try must(ea.waitCommitted(count, 60_000), "waitCommitted(count, 60_000)", ea);
    ea.follower.stop();
    try ea.expectOrdered(count);

    // no core from here on: B and C can only use their fallback
    w.core.stop();
    w.link.core_port.store(0, .release);

    // B: the bucket's own format (`<seq>.binpb.zst`, converted, then put in feed form)
    const protos = try corpusDir("binpb-done");
    defer protos.close(io);
    const specs = [_]edge.client.Spec{w.link.spec(Core.key())};
    const eb = try Edge.create(w.gpa, .{ .root = w.tmp.dir, .root_path = w.root_path, .name = "protos", .specs = &specs, .fallback = protos, .committee = w.committee });
    defer eb.destroy();
    try eb.follow();
    try must(eb.waitCommitted(count, 60_000), "waitCommitted(count, 60_000)", eb);
    eb.follower.stop();
    // (the directory holds the corpus' whole run: the edge went on past `count`)
    try eb.expectPrefix(count);
    try testing.expect(eb.stats().from_fallback.load(.monotonic) >= count);
    try testing.expectEqual(@as(u64, 0), eb.stats().from_core.load(.monotonic));

    // C: full blobs (`<seq>.chk` with their input objects)
    try w.bucket.publish(w.gpa, first + count - 1);
    const ec = try w.edge_("blobs", true, quick);
    defer ec.destroy();
    try ec.follow();
    try must(ec.waitCommitted(count, 60_000), "waitCommitted(count, 60_000)", ec);
    ec.follower.stop();
    try ec.expectOrdered(count);

    var nb: [64]u8 = undefined;
    var with_inputs: u64 = 0;
    for (0..count) |i| {
        const seq = first + i;
        // what the follower was handed: byte for byte the same file, and no aux record
        const name = try std.fmt.bufPrint(&nb, "{d}.chk", .{seq});
        const ba = try ea.spool.readFileAlloc(io, name, a, .limited(1 << 30));
        const bb = try eb.spool.readFileAlloc(io, name, a, .limited(1 << 30));
        const bc = try ec.spool.readFileAlloc(io, name, a, .limited(1 << 30));
        try testing.expectEqualSlices(u8, ba, bb);
        try testing.expectEqualSlices(u8, ba, bc);
        const full = try readSeq(a, w.bucket.chk, seq, ".chk");
        if (full.len != ba.len) with_inputs += 1;
        const aux = try std.fmt.bufPrint(&nb, "{d}.aux", .{seq});
        inline for (.{ ea, eb, ec }) |e| try testing.expectError(error.FileNotFound, e.spool.statFile(io, aux, .{}));
        // what each edge stored and serves: the feed of the checkpoint (every record) and the
        // whole get_checkpoint response
        const fa = try servedFeed(a, ea.st, seq);
        try testing.expectEqualSlices(u8, fa, try servedFeed(a, eb.st, seq));
        try testing.expectEqualSlices(u8, fa, try servedFeed(a, ec.st, seq));
        // and it is what the core serves
        try testing.expectEqualSlices(u8, fa, try servedFeed(a, w.core.st, seq));
        const ca = try servedCheckpoint(a, ea.st, seq);
        try testing.expect(ca.len > 64);
        try testing.expectEqualSlices(u8, ca, try servedCheckpoint(a, eb.st, seq));
        try testing.expectEqualSlices(u8, ca, try servedCheckpoint(a, ec.st, seq));
    }
    // the fallback really did carry more than the feed (input objects), and they were dropped
    try testing.expect(with_inputs > 0);
}

test "edge fallback: feedForm of a full blob is the blob a feed of it rebuilds to, and of a feed-form blob is itself" {
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const chk = try corpusDir("chk");
    defer chk.close(io);
    var sc = source_mod.Scratch.init(gpa);
    defer sc.deinit(gpa);
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var reordered: usize = 0;
    for ([_]u64{ first, first + 1, first + 2, first + 3, 342086715 }) |seq| {
        const blob = try readSeq(a, chk, seq, ".chk");
        // the feed a core builds, through the wire, rebuilt (edge-feed suite, edge/conformance.zig)
        try types.indexCheckpointData(blob, &idx);
        // as edgefeed.assemble does: each transaction's output objects in the order of its
        // effects' references, found by (id, version)
        const txs = try a.alloc(edge_wire.feed.TxIn, idx.tx_count);
        var refs: std.ArrayList(checkpoint.objects.OutRef) = .empty;
        for (txs, 0..) |*t, i| {
            const x = idx.txAt(i);
            const outs = idx.objs[x.out_first..][0..x.out_count];
            refs.clearRetainingCapacity();
            try edge_wire.feed.outputRefs(a, x.effects.slice(blob), &refs);
            try testing.expectEqual(outs.len, refs.items.len);
            const objs = try a.alloc([]const u8, x.out_count);
            for (objs, refs.items, 0..) |*o, *ref, k| {
                const j = for (outs, 0..) |r, j| {
                    if (std.mem.eql(u8, &(checkpoint.objects.outputRef(r.slice(blob)).?), ref)) break j;
                } else return error.TestUnexpectedResult;
                if (j != k) reordered += 1;
                o.* = outs[j].slice(blob);
            }
            t.* = .{ .tx = x.transaction.slice(blob), .effects = x.effects.slice(blob), .events = if (x.events) |ev| ev.slice(blob) else null, .objects = objs };
        }
        var raw: std.ArrayList(u8) = .empty;
        try edge_wire.feed.encode(&raw, a, seq, blob[idx.summary.o .. idx.sig.o + idx.sig.n], idx.contents.slice(blob), txs);
        var f = try edge_wire.feed.decode(a, raw.items);
        var want: std.ArrayList(u8) = .empty;
        try edge_wire.feed.toBlob(&want, a, &f);

        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try out.appendSlice(gpa, blob);
        try sc.aux.appendSlice(gpa, "stale aux");
        try source_mod.feedForm(gpa, &sc, &out);
        try testing.expectEqualSlices(u8, want.items, out.items);
        try testing.expectEqual(@as(usize, 0), sc.aux.items.len);
        try testing.expect(out.items.len < blob.len);

        // idempotent
        try source_mod.feedForm(gpa, &sc, &out);
        try testing.expectEqualSlices(u8, want.items, out.items);
    }
    // the archive's order is not the effects' order: without the reordering the two ways in
    // would hand the follower different bytes
    try testing.expect(reordered > 0);
    // bytes that are no checkpoint are bad data, not a crash
    var junk: std.ArrayList(u8) = .empty;
    defer junk.deinit(gpa);
    try junk.appendSlice(gpa, "\x01not a checkpoint");
    try testing.expectError(error.BadData, source_mod.feedForm(gpa, &sc, &junk));
}

const edge_wire = @import("edgewire");

test "edge fallback: off is the edge of before: no switch, no probe, the pool's own timeouts; a silent core is an error at start and a stall mid-follow, and the bucket is never asked" {
    var w: World = undefined;
    try w.init();
    defer w.deinit();
    try w.coreUp(true);
    try w.publish(6);
    w.link.down.store(true, .release);
    const e = try w.edge_("edge", false, quick);
    defer e.destroy();
    try testing.expect(e.src.edge_fb == null);
    try testing.expect(e.prober == null);
    try testing.expectEqual(@as(u64, 0), e.pool.stall_ms);
    try testing.expectEqual(@as(u64, 5_000), e.pool.connect_timeout_ms);
    e.pool.connect_timeout_ms = 200; // the test's patience, not a rule

    // start-up against a silent core: the error an edge gave before (the node does not start)
    var sc = source_mod.Scratch.init(w.gpa);
    defer sc.deinit(w.gpa);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(w.gpa);
    try testing.expectError(error.SourceUnavailable, e.src.latest(first));
    try testing.expectError(error.SourceUnavailable, e.src.exists(first));
    try testing.expectError(error.SourceUnavailable, e.src.fetchRaw(&sc, first, &buf));

    w.link.down.store(false, .release);
    try testing.expectEqual(first + 5, try e.src.latest(first));
    try e.follow();
    try must(e.waitCommitted(6, 20_000), "waitCommitted(6, 20_000)", e);

    // the core goes dark mid-follow: the edge stalls, though the bucket has the next checkpoints
    w.link.down.store(true, .release);
    try w.publish(10);
    sleepMs(1_500);
    try testing.expectEqual(@as(u64, 6), e.committed());
    // and resumes by itself when the core answers again
    w.link.down.store(false, .release);
    try must(e.waitCommitted(10, 40_000), "waitCommitted(10, 40_000)", e);
    e.follower.stop();
    try e.expectOrdered(10);
}

test "edge fallback: metrics name the active source and count the switches each way" {
    var sw: edge.fallback.Switch = .{ .log = false };
    var buf: [4096]u8 = undefined;
    {
        var w = std.Io.Writer.fixed(&buf);
        try node_mod.Node.renderEdgeFallback(&w, &sw);
        const text = w.buffered();
        try testing.expect(std.mem.indexOf(u8, text, "zui_edge_source_fallback 0\n") != null);
        try testing.expect(std.mem.indexOf(u8, text, "zui_edge_source{source=\"zui1\"} 1\n") != null);
        try testing.expect(std.mem.indexOf(u8, text, "zui_edge_fallback_switches{to=\"fallback\"} 0\n") != null);
    }
    try testing.expect(sw.coreFailed(10 * std.time.ns_per_s, 5 * std.time.ns_per_s, .silent, 42));
    sw.fetched(.fallback, 42);
    {
        var w = std.Io.Writer.fixed(&buf);
        try node_mod.Node.renderEdgeFallback(&w, &sw);
        const text = w.buffered();
        try testing.expect(std.mem.indexOf(u8, text, "zui_edge_source_fallback 1\n") != null);
        try testing.expect(std.mem.indexOf(u8, text, "zui_edge_source{source=\"fallback\"} 1\n") != null);
        try testing.expect(std.mem.indexOf(u8, text, "zui_edge_fallback_switches{to=\"fallback\"} 1\n") != null);
        try testing.expect(std.mem.indexOf(u8, text, "zui_edge_fallback_switches{to=\"zui1\"} 0\n") != null);
        try testing.expect(std.mem.indexOf(u8, text, "zui_edge_fallback_checkpoints{from=\"fallback\"} 1\n") != null);
        try testing.expect(std.mem.indexOf(u8, text, "zui_edge_fallback_back_after_ms 5000\n") != null);
    }
}

test "edge fallback: the signature-order node of an edge with the bucket fallback is the network's full node, as for --source http; off, a directory or an explicit choice change it" {
    const N = node_mod.Node;
    var c: node_mod.Config = .{ .dir = "", .source = .{ .zui1 = .{ .cores = "", .fallback = .{ .http = .{} } } } };
    try testing.expectEqualStrings("https://fullnode.mainnet.sui.io", N.sigOrderBase(&c, true).?);
    c.network = .testnet;
    try testing.expectEqualStrings("https://fullnode.testnet.sui.io", N.sigOrderBase(&c, true).?);
    // the fallback did not come up (no bucket for the network), or is off, or is a directory: as before
    try testing.expect(N.sigOrderBase(&c, false) == null);
    c.source.zui1.fallback = .off;
    try testing.expect(N.sigOrderBase(&c, false) == null);
    c.source.zui1.fallback = .{ .dir = "/mirror" };
    try testing.expect(N.sigOrderBase(&c, true) == null);
    // an explicit node, or a stream, wins
    c.source.zui1.fallback = .{ .http = .{} };
    c.stream = "https://a.example,http://127.0.0.1:9000";
    try testing.expectEqualStrings("http://127.0.0.1:9000", N.sigOrderBase(&c, true).?);
    c.sig_order_from = "http://10.0.0.5:9000/";
    try testing.expectEqualStrings("http://10.0.0.5:9000", N.sigOrderBase(&c, true).?);
    // other sources are untouched
    var h: node_mod.Config = .{ .dir = "", .source = .{ .http = .{} } };
    try testing.expect(N.sigOrderBase(&h, false) == null);
    h.stream = "https://fullnode.mainnet.sui.io";
    try testing.expectEqualStrings("https://fullnode.mainnet.sui.io", N.sigOrderBase(&h, false).?);
}
