//! Unit tests of an edge's certificate convergence (docs/EDGE.md section 13; edge/certs.zig,
//! edge_certs.zig, route.zig `foreign_cert`).
//!
//! The measurement these replay (mainnet, docs/EDGE.md 10.3): an edge's path to its core was
//! cut for a minute, it took its checkpoints from the bucket and returned to the core; every
//! bucket checkpoint then held another quorum certificate than the core's, valid, with the same
//! summary. Here:
//!
//! - The chain is the node simulation tester's (dst/chain.zig): real checkpoint blobs certified
//!   by real BLS aggregate signatures of committees whose keys are the test's, over three
//!   epochs. So a second, equally valid certificate can be made for any checkpoint: the same
//!   summary signed by another set of signers of the same committee (`World.other`).
//! - The core: the chain's checkpoints in a store, served over zui/1 (the real listener and
//!   dispatcher, with the edge feed) and over sui.rpc.v2 (the edge's `--core-upstream`).
//! - The bucket: a directory of the same checkpoints carrying the other certificate.
//! - The edge: the node's own fetch path, fallback switch, follower and store (as
//!   edge_fallback_tests.zig builds them), with `edge_certs.Converger` wired as node.zig wires
//!   it and `edge.forward.Forwarder` in front of its service. The zui/1 path to the core goes
//!   through `Link`, which can be cut; the sui.rpc.v2 path stays up, so forwarded reads can be
//!   compared with the core's own while the feed is down.
//!
//! The converge thread is not started: the tests call `Converger.step`, so what happens between
//! two calls to the core is theirs to look at. No corpus needed.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const Atomic = std.atomic.Value;
const store = @import("store");
const sync = @import("sync");
const bls = @import("bls");
const bcs = @import("bcs");
const types = @import("types");
const net = @import("net");
const native = @import("native");
const serve = @import("serve");
const edge = @import("edge");
const source_mod = @import("source.zig");
const edge_certs = @import("edge_certs.zig");
const chain_mod = @import("dst/chain.zig");
const fx = @import("edge_fallback_tests.zig");

const io = testing.io;
const Chain = chain_mod.Chain;
const h2 = serve.h2;
const proto = serve.proto;
const loopback = serve.loopback;
const service = serve.service;
const forward = edge.forward;
const route = edge.route;
const certs_mod = edge.certs;
const sys = std.heap.smp_allocator;
const ms: u64 = std.time.ns_per_ms;

const p_checkpoint = "/sui.rpc.v2.LedgerService/GetCheckpoint";
const p_subscribe = "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints";

/// Checkpoints per epoch of the test chain, and its length.
const epoch_len = 50;
const chain_len = 120;

// ------------------------------------------------------------------ the chain, twice certified

/// Signs `summary` for `epoch` with the validators `signers` (committee indices, ascending).
fn certifyWith(a: std.mem.Allocator, vals: []const chain_mod.Validator, epoch: u64, summary: []const u8, signers: []const u32) ![]u8 {
    const msg = try a.alloc(u8, 3 + summary.len + 8);
    msg[0..3].* = .{ 2, 0, 0 };
    @memcpy(msg[3..][0..summary.len], summary);
    std.mem.writeInt(u64, msg[3 + summary.len ..][0..8], epoch, .little);
    var sigs: [chain_mod.max_validators]bls.Signature = undefined;
    for (signers, 0..) |i, k| sigs[k] = vals[i].sk.sign(msg);
    const agg = bls.aggregate(sigs[0..signers.len]) orelse return error.NoSigners;
    return Chain.encodeSigInfo(a, epoch, agg.toBytes(), signers);
}

/// Another certificate than `own` (the chain's, a quorum in a random order) over the same
/// summary: every validator's signature, or, when the chain's own happens to be that, the
/// fewest validators by stake that make a quorum.
fn otherCert(a: std.mem.Allocator, vals: []const chain_mod.Validator, epoch: u64, summary: []const u8, own: []const u8) ![]u8 {
    var all: [chain_mod.max_validators]u32 = undefined;
    for (0..vals.len) |i| all[i] = @intCast(i);
    const full = try certifyWith(a, vals, epoch, summary, all[0..vals.len]);
    if (!std.mem.eql(u8, full, own)) return full;
    // heaviest first until the quorum, then in committee order
    std.mem.sort(u32, all[0..vals.len], vals, struct {
        fn lt(v: []const chain_mod.Validator, x: u32, y: u32) bool {
            return v[x].stake > v[y].stake;
        }
    }.lt);
    var n: usize = 0;
    var stake: u64 = 0;
    while (stake < sync.committee.quorum_threshold) : (n += 1) stake += vals[all[n]].stake;
    std.mem.sort(u32, all[0..n], {}, std.sort.asc(u32));
    return certifyWith(a, vals, epoch, summary, all[0..n]);
}

fn concat(a: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    return std.mem.concat(a, u8, parts);
}

// ------------------------------------------------------------------ the core

/// A node's sui.rpc.v2 port on loopback (the edge's `--core-upstream`).
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

const Core = struct {
    gpa: std.mem.Allocator,
    st: *store.Store,
    sio: *store.RealIo,
    svc: service.Service,
    dicts: native.dicts.Dicts,
    feeder: native.edgefeed.Feeder,
    disp: native.dispatch.Dispatcher,
    cert: native.cert.Cert,
    listener: ?*native.listener.Listener = null,
    rpc: ?*Rpc = null,
    /// Checkpoints stored: `0 .. have`.
    have: u64 = 0,

    const id_seed: [32]u8 = @splat(9);

    fn key() [32]u8 {
        return (std.crypto.sign.Ed25519.KeyPair.generateDeterministic(id_seed) catch unreachable).public_key.toBytes();
    }

    fn create(gpa: std.mem.Allocator, dir: []const u8) !*Core {
        const c = try gpa.create(Core);
        errdefer gpa.destroy(c);
        var cfg = fx.store_cfg;
        cfg.dir = dir;
        const h = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
        const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        c.* = .{
            .gpa = gpa,
            .st = h.store,
            .sio = h.io,
            .svc = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0), .json = false, .display = false },
            .dicts = native.dicts.Dicts.init(gpa),
            .feeder = undefined,
            .disp = undefined,
            .cert = native.cert.generate(try P256.KeyPair.generateDeterministic(@splat(6)), @splat(1), 1_800_000_000, 14, "zui"),
        };
        c.feeder = native.edgefeed.Feeder.init(&c.dicts);
        c.disp = .{ .svc = &c.svc, .dicts = &c.dicts, .edge = &c.feeder };
        return c;
    }

    fn destroy(c: *Core) void {
        if (c.rpc) |r| r.stop();
        if (c.listener) |l| l.stop();
        c.svc.deinit();
        c.dicts.deinit();
        c.st.deinit();
        c.sio.deinit();
        c.gpa.destroy(c);
    }

    /// Starts the zui/1 listener (a new port) and, once, the sui.rpc.v2 port.
    fn start(c: *Core) !u16 {
        if (c.listener) |l| l.stop();
        const l = try native.listener.Listener.start(c.gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = id_seed, .cert = &c.cert }, &c.disp);
        c.listener = l;
        if (c.rpc == null) c.rpc = try Rpc.start(c.svc.handler());
        return l.address().getPort();
    }

    /// Stores the chain's checkpoints `have .. upto` with the chain's own certificates.
    fn advance(c: *Core, ch: *const Chain, upto: u64) !void {
        var arena = std.heap.ArenaAllocator.init(c.gpa);
        defer arena.deinit();
        while (c.have < upto) : (c.have += 1) {
            _ = arena.reset(.retain_capacity);
            const cp = ch.cps[@intCast(c.have)];
            const b = try c.st.begin(cp.seq, cp.epoch);
            errdefer c.st.abort(b);
            try b.checkpoint(try concat(arena.allocator(), &.{ cp.summary, cp.sig }), cp.contents);
            try b.checkpointDigest(&cp.digest);
            try c.st.commit(b);
        }
    }
};

// ------------------------------------------------------------------ the world

const World = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    tmp: testing.TmpDir,
    root_path: []const u8,
    chain: *Chain,
    /// Per checkpoint: the BCS AuthorityQuorumSignInfo of the other certificate (the bucket's).
    other: [][]const u8,
    core: *Core,
    link: *fx.Link,
    bucket: Io.Dir,
    bucket_have: u64 = 0,

    fn init(w: *World, seed: u64) !void {
        const gpa = testing.allocator;
        w.gpa = gpa;
        w.arena = .init(gpa);
        errdefer w.arena.deinit();
        const a = w.arena.allocator();
        w.chain = try Chain.generate(gpa, .{ .seed = seed, .checkpoints = chain_len, .epoch_min = epoch_len, .epoch_max = epoch_len, .validators = 7 });
        errdefer w.chain.deinit();
        w.other = try a.alloc([]const u8, chain_len);
        for (w.chain.cps, w.other) |cp, *o| {
            o.* = try otherCert(a, w.chain.epochs[@intCast(cp.epoch)].vals, cp.epoch, cp.summary, cp.sig);
            // another certificate, not the same one again
            try testing.expect(!std.mem.eql(u8, o.*, cp.sig));
        }
        w.tmp = testing.tmpDir(.{});
        errdefer w.tmp.cleanup();
        var pb: [512]u8 = undefined;
        const n = try w.tmp.dir.realPath(io, &pb);
        w.root_path = try a.dupe(u8, pb[0..n]);
        try w.tmp.dir.createDirPath(io, "bucket");
        w.bucket = try w.tmp.dir.openDir(io, "bucket", .{});
        w.bucket_have = 0;
        w.core = try Core.create(gpa, try std.fmt.allocPrint(a, "{s}/core", .{w.root_path}));
        w.link = try fx.Link.create(gpa);
    }

    fn deinit(w: *World) void {
        w.link.destroy(w.gpa);
        w.core.destroy();
        w.bucket.close(io);
        w.tmp.cleanup();
        w.chain.deinit();
        w.arena.deinit();
    }

    fn coreUp(w: *World) !void {
        w.link.core_port.store(try w.core.start(), .release);
    }

    /// The bucket's blob of `seq`: the chain's checkpoint with the other certificate.
    fn bucketBlob(w: *World, a: std.mem.Allocator, seq: u64) ![]u8 {
        const cp = w.chain.cps[@intCast(seq)];
        return concat(a, &.{ &.{1}, cp.summary, w.other[@intCast(seq)], cp.contents, &.{0} });
    }

    /// The certified summary the bucket serves for `seq`, and the core's.
    fn bucketCert(w: *World, a: std.mem.Allocator, seq: u64) ![]u8 {
        return concat(a, &.{ w.chain.cps[@intCast(seq)].summary, w.other[@intCast(seq)] });
    }
    fn coreCert(w: *World, a: std.mem.Allocator, seq: u64) ![]u8 {
        const cp = w.chain.cps[@intCast(seq)];
        return concat(a, &.{ cp.summary, cp.sig });
    }

    /// Checkpoints `.. upto` on the core and in the bucket, as at the tip.
    fn publish(w: *World, upto: u64) !void {
        try w.core.advance(w.chain, upto);
        try w.publishBucket(upto);
    }

    fn publishBucket(w: *World, upto: u64) !void {
        var nb: [64]u8 = undefined;
        var tb: [64]u8 = undefined;
        while (w.bucket_have < upto) : (w.bucket_have += 1) {
            const blob = try w.bucketBlob(w.gpa, w.bucket_have);
            defer w.gpa.free(blob);
            const tmp = try std.fmt.bufPrint(&tb, ".{d}.part", .{w.bucket_have});
            try w.bucket.writeFile(io, .{ .sub_path = tmp, .data = blob });
            try w.bucket.rename(tmp, w.bucket, try std.fmt.bufPrint(&nb, "{d}.chk", .{w.bucket_have}), io);
        }
    }

    fn committeeOf(w: *World, a: std.mem.Allocator, epoch: u64) !sync.Committee {
        const e = &w.chain.epochs[@intCast(epoch)];
        return sync.Committee.init(a, epoch, try e.keys(a), try e.stakes(a));
    }

    /// edge_certs.zig `Committees` (the node reads the committees it persisted).
    fn committeeHook(ctx: *anyopaque, a: std.mem.Allocator, epoch: u64) ?sync.Committee {
        const w: *World = @ptrCast(@alignCast(ctx));
        if (epoch >= w.chain.epochs.len) return null;
        return w.committeeOf(a, epoch) catch null;
    }
};

// ------------------------------------------------------------------ the way to the core's sui.rpc.v2

/// The edge's `--core-upstream` transport with a switch: up, down (no connection: what the gRPC
/// transport reports when the core cannot be reached), or a core that answers every call with
/// its own INTERNAL.
const Upstream = struct {
    inner: forward.Transport,
    mode: Atomic(u8) = .init(@intFromEnum(Mode.up)),

    const Mode = enum(u8) { up, down, core_error };
    const vt: forward.Transport.VTable = .{ .start = start, .cancel = cancel, .credit = credit, .finish = finish };

    fn transport(t: *Upstream) forward.Transport {
        return .{ .ctx = t, .vt = &vt };
    }
    fn set(t: *Upstream, m: Mode) void {
        t.mode.store(@intFromEnum(m), .release);
    }
    fn of(ctx: *anyopaque) *Upstream {
        return @ptrCast(@alignCast(ctx));
    }
    fn start(ctx: *anyopaque, call: *forward.Call, path: []const u8, body: []const u8, opts: forward.CallOpts) void {
        const t = of(ctx);
        switch (@as(Mode, @enumFromInt(t.mode.load(.acquire)))) {
            .up => t.inner.vt.start(t.inner.ctx, call, path, body, opts),
            .down => call.onDone(14, "transport error: upstream connect failed", "", true),
            .core_error => call.onDone(13, "the core's own failure", "", false),
        }
    }
    fn cancel(ctx: *anyopaque, call: *forward.Call) void {
        const t = of(ctx);
        t.inner.vt.cancel(t.inner.ctx, call);
    }
    fn credit(ctx: *anyopaque, call: *forward.Call, n: usize) void {
        const t = of(ctx);
        t.inner.vt.credit(t.inner.ctx, call, n);
    }
    fn finish(ctx: *anyopaque, call: *forward.Call) void {
        const t = of(ctx);
        t.inner.vt.finish(t.inner.ctx, call);
    }
};

// ------------------------------------------------------------------ the edge

const Edge = struct {
    gpa: std.mem.Allocator,
    w: *World,
    st: *store.Store,
    sio: *store.RealIo,
    dir: Io.Dir,
    spool: Io.Dir,
    arch: sync.archive.Archive,
    pool: *edge.client.Pool,
    fb: *source_mod.EdgeFallback,
    prober: *edge.fallback.Prober,
    src: source_mod.Source,
    fetcher: source_mod.Fetcher,
    follower: *sync.Follower,
    cv: *edge_certs.Converger,
    svc: service.Service,
    gt: forward.GrpcTransport,
    up: Upstream,
    fwd: *forward.Forwarder,
    disp: native.dispatch.Dispatcher,
    first: u64,
    run_thread: ?std.Thread = null,
    run_err: ?anyerror = null,
    following: bool = false,

    const Opts = struct {
        name: []const u8,
        /// Where a fresh edge starts (as after a snapshot restore); a store that holds
        /// checkpoints resumes after its last one.
        first: u64 = 0,
        /// A fresh store is first given checkpoint `first - 1` the way a snapshot restore
        /// leaves it: held, with the certificate the restore's source gave (the bucket's), and
        /// recorded as pruned (not served over gRPC; zui/1 proofs and the epoch proof read it).
        restored: bool = false,
        crash_at: ?certs_mod.Crash = null,
    };

    /// Builds the edge over `<tmp>/<name>` (a store that is there is reopened, as a restart).
    fn create(w: *World, o: Opts) !*Edge {
        const gpa = w.gpa;
        const e = try gpa.create(Edge);
        errdefer gpa.destroy(e);
        var pb: [600]u8 = undefined;
        var cfg = fx.store_cfg;
        cfg.dir = try std.fmt.bufPrint(&pb, "{s}/{s}/store", .{ w.root_path, o.name });
        var sb: [128]u8 = undefined;
        try w.tmp.dir.createDirPath(io, try std.fmt.bufPrint(&sb, "{s}/spool", .{o.name}));
        const h = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
        const dir = try w.tmp.dir.openDir(io, o.name, .{ .iterate = true });
        // the spool is a cache of one process lifetime (node.zig empties it at start)
        dir.deleteTree(io, "spool") catch {};
        try dir.createDirPath(io, "spool");
        const spool = try dir.openDir(io, "spool", .{});
        const specs = [_]edge.client.Spec{w.link.spec(Core.key())};
        const pool = try edge.client.Pool.init(gpa, io, &specs, 2);
        if (o.restored and h.store.committed() == null) {
            const cp = w.chain.cps[@intCast(o.first - 1)];
            const cert_bytes = try w.bucketCert(gpa, cp.seq);
            defer gpa.free(cert_bytes);
            const b = try h.store.begin(cp.seq, cp.epoch);
            try b.checkpoint(cert_bytes, cp.contents);
            try b.checkpointDigest(&cp.digest);
            try b.highestPruned(cp.seq);
            try h.store.commit(b);
        }
        const first: u64 = if (h.store.committed()) |c| c + 1 else o.first;
        e.* = .{
            .gpa = gpa,
            .w = w,
            .st = h.store,
            .sio = h.io,
            .dir = dir,
            .spool = spool,
            .arch = .{ .dir = spool },
            .pool = pool,
            .fb = undefined,
            .prober = undefined,
            .src = .{ .gpa = gpa, .io = io, .kind = .{ .zui1 = pool } },
            .fetcher = undefined,
            .follower = undefined,
            .cv = undefined,
            .svc = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0), .json = false, .display = false, .lowest_checkpoint = o.first },
            .gt = undefined,
            .up = undefined,
            .fwd = undefined,
            .disp = undefined,
            .first = first,
        };
        // as node.zig's initEdgeFallback
        const fb = try gpa.create(source_mod.EdgeFallback);
        fb.* = .{ .src = .{ .gpa = gpa, .io = io, .kind = .{ .dir = w.bucket } }, .sw = .{ .t = fx.quick, .log = false } };
        fb.sw.since_ns.store(fx.nowNs(), .monotonic);
        e.fb = fb;
        e.src.edge_fb = fb;
        pool.stall_ms = fx.quick.fail_after_ms;
        e.prober = try edge.fallback.Prober.init(gpa, io, &fb.sw, &specs, null);
        try e.prober.start();
        // the follower resumes as a node does: the committee of the next checkpoint's epoch,
        // linked to the last one it holds
        const a = w.arena.allocator();
        const next_epoch = w.chain.cps[@intCast(first)].epoch;
        e.follower = try sync.Follower.init(gpa, io, e.st, .{ .archive = &e.arch }, .{ .mode = .apply, .workers = 2, .window = 8, .poll_ms = 50 }, .{
            .committee = try w.committeeOf(a, next_epoch),
            .first_seq = first,
            .prev_digest = if (first > 0) w.chain.cps[@intCast(first - 1)].digest else null,
            .prev_was_eoe = first > 0 and w.chain.cps[@intCast(first - 1)].eoe,
        });
        e.follower.observer = .{ .ctx = e, .on_checkpoint = onCheckpoint, .on_batch = onBatch, .on_committed = onCommitted };
        fb.applied_next = &e.follower.applied_next;
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
            .on_spooled = .{ .ctx = e.follower, .call = spooled },
        };
        // as node.zig: the certificate log beside the store, opened before the follower runs
        e.cv = try edge_certs.Converger.open(gpa, io, dir, e.st, pool, .{ .ctx = w, .get = World.committeeHook }, .{ .log = false, .crash_at = o.crash_at, .ahead = 8 });
        e.cv.fetcher = &e.fetcher;
        e.cv.sw = &fb.sw;
        // the forwarder in front of the service, the core's sui.rpc.v2 port as its upstream
        e.gt = try forward.GrpcTransport.init(sys, io, .{ .host = "127.0.0.1", .port = w.core.rpc.?.port, .security = .plain });
        e.up = .{ .inner = e.gt.transport() };
        e.fwd = try forward.Forwarder.create(gpa, io, &e.svc, e.up.transport(), .{ .ahead_wait_ms = 30, .hold_ms = 20 });
        e.fwd.source = .{ .ctx = e, .known_tip = knownTip, .silent_ns = silentNs, .on_fallback = onFallback };
        e.fwd.setCerts(e.cv.certs);
        // the zui/1 dispatcher of the edge's own listener
        e.disp = .{ .svc = &e.svc, .edge = &w.core.feeder };
        e.disp.foreign = e.cv.nativeHook();
        return e;
    }

    fn spooled(ctx: *anyopaque, seq: u64) void {
        const f: *sync.Follower = @ptrCast(@alignCast(ctx));
        f.notify(seq);
    }
    fn onCheckpoint(_: *anyopaque, _: u64, _: *const sync.verify.Checked, _: []const u8) void {}
    /// node.zig `onBatch`: the mark, before the commit.
    fn onBatch(ctx: *anyopaque, seq: u64, _: *const sync.verify.Checked, _: []const u8, _: *store.Batch) anyerror!void {
        const e: *Edge = @ptrCast(@alignCast(ctx));
        try e.cv.onBatch(seq);
    }
    fn onCommitted(ctx: *anyopaque, _: u64) void {
        const e: *Edge = @ptrCast(@alignCast(ctx));
        e.fwd.noteApplied();
    }
    fn knownTip(ctx: *anyopaque) ?u64 {
        const e: *Edge = @ptrCast(@alignCast(ctx));
        return e.fetcher.tipKnown();
    }
    fn silentNs(ctx: *anyopaque) u64 {
        const e: *Edge = @ptrCast(@alignCast(ctx));
        return e.fetcher.silentNs();
    }
    fn onFallback(ctx: *anyopaque) bool {
        const e: *Edge = @ptrCast(@alignCast(ctx));
        return e.fb.sw.mode() == .fallback;
    }

    fn follow(e: *Edge) !void {
        try e.fetcher.start(3);
        e.run_thread = try std.Thread.spawn(.{}, runMain, .{e});
        e.following = true;
    }
    fn runMain(e: *Edge) void {
        e.follower.run(null) catch |err| {
            e.run_err = err;
        };
    }

    /// The edge holds checkpoints `.. upto` (exclusive).
    fn waitHave(e: *Edge, upto: u64, limit_ms: u64) !void {
        const t0 = fx.nowNs();
        while ((e.st.committed() orelse 0) + 1 < upto or e.st.committed() == null) {
            if (e.run_err) |err| {
                std.debug.print("edge cert test: follower stopped: {s}\n", .{@errorName(err)});
                return error.TestUnexpectedResult;
            }
            if (fx.nowNs() - t0 > limit_ms * ms) {
                std.debug.print("edge cert test: waiting for checkpoint {d}: at {?d}, source {s}, {d} from the cores, {d} from the fallback\n", .{ upto - 1, e.st.committed(), @tagName(e.fb.sw.mode()), e.fb.sw.stats.from_core.load(.monotonic), e.fb.sw.stats.from_fallback.load(.monotonic) });
                return error.TestUnexpectedResult;
            }
            fx.sleepMs(2);
        }
    }

    fn waitMode(e: *Edge, m: edge.fallback.Mode, limit_ms: u64) !void {
        const t0 = fx.nowNs();
        while (e.fb.sw.mode() != m) {
            if (fx.nowNs() - t0 > limit_ms * ms) {
                std.debug.print("edge cert test: the edge did not get to {s}\n", .{@tagName(m)});
                return error.TestUnexpectedResult;
            }
            fx.sleepMs(2);
        }
    }

    /// The fetcher has met the tip (a request came back "not there yet"): the gate's view.
    fn waitTip(e: *Edge, limit_ms: u64) !void {
        const t0 = fx.nowNs();
        while (e.cv.gate() != .run) {
            if (fx.nowNs() - t0 > limit_ms * ms) {
                std.debug.print("edge cert test: the gate stays {s}\n", .{@tagName(e.cv.gate())});
                return error.TestUnexpectedResult;
            }
            fx.sleepMs(2);
        }
    }

    /// The guard as a healthy edge at its core's tip has it, and the core's floor known.
    fn healthy(e: *Edge) !void {
        e.fwd.observe(h2.meta.monoNs(), .{ .lag = 0, .source_age_ns = 0 });
        fx.sleepMs(25);
        e.fwd.observe(h2.meta.monoNs(), .{ .lag = 0, .source_age_ns = 0 });
        try testing.expectEqual(route.GuardState.ok, e.fwd.guardState());
        e.fwd.refreshFloor(h2.meta.monoNs());
    }

    fn held(e: *Edge, path: certs_mod.HeldPath) u64 {
        return e.cv.certs.stats.held_served[@intFromEnum(path)].load(.monotonic);
    }

    /// Steps the converge loop until nothing is marked (every step must do something).
    fn converge(e: *Edge) !u32 {
        var steps: u32 = 0;
        while (e.cv.certs.pending() != 0) : (steps += 1) {
            if (steps > 200) return error.TestUnexpectedResult;
            switch (e.cv.step()) {
                .clean, .failed => {},
                // every connection is with the feed for a moment, or the tip moved
                .idle => fx.sleepMs(5),
            }
        }
        return steps;
    }

    /// The certified summary the edge serves for `seq`, copied.
    fn cert(e: *Edge, a: std.mem.Allocator, seq: u64) ![]u8 {
        var snap = e.st.snapshot();
        defer snap.release();
        return a.dupe(u8, (snap.checkpoint(seq) orelse return error.TestUnexpectedResult).summary_cert);
    }

    /// Ends the process as a crash does: nothing is closed in order (the store and the log are
    /// left as their last write left them).
    fn destroy(e: *Edge) void {
        e.follower.stop();
        if (e.run_thread) |t| t.join();
        e.fb.stopping.store(true, .release);
        e.pool.stop();
        if (e.following) e.fetcher.stop();
        e.prober.deinit();
        e.follower.deinit();
        e.fwd.destroy();
        const conn = e.gt.up.conn;
        if (conn) |c| c.retain();
        e.gt.deinit();
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
        e.cv.deinit();
        e.svc.deinit();
        e.gpa.destroy(e.fb);
        e.pool.deinit();
        e.st.deinit();
        e.sio.deinit();
        e.spool.close(io);
        e.dir.close(io);
        e.gpa.destroy(e);
    }
};

// ------------------------------------------------------------------ requests and the diff

fn maskInto(w: *proto.Writer, field: u32, mask: ?[]const u8) !void {
    const text = mask orelse return;
    const m = try w.begin(field, 256);
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |p| if (p.len > 0) try w.string(1, p);
    try w.end(m);
}

fn checkpointReq(a: std.mem.Allocator, seq: ?u64, digest: ?*const [32]u8, mask: ?[]const u8) ![]const u8 {
    var w = proto.Writer.init(try a.alloc(u8, 4096));
    if (seq) |s| try w.uint(1, s);
    if (digest) |d| {
        var db: [serve.b58.max_len_32]u8 = undefined;
        try w.string(2, serve.b58.encode32(&db, d));
    }
    try maskInto(&w, 3, mask);
    return w.bytesWritten();
}

fn subscribeReq(a: std.mem.Allocator, mask: ?[]const u8) ![]const u8 {
    var w = proto.Writer.init(try a.alloc(u8, 4096));
    try maskInto(&w, 1, mask);
    return w.bytesWritten();
}

fn sameReply(x: loopback.Reply, y: loopback.Reply) bool {
    return x.status == y.status and std.mem.eql(u8, x.message, y.message) and std.mem.eql(u8, x.grpc_message, y.grpc_message) and std.mem.eql(u8, x.details, y.details);
}

/// Read masks of GetCheckpoint: the method's default, every field of the message one at a time,
/// and combinations. `cert`: the mask renders the quorum certificate.
const Mask = struct { text: ?[]const u8, cert: bool = false, object_set: bool = false };
const masks = [_]Mask{
    .{ .text = null },
    .{ .text = "sequence_number" },
    .{ .text = "digest" },
    .{ .text = "summary" },
    .{ .text = "summary.bcs" },
    .{ .text = "summary.digest,summary.timestamp" },
    .{ .text = "contents" },
    .{ .text = "contents.bcs" },
    .{ .text = "transactions.digest" },
    .{ .text = "sequence_number,digest,summary,contents" },
    .{ .text = "signature", .cert = true },
    .{ .text = "signature.signature", .cert = true },
    .{ .text = "signature.bitmap", .cert = true },
    .{ .text = "signature.epoch", .cert = true },
    .{ .text = "sequence_number,signature", .cert = true },
    .{ .text = "summary,signature,contents", .cert = true },
    .{ .text = "*", .cert = true, .object_set = true },
    .{ .text = "transactions", .object_set = true },
    .{ .text = "objects", .object_set = true },
    .{ .text = "signature,transactions", .cert = true, .object_set = true },
};

/// Core against edge: every request to the core's handler and to the edge's forwarding handler.
const Diff = struct {
    arena: std.heap.ArenaAllocator,
    core_h: h2.Handler,
    edge_h: h2.Handler,
    fwd: *forward.Forwarder,
    total: u64 = 0,
    differences: u64 = 0,
    /// By outcome: 0 served locally, 1 + reason forwarded for that reason.
    asked: [1 + route.Reason.count]u64 = @splat(0),

    fn routed(d: *const Diff) [1 + route.Reason.count]u64 {
        var out: [1 + route.Reason.count]u64 = @splat(0);
        for (&d.fwd.metrics.methods) |*pm| {
            out[0] += pm.served_local.load(.monotonic);
            for (&pm.forwarded, 0..) |*c, i| out[1 + i] += c.load(.monotonic);
        }
        return out;
    }

    const local: usize = 0;
    fn reason(r: route.Reason) usize {
        return 1 + @as(usize, @intFromEnum(r));
    }

    /// Asks both; returns how the edge routed it.
    fn check(d: *Diff, path: []const u8, body: []const u8) !usize {
        const a = d.arena.allocator();
        const want = try loopback.unary(a, d.core_h, path, body);
        const before = d.routed();
        const got = try loopback.unary(a, d.edge_h, path, body);
        const after = d.routed();
        d.total += 1;
        var bucket: usize = std.math.maxInt(usize);
        for (before, after, 0..) |x, y, i| if (y > x) {
            bucket = i;
        };
        try testing.expect(bucket != std.math.maxInt(usize));
        d.asked[bucket] += 1;
        if (!sameReply(want, got)) {
            d.differences += 1;
            if (d.differences <= 8) std.debug.print("edge-cert DIFFERENCE {s} request {x}\n  core: status {d} \"{s}\" {d} message bytes\n  edge: status {d} \"{s}\" {d} message bytes\n", .{ path, body[0..@min(body.len, 64)], want.status, want.grpc_message, want.message.len, got.status, got.grpc_message, got.message.len });
        }
        return bucket;
    }

    /// GetCheckpoint for every checkpoint in `lo..hi` under every mask, by number; by digest
    /// and as the latest for a few. Each must be routed as the rules say: to the core for a
    /// marked checkpoint's certificate, locally otherwise (object sets are never local).
    fn window(d: *Diff, e: *Edge, lo: u64, hi: u64) !void {
        const w = e.w;
        var seq = lo;
        while (seq < hi) : (seq += 1) {
            _ = d.arena.reset(.retain_capacity);
            const a = d.arena.allocator();
            for (masks) |m| {
                const marked = e.cv.certs.isMarked(seq);
                const want: usize = if (m.object_set) reason(.needs_read_sets) else if (m.cert and marked) reason(.foreign_cert) else local;
                const how = try d.check(p_checkpoint, try checkpointReq(a, seq, null, m.text));
                if (how != want) {
                    std.debug.print("edge-cert ROUTING checkpoint {d} (marked: {}) mask {?s}: outcome {d}, expected {d}\n", .{ seq, marked, m.text, how, want });
                    return error.TestUnexpectedResult;
                }
                if (seq % 7 == 3) {
                    const by_digest = try d.check(p_checkpoint, try checkpointReq(a, null, &w.chain.cps[@intCast(seq)].digest, m.text));
                    try testing.expectEqual(want, by_digest);
                }
            }
        }
        _ = d.arena.reset(.retain_capacity);
    }

    /// GetCheckpoint with no number and no digest (the latest), with and without the
    /// certificate; `marked`: the edge's tip is. Both nodes must be at the same tip.
    fn latest(d: *Diff, marked: bool) !void {
        const a = d.arena.allocator();
        try testing.expectEqual(local, try d.check(p_checkpoint, try checkpointReq(a, null, null, "sequence_number,digest,summary")));
        try testing.expectEqual(if (marked) reason(.foreign_cert) else local, try d.check(p_checkpoint, try checkpointReq(a, null, null, "sequence_number,signature")));
    }
};

/// The whole zui/1 response to `get_checkpoint` of `seq` with `parts`, from `disp`.
fn nativeCheckpoint(a: std.mem.Allocator, disp: *native.dispatch.Dispatcher, seq: u64, parts: u8) ![]const u8 {
    var body: std.ArrayList(u8) = .empty;
    const w: native.proto.W = .{ .gpa = a, .out = &body };
    try w.uleb(1);
    try w.int(u64, seq);
    try w.u8_(parts);
    var out: std.ArrayList(u8) = .empty;
    disp.handle(a, .{ .method = .get_checkpoint, .flags = 0, .body = body.items }, null, &out);
    return out.items;
}

/// The zui/1 response to `get_checkpoint_feed` of `seq`, uncompressed, from `disp`.
fn nativeFeed(a: std.mem.Allocator, disp: *native.dispatch.Dispatcher, seq: u64) ![]const u8 {
    var b: [12]u8 = undefined;
    std.mem.writeInt(u64, b[0..8], seq, .little);
    std.mem.writeInt(u32, b[8..12], 0, .little);
    var out: std.ArrayList(u8) = .empty;
    disp.handle(a, .{ .method = .get_checkpoint_feed, .flags = 0, .body = &b }, null, &out);
    return out.items;
}

const all_parts = native.proto.part_contents | native.proto.part_tx | native.proto.part_effects | native.proto.part_events;

/// Every byte the edge holds and serves for `lo..hi` is the core's: the stored records, the
/// zui/1 checkpoint in full and the feed.
fn expectEqualToCore(w: *World, e: *Edge, lo: u64, hi: u64) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var plain_edge: native.dispatch.Dispatcher = .{ .svc = &e.svc, .edge = &w.core.feeder };
    var seq = lo;
    while (seq < hi) : (seq += 1) {
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        {
            var es = e.st.snapshot();
            defer es.release();
            var cs = w.core.st.snapshot();
            defer cs.release();
            const er = es.checkpoint(seq) orelse return error.TestUnexpectedResult;
            const cr = cs.checkpoint(seq) orelse return error.TestUnexpectedResult;
            try testing.expectEqualSlices(u8, cr.summary_cert, er.summary_cert);
            try testing.expectEqualSlices(u8, cr.contents, er.contents);
            try testing.expectEqual(cr.epoch, er.epoch);
        }
        try testing.expectEqualSlices(u8, try nativeCheckpoint(a, &w.core.disp, seq, all_parts), try nativeCheckpoint(a, &plain_edge, seq, all_parts));
        try testing.expectEqualSlices(u8, try nativeFeed(a, &w.core.disp, seq), try nativeFeed(a, &plain_edge, seq));
    }
}

// ------------------------------------------------------------------ tests

test "edge certificates: the measured outage, replayed. The path to the core is cut, the edge takes its checkpoints from the bucket (another valid certificate each), and returns. Every outage checkpoint is marked; while marked, a read of its certificate goes to the core and everything else stays local; the edge then replaces each certificate with the core's, and every byte it holds equals the core's. Core against edge: 0 differences before, during and after" {
    var w: World = undefined;
    try w.init(0xce47_0001);
    defer w.deinit();
    try w.publish(40);
    try w.coreUp();
    const e = try Edge.create(&w, .{ .name = "outage" });
    defer e.destroy();
    try e.follow();
    try e.waitHave(40, 20_000);
    try e.healthy();
    var d: Diff = .{ .arena = std.heap.ArenaAllocator.init(testing.allocator), .core_h = w.core.svc.handler(), .edge_h = e.fwd.handler(), .fwd = e.fwd };
    defer d.arena.deinit();
    var scratch = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();
    const a = scratch.allocator();

    // ---- before: everything from the core's feed, nothing marked, nothing passed on for a certificate
    try testing.expectEqual(@as(u64, 0), e.cv.certs.pending());
    try testing.expectEqual(@as(u64, 0), e.fb.sw.stats.from_fallback.load(.monotonic));
    try d.window(e, 0, 40);
    try d.latest(false);
    const before = d.total;
    try testing.expectEqual(@as(u64, 0), d.differences);
    try testing.expectEqual(@as(u64, 0), d.asked[Diff.reason(.foreign_cert)]);
    try expectEqualToCore(&w, e, 0, 40);

    // ---- the path is cut. The chain goes on: the core has the checkpoints, the edge takes
    // them from the bucket
    w.link.down.store(true, .release);
    try w.publish(80);
    try e.waitMode(.fallback, 10_000);
    try e.waitHave(80, 20_000);
    // (the counter is of fetches: two fetch threads can bring the same checkpoint)
    try testing.expect(e.fb.sw.stats.from_fallback.load(.monotonic) >= 40);
    // every outage checkpoint is marked, and nothing else
    try testing.expectEqual(@as(u64, 40), e.cv.certs.pending());
    for (0..80) |s| try testing.expectEqual(s >= 40, e.cv.certs.isMarked(s));
    // the edge holds the bucket's certificate for each: valid, the same summary, other bytes
    for (40..80) |s| {
        const mine = try e.cert(a, s);
        try testing.expectEqualSlices(u8, try w.bucketCert(a, s), mine);
        try testing.expect(!std.mem.eql(u8, try w.coreCert(a, s), mine));
    }
    // what the rule is for: asked itself (no forwarding), the edge answers other bytes than the
    // core for `signature` of every outage checkpoint, and the same bytes for everything else
    {
        var raw_svc: service.Service = .{ .gpa = testing.allocator, .store = e.st, .chain_id = @splat(0), .json = false, .display = false };
        defer raw_svc.deinit();
        var differing: u32 = 0;
        for (40..80) |s| for (masks) |m| {
            if (m.object_set) continue;
            const body = try checkpointReq(a, s, null, m.text);
            const core = try loopback.unary(a, w.core.svc.handler(), p_checkpoint, body);
            const mine = try loopback.unary(a, raw_svc.handler(), p_checkpoint, body);
            try testing.expectEqual(@as(u8, 0), core.status);
            try testing.expectEqual(m.cert, !sameReply(core, mine));
            if (m.cert) differing += 1;
        };
        try testing.expectEqual(@as(u32, 40 * 6), differing);
    }

    // ---- during, on the fallback: the forwarder's diff, and how each request was routed
    d.asked = @splat(0);
    try d.window(e, 0, 80);
    try d.latest(true);
    try testing.expectEqual(@as(u64, 0), d.differences);
    const cert_masks: u64 = 6; // of `masks`: render the certificate and need no object set
    try testing.expect(d.asked[Diff.reason(.foreign_cert)] >= 40 * cert_masks);
    // a stream that renders certificates is not started here now; one that does not is
    try testing.expectEqual(Diff.reason(.foreign_cert), try d.check(p_subscribe, try subscribeReq(a, "sequence_number,signature")));
    try testing.expectEqual(Diff.local, try d.check(p_subscribe, try subscribeReq(a, "sequence_number,digest")));
    const during_fallback = d.total - before;
    try testing.expectEqual(@as(u64, 0), e.held(.grpc));

    // zui/1 has its own way to the core, the feed's, and that is the one that is cut: the edge
    // is on its fallback, so no core can be asked. A marked checkpoint's `get_checkpoint` is
    // answered here with the certificate the edge holds (the bucket's: valid, not the core's
    // bytes), at once and on whatever thread, and counted. Its feed is still "not held yet":
    // an edge never feeds another certificate than its core's on, outage or not.
    {
        var plain: native.dispatch.Dispatcher = .{ .svc = &e.svc, .edge = &w.core.feeder };
        try testing.expect(!e.disp.offThread(.{ .method = .get_checkpoint, .flags = 0, .body = "" }));
        for ([_]u64{ 40, 57, 79 }) |s| {
            for ([_]u8{ 0, all_parts }) |parts| {
                const mine = try nativeCheckpoint(a, &e.disp, s, parts);
                try testing.expectEqual(@as(u8, 0), mine[0]);
                try testing.expectEqualSlices(u8, try nativeCheckpoint(a, &plain, s, parts), mine);
                try testing.expect(!std.mem.eql(u8, try nativeCheckpoint(a, &w.core.disp, s, parts), mine));
            }
            try testing.expectEqualSlices(u8, try w.bucketCert(a, s), edge.client.Pool.parseSummary(try nativeCheckpoint(a, &e.disp, s, 0), s).cert);
            try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, try nativeFeed(a, &e.disp, s));
        }
        try testing.expectEqual(@as(u64, 9), e.held(.zui1));
        try testing.expectEqual(@as(u64, 9), e.disp.foreign_stats.held.load(.monotonic));
        try testing.expectEqual(@as(u64, 0), e.disp.foreign_stats.forwarded.load(.monotonic));
        try testing.expectEqual(@as(u64, 0), e.disp.foreign_stats.unavailable.load(.monotonic));
        try testing.expectEqual(@as(u64, 3), e.disp.foreign_stats.feed_withheld.load(.monotonic));
        // an unmarked checkpoint is the edge's own answer as ever, and not counted
        try testing.expectEqualSlices(u8, try nativeCheckpoint(a, &w.core.disp, 12, all_parts), try nativeCheckpoint(a, &e.disp, 12, all_parts));
        try testing.expectEqual(@as(u64, 9), e.held(.zui1));
    }

    // ---- the upstream is down too: no core is reachable by any way. A read of an outage
    // checkpoint's certificate is answered here, with the certificate the edge holds. The first
    // one tries the core (nothing said it was down), fails on the connection and is answered
    // here after all; from then on the edge knows and does not try.
    e.up.set(.down);
    {
        var raw_svc: service.Service = .{ .gpa = testing.allocator, .store = e.st, .chain_id = @splat(0), .json = false, .display = false };
        defer raw_svc.deinit();
        try testing.expect(!e.fwd.upstreamDown());
        var asked: u64 = 0;
        for ([_]u64{ 40, 41, 57, 79 }) |s| for (masks) |m| {
            if (!m.cert or m.object_set) continue;
            const body = try checkpointReq(a, s, null, m.text);
            const routed_before = d.routed();
            const mine = try loopback.unary(a, e.fwd.handler(), p_checkpoint, body);
            const routed_after = d.routed();
            asked += 1;
            // a success, the edge's own bytes (the bucket's certificate), served locally
            try testing.expectEqual(@as(u8, 0), mine.status);
            try testing.expect(sameReply(try loopback.unary(a, raw_svc.handler(), p_checkpoint, body), mine));
            try testing.expect(!sameReply(try loopback.unary(a, w.core.svc.handler(), p_checkpoint, body), mine));
            try testing.expectEqual(routed_before[Diff.local] + 1, routed_after[Diff.local]);
            try testing.expect(e.fwd.upstreamDown());
            try testing.expectEqual(asked, e.held(.grpc));
        };
        // the latest (79, marked), by a digest, and a stream that renders certificates: here too
        const latest_cert = try loopback.unary(a, e.fwd.handler(), p_checkpoint, try checkpointReq(a, null, null, "sequence_number,signature"));
        try testing.expectEqual(@as(u8, 0), latest_cert.status);
        const by_digest = try loopback.unary(a, e.fwd.handler(), p_checkpoint, try checkpointReq(a, null, &w.chain.cps[61].digest, "signature"));
        try testing.expect(sameReply(try loopback.unary(a, raw_svc.handler(), p_checkpoint, try checkpointReq(a, null, &w.chain.cps[61].digest, "signature")), by_digest));
        try testing.expectEqual(asked + 2, e.held(.grpc));
        try testing.expectEqual(Diff.local, try d.check(p_subscribe, try subscribeReq(a, "sequence_number,signature")));
        // everything that carries no certificate is local and the core's bytes, as before; an
        // unmarked checkpoint's certificate too (it is the core's), and neither is counted
        for ([_]u64{ 12, 40, 79 }) |s| for (masks) |m| {
            if (m.object_set or (m.cert and s >= 40)) continue;
            try testing.expectEqual(Diff.local, try d.check(p_checkpoint, try checkpointReq(a, s, null, m.text)));
        };
        try testing.expectEqual(@as(u64, 0), d.differences);
        try testing.expectEqual(asked + 2, e.held(.grpc));
        // what needs the core for another reason still does: UNAVAILABLE, not a held answer
        const needs_core = try loopback.unary(a, e.fwd.handler(), p_checkpoint, try checkpointReq(a, 57, null, "signature,transactions"));
        try testing.expectEqual(@as(u8, 14), needs_core.status);
        try testing.expectEqual(asked + 2, e.held(.grpc));
        // and the feed of a marked checkpoint is still not handed on
        try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, try nativeFeed(a, &e.disp, 57));
    }
    const held_grpc = e.held(.grpc);

    // ---- the upstream is back (the feed is still cut). The forwarder's floor thread asks the
    // core every second while the way is down; its first answer says the core is there, and
    // certificate reads are passed on again: 0 differences, nothing more answered from here.
    e.up.set(.up);
    try testing.expect(e.fwd.upstreamDown());
    e.fwd.refreshFloor(h2.meta.monoNs());
    try testing.expect(!e.fwd.upstreamDown());
    d.asked = @splat(0);
    try d.window(e, 36, 48);
    try d.latest(true);
    try testing.expectEqual(@as(u64, 0), d.differences);
    try testing.expect(d.asked[Diff.reason(.foreign_cert)] >= 8 * cert_masks);
    try testing.expectEqual(held_grpc, e.held(.grpc));
    const upstream_phases = d.total - before - during_fallback;

    // ---- the path is back; the edge returns to the core and follows it again
    w.link.down.store(false, .release);
    try e.waitMode(.core, 20_000);
    try w.publish(100);
    try e.waitHave(100, 20_000);
    try e.waitTip(10_000);
    // nothing converged by itself (the tests step the loop): still the 40, and the 20 new ones
    // came from the core
    try testing.expectEqual(@as(u64, 40), e.cv.certs.pending());
    for (80..100) |s| try testing.expect(!e.cv.certs.isMarked(s));
    d.asked = @splat(0);
    try d.window(e, 0, 100);
    try d.latest(false);
    try testing.expectEqual(@as(u64, 0), d.differences);
    try testing.expect(d.asked[Diff.reason(.foreign_cert)] >= 40 * cert_masks);
    // the newest marked checkpoint is 20 behind the tip: a stream that renders certificates
    // starts here again (and would end at a marked checkpoint, if one came)
    try testing.expectEqual(Diff.local, try d.check(p_subscribe, try subscribeReq(a, "sequence_number,signature")));
    const during_core = d.total - before - during_fallback - upstream_phases;

    // zui/1, on the edge's own listener: a marked checkpoint's `get_checkpoint` is the core's
    // answer (passed on from a worker; the I/O thread, which may not wait, says UNAVAILABLE),
    // its feed is "not held yet", and an unmarked checkpoint is answered here as ever
    {
        native.dispatch.may_block = true;
        defer native.dispatch.may_block = false;
        for ([_]u64{ 40, 57, 79 }) |s| {
            for ([_]u8{ 0, native.proto.part_contents, all_parts }) |parts| {
                try testing.expectEqualSlices(u8, try nativeCheckpoint(a, &w.core.disp, s, parts), try nativeCheckpoint(a, &e.disp, s, parts));
            }
            const feed = try nativeFeed(a, &e.disp, s);
            try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, feed);
        }
        try testing.expectEqual(@as(u64, 9), e.disp.foreign_stats.forwarded.load(.monotonic));
        try testing.expectEqual(@as(u64, 7), e.disp.foreign_stats.feed_withheld.load(.monotonic));
        // (a core is reachable: passed on, nothing more answered with the held certificate)
        try testing.expectEqual(@as(u64, 9), e.held(.zui1));
        for ([_]u64{ 0, 39, 80, 99 }) |s| {
            try testing.expectEqualSlices(u8, try nativeCheckpoint(a, &w.core.disp, s, all_parts), try nativeCheckpoint(a, &e.disp, s, all_parts));
            try testing.expectEqualSlices(u8, try nativeFeed(a, &w.core.disp, s), try nativeFeed(a, &e.disp, s));
        }
        try testing.expectEqual(@as(u64, 9), e.disp.foreign_stats.forwarded.load(.monotonic));
        native.dispatch.may_block = false;
        const refused = try nativeCheckpoint(a, &e.disp, 57, 0);
        try testing.expectEqual(@as(u8, @intFromEnum(native.proto.Code.unavailable)), refused[0]);
        try testing.expectEqual(@as(u64, 1), e.disp.foreign_stats.unavailable.load(.monotonic));
        try testing.expect(e.disp.offThread(.{ .method = .get_checkpoint, .flags = 0, .body = "" }));
        try testing.expect(!e.disp.offThread(.{ .method = .get_object, .flags = 0, .body = "" }));
        try testing.expect(e.disp.offThread(.{ .method = .get_object, .flags = native.proto.flag_verify, .body = "" }));
    }

    // The same through the edge's real zui/1 listener, as a client (or an edge that follows
    // this one) meets it: the listener hands a `get_checkpoint` to a worker while anything is
    // marked, the worker passes a marked one to the core, and the client reads the core's bytes.
    {
        const l = try native.listener.Listener.start(testing.allocator, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = Core.id_seed, .cert = &w.core.cert }, &e.disp);
        defer l.stop();
        const c = try edge.client.Conn.connect(testing.allocator, io, .{ .addr = .{ .ip4 = Io.net.Ip4Address.loopback(l.address().getPort()) }, .key = Core.key() }, 3_000);
        defer c.close();
        const forwarded = e.disp.foreign_stats.forwarded.load(.monotonic);
        for ([_]u64{ 12, 44, 78, 91 }) |s| {
            const req = edge.client.Pool.summaryRequest(s);
            const got = try c.request(a, .get_checkpoint, 0, &req);
            try testing.expectEqualSlices(u8, try nativeCheckpoint(a, &w.core.disp, s, 0), got);
            const sum = edge.client.Pool.parseSummary(got, s);
            try testing.expectEqualSlices(u8, try w.coreCert(a, s), sum.cert);
        }
        // two of the four were marked
        try testing.expectEqual(forwarded + 2, e.disp.foreign_stats.forwarded.load(.monotonic));
        // and what an edge that follows this one asks before it returns to it ("do you hold
        // the newest checkpoint I have") is answered for a marked checkpoint, by the core
        try testing.expect(try c.hasCheckpoint(a, 79));
    }

    // a response rendered before the replacement (by an edge without forwarding) is in the
    // GetCheckpoint cache with the bucket's certificate
    const stale_body = try checkpointReq(a, 61, null, "signature");
    const stale = try loopback.unary(a, e.svc.handler(), p_checkpoint, stale_body);
    try testing.expect(!sameReply(try loopback.unary(a, w.core.svc.handler(), p_checkpoint, stale_body), stale));

    // ---- converge: 40 summaries in calls of 16, highest first
    try testing.expectEqual(certs_mod.Gate.run, e.cv.gate());
    try testing.expectEqual(certs_mod.Pace.Outcome.clean, e.cv.step());
    try testing.expectEqual(@as(u64, 24), e.cv.certs.pending());
    for (40..80) |s| try testing.expectEqual(s < 64, e.cv.certs.isMarked(s));
    // half way: the replaced ones are served here, the rest still by the core; 0 differences
    try d.window(e, 56, 72);
    try testing.expectEqual(@as(u64, 0), d.differences);
    const steps = 1 + try e.converge();
    const st = &e.cv.certs.stats;
    try testing.expectEqual(@as(u64, 0), e.cv.certs.pending());
    try testing.expectEqual(@as(u64, 40), st.replaced.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), st.equal.load(.monotonic));
    try testing.expectEqual(@as(u64, 40), st.requests.load(.monotonic));
    try testing.expectEqual(@as(u64, 3), st.batches.load(.monotonic));
    try testing.expect(steps >= 3);
    for (&st.errors) |*c| try testing.expectEqual(@as(u64, 0), c.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), st.periods.load(.monotonic));
    try testing.expectEqual(@as(usize, 40), e.st.cert_fix.count());

    // ---- after: the edge's bytes are the core's for every checkpoint, in full
    try expectEqualToCore(&w, e, 0, 100);
    for (40..80) |s| try testing.expectEqualSlices(u8, try w.coreCert(a, s), try e.cert(a, s));
    // the cached response from before is not served again
    try testing.expect(sameReply(try loopback.unary(a, w.core.svc.handler(), p_checkpoint, stale_body), try loopback.unary(a, e.svc.handler(), p_checkpoint, stale_body)));
    // nothing is passed on for a certificate any more: every certificate is served here
    d.asked = @splat(0);
    try d.window(e, 0, 100);
    try d.latest(false);
    try testing.expectEqual(@as(u64, 0), d.differences);
    try testing.expectEqual(@as(u64, 0), d.asked[Diff.reason(.foreign_cert)]);
    try testing.expectEqual(Diff.local, try d.check(p_subscribe, try subscribeReq(a, "sequence_number,signature")));
    // zui/1: answered here, the core's bytes, the feed included
    const forwarded_before = e.disp.foreign_stats.forwarded.load(.monotonic);
    native.dispatch.may_block = true;
    for ([_]u64{ 40, 57, 79 }) |s| {
        try testing.expectEqualSlices(u8, try nativeFeed(a, &w.core.disp, s), try nativeFeed(a, &e.disp, s));
        try testing.expectEqualSlices(u8, try nativeCheckpoint(a, &w.core.disp, s, all_parts), try nativeCheckpoint(a, &e.disp, s, all_parts));
    }
    native.dispatch.may_block = false;
    try testing.expectEqual(forwarded_before, e.disp.foreign_stats.forwarded.load(.monotonic));
    try testing.expect(!e.disp.offThread(.{ .method = .get_checkpoint, .flags = 0, .body = "" }));
    std.debug.print("edge certificates, the outage replayed: 40 outage checkpoints marked, 40 replaced in {d} calls; core against edge (every phase with a core reachable): {d} requests before, {d} with the feed cut and the upstream up, {d} around the upstream's own outage (reads without a certificate during it, everything after it), {d} back on the core and before the replacement, {d} in all, {d} differences; with no core reachable {d} gRPC and {d} zui/1 reads of outage certificates answered with the held certificate\n", .{ st.batches.load(.monotonic), before, during_fallback, upstream_phases, during_core, d.total, d.differences, held_grpc, e.held(.zui1) });
    try testing.expectEqual(@as(u64, 0), d.differences);

    // the metrics a node renders
    var aw: Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try e.cv.renderMetrics(&aw.writer);
    try forward.renderMetrics(e.fwd, &aw.writer);
    try testing.expectEqual(held_grpc, e.held(.grpc));
    try testing.expectEqual(@as(u64, 9), e.held(.zui1));
    try testing.expectEqual(held_grpc + 9, e.cv.certs.period_held.load(.monotonic));
    var hb: [96]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, aw.written(), try std.fmt.bufPrint(&hb, "zui_edge_cert_held_served{{path=\"grpc\"}} {d}\n", .{held_grpc})) != null);
    for ([_][]const u8{ "zui_edge_cert_pending 0\n", "zui_edge_cert_replaced 40\n", "zui_edge_cert_marked 40\n", "zui_edge_cert_oldest_mark_seconds 0\n", "zui_edge_cert_periods_cleared 1\n", "reason=\"foreign_cert\"", "zui_edge_cert_held_served{path=\"zui1\"} 9\n", "zui_edge_cert_held_served{path=\"proof\"} 0\n", "zui_edge_cert_fixes 40\n", "zui_edge_cert_fix_bytes ", "zui_edge_route_upstream_down 0\n" }) |line| {
        try testing.expect(std.mem.indexOf(u8, aw.written(), line) != null);
    }
}

test "edge certificates: a crash after the marks, in the middle of a replacement's write, after its record and after its install loses no mark and leaves no certificate half written; the next start goes on and converges" {
    const Case = struct { at: ?certs_mod.Crash, name: []const u8 };
    const cases = [_]Case{
        .{ .at = null, .name = "marked" },
        .{ .at = .cert_torn, .name = "torn" },
        .{ .at = .cert_logged, .name = "logged" },
        .{ .at = .cert_installed, .name = "installed" },
    };
    var w: World = undefined;
    try w.init(0xce47_0002);
    defer w.deinit();
    try w.publish(12);
    try w.coreUp();
    var scratch = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();
    const a = scratch.allocator();
    // every case its own edge over the same chain: 0..11 from the core, then an outage
    var upto: u64 = 12;
    for (cases) |case| {
        const lo = upto;
        const hi = lo + 20;
        // the edge up to `lo` from the core
        w.link.down.store(false, .release);
        {
            const e = try Edge.create(&w, .{ .name = case.name });
            defer e.destroy();
            try e.follow();
            try e.waitHave(lo, 30_000);
            try testing.expectEqual(@as(u64, 0), e.cv.certs.pending());
            // the outage: `lo..hi` from the bucket
            w.link.down.store(true, .release);
            try w.publish(hi);
            try e.waitMode(.fallback, 10_000);
            try e.waitHave(hi, 20_000);
            try testing.expectEqual(@as(u64, 20), e.cv.certs.pending());
            if (case.at) |at| {
                // back on the core, and the crash inside the first replacement (16 of the 20)
                w.link.down.store(false, .release);
                try e.waitMode(.core, 20_000);
                try w.publish(hi + 4);
                try e.waitHave(hi + 4, 20_000);
                try e.waitTip(10_000);
                e.cv.certs.crash_at = at;
                try testing.expectError(error.CrashInjected, e.cv.stepInner());
                // until the last step the marks stand: reads still go to the core
                try testing.expectEqual(@as(u64, 20), e.cv.certs.pending());
            }
            // (the edge is destroyed here with nothing closed in order)
        }
        upto = if (case.at != null) hi + 4 else hi;
        w.link.down.store(false, .release);
        // ---- the next start
        const e = try Edge.create(&w, .{ .name = case.name });
        defer e.destroy();
        const marked = e.cv.certs.pending();
        const fixes = e.st.cert_fix.count();
        // What the log says after a restart is a superset of what was marked in memory: one
        // record covers 8 checkpoints ahead here, so the 4 checkpoints that came from the core
        // after the outage are under the last record and are marked now (and found equal).
        switch (case.at orelse .rewrite_before_rename) {
            // no replacement was begun (and the store's tip is the outage's last checkpoint):
            // exactly the 20 marks
            .rewrite_before_rename => {
                try testing.expectEqual(@as(u64, 20), marked);
                try testing.expectEqual(@as(usize, 0), fixes);
            },
            // The write stopped half way and was never synced. Whole records of it that reached
            // the file are whole, verified answers and are taken; the one it stopped in is cut.
            // Every other mark stands.
            .cert_torn => {
                try testing.expect(marked >= 8 and marked <= 24);
                try testing.expectEqual(24 - marked, @as(u64, fixes));
                try testing.expect(fixes < 16);
            },
            // the records are durable: the 16 are served with the core's certificate
            .cert_logged, .cert_installed => {
                try testing.expectEqual(@as(u64, 8), marked);
                try testing.expectEqual(@as(usize, 16), fixes);
            },
            else => unreachable,
        }
        // No mark lost: a checkpoint without a mark holds the core's certificate. No certificate
        // half written: a marked one holds the bucket's, whole (or the core's, for the 4).
        for (0..upto) |s| {
            const mine = try e.cert(a, s);
            if (!e.cv.certs.isMarked(s)) {
                try testing.expectEqualSlices(u8, try w.coreCert(a, s), mine);
            } else if (s >= lo and s < hi) {
                try testing.expectEqualSlices(u8, try w.bucketCert(a, s), mine);
            } else {
                try testing.expect(s >= hi and s < hi + 4);
                try testing.expectEqualSlices(u8, try w.coreCert(a, s), mine);
            }
        }
        // and it goes on: follows the core again and converges
        try e.follow();
        try w.publish(upto + 3);
        upto += 3;
        try e.waitHave(upto, 30_000);
        try e.waitMode(.core, 20_000);
        try e.waitTip(10_000);
        _ = try e.converge();
        try testing.expectEqual(@as(u64, 0), e.cv.certs.pending());
        try expectEqualToCore(&w, e, 0, upto);
        _ = scratch.reset(.retain_capacity);
    }
}

test "edge certificates: a core that answers a refetch with a certificate that does not verify, with another summary, or with bytes that do not decode is refused and counted; the mark stays and so does the edge's own certificate; an honest answer later is taken" {
    var w: World = undefined;
    try w.init(0xce47_0003);
    defer w.deinit();
    try w.publish(10);
    try w.coreUp();
    const e = try Edge.create(&w, .{ .name = "badcore" });
    defer e.destroy();
    try e.follow();
    try e.waitHave(10, 20_000);
    w.link.down.store(true, .release);
    try w.publish(30);
    try e.waitMode(.fallback, 10_000);
    try e.waitHave(30, 20_000);
    w.link.down.store(false, .release);
    try e.waitMode(.core, 20_000);
    try w.publish(34);
    try e.waitHave(34, 20_000);
    try e.waitTip(10_000);
    try testing.expectEqual(@as(u64, 20), e.cv.certs.pending());
    var scratch = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();
    const a = scratch.allocator();

    // The core's feed was honest; its `get_checkpoint` now lies for four checkpoints (the
    // core's own certificate table makes its store serve these bytes):
    const cps = w.chain.cps;
    //  29: another checkpoint's certified summary: a valid certificate over another summary
    const other_summary = try w.coreCert(a, 28);
    //  28: the right summary, one bit of the aggregate signature flipped
    const bad_sig = try w.coreCert(a, 28);
    bad_sig[cps[28].summary.len + 8 + 20] ^= 0x01;
    //  27: the right summary, signed by nobody (a real signature, an empty signers bitmap)
    const no_signers = try concat(a, &.{ cps[27].summary, try Chain.encodeSigInfo(a, cps[27].epoch, cps[27].sig[8..56].*, &.{}) });
    //  26: the right certificate with a byte after it
    const trailing = try concat(a, &.{ try w.coreCert(a, 26), &.{0} });
    const lies = [_]struct { seq: u64, bytes: []const u8 }{ .{ .seq = 29, .bytes = other_summary }, .{ .seq = 28, .bytes = bad_sig }, .{ .seq = 27, .bytes = no_signers }, .{ .seq = 26, .bytes = trailing } };
    for (lies) |l| _ = try w.core.st.cert_fix.put(l.seq, &store.certFixKey(l.seq), l.bytes);

    // the first call asks 29..14: four refused, twelve taken; the call counts as failed (the
    // loop backs off)
    try testing.expectEqual(certs_mod.Pace.Outcome.failed, e.cv.step());
    const st = &e.cv.certs.stats;
    try testing.expectEqual(@as(u64, 1), st.errors[@intFromEnum(certs_mod.ErrKind.summary_mismatch)].load(.monotonic));
    try testing.expectEqual(@as(u64, 2), st.errors[@intFromEnum(certs_mod.ErrKind.bad_certificate)].load(.monotonic));
    try testing.expectEqual(@as(u64, 1), st.errors[@intFromEnum(certs_mod.ErrKind.decode)].load(.monotonic));
    try testing.expectEqual(@as(u64, 12), st.replaced.load(.monotonic));
    try testing.expectEqual(@as(u64, 8), e.cv.certs.pending());
    // the refused ones are left alone for a while: the next call takes the rest
    try testing.expectEqual(certs_mod.Pace.Outcome.clean, e.cv.step());
    try testing.expectEqual(@as(u64, 4), e.cv.certs.pending());
    try testing.expectEqual(certs_mod.Pace.Outcome.idle, e.cv.step());
    // marks kept, the edge's own (the bucket's) certificate untouched, nothing overwritten
    for (lies) |l| {
        try testing.expect(e.cv.certs.isMarked(l.seq));
        try testing.expectEqualSlices(u8, try w.bucketCert(a, l.seq), try e.cert(a, l.seq));
    }
    try testing.expectEqual(@as(usize, 16), e.st.cert_fix.count());
    // and a read of those certificates still goes to the core (whatever it says is its answer)
    try e.healthy();
    const before = e.fwd.metrics.methods[@intFromEnum(route.Method.get_checkpoint)].forwarded[@intFromEnum(route.Reason.foreign_cert)].load(.monotonic);
    _ = try loopback.unary(a, e.fwd.handler(), p_checkpoint, try checkpointReq(a, 27, null, "signature"));
    try testing.expectEqual(before + 1, e.fwd.metrics.methods[@intFromEnum(route.Method.get_checkpoint)].forwarded[@intFromEnum(route.Reason.foreign_cert)].load(.monotonic));

    // A core that lies or errs is still the core: its answer goes out, and the edge does not
    // put its own certificate in its place. Only a failure of the connection does that.
    {
        const body = try checkpointReq(a, 28, null, "signature");
        // the lie, relayed as it is (gRPC and zui/1)
        const lie = try loopback.unary(a, w.core.svc.handler(), p_checkpoint, body);
        try testing.expect(sameReply(lie, try loopback.unary(a, e.fwd.handler(), p_checkpoint, body)));
        native.dispatch.may_block = true;
        try testing.expectEqualSlices(u8, try nativeCheckpoint(a, &w.core.disp, 28, 0), try nativeCheckpoint(a, &e.disp, 28, 0));
        native.dispatch.may_block = false;
        // the core's own error, relayed as it is
        e.up.set(.core_error);
        const erred = try loopback.unary(a, e.fwd.handler(), p_checkpoint, body);
        try testing.expectEqual(@as(u8, 13), erred.status);
        try testing.expectEqualStrings("the core's own failure", erred.grpc_message);
        try testing.expect(!e.fwd.upstreamDown());
        try testing.expectEqual(@as(u64, 0), e.held(.grpc) + e.held(.zui1) + e.held(.proof));
        // the connection fails: now, and only now, the certificate the edge holds
        e.up.set(.down);
        const mine = try loopback.unary(a, e.fwd.handler(), p_checkpoint, body);
        try testing.expectEqual(@as(u8, 0), mine.status);
        try testing.expect(!sameReply(lie, mine));
        try testing.expect(e.fwd.upstreamDown());
        try testing.expectEqual(@as(u64, 1), e.held(.grpc));
        e.up.set(.up);
        e.fwd.refreshFloor(h2.meta.monoNs());
        try testing.expect(!e.fwd.upstreamDown());
        try testing.expect(sameReply(lie, try loopback.unary(a, e.fwd.handler(), p_checkpoint, body)));
        try testing.expectEqual(@as(u64, 1), e.held(.grpc));
    }

    // the core is honest again; when their time comes the four are asked again and taken
    for (lies) |l| _ = try w.core.st.cert_fix.put(l.seq, &store.certFixKey(l.seq), try w.coreCert(a, l.seq));
    e.cv.certs.deferred.expire(std.math.maxInt(u64), 0);
    _ = try e.converge();
    try testing.expectEqual(@as(u64, 20), st.replaced.load(.monotonic));
    try expectEqualToCore(&w, e, 0, 34);
}

test "edge certificates: an edge that starts from the bucket (as after a snapshot restore, no core reachable) marks all of it and converges once it attaches to a core; a store without its log is checked in full" {
    var w: World = undefined;
    try w.init(0xce47_0004);
    defer w.deinit();
    // the core holds the chain and is not reachable; the bucket has 20..69 (across the end of
    // epoch 0 at checkpoint 49)
    try w.core.advance(w.chain, 70);
    w.bucket_have = 20;
    try w.publishBucket(70);
    try w.coreUp();
    w.link.down.store(true, .release);
    {
        const e = try Edge.create(&w, .{ .name = "restore", .first = 20, .restored = true });
        defer e.destroy();
        // the restored checkpoint (19) is not served over gRPC, but the edge holds it with the
        // bucket's certificate and zui/1 reads it: marked at this first start
        try testing.expectEqual(@as(u64, 1), e.cv.certs.pending());
        try testing.expect(e.cv.certs.isMarked(19));
        {
            var snap = e.st.snapshot();
            defer snap.release();
            try testing.expectEqual(@as(?u64, 20), snap.lowestAvailable());
        }
        try e.follow();
        try e.waitMode(.fallback, 10_000);
        try e.waitHave(70, 30_000);
        try testing.expectEqual(@as(u64, 51), e.cv.certs.pending());
        try testing.expectEqual(@as(u64, 0), e.fb.sw.stats.from_core.load(.monotonic));
        // on its fallback the edge does not ask (there is no core to ask)
        try testing.expectEqual(certs_mod.Gate.on_fallback, e.cv.gate());
        try testing.expectEqual(certs_mod.Pace.Outcome.idle, e.cv.step());
        try testing.expectEqual(@as(u64, 0), e.cv.certs.stats.batches.load(.monotonic));
        // a core appears: the edge attaches, follows it, and the marks go
        w.link.down.store(false, .release);
        try e.waitMode(.core, 20_000);
        try w.publish(74);
        try e.waitHave(74, 20_000);
        try e.waitTip(10_000);
        _ = try e.converge();
        try testing.expectEqual(@as(u64, 51), e.cv.certs.stats.replaced.load(.monotonic));
        try expectEqualToCore(&w, e, 20, 74);
        var scratch = std.heap.ArenaAllocator.init(testing.allocator);
        defer scratch.deinit();
        try testing.expectEqualSlices(u8, try w.coreCert(scratch.allocator(), 19), try e.cert(scratch.allocator(), 19));
    }
    // The same store without its log (an edge from before the log existed): nothing says which
    // certificates are the core's, so all are marked, asked about and found equal. The
    // certificates the log held are gone with it: the store serves the bucket's again for
    // 19..69, and those are replaced again.
    try w.tmp.dir.deleteFile(io, "restore/" ++ certs_mod.log_name);
    const e = try Edge.create(&w, .{ .name = "restore", .first = 20, .restored = true });
    defer e.destroy();
    try testing.expectEqual(@as(u64, 55), e.cv.certs.pending());
    for (19..74) |s| try testing.expect(e.cv.certs.isMarked(s));
    try e.follow();
    try w.publish(78);
    try e.waitHave(78, 20_000);
    try e.waitMode(.core, 20_000);
    try e.waitTip(10_000);
    _ = try e.converge();
    const st = &e.cv.certs.stats;
    try testing.expectEqual(@as(u64, 51), st.replaced.load(.monotonic));
    try testing.expectEqual(@as(u64, 4), st.equal.load(.monotonic));
    try expectEqualToCore(&w, e, 20, 78);
}

/// A stand-in for an edge's marks at the zui/1 dispatcher: everything marked, a core that can
/// or cannot be reached, a forward that answers `core_says` or finds no core.
const FakeMarks = struct {
    reachable: bool = true,
    core_answers: bool = true,
    core_says: []const u8 = "",
    forwards: u32 = 0,
    held_checkpoint: u32 = 0,
    held_proof: u32 = 0,
    pending: Atomic(u64) = .init(1),

    fn hook(m: *FakeMarks) native.dispatch.Foreign {
        return .{ .ctx = m, .pending = &m.pending, .marked = marked, .reachable = canReach, .forward = forwardFn, .held = heldFn };
    }
    fn of(ctx: *anyopaque) *FakeMarks {
        return @ptrCast(@alignCast(ctx));
    }
    fn marked(_: *anyopaque, _: u64) bool {
        return true;
    }
    fn canReach(ctx: *anyopaque) bool {
        return of(ctx).reachable;
    }
    fn forwardFn(ctx: *anyopaque, a: std.mem.Allocator, _: native.proto.Request, out: *std.ArrayList(u8)) bool {
        const m = of(ctx);
        m.forwards += 1;
        if (!m.core_answers) return false;
        out.clearRetainingCapacity();
        out.appendSlice(a, m.core_says) catch return false;
        return true;
    }
    fn heldFn(ctx: *anyopaque, proof: bool) void {
        const m = of(ctx);
        if (proof) m.held_proof += 1 else m.held_checkpoint += 1;
    }
};

test "edge certificates, zui/1 verified reads: the proof of an object written in a marked checkpoint is the core's answer while a core can be asked, and the edge's own (with the certificate it holds, counted as a proof) when none can; a core's own error is passed on; the feed is withheld either way" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    try w.core.advance(fx.first + 1);
    var scratch = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();
    const a = scratch.allocator();
    // an object the first checkpoint wrote: its proof is that checkpoint's certified summary
    const blob = try fx.readSeq(a, w.core.chk, fx.first, ".chk");
    const cp = try bcs.decode(types.CheckpointData, a, blob[1..]);
    const obj = for (cp.transactions) |*t| {
        if (t.output_objects.len > 0) break &t.output_objects[0];
    } else return error.SkipZigTest;
    const id: [32]u8, const version: u64 = switch (obj.data) {
        .Move => |m| .{ m.contents[0..32].*, m.version.@"0" },
        .Package => |pk| .{ pk.id.@"0".@"0", pk.version.@"0" },
    };
    var body: std.ArrayList(u8) = .empty;
    const bw: native.proto.W = .{ .gpa = a, .out = &body };
    try bw.fixed(&id);
    try bw.u8_(1);
    try bw.int(u64, version);
    const verified: native.proto.Request = .{ .method = .get_object, .flags = native.proto.flag_verify, .body = body.items };
    const unverified: native.proto.Request = .{ .method = .get_object, .flags = 0, .body = body.items };
    const disp = &w.core.disp;
    disp.edge = &w.core.feeder;
    const Ask = struct {
        fn of(d: *native.dispatch.Dispatcher, arena: std.mem.Allocator, req: native.proto.Request) ![]const u8 {
            var out: std.ArrayList(u8) = .empty;
            d.handle(arena, req, null, &out);
            return arena.dupe(u8, out.items);
        }
    };
    // the node's own answers (no marks): a proof with the certified summary in it
    const own = try Ask.of(disp, a, verified);
    const own_plain = try Ask.of(disp, a, unverified);
    try testing.expectEqual(@as(u8, 0), own[0]);
    try testing.expect(own.len > own_plain.len + 200);
    {
        var snap = w.core.st.snapshot();
        defer snap.release();
        try testing.expect(std.mem.indexOf(u8, own, snap.checkpoint(fx.first).?.summary_cert) != null);
    }

    var marks: FakeMarks = .{ .core_says = "\x00\x00the core's answer" };
    disp.foreign = marks.hook();
    defer disp.foreign = null;
    native.dispatch.may_block = true;
    defer native.dispatch.may_block = false;
    // a core can be asked: the verified read runs on a worker and is passed on
    try testing.expect(disp.offThread(verified));
    try testing.expect(!disp.offThread(unverified));
    try testing.expectEqualStrings(marks.core_says, try Ask.of(disp, a, verified));
    try testing.expectEqual(@as(u32, 1), marks.forwards);
    // without a proof nothing of a certificate is in the answer: the node's own, never passed on
    try testing.expectEqualSlices(u8, own_plain, try Ask.of(disp, a, unverified));
    try testing.expectEqual(@as(u32, 1), marks.forwards);
    // the core answers with its own error: that is the answer
    marks.core_says = "\x0a\x00the core's own error";
    try testing.expectEqualStrings(marks.core_says, try Ask.of(disp, a, verified));
    try testing.expectEqual(@as(u32, 0), marks.held_proof);
    // the forward finds no core (a connection-class failure): the node's own answer, counted
    marks.core_answers = false;
    try testing.expectEqualSlices(u8, own, try Ask.of(disp, a, verified));
    try testing.expectEqual(@as(u32, 3), marks.forwards);
    try testing.expectEqual(@as(u32, 1), marks.held_proof);
    // the edge is on its fallback: no core is tried, nothing waits, the node's own answer
    marks.reachable = false;
    try testing.expect(!disp.offThread(verified));
    native.dispatch.may_block = false;
    try testing.expectEqualSlices(u8, own, try Ask.of(disp, a, verified));
    try testing.expectEqual(@as(u32, 3), marks.forwards);
    try testing.expectEqual(@as(u32, 2), marks.held_proof);
    try testing.expectEqual(@as(u32, 0), marks.held_checkpoint);
    // a checkpoint is counted as a checkpoint
    const own_cp = blk: {
        disp.foreign = null;
        defer disp.foreign = marks.hook();
        break :blk try nativeCheckpoint(a, disp, fx.first, 0);
    };
    try testing.expectEqualSlices(u8, own_cp, try nativeCheckpoint(a, disp, fx.first, 0));
    try testing.expectEqual(@as(u32, 1), marks.held_checkpoint);
    try testing.expectEqual(@as(u64, 3), disp.foreign_stats.held.load(.monotonic));
    // the feed of a marked checkpoint: "not held yet", with a core reachable and without
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, try nativeFeed(a, disp, fx.first));
    marks.reachable = true;
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, try nativeFeed(a, disp, fx.first));
    try testing.expectEqual(@as(u64, 2), disp.foreign_stats.feed_withheld.load(.monotonic));
    // a subscription about to push it: ended while a core can be asked, served (and counted)
    // when none can
    try testing.expect(disp.withholdSeq(fx.first));
    marks.reachable = false;
    try testing.expect(!disp.withholdSeq(fx.first));
    try testing.expectEqual(@as(u32, 2), marks.held_checkpoint);
}
