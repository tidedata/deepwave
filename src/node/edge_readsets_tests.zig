//! Read sets through the edge feed (docs/EDGE.md section 12): a core with real read sets, edges
//! built from its feed, and the reads that need a transaction's object set answered by the edge
//! itself and compared with the core.
//!
//! The fixture, and what it can and cannot show.
//!
//! - The checkpoints are the corpus' archive protos (`$ZUI_CORPUS/binpb-done`, the bucket's own
//!   format), converted the way a `--source http` node converts them: a blob with its modified
//!   inputs and an aux record with every other object the transactions read and each
//!   transaction's loaded runtime object list as sui-node recorded it. Nothing about a read set
//!   here is made up.
//! - The core is a follower over those blobs with `history.History` on its batch hook: the very
//!   code a node with read sets runs (certificates, digests, outputs against effects, then the
//!   read set into the same batch), with `--edge-read-sets on` (it marks its checkpoints).
//! - Both stores start from the same base, standing in for the formal snapshot a real core and
//!   a real edge restore: every object the window reads at a version the window did not write,
//!   live, in the epoch before the window. It is the part of the live set the window touches,
//!   not the whole live set (about 5 GB of objects the corpus does not carry), and it sits in a
//!   store with two epochs of retention, so nothing here ages out: the xref rows are written
//!   and read, never followed into a cleaned segment (the store lane's own tests do that).
//! - A read of a version that is neither a window output nor its object's base version (the
//!   prep counts them as `stale`) is held by the core, from the archive, and not by the edge;
//!   the edge then leaves that checkpoint without its mark and forwards its reads.
//! - `json` and `display` are off and neither node has indexes, an executor or a name service,
//!   as in the forwarding conformance test. It is a sample: `ZUI_EDGE_RS_COUNT` checkpoints of
//!   the dense window (default 24), every `ZUI_EDGE_RS_STRIDE`-th transaction (default 2).
//!
//! Needs the corpus (`$ZUI_CORPUS`); skips without it.
//!
//! The archive mode (a test machine's run of the conformance test). With `ZUI_EDGE_RS_ARCHIVE` set to a
//! directory of archive protos (`<seq>.binpb.zst`, the full archive form of the checkpoints), the conformance test takes its window from there instead of the
//! corpus sample: `ZUI_EDGE_RS_START` (first checkpoint; default the corpus window's),
//! `ZUI_EDGE_RS_COUNT` checkpoints, every `ZUI_EDGE_RS_STRIDE`-th transaction. Everything about
//! a read set is then the archive's: each transaction's loaded list and every input object come
//! from those protos, as in the default run, and nothing is synthetic. It still needs
//! `$ZUI_CORPUS` for the request masks (`vectors/grpc-v2*/masks*.txt`), `epochs.jsonl` and the
//! last checkpoint of the epoch before the window (`chk/<seq>.chk`, the committee). In this mode
//! nothing skips: a checkpoint of the window missing from the directory, a missing corpus file
//! or a window that crosses an epoch end is a failure with its reason printed. One window must
//! fit the fixture's stores (`fx.store_cfg`: 4,096 checkpoints, 131,072 transactions and live
//! objects); for more coverage run more windows. The other tests of this file are not affected.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const Atomic = std.atomic.Value;
const bcs = @import("bcs");
const store = @import("store");
const types = @import("types");
const sync = @import("sync");
const serve = @import("serve");
const edge = @import("edge");
const native = @import("native");
const edgewire = @import("edgewire");
const index = @import("index");
const exec = @import("exec");
const protocol = @import("protocol");
const rpc_exec = @import("rpc_exec");
const node_rpc = @import("rpc.zig");
const history = @import("history.zig");
const convert = @import("convert.zig");
const source_mod = @import("source.zig");
const fx = @import("edge_fallback_tests.zig");

const io = testing.io;
const h2 = serve.h2;
const proto = serve.proto;
const loopback = serve.loopback;
const service = serve.service;
const forward = edge.forward;
const route = edge.route;
const sys = std.heap.smp_allocator;
const ms: u64 = std.time.ns_per_ms;

/// The window's first checkpoint and its epoch: the corpus window's, except while the
/// conformance test runs in the archive mode (it puts them back when it ends).
var first: u64 = fx.first;
var first_epoch: u64 = fx.epoch;
/// The archive mode's directory of `<seq>.binpb.zst` (null: the corpus' `binpb-done`).
var archive: ?Io.Dir = null;

/// One archive proto of the window. In the archive mode a missing one fails the test.
fn readProto(a: std.mem.Allocator, dir: Io.Dir, seq: u64) ![]u8 {
    if (archive == null) return fx.readSeq(a, dir, seq, ".binpb.zst");
    var nb: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&nb, "{d}.binpb.zst", .{seq});
    return dir.readFileAlloc(io, name, a, .limited(1 << 30)) catch |e| {
        std.debug.print("edge-readsets: ZUI_EDGE_RS_ARCHIVE has no readable {s} ({s}); the window starts at {d}\n", .{ name, @errorName(e), first });
        return error.ArchiveCheckpointMissing;
    };
}

/// The committee of the epoch that holds `start`, from the end-of-epoch checkpoint before it
/// (`fx.committee`, for any epoch), and that epoch. `count` checkpoints from `start` must end
/// inside it: the fixture's stores and followers are set up for one epoch.
fn windowCommittee(a: std.mem.Allocator, start: u64, count: u64) !struct { epoch: u64, committee: sync.Committee } {
    var pb: [512]u8 = undefined;
    const idx = try fx.trust.EpochIndex.load(a, io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{try fx.corpus()}));
    const epoch: u64 = for (idx.first, idx.last, 0..) |f, l, e| {
        const lo = f orelse continue;
        if (start >= lo and (l == null or start <= l.?)) break e;
    } else {
        std.debug.print("edge-readsets: no epoch of $ZUI_CORPUS/epochs.jsonl holds checkpoint {d}\n", .{start});
        return error.WindowEpochUnknown;
    };
    if (idx.last[epoch]) |l| if (start + count - 1 > l) {
        std.debug.print("edge-readsets: the window {d}..{d} crosses the end of epoch {d} at {d}; one window stays inside one epoch\n", .{ start, start + count - 1, epoch, l });
        return error.WindowCrossesEpoch;
    };
    const eoe = (if (epoch == 0) null else idx.last[epoch - 1]) orelse {
        std.debug.print("edge-readsets: epochs.jsonl has no last checkpoint for epoch {d}\n", .{epoch -| 1});
        return error.WindowEpochUnknown;
    };
    const chk = try fx.corpusDir("chk");
    defer chk.close(io);
    var nb: [64]u8 = undefined;
    const blob = chk.readFileAlloc(io, try std.fmt.bufPrint(&nb, "{d}.chk", .{eoe}), a, .limited(1 << 30)) catch |e| {
        std.debug.print("edge-readsets: $ZUI_CORPUS/chk/{d}.chk (the end of epoch {d}, for the committee): {s}\n", .{ eoe, epoch - 1, @errorName(e) });
        return error.WindowCommitteeMissing;
    };
    const cert = try fx.trust.blobCert(blob);
    const sum = try fx.checkpoint.Summary.parse(cert.summary);
    const cm = try fx.checkpoint.nextCommittee(a, sum);
    const info = try fx.trust.EpochInfo.fromCheckpoint(a, &cm, sum.next_protocol_version);
    return .{ .epoch = epoch, .committee = try info.syncCommittee(a) };
}

const ledger = "/sui.rpc.v2.LedgerService/";
const p_checkpoint = ledger ++ "GetCheckpoint";
const p_tx = ledger ++ "GetTransaction";
const p_txs = ledger ++ "BatchGetTransactions";

fn envU(name: [*:0]const u8, default: u64) u64 {
    const p = std.c.getenv(name) orelse return default;
    return std.fmt.parseInt(u64, std.mem.span(p), 10) catch default;
}

// ------------------------------------------------------------------ the window

const BaseObj = struct { id: [32]u8, version: u64, raw: []const u8 };

/// `count` corpus checkpoints as a bucket source hands them to a node, and the base they need.
const Window = struct {
    /// `<seq>.chk` (blob with its modified inputs) and `<seq>.aux` (the archive's other objects
    /// and loaded lists): a directory source with real read sets.
    dir: Io.Dir,
    base: []const BaseObj,
    /// Reads of a version that is neither written in the window nor its object's base version.
    stale: u64 = 0,
    /// Transactions with a non-empty loaded list, and their entries.
    listed: u64 = 0,
    entries: u64 = 0,
    transactions: u64 = 0,

    fn prepare(a: std.mem.Allocator, root: Io.Dir, name: []const u8, count: u64) !Window {
        try root.createDirPath(io, name);
        var w: Window = .{ .dir = try root.openDir(io, name, .{}), .base = &.{} };
        const protos = archive orelse try fx.corpusDir("binpb-done");
        defer if (archive == null) protos.close(io);
        var idx = try types.index.CheckpointIndex.init(testing.allocator);
        defer idx.deinit(testing.allocator);
        // one checkpoint at a time: only the output keys and the base objects are kept
        var scratch = std.heap.ArenaAllocator.init(testing.allocator);
        defer scratch.deinit();
        var outs: std.AutoHashMapUnmanaged([40]u8, void) = .empty;
        var nb: [64]u8 = undefined;
        for (0..@intCast(count)) |i| {
            _ = scratch.reset(.retain_capacity);
            const sa = scratch.allocator();
            const seq = first + i;
            const zst = try readProto(sa, protos, seq);
            const pb = try convert.unzstdArena(sa, zst, source_mod.max_blob);
            var blob: std.ArrayList(u8) = .empty;
            defer blob.deinit(testing.allocator);
            var aux: std.ArrayList(u8) = .empty;
            defer aux.deinit(testing.allocator);
            try testing.expectEqual(seq, try convert.protoToChkAux(testing.allocator, sa, pb, &blob, &aux));
            try w.dir.writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.aux", .{seq}), .data = aux.items });
            try w.dir.writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.chk", .{seq}), .data = blob.items });
            try types.index.indexCheckpointData(blob.items, &idx);
            for (0..idx.tx_count) |k| {
                const t = idx.txAt(k);
                for (idx.objs[t.out_first..][0..t.out_count]) |r| try outs.put(a, try serve.objset.headKey(r.slice(blob.items)), {});
            }
        }
        // The base: for each object, the first version read that the window did not write, unless
        // the window had written the object by then.
        var seen: std.AutoHashMapUnmanaged([32]u8, u64) = .empty;
        var base: std.ArrayList(BaseObj) = .empty;
        for (0..@intCast(count)) |i| {
            _ = scratch.reset(.retain_capacity);
            const sa = scratch.allocator();
            const blob = try fx.readSeq(sa, w.dir, first + i, ".chk");
            const aux = try fx.readSeq(sa, w.dir, first + i, ".aux");
            try types.index.indexCheckpointData(blob, &idx);
            const x = try convert.Aux.parse(sa, aux);
            w.transactions += idx.tx_count;
            for (x.loaded) |l| {
                if (l.len > 0) w.listed += 1;
                w.entries += l.len;
            }
            var reads: std.ArrayList([]const u8) = .empty;
            for (0..idx.tx_count) |k| {
                const t = idx.txAt(k);
                for (idx.objs[t.in_first..][0..t.in_count]) |r| try reads.append(sa, r.slice(blob));
            }
            try reads.appendSlice(sa, x.objects);
            for (reads.items) |raw| {
                const key = try serve.objset.headKey(raw);
                if (outs.contains(key)) continue;
                const id = key[0..32].*;
                const version = std.mem.readInt(u64, key[32..40], .little);
                if (seen.get(id)) |have| {
                    if (have != version) w.stale += 1;
                    continue;
                }
                try seen.put(a, id, version);
                try base.append(a, .{ .id = id, .version = version, .raw = try a.dupe(u8, raw) });
            }
            for (0..idx.tx_count) |k| {
                const t = idx.txAt(k);
                for (idx.objs[t.out_first..][0..t.out_count]) |r| {
                    const key = try serve.objset.headKey(r.slice(blob));
                    const gop = try seen.getOrPut(a, key[0..32].*);
                    if (!gop.found_existing) gop.value_ptr.* = std.math.maxInt(u64);
                }
            }
        }
        w.base = base.items;
        return w;
    }

    /// The base into an empty store: live objects of the epoch before the window, as a formal
    /// snapshot restore leaves them. `extra`: more live objects (a test's own).
    fn restore(w: *const Window, st: *store.Store, extra: []const BaseObj) !void {
        const b = try st.begin(first - 1, first_epoch - 1);
        errdefer st.abort(b);
        for ([_][]const BaseObj{ w.base, extra }) |set| for (set) |o| try b.putObject(&o.id, o.version, &types.digest.objectDigest(o.raw), o.raw);
        try st.commit(b);
    }
};

// ------------------------------------------------------------------ a node with read sets

/// A follower over a spool with `history.History` on its batch hook: what node.zig wires for a
/// node with read sets, on a core (the full path) or on an edge (`History.edge`).
const ReadSets = struct {
    st: *store.Store,
    h: history.History,
    /// The edge fixture's own observer, when this wraps one.
    inner: ?*fx.Edge = null,
    /// Time spent in the batch hook, and checkpoints it saw.
    hook_ns: Atomic(u64) = .init(0),
    batches: Atomic(u64) = .init(0),

    fn onCheckpoint(ctx: *anyopaque, seq: u64, c: *const sync.verify.Checked, blob: []const u8) void {
        const r: *ReadSets = @ptrCast(@alignCast(ctx));
        if (r.inner) |e| fx.Edge.onCheckpoint(e, seq, c, blob);
    }
    fn onBatch(ctx: *anyopaque, seq: u64, c: *const sync.verify.Checked, blob: []const u8, b: *store.Batch) anyerror!void {
        const r: *ReadSets = @ptrCast(@alignCast(ctx));
        const t0 = fx.nowNs();
        try r.h.onBatch(r.st, seq, c, blob, b);
        _ = r.hook_ns.fetchAdd(fx.nowNs() - t0, .monotonic);
        _ = r.batches.fetchAdd(1, .monotonic);
    }
    fn loaded(_: *const anyopaque, snap: *const store.Snapshot, digest: *const [32]u8, at: u64) []const serve.objset.Ref {
        return history.loadedListNear(serve.objset.Ref, snap, digest, at);
    }
    fn held(_: *const anyopaque, snap: *const store.Snapshot, seq: u64) bool {
        return history.readSetHeld(snap, seq);
    }
    /// The service hooks node.zig installs for a node with `--edge-read-sets on`.
    fn serveFrom(svc: *service.Service) void {
        svc.loaded = .{ .ctx = svc, .get = loaded };
        svc.read_sets = .{ .ctx = svc, .has = held };
    }
};

/// The core: `fx.Core`'s store, service and zui/1 listener, filled by a follower with read sets.
const Core = struct {
    c: *fx.Core,
    rs: *ReadSets,
    arch: sync.archive.Archive,

    /// Applies the window's `count` checkpoints over its base.
    fn build(w: *fx.World, win: *const Window, count: u64, extra: []const BaseObj) !Core {
        const rs = try sys.create(ReadSets);
        rs.* = .{ .st = w.core.st, .h = try history.History.init(testing.allocator, io, win.dir) };
        rs.h.mark_read_sets = true;
        var core: Core = .{ .c = w.core, .rs = rs, .arch = .{ .dir = win.dir } };
        try win.restore(w.core.st, extra);
        try core.apply(w, first, count);
        w.core.svc.json = false;
        w.core.svc.display = false;
        w.core.svc.lowest_checkpoint = first;
        ReadSets.serveFrom(&w.core.svc);
        return core;
    }

    /// Applies the window's checkpoints `from .. first + count` (the store holds those before).
    fn apply(core: *Core, w: *fx.World, from: u64, count: u64) !void {
        const rs = core.rs;
        const f = try sync.Follower.init(testing.allocator, io, w.core.st, .{ .archive = &core.arch }, .{ .mode = .apply, .workers = 2, .window = 8, .poll_ms = 20 }, .{ .committee = w.committee, .first_seq = from });
        defer f.deinit();
        f.observer = .{ .ctx = rs, .on_checkpoint = ReadSets.onCheckpoint, .on_batch = ReadSets.onBatch };
        const Run = struct {
            fn main(fl: *sync.Follower, to: u64, err: *?anyerror) void {
                fl.run(to) catch |e| {
                    err.* = e;
                };
            }
        };
        var err: ?anyerror = null;
        const t = try std.Thread.spawn(.{}, Run.main, .{ f, first + count - 1, &err });
        const t0 = fx.nowNs();
        while (f.applied_next.load(.acquire) < first + count and err == null and fx.nowNs() - t0 < (120_000 + count * 2_000) * ms) fx.sleepMs(2);
        // the run ends by itself at its last checkpoint; a stop only on a timeout or an error
        if (f.applied_next.load(.acquire) < first + count) f.stop();
        t.join();
        try testing.expectEqual(@as(?anyerror, null), err);
        try testing.expectEqual(first + count, f.applied_next.load(.acquire));
        w.core.have = first + count - 1;
    }

    fn destroy(core: *Core) void {
        core.rs.h.deinit();
        sys.destroy(core.rs);
    }
};

/// An edge of `fx` that keeps read sets (`--edge-read-sets on`), or one that does not.
const EdgeNode = struct {
    e: *fx.Edge,
    rs: ?*ReadSets = null,

    fn create(w: *fx.World, win: *const Window, name: []const u8, read_sets: bool, fallback: ?Io.Dir, extra: []const BaseObj) !EdgeNode {
        const specs = [_]edge.client.Spec{w.link.spec(fx.Core.key())};
        const e = try fx.Edge.create(w.gpa, .{ .root = w.tmp.dir, .root_path = w.root_path, .name = name, .specs = &specs, .fallback = fallback, .tuning = fx.quick, .committee = w.committee });
        errdefer e.destroy();
        if (first != fx.first) {
            // The fixture anchors its follower and fetcher at the corpus window: move both to
            // this window (nothing has started yet), configured as `fx.Edge.create` does.
            e.follower.deinit();
            e.follower = try sync.Follower.init(w.gpa, io, e.st, .{ .archive = &e.arch }, .{ .mode = .apply, .workers = 2, .window = 8, .poll_ms = 50 }, .{ .committee = w.committee, .first_seq = first });
            e.follower.observer = .{ .ctx = e, .on_checkpoint = fx.Edge.onCheckpoint };
            if (e.fb) |fb| fb.applied_next = &e.follower.applied_next;
            e.fetcher.next = .init(first);
            e.fetcher.applied_next = &e.follower.applied_next;
            e.fetcher.on_spooled = .{ .ctx = e.follower, .call = fx.Edge.spooled };
        }
        try win.restore(e.st, extra);
        var n: EdgeNode = .{ .e = e };
        if (read_sets) {
            // as node.zig for `--source zui1:` with `--edge-read-sets on`
            e.pool.read_sets = true;
            e.src.edge_read_sets = true;
            const rs = try sys.create(ReadSets);
            rs.* = .{ .st = e.st, .h = try history.History.init(testing.allocator, io, e.spool), .inner = e };
            rs.h.edge = true;
            rs.h.mark_read_sets = true;
            e.follower.observer = .{ .ctx = rs, .on_checkpoint = ReadSets.onCheckpoint, .on_batch = ReadSets.onBatch };
            n.rs = rs;
        }
        return n;
    }

    fn destroy(n: *EdgeNode) void {
        n.e.destroy();
        if (n.rs) |rs| {
            rs.h.deinit();
            sys.destroy(rs);
        }
    }

    /// The follower applied `count` checkpoints of the window (`fx.Edge.waitCommitted`, for
    /// any window start).
    fn waitApplied(n: *const EdgeNode, count: u64, limit_ms: u64) bool {
        const t0 = fx.nowNs();
        while (n.e.follower.applied_next.load(.acquire) < first + count) {
            if (n.e.run_err != null or fx.nowNs() - t0 > limit_ms * ms) return false;
            fx.sleepMs(2);
        }
        return true;
    }

    fn marks(n: *const EdgeNode, count: u64) u64 {
        var snap = n.e.st.snapshot();
        defer snap.release();
        var k: u64 = 0;
        for (0..count) |i| k += @intFromBool(history.readSetHeld(&snap, first + i));
        return k;
    }
};

// ------------------------------------------------------------------ requests and the diff

/// A node's sui.rpc.v2 port on loopback (the forwarder's upstream).
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

fn maskInto(w: *proto.Writer, field: u32, mask: ?[]const u8) !void {
    const text = mask orelse return;
    const m = try w.begin(field, 256);
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |p| if (p.len > 0) try w.string(1, p);
    try w.end(m);
}

const Req = struct {
    a: std.mem.Allocator,

    fn writer(r: Req) !proto.Writer {
        return proto.Writer.init(try r.a.alloc(u8, 64 << 10));
    }
    fn checkpoint(r: Req, seq: ?u64, mask: ?[]const u8) ![]const u8 {
        var w = try r.writer();
        if (seq) |s| try w.uint(1, s);
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
};

fn sameReply(x: loopback.Reply, y: loopback.Reply) bool {
    return x.status == y.status and std.mem.eql(u8, x.message, y.message) and std.mem.eql(u8, x.grpc_message, y.grpc_message) and std.mem.eql(u8, x.details, y.details);
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

/// How one request was routed by the forwarder under test.
const Routed = enum { local, forwarded, own };

/// Requests to the core's handler and to the edge's forwarding handler, compared.
const Diff = struct {
    arena: std.heap.ArenaAllocator,
    core_h: h2.Handler,
    edge_h: h2.Handler,
    fwd: *forward.Forwarder,
    total: u64 = 0,
    differences: u64 = 0,
    shown: u32 = 0,
    /// Differences are counted, not printed (a test that expects one).
    quiet: bool = false,
    local: u64 = 0,
    forwarded: u64 = 0,
    /// Requests under a mask that needs a transaction's object set: all, those the core
    /// answered with a success, those the edge answered itself, and those of them the core
    /// answered with a success (a local answer compared with data).
    set_asked: u64 = 0,
    set_core_ok: u64 = 0,
    set_local: u64 = 0,
    set_local_ok: u64 = 0,
    /// The core's first failure under such a mask.
    first_core_error: []const u8 = "",

    fn counts(d: *const Diff) [2]u64 {
        var l: u64 = 0;
        var fw: u64 = 0;
        for (&d.fwd.metrics.methods) |*pm| {
            l += pm.served_local.load(.monotonic);
            for (&pm.forwarded) |*c| fw += c.load(.monotonic);
        }
        return .{ l, fw };
    }

    fn check(d: *Diff, path: []const u8, body: []const u8, object_set: bool) !Routed {
        const a = d.arena.allocator();
        const want = try loopback.unary(a, d.core_h, path, body);
        const before = d.counts();
        const got = try loopback.unary(a, d.edge_h, path, body);
        const after = d.counts();
        d.total += 1;
        const how: Routed = if (after[0] > before[0]) .local else if (after[1] > before[1]) .forwarded else .own;
        switch (how) {
            .local => d.local += 1,
            .forwarded => d.forwarded += 1,
            .own => {},
        }
        if (object_set) {
            d.set_asked += 1;
            if (want.status == 0) d.set_core_ok += 1 else if (d.first_core_error.len == 0) {
                d.first_core_error = try sys.dupe(u8, want.grpc_message);
            }
            if (how == .local) {
                d.set_local += 1;
                if (want.status == 0) d.set_local_ok += 1;
            }
        }
        if (sameReply(want, got)) return how;
        d.differences += 1;
        if (d.shown < 12 and !d.quiet) {
            d.shown += 1;
            std.debug.print("edge-readsets DIFFERENCE {s} ({s}) request {x}\n  core: status {d} \"{s}\" {d} message bytes, {d} detail bytes\n  edge: status {d} \"{s}\" {d} message bytes, {d} detail bytes\n", .{ path, @tagName(how), body[0..@min(body.len, 96)], want.status, want.grpc_message, want.message.len, want.details.len, got.status, got.grpc_message, got.message.len, got.details.len });
        }
        return how;
    }
    fn round(d: *Diff) void {
        _ = d.arena.reset(.retain_capacity);
    }
    fn deinit(d: *Diff) void {
        if (d.first_core_error.len > 0) sys.free(d.first_core_error);
        d.arena.deinit();
    }
};

/// A forwarder in front of an edge's store, with the core's sui.rpc.v2 as its upstream.
const Front = struct {
    svc: service.Service,
    gt: forward.GrpcTransport,
    f: *forward.Forwarder,

    fn create(front: *Front, st: *store.Store, core_port: u16) !void {
        front.svc = .{ .gpa = testing.allocator, .store = st, .chain_id = @splat(0), .json = false, .display = false, .lowest_checkpoint = first };
        // (the loaded-list source is every node's; whether the store holds any is the question)
        front.svc.loaded = .{ .ctx = &front.svc, .get = ReadSets.loaded };
        front.gt = try forward.GrpcTransport.init(sys, io, .{ .host = "127.0.0.1", .port = core_port, .security = .plain });
        front.f = try forward.Forwarder.create(testing.allocator, io, &front.svc, front.gt.transport(), .{ .ahead_wait_ms = 30, .hold_ms = 20 });
        // a healthy edge at its core's tip, which knows its core's floor
        front.f.observe(h2.meta.monoNs(), .{ .lag = 0, .source_age_ns = 0 });
        fx.sleepMs(25);
        front.f.observe(h2.meta.monoNs(), .{ .lag = 0, .source_age_ns = 0 });
        try testing.expectEqual(route.GuardState.ok, front.f.guardState());
        front.f.refreshFloor(h2.meta.monoNs());
    }

    fn destroy(front: *Front) void {
        front.f.destroy();
        const conn = front.gt.up.conn;
        if (conn) |c| c.retain();
        front.gt.deinit();
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
        front.svc.deinit();
    }
};

const Tx = struct { digest: [32]u8, seq: u64, sigs: usize, loaded: usize };

/// The transactions of the first `count` checkpoints, from `st`.
fn windowTxs(a: std.mem.Allocator, st: *store.Store, count: u64) ![]Tx {
    var out: std.ArrayList(Tx) = .empty;
    var snap = st.snapshot();
    defer snap.release();
    for (0..count) |i| {
        const cp = snap.checkpoint(first + i) orelse return error.TestUnexpectedResult;
        for (try native.dispatch.contentDigests(a, cp.contents)) |dg| {
            const rec = snap.transaction(&dg) orelse return error.TestUnexpectedResult;
            const sp = try service.splitEnvelope(a, rec.tx);
            try out.append(a, .{ .digest = dg, .seq = first + i, .sigs = sp.sigs.len, .loaded = history.loadedList(serve.objset.Ref, &snap, &dg).len });
        }
    }
    return out.items;
}

/// Read mask paths that need a transaction's object set (docs/EDGE.md 11.3), on a transaction
/// and on a checkpoint. The second of each pair: the path also renders transaction signatures
/// (a transaction with two or more is forwarded for that, 10.3; not this lane's rule).
const tx_set_paths = [_]struct { []const u8, bool }{
    .{ "effects", false },                                  .{ "effects.status", false },
    .{ "effects.unchanged_loaded_runtime_objects", false }, .{ "effects.changed_objects", false },
    .{ "effects.unchanged_consensus_objects", false },      .{ "effects.gas_object", false },
    .{ "effects.bcs", false },                              .{ "balance_changes", false },
    .{ "objects", false },                                  .{ "objects.objects.bcs", false },
    .{ "digest,transaction,effects,events", false },        .{ "digest,effects,balance_changes,objects", false },
    .{ "*", true },
};
const cp_set_paths = [_]struct { []const u8, bool }{
    .{ "transactions.effects", false },                                  .{ "transactions.balance_changes", false },
    .{ "transactions.objects", false },                                  .{ "transactions.effects.unchanged_loaded_runtime_objects", false },
    .{ "objects", false },                                               .{ "objects.objects.bcs", false },
    .{ "sequence_number,digest,transactions.digest,transactions.effects", false }, .{ "transactions", true },
    .{ "*", true },
};

const Asked = struct {
    /// Object-set requests without signatures in the mask, and those answered locally.
    plain: u64 = 0,
    plain_local: u64 = 0,
    /// Object-set requests whose mask also renders signatures, and those answered locally.
    with_sigs: u64 = 0,
    with_sigs_local: u64 = 0,
    /// Per mask of `tx_set_paths`, `cp_set_paths` and `batch_masks`: asked, answered locally.
    tx: [tx_set_paths.len][2]u64 = @splat(.{ 0, 0 }),
    cp: [cp_set_paths.len][2]u64 = @splat(.{ 0, 0 }),
    batch: [batch_masks.len][2]u64 = @splat(.{ 0, 0 }),
};

/// Masks asked of each checkpoint's transactions as one BatchGetTransactions.
const batch_masks = [_][]const u8{ "effects", "digest,effects.status,balance_changes", "objects.objects.bcs" };

/// Calls forwarded so far, by reason (all methods).
fn forwardedByReason(f: *const forward.Forwarder) [route.Reason.count]u64 {
    var out: [route.Reason.count]u64 = @splat(0);
    for (&f.metrics.methods) |*pm| for (&pm.forwarded, 0..) |*c, i| {
        out[i] += c.load(.monotonic);
    };
    return out;
}

/// The request set of the gate: every mask of 11.3 on every `stride`-th transaction and on
/// every checkpoint, singly and as batches, then the grpc-v2 suite's own masks on the same.
fn askAll(d: *Diff, txs: []const Tx, count: u64, stride: usize, tx_masks: []const []const u8, cp_masks: []const []const u8) !Asked {
    const rq: Req = .{ .a = d.arena.allocator() };
    var n: Asked = .{};
    var i: usize = 0;
    while (i < txs.len) : (i += stride) {
        const t = &txs[i];
        for (tx_set_paths, 0..) |p, k| {
            const how = try d.check(p_tx, try rq.tx(&t.digest, p[0]), true);
            n.tx[k][0] += 1;
            n.tx[k][1] += @intFromBool(how == .local);
            if (p[1]) {
                n.with_sigs += 1;
                n.with_sigs_local += @intFromBool(how == .local);
            } else {
                n.plain += 1;
                n.plain_local += @intFromBool(how == .local);
            }
        }
        _ = try d.check(p_tx, try rq.tx(&t.digest, null), false);
        for (tx_masks) |m| _ = try d.check(p_tx, try rq.tx(&t.digest, m), needsSet(.transaction, m));
        d.round();
    }
    for (0..count) |c| {
        for (cp_set_paths, 0..) |p, k| {
            const how = try d.check(p_checkpoint, try rq.checkpoint(first + c, p[0]), true);
            n.cp[k][0] += 1;
            n.cp[k][1] += @intFromBool(how == .local);
            if (p[1]) {
                n.with_sigs += 1;
                n.with_sigs_local += @intFromBool(how == .local);
            } else {
                n.plain += 1;
                n.plain_local += @intFromBool(how == .local);
            }
        }
        _ = try d.check(p_checkpoint, try rq.checkpoint(first + c, null), false);
        for (cp_masks) |m| _ = try d.check(p_checkpoint, try rq.checkpoint(first + c, m), needsSet(.checkpoint, m));
        d.round();
    }
    // each checkpoint's transactions as one batch
    var batch: std.ArrayList([32]u8) = .empty;
    defer batch.deinit(sys);
    var at: usize = 0;
    while (at < txs.len) {
        batch.clearRetainingCapacity();
        const seq = txs[at].seq;
        while (at < txs.len and txs[at].seq == seq and batch.items.len < 200) : (at += 1) try batch.append(sys, txs[at].digest);
        for (batch_masks, 0..) |m, k| {
            const how = try d.check(p_txs, try rq.txs(batch.items, m), true);
            n.batch[k][0] += 1;
            n.batch[k][1] += @intFromBool(how == .local);
            n.plain += 1;
            n.plain_local += @intFromBool(how == .local);
        }
        d.round();
    }
    return n;
}

fn needsSet(kind: route.MaskOf, mask: []const u8) bool {
    var it = std.mem.splitScalar(u8, mask, ',');
    while (it.next()) |p| if (route.maskNeeds(kind, &[_][]const u8{p}).object_set) return true;
    return false;
}

// ------------------------------------------------------------------ the gate

test "edge read sets conformance: with read sets from the feed, transaction and checkpoint reads under effects, balance_changes and objects are answered by the edge and equal the core's" {
    // The archive mode (see the top of this file): the window comes from a directory of archive
    // protos and nothing skips.
    const archive_path: ?[]const u8 = if (std.c.getenv("ZUI_EDGE_RS_ARCHIVE")) |p| std.mem.span(p) else null;
    if (archive_path) |path| {
        archive = Io.Dir.cwd().openDir(io, path, .{}) catch |e| {
            std.debug.print("edge-readsets: ZUI_EDGE_RS_ARCHIVE={s}: {s}\n", .{ path, @errorName(e) });
            return error.ArchiveDirectoryUnreadable;
        };
        first = envU("ZUI_EDGE_RS_START", fx.first);
    }
    defer if (archive) |d| {
        d.close(io);
        archive = null;
        first = fx.first;
        first_epoch = fx.epoch;
    };
    conformance(archive_path) catch |e| {
        if (e == error.SkipZigTest and archive_path != null) {
            std.debug.print("edge-readsets: the archive mode needs $ZUI_CORPUS (vectors/grpc-v2/masks.txt, vectors/grpc-v2-tx/masks.txt, epochs.jsonl, chk/): something there is missing\n", .{});
            return error.ArchiveModeInputMissing;
        }
        return e;
    };
}

fn conformance(archive_path: ?[]const u8) !void {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const count = envU("ZUI_EDGE_RS_COUNT", 24);
    const stride: usize = @intCast(@max(1, envU("ZUI_EDGE_RS_STRIDE", 2)));
    const a = w.arena.allocator();
    const cp_masks = try masksFile(a, "grpc-v2/masks.txt");
    const tx_masks = try masksFile(a, "grpc-v2-tx/masks.txt");
    if (archive_path != null) {
        if (count == 0) return error.ArchiveWindowEmpty;
        const wc = try windowCommittee(a, first, count);
        first_epoch = wc.epoch;
        w.committee = wc.committee;
    }

    const win = try Window.prepare(a, w.tmp.dir, "window", count);
    defer win.dir.close(io);
    var core = try Core.build(&w, &win, count, &.{});
    defer core.destroy();
    w.core.feeder.read_sets = &w.core.svc;
    try w.coreUp(true);
    const core_rpc = try Rpc.start(w.core.svc.handler());
    defer core_rpc.stop();
    const txs = try windowTxs(a, w.core.st, count);

    // the edge: the same base, the feed with read sets, History in edge mode
    var en = try EdgeNode.create(&w, &win, "rs", true, null, &.{});
    defer en.destroy();
    try en.e.follow();
    try fx.must(en.waitApplied(count, 120_000 + count * 2_000), "the edge applied the window", en.e);
    const marked = en.marks(count);
    const hs = &en.rs.?.h.stats;
    var front: Front = undefined;
    try front.create(en.e.st, core_rpc.port);
    defer front.destroy();
    try testing.expectEqual(first, service.reportedLowest(&front.svc));

    // every list the edge stored is the core's, entry for entry
    {
        var cs = w.core.st.snapshot();
        defer cs.release();
        var es = en.e.st.snapshot();
        defer es.release();
        var listed: u64 = 0;
        for (txs) |*t| {
            const want = history.loadedList(serve.objset.Ref, &cs, &t.digest);
            if (!history.readSetHeld(&es, t.seq)) continue;
            const got = history.loadedList(serve.objset.Ref, &es, &t.digest);
            try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(want), std.mem.sliceAsBytes(got));
            listed += @intFromBool(want.len > 0);
        }
        // the fixture's lists are real ones, and some are not empty (a narrow archive window
        // may have none: its report says so)
        if (archive_path == null) try testing.expect(win.listed > 0 and listed > 0);
    }

    // ---- before this lane: the same edge, routed as an edge without read sets (the default
    // run's comparison; the archive mode measures the lane itself)
    var before: Diff = .{ .arena = std.heap.ArenaAllocator.init(testing.allocator), .core_h = w.core.svc.handler(), .edge_h = front.f.handler(), .fwd = front.f };
    defer before.deinit();
    if (archive_path == null) {
        const nb = try askAll(&before, txs, count, stride, tx_masks, cp_masks);
        try testing.expectEqual(@as(u64, 0), nb.plain_local + nb.with_sigs_local);
    }

    // ---- with read sets
    ReadSets.serveFrom(&front.svc);
    var after: Diff = .{ .arena = std.heap.ArenaAllocator.init(testing.allocator), .core_h = w.core.svc.handler(), .edge_h = front.f.handler(), .fwd = front.f };
    defer after.deinit();
    const reasons_before = forwardedByReason(front.f);
    const na = try askAll(&after, txs, count, stride, tx_masks, cp_masks);
    const reasons_after = forwardedByReason(front.f);

    var multi: u64 = 0;
    var with_list: u64 = 0;
    for (txs) |*t| {
        multi += @intFromBool(t.sigs > 1);
        with_list += @intFromBool(t.loaded > 0);
    }
    std.debug.print("edge-readsets fixture: {d} checkpoints, {d} transactions ({d} with a non-empty loaded list, {d} entries; {d} with two or more signatures), base {d} objects, {d} stale reads\n", .{ count, txs.len, with_list, win.entries, multi, win.base.len, win.stale });
    std.debug.print("edge-readsets edge: {d} of {d} checkpoints hold their read set ({d} rejected, {d} incomplete, {d} object versions missing); {d} lists stored, {d} xrefs written, {d} keys already readable; feed requests with read sets {d}, answered with them {d}\n", .{ marked, count, hs.edge_rejected.load(.monotonic), hs.edge_incomplete.load(.monotonic), hs.edge_missing_objects.load(.monotonic), hs.loaded_lists.load(.monotonic), hs.xref.load(.monotonic), hs.present.load(.monotonic), en.e.pool.stats.read_sets_asked.load(.monotonic), en.e.pool.stats.read_sets_held.load(.monotonic) });
    if (archive_path == null) std.debug.print("edge-readsets BEFORE (routing without read sets): {d} requests, {d} differences; {d} served locally, {d} forwarded; object-set requests {d}: local {d}, core answered OK {d}\n", .{ before.total, before.differences, before.local, before.forwarded, before.set_asked, before.set_local, before.set_core_ok });
    std.debug.print("edge-readsets AFTER  (read sets from the feed):   {d} requests, {d} differences; {d} served locally, {d} forwarded; object-set requests {d}: local {d} ({d} of them compared with a success of the core), core answered OK {d}\n", .{ after.total, after.differences, after.local, after.forwarded, after.set_asked, after.set_local, after.set_local_ok, after.set_core_ok });
    std.debug.print("edge-readsets focused masks (docs/EDGE.md 11.3), after: without signatures {d} asked, {d} local; with signatures {d} asked, {d} local\n", .{ na.plain, na.plain_local, na.with_sigs, na.with_sigs_local });
    if (after.first_core_error.len > 0) std.debug.print("edge-readsets: the core's first failure under an object-set mask: \"{s}\"\n", .{after.first_core_error});

    // ---- the block to paste: this run, with read sets
    std.debug.print("==== edge-readsets conformance: begin ====\n", .{});
    std.debug.print("source: {s}; window {d}..{d} (epoch {d}), {d} checkpoints, every {d}. transaction asked\n", .{ archive_path orelse "$ZUI_CORPUS/binpb-done (the corpus sample)", first, first + count - 1, first_epoch, count, stride });
    std.debug.print("transactions: {d}; non-empty lists: {d}; list entries: {d}; with two or more signatures: {d}\n", .{ txs.len, with_list, win.entries, multi });
    std.debug.print("checkpoints: marked {d}, rejected {d}, incomplete {d} ({d} object versions missing); reads in the window of a version neither live nor written in it: {d}\n", .{ marked, hs.edge_rejected.load(.monotonic), hs.edge_incomplete.load(.monotonic), hs.edge_missing_objects.load(.monotonic), win.stale });
    std.debug.print("requests: {d}; differences: {d}\n", .{ after.total, after.differences });
    std.debug.print("served locally: {d}; forwarded: {d}; object-set requests: {d}, of them local {d}, answered with data by the core {d}\n", .{ after.local, after.forwarded, after.set_asked, after.set_local, after.set_core_ok });
    std.debug.print("served locally by mask (local/asked):\n", .{});
    for (tx_set_paths, na.tx) |p, c| std.debug.print("  GetTransaction {s}: {d}/{d}\n", .{ p[0], c[1], c[0] });
    for (cp_set_paths, na.cp) |p, c| std.debug.print("  GetCheckpoint {s}: {d}/{d}\n", .{ p[0], c[1], c[0] });
    for (batch_masks, na.batch) |m, c| std.debug.print("  BatchGetTransactions {s}: {d}/{d}\n", .{ m, c[1], c[0] });
    std.debug.print("forwarded by reason:", .{});
    inline for (comptime std.meta.fieldNames(route.Reason), 0..) |name, i| std.debug.print(" {s} {d}", .{ name, reasons_after[i] - reasons_before[i] });
    std.debug.print("\n==== edge-readsets conformance: end ====\n", .{});

    // the gate: equal answers in both passes
    try testing.expectEqual(@as(u64, 0), before.differences);
    try testing.expectEqual(@as(u64, 0), after.differences);
    // the core has real read sets: it answers every object-set request with data
    try testing.expectEqual(after.set_asked, after.set_core_ok);
    try testing.expectEqual(before.set_asked, before.set_core_ok);
    // every checkpoint came with its read set
    try testing.expectEqual(count, en.e.pool.stats.read_sets_held.load(.monotonic));
    // ... and, in the corpus window, the edge accepts every list and holds every object named
    // (an archive window reports its rejected and incomplete checkpoints instead: their reads
    // are forwarded, which the 0 differences above covers)
    if (archive_path == null) {
        try testing.expectEqual(@as(u64, 0), hs.edge_rejected.load(.monotonic));
        if (win.stale == 0) try testing.expectEqual(count, marked);
    }
    // so, where the checkpoint is marked, every mask of 11.3 is answered here. With every
    // checkpoint marked that is all of them; signatures in the mask can still send a
    // transaction with two or more to the core (10.3).
    if (marked == count) {
        try testing.expectEqual(na.plain, na.plain_local);
        if (multi == 0) try testing.expectEqual(na.with_sigs, na.with_sigs_local);
    }
    try testing.expect(na.plain_local > 0 and after.set_local_ok > 0);
}

// ------------------------------------------------------------------ the three pairings

/// The feed of `seq` as `st`'s node serves it to a client that asks for nothing new.
fn plainFeed(a: std.mem.Allocator, st: *store.Store, seq: u64) ![]const u8 {
    var snap = st.snapshot();
    defer snap.release();
    var out: std.ArrayList(u8) = .empty;
    try testing.expect(try native.edgefeed.assemble(a, &snap, seq, &out));
    return out.items;
}

/// One GetTransaction under `effects` through a forwarder in front of `en`: how it was routed,
/// and that it equals the core's answer.
fn effectsRead(w: *fx.World, en: *EdgeNode, core_port: u16, t: *const Tx, read_sets: bool) !Routed {
    var front: Front = undefined;
    try front.create(en.e.st, core_port);
    defer front.destroy();
    if (read_sets) ReadSets.serveFrom(&front.svc);
    var d: Diff = .{ .arena = std.heap.ArenaAllocator.init(testing.allocator), .core_h = w.core.svc.handler(), .edge_h = front.f.handler(), .fwd = front.f };
    defer d.deinit();
    const rq: Req = .{ .a = d.arena.allocator() };
    const how = try d.check(p_tx, try rq.tx(&t.digest, "effects"), true);
    _ = try d.check(p_checkpoint, try rq.checkpoint(t.seq, "transactions.effects"), true);
    try testing.expectEqual(@as(u64, 0), d.differences);
    try testing.expectEqual(d.set_asked, d.set_core_ok);
    return how;
}

test "edge read sets: old edge with new core, new edge with old core, new with new" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const count: u64 = 8;
    const a = w.arena.allocator();
    const win = try Window.prepare(a, w.tmp.dir, "window", count);
    defer win.dir.close(io);
    var core = try Core.build(&w, &win, count, &.{});
    defer core.destroy();
    const core_rpc = try Rpc.start(w.core.svc.handler());
    defer core_rpc.stop();
    const txs = try windowTxs(a, w.core.st, count);
    // a transaction with a loaded list: the one whose `effects` an edge without it gets wrong
    const probe: *const Tx = for (txs) |*t| {
        if (t.loaded > 0 and t.sigs == 1) break t;
    } else return error.SkipZigTest;
    var nb: [64]u8 = undefined;

    // ---- new core (sends read sets when asked), old edge (never asks)
    w.core.feeder.read_sets = &w.core.svc;
    try w.coreUp(true);
    var old_edge = try EdgeNode.create(&w, &win, "old-edge", false, null, &.{});
    defer old_edge.destroy();
    try old_edge.e.follow();
    try fx.must(old_edge.e.waitCommitted(count, 60_000), "old edge, new core", old_edge.e);
    try testing.expectEqual(@as(u64, 0), old_edge.e.pool.stats.read_sets_asked.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), old_edge.marks(count));
    for (0..count) |i| try testing.expectError(error.FileNotFound, old_edge.e.spool.statFile(io, try std.fmt.bufPrint(&nb, "{d}.aux", .{first + i}), .{}));
    try testing.expectEqual(Routed.forwarded, try effectsRead(&w, &old_edge, core_rpc.port, probe, false));

    // ---- new with new: the read sets flow, the read is answered by the edge
    var new_edge = try EdgeNode.create(&w, &win, "new-edge", true, null, &.{});
    defer new_edge.destroy();
    try new_edge.e.follow();
    try fx.must(new_edge.e.waitCommitted(count, 60_000), "new edge, new core", new_edge.e);
    try testing.expectEqual(count, new_edge.e.pool.stats.read_sets_asked.load(.monotonic));
    try testing.expectEqual(count, new_edge.e.pool.stats.read_sets_held.load(.monotonic));
    if (win.stale == 0) try testing.expectEqual(count, new_edge.marks(count));
    const probe_held = blk: {
        var snap = new_edge.e.st.snapshot();
        defer snap.release();
        break :blk history.readSetHeld(&snap, probe.seq);
    };
    if (probe_held) try testing.expectEqual(Routed.local, try effectsRead(&w, &new_edge, core_rpc.port, probe, true));
    if (win.stale == 0) try testing.expect(probe_held);

    // ---- old core (no read sets in its feed: hello without bit 33, the flag unknown to it)
    w.core.stop();
    w.core.feeder.read_sets = null;
    try w.coreUp(true);
    var lone_edge = try EdgeNode.create(&w, &win, "new-edge-old-core", true, null, &.{});
    defer lone_edge.destroy();
    try lone_edge.e.follow();
    try fx.must(lone_edge.e.waitCommitted(count, 60_000), "new edge, old core", lone_edge.e);
    // never asked (an old core answers the flag with BAD_REQUEST: the follow above would not
    // have finished), nothing marked, and the read still goes to the core
    try testing.expectEqual(@as(u64, 0), lone_edge.e.pool.stats.read_sets_asked.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), lone_edge.e.pool.stats.errors.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), lone_edge.marks(count));
    try testing.expectEqual(Routed.forwarded, try effectsRead(&w, &lone_edge, core_rpc.port, probe, true));

    // ---- the bytes: all three edges were handed the same blobs and store the same checkpoints
    // and transactions; the two without read sets store nothing else
    for (0..count) |i| {
        const seq = first + i;
        const name = try std.fmt.bufPrint(&nb, "{d}.chk", .{seq});
        const b_old = try old_edge.e.spool.readFileAlloc(io, name, a, .limited(1 << 30));
        try testing.expectEqualSlices(u8, b_old, try new_edge.e.spool.readFileAlloc(io, name, a, .limited(1 << 30)));
        try testing.expectEqualSlices(u8, b_old, try lone_edge.e.spool.readFileAlloc(io, name, a, .limited(1 << 30)));
        const want = try plainFeed(a, w.core.st, seq);
        try testing.expectEqualSlices(u8, want, try plainFeed(a, old_edge.e.st, seq));
        try testing.expectEqualSlices(u8, want, try plainFeed(a, new_edge.e.st, seq));
        try testing.expectEqualSlices(u8, want, try plainFeed(a, lone_edge.e.st, seq));
    }
    // An edge that keeps read sets writes its xrefs for superseded inputs whether or not lists
    // arrive (they are what keeps earlier read sets readable); lists and marks only with them.
    const lone = &lone_edge.rs.?.h.stats;
    try testing.expectEqual(@as(u64, 0), lone.loaded_lists.load(.monotonic) + lone.marked.load(.monotonic) + lone.edge_rejected.load(.monotonic));
    try testing.expectEqual(count, lone.no_aux.load(.monotonic));
    try testing.expect(lone.xref.load(.monotonic) > 0);
    try testing.expect(lone_edge.e.st.stats.bytes_appended >= old_edge.e.st.stats.bytes_appended);
    try testing.expect(new_edge.e.st.stats.bytes_appended > lone_edge.e.st.stats.bytes_appended);
}

test "edge read sets: a feed without the flag is the feed of before, with it the same bytes and then the lists the core serves" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const count: u64 = 6;
    const a = w.arena.allocator();
    const win = try Window.prepare(a, w.tmp.dir, "window", count);
    defer win.dir.close(io);
    var core = try Core.build(&w, &win, count, &.{});
    defer core.destroy();
    var listed: u64 = 0;
    for (0..count) |i| {
        const seq = first + i;
        const plain = try plainFeed(a, w.core.st, seq);
        var snap = w.core.st.snapshot();
        defer snap.release();
        // not asked for: the old function and the new one give the same bytes
        var same: std.ArrayList(u8) = .empty;
        try testing.expect(try native.edgefeed.assembleWith(a, &snap, seq, &same, null));
        try testing.expectEqualSlices(u8, plain, same.items);
        // asked for: the feed, then the read sets
        var with: std.ArrayList(u8) = .empty;
        try testing.expect(try native.edgefeed.assembleWith(a, &snap, seq, &with, &w.core.svc));
        try testing.expectEqualSlices(u8, plain, with.items[0..plain.len]);
        var got = try edgewire.feed.decodeWithReadSets(a, with.items);
        defer got.deinit(a);
        const lists = got.read_sets.lists orelse return error.TestUnexpectedResult;
        const digests = try native.dispatch.contentDigests(a, snap.checkpoint(seq).?.contents);
        try testing.expectEqual(digests.len, lists.len);
        for (digests, lists) |*dg, l| {
            const want = history.loadedList(serve.objset.Ref, &snap, dg);
            try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(want), l);
            listed += @intFromBool(l.len > 0);
        }
        // a node that does not hold the checkpoint's read set says so in one byte
        var none_svc: service.Service = .{ .gpa = testing.allocator, .store = w.core.st, .chain_id = @splat(0) };
        defer none_svc.deinit();
        none_svc.loaded = w.core.svc.loaded;
        none_svc.read_sets = .{ .ctx = &none_svc, .has = struct {
            fn no(_: *const anyopaque, _: *const store.Snapshot, _: u64) bool {
                return false;
            }
        }.no };
        var none: std.ArrayList(u8) = .empty;
        try testing.expect(try native.edgefeed.assembleWith(a, &snap, seq, &none, &none_svc));
        try testing.expectEqual(plain.len + 1, none.items.len);
        try testing.expectEqual(@as(u8, 0), none.items[plain.len]);
    }
    try testing.expect(listed > 0);
}

// ------------------------------------------------------------------ the fallback builds them too

test "edge read sets: a checkpoint taken from the fallback gets the archive's lists, the same aux record and the same stored read set as one taken from the feed" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const count: u64 = 8;
    const a = w.arena.allocator();
    const win = try Window.prepare(a, w.tmp.dir, "window", count);
    defer win.dir.close(io);
    var core = try Core.build(&w, &win, count, &.{});
    defer core.destroy();
    w.core.feeder.read_sets = &w.core.svc;
    try w.coreUp(true);

    // Both edges take the window and nothing after it: the stores are compared whole at the
    // end. The core holds only the window, but the fallback directory is the whole corpus, and
    // an edge left to itself goes on into it until it is stopped (how far is a race).
    var by_feed = try EdgeNode.create(&w, &win, "by-feed", true, null, &.{});
    defer by_feed.destroy();
    by_feed.e.fetcher.to = first + count - 1;
    try by_feed.e.follow();
    try fx.must(by_feed.e.waitCommitted(count, 60_000), "by the feed", by_feed.e);
    by_feed.e.follower.stop();

    // no core from here on: the archive's protos (the bucket's format) are the only source
    w.core.stop();
    w.link.core_port.store(0, .release);
    const protos = try fx.corpusDir("binpb-done");
    defer protos.close(io);
    var by_bucket = try EdgeNode.create(&w, &win, "by-bucket", true, protos, &.{});
    defer by_bucket.destroy();
    by_bucket.e.fetcher.to = first + count - 1;
    try by_bucket.e.follow();
    try fx.must(by_bucket.e.waitCommitted(count, 60_000), "by the fallback", by_bucket.e);
    by_bucket.e.follower.stop();
    try testing.expect(by_bucket.e.stats().from_fallback.load(.monotonic) >= count);
    try testing.expectEqual(@as(u64, 0), by_bucket.e.pool.stats.read_sets_asked.load(.monotonic));

    var nb: [64]u8 = undefined;
    var with_lists: u64 = 0;
    for (0..count) |i| {
        const seq = first + i;
        // what the follower and the read-set hook were handed
        const chk = try std.fmt.bufPrint(&nb, "{d}.chk", .{seq});
        try testing.expectEqualSlices(u8, try by_feed.e.spool.readFileAlloc(io, chk, a, .limited(1 << 30)), try by_bucket.e.spool.readFileAlloc(io, chk, a, .limited(1 << 30)));
        const aux = try std.fmt.bufPrint(&nb, "{d}.aux", .{seq});
        const aux_feed = try by_feed.e.spool.readFileAlloc(io, aux, a, .limited(1 << 30));
        try testing.expectEqualSlices(u8, aux_feed, try by_bucket.e.spool.readFileAlloc(io, aux, a, .limited(1 << 30)));
        const x = try convert.Aux.parse(a, aux_feed);
        try testing.expectEqual(@as(usize, 0), x.objects.len);
        for (x.loaded) |l| with_lists += @intFromBool(l.len > 0);
        // what each stored: the same marks and the same feed with read sets
        var sf = by_feed.e.st.snapshot();
        defer sf.release();
        var sb = by_bucket.e.st.snapshot();
        defer sb.release();
        try testing.expectEqual(history.readSetHeld(&sf, seq), history.readSetHeld(&sb, seq));
        var svc_f: service.Service = .{ .gpa = testing.allocator, .store = by_feed.e.st, .chain_id = @splat(0) };
        defer svc_f.deinit();
        ReadSets.serveFrom(&svc_f);
        var svc_b: service.Service = .{ .gpa = testing.allocator, .store = by_bucket.e.st, .chain_id = @splat(0) };
        defer svc_b.deinit();
        ReadSets.serveFrom(&svc_b);
        var ff: std.ArrayList(u8) = .empty;
        var fb: std.ArrayList(u8) = .empty;
        try testing.expect(try native.edgefeed.assembleWith(a, &sf, seq, &ff, &svc_f));
        try testing.expect(try native.edgefeed.assembleWith(a, &sb, seq, &fb, &svc_b));
        try testing.expectEqualSlices(u8, ff.items, fb.items);
    }
    try testing.expect(with_lists > 0);
    try testing.expectEqual(by_feed.marks(count), by_bucket.marks(count));
    if (win.stale == 0) try testing.expectEqual(count, by_bucket.marks(count));
    // the same checkpoints in both stores, so the same bytes: nothing was stored twice, and the
    // read-set records of one path are no larger than the other's
    try testing.expectEqual(count, by_feed.e.committed());
    try testing.expectEqual(count, by_bucket.e.committed());
    try testing.expectEqual(by_feed.e.st.stats.bytes_appended, by_bucket.e.st.stats.bytes_appended);
}

// ------------------------------------------------------------------ a core that lies

/// How the lying core changes the list of a checkpoint's first transaction that has one.
const Lie = enum {
    none,
    /// Two entries swapped: not sui-node's order.
    unordered,
    /// An entry added for an object the transaction changed.
    changed,
    /// An entry added that names a package.
    package,
    /// An entry added for an object version that does not exist.
    absent,
    /// An entry added for a version that exists and the edge holds, but that was superseded
    /// before the transaction ran (the input version of an object the checkpoint before changed).
    stale,
    /// An entry left out. Nothing certified names the list: no edge can see this one.
    omitted,
};

const Liar = struct {
    /// Per checkpoint (index from `first`): what to do to its target transaction's list.
    plan: []const Lie,
    /// The target transaction of each checkpoint (the first with a list of two or more).
    targets: []const ?[32]u8,
    package: serve.objset.Ref,
    on: Atomic(bool) = .init(true),
    told: [8]Atomic(u64) = @splat(.init(0)),
    scratch: [64]serve.objset.Ref = undefined,

    threadlocal var buf: [64]serve.objset.Ref = undefined;

    fn loaded(ctx: *const anyopaque, snap: *const store.Snapshot, digest: *const [32]u8, at: u64) []const serve.objset.Ref {
        const l: *Liar = @constCast(@ptrCast(@alignCast(ctx)));
        const real = history.loadedListNear(serve.objset.Ref, snap, digest, at);
        if (!l.on.load(.acquire)) return real;
        const rec = snap.transaction(digest) orelse return real;
        const i = rec.checkpoint - first;
        if (i >= l.plan.len) return real;
        const target = l.targets[i] orelse return real;
        if (!std.mem.eql(u8, &target, digest) or real.len + 1 > buf.len) return real;
        const lie = l.plan[i];
        _ = l.told[@intFromEnum(lie)].fetchAdd(1, .monotonic);
        switch (lie) {
            .none => return real,
            .unordered => {
                @memcpy(buf[0..real.len], real);
                std.mem.swap(serve.objset.Ref, &buf[0], &buf[1]);
                return buf[0..real.len];
            },
            .omitted => return real[0 .. real.len - 1],
            .changed, .package, .absent, .stale => {
                const add: serve.objset.Ref = switch (lie) {
                    .package => l.package,
                    .absent => .{ .id = @splat(0xee), .version = 7 },
                    else => blk: {
                        // the first object the transaction's effects change, at its input
                        // version; for `stale`, of the target transaction one checkpoint back
                        var arena = std.heap.ArenaAllocator.init(sys);
                        defer arena.deinit();
                        const effects = if (lie == .changed) rec.effects else (snap.transaction(&(l.targets[i - 1] orelse return real)) orelse return real).effects;
                        const fx_ = @import("bcs").decode(types.TransactionEffects, arena.allocator(), effects) catch return real;
                        for (fx_.V2.changed_objects) |ch| switch (ch[1].input_state) {
                            .Exist => |e| break :blk .{ .id = ch[0].@"0".@"0", .version = e[0][0].@"0" },
                            .NotExist => {},
                        };
                        return real;
                    },
                };
                // in its place by id: the list stays in sui-node's order
                var n: usize = 0;
                var put = false;
                for (real) |r| {
                    const o = std.mem.order(u8, &add.id, &r.id);
                    if (o == .eq) return real;
                    if (!put and o == .lt) {
                        buf[n] = add;
                        n += 1;
                        put = true;
                    }
                    buf[n] = r;
                    n += 1;
                }
                if (!put) {
                    buf[n] = add;
                    n += 1;
                }
                return buf[0..n];
            },
        }
    }
};

/// A package object nobody reads: BCS `Object { data: Package { id, version, no modules, no
/// tables }, owner: Immutable, previous_transaction, storage_rebate }`.
fn fakePackage(buf: *[128]u8, id: [32]u8, version: u64) []const u8 {
    var n: usize = 0;
    buf[n] = 1;
    n += 1;
    @memcpy(buf[n..][0..32], &id);
    n += 32;
    std.mem.writeInt(u64, buf[n..][0..8], version, .little);
    n += 8;
    @memset(buf[n..][0..3], 0); // module_map, type_origin_table, linkage_table: empty
    n += 3;
    buf[n] = 3; // Owner::Immutable
    n += 1;
    buf[n] = 32;
    n += 1;
    @memset(buf[n..][0..32], 0x44);
    n += 32;
    @memset(buf[n..][0..8], 0);
    n += 8;
    return buf[0..n];
}

test "edge read sets: a core that sends wrong lists is caught wherever a list can be checked; what nothing can catch is shown too (an entry left out)" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const plan = [_]Lie{ .none, .changed, .package, .absent, .stale, .omitted, .unordered, .none };
    const count: u64 = plan.len;
    const a = w.arena.allocator();
    const win = try Window.prepare(a, w.tmp.dir, "window", count);
    defer win.dir.close(io);
    // one package in both base sets (the edge holds it: only its kind gives the lie away)
    var pkg_buf: [128]u8 = undefined;
    const pkg: BaseObj = .{ .id = @splat(0xab), .version = 1, .raw = fakePackage(&pkg_buf, @splat(0xab), 1) };
    var core = try Core.build(&w, &win, count, &.{pkg});
    defer core.destroy();
    const txs = try windowTxs(a, w.core.st, count);
    const targets = try a.alloc(?[32]u8, count);
    @memset(targets, null);
    for (txs) |*t| {
        const i = t.seq - first;
        if (targets[i] == null and t.loaded >= 2 and t.sigs == 1) targets[i] = t.digest;
    }
    for (plan, targets) |lie, t| if (lie != .none and t == null) return error.SkipZigTest;

    var liar: Liar = .{ .plan = &plan, .targets = targets, .package = .{ .id = pkg.id, .version = pkg.version } };
    const honest = w.core.svc.loaded;
    w.core.svc.loaded = .{ .ctx = &liar, .get = Liar.loaded };
    w.core.feeder.read_sets = &w.core.svc;
    try w.coreUp(true);
    const core_rpc = try Rpc.start(w.core.svc.handler());
    defer core_rpc.stop();

    // The edge has the archive's protos as its fallback: the checkpoint whose feed it must
    // refuse (the list out of order) comes from there.
    const protos = try fx.corpusDir("binpb-done");
    defer protos.close(io);
    var en = try EdgeNode.create(&w, &win, "lied-to", true, protos, &.{pkg});
    defer en.destroy();
    try en.e.follow();
    try fx.must(en.e.waitCommitted(count, 120_000), "the edge applied the window", en.e);
    en.e.follower.stop();
    const hs = &en.rs.?.h.stats;
    for ([_]Lie{ .changed, .package, .absent, .stale, .omitted, .unordered }) |lie| try testing.expect(liar.told[@intFromEnum(lie)].load(.monotonic) > 0);

    // from here the core tells the truth: its sui.rpc.v2 answers are what the edge's are
    // compared with
    liar.on.store(false, .release);
    _ = honest;
    var snap = en.e.st.snapshot();
    defer snap.release();
    var cs = w.core.st.snapshot();
    defer cs.release();
    var caught: u64 = 0;
    for (plan, 0..) |lie, i| {
        const seq = first + i;
        const dg = targets[i];
        const held = history.readSetHeld(&snap, seq);
        switch (lie) {
            // an honest checkpoint: marked (unless the window itself reads a version no
            // snapshot would hold)
            .none => if (win.stale == 0) try testing.expect(held),
            // refused at ingest: no mark, no list of the lying core in the store
            .changed, .package, .absent, .stale => {
                try testing.expect(!held);
                try testing.expectEqual(@as(usize, 0), history.loadedList(serve.objset.Ref, &snap, &dg.?).len);
                caught += 1;
            },
            // refused before ingest: the feed did not decode as one with read sets, the core was
            // dropped for it, and the checkpoint came from the fallback with the archive's list
            .unordered => {
                if (win.stale == 0) try testing.expect(held);
                const want = history.loadedList(serve.objset.Ref, &cs, &dg.?);
                if (held) try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(want), std.mem.sliceAsBytes(history.loadedList(serve.objset.Ref, &snap, &dg.?)));
                caught += 1;
            },
            // NOT caught, and it cannot be: the list is in order, names only objects the edge
            // holds, none of them changed, none a package. The edge stores the shorter list
            // and marks the checkpoint.
            .omitted => {
                const want = history.loadedList(serve.objset.Ref, &cs, &dg.?);
                const got = history.loadedList(serve.objset.Ref, &snap, &dg.?);
                if (win.stale == 0) {
                    try testing.expect(held);
                    try testing.expectEqual(want.len - 1, got.len);
                }
            },
        }
    }
    try testing.expectEqual(@as(u64, 5), caught);
    try testing.expectEqual(@as(u64, 3), hs.edge_rejected.load(.monotonic)); // changed, package, stale
    // absent (and, past the window, checkpoints the fallback directory goes on serving, whose
    // reads the window's base does not cover)
    try testing.expect(hs.edge_incomplete.load(.monotonic) >= 1);
    try testing.expect(en.e.pool.stats.failovers.load(.monotonic) >= 1); // unordered: the core dropped for that feed
    try testing.expect(en.e.stats().from_fallback.load(.monotonic) >= 1);

    // What a client sees. The refused checkpoints are answered by the (now honest) core:
    // equal. The checkpoint with the omitted entry is answered by the edge from the list it was
    // given, and differs from the truth in exactly that field: the limit, shown.
    var front: Front = undefined;
    try front.create(en.e.st, core_rpc.port);
    defer front.destroy();
    ReadSets.serveFrom(&front.svc);
    var d: Diff = .{ .arena = std.heap.ArenaAllocator.init(testing.allocator), .core_h = w.core.svc.handler(), .edge_h = front.f.handler(), .fwd = front.f, .quiet = true };
    defer d.deinit();
    const rq: Req = .{ .a = d.arena.allocator() };
    for (plan, 0..) |lie, i| {
        const dg = targets[i] orelse continue;
        const mark = history.readSetHeld(&snap, first + i);
        const diffs_before = d.differences;
        const how = try d.check(p_tx, try rq.tx(&dg, "effects.unchanged_loaded_runtime_objects"), true);
        const how_status = try d.check(p_tx, try rq.tx(&dg, "effects.status,balance_changes"), true);
        switch (lie) {
            .changed, .package, .absent, .stale => {
                try testing.expectEqual(Routed.forwarded, how);
                try testing.expectEqual(Routed.forwarded, how_status);
                try testing.expectEqual(diffs_before, d.differences);
            },
            .none, .unordered => {
                if (mark) try testing.expectEqual(Routed.local, how);
                try testing.expectEqual(diffs_before, d.differences);
            },
            .omitted => if (mark) {
                try testing.expectEqual(Routed.local, how);
                // the list differs; what does not render it is still the core's answer
                try testing.expectEqual(diffs_before + 1, d.differences);
            },
        }
    }
    std.debug.print("edge-readsets tampering: {d} of 6 lies caught (order: feed refused, checkpoint taken from the fallback; changed object, package, superseded version: rejected at ingest; absent version: checkpoint left unmarked); 1 not catchable (an entry left out: the edge served the shorter list); edge stats: rejected {d}, incomplete {d}, pool failovers {d}\n", .{ caught, hs.edge_rejected.load(.monotonic), hs.edge_incomplete.load(.monotonic), en.e.pool.stats.failovers.load(.monotonic) });
}

// ------------------------------------------------------------------ what it costs

/// Checkpoints in mainnet epoch 1303 (the window's epoch; `$ZUI_CORPUS/epochs.jsonl`).
const epoch_checkpoints: u64 = 342451160 - 342086716 + 1;

test "edge read sets cost: feed bytes with and without them (raw, zstd, zstd with a dictionary), what input objects would add, and what an edge stores and spends per checkpoint" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const a = w.arena.allocator();
    const gpa = testing.allocator;

    // ---- the feed, over `n` checkpoints of the dense window, straight from the archive protos
    const n = envU("ZUI_EDGE_RS_COST", 200);
    const protos = try fx.corpusDir("binpb-done");
    defer protos.close(io);
    var idx = try types.index.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const Sum = struct { raw: u64 = 0, zstd: u64 = 0, dict: u64 = 0 };
    var feed_only: Sum = .{};
    var with_rs: Sum = .{};
    var with_inputs: Sum = .{};
    var rs_raw: u64 = 0;
    var inputs_raw: u64 = 0;
    var input_objects: u64 = 0;
    var entries: u64 = 0;
    var listed: u64 = 0;
    var txs_total: u64 = 0;
    var after_dict: u64 = 0;
    var samples: std.ArrayList([]const u8) = .empty;
    defer {
        for (samples.items) |s| gpa.free(s);
        samples.deinit(gpa);
    }
    var dictionary: ?edgewire.dict.Dictionary = null;
    defer if (dictionary) |*d| d.deinit(gpa);
    for (0..n) |i| {
        _ = scratch.reset(.retain_capacity);
        const sa = scratch.allocator();
        const seq = first + i;
        const zst = try fx.readSeq(sa, protos, seq, ".binpb.zst");
        const pb = try convert.unzstdArena(sa, zst, source_mod.max_blob);
        var blob: std.ArrayList(u8) = .empty;
        defer blob.deinit(gpa);
        var aux: std.ArrayList(u8) = .empty;
        defer aux.deinit(gpa);
        _ = try convert.protoToChkAux(gpa, sa, pb, &blob, &aux);
        try types.index.indexCheckpointData(blob.items, &idx);
        const x = try convert.Aux.parse(sa, aux.items);
        const tx_in = try sa.alloc(edgewire.feed.TxIn, idx.tx_count);
        const lists = try sa.alloc([]const u8, idx.tx_count);
        var inputs: std.ArrayList(u8) = .empty;
        for (tx_in, lists, 0..) |*t, *l, k| {
            const tx = idx.txAt(k);
            const objs = try sa.alloc([]const u8, tx.out_count);
            for (objs, idx.objs[tx.out_first..][0..tx.out_count]) |*o, r| o.* = r.slice(blob.items);
            t.* = .{ .tx = tx.transaction.slice(blob.items), .effects = tx.effects.slice(blob.items), .events = if (tx.events) |e| e.slice(blob.items) else null, .objects = objs };
            const bytes = try sa.alloc(u8, x.loaded[k].len * 40);
            for (x.loaded[k], 0..) |r, j| {
                std.mem.writeInt(u64, bytes[j * 40 ..][0..8], r.version, .little);
                bytes[j * 40 + 8 ..][0..32].* = r.id;
            }
            l.* = bytes;
            entries += x.loaded[k].len;
            listed += @intFromBool(x.loaded[k].len > 0);
            for (idx.objs[tx.in_first..][0..tx.in_count]) |r| {
                try inputs.appendSlice(sa, r.slice(blob.items));
                input_objects += 1;
            }
        }
        for (x.objects) |o| {
            try inputs.appendSlice(sa, o);
            input_objects += 1;
        }
        txs_total += idx.tx_count;
        var raw: std.ArrayList(u8) = .empty;
        try edgewire.feed.encode(&raw, sa, seq, blob.items[idx.summary.o .. idx.sig.o + idx.sig.n], idx.contents.slice(blob.items), tx_in);
        const feed_len = raw.items.len;
        try edgewire.feed.encodeReadSets(&raw, sa, lists);
        const rs_len = raw.items.len;
        try raw.appendSlice(sa, inputs.items);
        const sets = [_]struct { *Sum, []const u8 }{ .{ &feed_only, raw.items[0..feed_len] }, .{ &with_rs, raw.items[0..rs_len] }, .{ &with_inputs, raw.items } };
        rs_raw += rs_len - feed_len;
        inputs_raw += inputs.items.len;
        for (sets) |s| {
            s[0].raw += s[1].len;
            s[0].zstd += (try edgewire.dict.compress(sa, null, s[1])).len;
            if (dictionary) |*d| s[0].dict += (try edgewire.dict.compress(sa, d, s[1])).len;
        }
        if (dictionary != null) after_dict += 1;
        // one dictionary from the first 8 plain feeds, as a core builds one and keeps it
        if (dictionary == null) {
            try samples.append(gpa, try gpa.dupe(u8, raw.items[0..feed_len]));
            if (samples.items.len == 8) {
                const content = try edgewire.dict.build(gpa, samples.items, edgewire.dict.default_dict);
                defer gpa.free(content);
                dictionary = try edgewire.dict.Dictionary.init(gpa, content, 3);
            }
        }
    }
    const per = struct {
        fn of(total: u64, k: u64) u64 {
            return if (k == 0) 0 else total / k;
        }
    }.of;
    std.debug.print(
        \\edge-readsets cost, feed bytes over {d} checkpoints ({d} transactions, {d} with a loaded list, {d} list entries; Mac, dense window from {d}):
        \\  per checkpoint, raw:               feed {d}, with read sets {d} (+{d}, {d}.{d:0>2}%)
        \\  per checkpoint, zstd:              feed {d}, with read sets {d} (+{d}, {d}.{d:0>2}%)
        \\  per checkpoint, zstd + dictionary: feed {d}, with read sets {d} (+{d}, {d}.{d:0>2}%)   ({d} checkpoints after the dictionary's 8)
        \\  input objects, if a feed carried them too ({d} per checkpoint): raw +{d}, zstd +{d} per checkpoint over the feed with read sets
        \\
    , .{
        n,                                             txs_total,                                 listed,                                                     entries,                                                                        first,
        per(feed_only.raw, n),                         per(with_rs.raw, n),                       per(with_rs.raw - feed_only.raw, n),                        (with_rs.raw - feed_only.raw) * 100 / feed_only.raw,                            (with_rs.raw - feed_only.raw) * 10000 / feed_only.raw % 100,
        per(feed_only.zstd, n),                        per(with_rs.zstd, n),                      per(with_rs.zstd - feed_only.zstd, n),                      (with_rs.zstd - feed_only.zstd) * 100 / feed_only.zstd,                         (with_rs.zstd - feed_only.zstd) * 10000 / feed_only.zstd % 100,
        per(feed_only.dict, after_dict),               per(with_rs.dict, after_dict),             per(with_rs.dict -| feed_only.dict, after_dict),            if (feed_only.dict == 0) 0 else (with_rs.dict -| feed_only.dict) * 100 / feed_only.dict, if (feed_only.dict == 0) 0 else (with_rs.dict -| feed_only.dict) * 10000 / feed_only.dict % 100,
        after_dict,                                    per(input_objects, n),                     per(with_inputs.raw - with_rs.raw, n),                      per(with_inputs.zstd - with_rs.zstd, n),
    });
    try testing.expectEqual(rs_raw, with_rs.raw - feed_only.raw);
    try testing.expectEqual(inputs_raw, with_inputs.raw - with_rs.raw);
    try testing.expect(entries > 0);

    // ---- the edge: the same checkpoints followed with and without read sets
    const count = envU("ZUI_EDGE_RS_COST_FOLLOW", 24);
    const win = try Window.prepare(a, w.tmp.dir, "window", count);
    defer win.dir.close(io);
    var core = try Core.build(&w, &win, count, &.{});
    defer core.destroy();
    w.core.feeder.read_sets = &w.core.svc;
    try w.coreUp(true);
    var plain = try EdgeNode.create(&w, &win, "plain", false, null, &.{});
    defer plain.destroy();
    const base_plain = plain.e.st.stats.bytes_appended;
    try plain.e.follow();
    try fx.must(plain.e.waitCommitted(count, 120_000), "the edge without read sets", plain.e);
    plain.e.follower.stop();
    var rs = try EdgeNode.create(&w, &win, "rs", true, null, &.{});
    defer rs.destroy();
    const base_rs = rs.e.st.stats.bytes_appended;
    try rs.e.follow();
    try fx.must(rs.e.waitCommitted(count, 120_000), "the edge with read sets", rs.e);
    rs.e.follower.stop();
    const hs = &rs.rs.?.h.stats;
    const stored_plain = plain.e.st.stats.bytes_appended - base_plain;
    const stored_rs = rs.e.st.stats.bytes_appended - base_rs;
    const extra = stored_rs - stored_plain;
    const per_cp = extra / count;
    const hook = rs.rs.?.hook_ns.load(.monotonic) / @max(1, rs.rs.?.batches.load(.monotonic));
    const core_hook = core.rs.hook_ns.load(.monotonic) / @max(1, core.rs.batches.load(.monotonic));
    // the core's side: assembling a feed with and without read sets (best of 5 passes)
    var asm_plain: u64 = std.math.maxInt(u64);
    var asm_rs: u64 = std.math.maxInt(u64);
    for (0..5) |_| {
        inline for (.{ false, true }) |with| {
            const t0 = fx.nowNs();
            for (0..count) |i| {
                _ = scratch.reset(.retain_capacity);
                var snap = w.core.st.snapshot();
                defer snap.release();
                var out: std.ArrayList(u8) = .empty;
                try testing.expect(try native.edgefeed.assembleWith(scratch.allocator(), &snap, first + i, &out, if (with) &w.core.svc else null));
            }
            const dt = (fx.nowNs() - t0) / count;
            if (with) asm_rs = @min(asm_rs, dt) else asm_plain = @min(asm_plain, dt);
        }
    }
    std.debug.print(
        \\edge-readsets cost, an edge's store over {d} checkpoints ({s} build, Mac):
        \\  appended without read sets {d} bytes, with {d}: +{d} bytes, {d} per checkpoint ({d} xrefs, {d} lists, {d} marks; {d} keys needed nothing)
        \\  at {d} checkpoints an epoch: {d} MiB per epoch, {d} MiB for an epoch and a half (segment bytes before compression; the version index adds its entries)
        \\  read-set hook per checkpoint: edge {d} us, core (full path, same checkpoints) {d} us
        \\  feed assembly on the core per checkpoint: {d} us without read sets, {d} us with
        \\
    , .{
        count,          @tagName(@import("builtin").mode),
        stored_plain,   stored_rs,
        extra,          per_cp,
        hs.xref.load(.monotonic), hs.loaded_lists.load(.monotonic),
        hs.marked.load(.monotonic), hs.present.load(.monotonic),
        epoch_checkpoints, per_cp * epoch_checkpoints >> 20,
        per_cp * epoch_checkpoints * 3 / 2 >> 20, hook / 1000,
        core_hook / 1000, asm_plain / 1000,
        asm_rs / 1000,
    });
    try testing.expect(stored_rs > stored_plain);
}

test "edge read sets: a checkpoint spooled again after its first copy was refused does not keep that copy's aux record" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var src: source_mod.Source = .{ .gpa = gpa, .io = io, .kind = .none };
    var applied: Atomic(u64) = .init(0);
    const f = try gpa.create(source_mod.Fetcher);
    defer gpa.destroy(f);
    f.* = .{ .gpa = gpa, .io = io, .source = &src, .spool = tmp.dir, .next = .init(7), .applied_next = &applied, .window = 4, .poll_ms = 10, .to = std.math.maxInt(u64), .keep = true };
    try f.writeSpool(7, "BLOB-A", "LISTS-OF-A");
    try testing.expectEqualStrings("LISTS-OF-A", try tmp.dir.readFileAlloc(io, "7.aux", a, .limited(64)));
    // the plain writer leaves an aux record it was given none for (every other path relies on
    // one writer per checkpoint)
    try f.writeSpool(7, "BLOB-B", "");
    try testing.expectEqualStrings("LISTS-OF-A", try tmp.dir.readFileAlloc(io, "7.aux", a, .limited(64)));
    // the refetch after a refused copy does not: the refused core's lists never go with the
    // blob another source served
    try f.writeSpoolAgain(7, "BLOB-C", "", false);
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "7.aux", .{}));
    try testing.expectEqualStrings("BLOB-C", try tmp.dir.readFileAlloc(io, "7.chk", a, .limited(64)));
    // with read sets of its own, they replace the old ones; with nothing to remove, nothing happens
    try f.writeSpool(7, "BLOB-A", "LISTS-OF-A");
    try f.writeSpoolAgain(7, "BLOB-D", "LISTS-OF-D", true);
    try testing.expectEqualStrings("LISTS-OF-D", try tmp.dir.readFileAlloc(io, "7.aux", a, .limited(64)));
    try f.writeSpoolAgain(8, "BLOB-E", "", true);
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "8.aux", .{}));
    try testing.expectEqualStrings("BLOB-E", try tmp.dir.readFileAlloc(io, "8.chk", a, .limited(64)));
    // and the origin recorded is the new copy's (docs/EDGE.md section 13: a blob that did not
    // come from a core's feed has its certificate marked)
    try testing.expect(!f.fromCore(6));
    try testing.expect(f.fromCore(7) and f.fromCore(8));
    try f.writeSpoolAgain(7, "BLOB-F", "", false);
    try testing.expect(!f.fromCore(7));
}

// ------------------------------------------------------------------ pipelined calls, and a core that refuses

/// The feed of `seq` with its read sets, as a node over `st` with `--edge-read-sets on` sends
/// it: the checkpoint, the lists and whether the store holds its read set, in one comparison.
fn feedWithReadSets(a: std.mem.Allocator, st: *store.Store, seq: u64) ![]const u8 {
    var svc: service.Service = .{ .gpa = testing.allocator, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    ReadSets.serveFrom(&svc);
    var snap = st.snapshot();
    defer snap.release();
    var out: std.ArrayList(u8) = .empty;
    try testing.expect(try native.edgefeed.assembleWith(a, &snap, seq, &out, &svc));
    return out.items;
}

test "edge read sets: they arrive over pipelined feed calls as over single ones; the in-flight count changes how many requests a call has, never what a request asks" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const count: u64 = 40;
    const a = w.arena.allocator();
    const win = try Window.prepare(a, w.tmp.dir, "window", count);
    defer win.dir.close(io);
    var core = try Core.build(&w, &win, count, &.{});
    defer core.destroy();
    w.core.feeder.read_sets = &w.core.svc;
    try w.coreUp(true);

    // one request at a time (no in-flight control: the edge of the tests above)
    var single = try EdgeNode.create(&w, &win, "single", true, null, &.{});
    defer single.destroy();
    try single.e.follow();
    try fx.must(single.waitApplied(count, 120_000), "one request at a time", single.e);

    // pipelined: 12 in flight over the 3 fetch threads, 4 requests in each call
    var piped = try EdgeNode.create(&w, &win, "piped", true, null, &.{});
    defer piped.destroy();
    var fl = source_mod.InFlight.init(12, 64, 16);
    piped.e.fetcher.inflight = &fl;
    try piped.e.follow();
    try fx.must(piped.waitApplied(count, 120_000), "pipelined", piped.e);
    // the catch-up came through pipelined calls, several requests each ...
    const calls = fl.calls.load(.acquire);
    const brought = fl.fetched.load(.acquire);
    try testing.expect(calls > 0 and brought >= 2 * calls and brought >= count / 2);
    try testing.expect(fl.peak.load(.acquire) >= 8);
    // ... every one of whose requests asked for read sets and got them: a checkpoint a
    // pipelined call brought without its lists would have no aux record and no mark
    try testing.expect(piped.e.pool.stats.read_sets_asked.load(.monotonic) >= count);
    try testing.expectEqual(piped.e.pool.stats.read_sets_asked.load(.monotonic), piped.e.pool.stats.read_sets_held.load(.monotonic));
    if (win.stale == 0) try testing.expectEqual(count, piped.marks(count));
    try testing.expectEqual(single.marks(count), piped.marks(count));

    // a third edge, pipelined, that does not keep read sets: its calls never carry the flag
    var plain = try EdgeNode.create(&w, &win, "piped-plain", false, null, &.{});
    defer plain.destroy();
    var fl_plain = source_mod.InFlight.init(12, 64, 16);
    plain.e.fetcher.inflight = &fl_plain;
    try plain.e.follow();
    try fx.must(plain.waitApplied(count, 120_000), "pipelined, no read sets", plain.e);
    try testing.expect(fl_plain.calls.load(.acquire) > 0);
    try testing.expectEqual(@as(u64, 0), plain.e.pool.stats.read_sets_asked.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), plain.marks(count));

    var nb: [64]u8 = undefined;
    var listed: u64 = 0;
    for (0..count) |i| {
        const seq = first + i;
        // the same blob and the same aux record were spooled whichever way the checkpoint came
        const chk = try std.fmt.bufPrint(&nb, "{d}.chk", .{seq});
        const blob = try single.e.spool.readFileAlloc(io, chk, a, .limited(1 << 30));
        try testing.expectEqualSlices(u8, blob, try piped.e.spool.readFileAlloc(io, chk, a, .limited(1 << 30)));
        try testing.expectEqualSlices(u8, blob, try plain.e.spool.readFileAlloc(io, chk, a, .limited(1 << 30)));
        const aux = try std.fmt.bufPrint(&nb, "{d}.aux", .{seq});
        const lists = try single.e.spool.readFileAlloc(io, aux, a, .limited(1 << 30));
        try testing.expectEqualSlices(u8, lists, try piped.e.spool.readFileAlloc(io, aux, a, .limited(1 << 30)));
        try testing.expectError(error.FileNotFound, plain.e.spool.statFile(io, aux, .{}));
        for ((try convert.Aux.parse(a, lists)).loaded) |l| listed += @intFromBool(l.len > 0);
        // and both stores hold what the core holds: checkpoint, lists and mark
        const want = try feedWithReadSets(a, w.core.st, seq);
        try testing.expectEqualSlices(u8, want, try feedWithReadSets(a, single.e.st, seq));
        try testing.expectEqualSlices(u8, want, try feedWithReadSets(a, piped.e.st, seq));
    }
    try testing.expect(listed > 0);
    std.debug.print("edge-readsets pipelined: {d} checkpoints; {d} pipelined calls brought {d} of them (peak {d} in flight); read sets asked {d}, held {d}; marked {d}; without read sets: {d} pipelined calls, asked 0\n", .{ count, calls, brought, fl.peak.load(.acquire), piped.e.pool.stats.read_sets_asked.load(.monotonic), piped.e.pool.stats.read_sets_held.load(.monotonic), piped.marks(count), fl_plain.calls.load(.acquire) });
}

test "edge read sets: feed requests the core's queue refuses (two edges on a small fair queue) are asked again; every checkpoint ends with the core's read set or with none, never with a mark it has no lists for" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const count: u64 = 24;
    const a = w.arena.allocator();
    const win = try Window.prepare(a, w.tmp.dir, "window", count);
    defer win.dir.close(io);
    var core = try Core.build(&w, &win, count, &.{});
    defer core.destroy();
    w.core.feeder.read_sets = &w.core.svc;
    // The node's listener with a feed queue of 4 (one worker): two edges sending 4 requests a
    // call from 3 threads each are refused much of what they send. Both edges reach the core
    // from the loopback address, which is one client to the queue's shares (listener.zig
    // `feedClient`), so these refusals are "queue full" at the door. A request refused after
    // it was queued (another client's arrival shrinks the share, fairq.zig) is answered with
    // the same status and the same bytes (jobs.zig `evict_message`): the client cannot tell the
    // two apart and this is the code that handles both.
    w.core.stop();
    w.core.disp.edge = &w.core.feeder;
    const l = try native.listener.Listener.start(w.core.gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = fx.Core.id_seed, .cert = &w.core.cert, .feed_workers = 1, .feed_queue = 4, .feed_min_share = 1 }, &w.core.disp);
    w.core.listener = l;
    w.link.core_port.store(l.address().getPort(), .release);

    var e1 = try EdgeNode.create(&w, &win, "refused-1", true, null, &.{});
    defer e1.destroy();
    var e2 = try EdgeNode.create(&w, &win, "refused-2", true, null, &.{});
    defer e2.destroy();
    var fl1 = source_mod.InFlight.init(12, 64, 16);
    var fl2 = source_mod.InFlight.init(12, 64, 16);
    e1.e.fetcher.inflight = &fl1;
    e2.e.fetcher.inflight = &fl2;
    try e1.e.follow();
    try e2.e.follow();
    try fx.must(e1.waitApplied(count, 240_000), "first edge, refusing core", e1.e);
    try fx.must(e2.waitApplied(count, 240_000), "second edge, refusing core", e2.e);
    const refused = l.feed_stats.refused_over_share.load(.monotonic) + l.feed_stats.refused_full.load(.monotonic);
    // the queue did refuse, and the fetch stage saw it (a refused pipelined request, or a
    // refused single one, which is an error of that try)
    try testing.expect(refused > 0);
    try testing.expect(fl1.errors.load(.monotonic) + fl2.errors.load(.monotonic) + e1.e.pool.stats.errors.load(.monotonic) + e2.e.pool.stats.errors.load(.monotonic) > 0);
    // every checkpoint was asked again until it came, with its lists: both edges hold exactly
    // what the core holds, marks included
    for (0..count) |i| {
        const seq = first + i;
        const want = try feedWithReadSets(a, w.core.st, seq);
        try testing.expectEqualSlices(u8, want, try feedWithReadSets(a, e1.e.st, seq));
        try testing.expectEqualSlices(u8, want, try feedWithReadSets(a, e2.e.st, seq));
    }
    if (win.stale == 0) {
        try testing.expectEqual(count, e1.marks(count));
        try testing.expectEqual(count, e2.marks(count));
    }
    inline for (.{ &e1, &e2 }) |en| {
        const hs = &en.rs.?.h.stats;
        try testing.expectEqual(@as(u64, 0), hs.edge_rejected.load(.monotonic));
        // a mark only ever with the lists that came with that checkpoint's blob
        try testing.expectEqual(hs.marked.load(.monotonic), en.marks(count));
    }
    std.debug.print("edge-readsets refused: {d} checkpoints to two edges through a feed queue of 4; the core refused {d} feed requests ({d} over a client's share, {d} queue full); pipelined calls with a refusal or failure {d}, single requests failed {d}; marked {d} and {d}\n", .{ count, refused, l.feed_stats.refused_over_share.load(.monotonic), l.feed_stats.refused_full.load(.monotonic), fl1.errors.load(.monotonic) + fl2.errors.load(.monotonic), e1.e.pool.stats.errors.load(.monotonic) + e2.e.pool.stats.errors.load(.monotonic), e1.marks(count), e2.marks(count) });
}

// ------------------------------------------------------------------ the re-ask (docs/EDGE.md 12.7)

/// The core's `read_sets` hook as a p2p-built core answers it while its reconcile is pending:
/// "none held" for the first `deny[i]` asks of checkpoint `first + i`, then the store's own
/// answer. Asks are counted per checkpoint (the feed's own, then each re-ask).
const Script = struct {
    mu: std.atomic.Mutex = .unlocked,
    calls: [64]u32 = @splat(0),
    deny: [64]u32 = @splat(0),

    fn has(ctx: *const anyopaque, snap: *const store.Snapshot, seq: u64) bool {
        const s: *Script = @ptrCast(@alignCast(@constCast(ctx)));
        const i = seq - first;
        if (i < s.calls.len) {
            while (!s.mu.tryLock()) std.atomic.spinLoopHint();
            defer s.mu.unlock();
            const n = s.calls[i];
            s.calls[i] = n + 1;
            if (n < s.deny[i]) return false;
        }
        return history.readSetHeld(snap, seq);
    }

    fn set(s: *Script, deny: []const u32) void {
        while (!s.mu.tryLock()) std.atomic.spinLoopHint();
        defer s.mu.unlock();
        s.calls = @splat(0);
        s.deny = @splat(0);
        @memcpy(s.deny[0..deny.len], deny);
    }
};

/// The re-ask on an edge of the fixture, as node.zig wires it.
fn reAskOn(en: *EdgeNode, cfg: @import("reask.zig").Config) !*@import("reask.zig").ReAsk {
    const R = @import("reask.zig").ReAsk;
    const r = try sys.create(R);
    r.* = .{ .gpa = testing.allocator, .io = io, .pool = en.e.pool, .hist = &en.rs.?.h, .st = en.e.st, .cfg = cfg };
    en.e.src.reask = r;
    try r.start();
    return r;
}

fn reAskDone(r: *@import("reask.zig").ReAsk) void {
    r.deinit();
    sys.destroy(r);
}

/// `reask.schedule_ms` scaled down (250 ms, 600 ms, 2 s, 5 s, 11 s become 10 to 250 ms): the
/// same five attempts, in the same order.
const quick_schedule = [_]u64{ 10, 25, 60, 120, 250 };
const quick_reask: @import("reask.zig").Config = .{ .schedule = &quick_schedule, .give_up_ms = 1_000 };

// Two edges on one core whose hook says "none held" for the first checkpoints of the window, as a
// core that builds over p2p does until each checkpoint's reconcile (about 0.2 s after the build).
// The core starts with 6 checkpoints. The first edge meets a core that never settles them: it
// asks each at all five times of the schedule, gives them up as `unsettled`, and those
// checkpoints stay unmarked and forwarded. The second edge meets one that settles checkpoint i
// at attempt deny[i]: the first (250 ms), the second (600 ms), the third (2 s), the fourth (the
// 5 s-style delay, twice) and the last (past the core's 10 s bucket fallback). Its late lists are
// checked and wait for the next commit group: none is marked, and none counts as settled, while
// the core has nothing new. Then the core takes 6 more checkpoints (held at once), the edges
// follow, and the second edge holds every checkpoint's lists and mark exactly as the core does,
// counts each settled by its attempt, and answers an `effects` read of an early checkpoint
// itself. Last, the hold is off (`read_set_hold_ms` 0): a read of a checkpoint without its mark
// goes to the core at once, whether a re-ask is under way for it or not, and nothing is held.
test "edge read sets: a checkpoint fed without its read set is asked again; one the core settles later is stored with its lists and mark, one it never settles stays forwarded" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const total: u64 = 12;
    const early: u64 = 6;
    const a = w.arena.allocator();
    const win = try Window.prepare(a, w.tmp.dir, "window", total);
    defer win.dir.close(io);
    var core = try Core.build(&w, &win, early, &.{});
    defer core.destroy();
    var script: Script = .{};
    const deny_all: [early]u32 = @splat(std.math.maxInt(u32));
    script.set(&deny_all);
    w.core.svc.read_sets = .{ .ctx = &script, .has = Script.has };
    w.core.feeder.read_sets = &w.core.svc;
    try w.coreUp(true);
    const core_rpc = try Rpc.start(w.core.svc.handler());
    defer core_rpc.stop();
    const txs = try windowTxs(a, w.core.st, early);
    const probe: ?*const Tx = for (txs) |*t| {
        if (t.loaded > 0 and t.sigs == 1) break t;
    } else null;
    const G = edge.client.ReadSetsGaveUp;
    const attempts = edge.client.read_sets_attempts;

    // ---- a core that never settles the early checkpoints
    var never = try EdgeNode.create(&w, &win, "reask-never", true, null, &.{});
    defer never.destroy();
    const r_never = try reAskOn(&never, quick_reask);
    defer reAskDone(r_never);
    try never.e.follow();
    try fx.must(never.waitApplied(early, 60_000), "re-ask, core never settles", never.e);
    const ns = &never.e.pool.stats;
    var t0 = fx.nowNs();
    while (ns.gaveUpTotal() < early and fx.nowNs() - t0 < 30_000 * ms) fx.sleepMs(5);
    try testing.expectEqual(early, ns.read_sets_gave_up[@intFromEnum(G.unsettled)].load(.monotonic));
    try testing.expectEqual(early, ns.gaveUpTotal());
    try testing.expectEqual(attempts * early, ns.read_sets_reasked.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), ns.settledTotal());
    try testing.expectEqual(@as(usize, 0), r_never.pending());

    // ---- a core that settles checkpoint i at re-ask deny[i] (the feed's own ask is the first
    // "none", so deny[i] asks are refused in all)
    const deny = [early]u32{ 1, 2, 3, 4, 5, 4 };
    var want_settled: [attempts]u64 = @splat(0);
    var want_reasked: u64 = 0;
    for (deny) |d| {
        want_settled[d - 1] += 1;
        want_reasked += d;
    }
    script.set(&deny);
    var late = try EdgeNode.create(&w, &win, "reask-late", true, null, &.{});
    defer late.destroy();
    const r_late = try reAskOn(&late, quick_reask);
    defer reAskDone(r_late);
    try late.e.follow();
    try fx.must(late.waitApplied(early, 60_000), "re-ask, core settles late", late.e);
    const ls = &late.e.pool.stats;
    const staged_n = &r_late.outcomes[@intFromEnum(history.LateOutcome.staged)];
    t0 = fx.nowNs();
    const already_n = &r_late.outcomes[@intFromEnum(history.LateOutcome.already)];
    // every checkpoint planned (a settled one was planned first), found marked, or given up
    while (staged_n.load(.monotonic) + already_n.load(.monotonic) + ls.gaveUpTotal() < early and fx.nowNs() - t0 < 30_000 * ms) fx.sleepMs(5);
    const staged = staged_n.load(.monotonic);
    // A plan is written by the first commit group after it, and only then marked and counted
    // settled; until then it is pending (a read of it may be held). The first re-asks can land
    // while the edge still applies the early checkpoints, so some may be written already; the
    // ones planned after the last commit wait for the core's next checkpoint. (The follower is
    // idle here: no group is open.)
    const written = late.rs.?.h.stats.late_marked.load(.monotonic);
    try testing.expectEqual(written, late.marks(early));
    try testing.expectEqual(written, ls.settledTotal());
    try testing.expectEqual(@as(usize, @intCast(staged - written)), r_late.pending());
    {
        var snap = late.e.st.snapshot();
        defer snap.release();
        for (0..early) |i| if (!history.readSetHeld(&snap, first + i)) try testing.expectEqual(win.stale == 0, r_late.isPending(first + i));
    }
    if (win.stale == 0) {
        try testing.expectEqual(early, staged);
        try testing.expectEqual(@as(u64, 0), ls.gaveUpTotal());
        try testing.expectEqual(want_reasked, ls.read_sets_reasked.load(.monotonic));
    }

    // ---- the core goes on (held at once); both edges follow
    try core.apply(&w, first + early, total);
    try fx.must(never.waitApplied(total, 60_000), "re-ask, never, second half", never.e);
    try fx.must(late.waitApplied(total, 60_000), "re-ask, late, second half", late.e);
    // every staged plan went into the first commit group after it, with its mark last, and
    // counted settled by the attempt that brought it
    try testing.expectEqual(staged, late.rs.?.h.stats.late_marked.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), late.rs.?.h.stats.late_dropped.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), late.rs.?.h.stats.edge_rejected.load(.monotonic));
    try testing.expectEqual(staged, ls.settledTotal());
    try testing.expectEqual(@as(usize, 0), r_late.pending());
    try testing.expectEqual(@as(u64, 0), never.rs.?.h.stats.late_marked.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), never.marks(early));
    if (win.stale == 0) {
        for (want_settled, &ls.read_sets_settled) |want, *got| try testing.expectEqual(want, got.load(.monotonic));
        try testing.expectEqual(@as(u64, 0), ls.gaveUpTotal());
        try testing.expectEqual(total, late.marks(total));
        try testing.expectEqual(total - early, never.marks(total));
        // the late edge holds what the core holds: checkpoint, lists, mark
        for (0..total) |i| {
            const seq = first + i;
            try testing.expectEqualSlices(u8, try feedWithReadSets(a, w.core.st, seq), try feedWithReadSets(a, late.e.st, seq));
        }
    }
    // a mark only with its lists, on both
    try testing.expectEqual(late.rs.?.h.stats.marked.load(.monotonic), late.marks(total));
    try testing.expectEqual(never.rs.?.h.stats.marked.load(.monotonic), never.marks(total));

    // ---- the read: answered by the late edge, forwarded by the other
    ReadSets.serveFrom(&w.core.svc);
    if (probe) |p| {
        const held = blk: {
            var snap = late.e.st.snapshot();
            defer snap.release();
            break :blk history.readSetHeld(&snap, p.seq);
        };
        if (win.stale == 0) try testing.expect(held);
        if (held) {
            try testing.expectEqual(Routed.local, try effectsRead(&w, &late, core_rpc.port, p, true));
            // ---- the hold is off: the same read while the mark is still to come is not held
            inline for (.{ HoldCase.comes, HoldCase.never, HoldCase.not_pending }) |case| try testing.expectEqual(HoldEnd.none, try heldRead(&w, &late, core_rpc.port, p, case));
        }
        try testing.expectEqual(Routed.forwarded, try effectsRead(&w, &never, core_rpc.port, p, true));
    }
    std.debug.print("edge-readsets re-ask: {d} checkpoints fed without read sets; a core that never settles: {d} re-asks, {d} given up unsettled, {d} marked; one that settles late: {d} re-asks, settled by attempt {any}, {d} given up, {d} written into the next commit group, {d} of {d} checkpoints marked\n", .{ early, ns.read_sets_reasked.load(.monotonic), ns.read_sets_gave_up[@intFromEnum(G.unsettled)].load(.monotonic), never.marks(early), ls.read_sets_reasked.load(.monotonic), want_settled, ls.gaveUpTotal(), late.rs.?.h.stats.late_marked.load(.monotonic), late.marks(total), total });
}

/// A loaded entry of checkpoint `seq` whose object checkpoint `seq + 1` changes, from the
/// version the entry names, and that `seq` itself does not change.
const Hit = struct { seq: u64, id: [32]u8, version: u64 };

/// Every object the transactions of `blob` change (accumulator writes are not changes), with
/// the input version of its first change (0: created or unwrapped).
fn changedIn(a: std.mem.Allocator, blob: []const u8) !std.AutoHashMapUnmanaged([32]u8, u64) {
    var idx = try types.index.CheckpointIndex.init(testing.allocator);
    defer idx.deinit(testing.allocator);
    try types.index.indexCheckpointData(blob, &idx);
    var out: std.AutoHashMapUnmanaged([32]u8, u64) = .empty;
    for (0..idx.tx_count) |k| {
        const t = idx.txAt(k);
        switch (try bcs.decode(types.TransactionEffects, a, t.effects.slice(blob))) {
            .V2 => |v| for (v.changed_objects) |ch| {
                if (ch[1].output_state == .AccumulatorWriteV1) continue;
                const gop = try out.getOrPut(a, ch[0].@"0".@"0");
                if (!gop.found_existing) gop.value_ptr.* = switch (ch[1].input_state) {
                    .Exist => |x| x[0][0].@"0",
                    .NotExist => 0,
                };
            },
            .V1 => {},
        }
    }
    return out;
}

/// The first checkpoint of the window's first `count - 2` with a `Hit` (two more checkpoints
/// follow it in the window).
fn listedThenChanged(a: std.mem.Allocator, win: *const Window, count: u64) !?Hit {
    for (0..@intCast(count - 2)) |i| {
        const seq = first + i;
        const here = try changedIn(a, try fx.readSeq(a, win.dir, seq, ".chk"));
        const next = try changedIn(a, try fx.readSeq(a, win.dir, seq + 1, ".chk"));
        const x = try convert.Aux.parse(a, try fx.readSeq(a, win.dir, seq, ".aux"));
        for (x.loaded) |list| for (list) |r| {
            if (here.contains(r.id)) continue;
            if (next.get(r.id)) |v| if (v == r.version) return .{ .seq = seq, .id = r.id, .version = r.version };
        };
    }
    return null;
}

// Late lists for a checkpoint N after N + 1 changed an object N's list names (keepers touch the
// same hot objects every checkpoint). The edge is fed N without lists and N + 1 with them;
// then N's lists come late, as the re-ask brings them.
// - From a snapshot taken while N + 1's commit is in flight: the store's live table holds N + 1's
//   version already, the snapshot's tip is still N. Before the fix the listed version was found
//   but not live, and N + 1's change was not in `first`: rejected ("the read sets its source
//   sent late fail the edge's checks"). Now the version as of the snapshot is the one: accepted.
// - From a snapshot after N + 1 was published (`first` has N + 1's change): accepted.
// The accepted lists go into the next commit group; then the edge holds N's read set as the core
// does and answers an effects read of a transaction of N itself, equal to the core's answer.
test "edge read sets: late lists for checkpoint N are accepted after N + 1 changed an object they name, also while N + 1's commit is in flight" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const scan: u64 = 24;
    const a = w.arena.allocator();
    const win = try Window.prepare(a, w.tmp.dir, "window", scan);
    defer win.dir.close(io);
    const hit = (try listedThenChanged(a, &win, scan)) orelse {
        std.debug.print("edge-readsets late check: no checkpoint of the {d}-checkpoint window lists an object the next one changes\n", .{scan});
        return error.TestUnexpectedResult;
    };
    const n = hit.seq;
    const upto = n - first + 1; // checkpoints first ..= N
    var core = try Core.build(&w, &win, upto, &.{});
    defer core.destroy();
    // the core holds N's read set but says "none" for it: the edge applies N without lists
    var script: Script = .{};
    var deny: [64]u32 = @splat(0);
    deny[@intCast(n - first)] = std.math.maxInt(u32);
    script.set(deny[0..@intCast(upto)]);
    w.core.svc.read_sets = .{ .ctx = &script, .has = Script.has };
    w.core.feeder.read_sets = &w.core.svc;
    try w.coreUp(true);
    const core_rpc = try Rpc.start(w.core.svc.handler());
    defer core_rpc.stop();

    var en = try EdgeNode.create(&w, &win, "late-check", true, null, &.{});
    defer en.destroy();
    const h = &en.rs.?.h;
    try en.e.follow();
    try fx.must(en.waitApplied(upto, 60_000), "late check, through N", en.e);
    {
        var snap = en.e.st.snapshot();
        defer snap.release();
        try testing.expect(!history.readSetHeld(&snap, n));
    }
    // A late plan starts on this snapshot (tip N) ...
    var stale = en.e.st.snapshot();
    defer stale.release();
    // ... while the edge commits N + 1, which changes the listed object.
    try core.apply(&w, n + 1, upto + 1);
    try fx.must(en.waitApplied(upto + 1, 60_000), "late check, N + 1", en.e);
    try testing.expectEqual(n, stale.highestCommitted().?);
    const f = (try stale.objectFind(&hit.id, hit.version)) orelse return error.TestUnexpectedResult;
    try testing.expect(!f.live); // the old rule (`live`) rejected the list here

    // N's lists, as the core sends them late, and N's contents as stored
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(testing.allocator);
    try aux.appendSlice(testing.allocator, try fx.readSeq(a, win.dir, n, ".aux"));
    try convert.auxListsOnly(&aux, testing.allocator, a);
    const contents = blk: {
        var snap = w.core.st.snapshot();
        defer snap.release();
        break :blk try a.dupe(u8, (snap.checkpoint(n) orelse return error.TestUnexpectedResult).contents);
    };

    var plan: ?*history.LatePlan = null;
    const in_flight = try h.planLateIn(testing.allocator, &stale, n, contents, aux.items, &plan);
    if (plan) |p| p.destroy();
    const published = try h.planLate(testing.allocator, en.e.st, n, contents, aux.items);
    try testing.expectEqual(@as(u64, 0), h.stats.edge_rejected.load(.monotonic));
    if (win.stale == 0) {
        try testing.expectEqual(history.LateOutcome.staged, in_flight);
        try testing.expectEqual(history.LateOutcome.staged, published);
    }
    // the next commit group takes the plan
    try core.apply(&w, n + 2, upto + 2);
    try fx.must(en.waitApplied(upto + 2, 60_000), "late check, N + 2", en.e);
    const marked = blk: {
        var snap = en.e.st.snapshot();
        defer snap.release();
        break :blk history.readSetHeld(&snap, n);
    };
    try testing.expectEqual(published == .staged, marked);
    try testing.expectEqual(@as(u64, @intFromBool(marked)), h.stats.late_marked.load(.monotonic));
    if (marked) {
        // what the core holds for N: checkpoint, lists, mark
        try testing.expectEqualSlices(u8, try feedWithReadSets(a, w.core.st, n), try feedWithReadSets(a, en.e.st, n));
        // an effects read of a transaction of N: the edge answers it, equal to the core's
        ReadSets.serveFrom(&w.core.svc);
        const txs = try windowTxs(a, w.core.st, upto + 2);
        const probe: ?*const Tx = for (txs) |*t| {
            if (t.seq == n and t.sigs == 1) break t;
        } else null;
        try testing.expect(probe != null);
        try testing.expectEqual(Routed.local, try effectsRead(&w, &en, core_rpc.port, probe.?, true));
    }
    std.debug.print("edge-readsets late check: checkpoint {d} lists {x} at version {d}, which {d} changes; late lists from a snapshot taken while {d} was in flight: {s}; after it: {s}; marked {any}\n", .{ n, hit.id[0..8], hit.version, n + 1, n + 1, @tagName(in_flight), @tagName(published), marked });
}

/// The edge's read-set hook while a re-ask is under way (`heldRead`): the checkpoint's mark is
/// "not held" until the hold has looked once (`comes`), never (`never`); `not_pending`: no
/// re-ask is under way for it.
const HoldCase = enum { comes, never, not_pending };
const HoldEnd = enum { none, marked, forwarded };

const HoldScript = struct {
    case: HoldCase,
    seq: u64,
    /// `has` calls for `seq` since the hold asked whether a re-ask is pending.
    armed: Atomic(bool) = .init(false),
    looks: Atomic(u32) = .init(0),

    fn has(ctx: *const anyopaque, snap: *const store.Snapshot, seq: u64) bool {
        const s: *HoldScript = @ptrCast(@alignCast(@constCast(ctx)));
        if (seq != s.seq) return history.readSetHeld(snap, seq);
        if (!s.armed.load(.acquire)) return false; // the first local attempt meets the gap
        const n = s.looks.fetchAdd(1, .acq_rel);
        // the hold's first look: still none; its second (after a wait slice): here
        return switch (s.case) {
            .comes => n >= 1 and history.readSetHeld(snap, seq),
            .never, .not_pending => false,
        };
    }

    fn pending(ctx: *anyopaque, seq: u64) bool {
        const s: *HoldScript = @ptrCast(@alignCast(ctx));
        if (seq != s.seq or s.case == .not_pending) return false;
        s.armed.store(true, .release);
        return true;
    }
};

/// One GetTransaction under `effects` of `t` through a forwarder in front of `en` with the hold's
/// hook installed as node.zig installs it and the forwarder's default bound (`read_set_hold_ms`,
/// any checkpoint of the window near enough), while `t`'s checkpoint is scripted by `case`: how
/// the hold ended, checked against the routing and the core's answer.
fn heldRead(w: *fx.World, en: *EdgeNode, core_port: u16, t: *const Tx, case: HoldCase) !HoldEnd {
    var front: Front = undefined;
    try front.create(en.e.st, core_port);
    defer front.destroy();
    ReadSets.serveFrom(&front.svc);
    var hs: HoldScript = .{ .case = case, .seq = t.seq };
    front.svc.read_sets = .{ .ctx = &hs, .has = HoldScript.has };
    try testing.expectEqual(forward.read_set_hold_ms, front.f.cfg.read_set_hold_ms);
    front.f.cfg.read_set_hold_near = 64;
    front.f.read_set_hold = .{ .ctx = &hs, .pending = HoldScript.pending };
    var d: Diff = .{ .arena = std.heap.ArenaAllocator.init(testing.allocator), .core_h = w.core.svc.handler(), .edge_h = front.f.handler(), .fwd = front.f };
    defer d.deinit();
    const rq: Req = .{ .a = d.arena.allocator() };
    const how = try d.check(p_tx, try rq.tx(&t.digest, "effects"), true);
    try testing.expectEqual(@as(u64, 0), d.differences);
    const m = &front.f.metrics;
    const marked = m.read_set_hold_marked.load(.monotonic);
    const fwd = m.read_set_hold_forwarded.load(.monotonic);
    try testing.expect(marked + fwd <= 1);
    const end: HoldEnd = if (marked == 1) .marked else if (fwd == 1) .forwarded else .none;
    // marked in time: answered here; otherwise the core answered, as without a hold
    try testing.expectEqual(if (end == .marked) Routed.local else Routed.forwarded, how);
    try testing.expectEqual(@as(u64, @intFromBool(end != .none)), m.read_set_hold.n.load(.monotonic));
    // with the bound at 0 the hold is not entered: the re-ask is not even asked about
    if (front.f.cfg.read_set_hold_ms == 0) try testing.expect(!hs.armed.load(.acquire));
    return end;
}

// ------------------------------------------------------------------ the policy settings (docs/EDGE.md 11.8)

// `--edge-balance-lists local` and `--edge-simulate local` on the conformance fixture: a core
// that followed the window over its base, and an edge built from that core's feed with read
// sets over the same base. What each node gets beside that, and what the run can show:
// - a StateService index. The core's starts at the base and takes the window's checkpoints one
//   by one (the path of a node that has followed for a long time, which keeps the rows of coin
//   types emptied to zero); the edge's is built from its live set at the tip (the path of a
//   node restored from a snapshot, which has none). ListBalances is asked for every address
//   that owns a live object, and for the sender of every transaction of the window.
// - the node's own SimulateTransaction service (node/rpc.zig) over its store. The epoch
//   parameters are the corpus' (`epochs.jsonl`), the same on both: the base holds `0x5` only
//   when the window read it. The simulated transactions are the NEXT checkpoint's (its inputs
//   are part of the base, it is applied on neither node), so each runs on the state it met on
//   chain unless an earlier transaction of that checkpoint wrote one of its inputs. Each is asked
//   four ways: as it is, with checks disabled, with gas selection, and with gas selection as the
//   SDK asks before signing (the message form with kind and sender only: no gas payment, no
//   budget, no price), which makes the node pick the coins and estimate the budget. A third
//   pass runs `--edge-simulate local-gas`: there every gas selection the edge answers is
//   compared field by field with the core's, and the transaction the edge resolved is given to
//   the core to simulate as it is.
// It is a sample (`ZUI_EDGE_POLICY_COUNT` checkpoints, default 200), on one process and one
// tip: it does not show an edge that lags its core, nor two nodes with different uptimes
// (`suggested_gas_price`), nor a core with a transaction driver (gas selection's proposers).
test "edge policy conformance: with --edge-balance-lists local and --edge-simulate local an edge built from its core's feed answers ListBalances (differences in zero rows only) and the next checkpoint's simulations as the core does" {
    var w: fx.World = undefined;
    try w.init();
    defer w.deinit();
    const count = envU("ZUI_EDGE_POLICY_COUNT", 200);
    const a = w.arena.allocator();
    const next = first + count;

    // the base covers the next checkpoint's reads too; its files leave the directory the core follows
    const win = try Window.prepare(a, w.tmp.dir, "window", count + 1);
    defer win.dir.close(io);
    const next_blob = try fx.readSeq(a, win.dir, next, ".chk");
    {
        var nb: [64]u8 = undefined;
        try win.dir.deleteFile(io, try std.fmt.bufPrint(&nb, "{d}.chk", .{next}));
        try win.dir.deleteFile(io, try std.fmt.bufPrint(&nb, "{d}.aux", .{next}));
    }

    // ---- packages. The archive's input objects carry none, and a node restored from a snapshot
    // holds them all: both stores get, as live objects, every corpus package whose id appears
    // anywhere in the next checkpoint (transactions, type arguments, object types), their
    // linkage, and the system packages as the last epoch changes left them.
    var extra: std.ArrayList(BaseObj) = .empty;
    var n_user: usize = 0;
    {
        var pb: [512]u8 = undefined;
        const text = Io.Dir.cwd().readFileAlloc(io, try std.fmt.bufPrint(&pb, "{s}/packages/index.jsonl", .{try fx.corpus()}), a, .limited(256 << 20)) catch return error.SkipZigTest;
        const L = struct { id: []const u8, linkage: []const []const u8 = &.{} };
        var known: std.AutoHashMapUnmanaged([32]u8, []const []const u8) = .empty;
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| {
            if (std.mem.trim(u8, line, " \r").len == 0) continue;
            const l = try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true });
            var id: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&id, l.id) catch continue;
            try known.put(a, id, l.linkage);
        }
        var want: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty;
        var i: usize = 0;
        while (i + 32 <= next_blob.len) : (i += 1) {
            const id = next_blob[i..][0..32];
            if (known.contains(id.*)) try want.put(a, id.*, {});
        }
        // the linkage of each (a linkage table lists every dependency, so one round is the closure)
        var k: usize = 0;
        while (k < want.count()) : (k += 1) {
            for (known.get(want.keys()[k]) orelse continue) |dep| {
                var id: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&id, dep) catch continue;
                if (known.contains(id)) try want.put(a, id, {});
            }
        }
        const pdir = try fx.corpusDir("packages");
        defer pdir.close(io);
        for (want.keys()) |*id| {
            var nb: [80]u8 = undefined;
            const raw = pdir.readFileAlloc(io, try std.fmt.bufPrint(&nb, "{x}.obj", .{id}), a, .limited(1 << 28)) catch continue;
            const v = exec.objects.ObjectView.parse(raw) catch continue;
            try extra.append(a, .{ .id = id.*, .version = v.version, .raw = raw });
        }
        n_user = extra.items.len;
        // system packages: the newest write of each in an epoch's last checkpoint before this epoch
        const etext = Io.Dir.cwd().readFileAlloc(io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{try fx.corpus()}), a, .limited(64 << 20)) catch return error.SkipZigTest;
        const E = struct { epoch: u64, last: ?u64 = null };
        var lasts: std.ArrayList(E) = .empty;
        var eit = std.mem.splitScalar(u8, etext, '\n');
        while (eit.next()) |line| {
            if (std.mem.trim(u8, line, " \r").len == 0) continue;
            const l = try std.json.parseFromSliceLeaky(E, a, line, .{ .ignore_unknown_fields = true });
            if (l.epoch < first_epoch) try lasts.append(a, l);
        }
        var have: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
        var core_ids: usize = 0; // of 0x1, 0x2, 0x3
        var idx = try types.index.CheckpointIndex.init(testing.allocator);
        defer idx.deinit(testing.allocator);
        var scanned: usize = 0;
        var e = lasts.items.len;
        while (e > 0 and core_ids < 3 and scanned < 400) {
            e -= 1;
            const seq = lasts.items[e].last orelse continue;
            const blob = fx.readSeq(a, w.core.chk, seq, ".chk") catch continue;
            scanned += 1;
            try types.index.indexCheckpointData(blob, &idx);
            for (0..idx.tx_count) |t| {
                const tx = idx.txAt(t);
                for (idx.objs[tx.out_first..][0..tx.out_count]) |r| {
                    const raw = r.slice(blob);
                    const v = exec.objects.ObjectView.parse(raw) catch continue;
                    if (!v.is_package or !exec.packages.isSystemPackage(&v.id) or have.contains(v.id)) continue;
                    try have.put(a, v.id, {});
                    try extra.append(a, .{ .id = v.id, .version = v.version, .raw = raw });
                    if (std.mem.allEqual(u8, v.id[0..31], 0) and v.id[31] >= 1 and v.id[31] <= 3) core_ids += 1;
                }
            }
        }
        if (core_ids < 3) return error.SkipZigTest; // the corpus lacks the framework's checkpoints
    }

    // ---- the core, and its index from the base on
    var core_ix = try index.Index.init(testing.allocator);
    defer core_ix.deinit();
    for (win.base) |o| try core_ix.insert(o.raw);
    for (extra.items) |o| try core_ix.insert(o.raw);
    core_ix.setCheckpoint(first - 1);
    var core = try Core.build(&w, &win, count, extra.items);
    defer core.destroy();
    var core_feed = index.feed.Feed.init(testing.allocator, &core_ix, w.core.st);
    defer core_feed.deinit();
    {
        var snap = w.core.st.snapshot();
        defer snap.release();
        try testing.expectEqual(count, try core_feed.replayTo(&snap, next - 1));
    }
    try testing.expectEqual(@as(u64, 0), core_feed.missing_old);
    try testing.expectEqual(@as(?u64, next - 1), core_ix.liveCheckpoint());
    w.core.svc.state = index.state.hook(&core_ix);
    w.core.feeder.read_sets = &w.core.svc;
    try w.coreUp(true);

    // ---- the edge: the same base, the feed with read sets; its index from its live set
    var en = try EdgeNode.create(&w, &win, "policy", true, null, extra.items);
    defer en.destroy();
    try en.e.follow();
    try fx.must(en.waitApplied(count, 120_000 + count * 2_000), "the edge applied the window", en.e);
    try testing.expectEqual(count, en.marks(count));
    var edge_ix = try index.Index.init(testing.allocator);
    defer edge_ix.deinit();
    var edge_feed = index.feed.Feed.init(testing.allocator, &edge_ix, en.e.st);
    defer edge_feed.deinit();
    try edge_feed.rebuild();
    try testing.expectEqual(@as(?u64, next - 1), edge_ix.liveCheckpoint());

    // ---- SimulateTransaction on both, with the epoch's parameters from the corpus
    const Env = struct {
        var env: rpc_exec.EpochEnv = undefined;
        fn get(_: *const anyopaque) ?rpc_exec.EpochEnv {
            return env;
        }
    };
    {
        var pb: [512]u8 = undefined;
        const text = Io.Dir.cwd().readFileAlloc(io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{try fx.corpus()}), a, .limited(64 << 20)) catch return error.SkipZigTest;
        const L = struct { epoch: u64, pv: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };
        var found: ?L = null;
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| {
            if (std.mem.trim(u8, line, " \r").len == 0) continue;
            const l = try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true });
            if (l.epoch == first_epoch) found = l;
        }
        const l = found orelse return error.SkipZigTest;
        const pv = l.pv orelse return error.SkipZigTest;
        Env.env = .{
            .chain_id = serve.b58.decode32("4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S").?,
            .epoch = first_epoch,
            .pv = pv,
            .cfg = try protocol.get(pv, .mainnet),
            .rgp = l.rgp orelse return error.SkipZigTest,
            .epoch_start_ms = l.start_ms orelse return error.SkipZigTest,
            .committee_size = @intCast(w.committee.keys.len),
        };
    }
    const core_x = try sys.create(node_rpc.Rpc);
    defer sys.destroy(core_x);
    try core_x.init(testing.allocator, io, w.core.st, Env.env.chain_id);
    defer core_x.deinit();
    const edge_x = try sys.create(node_rpc.Rpc);
    defer sys.destroy(edge_x);
    try edge_x.init(testing.allocator, io, en.e.st, Env.env.chain_id);
    defer edge_x.deinit();
    for ([_]*node_rpc.Rpc{ core_x, edge_x }) |x| x.svc.env = .{ .ctx = x, .get = Env.get };
    // gas selection reads each node's own owner index
    core_x.setIndex(&core_ix);
    edge_x.setIndex(&edge_ix);
    w.core.svc.execution = core_x.handler();
    defer w.core.svc.execution = null;
    defer w.core.svc.state = null;

    const core_rpc = try Rpc.start(w.core.svc.handler());
    defer core_rpc.stop();
    var front: Front = undefined;
    try front.create(en.e.st, core_rpc.port);
    defer front.destroy();
    ReadSets.serveFrom(&front.svc);
    front.svc.state = index.state.hook(&edge_ix);
    front.svc.execution = edge_x.handler();
    const core_h = w.core.svc.handler();
    const edge_h = front.f.handler();

    // ---- the requests
    // every address that owns a live object on the core, and every sender of the window
    var owners: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty;
    {
        var snap = w.core.st.snapshot();
        defer snap.release();
        const Each = struct {
            set: *std.AutoArrayHashMapUnmanaged([32]u8, void),
            gpa: std.mem.Allocator,
            fn each(c: @This(), _: *const [32]u8, _: u64, bytes: []const u8) anyerror!void {
                const v = exec.objects.ObjectView.parse(bytes) catch return;
                const o = bytes[v.owner_at..];
                // Owner: AddressOwner (0) and ConsensusAddressOwner (4: start version, then the address)
                if (o.len >= 33 and o[0] == 0) try c.set.put(c.gpa, o[1..33].*, {});
                if (o.len >= 41 and o[0] == 4) try c.set.put(c.gpa, o[9..41].*, {});
            }
        };
        try snap.forEachLive(Each{ .set = &owners, .gpa = a }, Each.each);
        for (0..count) |i| {
            const cp = snap.checkpoint(first + i) orelse return error.TestUnexpectedResult;
            for (try native.dispatch.contentDigests(a, cp.contents)) |dg| {
                const rec = snap.transaction(&dg) orelse return error.TestUnexpectedResult;
                const sp = try service.splitEnvelope(a, rec.tx);
                const td = try @import("bcs").decode(types.TransactionData, a, sp.data);
                try owners.put(a, td.V1.sender.@"0", {});
            }
        }
    }
    // Keeper style: the objects every one of the window's last `hot_span` checkpoints changed
    // (the clock, and shared objects as hot as a perp pool or an oracle), and which of the next
    // checkpoint's transactions take one of them as a shared input.
    const hot_span: u64 = @min(count, 8);
    var hot: std.AutoHashMapUnmanaged([32]u8, u64) = .empty;
    {
        var snap = w.core.st.snapshot();
        defer snap.release();
        var s = next - hot_span;
        while (s < next) : (s += 1) {
            const cp = snap.checkpoint(s) orelse return error.TestUnexpectedResult;
            var seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
            for (try native.dispatch.contentDigests(a, cp.contents)) |dg| {
                const rec = snap.transaction(&dg) orelse return error.TestUnexpectedResult;
                switch (try @import("bcs").decode(types.TransactionEffects, a, rec.effects)) {
                    .V2 => |v| for (v.changed_objects) |ch| try seen.put(a, ch[0].@"0".@"0", {}),
                    .V1 => {},
                }
            }
            var it = seen.keyIterator();
            while (it.next()) |id| {
                const g = try hot.getOrPut(a, id.*);
                if (!g.found_existing) g.value_ptr.* = 0;
                g.value_ptr.* += 1;
            }
        }
    }
    const Keeper = struct {
        fn of(al: std.mem.Allocator, hot_ids: *const std.AutoHashMapUnmanaged([32]u8, u64), span: u64, td_bytes: []const u8) bool {
            const td = @import("bcs").decode(types.TransactionData, al, td_bytes) catch return false;
            const p = switch (td.V1.kind) {
                .ProgrammableTransaction => |p| p,
                else => return false,
            };
            for (p.inputs) |in| switch (in) {
                .Object => |o| switch (o) {
                    .SharedObject => |so| if ((hot_ids.get(so.id.@"0".@"0") orelse 0) == span) return true,
                    else => {},
                },
                else => {},
            };
            return false;
        }
    };
    // the next checkpoint's transactions (TransactionData, as BCS), and which are keeper style
    var sims: std.ArrayList([]const u8) = .empty;
    var sims_keeper: std.ArrayList(bool) = .empty;
    {
        var idx = try types.index.CheckpointIndex.init(testing.allocator);
        defer idx.deinit(testing.allocator);
        try types.index.indexCheckpointData(next_blob, &idx);
        for (0..idx.tx_count) |k| {
            const td = idx.txAt(k).data.slice(next_blob);
            try sims.append(a, td);
            try sims_keeper.append(a, Keeper.of(a, &hot, hot_span, td));
        }
    }
    try testing.expect(owners.count() > 0 and sims.items.len > 0);

    const p_balances = "/sui.rpc.v2.StateService/ListBalances";
    const p_simulate = "/sui.rpc.v2.TransactionExecutionService/SimulateTransaction";
    const Tally = struct {
        asked: u64 = 0,
        equal: u64 = 0,
        zero_only: u64 = 0,
        differences: u64 = 0,
        core_ok: u64 = 0,
        local: u64 = 0,
        local_ok: u64 = 0,
    };
    const M = struct {
        fn local(f: *const forward.Forwarder, m: route.Method) u64 {
            return f.metrics.methods[@intFromEnum(m)].served_local.load(.monotonic);
        }
        fn fwd(f: *const forward.Forwarder, m: route.Method, why: route.Reason) u64 {
            return f.metrics.methods[@intFromEnum(m)].forwarded[@intFromEnum(why)].load(.monotonic);
        }
        /// SimulateTransactionRequest { transaction { bcs { value } }, checks, do_gas_selection }.
        fn simulate(al: std.mem.Allocator, td: []const u8, checks_off: bool, gas_selection: bool) ![]const u8 {
            var pw = proto.Writer.init(try al.alloc(u8, td.len + 64));
            const t = try pw.begin(1, td.len + 32);
            const b = try pw.begin(1, td.len + 16);
            try pw.bytes(2, td);
            try pw.end(b);
            try pw.end(t);
            if (checks_off) try pw.uint(3, 1);
            if (gas_selection) try pw.uint(4, 1);
            return pw.bytesWritten();
        }
        /// What the SDK sends before signing: the transaction as a message with its kind and
        /// sender only (no gas payment, no budget, no price), and `do_gas_selection`. `tx` is
        /// the Transaction message a node rendered for it.
        fn stripped(al: std.mem.Allocator, tx: []const u8) ![]const u8 {
            var pw = proto.Writer.init(try al.alloc(u8, tx.len + 64));
            const t = try pw.begin(1, tx.len);
            var r = proto.Reader.init(tx);
            while (try r.next()) |f| if (f.number == 4 or f.number == 5) try pw.bytes(f.number, try proto.Reader.bytesOf(f));
            try pw.end(t);
            try pw.uint(4, 1);
            return pw.bytesWritten();
        }
        /// The resolved transaction of a SimulateTransactionResponse (`transaction.transaction.bcs`)
        /// with the nonce of its expiration set to 0: a node draws that nonce at random, so two
        /// answers to one request differ in it (and in the digest and effects that follow from
        /// it) even from the same node.
        fn withoutNonce(al: std.mem.Allocator, response: []const u8) !?[]const u8 {
            const raw = edge.raw.nested(response, &.{ 1, 2, 1, 2 }) orelse return null;
            var td = (@import("bcs").decode(types.TransactionData, al, raw) catch return null).V1;
            switch (td.expiration) {
                .ValidDuring => |*v| v.nonce = 0,
                .Validity => |*v| v.nonce = 0,
                else => {},
            }
            return try @import("bcs").encodeAlloc(types.TransactionData, al, &types.TransactionData{ .V1 = td });
        }
        /// The rows of a ListBalancesResponse that hold an amount (a Balance whose numeric
        /// fields are all zero or absent is a zero row), and everything else of the message.
        fn amounts(al: std.mem.Allocator, msg: []const u8) ![]const []const u8 {
            var out: std.ArrayList([]const u8) = .empty;
            var r = proto.Reader.init(msg);
            while (try r.next()) |f| {
                if (f.number != 1) {
                    try out.append(al, try std.fmt.allocPrint(al, "field {d}", .{f.number}));
                    continue;
                }
                const row = try proto.Reader.bytesOf(f);
                var q = proto.Reader.init(row);
                var any = false;
                while (try q.next()) |g| {
                    if (g.number == 1) continue; // coin_type
                    const v = proto.Reader.varintOf(g) catch 1; // not a number: counts as content
                    if (v != 0) any = true;
                }
                if (any) try out.append(al, row);
            }
            return out.items;
        }
    };
    var req_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer req_arena.deinit();

    // the core's refusals of a simulation, by status and text (cut), over both passes
    var core_errors: std.StringArrayHashMapUnmanaged(u32) = .empty;
    // what a gas selection answered by the edge was checked for (the `local-gas` pass)
    var gas: struct {
        /// Answered by the edge itself with a success.
        local_ok: u64 = 0,
        /// The resolved transaction in its answer, against the core's for the same request:
        same_bytes: u64 = 0,
        same_coins: u64 = 0,
        same_budget: u64 = 0,
        same_but_nonce: u64 = 0,
        /// The edge's resolved transaction simulated by the core as it is (no gas selection):
        /// answered OK, with the effects the edge's answer has, and how many of those succeed.
        core_accepts: u64 = 0,
        same_effects: u64 = 0,
        effects_success: u64 = 0,
        with_expiration: u64 = 0,
    } = .{};
    // the next checkpoint's user transactions as the message a node renders (kind and sender kept)
    var stripped: std.ArrayList([]const u8) = .empty;
    var stripped_keeper: std.ArrayList(bool) = .empty;
    for (sims.items, sims_keeper.items) |td, is_keeper| {
        var pw = proto.Writer.init(try a.alloc(u8, td.len + 128));
        const t = try pw.begin(1, td.len + 32);
        const b = try pw.begin(1, td.len + 16);
        try pw.bytes(2, td);
        try pw.end(b);
        try pw.end(t);
        const m = try pw.begin(2, 64);
        try pw.string(1, "transaction.transaction");
        try pw.end(m);
        const r = try loopback.unary(a, core_h, p_simulate, pw.bytesWritten());
        if (r.status != 0) continue; // a system transaction
        const tx = edge.raw.nested(r.message, &.{ 1, 2 }) orelse continue;
        try stripped.append(a, try M.stripped(a, tx));
        try stripped_keeper.append(a, is_keeper);
    }
    try testing.expect(stripped.items.len > 0);
    // The edge's tip without its read set (pass 3): what a core that builds over p2p gives an
    // edge at the tip for about 0.2 s of every checkpoint, here for all of them.
    const NoReadSets = struct {
        fn has(_: *const anyopaque, _: *const store.Snapshot, _: u64) bool {
            return false;
        }
    };
    // the keeper-style gas selections of pass 3 (shapes 2 and 3)
    var keeper: struct { asked: u64 = 0, core_ok: u64 = 0, local: u64 = 0, local_ok: u64 = 0, same: u64 = 0 } = .{};
    var passes: [4]struct { bal: Tally, sim: [4]Tally, policy_bal: u64, policy_sim: u64, negative_sim: u64, ahead_sim: u64 } = undefined;
    var zero_rows_core: u64 = 0;
    var zero_rows_edge: u64 = 0;
    for (&passes, 0..) |*p, pass| {
        // pass 0: the defaults (forward); pass 1: both settings on; pass 2: simulate `local-gas`;
        // pass 3: `local-gas` again with no checkpoint's read set held (gas selections only)
        front.f.cfg.balance_lists = if (pass == 0) .forward else .local;
        front.f.cfg.simulate = switch (pass) {
            0 => .forward,
            1 => .local_forward_on_miss,
            else => .local_gas,
        };
        if (pass == 3) front.svc.read_sets = .{ .ctx = &front.svc, .has = NoReadSets.has };
        p.* = .{ .bal = .{}, .sim = @splat(.{}), .policy_bal = M.fwd(front.f, .list_balances, .policy), .policy_sim = M.fwd(front.f, .simulate_transaction, .policy), .negative_sim = M.fwd(front.f, .simulate_transaction, .negative), .ahead_sim = M.fwd(front.f, .simulate_transaction, .ahead) };
        if (pass != 3) for (owners.keys()) |*owner| {
            _ = req_arena.reset(.retain_capacity);
            const ra = req_arena.allocator();
            var pw = proto.Writer.init(try ra.alloc(u8, 128));
            try pw.string(1, try std.fmt.allocPrint(ra, "0x{x}", .{owner}));
            try pw.uint(2, 1000);
            const body = pw.bytesWritten();
            const want = try loopback.unary(ra, core_h, p_balances, body);
            const l0 = M.local(front.f, .list_balances);
            const got = try loopback.unary(ra, edge_h, p_balances, body);
            const was_local = M.local(front.f, .list_balances) > l0;
            p.bal.asked += 1;
            p.bal.core_ok += @intFromBool(want.status == 0);
            p.bal.local += @intFromBool(was_local);
            p.bal.local_ok += @intFromBool(was_local and want.status == 0);
            if (sameReply(want, got)) {
                p.bal.equal += 1;
                continue;
            }
            // not the same bytes: the same but for rows without an amount?
            const same_but_zero = blk: {
                if (want.status != 0 or got.status != 0) break :blk false;
                const x = M.amounts(ra, want.message) catch break :blk false;
                const y = M.amounts(ra, got.message) catch break :blk false;
                if (x.len != y.len) break :blk false;
                for (x, y) |rx, ry| if (!std.mem.eql(u8, rx, ry)) break :blk false;
                var nx: u64 = 0;
                var ny: u64 = 0;
                var r1 = proto.Reader.init(want.message);
                while (r1.next() catch null) |f| nx += @intFromBool(f.number == 1);
                var r2 = proto.Reader.init(got.message);
                while (r2.next() catch null) |f| ny += @intFromBool(f.number == 1);
                zero_rows_core += nx - x.len;
                zero_rows_edge += ny - y.len;
                break :blk true;
            };
            if (same_but_zero) {
                p.bal.zero_only += 1;
            } else {
                p.bal.differences += 1;
                std.debug.print("edge-policy DIFFERENCE ListBalances 0x{x}: core status {d} {d} bytes, edge status {d} {d} bytes\n", .{ owner, want.status, want.message.len, got.status, got.message.len });
            }
        };
        for (0..4) |shape| for (if (shape == 3) stripped.items else sims.items, 0..) |td, j| {
            if (pass == 3 and shape < 2) continue;
            const is_keeper = (if (shape == 3) stripped_keeper.items else sims_keeper.items)[j];
            _ = req_arena.reset(.retain_capacity);
            const ra = req_arena.allocator();
            const body = if (shape == 3) td else try M.simulate(ra, td, shape == 1, shape == 2);
            const want = try loopback.unary(ra, core_h, p_simulate, body);
            const l0 = M.local(front.f, .simulate_transaction);
            const got = try loopback.unary(ra, edge_h, p_simulate, body);
            const was_local = M.local(front.f, .simulate_transaction) > l0;
            const t = &p.sim[shape];
            t.asked += 1;
            t.core_ok += @intFromBool(want.status == 0);
            if (want.status != 0) {
                const gop = try core_errors.getOrPut(a, try std.fmt.allocPrint(a, "{d} {s}", .{ want.status, want.grpc_message[0..@min(want.grpc_message.len, 110)] }));
                if (!gop.found_existing) gop.value_ptr.* = 0;
                gop.value_ptr.* += 1;
            }
            t.local += @intFromBool(was_local);
            t.local_ok += @intFromBool(was_local and want.status == 0);
            // a gas selection the edge answered itself: what it resolved, and whether the core takes it
            if (pass == 2 and shape >= 2 and was_local and got.status == 0) check: {
                gas.local_ok += 1;
                const mine = edge.raw.nested(got.message, &.{ 1, 2, 1, 2 }) orelse break :check;
                const my_effects = edge.raw.nested(got.message, &.{ 1, 4, 1, 2 }) orelse break :check;
                if (want.status == 0) if (edge.raw.nested(want.message, &.{ 1, 2, 1, 2 })) |theirs| {
                    const x = (try @import("bcs").decode(types.TransactionData, ra, mine)).V1;
                    const y = (try @import("bcs").decode(types.TransactionData, ra, theirs)).V1;
                    gas.same_bytes += @intFromBool(std.mem.eql(u8, mine, theirs));
                    var coins = x.gas_data.payment.len == y.gas_data.payment.len;
                    if (coins) for (x.gas_data.payment, y.gas_data.payment) |cp, cq| {
                        if (!std.mem.eql(u8, &cp[0].@"0".@"0", &cq[0].@"0".@"0") or cp[1].@"0" != cq[1].@"0") coins = false;
                    };
                    gas.same_coins += @intFromBool(coins);
                    gas.same_budget += @intFromBool(x.gas_data.budget == y.gas_data.budget and x.gas_data.price == y.gas_data.price);
                    gas.with_expiration += @intFromBool(x.expiration != .None);
                    // the same but for the nonce a node draws
                    const xb = (try M.withoutNonce(ra, got.message)) orelse break :check;
                    const yb = (try M.withoutNonce(ra, want.message)) orelse break :check;
                    gas.same_but_nonce += @intFromBool(std.mem.eql(u8, xb, yb));
                };
                // the core simulates the edge's resolved transaction as it is
                const again = try loopback.unary(ra, core_h, p_simulate, try M.simulate(ra, mine, false, false));
                if (again.status != 0) {
                    std.debug.print("edge-policy: the core REFUSED a transaction the edge resolved: status {d} \"{s}\"\n", .{ again.status, again.grpc_message[0..@min(again.grpc_message.len, 160)] });
                    break :check;
                }
                gas.core_accepts += 1;
                const their_effects = edge.raw.nested(again.message, &.{ 1, 4, 1, 2 }) orelse break :check;
                gas.same_effects += @intFromBool(std.mem.eql(u8, my_effects, their_effects));
                const fx_ = @import("bcs").decode(types.TransactionEffects, ra, my_effects) catch break :check;
                gas.effects_success += @intFromBool(switch (fx_) {
                    .V1 => |v| v.status == .Success,
                    .V2 => |v| v.status == .Success,
                });
            }
            if (pass == 3 and is_keeper) {
                keeper.asked += 1;
                keeper.core_ok += @intFromBool(want.status == 0);
                keeper.local += @intFromBool(was_local);
                keeper.local_ok += @intFromBool(was_local and want.status == 0);
            }
            if (sameReply(want, got)) {
                t.equal += 1;
                if (pass == 3 and is_keeper) keeper.same += 1;
            } else if (shape >= 2 and want.status == 0 and got.status == 0 and nonce: {
                // two answers to a gas selection (from two nodes, or twice from the core when the
                // edge forwards): the same resolved transaction but for the nonce drawn
                const x = (try M.withoutNonce(ra, want.message)) orelse break :nonce false;
                const y = (try M.withoutNonce(ra, got.message)) orelse break :nonce false;
                break :nonce std.mem.eql(u8, x, y);
            }) {
                t.zero_only += 1;
                if (pass == 3 and is_keeper) keeper.same += 1;
            } else {
                t.differences += 1;
                std.debug.print("edge-policy DIFFERENCE SimulateTransaction (shape {d}): core status {d} \"{s}\" {d} bytes, edge status {d} \"{s}\" {d} bytes\n", .{ shape, want.status, want.grpc_message[0..@min(want.grpc_message.len, 120)], want.message.len, got.status, got.grpc_message[0..@min(got.grpc_message.len, 120)], got.message.len });
            }
        };
        p.policy_bal = M.fwd(front.f, .list_balances, .policy) - p.policy_bal;
        p.policy_sim = M.fwd(front.f, .simulate_transaction, .policy) - p.policy_sim;
        p.negative_sim = M.fwd(front.f, .simulate_transaction, .negative) - p.negative_sim;
        p.ahead_sim = M.fwd(front.f, .simulate_transaction, .ahead) - p.ahead_sim;
    }

    std.debug.print("==== edge-policy conformance: begin ====\n", .{});
    std.debug.print("window {d}..{d} (epoch {d}, protocol {d}), {d} checkpoints, {d} of them with their read set on the edge; base {d} objects and {d} packages ({d} of them system packages); index rows: core fed checkpoint by checkpoint from the base, edge built from its live set\n", .{ first, next - 1, first_epoch, Env.env.pv, count, en.marks(count), win.base.len, extra.items.len, extra.items.len - n_user });
    for (passes, 0..) |p, pass| {
        std.debug.print("{s}:\n", .{switch (pass) {
            0 => "defaults (--edge-balance-lists forward, --edge-simulate forward)",
            1 => "--edge-balance-lists local, --edge-simulate local",
            2 => "--edge-balance-lists local, --edge-simulate local-gas",
            else => "--edge-simulate local-gas at a tip without its read set (no checkpoint's held; gas selections only)",
        }});
        std.debug.print("  ListBalances: {d} owners asked, {d} answered OK by the core; {d} answered by the edge itself, {d} forwarded by policy; {d} byte-equal, {d} equal but for zero rows, {d} differences\n", .{ p.bal.asked, p.bal.core_ok, p.bal.local, p.policy_bal, p.bal.equal, p.bal.zero_only, p.bal.differences });
        inline for (.{ "as it is", "checks disabled", "gas selection", "gas selection, payment and budget stripped" }, 0..) |name, shape| {
            const t = p.sim[shape];
            std.debug.print("  SimulateTransaction of checkpoint {d}, {s}: {d} asked, {d} answered OK by the core; {d} answered by the edge itself ({d} of them OK on the core); {d} byte-equal, {d} a drawn nonce apart, {d} differences\n", .{ next, name, t.asked, t.core_ok, t.local, t.local_ok, t.equal, t.zero_only, t.differences });
        }
        std.debug.print("  SimulateTransaction forwarded: policy {d}, after a local run that did not answer {d}, pending transaction {d}\n", .{ p.policy_sim, p.negative_sim, p.ahead_sim });
    }
    std.debug.print("gas selection answered by the edge (local-gas): {d} answers; resolved transaction against the core's for the same request: {d} the same bytes, {d} the same coins, {d} the same budget and price, {d} the same but for a nonce, {d} with an expiration; the core simulating the edge's resolved transaction as it is: {d} accepted, {d} with the same effects, {d} of them successful\n", .{ gas.local_ok, gas.same_bytes, gas.same_coins, gas.same_budget, gas.same_but_nonce, gas.with_expiration, gas.core_accepts, gas.same_effects, gas.effects_success });
    std.debug.print("keeper style (a shared input changed in each of the window's last {d} checkpoints; {d} such objects), local-gas at a tip without its read set: {d} gas selections asked, {d} answered OK by the core, {d} answered by the edge itself ({d} of them OK on the core), {d} the core's answer (bytes, or a drawn nonce apart)\n", .{ hot_span, hot_count: {
        var n: u64 = 0;
        var it = hot.valueIterator();
        while (it.next()) |v| n += @intFromBool(v.* == hot_span);
        break :hot_count n;
    }, keeper.asked, keeper.core_ok, keeper.local, keeper.local_ok, keeper.same });
    for (core_errors.keys(), core_errors.values()) |k, n| std.debug.print("  the core refused {d} simulations with: {s}\n", .{ n, k });
    std.debug.print("zero rows in the answers that differed: {d} on the core, {d} on the edge\n", .{ zero_rows_core, zero_rows_edge });
    std.debug.print("==== edge-policy conformance: end ====\n", .{});

    const n_sim: u64 = sims.items.len;
    // the defaults: everything is the core's answer
    try testing.expectEqual(@as(u64, 0), passes[0].bal.local + passes[0].sim[0].local + passes[0].sim[1].local + passes[0].sim[2].local + passes[0].sim[3].local);
    try testing.expectEqual(passes[0].bal.asked, passes[0].policy_bal);
    try testing.expectEqual(3 * n_sim + stripped.items.len, passes[0].policy_sim);
    try testing.expectEqual(passes[0].bal.asked, passes[0].bal.equal);
    // a nonce is drawn only where a node resolves a transaction: never without gas selection
    for (passes) |p| try testing.expectEqual(@as(u64, 0), p.sim[0].zero_only + p.sim[1].zero_only);
    for (passes) |p| {
        try testing.expectEqual(@as(u64, 0), p.bal.differences);
        for (p.sim) |t| {
            try testing.expectEqual(@as(u64, 0), t.differences);
            try testing.expectEqual(t.asked, t.equal + t.zero_only);
        }
    }
    // the settings on: every list is the edge's own, and equal but for zero rows
    try testing.expectEqual(passes[1].bal.asked, passes[1].bal.local);
    try testing.expectEqual(@as(u64, 0), passes[1].policy_bal);
    try testing.expectEqual(passes[1].bal.asked, passes[1].bal.core_ok);
    // only the core can have rows the other lacks here (it saw the coin types emptied)
    try testing.expectEqual(@as(u64, 0), zero_rows_edge);
    // gas selection is never the edge's; a simulation the edge answers is one the core answers OK
    try testing.expectEqual(@as(u64, 0), passes[1].sim[2].local + passes[1].sim[3].local);
    try testing.expectEqual(n_sim + stripped.items.len, passes[1].policy_sim);
    try testing.expectEqual(passes[1].sim[0].local, passes[1].sim[0].local_ok);
    try testing.expectEqual(passes[1].sim[1].local, passes[1].sim[1].local_ok);
    try testing.expect(passes[1].sim[0].local_ok > 0);
    try testing.expectEqual(@as(u64, 0), passes[1].ahead_sim);
    // local-gas: nothing is forwarded by policy; every gas selection the core answers the edge
    // answers itself; what it resolved is what the core resolved (the same coins, budget and
    // price; at most a nonce apart), the core accepts it as it is, with the same effects
    try testing.expectEqual(@as(u64, 0), passes[2].policy_sim);
    try testing.expectEqual(passes[2].sim[2].core_ok, passes[2].sim[2].local_ok);
    try testing.expectEqual(passes[2].sim[3].core_ok, passes[2].sim[3].local_ok);
    try testing.expectEqual(passes[2].sim[2].local_ok + passes[2].sim[3].local_ok, gas.local_ok);
    try testing.expect(passes[2].sim[3].local_ok > 0);
    try testing.expectEqual(gas.local_ok, gas.same_coins);
    try testing.expectEqual(gas.local_ok, gas.same_budget);
    try testing.expectEqual(gas.local_ok, gas.same_but_nonce);
    try testing.expectEqual(gas.local_ok, gas.core_accepts);
    try testing.expectEqual(gas.local_ok, gas.same_effects);
    // local-gas without read sets (EDGE.md 11.8: a simulation reads live state only): the same
    // as with them. Nothing forwarded by policy, every gas selection the core answers the edge
    // answers itself, keeper style ones included, and each is the core's answer.
    try testing.expectEqual(@as(u64, 0), passes[3].policy_sim);
    try testing.expectEqual(passes[2].sim[2].local, passes[3].sim[2].local);
    try testing.expectEqual(passes[2].sim[3].local, passes[3].sim[3].local);
    try testing.expectEqual(passes[3].sim[2].core_ok, passes[3].sim[2].local_ok);
    try testing.expectEqual(passes[3].sim[3].core_ok, passes[3].sim[3].local_ok);
    try testing.expectEqual(keeper.core_ok, keeper.local_ok);
    try testing.expectEqual(keeper.asked, keeper.same);
    try testing.expect(keeper.asked > 0);
}
