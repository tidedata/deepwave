//! zui/1 response compression (docs/NATIVE-PROTOCOL.md sections 2.2 and 2.3): the zstd
//! dictionaries `hello` lists and `get_dictionary` serves, one per kind, and the framing of a
//! compressed response.
//!
//! A dictionary is raw content (edgewire dict.zig: windows sampled from real responses, no zstd
//! dictionary header, id = the first four bytes of its SHA-256). The node's warm thread builds all
//! three once, from checkpoints spread over the newest part of the store, and publishes each
//! through an atomic pointer for the life of the process. No request ever builds one: until a
//! kind is published, responses of that kind go out as plain zstd (dict id 0).
//!
//!   kind 0 object      output objects of the sampled checkpoints
//!   kind 1 checkpoint  the edge feed of each sampled checkpoint (summary, contents, transactions,
//!                      effects, events, output objects); the `get_checkpoint` body when a feed
//!                      cannot be assembled
//!   kind 2 effects     each sampled checkpoint's transactions as `Tx` (data, effects, events)
const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store");
const edgewire = @import("edgewire");
const proto = @import("proto.zig");
const W = proto.W;
const dict = edgewire.dict;
const zc = store.zstd_c;

pub const Kind = enum(u8) { object = 0, checkpoint = 1, effects = 2 };
pub const kinds = 3;

/// Responses at or under this many bytes (body and proof) are never compressed (spec 2.3).
pub const min_compress: usize = 1024;

/// The dictionary kind that compresses `m`'s responses; null: plain zstd.
pub fn kindFor(m: proto.Method) ?Kind {
    return switch (m) {
        .get_object, .batch_get_objects, .list_owned_objects => .object,
        .get_checkpoint, .get_epoch_proof => .checkpoint,
        .get_transaction, .batch_get_transactions, .dry_run, .submit_transaction => .effects,
        else => null,
    };
}

/// Methods whose responses the generic layer never compresses: kept-open streams (their ack is
/// fixed-size, flags 0) and the edge feed (its body is its own compressed frame, docs/EDGE.md).
pub fn neverCompressed(m: proto.Method) bool {
    return switch (m) {
        .subscribe, .pair_relay, .get_checkpoint_feed => true,
        else => false,
    };
}

pub const Dicts = struct {
    gpa: Allocator,
    /// Published dictionaries by kind (release on publish, acquire on read). Never replaced.
    slots: [kinds]std.atomic.Value(?*const dict.Dictionary) = @splat(.init(null)),
    owned: [kinds]dict.Dictionary = undefined,
    built: [kinds]bool = @splat(false),
    /// Serializes builds (the warm thread only); readers never take it.
    mu: std.atomic.Mutex = .unlocked,
    /// Checkpoints sampled, and the stride between them.
    samples: u32 = 24,
    stride: u64 = 256,
    /// Compression level of every response frame (dictionary or plain).
    level: i32 = 3,

    pub fn init(gpa: Allocator) Dicts {
        return .{ .gpa = gpa };
    }

    pub fn deinit(d: *Dicts) void {
        for (&d.owned, d.built) |*x, b| if (b) x.deinit(d.gpa);
        d.* = undefined;
    }

    pub fn get(d: *const Dicts, k: Kind) ?*const dict.Dictionary {
        return d.slots[@intFromEnum(k)].load(.acquire);
    }

    pub fn byId(d: *const Dicts, id: u32) ?*const dict.Dictionary {
        if (id == 0) return null;
        for (&d.slots) |*s| if (s.load(.acquire)) |x| if (x.id == id) return x;
        return null;
    }

    pub fn ready(d: *const Dicts) bool {
        for (&d.slots) |*s| if (s.load(.acquire) == null) return false;
        return true;
    }

    /// `vector<DictInfo>` of the published dictionaries, in kind order.
    pub fn writeInfos(d: *const Dicts, w: W) !void {
        var n: usize = 0;
        for (&d.slots) |*s| if (s.load(.acquire) != null) {
            n += 1;
        };
        try w.uleb(n);
        for (&d.slots, 0..) |*s, k| if (s.load(.acquire)) |x| {
            try w.int(u32, x.id);
            try w.u8_(@intCast(k));
            try w.fixed(&x.sha256);
            try w.int(u32, @intCast(x.content.len));
        };
    }

    /// Builds every kind not yet published from `snap` and publishes it. Only the warm thread
    /// calls this (it reads `samples` checkpoints). Error.Unavailable: the store holds too few
    /// checkpoints yet; what could be built is published, try again later.
    pub fn warm(d: *Dicts, snap: *store.Snapshot) !void {
        return d.warmCancel(snap, null);
    }

    /// `warm` that gives up with `error.Cancelled` once `cancel` is set (the node is stopping):
    /// looked at before every sample (each one assembles a checkpoint's feed and reads its
    /// transactions and objects from the store, which on a cold store is most of the time a
    /// warm takes) and before every dictionary is built. A kind is published whole or not at
    /// all, so a cancelled warm leaves nothing half made: what was already published stays,
    /// the rest is built by a later call.
    pub fn warmCancel(d: *Dicts, snap: *store.Snapshot, cancel: ?*const std.atomic.Value(bool)) !void {
        if (d.ready()) return;
        while (!d.mu.tryLock()) std.atomic.spinLoopHint();
        defer d.mu.unlock();
        const hi = snap.highestCommitted() orelse return error.Unavailable;
        const lo = snap.lowestAvailable() orelse 0;
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var lists: [kinds]std.ArrayList([]const u8) = @splat(.empty);
        var seq = hi;
        var taken: u32 = 0;
        while (taken < d.samples and seq >= lo) {
            if (cancelled(cancel)) return error.Cancelled;
            if (try sample(a, snap, seq)) |s| {
                taken += 1;
                for (&lists, s) |*l, x| if (x.len > 0) try l.append(a, x);
            }
            if (seq < d.stride) break;
            seq -= d.stride;
        }
        var missing = false;
        for (&lists, 0..) |*l, k| {
            if (d.built[k]) continue;
            if (cancelled(cancel)) return error.Cancelled;
            if (l.items.len < 2) {
                missing = true;
                continue;
            }
            const content = try dict.build(d.gpa, l.items, dict.default_dict);
            defer d.gpa.free(content);
            d.owned[k] = try dict.Dictionary.init(d.gpa, content, d.level);
            d.built[k] = true;
            d.slots[k].store(&d.owned[k], .release);
        }
        // A kind with no samples in a store that already spans every sampled checkpoint (no
        // object history, say) never gets one: stop asking.
        if (missing and taken < d.samples) return error.Unavailable;
    }

    fn cancelled(cancel: ?*const std.atomic.Value(bool)) bool {
        return if (cancel) |c| c.load(.acquire) else false;
    }

    /// Compresses the OK response in `out` in place when the request allowed it (flag ZSTD_OK),
    /// the method is not exempt and its body (with the proof) is over `min_compress` bytes:
    /// status 0, flags | ZSTD, varint dict_id, varint raw_len, then one zstd frame of
    /// `body || proof`. Left as it is when compression would not make it smaller.
    pub fn compressResponse(d: ?*const Dicts, a: Allocator, m: proto.Method, req_flags: u64, out: *std.ArrayList(u8)) !void {
        if (req_flags & proto.flag_zstd_ok == 0 or neverCompressed(m)) return;
        if (out.items.len < 2 or out.items[0] != 0) return; // errors stay plain
        var p: usize = 1;
        const flags = proto.getVarint(out.items, &p) orelse return;
        if (flags & proto.resp_zstd != 0) return;
        const body = out.items[p..];
        if (body.len <= min_compress) return;
        const dc: ?*const dict.Dictionary = if (d) |x| (if (kindFor(m)) |k| x.get(k) else null) else null;
        const id: u32 = if (dc) |x| x.id else 0;
        var res: std.ArrayList(u8) = .empty;
        try res.ensureTotalCapacity(a, 1 + 8 + 8 + 8 + zc.compressBound(body.len));
        res.appendAssumeCapacity(0);
        try proto.putVarint(&res, a, flags | proto.resp_zstd);
        try proto.putVarint(&res, a, id);
        try proto.putVarint(&res, a, body.len);
        const head = res.items.len;
        const dst = res.unusedCapacitySlice();
        const n = (if (dc) |x|
            x.z.compress(body, dst) catch return
        else
            zc.compressPooled(body, dst, if (d) |x| x.level else 3) catch return) orelse return;
        if (head + n >= out.items.len) return;
        res.items.len = head + n;
        out.* = res;
    }
};

/// One checkpoint's samples by kind (empty slices where it gave nothing); null when the
/// checkpoint is not held.
fn sample(a: Allocator, snap: *store.Snapshot, seq: u64) !?[kinds][]const u8 {
    const c = snap.checkpoint(seq) orelse return null;
    var out: [kinds][]const u8 = @splat(&.{});
    // kind 1: the feed, else the get_checkpoint body (all parts)
    var feed: std.ArrayList(u8) = .empty;
    const have = edgefeed.assemble(a, snap, seq, &feed) catch false;
    if (have) out[1] = feed.items else {
        var cp: std.ArrayList(u8) = .empty;
        dispatch.writeCheckpoint(a, snap, .{ .gpa = a, .out = &cp }, c, 0x0f) catch {};
        out[1] = cp.items;
    }
    const digests = dispatch.contentDigests(a, c.contents) catch return out;
    var objs: std.ArrayList(u8) = .empty;
    var txs: std.ArrayList(u8) = .empty;
    var refs: std.ArrayList([72]u8) = .empty;
    for (digests) |*dg| {
        const t = snap.transaction(dg) orelse continue;
        try dispatch.writeTx(.{ .gpa = a, .out = &txs }, t, proto.part_tx | proto.part_effects | proto.part_events);
        refs.clearRetainingCapacity();
        edgewire.feed.outputRefs(a, t.effects, &refs) catch continue;
        for (refs.items) |*ref| {
            const o = (snap.objectAtChecked(ref[0..32], std.mem.readInt(u64, ref[32..40], .little)) catch null) orelse continue;
            try objs.appendSlice(a, o.bytes);
        }
    }
    out[0] = objs.items;
    out[2] = txs.items;
    return out;
}

const dispatch = @import("dispatch.zig");
const edgefeed = @import("edgefeed.zig");

test "dictionary warm: a cancel ends it at the next sample, before anything is built; nothing is published half made and a later warm starts over" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const plen = try tmp.dir.realPath(io, &pb);
    var cfg: store.Config = .{ .max_live_objects = 1 << 12, .max_object_versions = 1 << 12, .max_transactions = 1 << 12, .max_checkpoints = 1 << 12 };
    cfg.dir = pb[0..plen];
    const h = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    {
        const b = try h.store.begin(1, 1);
        try b.checkpoint("summary-1", "contents-1");
        try h.store.commit(b);
    }
    var d = Dicts.init(gpa);
    defer d.deinit();
    // a warm that would sample for a long time: the one checkpoint, again and again
    d.samples = 400_000;
    d.stride = 0;
    const T = struct {
        d: *Dicts,
        st: *store.Store,
        cancel: std.atomic.Value(bool) = .init(false),
        cancelled: bool = false,
        other: bool = false,
        done_ns: std.atomic.Value(u64) = .init(0),
        fn now() u64 {
            var ts: std.posix.timespec = undefined;
            _ = std.c.clock_gettime(.MONOTONIC, &ts);
            return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
        }
        fn run(t: *@This()) void {
            var snap = t.st.snapshot();
            defer snap.release();
            if (t.d.warmCancel(&snap, &t.cancel)) |_| {
                t.other = true;
            } else |e| if (e == error.Cancelled) {
                t.cancelled = true;
            } else {
                t.other = true;
            }
            t.done_ns.store(now(), .release);
        }
    };
    var t: T = .{ .d = &d, .st = h.store };
    const th = try std.Thread.spawn(.{}, T.run, .{&t});
    io.sleep(.fromMilliseconds(20), .awake) catch {};
    const t0 = T.now();
    t.cancel.store(true, .release);
    // bounded either way: without the cancel the warm ends by itself after its samples
    th.join();
    try std.testing.expect(t.cancelled and !t.other);
    try std.testing.expect(t.done_ns.load(.acquire) -| t0 < 500 * std.time.ns_per_ms);
    // nothing was published, whole or half
    try std.testing.expect(!d.ready());
    for (&d.slots) |*s| try std.testing.expect(s.load(.acquire) == null);
    for (d.built) |b| try std.testing.expect(!b);
    // a flag set before the call: no sample is taken at all
    var snap = h.store.snapshot();
    defer snap.release();
    try std.testing.expectError(error.Cancelled, d.warmCancel(&snap, &t.cancel));
    // and without one the same call runs: a short warm now ends by itself, not cancelled
    d.samples = 2;
    if (d.warm(&snap)) |_| {} else |e| try std.testing.expect(e != error.Cancelled);
}

test "compressResponse: frames OK bodies over 1 KiB, with and without a dictionary" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    // a body that repeats itself compresses well
    var body: [4000]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @truncate((i % 97) * 7);
    var out: std.ArrayList(u8) = .empty;
    try proto.okHeader(&out, a, proto.resp_proof);
    try out.appendSlice(a, &body);

    // no ZSTD_OK: unchanged
    try Dicts.compressResponse(null, a, .get_object, 0, &out);
    try std.testing.expectEqual(@as(usize, 2 + body.len), out.items.len);

    // plain (no dictionaries yet)
    try Dicts.compressResponse(null, a, .get_object, proto.flag_zstd_ok, &out);
    var r = proto.parseResponse(out.items).?;
    try std.testing.expectEqual(proto.resp_proof | proto.resp_zstd, r.flags);
    var p: usize = 0;
    try std.testing.expectEqual(@as(u64, 0), proto.getVarint(r.body, &p).?);
    try std.testing.expectEqual(@as(u64, body.len), proto.getVarint(r.body, &p).?);
    const back = try a.alloc(u8, body.len);
    try zc.decodeInto(r.body[p..], back);
    try std.testing.expectEqualSlices(u8, &body, back);

    // with a dictionary of the right kind
    var ds = Dicts.init(gpa);
    defer ds.deinit();
    ds.owned[0] = try dict.Dictionary.init(gpa, body[0..2000], 3);
    ds.built[0] = true;
    ds.slots[0].store(&ds.owned[0], .release);
    var out2: std.ArrayList(u8) = .empty;
    try proto.okHeader(&out2, a, 0);
    try out2.appendSlice(a, &body);
    try Dicts.compressResponse(&ds, a, .batch_get_objects, proto.flag_zstd_ok | proto.flag_verify, &out2);
    r = proto.parseResponse(out2.items).?;
    try std.testing.expectEqual(proto.resp_zstd, r.flags);
    p = 0;
    try std.testing.expectEqual(@as(u64, ds.owned[0].id), proto.getVarint(r.body, &p).?);
    try std.testing.expectEqual(@as(u64, body.len), proto.getVarint(r.body, &p).?);
    try ds.owned[0].z.decompress(r.body[p..], back);
    try std.testing.expectEqualSlices(u8, &body, back);
    // the hello list names it once, as kind 0
    var infos: std.ArrayList(u8) = .empty;
    try ds.writeInfos(.{ .gpa = a, .out = &infos });
    try std.testing.expectEqual(@as(usize, 1 + 4 + 1 + 32 + 4), infos.items.len);
    try std.testing.expectEqual(@as(u8, 0), infos.items[5]);
    try std.testing.expect(ds.byId(ds.owned[0].id) != null);
    try std.testing.expect(ds.byId(0) == null);

    // small bodies, errors, the feed and kept-open methods stay plain
    var small: std.ArrayList(u8) = .empty;
    try proto.okHeader(&small, a, 0);
    try small.appendSlice(a, body[0..1024]);
    try Dicts.compressResponse(&ds, a, .get_object, proto.flag_zstd_ok, &small);
    try std.testing.expectEqual(@as(u64, 0), proto.parseResponse(small.items).?.flags);
    var err: std.ArrayList(u8) = .empty;
    try proto.errorResponse(&err, a, .not_found, &body, "");
    const elen = err.items.len;
    try Dicts.compressResponse(&ds, a, .get_dictionary, proto.flag_zstd_ok, &err);
    try std.testing.expectEqual(elen, err.items.len);
    var fd: std.ArrayList(u8) = .empty;
    try proto.okHeader(&fd, a, 0);
    try fd.appendSlice(a, &body);
    try Dicts.compressResponse(&ds, a, .get_checkpoint_feed, proto.flag_zstd_ok, &fd);
    try std.testing.expectEqual(@as(u64, 0), proto.parseResponse(fd.items).?.flags);
}
