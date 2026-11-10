//! zui/1 edge feed methods (docs/EDGE.md): `get_checkpoint_feed` (0x0e) and `get_dictionary` (0x0b).
//!
//! The feed of checkpoint `seq` is assembled from the store the way any read is: the certified
//! summary and contents, each transaction's envelope, effects and events as stored, and the output
//! objects the effects commit to, read at their exact versions. Any deepwave node serves it, core or
//! edge, so edges can feed from each other. Nothing here is trusted by the receiver: it rebuilds
//! the checkpoint blob and verifies it like any other source (src/edge, docs/EDGE.md section 2).
//!
//! The dictionary (kind 1, `Hello.dictionaries`) is sampled once, by the node's warm thread, from
//! checkpoints spread over the newest part of the store, and published through an atomic pointer
//! for the life of the process: its id changes only when the process restarts. No request ever
//! builds it (until it is published, feeds are plain zstd and get_dictionary is UNAVAILABLE).
//!
//!   request  FeedReq  { seq: u64, dict: u32 }   dict: the id the client holds (0: none)
//!   response Option<bytes>                      the frame (edgewire dict.zig), `resp_zstd` set;
//!                                               None: that checkpoint is not held yet
//!                                               with flag_zstd_ok clear: the raw feed, no frame
const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store");
const edgewire = @import("edgewire");
const proto = @import("proto.zig");
const R = proto.R;
const W = proto.W;
const feed = edgewire.feed;
const dict = edgewire.dict;

pub const Feeder = struct {
    gpa: Allocator,
    /// Serializes builds (the warm thread only); readers never take it.
    mu: std.atomic.Mutex = .unlocked,
    /// The built dictionary, published once with release; read lock-free by every request and by
    /// hello on the listener's I/O thread. Never replaced while the process runs.
    published: std.atomic.Value(?*const dict.Dictionary) = .init(null),
    d: dict.Dictionary = undefined,
    built: bool = false,
    /// Checkpoints sampled for the dictionary, and the stride between them.
    samples: u32 = 24,
    stride: u64 = 256,
    level: i32 = 3,

    pub fn init(gpa: Allocator) Feeder {
        return .{ .gpa = gpa };
    }

    pub fn deinit(f: *Feeder) void {
        if (f.built) f.d.deinit(f.gpa);
    }

    /// The published dictionary (null until `warm` built it). Lock-free, never builds: requests
    /// answer with plain zstd or UNAVAILABLE until the warm thread has published.
    pub fn peek(f: *const Feeder) ?*const dict.Dictionary {
        return f.published.load(.acquire);
    }

    /// Builds the dictionary from the snapshot and publishes it. Only the warm thread calls this
    /// (it may take a while: it assembles `samples` checkpoints). Error: too few checkpoints yet,
    /// try again later.
    pub fn warm(f: *Feeder, snap: *store.Snapshot) !*const dict.Dictionary {
        if (f.peek()) |d| return d;
        while (!f.mu.tryLock()) std.atomic.spinLoopHint();
        defer f.mu.unlock();
        if (f.built) return &f.d;
        try f.build(snap);
        f.built = true;
        f.published.store(&f.d, .release);
        return &f.d;
    }

    fn build(f: *Feeder, snap: *store.Snapshot) !void {
        const hi = snap.highestCommitted() orelse return error.Unavailable;
        const lo = snap.lowestAvailable() orelse 0;
        var arena = std.heap.ArenaAllocator.init(f.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var samples: std.ArrayList([]const u8) = .empty;
        var seq = hi;
        while (samples.items.len < f.samples and seq >= lo) {
            var out: std.ArrayList(u8) = .empty;
            if (try assemble(a, snap, seq, &out)) try samples.append(a, out.items);
            if (seq < f.stride) break;
            seq -= f.stride;
        }
        if (samples.items.len < 2) return error.Unavailable;
        const content = try dict.build(f.gpa, samples.items, dict.default_dict);
        defer f.gpa.free(content);
        f.d = try dict.Dictionary.init(f.gpa, content, f.level);
    }

    /// `get_checkpoint_feed`: whole response into `out`.
    pub fn handle(f: *Feeder, a: Allocator, snap: *store.Snapshot, req: proto.Request, out: *std.ArrayList(u8)) !void {
        if (req.flags & ~(proto.flag_verify | proto.flag_zstd_ok) != 0) return error.Malformed;
        var r: R = .{ .b = req.body };
        const seq = try r.int(u64);
        const want_dict = try r.int(u32);
        try r.done();
        if (snap.lowestAvailable()) |lo| if (seq < lo) {
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, lo, .little);
            return proto.errorResponse(out, a, .pruned, "below the lowest available checkpoint", &b);
        };
        var raw: std.ArrayList(u8) = .empty;
        const have = assemble(a, snap, seq, &raw) catch |e| switch (e) {
            error.OutputMissing => return proto.errorResponse(out, a, .unavailable, "output object version not held", ""),
            else => return e,
        };
        const w: W = .{ .gpa = a, .out = out };
        if (!have) {
            try proto.okHeader(out, a, 0);
            return w.u8_(0);
        }
        if (req.flags & proto.flag_zstd_ok == 0) {
            try proto.okHeader(out, a, 0);
            try w.u8_(1);
            return w.bytes(raw.items);
        }
        // the dictionary only when the client holds the one this node has
        const dc: ?*const dict.Dictionary = blk: {
            if (want_dict == 0) break :blk null;
            const d = f.peek() orelse break :blk null;
            break :blk if (d.id == want_dict) d else null;
        };
        const frame = try dict.compress(a, dc, raw.items);
        try proto.okHeader(out, a, proto.resp_zstd);
        try w.u8_(1);
        try w.bytes(frame);
    }

    /// `get_dictionary`: the content of dictionary `id` (bytes), or NOT_FOUND.
    pub fn handleDict(f: *Feeder, a: Allocator, snap: *store.Snapshot, id: u32, out: *std.ArrayList(u8)) !void {
        _ = snap;
        const d = f.peek() orelse return proto.errorResponse(out, a, .unavailable, "no dictionary yet", "");
        if (d.id != id) return proto.errorResponse(out, a, .not_found, "unknown dictionary", "");
        try proto.okHeader(out, a, 0);
        const w: W = .{ .gpa = a, .out = out };
        try w.bytes(d.content);
    }
};

pub const AssembleError = error{ OutputMissing, Malformed } || Allocator.Error || store.Error;

/// The raw feed of `seq` into `out`; false when the checkpoint is not held. `a` is a request arena.
pub fn assemble(a: Allocator, snap: *store.Snapshot, seq: u64, out: *std.ArrayList(u8)) AssembleError!bool {
    const c = snap.checkpoint(seq) orelse return false;
    const digests = contentDigests(a, c.contents) catch return error.Malformed;
    const txs = try a.alloc(feed.TxIn, digests.len);
    var refs: std.ArrayList([72]u8) = .empty;
    for (digests, txs) |*dg, *t| {
        const rec = snap.transaction(dg) orelse return error.OutputMissing;
        refs.clearRetainingCapacity();
        feed.outputRefs(a, rec.effects, &refs) catch return error.Malformed;
        const objs = try a.alloc([]const u8, refs.items.len);
        for (refs.items, objs) |*ref, *o| {
            const got = (try snap.objectAtChecked(ref[0..32], std.mem.readInt(u64, ref[32..40], .little))) orelse return error.OutputMissing;
            // the store is trusted for availability only: the digest must be the effects' own
            if (!std.mem.eql(u8, &got.digest, ref[40..72])) return error.OutputMissing;
            o.* = got.bytes;
        }
        t.* = .{ .tx = rec.tx, .effects = rec.effects, .events = rec.events, .objects = objs };
    }
    try feed.encode(out, a, c.seq, c.summary_cert, c.contents, txs);
    return true;
}

const dispatch = @import("dispatch.zig");

fn contentDigests(a: Allocator, contents: []const u8) ![]const [32]u8 {
    return dispatch.contentDigests(a, contents);
}
