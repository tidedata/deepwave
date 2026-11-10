//! zui/1 edge feed method (docs/EDGE.md): `get_checkpoint_feed` (0x0e). `get_dictionary` is dicts.zig.
//!
//! The feed of checkpoint `seq` is assembled from the store the way any read is: the certified
//! summary and contents, each transaction's envelope, effects and events as stored, and the output
//! objects the effects commit to, read at their exact versions. Any deepwave node serves it, core or
//! edge, so edges can feed from each other. Nothing here is trusted by the receiver: it rebuilds
//! the checkpoint blob and verifies it like any other source (src/edge, docs/EDGE.md section 2).
//!
//! The dictionary is the node's checkpoint dictionary (dicts.zig, kind 1, `Hello.dictionaries`),
//! sampled once by the node's warm thread and published for the life of the process: its id
//! changes only when the process restarts. Until it is published, feeds are plain zstd frames.
//!
//!   request  FeedReq  { seq: u64, dict: u32 }   dict: the id the client holds (0: none)
//!   response Option<bytes>                      with flag_zstd_ok: the frame (edgewire dict.zig);
//!                                               without: the raw feed. None: not held yet.
//!                                               The response header never sets ZSTD (the frame
//!                                               is its own envelope; spec 2.2).
const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store");
const edgewire = @import("edgewire");
const proto = @import("proto.zig");
const R = proto.R;
const W = proto.W;
const feed = edgewire.feed;
const dict = edgewire.dict;
const Dicts = @import("dicts.zig").Dicts;

pub const Feeder = struct {
    /// The node's response dictionaries: the feed uses the checkpoint kind (dicts.zig builds it
    /// from feeds on the warm thread; requests never build it).
    dicts: *const Dicts,

    pub fn init(dicts: *const Dicts) Feeder {
        return .{ .dicts = dicts };
    }

    /// The published checkpoint dictionary (null until the warm thread built it). Lock-free:
    /// until it exists, feeds go out as plain zstd frames.
    pub fn peek(f: *const Feeder) ?*const dict.Dictionary {
        return f.dicts.get(.checkpoint);
    }

    /// `get_checkpoint_feed`: whole response into `out`. The response header never sets ZSTD:
    /// with `flag_zstd_ok` the body's bytes are a dict.zig frame (its own envelope).
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
        try proto.okHeader(out, a, 0);
        if (!have) return w.u8_(0);
        if (req.flags & proto.flag_zstd_ok == 0) {
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
        try w.u8_(1);
        try w.bytes(frame);
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
