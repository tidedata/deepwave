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
//!
//! Read sets (docs/EDGE.md section 12). A node that keeps read sets for the feed (`read_sets`
//! set: hello feature bit 33) accepts the request flag READ_SETS and then appends the
//! checkpoint's `ReadSets` (edgewire feed.zig) to the raw feed, inside the same frame: each
//! transaction's loaded runtime object list, read through the service's `loaded` source, which
//! is the read its own sui.rpc.v2 answers use. Without the flag the bytes are the feed alone.
const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store");
const serve = @import("serve");
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
    /// The service whose read sets a feed may carry (its `loaded` and `read_sets` hooks); null:
    /// none, hello does not advertise them and READ_SETS is an unknown flag.
    read_sets: ?*const serve.service.Service = null,

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
        const rs_flag: u64 = if (f.read_sets != null) proto.flag_read_sets else 0;
        if (req.flags & ~(proto.flag_verify | proto.flag_zstd_ok | rs_flag) != 0) return error.Malformed;
        const with_rs: ?*const serve.service.Service = if (req.flags & proto.flag_read_sets != 0) f.read_sets else null;
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
        const have = assembleWith(a, snap, seq, &raw, with_rs) catch |e| switch (e) {
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
    return assembleWith(a, snap, seq, out, null);
}

/// `assemble`, followed by the checkpoint's read sets when `read_sets` is given (the client
/// asked for them): the lists `svc` serves, or "none held" when its store has no final read set
/// for this checkpoint.
pub fn assembleWith(a: Allocator, snap: *store.Snapshot, seq: u64, out: *std.ArrayList(u8), read_sets: ?*const serve.service.Service) AssembleError!bool {
    const c = snap.checkpoint(seq) orelse return false;
    const digests = contentDigests(a, c.contents) catch return error.Malformed;
    const txs = try a.alloc(feed.TxIn, digests.len);
    var refs: std.ArrayList([72]u8) = .empty;
    // Asked first: a read set that becomes final while the feed is assembled is not sent half.
    const lists: ?[][]const u8 = blk: {
        const svc = read_sets orelse break :blk null;
        const has = svc.read_sets orelse break :blk null;
        if (svc.loaded == null or !has.has(has.ctx, snap, seq)) break :blk null;
        break :blk try a.alloc([]const u8, digests.len);
    };
    for (digests, txs, 0..) |*dg, *t, i| {
        const rec = snap.transaction(dg) orelse return error.OutputMissing;
        if (lists) |ls| ls[i] = try loadedBytes(a, read_sets.?, snap, &rec);
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
    if (read_sets != null) try feed.encodeReadSets(out, a, lists);
    return true;
}

/// A transaction's loaded runtime object list as `svc` serves it, in the stored form
/// (`version: u64 LE ++ id` per entry).
fn loadedBytes(a: Allocator, svc: *const serve.service.Service, snap: *const store.Snapshot, rec: *const store.TransactionRecord) Allocator.Error![]const u8 {
    const src = svc.loaded.?;
    const list = src.get(src.ctx, snap, rec.digest, rec.loc);
    const out = try a.alloc(u8, list.len * feed.loaded_entry_len);
    for (list, 0..) |r, i| {
        std.mem.writeInt(u64, out[i * feed.loaded_entry_len ..][0..8], r.version, .little);
        out[i * feed.loaded_entry_len + 8 ..][0..32].* = r.id;
    }
    return out;
}

const dispatch = @import("dispatch.zig");

fn contentDigests(a: Allocator, contents: []const u8) ![]const [32]u8 {
    return dispatch.contentDigests(a, contents);
}
