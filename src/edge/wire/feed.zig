//! The edge feed: one checkpoint as a core sends it to an edge (docs/EDGE.md section 2), and the
//! rebuild of the full checkpoint blob (`0x01 ++ BCS(CheckpointData)`) on the edge.
//!
//! A feed carries exactly what an edge needs to verify and apply a checkpoint and nothing a
//! verify-only node never reads: the certified summary, the contents, and per transaction the
//! envelope, effects, events and the output objects that the effects commit to. Input objects
//! (about half of a full checkpoint's bytes) are left out. Every part is the stored BCS, byte for
//! byte, so the edge's blob is canonical and every digest the follower checks is over the bytes
//! the core stored:
//!
//!   Feed   { seq: u64, summary: bytes, contents: bytes, txs: vector<FeedTx> }
//!   FeedTx { tx: bytes, effects: bytes, events: Option<bytes>, objects: vector<bytes> }
//!
//! Only when the client asked for them (hello feature bit 33, request flag READ_SETS; docs/EDGE.md
//! section 12) the feed is followed by the checkpoint's read sets, `ReadSets` below. A feed
//! without them is the bytes above and nothing else, as it always was.
//!
//! `summary` is BCS CertifiedCheckpointSummary (summary ++ AuthorityStrongQuorumSignInfo),
//! `tx` the BCS Transaction envelope, `events` BCS TransactionEvents, `objects` BCS Object in
//! the order of the effects' changed objects. Nothing in a feed is trusted: the edge rebuilds
//! the blob and runs the same checks as for any other source (BLS quorum certificate, contents
//! and effects digests, every output object against the effects).
const std = @import("std");
const Allocator = std.mem.Allocator;
const checkpoint = @import("checkpoint");
const types = @import("types");

pub const Error = error{ Malformed, TooLarge } || Allocator.Error;

/// Limits of a decoded feed (protocol maxima: types.CheckpointIndex).
pub const max_txs: u64 = 1 << 14;
pub const max_objects_per_tx: u64 = 1 << 20;

pub const TxIn = struct {
    tx: []const u8,
    effects: []const u8,
    events: ?[]const u8,
    /// Output objects, one per changed object of `effects`.
    objects: []const []const u8,
};

fn uleb(out: *std.ArrayList(u8), gpa: Allocator, v: u64) Allocator.Error!void {
    var x = v;
    while (x >= 0x80) {
        try out.append(gpa, @as(u8, @truncate(x)) | 0x80);
        x >>= 7;
    }
    try out.append(gpa, @intCast(x));
}

fn bytes(out: *std.ArrayList(u8), gpa: Allocator, b: []const u8) Allocator.Error!void {
    try uleb(out, gpa, b.len);
    try out.appendSlice(gpa, b);
}

/// Appends the feed of one checkpoint.
pub fn encode(out: *std.ArrayList(u8), gpa: Allocator, seq: u64, summary_cert: []const u8, contents: []const u8, txs: []const TxIn) Allocator.Error!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, seq, .little);
    try out.appendSlice(gpa, &b);
    try bytes(out, gpa, summary_cert);
    try bytes(out, gpa, contents);
    try uleb(out, gpa, txs.len);
    for (txs) |t| {
        try bytes(out, gpa, t.tx);
        try bytes(out, gpa, t.effects);
        if (t.events) |e| {
            try out.append(gpa, 1);
            try bytes(out, gpa, e);
        } else try out.append(gpa, 0);
        try uleb(out, gpa, t.objects.len);
        for (t.objects) |o| try bytes(out, gpa, o);
    }
}

/// A decoded feed. `txs` and every slice point into the input (the objects' slices into `objs`).
pub const Feed = struct {
    seq: u64,
    summary_cert: []const u8,
    contents: []const u8,
    txs: []Tx,
    objs: [][]const u8,

    pub const Tx = struct { tx: []const u8, effects: []const u8, events: ?[]const u8, first: u32, count: u32 };

    pub fn objects(f: *const Feed, t: *const Tx) []const []const u8 {
        return f.objs[t.first..][0..t.count];
    }

    pub fn deinit(f: *Feed, gpa: Allocator) void {
        gpa.free(f.txs);
        gpa.free(f.objs);
    }
};

const Rd = struct {
    b: []const u8,
    p: usize = 0,

    fn uleb(r: *Rd) Error!u64 {
        var v: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            if (r.p >= r.b.len or shift > 63) return error.Malformed;
            const x = r.b[r.p];
            r.p += 1;
            v |= @as(u64, x & 0x7f) << @intCast(shift);
            if (x & 0x80 == 0) return v;
            shift += 7;
        }
    }
    fn u8_(r: *Rd) Error!u8 {
        if (r.p >= r.b.len) return error.Malformed;
        r.p += 1;
        return r.b[r.p - 1];
    }
    fn bytes(r: *Rd) Error![]const u8 {
        const n = try r.uleb();
        if (n > r.b.len - r.p) return error.Malformed;
        defer r.p += @intCast(n);
        return r.b[r.p..][0..@intCast(n)];
    }
};

/// Decodes `b` (the whole feed, nothing after it).
pub fn decode(gpa: Allocator, b: []const u8) Error!Feed {
    var end: usize = 0;
    var f = try decodeAt(gpa, b, &end);
    if (end != b.len) {
        f.deinit(gpa);
        return error.Malformed;
    }
    return f;
}

/// Decodes the feed at the start of `b`; `end` receives where it stops.
fn decodeAt(gpa: Allocator, b: []const u8, end: *usize) Error!Feed {
    var r: Rd = .{ .b = b };
    if (b.len < 8) return error.Malformed;
    const seq = std.mem.readInt(u64, b[0..8], .little);
    r.p = 8;
    const summary = try r.bytes();
    const contents = try r.bytes();
    const ntx = try r.uleb();
    if (ntx > max_txs) return error.TooLarge;
    // Every tx takes at least 4 bytes, so a count the input cannot hold is refused before allocating.
    if (ntx > (b.len - r.p) / 4) return error.Malformed;
    const txs = try gpa.alloc(Feed.Tx, @intCast(ntx));
    errdefer gpa.free(txs);
    var objs: std.ArrayList([]const u8) = .empty;
    errdefer objs.deinit(gpa);
    for (txs) |*t| {
        t.tx = try r.bytes();
        t.effects = try r.bytes();
        t.events = switch (try r.u8_()) {
            0 => null,
            1 => try r.bytes(),
            else => return error.Malformed,
        };
        const n = try r.uleb();
        if (n > max_objects_per_tx or n > b.len - r.p) return error.Malformed;
        t.first = @intCast(objs.items.len);
        t.count = @intCast(n);
        for (0..@as(usize, @intCast(n))) |_| try objs.append(gpa, try r.bytes());
    }
    end.* = r.p;
    return .{ .seq = seq, .summary_cert = summary, .contents = contents, .txs = txs, .objs = try objs.toOwnedSlice(gpa) };
}

// ------------------------------------------------------------------ read sets (docs/EDGE.md 12)
//
//   ReadSets { present: u8, loaded: [bytes; txs.len] }      `loaded` only when present = 1
//
// `present` 0: the serving node holds no final read set for this checkpoint (it was stored
// without one, or its lists may still change); nothing follows. 1: one `bytes` per transaction,
// in the feed's order: the transaction's `unchanged_loaded_runtime_objects` list as the node's
// store keeps it, `count * (version: u64 LE ++ id: [u8; 32])` (empty: none), ids ascending.
//
// A list is the serving node's word: nothing certified names it (it is not in the effects). The
// receiver checks what can be checked (`listCanonical` here; the rest against its own store,
// node history.zig) and treats the membership itself as unproven.

/// One entry of a loaded runtime object list: `version: u64 LE ++ id: [u8; 32]`.
pub const loaded_entry_len = 40;

/// Whether `list` is a loaded list in sui-node's form: whole entries, ids strictly ascending
/// (a BTreeMap by object id: one version per id), every version a real object version (at most
/// i64 max, Rust `SequenceNumber::MAX`).
pub fn listCanonical(list: []const u8) bool {
    if (list.len % loaded_entry_len != 0) return false;
    var prev: ?*const [32]u8 = null;
    var at: usize = 0;
    while (at < list.len) : (at += loaded_entry_len) {
        if (std.mem.readInt(u64, list[at..][0..8], .little) > std.math.maxInt(i64)) return false;
        const id = list[at + 8 ..][0..32];
        if (prev) |p| if (std.mem.order(u8, p, id) != .lt) return false;
        prev = id;
    }
    return true;
}

/// Appends the read sets of a feed: `lists` null when the node holds none for the checkpoint,
/// else one list per transaction of the feed.
pub fn encodeReadSets(out: *std.ArrayList(u8), gpa: Allocator, lists: ?[]const []const u8) Allocator.Error!void {
    const ls = lists orelse return out.append(gpa, 0);
    try out.append(gpa, 1);
    for (ls) |l| try bytes(out, gpa, l);
}

/// The read sets that followed a feed. `lists` point into the input.
pub const ReadSets = struct {
    /// Null: the serving node holds none for this checkpoint.
    lists: ?[][]const u8 = null,

    pub fn deinit(rs: *ReadSets, gpa: Allocator) void {
        if (rs.lists) |l| gpa.free(l);
        rs.lists = null;
    }
};

pub const WithReadSets = struct {
    feed: Feed,
    read_sets: ReadSets,

    pub fn deinit(w: *WithReadSets, gpa: Allocator) void {
        w.feed.deinit(gpa);
        w.read_sets.deinit(gpa);
    }
};

/// Decodes `b`: a feed, then its read sets, nothing after them. A list that is not in sui-node's
/// form (`listCanonical`) makes the whole answer malformed: the node that sent it is at fault.
pub fn decodeWithReadSets(gpa: Allocator, b: []const u8) Error!WithReadSets {
    var end: usize = 0;
    var f = try decodeAt(gpa, b, &end);
    errdefer f.deinit(gpa);
    var r: Rd = .{ .b = b, .p = end };
    switch (try r.u8_()) {
        0 => {
            if (r.p != b.len) return error.Malformed;
            return .{ .feed = f, .read_sets = .{} };
        },
        1 => {},
        else => return error.Malformed,
    }
    const lists = try gpa.alloc([]const u8, f.txs.len);
    errdefer gpa.free(lists);
    for (lists) |*l| {
        l.* = try r.bytes();
        if (!listCanonical(l.*)) return error.Malformed;
    }
    if (r.p != b.len) return error.Malformed;
    return .{ .feed = f, .read_sets = .{ .lists = lists } };
}

/// Appends the checkpoint blob (`0x01 ++ BCS(CheckpointData)`) of a feed: the same bytes a source
/// would hand the follower, with empty input-object lists.
pub fn toBlob(out: *std.ArrayList(u8), gpa: Allocator, f: *const Feed) Allocator.Error!void {
    try out.append(gpa, 1);
    try out.appendSlice(gpa, f.summary_cert);
    try out.appendSlice(gpa, f.contents);
    try uleb(out, gpa, f.txs.len);
    for (f.txs) |*t| {
        try out.appendSlice(gpa, t.tx);
        try out.appendSlice(gpa, t.effects);
        if (t.events) |e| {
            try out.append(gpa, 1);
            try out.appendSlice(gpa, e);
        } else try out.append(gpa, 0);
        try uleb(out, gpa, 0); // input_objects
        try uleb(out, gpa, t.count);
        for (f.objects(t)) |o| try out.appendSlice(gpa, o);
    }
}

/// Appends the feed-form blob of a full checkpoint blob (`idx` is its index): the blob `toBlob`
/// gives for the feed a core builds of the same checkpoint (serve/native/edgefeed.zig
/// `assemble`). The same summary, certificate, contents, envelopes, effects and events; no input
/// objects; and each transaction's output objects in the order of its effects' references
/// (`outputRefs`), which is the order a core reads them from its store in. A full blob from the
/// archive lists them in another order (mutated, created, unwrapped). An edge that takes a
/// checkpoint from a full source (the public bucket, a directory) hands the follower this form,
/// so the bytes it applies and indexes do not depend on which source served the checkpoint.
/// A transaction whose output objects are not exactly its effects' references keeps the blob's
/// order (the follower's check of outputs against effects then gives the verdict).
/// `arena` holds the tables.
pub fn feedForm(out: *std.ArrayList(u8), gpa: Allocator, arena: Allocator, blob: []const u8, idx: *const types.index.CheckpointIndex) Allocator.Error!void {
    const txs = try arena.alloc(Feed.Tx, idx.tx_count);
    var n_out: usize = 0;
    for (0..idx.tx_count) |i| n_out += idx.txAt(i).out_count;
    const objs = try arena.alloc([]const u8, n_out);
    var refs: std.ArrayList(checkpoint.objects.OutRef) = .empty;
    var keys: std.ArrayList(Key) = .empty;
    var at: u32 = 0;
    for (txs, 0..) |*t, i| {
        const x = idx.txAt(i);
        const outs = idx.objs[x.out_first..][0..x.out_count];
        const dst = objs[at..][0..x.out_count];
        t.* = .{ .tx = x.transaction.slice(blob), .effects = x.effects.slice(blob), .events = if (x.events) |e| e.slice(blob) else null, .first = at, .count = @intCast(x.out_count) };
        at += @intCast(x.out_count);
        if (!try inEffectsOrder(arena, blob, t.effects, outs, dst, &refs, &keys)) {
            for (dst, outs) |*d, r| d.* = r.slice(blob);
        }
    }
    const f: Feed = .{ .seq = 0, .summary_cert = blob[idx.summary.o .. idx.sig.o + idx.sig.n], .contents = idx.contents.slice(blob), .txs = txs, .objs = objs };
    try toBlob(out, gpa, &f);
}

/// (id, version) of an output object and its place in the blob's list.
const Key = struct { k: [40]u8, i: u32 };

fn keyLess(_: void, a: Key, b: Key) bool {
    return std.mem.order(u8, &a.k, &b.k) == .lt;
}

/// Fills `dst` with the objects of `outs` in the order of the effects' output references. False
/// (and `dst` unspecified) unless the two are the same set of (id, version).
fn inEffectsOrder(arena: Allocator, blob: []const u8, effects: []const u8, outs: []const types.index.Range, dst: [][]const u8, refs: *std.ArrayList(checkpoint.objects.OutRef), keys: *std.ArrayList(Key)) Allocator.Error!bool {
    refs.clearRetainingCapacity();
    checkpoint.objects.outputRefsOf(arena, effects, refs) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Decode => return false,
    };
    if (refs.items.len != outs.len) return false;
    keys.clearRetainingCapacity();
    try keys.ensureTotalCapacity(arena, outs.len);
    for (outs, 0..) |r, i| {
        const k = checkpoint.objects.outputKey(r.slice(blob)) orelse return false;
        keys.appendAssumeCapacity(.{ .k = k, .i = @intCast(i) });
    }
    std.mem.sort(Key, keys.items, {}, keyLess);
    for (refs.items, dst) |*ref, *d| {
        const want = ref[0..40];
        var lo: usize = 0;
        var hi: usize = keys.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (std.mem.order(u8, &keys.items[mid].k, want) == .lt) lo = mid + 1 else hi = mid;
        }
        if (lo == keys.items.len or !std.mem.eql(u8, &keys.items[lo].k, want)) return false;
        d.* = outs[keys.items[lo].i].slice(blob);
    }
    return true;
}

/// The output objects a transaction's effects commit to, as (id, version, digest) references in
/// effects order (core side: the keys to read from the store).
pub fn outputRefs(gpa: Allocator, effects: []const u8, out: *std.ArrayList(checkpoint.objects.OutRef)) error{ OutOfMemory, Decode }!void {
    return checkpoint.objects.outputRefsOf(gpa, effects, out);
}

test "feed encode, decode and blob rebuild" {
    const gpa = std.testing.allocator;
    const objs = [_][]const u8{ "obj-a", "obj-bb" };
    const txs = [_]TxIn{
        .{ .tx = "TX0", .effects = "EFF0", .events = null, .objects = &objs },
        .{ .tx = "TX1", .effects = "EFF1", .events = "EV1", .objects = &.{} },
    };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try encode(&out, gpa, 77, "SUMSIG", "CONTENTS", &txs);
    var f = try decode(gpa, out.items);
    defer f.deinit(gpa);
    try std.testing.expectEqual(@as(u64, 77), f.seq);
    try std.testing.expectEqualStrings("SUMSIG", f.summary_cert);
    try std.testing.expectEqualStrings("CONTENTS", f.contents);
    try std.testing.expectEqual(@as(usize, 2), f.txs.len);
    try std.testing.expectEqualStrings("obj-bb", f.objects(&f.txs[0])[1]);
    try std.testing.expect(f.txs[0].events == null);
    try std.testing.expectEqualStrings("EV1", f.txs[1].events.?);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    try toBlob(&blob, gpa, &f);
    const want = "\x01SUMSIGCONTENTS\x02TX0EFF0\x00\x00\x02obj-aobj-bbTX1EFF1\x01EV1\x00\x00";
    try std.testing.expectEqualSlices(u8, want, blob.items);
}

test "feed decode refuses truncation, trailing bytes and absurd counts" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try encode(&out, gpa, 1, "S", "C", &.{.{ .tx = "T", .effects = "E", .events = null, .objects = &.{"O"} }});
    for (0..out.items.len) |n| try std.testing.expect(std.meta.isError(decode(gpa, out.items[0..n])));
    try out.append(gpa, 0);
    try std.testing.expectError(error.Malformed, decode(gpa, out.items));
    // tx count far past what the bytes can hold
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    try bad.appendNTimes(gpa, 0, 8);
    try bad.appendSlice(gpa, &.{ 0, 0, 0xff, 0xff, 0x03 });
    try std.testing.expect(std.meta.isError(decode(gpa, bad.items)));
}

fn testEntry(buf: *[loaded_entry_len]u8, id_byte: u8, version: u64) []const u8 {
    std.mem.writeInt(u64, buf[0..8], version, .little);
    @memset(buf[8..40], id_byte);
    return buf;
}

test "read sets: a feed followed by its lists round trips; without them the feed bytes are unchanged" {
    const gpa = std.testing.allocator;
    const txs = [_]TxIn{
        .{ .tx = "TX0", .effects = "EFF0", .events = null, .objects = &.{"obj-a"} },
        .{ .tx = "TX1", .effects = "EFF1", .events = "EV1", .objects = &.{} },
    };
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try encode(&plain, gpa, 9, "SUMSIG", "CONTENTS", &txs);

    var e0: [loaded_entry_len]u8 = undefined;
    var e1: [loaded_entry_len]u8 = undefined;
    var two: [2 * loaded_entry_len]u8 = undefined;
    @memcpy(two[0..40], testEntry(&e0, 0x11, 7));
    @memcpy(two[40..80], testEntry(&e1, 0x22, 3));
    const lists = [_][]const u8{ &two, "" };

    var with: std.ArrayList(u8) = .empty;
    defer with.deinit(gpa);
    try encode(&with, gpa, 9, "SUMSIG", "CONTENTS", &txs);
    try std.testing.expectEqualSlices(u8, plain.items, with.items);
    try encodeReadSets(&with, gpa, &lists);
    // the feed part is the same bytes, the read sets follow it
    try std.testing.expectEqualSlices(u8, plain.items, with.items[0..plain.items.len]);
    var got = try decodeWithReadSets(gpa, with.items);
    defer got.deinit(gpa);
    try std.testing.expectEqual(@as(u64, 9), got.feed.seq);
    try std.testing.expectEqual(@as(usize, 2), got.read_sets.lists.?.len);
    try std.testing.expectEqualSlices(u8, &two, got.read_sets.lists.?[0]);
    try std.testing.expectEqual(@as(usize, 0), got.read_sets.lists.?[1].len);
    // a reader that did not ask for read sets refuses the longer form, and the other way round
    try std.testing.expectError(error.Malformed, decode(gpa, with.items));
    try std.testing.expectError(error.Malformed, decodeWithReadSets(gpa, plain.items));

    // "none held" is one byte
    var none: std.ArrayList(u8) = .empty;
    defer none.deinit(gpa);
    try none.appendSlice(gpa, plain.items);
    try encodeReadSets(&none, gpa, null);
    try std.testing.expectEqual(plain.items.len + 1, none.items.len);
    var got0 = try decodeWithReadSets(gpa, none.items);
    defer got0.deinit(gpa);
    try std.testing.expect(got0.read_sets.lists == null);
    // every truncation and any trailing byte is refused
    for (plain.items.len..with.items.len) |n| try std.testing.expect(std.meta.isError(decodeWithReadSets(gpa, with.items[0..n])));
    try with.append(gpa, 0);
    try std.testing.expectError(error.Malformed, decodeWithReadSets(gpa, with.items));
    try none.append(gpa, 0);
    try std.testing.expectError(error.Malformed, decodeWithReadSets(gpa, none.items));
    none.items[plain.items.len] = 2;
    try std.testing.expectError(error.Malformed, decodeWithReadSets(gpa, none.items[0 .. plain.items.len + 1]));
}

test "read sets: a list out of sui-node's form is refused" {
    const gpa = std.testing.allocator;
    var a: [loaded_entry_len]u8 = undefined;
    var b: [loaded_entry_len]u8 = undefined;
    var two: [2 * loaded_entry_len]u8 = undefined;
    try std.testing.expect(listCanonical(""));
    try std.testing.expect(listCanonical(testEntry(&a, 5, 1)));
    @memcpy(two[0..40], testEntry(&a, 5, 1));
    @memcpy(two[40..80], testEntry(&b, 6, 1));
    try std.testing.expect(listCanonical(&two));
    // descending ids, a repeated id, a broken entry, a version no object can have
    @memcpy(two[40..80], testEntry(&b, 4, 1));
    try std.testing.expect(!listCanonical(&two));
    @memcpy(two[40..80], testEntry(&b, 5, 2));
    try std.testing.expect(!listCanonical(&two));
    try std.testing.expect(!listCanonical(two[0..79]));
    try std.testing.expect(!listCanonical(testEntry(&a, 5, std.math.maxInt(u64))));
    try std.testing.expect(!listCanonical(testEntry(&a, 5, @as(u64, std.math.maxInt(i64)) + 1)));
    try std.testing.expect(listCanonical(testEntry(&a, 5, std.math.maxInt(i64))));

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try encode(&out, gpa, 1, "S", "C", &.{.{ .tx = "T", .effects = "E", .events = null, .objects = &.{} }});
    @memcpy(two[0..40], testEntry(&a, 9, 1));
    @memcpy(two[40..80], testEntry(&b, 8, 1));
    try encodeReadSets(&out, gpa, &.{&two});
    try std.testing.expectError(error.Malformed, decodeWithReadSets(gpa, out.items));
}
