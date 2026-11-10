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
//! `summary` is BCS CertifiedCheckpointSummary (summary ++ AuthorityStrongQuorumSignInfo),
//! `tx` the BCS Transaction envelope, `events` BCS TransactionEvents, `objects` BCS Object in
//! the order of the effects' changed objects. Nothing in a feed is trusted: the edge rebuilds
//! the blob and runs the same checks as for any other source (BLS quorum certificate, contents
//! and effects digests, every output object against the effects).
const std = @import("std");
const Allocator = std.mem.Allocator;
const checkpoint = @import("checkpoint");

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
    if (r.p != b.len) return error.Malformed;
    return .{ .seq = seq, .summary_cert = summary, .contents = contents, .txs = txs, .objs = try objs.toOwnedSlice(gpa) };
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
