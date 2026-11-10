//! Reader for the storage truth files written by `tools/truth/storage` (`zui-store-truth build`,
//! format in its README.md): per checkpoint, the byte ranges of everything a store keeps and
//! the object writes and removals Mysten's sui-types derives from the effects.
const std = @import("std");
const store = @import("store.zig");

pub const Put = struct { id: *const [32]u8, version: u64, digest: *const [32]u8, bytes: []const u8 };
/// kind: 0 deleted, 1 wrapped, 2 unwrapped then deleted.
pub const Remove = struct { id: *const [32]u8, version: u64, kind: u8 };

pub const Tx = struct {
    digest: *const [32]u8,
    effects_digest: *const [32]u8,
    tx: []const u8,
    effects: []const u8,
    events: ?[]const u8,
    puts: []Put,
    removes: []Remove,
};

pub const Checkpoint = struct {
    seq: u64,
    epoch: u64,
    summary_cert: []const u8,
    contents: []const u8,
    txs: []Tx,
};

pub const Error = error{BadOps} || std.mem.Allocator.Error;

const Cursor = struct {
    b: []const u8,
    p: usize = 0,
    fn take(c: *Cursor, n: usize) Error![]const u8 {
        if (c.p + n > c.b.len) return error.BadOps;
        defer c.p += n;
        return c.b[c.p..][0..n];
    }
    fn int(c: *Cursor, comptime T: type) Error!T {
        return std.mem.readInt(T, (try c.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }
    fn d32(c: *Cursor) Error!*const [32]u8 {
        return (try c.take(32))[0..32];
    }
    fn range(c: *Cursor, blob: []const u8) Error![]const u8 {
        const o = try c.int(u32);
        const n = try c.int(u32);
        if (@as(u64, o) + n > blob.len) return error.BadOps;
        return blob[o..][0..n];
    }
};

/// Parses `ops` (views into it and into `blob`; the arrays come from `arena`).
pub fn parse(arena: std.mem.Allocator, ops: []const u8, blob: []const u8) Error!Checkpoint {
    var c: Cursor = .{ .b = ops };
    if (!std.mem.eql(u8, try c.take(4), "ZSOP")) return error.BadOps;
    if (try c.int(u32) != 1) return error.BadOps;
    var cp: Checkpoint = .{
        .seq = try c.int(u64),
        .epoch = try c.int(u64),
        .summary_cert = try c.range(blob),
        .contents = try c.range(blob),
        .txs = undefined,
    };
    const ntx = try c.int(u32);
    cp.txs = try arena.alloc(Tx, ntx);
    for (cp.txs) |*t| {
        t.digest = try c.d32();
        t.effects_digest = try c.d32();
        t.tx = try c.range(blob);
        t.effects = try c.range(blob);
        const has_ev = (try c.take(1))[0];
        const ev = try c.range(blob);
        t.events = if (has_ev == 1) ev else null;
        const np = try c.int(u32);
        const nr = try c.int(u32);
        t.puts = try arena.alloc(Put, np);
        t.removes = try arena.alloc(Remove, nr);
        for (t.puts) |*p| {
            p.id = try c.d32();
            p.version = try c.int(u64);
            p.digest = try c.d32();
            p.bytes = try c.range(blob);
        }
        for (t.removes) |*r| {
            r.id = try c.d32();
            r.version = try c.int(u64);
            _ = try c.d32();
            r.kind = (try c.take(1))[0];
            if (r.kind > 2) return error.BadOps;
        }
    }
    if (c.p != ops.len) return error.BadOps;
    return cp;
}

pub fn removeKind(k: u8) store.RemoveKind {
    return if (k == 1) .wrapped else .deleted;
}

/// Writes one checkpoint into a batch: the checkpoint, then per transaction its record, its
/// object writes and its removals, in Mysten's order.
pub fn apply(b: *store.Batch, cp: *const Checkpoint) store.Error!void {
    try b.checkpoint(cp.summary_cert, cp.contents);
    for (cp.txs) |*t| {
        try b.transaction(t.digest, t.effects_digest, t.tx, t.effects, t.events);
        for (t.puts) |*p| try b.putObject(p.id, p.version, p.digest, p.bytes);
        for (t.removes) |*r| try b.removeObject(r.id, r.version, removeKind(r.kind));
    }
}
