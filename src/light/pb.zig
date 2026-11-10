//! Minimal protobuf reader (prost semantics: a scalar or bytes field seen twice keeps the last
//! value, a message field seen twice is merged in order). Borrowed from src/node/convert.zig,
//! which the light client cannot import (node pulls in the executor).
const std = @import("std");

pub const Error = error{Malformed};

pub const Field = struct { number: u32, wire: u3, varint: u64 = 0, data: []const u8 = &.{} };

pub const Pb = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn varint(r: *Pb) Error!u64 {
        var v: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            if (r.pos >= r.buf.len or shift > 63) return error.Malformed;
            const b = r.buf[r.pos];
            r.pos += 1;
            v |= @as(u64, b & 0x7f) << @intCast(shift);
            if (b < 0x80) return v;
            shift += 7;
        }
    }

    fn take(r: *Pb, n: u64) Error![]const u8 {
        if (n > r.buf.len - r.pos) return error.Malformed;
        const s = r.buf[r.pos..][0..@intCast(n)];
        r.pos += @intCast(n);
        return s;
    }

    /// Next field, or null at the end. Groups are skipped.
    pub fn next(r: *Pb) Error!?Field {
        while (true) {
            if (r.pos == r.buf.len) return null;
            const k = try r.varint();
            const number = k >> 3;
            if (number == 0 or number > 0x1fffffff) return error.Malformed;
            const wire: u3 = @truncate(k);
            var f: Field = .{ .number = @intCast(number), .wire = wire };
            switch (wire) {
                0 => f.varint = try r.varint(),
                1 => f.data = try r.take(8),
                2 => f.data = try r.take(try r.varint()),
                5 => f.data = try r.take(4),
                3 => {
                    try r.skipGroup(@intCast(number), 0);
                    continue;
                },
                else => return error.Malformed,
            }
            return f;
        }
    }

    fn skipGroup(r: *Pb, number: u32, depth: u32) Error!void {
        if (depth > 100) return error.Malformed;
        while (true) {
            const k = try r.varint();
            const n = k >> 3;
            const wire: u3 = @truncate(k);
            switch (wire) {
                0 => _ = try r.varint(),
                1 => _ = try r.take(8),
                2 => _ = try r.take(try r.varint()),
                5 => _ = try r.take(4),
                3 => try r.skipGroup(@intCast(n), depth + 1),
                4 => {
                    if (n != number) return error.Malformed;
                    return;
                },
                else => return error.Malformed,
            }
        }
    }
};

pub fn bytesOf(f: Field) Error![]const u8 {
    if (f.wire != 2) return error.Malformed;
    return f.data;
}

pub fn varintOf(f: Field) Error!u64 {
    if (f.wire != 0) return error.Malformed;
    return f.varint;
}

/// `Bcs { name = 1; value = 2 }`: applies one occurrence into `value`.
fn mergeBcs(value: *?[]const u8, msg: []const u8) Error!void {
    var r: Pb = .{ .buf = msg };
    while (try r.next()) |f| {
        if (f.number == 2) value.* = try bytesOf(f);
    }
}

/// A message whose field 1 is a `Bcs` (CheckpointSummary, CheckpointContents, Transaction,
/// TransactionEffects, TransactionEvents, Object).
pub fn mergeBcsHolder(value: *?[]const u8, msg: []const u8) Error!void {
    var r: Pb = .{ .buf = msg };
    while (try r.next()) |f| {
        if (f.number == 1) try mergeBcs(value, try bytesOf(f));
    }
}

/// sui.rpc.v2 `ValidatorAggregatedSignature { epoch = 1; signature = 2; bitmap = 3 }`.
pub const AggSig = struct {
    epoch: u64 = 0,
    signature: []const u8 = &.{},
    bitmap: []const u8 = &.{},
};

pub fn mergeAggSig(s: *AggSig, msg: []const u8) Error!void {
    var r: Pb = .{ .buf = msg };
    while (try r.next()) |f| switch (f.number) {
        1 => s.epoch = try varintOf(f),
        2 => s.signature = try bytesOf(f),
        3 => s.bitmap = try bytesOf(f),
        else => {},
    };
}

/// sui.rpc.v2 `ExecutedTransaction`: transaction = 2, effects = 4, events = 5 (each a Bcs holder).
pub const Tx = struct {
    data: ?[]const u8 = null,
    effects: ?[]const u8 = null,
    has_events: bool = false,
    events: ?[]const u8 = null,
};

pub fn mergeTx(t: *Tx, msg: []const u8) Error!void {
    var r: Pb = .{ .buf = msg };
    while (try r.next()) |f| switch (f.number) {
        2 => try mergeBcsHolder(&t.data, try bytesOf(f)),
        4 => try mergeBcsHolder(&t.effects, try bytesOf(f)),
        5 => {
            t.has_events = true;
            try mergeBcsHolder(&t.events, try bytesOf(f));
        },
        else => {},
    };
}

/// sui.rpc.v2 `Checkpoint`: summary = 3, signature = 4, contents = 5, transactions = 6.
/// `txs` borrows `tx_buf` (a checkpoint with more transactions than it holds is Malformed).
pub const Checkpoint = struct {
    seq: ?u64 = null,
    summary: ?[]const u8 = null,
    sig: AggSig = .{},
    has_sig: bool = false,
    contents: ?[]const u8 = null,
    txs: []Tx = &.{},
};

/// Counts the `transactions` entries of a Checkpoint proto (to size the buffer for `parseCheckpoint`).
pub fn countTxs(proto: []const u8) Error!usize {
    var r: Pb = .{ .buf = proto };
    var n: usize = 0;
    while (try r.next()) |f| {
        if (f.number == 6) n += 1;
    }
    return n;
}

pub fn parseCheckpoint(proto: []const u8, tx_buf: []Tx) Error!Checkpoint {
    var p: Checkpoint = .{};
    var r: Pb = .{ .buf = proto };
    var n: usize = 0;
    while (try r.next()) |f| switch (f.number) {
        1 => p.seq = try varintOf(f),
        3 => try mergeBcsHolder(&p.summary, try bytesOf(f)),
        4 => {
            p.has_sig = true;
            try mergeAggSig(&p.sig, try bytesOf(f));
        },
        5 => try mergeBcsHolder(&p.contents, try bytesOf(f)),
        6 => {
            if (n == tx_buf.len) return error.Malformed;
            tx_buf[n] = .{};
            try mergeTx(&tx_buf[n], try bytesOf(f));
            n += 1;
        },
        else => {},
    };
    p.txs = tx_buf[0..n];
    return p;
}

/// Unwraps `GetCheckpointResponse { checkpoint = 1 }` when given one; a bare Checkpoint passes
/// through (field 1 of a Checkpoint is a varint, of the response a message).
pub fn unwrapResponse(proto: []const u8) Error![]const u8 {
    var r: Pb = .{ .buf = proto };
    const f = (try r.next()) orelse return proto;
    if (f.number == 1 and f.wire == 2) {
        var inner: ?[]const u8 = null;
        r = .{ .buf = proto };
        while (try r.next()) |g| {
            if (g.number == 1) inner = try bytesOf(g);
        }
        return inner.?;
    }
    return proto;
}

test "varint and nested bcs holder" {
    // CheckpointSummary { bcs: Bcs { value: [1,2,3] } } as field 3 of a Checkpoint, seq 7
    const msg = [_]u8{ 0x08, 7, 0x1a, 7, 0x0a, 5, 0x12, 3, 1, 2, 3 };
    var txs: [1]Tx = undefined;
    const c = try parseCheckpoint(&msg, &txs);
    try std.testing.expectEqual(@as(?u64, 7), c.seq);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, c.summary.?);
    try std.testing.expectEqualSlices(u8, &msg, try unwrapResponse(&msg));
}
