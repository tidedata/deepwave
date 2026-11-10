//! LedgerService handlers on raw record bytes (store-independent core). The gRPC glue lives in
//! service.zig; these functions take the BCS the store holds and write the response message.
const std = @import("std");
const Allocator = std.mem.Allocator;
const proto = @import("proto.zig");
const mask = @import("mask.zig");
const rc = @import("render_checkpoint.zig");
const render_tx = @import("render_tx.zig");
const balance = @import("balance.zig");
const objset = @import("objset.zig");

pub const Error = rc.Error;

/// `GetCheckpointResponse { checkpoint = 1 }` fields 1-5 of the Checkpoint (summary, signature,
/// contents); transactions and objects are appended by the caller.
pub fn getCheckpoint(
    arena: Allocator,
    w: *proto.Writer,
    m: mask.Mask,
    cert_bytes: []const u8,
    contents_bytes: ?[]const u8,
    object_raws: []const []const u8,
    txs: []const render_tx.Input,
) Error!void {
    return checkpointAt(arena, w, 1, m, cert_bytes, contents_bytes, object_raws, txs);
}

/// The Checkpoint message as field `field` of the parent (1 in GetCheckpointResponse, 2 in
/// SubscribeCheckpointsResponse).
pub fn checkpointAt(
    arena: Allocator,
    w: *proto.Writer,
    field: u32,
    m: mask.Mask,
    cert_bytes: []const u8,
    contents_bytes: ?[]const u8,
    object_raws: []const []const u8,
    txs: []const render_tx.Input,
) Error!void {
    const cert = try rc.Cert.parse(arena, cert_bytes);
    var contents: ?rc.Contents = null;
    const want_contents = m.subtree("contents") != null;
    const eff_digests = if (m.subtree("transactions")) |t| if (t.subtree("effects")) |e| e.contains("digest") else false else false;
    if (want_contents or (eff_digests and txs.len > 0)) {
        if (contents_bytes) |cb| contents = try rc.Contents.parse(arena, cb);
    }
    // The contents carry each transaction's effects digest: no need to hash the effects again.
    var txs_with = txs;
    if (eff_digests and txs.len > 0) if (contents) |*c| {
        const copy = try arena.dupe(render_tx.Input, txs);
        for (copy, 0..) |*t, i| t.effects_digest = switch (c.value) {
            .V1 => |v| if (i < v.transactions.len) &v.transactions[i].effects.@"0".@"0" else null,
            .V2 => |v| if (i < v.transactions.len) &v.transactions[i].digest.effects.@"0".@"0" else null,
        };
        txs_with = copy;
    };
    const mm = try w.begin(field, 512);
    try rc.writeCheckpointHead(w, m, &cert, if (contents) |*c| c else null, arena);
    try writeTransactions(arena, w, m, cert.summary.sequence_number, cert.summary.timestamp_ms, txs_with, object_raws);
    try writeObjectSet(arena, w, m, object_raws);
    try w.end(mm);
}

const types = @import("types");
const bcs = @import("bcs");
const render_object = @import("render_object.zig");

/// The `objects` field (7) of a Checkpoint: an ObjectSet of every distinct (id, version) object
/// the checkpoint's transactions read or wrote, in ObjectKey order (id bytes, then version).
/// `raws` are BCS(Object) in any order and may repeat; duplicates are collapsed like Rust's
/// BTreeMap insert (the later insert wins, and equal keys have equal bytes).
pub fn writeObjectSet(arena: Allocator, w: *proto.Writer, m: mask.Mask, raws: []const []const u8) Error!void {
    return writeObjectSetAt(arena, w, 7, m, raws);
}

/// `ObjectSet` message at `field` of the parent, when mask `m` selects `objects.objects`.
pub fn writeObjectSetAt(arena: Allocator, w: *proto.Writer, field: u32, m: mask.Mask, raws: []const []const u8) Error!void {
    return writeObjectSetAtCtx(arena, w, field, m, raws, null);
}

/// As `writeObjectSetAt`, rendering `json`/`display` with `ctx` (GetTransaction's object set).
pub fn writeObjectSetAtCtx(arena: Allocator, w: *proto.Writer, field: u32, m: mask.Mask, raws: []const []const u8, ctx: ?*const render_object.Ctx) Error!void {
    const sub = (m.subtree("objects") orelse return).subtree("objects") orelse return;
    const Entry = struct { id: [32]u8, version: u64, raw: []const u8 };
    const entries = try arena.alloc(Entry, raws.len);
    for (raws, entries) |raw, *e| {
        const obj = try bcs.decode(types.Object, arena, raw);
        switch (obj.data) {
            .Move => |mo| e.* = .{ .id = mo.contents[0..32].*, .version = mo.version.@"0", .raw = raw },
            .Package => |p| e.* = .{ .id = p.id.@"0".@"0", .version = p.version.@"0", .raw = raw },
        }
    }
    std.mem.sort(Entry, entries, {}, struct {
        fn lt(_: void, a: Entry, b: Entry) bool {
            const o = std.mem.order(u8, &a.id, &b.id);
            return if (o == .eq) a.version < b.version else o == .lt;
        }
    }.lt);
    const set = try w.begin(field, 4096);
    var prev: ?Entry = null;
    for (entries) |e| {
        if (prev) |p| if (std.mem.eql(u8, &p.id, &e.id) and p.version == e.version) continue;
        prev = e;
        const mm = try w.begin(1, e.raw.len + 128);
        try render_object.writeObjectCtx(arena, w, sub, e.raw, ctx);
        try w.end(mm);
    }
    try w.end(set);
}

/// The `transactions` field (6) of a Checkpoint. `checkpoint`/`timestamp` come from the summary.
pub fn writeTransactions(arena: Allocator, w: *proto.Writer, m: mask.Mask, seq: u64, ts_ms: u64, txs: []const render_tx.Input, object_raws: []const []const u8) Error!void {
    const sub = m.subtree("transactions") orelse return;
    const want_balance = sub.contains("balance_changes");
    const want_types = if (sub.subtree("effects")) |em| em.contains("changed_objects") or em.contains("unchanged_consensus_objects") else false;
    var set: objset.ObjSet = .{};
    if ((want_types or want_balance) and txs.len > 0) set = try objset.ObjSet.build(arena, object_raws);
    for (txs) |t0| {
        var t = t0;
        if (want_types and t.objects == null) t.objects = &set;
        if (want_balance) t.decoded_effects = try bcs.decode(types.TransactionEffects, arena, t.effects);
        const mm = try w.begin(6, t.transaction.len + t.effects.len + 256);
        try render_tx.writeExecuted(arena, w, sub, t);
        if (sub.contains("checkpoint")) try w.uint(6, seq);
        if (sub.contains("timestamp")) {
            const tm = try w.begin(7, 12);
            if (ts_ms / 1000 != 0) try w.uint(1, ts_ms / 1000);
            if (ts_ms % 1000 != 0) try w.uint(2, (ts_ms % 1000) * 1_000_000);
            try w.end(tm);
        }
        if (want_balance) {
            for (try balance.derive(arena, t.decoded_effects.?, &set.map)) |c| try balance.write(w, 8, c);
        }
        try w.end(mm);
    }
}

/// ExecutedTransaction message body for GetTransaction: the mask's fields 1-5 plus checkpoint,
/// timestamp and balance changes. `object_raws` are the transaction's input/output objects.
pub fn writeExecutedBody(arena: Allocator, w: *proto.Writer, m: mask.Mask, t0: render_tx.Input, seq: u64, ts_ms: u64, object_raws: []const []const u8) Error!void {
    var t = t0;
    var set: objset.ObjSet = .{};
    const want_types = if (m.subtree("effects")) |em| em.contains("changed_objects") or em.contains("unchanged_consensus_objects") else false;
    if (t.objects == null and (want_types or m.contains("balance_changes"))) {
        set = try objset.ObjSet.build(arena, object_raws);
        t.objects = &set;
    }
    if (m.contains("balance_changes") and t.decoded_effects == null) t.decoded_effects = try bcs.decode(types.TransactionEffects, arena, t.effects);
    try render_tx.writeExecuted(arena, w, m, t);
    if (m.contains("checkpoint")) try w.uint(6, seq);
    if (m.contains("timestamp")) {
        const tm = try w.begin(7, 12);
        if (ts_ms / 1000 != 0) try w.uint(1, ts_ms / 1000);
        if (ts_ms % 1000 != 0) try w.uint(2, (ts_ms % 1000) * 1_000_000);
        try w.end(tm);
    }
    if (m.contains("balance_changes")) {
        for (try balance.derive(arena, t.decoded_effects.?, &t.objects.?.map)) |c| try balance.write(w, 8, c);
    }
    try writeObjectSetAtCtx(arena, w, 9, m, object_raws, t0.render);
}
