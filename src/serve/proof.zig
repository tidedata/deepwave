//! sui.rpc.v2alpha.ProofService on a `store.Store`, as sui-node 1.83.1 answers it
//! (sui-rpc-api grpc/v2alpha/proof_service/get_checkpoint_object_proof.rs):
//!
//! GetCheckpointObjectProof { object_id, checkpoint } ->
//!   { checkpoint_summary = BCS(CertifiedCheckpointSummary), inclusion | non_inclusion }
//!
//! Checks in the handler's order: object_id (missing, blank, `ObjectID::from_str`), checkpoint
//! missing, indexes (none: `RpcError::not_found()`, NOT_FOUND without a message), then the
//! checkpoint against the lowest available objects checkpoint and the highest indexed one, the
//! checkpoint load, V1 effects (FAILED_PRECONDITION), then the OCS leaves
//! (`CheckpointArtifacts::object_states`: every effects' `written()` in checkpoint order, the last
//! write of an id winning, sorted by id) and the proof (merkle.zig). An inclusion proof carries the
//! object's BCS when the leaf digest is not the deleted/wrapped sentinel. No read mask.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const h2 = @import("h2/root.zig");
const service = @import("service.zig");
const reqdecode = @import("reqdecode.zig");
const proto = @import("proto.zig");
const b58 = @import("b58.zig");
const merkle = @import("merkle.zig");

pub const prefix = "/sui.rpc.v2alpha.ProofService/";

pub fn call(svc: *service.Service, arena: Allocator, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    const method = req.path[prefix.len..];
    if (!std.mem.eql(u8, method, "GetCheckpointObjectProof")) return .unimplemented;
    if (reqdecode.check(arena, &reqdecode.get_checkpoint_object_proof_request, req.body)) |text| {
        rs.setMessage(text);
        return .internal; // tonic: Status::internal(DecodeError), no details
    }
    var snap = svc.store.snapshot();
    defer snap.release();
    return getCheckpointObjectProof(svc, arena, &snap, req.body, rs) catch |e| switch (e) {
        error.OutOfMemory => service.fail(arena, rs, e),
        else => {
            if (rs.msg.len == 0) rs.setMessage(@errorName(e));
            return service.withDetails(arena, rs, .internal);
        },
    };
}

/// An `RpcError::new(code, message)` reply: the message, and details `Status { code, message }`.
fn reply(arena: Allocator, rs: *h2.ResponseStream, code: h2.Status, text: []const u8) h2.Status {
    rs.setMessage(text);
    return service.withDetails(arena, rs, code);
}

fn getCheckpointObjectProof(svc: *service.Service, arena: Allocator, snap: *store.Snapshot, body: []const u8, rs: *h2.ResponseStream) !h2.Status {
    // prost: the last occurrence of a scalar field wins
    var id_text: ?[]const u8 = null;
    var checkpoint: ?u64 = null;
    var r = proto.Reader.init(body);
    while (try r.next()) |f| switch (f.number) {
        1 => id_text = try proto.Reader.stringOf(f),
        2 => checkpoint = try proto.Reader.varintOf(f),
        else => {},
    };

    // parse_object_id
    const text = id_text orelse return reply(arena, rs, .invalid_argument, "missing object_id");
    if (isBlank(text)) return reply(arena, rs, .invalid_argument, "object_id cannot be empty");
    const id = objectIdFromStr(text) orelse return reply(arena, rs, .invalid_argument, "invalid object_id: ObjectID hex literal must start with 0x");
    const seq = checkpoint orelse return reply(arena, rs, .invalid_argument, "missing checkpoint");

    // validate_checkpoint_bounds
    const hi = highestIndexed(svc) orelse return service.fail(arena, rs, error.NotFoundBare);
    const lowest = service.lowestOf(svc);
    if (seq < lowest) return reply(arena, rs, .not_found, try std.fmt.allocPrint(arena, "requested checkpoint {d} has been pruned; lowest available checkpoint is {d}", .{ seq, lowest }));
    if (seq > hi) return reply(arena, rs, .not_found, try std.fmt.allocPrint(arena, "requested checkpoint {d} is not yet indexed; highest indexed checkpoint is {d}", .{ seq, hi }));

    // load_checkpoint
    const rec = snap.checkpoint(seq) orelse return reply(arena, rs, .not_found, try std.fmt.allocPrint(arena, "checkpoint {d} not found", .{seq}));
    const effects = loadEffects(arena, snap, rec) catch |e| switch (e) {
        error.MissingTransaction => return reply(arena, rs, .internal, try std.fmt.allocPrint(arena, "checkpoint {d}: transaction data not found", .{seq})),
        else => return e,
    };

    // build_ocs_leaves: V1 effects first
    for (effects) |fx| if (fx.len == 0 or fx[0] == 0) {
        return reply(arena, rs, .failed_precondition, try std.fmt.allocPrint(arena, "object proofs are not supported for checkpoint {d} because it contains TransactionEffectsV1", .{seq}));
    };
    const leaves = try objectStates(arena, effects);
    const tree = try merkle.ocsTree(arena, leaves);
    const root = tree.root().bytes();
    const path_buf = try arena.alloc(merkle.Node, tree.depth());

    var e: Enc = .{ .a = arena };
    try e.bytes(1, rec.summary_cert);
    switch (merkle.search(leaves, &id)) {
        .found => |i| {
            const leaf = leaves[i];
            var inc: Enc = .{ .a = arena };
            try inc.msg(1, try objectReference(arena, &leaf));
            try inc.msg(2, try merkleProof(arena, tree.proof(i, path_buf).?));
            try inc.uint(3, i);
            try inc.bytes(4, &root);
            if (merkle.isAlive(&leaf.digest)) {
                const raw = snap.objectAt(&leaf.id, leaf.version) orelse {
                    const hex = std.fmt.bytesToHex(leaf.id, .lower);
                    return reply(arena, rs, .not_found, try std.fmt.allocPrint(arena, "object 0x{s} not found at version 0x{x}", .{ &hex, leaf.version }));
                };
                try inc.bytes(5, raw);
            }
            try e.msg(2, &inc);
        },
        .absent => |pos| {
            var ni: Enc = .{ .a = arena };
            try ni.uint(1, pos);
            if (pos > 0) try ni.msg(2, try neighbour(arena, &tree, leaves, pos - 1, path_buf));
            if (pos < leaves.len) try ni.msg(3, try neighbour(arena, &tree, leaves, pos, path_buf));
            var non: Enc = .{ .a = arena };
            try non.msg(1, &ni);
            try non.bytes(2, &root);
            try e.msg(3, &non);
        },
    }
    try rs.message(e.buf.items);
    return .ok;
}

/// `reader.indexes()` and `get_highest_indexed_checkpoint_seq_number().unwrap_or(0)`: the rpc
/// index's highest indexed checkpoint, else the ledger-history index's published one (a node
/// serves both or neither; the conformance node has only the latter). Null: indexing is off.
fn highestIndexed(svc: *const service.Service) ?u64 {
    if (svc.rpc) |x| return x.highestIndexed() orelse 0;
    if (svc.history) |h| {
        const p = h.published.load(.acquire); // readers see checkpoints < p
        return if (p == 0) 0 else p - 1;
    }
    return null;
}

/// Each transaction's effects BCS, in checkpoint order (`get_checkpoint_data`'s transactions).
fn loadEffects(arena: Allocator, snap: *store.Snapshot, rec: store.CheckpointRecord) ![]const []const u8 {
    const contents = try bcs.decode(types.CheckpointContents, arena, rec.contents);
    const n = switch (contents) {
        .V1 => |v| v.transactions.len,
        .V2 => |v| v.transactions.len,
    };
    const out = try arena.alloc([]const u8, n);
    for (out, 0..) |*o, i| {
        const dg: *const [32]u8 = switch (contents) {
            .V1 => |v| &v.transactions[i].transaction.@"0".@"0",
            .V2 => |v| &v.transactions[i].digest.transaction.@"0".@"0",
        };
        const t = snap.transactionNear(dg, rec.seq) orelse return error.MissingTransaction;
        o.* = t.effects;
    }
    return out;
}

/// `CheckpointArtifacts::from(&[&TransactionEffects]).object_states()`: each V2 effects'
/// `written()` (deleted: lamport version + DELETED sentinel; wrapped: lamport + WRAPPED; written
/// object: lamport + its digest; package: its own version and digest; created-and-gone and
/// accumulator writes: none), later transactions overwriting earlier ones, sorted by id.
pub fn objectStates(arena: Allocator, effects: []const []const u8) ![]merkle.ObjRef {
    var at: std.AutoHashMapUnmanaged([32]u8, usize) = .empty;
    var list: std.ArrayList(merkle.ObjRef) = .empty;
    for (effects) |raw| {
        const fx = try bcs.decode(types.TransactionEffects, arena, raw);
        const v = switch (fx) {
            .V1 => return error.EffectsV1,
            .V2 => |v| v,
        };
        const lamport = v.lamport_version.@"0";
        for (v.changed_objects) |c| {
            const id = c.@"0".@"0".@"0";
            const ch = c.@"1";
            const ref: merkle.ObjRef = switch (ch.output_state) {
                .NotExist => switch (ch.id_operation) {
                    .Deleted => .{ .id = id, .version = lamport, .digest = merkle.digest_deleted },
                    .None => .{ .id = id, .version = lamport, .digest = merkle.digest_wrapped },
                    .Created => continue,
                },
                .ObjectWrite => |w| .{ .id = id, .version = lamport, .digest = w.@"0".@"0".@"0" },
                .PackageWrite => |w| .{ .id = id, .version = w.@"0".@"0", .digest = w.@"1".@"0".@"0" },
                .AccumulatorWriteV1 => continue,
            };
            const gop = try at.getOrPut(arena, id);
            if (gop.found_existing) {
                list.items[gop.value_ptr.*] = ref;
            } else {
                gop.value_ptr.* = list.items.len;
                try list.append(arena, ref);
            }
        }
    }
    std.mem.sort(merkle.ObjRef, list.items, {}, merkle.ObjRef.lessById);
    return list.items;
}

// ---- request parsing ----

/// Rust `str::trim().is_empty()`: only Unicode White_Space code points (the request decoded, so
/// `text` is UTF-8).
fn isBlank(text: []const u8) bool {
    const view = std.unicode.Utf8View.init(text) catch return false;
    var it = view.iterator();
    while (it.nextCodepoint()) |c| switch (c) {
        0x09...0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => {},
        else => return false,
    };
    return true;
}

/// sui-types `ObjectID::from_str`: `decode_bytes_hex` (fastcrypto `Hex::decode`: one optional
/// "0x" stripped, any-case hex, exactly 32 bytes), else `from_hex_literal`: "0x" required, fewer
/// than 64 digits left-padded with '0' and parsed again, otherwise the digits parsed again. Every
/// failure ends in `HexLiteralPrefixMissing`.
/// A loop, not the Rust recursion: a 4 MiB "0x0x0x..." id would otherwise recurse two million
/// frames deep on a request worker's stack.
pub fn objectIdFromStr(s_in: []const u8) ?[32]u8 {
    var s = s_in;
    var padded: [64]u8 = undefined;
    while (true) {
        if (decodeHex32(s)) |id| return id;
        if (!std.mem.startsWith(u8, s, "0x")) return null;
        const hex_len = s.len - 2;
        if (hex_len < 64) {
            // s may be `padded` itself: copy the digits out first
            var tmp: [64]u8 = undefined;
            @memcpy(tmp[0..hex_len], s[2..]);
            @memset(padded[0 .. 64 - hex_len], '0');
            @memcpy(padded[64 - hex_len ..], tmp[0..hex_len]);
            s = &padded;
        } else s = s[2..];
    }
}

fn decodeHex32(s: []const u8) ?[32]u8 {
    const h = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    if (h.len != 64) return null;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch return null;
    return out;
}

// ---- response encoding (prost: fields in number order, `optional` written when present) ----

const Enc = struct {
    a: Allocator,
    buf: std.ArrayList(u8) = .empty,

    fn varint(e: *Enc, v: u64) !void {
        var x = v;
        while (x >= 0x80) : (x >>= 7) try e.buf.append(e.a, @as(u8, @truncate(x)) | 0x80);
        try e.buf.append(e.a, @truncate(x));
    }
    fn uint(e: *Enc, field: u32, v: u64) !void {
        try e.varint(@as(u64, field) << 3 | proto.wire_varint);
        try e.varint(v);
    }
    fn bytes(e: *Enc, field: u32, data: []const u8) !void {
        try e.varint(@as(u64, field) << 3 | proto.wire_len);
        try e.varint(data.len);
        try e.buf.appendSlice(e.a, data);
    }
    fn msg(e: *Enc, field: u32, sub: *const Enc) !void {
        try e.bytes(field, sub.buf.items);
    }
};

/// sui.rpc.v2.ObjectReference { object_id = "0x" + 64 hex, version, digest = base58 }.
fn objectReference(arena: Allocator, r: *const merkle.ObjRef) !*Enc {
    const e = try arena.create(Enc);
    e.* = .{ .a = arena };
    var id: [66]u8 = undefined;
    id[0] = '0';
    id[1] = 'x';
    id[2..].* = std.fmt.bytesToHex(r.id, .lower);
    try e.bytes(1, &id);
    try e.uint(2, r.version);
    var dbuf: [b58.max_len_32]u8 = undefined;
    try e.bytes(3, b58.encode32(&dbuf, &r.digest));
    return e;
}

/// MerkleProof { repeated MerkleNode path = 1 }, MerkleNode { oneof { Empty empty = 1; bytes digest = 2 } }.
fn merkleProof(arena: Allocator, path: []const merkle.Node) !*Enc {
    const e = try arena.create(Enc);
    e.* = .{ .a = arena };
    for (path) |n| {
        var node: Enc = .{ .a = arena };
        switch (n) {
            .empty => try node.bytes(1, ""),
            .digest => |dg| try node.bytes(2, &dg),
        }
        try e.msg(1, &node);
    }
    return e;
}

/// MerkleNeighbourLeaf { leaf = 1, merkle_proof = 2 } for leaf `i`.
fn neighbour(arena: Allocator, tree: *const merkle.Tree, leaves: []const merkle.ObjRef, i: usize, path_buf: []merkle.Node) !*const Enc {
    const e = try arena.create(Enc);
    e.* = .{ .a = arena };
    try e.msg(1, try objectReference(arena, &leaves[i]));
    try e.msg(2, try merkleProof(arena, tree.proof(i, path_buf).?));
    return e;
}

test "proof: ObjectID::from_str as sui-types parses it" {
    const full = "e4b533e84975e5f2a48ae1961e2606e81a57050fe738ca30ac77ed4d8b9b4f18";
    const want = objectIdFromStr("0x" ++ full).?;
    try std.testing.expectEqual(@as(u8, 0xe4), want[0]);
    try std.testing.expectEqualSlices(u8, &want, &objectIdFromStr(full).?); // no prefix: decode_bytes_hex
    try std.testing.expectEqualSlices(u8, &want, &objectIdFromStr("0xE4B533E84975E5F2A48AE1961E2606E81A57050FE738CA30AC77ED4D8B9B4F18").?);
    const six = objectIdFromStr("0x6").?;
    try std.testing.expectEqual(@as(u8, 6), six[31]);
    try std.testing.expectEqual(@as(u8, 0), six[0]);
    try std.testing.expectEqual(@as(u8, 0), objectIdFromStr("0x").?[31]); // padded to 64 zeros
    try std.testing.expect(objectIdFromStr("6") == null); // short without 0x: prefix missing
    {
        // "0x" repeated to the request cap: a loop, not a recursion two million deep
        const gpa = std.testing.allocator;
        const n = 2 << 20;
        const long = try gpa.alloc(u8, 2 * n + 64);
        defer gpa.free(long);
        for (0..n) |i| @memcpy(long[2 * i ..][0..2], "0x");
        @memcpy(long[2 * n ..], full);
        try std.testing.expectEqualSlices(u8, &want, &objectIdFromStr(long).?);
    }
    try std.testing.expect(objectIdFromStr("0xzz") == null);
    const ones: [66]u8 = @splat('1');
    try std.testing.expect(objectIdFromStr("0x" ++ ones) == null);
    try std.testing.expect(objectIdFromStr("0x0x6") == null);
    try std.testing.expect(isBlank("  \t\u{3000}"));
    try std.testing.expect(!isBlank(" 0x6 "));
}
