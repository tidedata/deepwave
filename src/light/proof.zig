//! zui/1 verified-mode proofs (docs/NATIVE-PROTOCOL.md section 7) checked in one call: the BCS
//! `Proof` an edge or core sends beside an object or transaction answer, against the committee
//! the light client trusts. No trust in the server, the edge operator or the transport:
//!
//!   Proof     { checkpoints: vector<ProofCheckpoint>, items: vector<ItemProof> }
//!   ProofCheckpoint { summary: bytes /* CertifiedCheckpointSummary */, contents: bytes }
//!   ItemProof = None | Tx { checkpoint: u32, effects: bytes } | Object { checkpoint: u32, effects: bytes }
//!
//! For item `i`: the referenced certified summary is checked against its epoch's committee (BLS
//! quorum, memoised by `Client`), the contents against the summary's digest, the effects against
//! the contents' execution digest, and then either the transaction's data and events against
//! their digests, or the object's (id, version, digest) against the effects' changed objects.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const root = @import("root.zig");
const Client = root.Client;
const Status = root.Status;

/// What a proof item claims to prove.
pub const Kind = enum {
    /// `data` is BCS `TransactionData`.
    tx,
    /// `data` is the BCS `Transaction` envelope (`Tx.tx` of the native protocol: SenderSignedData
    /// with its signatures); its `TransactionData` is checked against the digest.
    tx_envelope,
    object,
};

/// The `TransactionData` inside a BCS `Transaction` envelope (a one-element SenderSignedData: the
/// intent, the data, the signatures).
pub fn transactionDataOf(envelope: []const u8) ?[]const u8 {
    var r = bcs.Reader.init(envelope);
    const n = r.length() catch return null;
    if (n != 1) return null;
    _ = r.bytes(3) catch return null; // intent
    const at = r.at;
    bcs.skip(types.TransactionData, &r) catch return null;
    return envelope[at..r.at];
}

pub const Verdict = struct {
    status: Status,
    checkpoint: root.Verified = undefined,
    tx: root.TxOut = .{},
    obj: root.ObjOut = .{},
};

const Cp = struct { summary: []const u8, contents: []const u8 };
const Item = union(enum) { none, tx: struct { cp: u32, effects: []const u8 }, object: struct { cp: u32, effects: []const u8 } };

fn readBytes(r: *bcs.Reader) bcs.Error![]const u8 {
    const n = try r.length();
    return r.bytes(n);
}

/// Item count of a proof (for batch answers), or null when it does not parse.
pub fn itemCount(proof: []const u8) ?usize {
    var r = bcs.Reader.init(proof);
    const ncp = r.length() catch return null;
    for (0..ncp) |_| {
        _ = readBytes(&r) catch return null;
        _ = readBytes(&r) catch return null;
    }
    return r.length() catch null;
}

/// Verifies item `index` of `proof` as `kind`. `data` is the object's BCS (kind `object`) or the
/// transaction's BCS `TransactionData` (kind `tx`, optional); `events` is the transaction's BCS
/// `TransactionEvents` (kind `tx`, optional).
pub fn verifyItem(c: *Client, proof: []const u8, index: usize, kind: Kind, data: ?[]const u8, events: ?[]const u8) Verdict {
    var v: Verdict = .{ .status = .decode };
    var r = bcs.Reader.init(proof);
    const ncp = r.length() catch return v;
    // checkpoints are walked twice (find the item, then the one it names): remember their ranges
    var cps: std.ArrayList(Cp) = .empty;
    defer cps.deinit(c.gpa);
    for (0..ncp) |_| {
        const s = readBytes(&r) catch return v;
        const ct = readBytes(&r) catch return v;
        cps.append(c.gpa, .{ .summary = s, .contents = ct }) catch {
            v.status = .out_of_memory;
            return v;
        };
    }
    const nitems = r.length() catch return v;
    if (index >= nitems) return v;
    var item: Item = .none;
    for (0..index + 1) |i| {
        const tag = r.uleb32() catch return v;
        switch (tag) {
            0 => item = .none,
            1, 2 => {
                const cp = r.int(u32) catch return v;
                const eff = readBytes(&r) catch return v;
                if (i == index) item = if (tag == 1) .{ .tx = .{ .cp = cp, .effects = eff } } else .{ .object = .{ .cp = cp, .effects = eff } };
            },
            else => return v,
        }
    }
    const cp_idx: u32, const effects: []const u8 = switch (item) {
        .none => {
            v.status = .not_found;
            return v;
        },
        .tx => |x| .{ x.cp, x.effects },
        .object => |x| .{ x.cp, x.effects },
    };
    // an object answer must carry an object item and a transaction answer a transaction item
    if ((item == .tx) != (kind != .object)) return v;
    if (cp_idx >= cps.items.len) return v;
    const cp = cps.items[cp_idx];
    var vc: root.Verified = undefined;
    v.status = c.verifyCertified(cp.summary, &vc);
    if (v.status != .ok) return v;
    v.checkpoint = vc;
    v.status = switch (kind) {
        .tx => c.verifyTransaction(&vc.digest, cp.contents, effects, data, events, &v.tx),
        .tx_envelope => blk: {
            const td = if (data) |env| (transactionDataOf(env) orelse return .{ .status = .decode }) else null;
            break :blk c.verifyTransaction(&vc.digest, cp.contents, effects, td, events, &v.tx);
        },
        .object => c.verifyObject(&vc.digest, cp.contents, effects, data orelse return .{ .status = .decode }, &v.tx, &v.obj),
    };
    return v;
}

// ---------------------------------------------------------------------------------------------
// tests: a synthetic committee signs a checkpoint whose single transaction wrote one object

const testing = std.testing;
const hash = @import("hash");
const bls = root.bls;

fn putU64(l: *std.ArrayList(u8), a: std.mem.Allocator, v: u64) !void {
    try l.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u64, v)));
}

fn putBytes(l: *std.ArrayList(u8), a: std.mem.Allocator, b: []const u8) !void {
    var n = b.len;
    while (n >= 0x80) : (n >>= 7) try l.append(a, @as(u8, @truncate(n)) | 0x80);
    try l.append(a, @intCast(n));
    try l.appendSlice(a, b);
}

const Fixture = struct {
    certified: []const u8,
    contents: []const u8,
    effects: []const u8,
    object: []const u8,
    tx_data: []const u8,
    tx_envelope: []const u8,
    proof: []const u8,
    members: [4]root.Member,
};

fn fixture(a: std.mem.Allocator, flip_object: bool, as_tx: bool) !Fixture {
    var sks: [4]bls.sig.SecretKey = undefined;
    var f: Fixture = undefined;
    for (&sks, &f.members, 0..) |*sk, *m, i| {
        var b: [32]u8 = @splat(0);
        b[31] = @intCast(i + 1);
        b[0] = 0x11;
        sk.* = bls.sig.SecretKey.fromBytes(&b).?;
        m.* = .{ .name = sk.publicKey().toBytes(), .stake = 2500 };
    }
    // the transaction: an empty programmable transaction, in its envelope
    var td: std.ArrayList(u8) = .empty;
    try td.appendSlice(a, &.{ 0, 0, 0, 0 }); // V1, ProgrammableTransaction, no inputs, no commands
    try td.appendNTimes(a, 0x77, 32); // sender
    try td.append(a, 0); // gas payment
    try td.appendNTimes(a, 0x77, 32); // gas owner
    try putU64(&td, a, 1000);
    try putU64(&td, a, 5000);
    try td.append(a, 0); // expiration None
    const tdigest = hash.blake2b256(&.{ "TransactionData::", td.items });
    var env: std.ArrayList(u8) = .empty;
    try env.append(a, 1);
    try env.appendSlice(a, &.{ 0, 0, 0 }); // intent
    try env.appendSlice(a, td.items);
    try env.append(a, 0); // no signatures
    f.tx_data = td.items;
    f.tx_envelope = env.items;
    // the object: a Move GasCoin, owner Immutable
    var o: std.ArrayList(u8) = .empty;
    try o.appendSlice(a, &.{ 0, 1, 1 }); // Data::Move, MoveObjectType::GasCoin, has_public_transfer
    try putU64(&o, a, 9); // version
    try o.append(a, 40); // contents: id ++ balance
    try o.appendNTimes(a, 0xab, 32);
    try putU64(&o, a, 1000);
    try o.append(a, 3); // Owner::Immutable
    try putBytes(&o, a, &tdigest); // previous_transaction
    try putU64(&o, a, 0);
    const odigest = hash.blake2b256(&.{ "Object::", o.items });
    // effects V2 with that object created at lamport version 9
    var e: std.ArrayList(u8) = .empty;
    try e.append(a, 1); // V2
    try e.append(a, 0); // ExecutionStatus::Success
    try putU64(&e, a, 5);
    try e.appendNTimes(a, 0, 32); // gas used
    try putBytes(&e, a, &tdigest); // transaction digest
    try e.append(a, 0); // gas_object_index None
    try e.append(a, 0); // events_digest None
    try e.append(a, 0); // dependencies
    try putU64(&e, a, 9); // lamport version
    try e.append(a, 1); // one changed object
    try e.appendNTimes(a, 0xab, 32);
    try e.append(a, 0); // input NotExist
    try e.append(a, 1); // output ObjectWrite
    try putBytes(&e, a, &odigest);
    try e.append(a, 3); // Owner::Immutable
    try e.append(a, 1); // IDOperation::Created
    try e.append(a, 0); // unchanged_consensus_objects
    try e.append(a, 0); // aux_data_digest
    // contents V1 with that one execution digest pair
    var ct: std.ArrayList(u8) = .empty;
    try ct.appendSlice(a, &.{ 0, 1 });
    try putBytes(&ct, a, &tdigest);
    try putBytes(&ct, a, &hash.blake2b256(&.{ "TransactionEffects::", e.items }));
    try ct.append(a, 0); // user signatures: none (V1 has a vector per tx)
    // summary
    var s: std.ArrayList(u8) = .empty;
    try putU64(&s, a, 5);
    try putU64(&s, a, 100);
    try s.appendNTimes(a, 0, 8);
    try putBytes(&s, a, &hash.blake2b256(&.{ "CheckpointContents::", ct.items }));
    try s.append(a, 0);
    try s.appendNTimes(a, 0, 40);
    try s.appendSlice(a, &.{ 0, 0, 0 });
    // certificate: members 0..2 (7500 of 10000)
    var c = try Client.init(a);
    defer c.deinit();
    _ = c.trustCommittee(5, &f.members);
    const com = c.committeeMembers(5).?;
    var msg: std.ArrayList(u8) = .empty;
    try msg.appendSlice(a, &.{ 2, 0, 0 });
    try msg.appendSlice(a, s.items);
    try putU64(&msg, a, 5);
    var sigs: [3]bls.sig.Signature = undefined;
    for (0..3) |i| for (sks) |sk| if (std.mem.eql(u8, &sk.publicKey().toBytes(), &com[i].name)) {
        sigs[i] = sk.sign(msg.items);
    };
    const agg = bls.sig.aggregate(&sigs).?.toBytes();
    const bitmap = [_]u8{ 0x3a, 0x30, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 16, 0, 0, 0, 0, 0, 1, 0, 2, 0 };
    var cert: std.ArrayList(u8) = .empty;
    try cert.appendSlice(a, s.items);
    try putU64(&cert, a, 5);
    try cert.appendSlice(a, &agg);
    try putBytes(&cert, a, &bitmap);
    // the Proof: one checkpoint, one object item
    var p: std.ArrayList(u8) = .empty;
    try p.append(a, 1);
    try putBytes(&p, a, cert.items);
    try putBytes(&p, a, ct.items);
    try p.append(a, 2); // two items: an object (or a transaction), a not-provable one
    try p.append(a, if (as_tx) 1 else 2); // ItemProof::Tx or ItemProof::Object
    try p.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u32, 0)));
    try putBytes(&p, a, e.items);
    try p.append(a, 0); // ItemProof::None
    const obj = try a.dupe(u8, o.items);
    if (flip_object) obj[obj.len - 1] ^= 1; // storage rebate: the digest no longer matches
    f.certified = cert.items;
    f.contents = ct.items;
    f.effects = e.items;
    f.object = obj;
    f.proof = p.items;
    return f;
}

test "native proof: an object is proven from a committee alone; tampering is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f = try fixture(a, false, false);
    try testing.expectEqual(@as(?usize, 2), itemCount(f.proof));

    var c = try Client.init(testing.allocator);
    defer c.deinit();
    // no trusted committee yet
    try testing.expectEqual(Status.unknown_epoch, verifyItem(&c, f.proof, 0, .object, f.object, null).status);
    try testing.expectEqual(Status.ok, c.trustCommittee(5, &f.members));
    const v = verifyItem(&c, f.proof, 0, .object, f.object, null);
    try testing.expectEqual(Status.ok, v.status);
    try testing.expectEqual(@as(u64, 100), v.checkpoint.seq);
    try testing.expectEqual(@as(u64, 9), v.obj.version);
    try testing.expectEqual(@as(u8, 0xab), v.obj.id[0]);
    try testing.expectEqual(@as(u32, 0), v.tx.index);
    // an item that is not provable
    try testing.expectEqual(Status.not_found, verifyItem(&c, f.proof, 1, .object, f.object, null).status);
    // an index past the items, and a kind that does not match the item
    try testing.expectEqual(Status.decode, verifyItem(&c, f.proof, 2, .object, f.object, null).status);
    try testing.expectEqual(Status.decode, verifyItem(&c, f.proof, 0, .tx, null, null).status);
    // an object whose bytes the effects do not commit to
    const bad = try fixture(a, true, false);
    try testing.expectEqual(Status.digest_mismatch, verifyItem(&c, bad.proof, 0, .object, bad.object, null).status);
    // a flipped byte in the effects inside the proof breaks the contents' effects digest
    const tampered = try a.dupe(u8, f.proof);
    tampered[tampered.len - 20] ^= 1;
    try testing.expect(verifyItem(&c, tampered, 0, .object, f.object, null).status != .ok);
    // a flipped byte in the summary breaks the certificate
    const t2 = try a.dupe(u8, f.proof);
    t2[10] ^= 1;
    try testing.expect(verifyItem(&c, t2, 0, .object, f.object, null).status != .ok);
    // proofs cut inside item 0 never pass (the last byte belongs to item 1, which item 0 never reads)
    for (0..f.proof.len - 1) |n| try testing.expect(verifyItem(&c, f.proof[0..n], 0, .object, f.object, null).status != .ok);
}

test "native proof: the same effects prove the transaction" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f = try fixture(a, false, true);
    var c = try Client.init(testing.allocator);
    defer c.deinit();
    _ = c.trustCommittee(5, &f.members);
    const p = f.proof;
    const v = verifyItem(&c, p, 0, .tx, null, null);
    try testing.expectEqual(Status.ok, v.status);
    try testing.expect(v.tx.tx_digest[0] != 0);
    // with the data: TransactionData, or the envelope it came in
    const v2 = verifyItem(&c, p, 0, .tx, f.tx_data, null);
    try testing.expectEqual(Status.ok, v2.status);
    try testing.expect(v2.tx.data_verified);
    const v3 = verifyItem(&c, p, 0, .tx_envelope, f.tx_envelope, null);
    try testing.expectEqual(Status.ok, v3.status);
    try testing.expect(v3.tx.data_verified);
    // other data does not hash to the contents' transaction digest
    var other = try a.dupe(u8, f.tx_envelope);
    other[10] ^= 1;
    try testing.expect(verifyItem(&c, p, 0, .tx_envelope, other, null).status != .ok);
    try testing.expectEqual(Status.decode, verifyItem(&c, p, 0, .tx_envelope, &.{ 1, 2 }, null).status);
}
