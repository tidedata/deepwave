//! light: deepwave's verify-only light client, the core the WebAssembly build
//! (`zig build wasm-light`, src/light/wasm.zig) exports. Pure Zig, no I/O: every input is plain
//! bytes, so any transport works (public fullnode gRPC or gRPC-web, JSON-RPC BCS fields, an
//! archive, the native protocol's proof bundle).
//!
//! Trust starts from either a committee the caller trusts (the genesis committee, or any epoch's
//! committee) or a pinned end-of-epoch checkpoint digest. From there:
//!
//!   1. a certified checkpoint summary is checked against the committee of its epoch (signer
//!      bitmap, quorum stake, the BLS12-381 aggregate signature over Intent ++ summary ++ epoch);
//!      an end-of-epoch summary then yields the next epoch's committee, so walking the epochs'
//!      last checkpoints reaches the current committee;
//!   2. contents against the summary's content digest;
//!   3. a transaction's effects (and events) against the contents' execution digests;
//!   4. an object against the effects' changed objects (id, version, Blake2b("Object::" ++ BCS)).
//!
//! Verified summaries are remembered by digest (a ring of `ring_len`), so reads that anchor on
//! a checkpoint verified earlier cost hashes only. Aggregate public keys are cached per
//! (epoch, signer bitmap): consecutive checkpoints are usually signed by the same set.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const cp = @import("checkpoint");
pub const pb = @import("pb.zig");
pub const proof = @import("proof.zig");
pub const bls = @import("bls");

const Allocator = std.mem.Allocator;
const Summary = cp.summary.Summary;
const SigInfo = cp.summary.SigInfo;
const Committee = cp.Committee;
pub const Member = cp.Member;
const G2Affine = bls.G2Affine;

pub const Status = enum(u32) {
    ok = 0,
    decode = 1,
    bad_signature = 2,
    insufficient_stake = 3,
    bad_bitmap = 4,
    epoch_mismatch = 5,
    digest_mismatch = 6,
    chain_break = 7,
    /// No trusted committee for the summary's epoch: walk the epochs first.
    unknown_epoch = 8,
    /// The transaction is not in the contents, or the object not among the effects' outputs.
    not_found = 9,
    pin_mismatch = 10,
    not_end_of_epoch = 11,
    out_of_memory = 12,
    bad_committee = 13,
    /// The anchor digest names no summary this client verified (or it left the ring).
    unknown_checkpoint = 14,
};

/// What a verified summary leaves behind (also the record `verifySummary` returns).
pub const Verified = struct {
    digest: [32]u8,
    content_digest: [32]u8,
    seq: u64,
    epoch: u64,
    timestamp_ms: u64,
    network_total_transactions: u64,
    end_of_epoch: bool,
};

/// Where a digest mismatch was found.
pub const What = enum(u32) { none, contents, tx_count, transaction, effects_tx, effects, events, object };

pub const TxOut = struct {
    tx_digest: [32]u8 = @splat(0),
    effects_digest: [32]u8 = @splat(0),
    events_digest: ?[32]u8 = null,
    /// Position in the checkpoint's contents.
    index: u32 = 0,
    events_verified: bool = false,
    data_verified: bool = false,
};

pub const ObjOut = struct {
    id: [32]u8 = @splat(0),
    version: u64 = 0,
    digest: [32]u8 = @splat(0),
};

pub const ring_len = 1024;
const agg_len = 8;
const prepared_len = 3;

const EpochEntry = struct { epoch: u64, members: []Member };
const Prepared = struct { epoch: u64, arena: std.heap.ArenaAllocator, committee: Committee, used: u64 };
const AggEntry = struct { epoch: u64, bitmap: [32]u8, key: G2Affine, used: u64 };

pub const Client = struct {
    gpa: Allocator,
    /// Trusted committees, by epoch (raw members, sorted as Committee.init sorts them).
    epochs: std.ArrayList(EpochEntry) = .empty,
    /// Decoded committees (G2 keys, their sum, the generator's Miller lines): LRU of a few.
    prepared: [prepared_len]?Prepared = @splat(null),
    agg: [agg_len]?AggEntry = @splat(null),
    ring: []?Verified,
    ring_at: usize = 0,
    head: ?Verified = null,
    tick: u64 = 0,
    /// Off: every summary goes through the BLS check even when seen before (benchmarks).
    cache: bool = true,
    /// Off: the signers' aggregate public key is summed again for every certificate.
    cache_agg: bool = true,
    /// The last mismatch: where, and the transaction index.
    last_what: What = .none,
    last_index: u32 = 0,
    stats: struct { bls_checks: u64 = 0, agg_hits: u64 = 0, ring_hits: u64 = 0 } = .{},

    pub fn init(gpa: Allocator) error{OutOfMemory}!Client {
        const ring = try gpa.alloc(?Verified, ring_len);
        @memset(ring, null);
        return .{ .gpa = gpa, .ring = ring };
    }

    pub fn deinit(c: *Client) void {
        for (c.epochs.items) |e| c.gpa.free(e.members);
        c.epochs.deinit(c.gpa);
        for (&c.prepared) |*p| if (p.*) |*q| q.arena.deinit();
        c.gpa.free(c.ring);
    }

    // ------------------------------------------------------------------ committees

    pub fn knownEpoch(c: *const Client, epoch: u64) bool {
        for (c.epochs.items) |e| if (e.epoch == epoch) return true;
        return false;
    }

    /// The highest epoch with a trusted committee, or null before any trust is set.
    pub fn latestEpoch(c: *const Client) ?u64 {
        var best: ?u64 = null;
        for (c.epochs.items) |e| best = if (best) |b| @max(b, e.epoch) else e.epoch;
        return best;
    }

    /// Trusts `members` as the committee of `epoch` (Committee::new rules: total stake 10,000,
    /// every key a G2 point).
    pub fn trustCommittee(c: *Client, epoch: u64, members: []const Member) Status {
        if (c.knownEpoch(epoch)) return .ok;
        // validate (and warm the prepared cache) before keeping anything
        _ = c.prepare(epoch, members) catch |e| return switch (e) {
            error.OutOfMemory => .out_of_memory,
            else => .bad_committee,
        };
        return .ok;
    }

    /// Committee of `epoch`, decoding its keys if they are not cached.
    fn committeeFor(c: *Client, epoch: u64) ?*const Committee {
        c.tick += 1;
        for (&c.prepared) |*p| if (p.*) |*q| if (q.epoch == epoch) {
            q.used = c.tick;
            return &q.committee;
        };
        for (c.epochs.items) |e| if (e.epoch == epoch) {
            return c.prepare(epoch, e.members) catch null;
        };
        return null;
    }

    fn prepare(c: *Client, epoch: u64, members: []const Member) !*const Committee {
        var slot: usize = 0;
        var oldest: u64 = std.math.maxInt(u64);
        for (c.prepared, 0..) |p, i| {
            const u = if (p) |q| q.used else 0;
            if (u < oldest) {
                oldest = u;
                slot = i;
            }
        }
        var arena = std.heap.ArenaAllocator.init(c.gpa);
        errdefer arena.deinit();
        const com = try Committee.init(arena.allocator(), epoch, members);
        if (!c.knownEpoch(epoch)) {
            const owned = try c.gpa.dupe(Member, com.members);
            errdefer c.gpa.free(owned);
            try c.epochs.append(c.gpa, .{ .epoch = epoch, .members = owned });
        }
        if (c.prepared[slot]) |*old| old.arena.deinit();
        c.prepared[slot] = .{ .epoch = epoch, .arena = arena, .committee = com, .used = c.tick };
        return &c.prepared[slot].?.committee;
    }

    /// Committee members of a trusted epoch (sorted by key), for exporting a pin.
    pub fn committeeMembers(c: *const Client, epoch: u64) ?[]const Member {
        for (c.epochs.items) |e| if (e.epoch == epoch) return e.members;
        return null;
    }

    fn adoptNext(c: *Client, s: *const Summary) Status {
        const eoe = s.next_committee orelse return .ok;
        if (c.knownEpoch(s.epoch + 1)) return .ok;
        const rights = c.gpa.alloc(Member, eoe.count) catch return .out_of_memory;
        defer c.gpa.free(rights);
        for (rights, 0..) |*m, i| m.* = .{ .name = eoe.key(i).*, .stake = eoe.stake(i) };
        return c.trustCommittee(s.epoch + 1, rights);
    }

    // ------------------------------------------------------------------ summaries

    /// Trusts an end-of-epoch checkpoint by digest (a pin): its next committee becomes trusted.
    pub fn trustPinned(c: *Client, summary_bytes: []const u8, pin: *const [32]u8) Status {
        const d = summaryDigest(summary_bytes);
        if (!std.mem.eql(u8, &d, pin)) return .pin_mismatch;
        _ = bcs.View(types.CheckpointSummary).init(summary_bytes) catch return .decode;
        const s = Summary.parse(summary_bytes) catch return .decode;
        if (s.next_committee == null) return .not_end_of_epoch;
        const st = c.adoptNext(&s);
        if (st != .ok) return st;
        c.remember(record(&s, d));
        return .ok;
    }

    /// `trustPinned` from a BCS `CertifiedCheckpointSummary` (what `get_epoch_proof` and the
    /// native protocol's checkpoints carry): the pin names the summary part.
    pub fn trustPinnedCertified(c: *Client, certified: []const u8, pin: *const [32]u8) Status {
        var r = bcs.Reader.init(certified);
        bcs.skip(types.CheckpointSummary, &r) catch return .decode;
        return c.trustPinned(certified[0..r.at], pin);
    }

    /// Verifies a certified summary: `sig` is BCS `AuthorityStrongQuorumSignInfo`.
    pub fn verifySummary(c: *Client, summary_bytes: []const u8, sig: []const u8, out: *Verified) Status {
        const si = SigInfo.parse(sig) catch return .decode;
        return c.verifySummaryParts(summary_bytes, si.epoch, si.signature, si.bitmap, out);
    }

    /// Verifies a BCS `CertifiedCheckpointSummary` (summary ++ AuthorityStrongQuorumSignInfo),
    /// the `ProofCheckpoint.summary` of the native protocol's verified mode.
    pub fn verifyCertified(c: *Client, certified: []const u8, out: *Verified) Status {
        var r = bcs.Reader.init(certified);
        bcs.skip(types.CheckpointSummary, &r) catch return .decode;
        const cut = r.at;
        return c.verifySummary(certified[0..cut], certified[cut..], out);
    }

    /// Verifies a certified summary from its signature parts (sui.rpc.v2
    /// `ValidatorAggregatedSignature`: epoch, 48-byte signature, roaring bitmap).
    pub fn verifySummaryParts(c: *Client, summary_bytes: []const u8, sig_epoch: u64, signature: []const u8, bitmap: []const u8, out: *Verified) Status {
        const d = summaryDigest(summary_bytes);
        if (c.cache) if (c.lookup(&d)) |v| {
            c.stats.ring_hits += 1;
            out.* = v;
            return .ok;
        };
        if (signature.len != 48) return .decode;
        _ = bcs.View(types.CheckpointSummary).init(summary_bytes) catch return .decode;
        const s = Summary.parse(summary_bytes) catch return .decode;
        const si: SigInfo = .{ .epoch = sig_epoch, .signature = signature[0..48], .bitmap = bitmap };
        const com = c.committeeFor(s.epoch) orelse return .unknown_epoch;
        const st = c.certify(com, &s, &si, bitmap);
        if (st != .ok) return st;
        const v = record(&s, d);
        // chain step against the head when this is its successor (a certified fork would
        // mean an equivocating quorum: refuse it rather than move on)
        if (c.head) |h| if (s.sequence_number == h.seq + 1) {
            const pd = s.previous_digest orelse return .chain_break;
            if (!std.mem.eql(u8, pd, &h.digest)) return .chain_break;
        };
        const nst = c.adoptNext(&s);
        if (nst != .ok) return nst;
        c.remember(v);
        out.* = v;
        return .ok;
    }

    fn certify(c: *Client, com: *const Committee, s: *const Summary, si: *const SigInfo, bitmap: []const u8) Status {
        if (s.epoch != si.epoch or si.epoch != com.epoch) return .epoch_mismatch;
        var sg: cp.summary.Signers = undefined;
        cp.summary.signers(si.bitmap, &sg) catch return .bad_bitmap;
        var weight: u64 = 0;
        for (sg.slice()) |idx| {
            const stake = com.stakeByIndex(idx) orelse return .bad_bitmap;
            if (stake == 0) return .bad_bitmap;
            weight +%= stake;
        }
        if (weight < com.quorum_threshold) return .insufficient_stake;
        const sig = bls.sig.Signature.decode(si.signature) orelse return .decode;
        const pk = c.aggKey(com, sg.slice(), bitmap) orelse return .bad_bitmap;

        const msg = c.gpa.alloc(u8, s.bytes.len + 11) catch return .out_of_memory;
        defer c.gpa.free(msg);
        msg[0..3].* = .{ 2, 0, 0 }; // Intent: CheckpointSummary, V0, Sui
        @memcpy(msg[3..][0..s.bytes.len], s.bytes);
        std.mem.writeInt(u64, msg[3 + s.bytes.len ..][0..8], si.epoch, .little);
        c.stats.bls_checks += 1;
        return if (bls.sig.coreVerify(pk, msg, sig.point, com.prepared.g2_lines)) .ok else .bad_signature;
    }

    fn aggKey(c: *Client, com: *const Committee, signers: []const u32, bitmap: []const u8) ?G2Affine {
        const bh = hash.blake2b256(&.{bitmap});
        c.tick += 1;
        if (c.cache_agg) for (&c.agg) |*e| if (e.*) |*a| if (a.epoch == com.epoch and std.mem.eql(u8, &a.bitmap, &bh)) {
            a.used = c.tick;
            c.stats.agg_hits += 1;
            return a.key;
        };
        const key = switch (com.prepared.aggregateKey(signers)) {
            .ok => |k| k,
            .unknown_signer, .empty => return null,
        };
        var slot: usize = 0;
        var oldest: u64 = std.math.maxInt(u64);
        for (c.agg, 0..) |e, i| {
            const u = if (e) |a| a.used else 0;
            if (u < oldest) {
                oldest = u;
                slot = i;
            }
        }
        c.agg[slot] = .{ .epoch = com.epoch, .bitmap = bh, .key = key, .used = c.tick };
        return key;
    }

    fn remember(c: *Client, v: Verified) void {
        if (c.lookup(&v.digest) == null) {
            c.ring[c.ring_at] = v;
            c.ring_at = (c.ring_at + 1) % ring_len;
        }
        if (c.head == null or v.seq > c.head.?.seq) c.head = v;
    }

    pub fn lookup(c: *const Client, digest: *const [32]u8) ?Verified {
        // newest first: reads usually anchor on recent checkpoints
        var k: usize = 0;
        while (k < ring_len) : (k += 1) {
            const i = (c.ring_at + ring_len - 1 - k) % ring_len;
            const v = c.ring[i] orelse return null;
            if (std.mem.eql(u8, &v.digest, digest)) return v;
        }
        return null;
    }

    // ------------------------------------------------------------------ contents, transactions, objects

    fn mismatch(c: *Client, what: What, i: usize) Status {
        c.last_what = what;
        c.last_index = @intCast(@min(i, std.math.maxInt(u32)));
        return .digest_mismatch;
    }

    /// Contents against a verified summary.
    pub fn verifyContents(c: *Client, anchor: *const [32]u8, contents: []const u8) Status {
        const v = c.lookup(anchor) orelse return .unknown_checkpoint;
        return c.contentsAgainst(&v, contents);
    }

    fn contentsAgainst(c: *Client, v: *const Verified, contents: []const u8) Status {
        const cd = hash.blake2b256(&.{ "CheckpointContents::", contents });
        if (!std.mem.eql(u8, &cd, &v.content_digest)) return c.mismatch(.contents, 0);
        return .ok;
    }

    /// One transaction of a verified checkpoint: `contents` (checked against the summary), its
    /// `effects`, optionally its `TransactionData` and its `TransactionEvents`. The contents
    /// entry is found by the effects' transaction digest.
    pub fn verifyTransaction(c: *Client, anchor: *const [32]u8, contents: []const u8, effects: []const u8, tx_data: ?[]const u8, events: ?[]const u8, out: *TxOut) Status {
        const v = c.lookup(anchor) orelse return .unknown_checkpoint;
        const st = c.contentsAgainst(&v, contents);
        if (st != .ok) return st;
        const ev = bcs.View(types.TransactionEffects).init(effects) catch return .decode;
        const fx = effectsFields(ev);
        out.* = .{};
        @memcpy(&out.tx_digest, fx.tx_digest);
        const entry = findEntry(contents, fx.tx_digest) catch return .decode;
        const e = entry orelse return .not_found;
        out.index = e.index;
        const edig = hash.blake2b256(&.{ "TransactionEffects::", effects });
        if (!std.mem.eql(u8, &edig, e.effects)) return c.mismatch(.effects, e.index);
        out.effects_digest = edig;
        if (fx.events_digest) |ed| out.events_digest = ed.*;
        if (tx_data) |data| {
            _ = bcs.View(types.TransactionData).init(data) catch return .decode;
            const tdig = hash.blake2b256(&.{ "TransactionData::", data });
            if (!std.mem.eql(u8, &tdig, e.tx)) return c.mismatch(.transaction, e.index);
            out.data_verified = true;
        }
        if (events) |evb| {
            const want = fx.events_digest orelse return c.mismatch(.events, e.index);
            const got = hash.blake2b256(&.{ "TransactionEvents::", evb });
            if (!std.mem.eql(u8, &got, want)) return c.mismatch(.events, e.index);
            _ = bcs.View(types.TransactionEvents).init(evb) catch return .decode;
            out.events_verified = true;
        }
        return .ok;
    }

    /// An object written by a verified transaction: `object` (BCS `Object`) must be one of the
    /// effects' changed objects (mutated, created, unwrapped) at its version and digest.
    pub fn verifyObject(c: *Client, anchor: *const [32]u8, contents: []const u8, effects: []const u8, object: []const u8, tx: *TxOut, out: *ObjOut) Status {
        const st = c.verifyTransaction(anchor, contents, effects, null, null, tx);
        if (st != .ok) return st;
        _ = bcs.View(types.Object).init(object) catch return .decode;
        const ref = objectRef(object) orelse return .decode;
        @memcpy(&out.id, ref[0..32]);
        out.version = std.mem.readInt(u64, ref[32..40], .little);
        @memcpy(&out.digest, ref[40..72]);
        const found = changedHas(effects, &ref) catch return .decode;
        if (!found) return c.mismatch(.object, tx.index);
        return .ok;
    }

    /// A whole sui.rpc.v2 `Checkpoint` (or `GetCheckpointResponse`) proto: the certified
    /// summary, then contents and every transaction it carries (data, effects, events).
    pub fn verifyCheckpointProto(c: *Client, proto_in: []const u8, out: *Verified) Status {
        const proto = pb.unwrapResponse(proto_in) catch return .decode;
        const n = pb.countTxs(proto) catch return .decode;
        const txs = c.gpa.alloc(pb.Tx, n) catch return .out_of_memory;
        defer c.gpa.free(txs);
        const p = pb.parseCheckpoint(proto, txs) catch return .decode;
        const summary = p.summary orelse return .decode;
        if (!p.has_sig) return .decode;
        const st = c.verifySummaryParts(summary, p.sig.epoch, p.sig.signature, p.sig.bitmap, out);
        if (st != .ok) return st;
        const contents = p.contents orelse return .ok; // summary only
        const cst = c.contentsAgainst(out, contents);
        if (cst != .ok) return cst;
        if (p.txs.len == 0) return .ok;
        return c.transactionsAgainst(contents, p.txs);
    }

    /// Every transaction of a checkpoint against its (already verified) contents, in order.
    fn transactionsAgainst(c: *Client, contents: []const u8, txs: []const pb.Tx) Status {
        var it = Entries.init(contents) catch return .decode;
        if (it.count != txs.len) return c.mismatch(.tx_count, txs.len);
        for (txs, 0..) |t, i| {
            const e = (it.next() catch return .decode) orelse return .decode;
            const data = t.data orelse return .decode;
            const effects = t.effects orelse return .decode;
            const tdig = hash.blake2b256(&.{ "TransactionData::", data });
            if (!std.mem.eql(u8, &tdig, e.tx)) return c.mismatch(.transaction, i);
            const ev = bcs.View(types.TransactionEffects).init(effects) catch return .decode;
            const fx = effectsFields(ev);
            if (!std.mem.eql(u8, fx.tx_digest, &tdig)) return c.mismatch(.effects_tx, i);
            const edig = hash.blake2b256(&.{ "TransactionEffects::", effects });
            if (!std.mem.eql(u8, &edig, e.effects)) return c.mismatch(.effects, i);
            if (t.has_events) {
                const evb = t.events orelse return .decode;
                const want = fx.events_digest orelse return c.mismatch(.events, i);
                const got = hash.blake2b256(&.{ "TransactionEvents::", evb });
                if (!std.mem.eql(u8, &got, want)) return c.mismatch(.events, i);
            } else if (fx.events_digest != null) return c.mismatch(.events, i);
        }
        return .ok;
    }
};

pub fn summaryDigest(summary_bytes: []const u8) [32]u8 {
    return hash.blake2b256(&.{ "CheckpointSummary::", summary_bytes });
}

fn record(s: *const Summary, d: [32]u8) Verified {
    return .{
        .digest = d,
        .content_digest = s.content_digest.*,
        .seq = s.sequence_number,
        .epoch = s.epoch,
        .timestamp_ms = s.timestamp_ms,
        .network_total_transactions = s.network_total_transactions,
        .end_of_epoch = s.next_committee != null,
    };
}

const EffectsView = bcs.View(types.TransactionEffects);

const EffectsFields = struct { tx_digest: *const [32]u8, events_digest: ?*const [32]u8 };

fn effectsFields(ev: EffectsView) EffectsFields {
    const is_v1 = ev.tag() == 0;
    const td: []const u8 = if (is_v1)
        ev.payload("V1").?.field("transaction_digest").bytes
    else
        ev.payload("V2").?.field("transaction_digest").bytes;
    const want = if (is_v1)
        ev.payload("V1").?.field("events_digest").some()
    else
        ev.payload("V2").?.field("events_digest").some();
    return .{
        .tx_digest = td[1..33],
        .events_digest = if (want) |w| w.bytes[1..33] else null,
    };
}

/// The execution digests of a `CheckpointContents` (V1 or V2), in order.
const Entries = struct {
    r: bcs.Reader,
    variant: u32,
    count: usize,
    at: usize = 0,

    const Entry = struct { index: u32, tx: *const [32]u8, effects: *const [32]u8 };

    fn init(contents: []const u8) bcs.Error!Entries {
        var r = bcs.Reader.init(contents);
        const variant = try r.uleb32();
        if (variant > 1) return error.InvalidEnumTag;
        const n = try r.length();
        return .{ .r = r, .variant = variant, .count = n };
    }

    fn next(e: *Entries) bcs.Error!?Entry {
        if (e.at == e.count) return null;
        const dg = try e.r.bytes(66);
        if (dg[0] != 32 or dg[33] != 32) return error.InvalidValue;
        if (e.variant == 1) try skipV2Sigs(&e.r);
        const i = e.at;
        e.at += 1;
        return .{ .index = @intCast(i), .tx = dg[1..33], .effects = dg[34..66] };
    }
};

fn findEntry(contents: []const u8, tx_digest: *const [32]u8) bcs.Error!?Entries.Entry {
    var it = try Entries.init(contents);
    while (try it.next()) |e| if (std.mem.eql(u8, e.tx, tx_digest)) return e;
    return null;
}

/// V2 only: skips `Vec<(GenericSignature, Option<SequenceNumber>)>`.
fn skipV2Sigs(r: *bcs.Reader) bcs.Error!void {
    const n = try r.length();
    for (0..n) |_| {
        const l = try r.length();
        _ = try r.bytes(l);
        switch (try r.int(u8)) {
            0 => {},
            1 => _ = try r.bytes(8),
            else => return error.InvalidEnumTag,
        }
    }
}

/// id (32) ++ version (u64 LE) ++ digest (32).
const Ref = [72]u8;

/// The reference of one `Object` (its validated BCS bytes): id, version, digest.
fn objectRef(obj: []const u8) ?Ref {
    var r = bcs.Reader.init(obj);
    var ref: Ref = undefined;
    const tag = r.uleb32() catch return null;
    switch (tag) {
        0 => {
            bcs.skip(types.MoveObjectType, &r) catch return null;
            _ = r.int(u8) catch return null; // has_public_transfer
            const version = r.int(u64) catch return null;
            const n = r.length() catch return null;
            const contents = r.bytes(n) catch return null;
            if (contents.len < 32) return null;
            @memcpy(ref[0..32], contents[0..32]);
            std.mem.writeInt(u64, ref[32..40], version, .little);
        },
        1 => {
            const id = r.bytes(32) catch return null;
            const version = r.int(u64) catch return null;
            @memcpy(ref[0..32], id);
            std.mem.writeInt(u64, ref[32..40], version, .little);
        },
        else => return null,
    }
    ref[40..72].* = hash.blake2b256(&.{ "Object::", obj });
    return ref;
}

const Owner = types.Owner;

/// True when `want` is one of the effects' changed objects (mutated, created, unwrapped), the
/// set sui-types' `all_changed_objects` returns (same walk as checkpoint/objects.zig).
fn changedHas(eff: []const u8, want: *const Ref) bcs.Error!bool {
    var r = bcs.Reader.init(eff);
    const variant = try r.uleb32();
    try bcs.skip(types.ExecutionStatus, &r);
    _ = try r.bytes(8 + 32); // executed_epoch, gas_used
    var ref: Ref = undefined;
    switch (variant) {
        0 => {
            try bcs.skip(@FieldType(types.TransactionEffectsV1, "modified_at_versions"), &r);
            try bcs.skip(@FieldType(types.TransactionEffectsV1, "shared_objects"), &r);
            try bcs.skip(types.TransactionDigest, &r);
            for (0..3) |_| { // created, mutated, unwrapped
                const n = try r.length();
                for (0..n) |_| {
                    @memcpy(ref[0..32], try r.bytes(32));
                    std.mem.writeInt(u64, ref[32..40], try r.int(u64), .little);
                    if ((try r.int(u8)) != 32) return error.InvalidValue;
                    @memcpy(ref[40..72], try r.bytes(32));
                    try bcs.skip(Owner, &r);
                    if (std.mem.eql(u8, &ref, want)) return true;
                }
            }
        },
        1 => {
            try bcs.skip(types.TransactionDigest, &r);
            try bcs.skip(@FieldType(types.TransactionEffectsV2, "gas_object_index"), &r);
            try bcs.skip(@FieldType(types.TransactionEffectsV2, "events_digest"), &r);
            try bcs.skip(@FieldType(types.TransactionEffectsV2, "dependencies"), &r);
            const lamport = try r.int(u64);
            const n = try r.length();
            for (0..n) |_| {
                @memcpy(ref[0..32], try r.bytes(32));
                const in_exist = switch (try r.uleb32()) {
                    0 => false,
                    1 => blk: {
                        try bcs.skip(@FieldType(@FieldType(types.ObjectIn, "Exist"), "0"), &r);
                        try bcs.skip(Owner, &r);
                        break :blk true;
                    },
                    else => return error.InvalidEnumTag,
                };
                const Kind = enum { none, object, package, other };
                var kind: Kind = .none;
                switch (try r.uleb32()) {
                    0 => {},
                    1 => {
                        if ((try r.int(u8)) != 32) return error.InvalidValue;
                        @memcpy(ref[40..72], try r.bytes(32));
                        try bcs.skip(Owner, &r);
                        std.mem.writeInt(u64, ref[32..40], lamport, .little);
                        kind = .object;
                    },
                    2 => {
                        std.mem.writeInt(u64, ref[32..40], try r.int(u64), .little);
                        if ((try r.int(u8)) != 32) return error.InvalidValue;
                        @memcpy(ref[40..72], try r.bytes(32));
                        kind = .package;
                    },
                    3 => {
                        try bcs.skip(types.AccumulatorWriteV1, &r);
                        kind = .other;
                    },
                    else => return error.InvalidEnumTag,
                }
                const op = try r.uleb32();
                if (op > 2) return error.InvalidEnumTag;
                const wrote = kind == .object or kind == .package;
                if (wrote and (in_exist or op == 1 or (op == 0 and kind == .object)) and std.mem.eql(u8, &ref, want)) return true;
            }
        },
        else => return error.InvalidEnumTag,
    }
    return false;
}

/// Splits a corpus/archive blob (`0x01 ++ BCS(CheckpointData)`, or the bare BCS) into its
/// certified summary and contents: byte ranges [start, end) into `blob`.
pub const ChkParts = struct { summary: [2]usize, sig: [2]usize, contents: [2]usize };

pub fn splitChk(blob: []const u8) bcs.Error!ChkParts {
    const off: usize = if (blob.len > 0 and blob[0] == 1) 1 else 0;
    var r = bcs.Reader.init(blob[off..]);
    var p: ChkParts = undefined;
    const s0 = r.at;
    try bcs.skip(types.CheckpointSummary, &r);
    p.summary = .{ off + s0, off + r.at };
    const g0 = r.at;
    try bcs.skip(types.AuthorityQuorumSignInfo, &r);
    p.sig = .{ off + g0, off + r.at };
    const c0 = r.at;
    try bcs.skip(types.CheckpointContents, &r);
    p.contents = .{ off + c0, off + r.at };
    return p;
}

// ---------------------------------------------------------------------------------------------
// tests (native): synthetic committee and certificates; the mainnet ones run in the Node test

const testing = std.testing;

test {
    _ = pb;
    _ = proof;
}

test "synthetic committee: verify, cache, epoch change, tamper" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var sks: [4]bls.sig.SecretKey = undefined;
    var ms: [4]Member = undefined;
    for (&sks, &ms, 0..) |*sk, *m, i| {
        var b: [32]u8 = @splat(0);
        b[31] = @intCast(i + 1);
        b[0] = 0x11;
        sk.* = bls.sig.SecretKey.fromBytes(&b).?;
        m.* = .{ .name = sk.publicKey().toBytes(), .stake = 2500 };
    }
    var c = try Client.init(testing.allocator);
    defer c.deinit();
    try testing.expectEqual(Status.ok, c.trustCommittee(5, &ms));
    const com = c.committeeFor(5).?;

    // a summary of epoch 5, seq 100, no previous digest, no end of epoch
    var w: std.ArrayList(u8) = .empty;
    try w.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u64, 5)));
    try w.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u64, 100)));
    try w.appendNTimes(a, 0, 8);
    try w.append(a, 32);
    try w.appendNTimes(a, 7, 32);
    try w.append(a, 0);
    try w.appendNTimes(a, 0, 40);
    try w.appendSlice(a, &.{ 0, 0, 0 });
    const summary = w.items;
    var msg: std.ArrayList(u8) = .empty;
    try msg.appendSlice(a, &.{ 2, 0, 0 });
    try msg.appendSlice(a, summary);
    try msg.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u64, 5)));
    // members 0..2 by committee order
    var sigs: [3]bls.sig.Signature = undefined;
    for (0..3) |i| {
        for (sks) |sk| if (std.mem.eql(u8, &sk.publicKey().toBytes(), &com.members[i].name)) {
            sigs[i] = sk.sign(msg.items);
        };
    }
    const agg = bls.sig.aggregate(&sigs).?.toBytes();
    const bitmap = [_]u8{ 0x3a, 0x30, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 16, 0, 0, 0, 0, 0, 1, 0, 2, 0 };
    var v: Verified = undefined;
    try testing.expectEqual(Status.ok, c.verifySummaryParts(summary, 5, &agg, &bitmap, &v));
    try testing.expectEqual(@as(u64, 100), v.seq);
    try testing.expectEqual(@as(u64, 1), c.stats.bls_checks);
    // seen again: the ring answers
    try testing.expectEqual(Status.ok, c.verifySummaryParts(summary, 5, &agg, &bitmap, &v));
    try testing.expectEqual(@as(u64, 1), c.stats.bls_checks);
    // without the cache the aggregate key is still reused
    c.cache = false;
    try testing.expectEqual(Status.ok, c.verifySummaryParts(summary, 5, &agg, &bitmap, &v));
    c.cache = true;
    // a tampered summary byte
    const bad = try a.dupe(u8, summary);
    bad[20] ^= 1;
    try testing.expectEqual(Status.bad_signature, c.verifySummaryParts(bad, 5, &agg, &bitmap, &v));
    // two signers: 5000 < 6667
    const two = [_]u8{ 0x3a, 0x30, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 1, 0 };
    try testing.expectEqual(Status.insufficient_stake, c.verifySummaryParts(bad, 5, &agg, &two, &v));
    // an unknown epoch
    const other = try a.dupe(u8, summary);
    other[0] = 6;
    try testing.expectEqual(Status.unknown_epoch, c.verifySummaryParts(other, 6, &agg, &bitmap, &v));
    // contents against the summary: digest 0x07.. is not the hash of anything here
    try testing.expectEqual(Status.digest_mismatch, c.verifyContents(&v.digest, &.{ 0, 0, 0 }));
    var unknown: [32]u8 = @splat(9);
    try testing.expectEqual(Status.unknown_checkpoint, c.verifyContents(&unknown, &.{ 0, 0 }));
}
