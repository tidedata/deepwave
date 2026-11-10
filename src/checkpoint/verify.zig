//! Checkpoint verification: what a full node checks before it trusts a checkpoint and its
//! contents, in the order Mysten's code checks it (proven against sui-types by the
//! `checkpoint-verify` suite):
//!
//!   1. chain step (`sui_storage::verify_checkpoint_with_committee`): sequence number, previous
//!      digest, epoch step only after an end-of-epoch checkpoint;
//!   2. certificate (`CertifiedCheckpointSummary::verify_authority_signatures`): epochs, the
//!      aggregate signature decodes, signer indices and stakes, quorum, the BLS pairing check;
//!   3. contents digest against the summary (`verify_with_contents`);
//!   4. contents against the transactions: count, then per transaction the transaction digest,
//!      the effects' transaction digest, the effects digest and the events digest.
//!
//! Nothing here allocates except a certificate whose signed message exceeds `msg_stack`
//! (never seen on mainnet).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const bls = @import("bls");
const committee_mod = @import("committee.zig");
const sm = @import("summary.zig");
const Committee = committee_mod.Committee;

pub const What = enum { contents, tx_count, transaction, effects_tx, effects, events, output_object, missing_output };

pub const Verdict = union(enum) {
    ok,
    /// The blob does not decode as `CheckpointData` (reported by `verifyBlob`).
    decode,
    bad_signature,
    insufficient_stake,
    bad_bitmap,
    epoch_mismatch,
    digest_mismatch: struct { what: What, index: u32 },
    chain_break,

    pub fn isOk(v: Verdict) bool {
        return v == .ok;
    }
};

/// The previous checkpoint as the chain step needs it.
pub const Prev = struct {
    digest: [32]u8,
    sequence_number: u64,
    epoch: u64,
    end_of_epoch: bool,
};

/// A certified summary as two borrowed BCS values (a validated blob's `idx.summary` and `idx.sig`).
pub const CertifiedSummaryView = struct {
    summary: []const u8,
    sig: []const u8,
};

const decode = @import("decode.zig");

const msg_stack = 48 << 10;
const intent_checkpoint_summary = [3]u8{ 2, 0, 0 };

/// The certificate check on parsed values. `msg_buf` receives the signed message
/// (Intent ++ summary ++ epoch LE) and must hold `summary.len + 11` bytes.
fn certify(c: *const Committee, s: *const sm.Summary, si: *const sm.SigInfo, sig: bls.sig.Signature, msg_buf: []u8) Verdict {
    if (s.epoch != si.epoch) return .epoch_mismatch;
    if (si.epoch != c.epoch) return .epoch_mismatch;
    var sg: sm.Signers = undefined;
    sm.signers(si.bitmap, &sg) catch return .bad_bitmap;
    var weight: u64 = 0;
    for (sg.slice()) |idx| {
        const stake = c.stakeByIndex(idx) orelse return .bad_bitmap;
        if (stake == 0) return .bad_bitmap;
        // Rust's `weight += voting_rights` wraps in the release build; a committee whose stakes
        // wrap to 10,000 can wrap here too (suite cases synth/cert-wrap*)
        weight +%= stake;
    }
    if (weight < c.quorum_threshold) return .insufficient_stake;
    const pk = switch (c.prepared.aggregateKey(sg.slice())) {
        .ok => |a| a,
        .unknown_signer => return .bad_bitmap,
        .empty => return .bad_signature,
    };
    msg_buf[0..3].* = intent_checkpoint_summary;
    @memcpy(msg_buf[3..][0..s.bytes.len], s.bytes);
    std.mem.writeInt(u64, msg_buf[3 + s.bytes.len ..][0..8], si.epoch, .little);
    const msg = msg_buf[0 .. s.bytes.len + 11];
    return if (bls.sig.coreVerify(pk, msg, sig.point, c.prepared.g2_lines)) .ok else .bad_signature;
}

fn certifyAlloc(c: *const Committee, s: *const sm.Summary, si: *const sm.SigInfo, sig: bls.sig.Signature) Verdict {
    var stack: [msg_stack]u8 = undefined;
    if (s.bytes.len + 11 <= stack.len) return certify(c, s, si, sig, &stack);
    const heap = std.heap.page_allocator.alloc(u8, s.bytes.len + 11) catch return .bad_signature;
    defer std.heap.page_allocator.free(heap);
    return certify(c, s, si, sig, heap);
}

/// `verify_authority_signatures` on a certified summary. Inputs must be validated BCS.
pub fn verifyCertifiedSummary(c: *const Committee, cert: CertifiedSummaryView) Verdict {
    const s = sm.Summary.parse(cert.summary) catch return .decode;
    const si = sm.SigInfo.parse(cert.sig) catch return .decode;
    // the aggregate signature is a curve point: Rust's decode of the certificate checks it
    const sig = bls.sig.Signature.decode(si.signature) orelse return .decode;
    return certifyAlloc(c, &s, &si, sig);
}

/// The digest of a summary: Blake2b256("CheckpointSummary::" ++ BCS).
pub fn summaryDigest(summary_bytes: []const u8) [32]u8 {
    return hash.blake2b256(&.{ "CheckpointSummary::", summary_bytes });
}

fn chainStep(s: *const sm.Summary, p: *const Prev) bool {
    if (p.sequence_number == std.math.maxInt(u64) or s.sequence_number != p.sequence_number + 1) return false;
    const pd = s.previous_digest orelse return false;
    if (!std.mem.eql(u8, pd, &p.digest)) return false;
    const next_epoch = p.epoch +% 1;
    if (s.epoch != p.epoch and s.epoch != next_epoch) return false;
    if (s.epoch == next_epoch and !p.end_of_epoch) return false;
    return true;
}

fn mismatch(what: What, i: usize) Verdict {
    return .{ .digest_mismatch = .{ .what = what, .index = @intCast(@min(i, std.math.maxInt(u32))) } };
}

/// Verifies one indexed blob (`types.indexCheckpointData` succeeded on it): chain step when
/// `prev` is given, certificate under `c`, contents and every transaction digest.
pub fn verifyCheckpointData(c: *const Committee, blob: []const u8, idx: *const types.CheckpointIndex, prev: ?*const Prev) Verdict {
    const s = sm.Summary.parse(idx.summary.slice(blob)) catch return .decode;
    const si = sm.SigInfo.parse(idx.sig.slice(blob)) catch return .decode;
    if (!decode.check(blob, idx)) return .decode;
    // the blob decode (Rust: CheckpointData::deserialize) checks the signature is a curve point
    const sig = bls.sig.Signature.decode(si.signature) orelse return .decode;
    if (prev) |p| if (!chainStep(&s, p)) return .chain_break;
    const cv = certifyAlloc(c, &s, &si, sig);
    if (cv != .ok) return cv;

    const contents = idx.contents.slice(blob);
    const cd = hash.blake2b256(&.{ "CheckpointContents::", contents });
    if (!std.mem.eql(u8, &cd, s.content_digest)) return mismatch(.contents, 0);
    return verifyTransactions(blob, idx, contents);
}

const EffectsView = bcs.View(types.TransactionEffects);

/// Step 4: contents against the transactions. The user signatures pinned in the contents are not
/// compared with the transactions' own (see the truth tool: mainnet's first epochs pin none for
/// system transactions that carry a zero signature, and no Mysten path compares them).
fn verifyTransactions(blob: []const u8, idx: *const types.CheckpointIndex, contents: []const u8) Verdict {
    var r = bcs.Reader.init(contents);
    const variant = r.uleb32() catch return .decode;
    const ntx = r.length() catch return .decode;
    if (ntx != idx.tx_count) return mismatch(.tx_count, idx.tx_count);
    if (variant > 1) return .decode;
    const per = 66; // ExecutionDigests: two 33-byte digests
    for (0..ntx) |i| {
        const tx = idx.txAt(i);
        // V1 lists all digests first (signatures follow the last one); V2 interleaves each
        // transaction's digests with its signature list.
        const dg = r.bytes(per) catch return .decode;
        if (variant == 1) skipV2Sigs(&r) catch return .decode;

        const data = tx.data.slice(blob);
        const tdig = hash.blake2b256(&.{ "TransactionData::", data });
        if (!std.mem.eql(u8, &tdig, dg[1..33])) return mismatch(.transaction, i);

        const eff = tx.effects.slice(blob);
        const ev = EffectsView{ .bytes = eff };
        const is_v1 = ev.tag() == 0;
        const eff_tx_digest: []const u8 = if (is_v1)
            ev.payload("V1").?.field("transaction_digest").bytes
        else
            ev.payload("V2").?.field("transaction_digest").bytes;
        if (!std.mem.eql(u8, eff_tx_digest[1..33], &tdig)) return mismatch(.effects_tx, i);
        const edig = hash.blake2b256(&.{ "TransactionEffects::", eff });
        if (!std.mem.eql(u8, &edig, dg[34..66])) return mismatch(.effects, i);

        const want_events = if (is_v1)
            ev.payload("V1").?.field("events_digest").some()
        else
            ev.payload("V2").?.field("events_digest").some();
        if (tx.events) |er| {
            const edg = hash.blake2b256(&.{ "TransactionEvents::", er.slice(blob) });
            const w = want_events orelse return mismatch(.events, i);
            if (!std.mem.eql(u8, w.bytes[1..33], &edg)) return mismatch(.events, i);
        } else if (want_events != null) return mismatch(.events, i);
    }
    return .ok;
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

/// The decode checks the index does not do yet (decode.zig): true when the blob would decode.
pub fn decodeChecks(blob: []const u8, idx: *const types.CheckpointIndex) bool {
    return decode.check(blob, idx);
}

/// Decode (index) then verify. `Verdict.decode` when the blob is not a valid `CheckpointData`.
pub fn verifyBlob(c: *const Committee, blob: []const u8, idx: *types.CheckpointIndex, prev: ?*const Prev) Verdict {
    types.indexCheckpointData(blob, idx) catch return .decode;
    return verifyCheckpointData(c, blob, idx, prev);
}

// ---------------------------------------------------------------------------------------------
// tests: a synthetic committee, signed certificates and every certificate verdict

const testing = std.testing;

/// A minimal valid BCS CheckpointSummary: epoch, sequence, no previous digest, no commitments,
/// no end-of-epoch data, no version-specific data.
fn testSummary(a: std.mem.Allocator, epoch: u64, seq: u64) ![]u8 {
    var w: std.ArrayList(u8) = .empty;
    try w.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u64, epoch)));
    try w.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u64, seq)));
    try w.appendNTimes(a, 0, 8); // network_total_transactions
    try w.append(a, 32);
    try w.appendNTimes(a, 7, 32); // content_digest
    try w.append(a, 0); // previous_digest: None
    try w.appendNTimes(a, 0, 32 + 8); // gas summary + timestamp
    try w.append(a, 0); // checkpoint_commitments: empty
    try w.append(a, 0); // end_of_epoch_data: None
    try w.append(a, 0); // version_specific_data: empty
    return w.items;
}

/// AuthorityStrongQuorumSignInfo bytes for the given signers (all below 65536).
fn testSigInfo(a: std.mem.Allocator, epoch: u64, sig: [48]u8, ids: []const u16) ![]u8 {
    var w: std.ArrayList(u8) = .empty;
    try w.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u64, epoch)));
    try w.appendSlice(a, &sig);
    var bm: std.ArrayList(u8) = .empty;
    if (ids.len > 0) {
        try bm.appendSlice(a, &.{ 0x3a, 0x30, 0, 0, 1, 0, 0, 0, 0, 0 });
        try bm.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u16, @intCast(ids.len - 1))));
        try bm.appendSlice(a, &.{ 16, 0, 0, 0 });
        for (ids) |i| try bm.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u16, i)));
    } else {
        try bm.appendSlice(a, &.{ 0x3a, 0x30, 0, 0, 0, 0, 0, 0 });
    }
    try w.append(a, @intCast(bm.items.len));
    try w.appendSlice(a, bm.items);
    return w.items;
}

fn testCommittee(a: std.mem.Allocator, stakes: []const u64, sks: []bls.sig.SecretKey) !Committee {
    var members = try a.alloc(committee_mod.Member, stakes.len);
    for (stakes, 0..) |st, i| {
        var b: [32]u8 = @splat(0);
        b[31] = @intCast(i + 1);
        b[0] = 0x11;
        sks[i] = bls.sig.SecretKey.fromBytes(&b).?;
        members[i] = .{ .name = sks[i].publicKey().toBytes(), .stake = st };
    }
    return Committee.init(a, 5, members);
}

test "certificate verdicts on a synthetic committee" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // 4 validators; Committee sorts by key, so map signer index -> secret key by key order
    var sks: [4]bls.sig.SecretKey = undefined;
    const c = try testCommittee(a, &.{ 3000, 3000, 2000, 2000 }, &sks);
    var order: [4]usize = undefined; // order[i] = secret key index of committee member i
    for (c.members, 0..) |m, i| {
        for (sks, 0..) |sk, k| if (std.mem.eql(u8, &sk.publicKey().toBytes(), &m.name)) {
            order[i] = k;
        };
    }
    const summary = try testSummary(a, 5, 100);
    var msg: std.ArrayList(u8) = .empty;
    try msg.appendSlice(a, &intent_checkpoint_summary);
    try msg.appendSlice(a, summary);
    try msg.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u64, 5)));

    // members 0, 1, 2 sign: stake of those three must reach 6667
    var sigs: [3]bls.sig.Signature = undefined;
    for (0..3) |i| sigs[i] = sks[order[i]].sign(msg.items);
    const agg = bls.sig.aggregate(&sigs).?.toBytes();
    const ids = [_]u16{ 0, 1, 2 };
    var stake: u64 = 0;
    for (ids) |i| stake += c.members[i].stake;
    try testing.expect(stake >= 6667);

    const good = try testSigInfo(a, 5, agg, &ids);
    try testing.expectEqual(Verdict.ok, verifyCertifiedSummary(&c, .{ .summary = summary, .sig = good }));
    // a different epoch inside the signature info, or in the committee
    try testing.expectEqual(Verdict.epoch_mismatch, verifyCertifiedSummary(&c, .{ .summary = summary, .sig = try testSigInfo(a, 6, agg, &ids) }));
    const other_epoch = try testSummary(a, 6, 100);
    try testing.expectEqual(Verdict.epoch_mismatch, verifyCertifiedSummary(&c, .{ .summary = other_epoch, .sig = good }));
    // a signer outside the committee, too little stake, no signers
    try testing.expectEqual(Verdict.bad_bitmap, verifyCertifiedSummary(&c, .{ .summary = summary, .sig = try testSigInfo(a, 5, agg, &.{ 0, 1, 2, 4 }) }));
    try testing.expectEqual(Verdict.insufficient_stake, verifyCertifiedSummary(&c, .{ .summary = summary, .sig = try testSigInfo(a, 5, agg, &.{ 0, 1 }) }));
    try testing.expectEqual(Verdict.insufficient_stake, verifyCertifiedSummary(&c, .{ .summary = summary, .sig = try testSigInfo(a, 5, agg, &.{}) }));
    // enough stake but the aggregate is for another signer set
    try testing.expectEqual(Verdict.bad_signature, verifyCertifiedSummary(&c, .{ .summary = summary, .sig = try testSigInfo(a, 5, agg, &.{ 0, 1, 3 }) }));
    // another message
    const moved = try testSummary(a, 5, 101);
    try testing.expectEqual(Verdict.bad_signature, verifyCertifiedSummary(&c, .{ .summary = moved, .sig = good }));
    // bytes that are not a curve point
    var junk: [48]u8 = @splat(0xff);
    try testing.expectEqual(Verdict.decode, verifyCertifiedSummary(&c, .{ .summary = summary, .sig = try testSigInfo(a, 5, junk, &ids) }));
    junk = @splat(0);
    junk[0] = 0xc0; // infinity: a valid encoding, never a valid certificate
    try testing.expectEqual(Verdict.bad_signature, verifyCertifiedSummary(&c, .{ .summary = summary, .sig = try testSigInfo(a, 5, junk, &ids) }));

    const s = try sm.Summary.parse(summary);
    try testing.expectEqual(@as(u64, 100), s.sequence_number);
    try testing.expect(s.previous_digest == null and s.next_committee == null);
    // the summary digest feeds the next checkpoint's previous_digest
    const d = summaryDigest(summary);
    var next = try testSummary(a, 5, 101);
    // splice previous_digest = Some(d): tag byte 1, length 32, digest
    const at = 8 + 8 + 8 + 33;
    var with_prev: std.ArrayList(u8) = .empty;
    try with_prev.appendSlice(a, next[0..at]);
    try with_prev.appendSlice(a, &.{ 1, 32 });
    try with_prev.appendSlice(a, &d);
    try with_prev.appendSlice(a, next[at + 1 ..]);
    next = with_prev.items;
    const sn = try sm.Summary.parse(next);
    try testing.expectEqualSlices(u8, &d, sn.previous_digest.?);
    const prev: Prev = .{ .digest = d, .sequence_number = 100, .epoch = 5, .end_of_epoch = false };
    try testing.expect(chainStep(&sn, &prev));
    try testing.expect(!chainStep(&sn, &.{ .digest = d, .sequence_number = 99, .epoch = 5, .end_of_epoch = false }));
    var wrong = d;
    wrong[0] ^= 1;
    try testing.expect(!chainStep(&sn, &.{ .digest = wrong, .sequence_number = 100, .epoch = 5, .end_of_epoch = false }));
    // an epoch step needs an end-of-epoch predecessor, and may only be one epoch
    try testing.expect(!chainStep(&sn, &.{ .digest = d, .sequence_number = 100, .epoch = 4, .end_of_epoch = false }));
    try testing.expect(chainStep(&sn, &.{ .digest = d, .sequence_number = 100, .epoch = 4, .end_of_epoch = true }));
    try testing.expect(!chainStep(&sn, &.{ .digest = d, .sequence_number = 100, .epoch = 3, .end_of_epoch = true }));
}
