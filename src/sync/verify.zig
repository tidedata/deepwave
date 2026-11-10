//! Verification of one checkpoint blob (`0x01 ++ BCS(CheckpointData)`), in two parts that
//! the follower runs on different threads:
//!
//!  * `check`: everything that needs no committee. Contents digest against the summary,
//!    transaction/effects/events digests against the contents, and every output object's
//!    digest against the (certified) effects. The result is an `Applied` plan: the object
//!    writes and removals the store must record, derived from the effects the way
//!    sui-types does (`deleted`, `wrapped`, `unwrapped_then_deleted`).
//!  * `checkCert`: the BLS quorum certificate over the summary against a `Committee`.
//!
//! A checkpoint is only applied when both pass and the chain links (follower.zig).
const std = @import("std");
const bcs = @import("bcs");
const hash = @import("hash");
const types = @import("types");
const bls = @import("bls");
const Committee = @import("committee.zig").Committee;
const wire = @import("wire.zig");
const Reader = bcs.Reader;

pub const What = enum { contents, tx, effects, events, object, object_set, effects_shape, tx_count, sequence };

pub const Verdict = union(enum) {
    ok,
    decode,
    epoch_mismatch,
    bad_bitmap,
    insufficient_stake,
    bad_signature,
    digest_mismatch: What,
    chain_break,
    no_committee,

    pub fn isOk(v: Verdict) bool {
        return v == .ok;
    }
    pub fn name(v: Verdict) []const u8 {
        return switch (v) {
            .digest_mismatch => |w| @tagName(w),
            else => @tagName(v),
        };
    }
};

pub const Put = struct { index: u32, id: *const [32]u8, version: u64, digest: [32]u8 };
pub const Remove = struct { id: [32]u8, version: u64, kind: u8 };
pub const TxPlan = struct {
    tx_digest: *const [32]u8,
    effects_digest: [32]u8,
    puts: []const Put,
    removes: []const Remove,
};

/// What `check` learns about a checkpoint. Everything lives in the arena given to `check`.
pub const Checked = struct {
    seq: u64,
    epoch: u64,
    timestamp_ms: u64,
    network_total_transactions: u64,
    digest: [32]u8,
    previous: ?[32]u8,
    content_digest: [32]u8,
    end_of_epoch: ?types.EndOfEpochData,
    txs: []const TxPlan,
    puts: u32,
    removes: u32,
};

pub const CheckResult = union(enum) { ok: Checked, bad: Verdict };


inline fn bad(v: Verdict) CheckResult {
    return .{ .bad = v };
}

pub fn objectDigest(bytes: []const u8) [32]u8 {
    return hash.blake2b256(&.{ "Object::", bytes });
}

/// Everything except the certificate. `idx` must be the index of `blob`.
pub fn check(arena: std.mem.Allocator, blob: []const u8, idx: *const types.CheckpointIndex) std.mem.Allocator.Error!CheckResult {
    const summary_bytes = idx.summary.slice(blob);
    const summary = bcs.decode(types.CheckpointSummary, arena, summary_bytes) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else bad(.decode);
    // Mysten deserialises the aggregate signature (blst `Signature::from_bytes`) with the blob, so
    // an undecodable point is `decode` before any digest, epoch or signer check (sync-follow
    // edge/sig-not-a-point-and-epoch). AuthorityQuorumSignInfo = epoch u64 ++ 48 bytes ++ bitmap.
    const sig_bytes = idx.sig.slice(blob);
    if (sig_bytes.len < 56 or bls.Signature.decode(sig_bytes[8..56]) == null) return bad(.decode);
    const contents_bytes = idx.contents.slice(blob);
    const content_digest = hash.blake2b256(&.{ "CheckpointContents::", contents_bytes });
    if (!std.mem.eql(u8, &content_digest, &summary.content_digest.@"0".@"0")) return bad(.{ .digest_mismatch = .contents });
    const pairs = wire.contentsDigests(arena, contents_bytes) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return bad(.decode),
    };
    if (pairs.len != idx.tx_count) return bad(.{ .digest_mismatch = .tx_count });

    const txs = try arena.alloc(TxPlan, pairs.len);
    var n_put: u32 = 0;
    var n_rm: u32 = 0;
    for (pairs, txs, 0..) |pair, *plan, i| {
        const t = idx.txAt(i);
        const tx_digest = hash.blake2b256(&.{ "TransactionData::", t.data.slice(blob) });
        if (!std.mem.eql(u8, &tx_digest, pair.tx)) return bad(.{ .digest_mismatch = .tx });
        const eff_bytes = t.effects.slice(blob);
        const eff_digest = hash.blake2b256(&.{ "TransactionEffects::", eff_bytes });
        if (!std.mem.eql(u8, &eff_digest, pair.effects)) return bad(.{ .digest_mismatch = .effects });
        const eff = bcs.decode(types.TransactionEffects, arena, eff_bytes) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else bad(.decode);

        const events_digest: ?*const [32]u8 = switch (eff) {
            .V1 => |v| if (v.events_digest) |*d| &d.@"0".@"0" else null,
            .V2 => |v| if (v.events_digest) |*d| &d.@"0".@"0" else null,
        };
        if (t.events) |ev| {
            const d = hash.blake2b256(&.{ "TransactionEvents::", ev.slice(blob) });
            if (events_digest == null or !std.mem.eql(u8, &d, events_digest.?)) return bad(.{ .digest_mismatch = .events });
        } else if (events_digest != null) return bad(.{ .digest_mismatch = .events });

        // Output objects against the effects.
        const outs = idx.objs[t.out_first..][0..t.out_count];
        const puts = try arena.alloc(Put, outs.len);
        for (outs, puts, 0..) |r, *p, k| {
            const ob = r.slice(blob);
            const head = wire.objectHead(ob) catch return bad(.decode);
            p.* = .{ .index = @intCast(t.out_first + k), .id = head.id, .version = head.version, .digest = objectDigest(ob) };
        }
        var removes: std.ArrayList(Remove) = .empty;
        if (!try matchEffects(arena, &eff, puts, &removes)) return bad(.{ .digest_mismatch = .object });
        plan.* = .{ .tx_digest = pair.tx, .effects_digest = eff_digest, .puts = puts, .removes = removes.items };
        n_put += @intCast(puts.len);
        n_rm += @intCast(removes.items.len);
    }
    return .{ .ok = .{
        .seq = summary.sequence_number,
        .epoch = summary.epoch,
        .timestamp_ms = summary.timestamp_ms,
        .network_total_transactions = summary.network_total_transactions,
        .digest = hash.blake2b256(&.{ "CheckpointSummary::", summary_bytes }),
        .previous = if (summary.previous_digest) |p| p.@"0".@"0" else null,
        .content_digest = content_digest,
        .end_of_epoch = summary.end_of_epoch_data,
        .txs = txs,
        .puts = n_put,
        .removes = n_rm,
    } };
}

const Ref = struct { id: *const [32]u8, version: u64, digest: *const [32]u8 };

fn same(a: *const [32]u8, b: *const [32]u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Every object write the effects promise must be present among the output objects with the
/// promised digest, and every output object must be promised. Fills `removes` in sui-types
/// order: deleted, wrapped, unwrapped_then_deleted.
fn matchEffects(arena: std.mem.Allocator, eff: *const types.TransactionEffects, puts: []const Put, removes: *std.ArrayList(Remove)) std.mem.Allocator.Error!bool {
    var expected: usize = 0;
    switch (eff.*) {
        .V1 => |*v| {
            for (v.created) |*e| {
                if (!findPut(puts, &e.@"0"[0].@"0".@"0", e.@"0"[1].@"0", &e.@"0"[2].@"0".@"0")) return false;
                expected += 1;
            }
            for (v.mutated) |*e| {
                if (!findPut(puts, &e.@"0"[0].@"0".@"0", e.@"0"[1].@"0", &e.@"0"[2].@"0".@"0")) return false;
                expected += 1;
            }
            for (v.unwrapped) |*e| {
                if (!findPut(puts, &e.@"0"[0].@"0".@"0", e.@"0"[1].@"0", &e.@"0"[2].@"0".@"0")) return false;
                expected += 1;
            }
            for (v.deleted) |*e| try removes.append(arena, .{ .id = e.@"0".@"0".@"0", .version = e.@"1".@"0", .kind = 0 });
            for (v.wrapped) |*e| try removes.append(arena, .{ .id = e.@"0".@"0".@"0", .version = e.@"1".@"0", .kind = 1 });
            for (v.unwrapped_then_deleted) |*e| try removes.append(arena, .{ .id = e.@"0".@"0".@"0", .version = e.@"1".@"0", .kind = 2 });
        },
        .V2 => |*v| {
            const lamport = v.lamport_version.@"0";
            for (v.changed_objects) |*c| {
                const id = &c.@"0".@"0".@"0";
                switch (c.@"1".output_state) {
                    .ObjectWrite => |w| {
                        if (!findPutAtLamport(puts, id, lamport, &w[0].@"0".@"0")) return false;
                        expected += 1;
                    },
                    .PackageWrite => |w| {
                        if (!findPut(puts, id, w[0].@"0", &w[1].@"0".@"0")) return false;
                        expected += 1;
                    },
                    .AccumulatorWriteV1 => {},
                    .NotExist => {},
                }
            }
            for ([3]u8{ 0, 1, 2 }) |kind| {
                for (v.changed_objects) |*c| {
                    const in_exist = c.@"1".input_state == .Exist;
                    if (c.@"1".output_state != .NotExist) continue;
                    const op = c.@"1".id_operation;
                    const hit = switch (kind) {
                        0 => in_exist and op == .Deleted,
                        1 => in_exist and op == .None,
                        else => !in_exist and op == .Deleted,
                    };
                    if (hit) try removes.append(arena, .{ .id = c.@"0".@"0".@"0", .version = lamport, .kind = kind });
                }
            }
        },
    }
    return expected == puts.len;
}

fn findPut(puts: []const Put, id: *const [32]u8, version: u64, digest: *const [32]u8) bool {
    for (puts) |*p| {
        if (same(p.id, id)) return p.version == version and same(&p.digest, digest);
    }
    return false;
}

fn findPutAtLamport(puts: []const Put, id: *const [32]u8, lamport: u64, digest: *const [32]u8) bool {
    return findPut(puts, id, lamport, digest);
}

/// The BLS certificate of a summary against `committee`. `sig_bytes` is the BCS of the
/// AuthorityQuorumSignInfo, `summary_bytes` the BCS of the summary.
///
/// Out of memory is an error, never a verdict: a transient allocation failure must not read as a
/// bad checkpoint (the follower would stop on it, and a peer would be blamed for it).
pub fn checkCert(arena: std.mem.Allocator, committee: *const Committee, summary_epoch: u64, summary_bytes: []const u8, sig_bytes: []const u8) std.mem.Allocator.Error!Verdict {
    var r = Reader.init(sig_bytes);
    const epoch = r.int(u64) catch return .decode;
    const sig = (r.bytes(48) catch return .decode)[0..48];
    const blen = r.length() catch return .decode;
    const bitmap = r.bytes(blen) catch return .decode;
    if (epoch != committee.epoch or summary_epoch != committee.epoch) return .epoch_mismatch;
    var signers_buf: [160]u32 = undefined;
    const signers = wire.roaringMembers(bitmap, &signers_buf) catch return .bad_bitmap;
    const w = committee.weight(signers) orelse return .bad_bitmap;
    if (w < committee.quorum()) return .insufficient_stake;
    const msg = try arena.alloc(u8, 3 + summary_bytes.len + 8);
    msg[0..3].* = .{ 2, 0, 0 }; // Intent { scope: CheckpointSummary, version: V0, app_id: Sui }
    @memcpy(msg[3..][0..summary_bytes.len], summary_bytes);
    std.mem.writeInt(u64, msg[3 + summary_bytes.len ..][0..8], epoch, .little);
    return switch (committee.prepared.verifyAggregateVerdict(signers, msg, sig)) {
        .ok => .ok,
        // Mysten deserialises (and validates) the aggregate signature with the blob.
        .sig_decode => .decode,
        .unknown_signer => .bad_bitmap,
        .invalid => .bad_signature,
    };
}


/// The truth tool's vocabulary for a verdict (tools/truth/state-sync): decode, contents, tx_count,
/// tx, effects, events, objects, epoch, bitmap, stake, signature, chain, ok.
pub fn class(v: Verdict) []const u8 {
    return switch (v) {
        .ok => "ok",
        .decode => "decode",
        .epoch_mismatch => "epoch",
        .bad_bitmap => "bitmap",
        .insufficient_stake => "stake",
        .bad_signature => "signature",
        .chain_break => "chain",
        .no_committee => "no_committee",
        .digest_mismatch => |w| switch (w) {
            .contents => "contents",
            .tx_count => "tx_count",
            .tx => "tx",
            .effects => "effects",
            .events => "events",
            .object, .object_set, .effects_shape => "objects",
            .sequence => "sequence",
        },
    };
}

/// Index, check, certificate and chain link of one blob, in the order the truth tool uses.
/// `idx` is scratch. No store is touched.
pub fn full(arena: std.mem.Allocator, blob: []const u8, idx: *types.CheckpointIndex, committee: *const Committee, prev_digest: ?[32]u8) std.mem.Allocator.Error!Verdict {
    types.indexCheckpointData(blob, idx) catch return .decode;
    const r = try check(arena, blob, idx);
    const c = switch (r) {
        .ok => |c| c,
        .bad => |v| return v,
    };
    const cv = try checkCert(arena, committee, c.epoch, idx.summary.slice(blob), idx.sig.slice(blob));
    if (!cv.isOk()) return cv;
    if (prev_digest) |p| {
        if (c.previous == null or !std.mem.eql(u8, &c.previous.?, &p)) return .chain_break;
    }
    return .ok;
}

// ------------------------------------------------------------------------------------------------
// Batched certificate checks
//
// `checkCert` is the cheap per-item part (signature info decode, epoch rule, signer bitmap,
// stake, aggregate signature decode, the signers' aggregate key) followed by one pairing check.
// `prepCert` does the cheap part with the same verdicts in the same order and returns the pairing
// check as a `bls.sig.BatchItem`; `pairingVerdicts` decides many of them as randomized batches.
// The pair gives every certificate the verdict `checkCert` gives it.

pub const CertPrep = union(enum) {
    /// Decided without the pairing (the verdict `checkCert` returns).
    done: Verdict,
    /// Everything but the pairing check passed; `checkCert` is .ok iff
    /// `bls.sig.coreVerify(item.pk, item.msg, item.sig)` holds, else .bad_signature.
    pairing: bls.sig.BatchItem,
};

/// The part of `checkCert` before the pairing. `msg` lives in `arena`.
pub fn prepCert(arena: std.mem.Allocator, committee: *const Committee, summary_epoch: u64, summary_bytes: []const u8, sig_bytes: []const u8) std.mem.Allocator.Error!CertPrep {
    var r = Reader.init(sig_bytes);
    const epoch = r.int(u64) catch return .{ .done = .decode };
    const sig = (r.bytes(48) catch return .{ .done = .decode })[0..48];
    const blen = r.length() catch return .{ .done = .decode };
    const bitmap = r.bytes(blen) catch return .{ .done = .decode };
    if (epoch != committee.epoch or summary_epoch != committee.epoch) return .{ .done = .epoch_mismatch };
    var signers_buf: [160]u32 = undefined;
    const signers = wire.roaringMembers(bitmap, &signers_buf) catch return .{ .done = .bad_bitmap };
    const w = committee.weight(signers) orelse return .{ .done = .bad_bitmap };
    if (w < committee.quorum()) return .{ .done = .insufficient_stake };
    const msg = try arena.alloc(u8, 3 + summary_bytes.len + 8);
    msg[0..3].* = .{ 2, 0, 0 };
    @memcpy(msg[3..][0..summary_bytes.len], summary_bytes);
    std.mem.writeInt(u64, msg[3 + summary_bytes.len ..][0..8], epoch, .little);
    // PreparedCommittee.verifyAggregateVerdict up to its pairing, same order and verdicts
    const s = bls.Signature.decode(sig) orelse return .{ .done = .decode };
    const pk = switch (committee.prepared.aggregateKey(signers)) {
        .ok => |a| a,
        .unknown_signer => return .{ .done = .bad_bitmap },
        .empty => return .{ .done = .bad_signature },
    };
    return .{ .pairing = .{ .pk = pk, .msg = msg, .sig = s.point } };
}

/// Whether every non-infinite key of `committee` is in G2, so a certificate's aggregate key is
/// too and a batch may skip the per-item key group check (`keys_in_group`). Committee keys are
/// decoded without a subgroup check (as Mysten's Committee::new); costs one G2 check per member.
pub fn keysInG2(committee: *const Committee) bool {
    for (committee.prepared.keys) |k| {
        if (!k.isInfinity() and !bls.curve.g2AffineInGroup(k)) return false;
    }
    return true;
}

pub const PairingOpts = struct {
    /// Every item's key comes from a committee for which `keysInG2` holds. Then a failed item is
    /// .bad_signature directly; otherwise a failed item is decided again by `checkCert`'s own
    /// pairing (`fallback` must be given) so the verdict never depends on the batch path.
    keys_in_group: bool = false,
    /// null: core.pool.shared() (inline when none).
    pool: ?*@import("core").pool.Pool = null,
};

/// The pairing verdicts of `items` (each .ok or .bad_signature, as `checkCert` would give for the
/// certificate behind it), as randomized batches. `rng` must be a CSPRNG outside tests.
/// Without `keys_in_group`, `true` from the batch means verifyValidated held, which implies
/// coreVerify; a `false` is re-decided with `coreVerify` itself (rare: only bad certificates).
pub fn pairingVerdicts(gpa: std.mem.Allocator, items: []const bls.sig.BatchItem, rng: std.Random, opts: PairingOpts, out: []Verdict) void {
    std.debug.assert(out.len >= items.len);
    var stack: [64]bool = undefined;
    const ok: []bool = if (items.len <= stack.len) stack[0..items.len] else gpa.alloc(bool, items.len) catch {
        for (items, out[0..items.len]) |it, *o| o.* = if (bls.sig.coreVerify(it.pk, it.msg, it.sig, bls.sig.generatorLines())) .ok else .bad_signature;
        return;
    };
    defer if (items.len > stack.len) gpa.free(ok);
    bls.sig.verifyBatchValidated(gpa, items, null, rng, .{ .pool = opts.pool, .keys_in_group = opts.keys_in_group }, ok);
    for (items, ok, out[0..items.len]) |it, good, *o| {
        o.* = if (good) .ok else if (opts.keys_in_group) .bad_signature else if (bls.sig.coreVerify(it.pk, it.msg, it.sig, bls.sig.generatorLines())) .ok else .bad_signature;
    }
}

/// One certificate to check: the summary's epoch and bytes, the AuthorityQuorumSignInfo bytes.
pub const CertJob = struct {
    committee: *const Committee,
    summary_epoch: u64,
    summary: []const u8,
    sig: []const u8,
};

/// `checkCert` of every job, with the pairings batched. `arena` holds the signed messages.
pub fn checkCerts(gpa: std.mem.Allocator, arena: std.mem.Allocator, jobs: []const CertJob, rng: std.Random, opts: PairingOpts, out: []Verdict) std.mem.Allocator.Error!void {
    std.debug.assert(out.len >= jobs.len);
    const items = try gpa.alloc(bls.sig.BatchItem, jobs.len);
    defer gpa.free(items);
    const where = try gpa.alloc(u32, jobs.len);
    defer gpa.free(where);
    var m: usize = 0;
    for (jobs, out[0..jobs.len], 0..) |j, *o, i| {
        switch (try prepCert(arena, j.committee, j.summary_epoch, j.summary, j.sig)) {
            .done => |v| o.* = v,
            .pairing => |it| {
                items[m] = it;
                where[m] = @intCast(i);
                m += 1;
            },
        }
    }
    if (m == 0) return;
    const pv = try gpa.alloc(Verdict, m);
    defer gpa.free(pv);
    pairingVerdicts(gpa, items[0..m], rng, opts, pv);
    for (where[0..m], pv) |i, v| out[i] = v;
}

// ------------------------------------------------------------------------------------------------
// tests

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

fn testMsg(a: std.mem.Allocator, summary: []const u8, epoch: u64) ![]u8 {
    const m = try a.alloc(u8, 3 + summary.len + 8);
    m[0..3].* = .{ 2, 0, 0 };
    @memcpy(m[3..][0..summary.len], summary);
    std.mem.writeInt(u64, m[3 + summary.len ..][0..8], epoch, .little);
    return m;
}

test "batched certificate checks give checkCert's verdict for every certificate" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // 4 members, keys sorted; order[i] = the secret key of committee member i
    var sks: [4]bls.sig.SecretKey = undefined;
    var keys: [4][96]u8 = undefined;
    for (&sks, 0..) |*sk, i| {
        var b: [32]u8 = @splat(0);
        b[0] = 0x21;
        b[31] = @intCast(i + 1);
        sk.* = bls.sig.SecretKey.fromBytes(&b).?;
        keys[i] = sk.publicKey().toBytes();
    }
    var order = [4]usize{ 0, 1, 2, 3 };
    std.mem.sort(usize, &order, @as(*const [4][96]u8, &keys), struct {
        fn lt(k: *const [4][96]u8, x: usize, y: usize) bool {
            return std.mem.order(u8, &k[x], &k[y]) == .lt;
        }
    }.lt);
    var sorted: [4][96]u8 = undefined;
    for (order, &sorted) |o, *k| k.* = keys[o];
    const comm = try Committee.init(a, 7, &sorted, &.{ 3000, 3000, 2000, 2000 });
    try testing.expect(keysInG2(&comm));

    const S = struct {
        fn agg(al: std.mem.Allocator, s: []const bls.sig.SecretKey, ord: []const usize, ids: []const u16, msg: []const u8) ![48]u8 {
            const sigs = try al.alloc(bls.sig.Signature, ids.len);
            for (ids, sigs) |i, *sg| sg.* = s[ord[i]].sign(msg);
            return bls.sig.aggregate(sigs).?.toBytes();
        }
    };
    var jobs: std.ArrayList(CertJob) = .empty;
    var want: std.ArrayList(Verdict) = .empty;
    for (0..12) |k| {
        const summary = try std.fmt.allocPrint(a, "summary {d} of epoch 7, some bytes to sign", .{k});
        const msg = try testMsg(a, summary, 7);
        const all = [_]u16{ 0, 1, 2, 3 };
        const three = [_]u16{ 0, 1, 2 };
        const good3 = try S.agg(a, &sks, &order, &three, msg);
        var sig_info: []u8 = undefined;
        var epoch: u64 = 7;
        var expect: Verdict = .ok;
        switch (k % 12) {
            0, 6 => sig_info = try testSigInfo(a, 7, good3, &three),
            1, 7 => sig_info = try testSigInfo(a, 7, try S.agg(a, &sks, &order, &all, msg), &all),
            2 => { // signed another message
                sig_info = try testSigInfo(a, 7, try S.agg(a, &sks, &order, &three, "other"), &three);
                expect = .bad_signature;
            },
            3 => { // right signature, wrong signer set
                sig_info = try testSigInfo(a, 7, good3, &.{ 0, 1, 3 });
                expect = .bad_signature;
            },
            4 => {
                sig_info = try testSigInfo(a, 7, good3, &.{ 0, 1, 9 });
                expect = .bad_bitmap;
            },
            5 => {
                sig_info = try testSigInfo(a, 7, good3, &.{});
                expect = .insufficient_stake;
            },
            8 => {
                sig_info = try testSigInfo(a, 7, good3, &.{ 2, 3 });
                expect = .insufficient_stake;
            },
            9 => {
                sig_info = try testSigInfo(a, 7, @splat(0xff), &three);
                expect = .decode;
            },
            10 => {
                sig_info = try testSigInfo(a, 8, good3, &three);
                expect = .epoch_mismatch;
            },
            else => { // the point at infinity as the signature
                var inf: [48]u8 = @splat(0);
                inf[0] = 0xc0;
                sig_info = try testSigInfo(a, 7, inf, &three);
                expect = .bad_signature;
                epoch = 7;
            },
        }
        const single = try checkCert(a, &comm, epoch, summary, sig_info);
        try testing.expectEqual(expect, single);
        try jobs.append(a, .{ .committee = &comm, .summary_epoch = epoch, .summary = summary, .sig = sig_info });
        try want.append(a, single);
    }
    // a summary changed after signing (wrong message), and a short signature info
    {
        const msg = try testMsg(a, "signed summary", 7);
        const three = [_]u16{ 0, 1, 2 };
        const si = try testSigInfo(a, 7, try S.agg(a, &sks, &order, &three, msg), &three);
        try jobs.append(a, .{ .committee = &comm, .summary_epoch = 7, .summary = "changed summary", .sig = si });
        try want.append(a, .bad_signature);
        try jobs.append(a, .{ .committee = &comm, .summary_epoch = 7, .summary = "x", .sig = si[0..20] });
        try want.append(a, .decode);
    }
    const out = try a.alloc(Verdict, jobs.items.len);
    var prng = std.Random.DefaultPrng.init(0x5e7);
    const pool = try @import("core").pool.Pool.init(testing.io, testing.allocator, 3);
    defer pool.deinit();
    for ([_]bool{ false, true }) |kig| for ([_]?*@import("core").pool.Pool{ null, pool }) |p| {
        try checkCerts(testing.allocator, a, jobs.items, prng.random(), .{ .keys_in_group = kig, .pool = p }, out);
        for (want.items, out, jobs.items) |w, g, j| {
            try testing.expectEqual(w, g);
            try testing.expectEqual(w, try checkCert(a, j.committee, j.summary_epoch, j.summary, j.sig));
        }
    };
    // all good: one passing batch
    var goods: std.ArrayList(CertJob) = .empty;
    for (jobs.items, want.items) |j, w| if (w == .ok) try goods.append(a, j);
    try checkCerts(testing.allocator, a, goods.items, prng.random(), .{ .keys_in_group = true, .pool = pool }, out);
    for (out[0..goods.items.len]) |v| try testing.expectEqual(Verdict.ok, v);
}

test "a committee key outside G2: keysInG2 is false, and the batch (no keys_in_group) gives checkCert's verdicts" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // an on-curve G2 point outside the subgroup: compressed bytes with a small x (decode does no
    // subgroup check, as Mysten's Committee::new)
    var off: [96]u8 = @splat(0);
    {
        var x: u8 = 1;
        while (true) : (x += 1) {
            off[0] = 0x80;
            off[95] = x;
            if (bls.sig.PublicKey.decode(&off)) |pk| {
                if (!bls.curve.g2AffineInGroup(pk.point)) break;
            }
        }
    }
    // members: 3 real keys and the bad one, sorted; secret[i] null for the bad member
    var sks: [3]bls.sig.SecretKey = undefined;
    var raw: [4][96]u8 = undefined;
    for (&sks, 0..) |*sk, i| {
        var b: [32]u8 = @splat(0);
        b[0] = 0x33;
        b[31] = @intCast(i + 1);
        sk.* = bls.sig.SecretKey.fromBytes(&b).?;
        raw[i] = sk.publicKey().toBytes();
    }
    raw[3] = off;
    var order = [4]usize{ 0, 1, 2, 3 };
    std.mem.sort(usize, &order, @as(*const [4][96]u8, &raw), struct {
        fn lt(k: *const [4][96]u8, x: usize, y: usize) bool {
            return std.mem.order(u8, &k[x], &k[y]) == .lt;
        }
    }.lt);
    var sorted: [4][96]u8 = undefined;
    for (order, &sorted) |o, *k| k.* = raw[o];
    var bad_idx: u16 = 0;
    for (order, 0..) |o, i| if (o == 3) {
        bad_idx = @intCast(i);
    };
    const comm = try Committee.init(a, 9, &sorted, &.{ 2500, 2500, 2500, 2500 });
    // the follower batches an epoch only when this holds; here it must not
    try testing.expect(!keysInG2(&comm));

    // member indices of the three real keys
    var good_ids: [3]u16 = undefined;
    var gi: usize = 0;
    for (0..4) |i| if (i != bad_idx) {
        good_ids[gi] = @intCast(i);
        gi += 1;
    };
    const signWith = struct {
        fn f(al: std.mem.Allocator, s: []const bls.sig.SecretKey, ord: []const usize, ids: []const u16, msg: []const u8) ![48]u8 {
            var sigs: std.ArrayList(bls.sig.Signature) = .empty;
            for (ids) |i| if (ord[i] < 3) try sigs.append(al, s[ord[i]].sign(msg));
            return bls.sig.aggregate(sigs.items).?.toBytes();
        }
    }.f;
    var jobs: std.ArrayList(CertJob) = .empty;
    for (0..6) |k| {
        const summary = try std.fmt.allocPrint(a, "epoch 9 summary {d}", .{k});
        const msg = try testMsg(a, summary, 9);
        const with_bad = [_]u16{ good_ids[0], good_ids[1], bad_idx };
        const si = switch (k) {
            // the three real members: valid, and the bad key plays no part
            0, 1 => try testSigInfo(a, 9, try signWith(a, &sks, &order, &good_ids, msg), &good_ids),
            // the bad key in the signer set, signature from the real two only
            2 => try testSigInfo(a, 9, try signWith(a, &sks, &order, &with_bad, msg), &with_bad),
            // the bad key in the signer set with the full set's signature
            3 => try testSigInfo(a, 9, try signWith(a, &sks, &order, &good_ids, msg), &with_bad),
            // every member
            4 => try testSigInfo(a, 9, try signWith(a, &sks, &order, &.{ 0, 1, 2, 3 }, msg), &.{ 0, 1, 2, 3 }),
            // wrong message
            else => try testSigInfo(a, 9, try signWith(a, &sks, &order, &good_ids, "other"), &good_ids),
        };
        try jobs.append(a, .{ .committee = &comm, .summary_epoch = 9, .summary = summary, .sig = si });
    }
    var want: [6]Verdict = undefined;
    for (jobs.items, &want) |j, *w| w.* = try checkCert(a, j.committee, j.summary_epoch, j.summary, j.sig);
    try testing.expectEqual(Verdict.ok, want[0]);
    try testing.expectEqual(Verdict.bad_signature, want[5]);
    var out: [6]Verdict = undefined;
    var prng = std.Random.DefaultPrng.init(0x0ff9);
    const pool = try @import("core").pool.Pool.init(testing.io, testing.allocator, 3);
    defer pool.deinit();
    for ([_]?*@import("core").pool.Pool{ null, pool }) |p| {
        try checkCerts(testing.allocator, a, jobs.items, prng.random(), .{ .keys_in_group = false, .pool = p }, &out);
        try testing.expectEqualSlices(Verdict, &want, &out);
        // and each job alone
        for (jobs.items, want) |j, w| {
            try checkCerts(testing.allocator, a, &.{j}, prng.random(), .{ .keys_in_group = false, .pool = p }, out[0..1]);
            try testing.expectEqual(w, out[0]);
        }
    }
}
