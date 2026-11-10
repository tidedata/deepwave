//! BLS min-sig signatures as Sui uses them (fastcrypto `bls12381::min_sig` over blst):
//! signatures in G1 (48 bytes), public keys in G2 (96 bytes), DST
//! "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_".
//!
//! Every accept/reject rule mirrors the Rust path it replaces:
//!   - decoding is blst's `from_bytes` (on-curve, no subgroup check);
//!   - `verify` and the aggregate checks group-check the signature (infinity passes and is then
//!     skipped, as blst does), reject an infinite (aggregate) public key, never group-check
//!     public keys (they are proof-of-possession checked on chain), and accept iff
//!     e(H(m), pk) == e(sig, g2), computed as one shared Miller loop and one final
//!     exponentiation whose input is the same Fp12 element blst's check exponentiates.
//! Signing and key derivation are constant time.
const std = @import("std");
const cpu = @import("core").cpu;
const curve = @import("curve.zig");
const encoding = @import("encoding.zig");
const h2c = @import("hash_to_curve.zig");
const pairing = @import("pairing.zig");
const field = @import("field.zig");
const G1 = curve.G1;
const G2 = curve.G2;
const Fr = field.Fr;

pub const min_sig_dst = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

pub const PublicKey = struct {
    point: G2.Affine,

    /// blst `PublicKey::from_bytes` (what fastcrypto's `BLS12381PublicKey::from_bytes` does):
    /// 96 compressed or 192 uncompressed bytes, on the curve; no subgroup check.
    pub fn decode(b: []const u8) ?PublicKey {
        return switch (encoding.g2FromBytes(b)) {
            .ok => |a| .{ .point = a },
            .err => null,
        };
    }

    /// fastcrypto `BLS12381PublicKey::validate`: not infinity and in G2.
    pub fn validate(pk: PublicKey) bool {
        return !pk.point.isInfinity() and curve.g2AffineInGroup(pk.point);
    }

    /// Decode and validate (CONTRACTS.md 5.5: G2, subgroup checked).
    pub fn fromBytes(b: *const [96]u8) ?PublicKey {
        const pk = decode(b) orelse return null;
        if (!pk.validate()) return null;
        return pk;
    }

    pub fn toBytes(pk: PublicKey) [96]u8 {
        return encoding.g2Compress(pk.point);
    }
};

pub const Signature = struct {
    point: G1.Affine,

    /// blst `Signature::from_bytes`: 48 compressed or 96 uncompressed bytes, on the curve;
    /// no subgroup check (verification does it).
    pub fn decode(b: []const u8) ?Signature {
        return switch (encoding.g1FromBytes(b)) {
            .ok => |a| .{ .point = a },
            .err => null,
        };
    }

    /// Decode and check G1 membership (CONTRACTS.md 5.5).
    pub fn fromBytes(b: *const [48]u8) ?Signature {
        const s = decode(b) orelse return null;
        if (!curve.g1AffineInGroup(s.point)) return null;
        return s;
    }

    pub fn toBytes(s: Signature) [48]u8 {
        return encoding.g1Compress(s.point);
    }
};

/// The shared check behind every verification: `pk` is an already aggregated, non-infinite
/// G2 point (affine), `sig` a decoded G1 point. `g2_lines` are precomputed lines of the G2
/// generator, or null to compute them inside the loop.
pub fn coreVerify(pk: G2.Affine, msg: []const u8, sig: G1.Affine, g2_lines: ?*const [pairing.n_lines]pairing.Line) bool {
    return cpu.call("bls_core_verify", coreVerifyImpl, .{ pk, msg, sig, g2_lines });
}

pub fn coreVerifyImpl(pk: G2.Affine, msg: []const u8, sig: G1.Affine, g2_lines: ?*const [pairing.n_lines]pairing.Line) bool {
    if (pk.isInfinity()) return false;
    if (!sig.isInfinity() and !curve.g1AffineInGroup(sig)) return false;
    const h = h2c.hashToG1(msg, min_sig_dst).toAffine();
    const neg_sig = sig.neg();
    const f = if (g2_lines) |lines|
        pairing.millerLoop(&.{.{ .p = h, .q = pk }}, &.{.{ .p = neg_sig, .lines = lines }})
    else
        pairing.millerLoop(&.{ .{ .p = h, .q = pk }, .{ .p = neg_sig, .q = curve.g2_generator } }, &.{});
    return pairing.finalExp(f).isOne();
}

/// fastcrypto `BLS12381PublicKey::verify` (blst `verify(sig_groupcheck = true, pk_validate = false)`).
pub fn verify(pk: *const PublicKey, msg: []const u8, sig: *const Signature) bool {
    return coreVerify(pk.point, msg, sig.point, null);
}

/// The Move natives' whole check from bytes as one CPU-dispatched call, so decoding, the
/// subgroup checks and hash-to-curve run in the same kernel object as the pairing:
///   - min-sig (`bls12381_min_sig_verify`): fastcrypto `BLS12381PublicKey::from_bytes` (G2) and
///     `validate`, `BLS12381Signature::from_bytes` (G1), then `verify`;
///   - min-pk (`bls12381_min_pk_verify`): the same with the groups swapped and the G2 DST.
/// `g2_lines` (min-sig only) are the G2 generator's precomputed lines, or null.
pub fn verifyBytes(min_sig: bool, pk: []const u8, msg: []const u8, sig: []const u8, g2_lines: ?*const [pairing.n_lines]pairing.Line) bool {
    return cpu.call("bls_verify_bytes", verifyBytesImpl, .{ min_sig, pk, msg, sig, g2_lines });
}

pub const min_pk_dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub fn verifyBytesImpl(min_sig: bool, pk_bytes: []const u8, msg: []const u8, sig_bytes: []const u8, g2_lines: ?*const [pairing.n_lines]pairing.Line) bool {
    if (min_sig) {
        const s = Signature.decode(sig_bytes) orelse return false;
        const pk = PublicKey.decode(pk_bytes) orelse return false;
        if (!pk.validate()) return false;
        return coreVerifyImpl(pk.point, msg, s.point, g2_lines);
    }
    const s = switch (encoding.g2FromBytes(sig_bytes)) {
        .ok => |a| a,
        .err => return false,
    };
    const pk = switch (encoding.g1FromBytes(pk_bytes)) {
        .ok => |a| a,
        .err => return false,
    };
    // BLS12381PublicKey::validate: not infinity, in G1
    if (pk.isInfinity() or !curve.g1AffineInGroup(pk)) return false;
    // blst verify(sig_groupcheck = true): infinity passes the group check
    if (!s.isInfinity() and !curve.g2AffineInGroup(s)) return false;
    const h = h2c.hashToG2(msg, min_pk_dst).toAffine();
    // e(pk, H(m)) == e(g1, sig)
    const f = pairing.millerLoop(&.{ .{ .p = pk, .q = h }, .{ .p = curve.g1_generator.neg(), .q = s } }, &.{});
    return pairing.finalExp(f).isOne();
}

/// Proof-of-possession style check on decoded points: `pk` validated (not infinity, in G2),
/// then `verify` (one dispatched call).
pub fn verifyValidated(pk: G2.Affine, msg: []const u8, sig: G1.Affine, g2_lines: ?*const [pairing.n_lines]pairing.Line) bool {
    return cpu.call("bls_verify_validated", verifyValidatedImpl, .{ pk, msg, sig, g2_lines });
}

pub fn verifyValidatedImpl(pk: G2.Affine, msg: []const u8, sig: G1.Affine, g2_lines: ?*const [pairing.n_lines]pairing.Line) bool {
    if (!(PublicKey{ .point = pk }).validate()) return false;
    return coreVerifyImpl(pk, msg, sig, g2_lines);
}

/// Sum of points without validation (blst `AggregateSignature::aggregate(_, false)`); null on
/// an empty list, as blst returns BLST_AGGR_TYPE_MISMATCH.
pub fn aggregate(sigs: []const Signature) ?Signature {
    if (sigs.len == 0) return null;
    var acc = G1.Point.infinity;
    for (sigs) |s| acc = acc.addAffine(s.point);
    return .{ .point = acc.toAffine() };
}

/// Sum of public keys without validation (blst `AggregatePublicKey::aggregate(_, false)`).
pub fn aggregatePublicKeys(pks: []const PublicKey) ?G2.Affine {
    if (pks.len == 0) return null;
    var acc = G2.Point.infinity;
    for (pks) |p| acc = acc.addAffine(p.point);
    return acc.toAffine();
}

/// fastcrypto `BLS12381AggregateSignature::verify` (blst fast_aggregate_verify, sig group check).
pub fn fastAggregateVerify(pks: []const PublicKey, msg: []const u8, sig: *const Signature) bool {
    const agg = aggregatePublicKeys(pks) orelse return false;
    return coreVerify(agg, msg, sig.point, null);
}

/// fastcrypto `verify_different_msg` (blst aggregate_verify, sig group check, no pk checks
/// beyond rejecting infinity): e(sig, g2) == prod e(H(m_i), pk_i).
pub fn aggregateVerify(pks: []const PublicKey, msgs: []const []const u8, sig: *const Signature) bool {
    return cpu.call("bls_aggregate_verify", aggregateVerifyImpl, .{ pks, msgs, sig });
}

pub fn aggregateVerifyImpl(pks: []const PublicKey, msgs: []const []const u8, sig: *const Signature) bool {
    if (pks.len == 0 or pks.len != msgs.len) return false;
    for (pks) |pk| if (pk.point.isInfinity()) return false;
    if (!sig.point.isInfinity() and !curve.g1AffineInGroup(sig.point)) return false;
    var f = pairing.millerLoop(&.{.{ .p = sig.point.neg(), .q = curve.g2_generator }}, &.{});
    var buf: [pairing.max_pairs]pairing.Pair = undefined;
    var i: usize = 0;
    while (i < pks.len) {
        const n = @min(pairing.max_pairs, pks.len - i);
        for (0..n) |j| buf[j] = .{ .p = h2c.hashToG1(msgs[i + j], min_sig_dst).toAffine(), .q = pks[i + j].point };
        f = f.mul(pairing.millerLoop(buf[0..n], &.{}));
        i += n;
    }
    return pairing.finalExp(f).isOne();
}

// ---------------------------------------------------------------------------------------------
// secret keys (constant time)

pub const SecretKey = struct {
    /// Little-endian scalar, 0 < sk < r.
    le: [32]u8,

    /// blst `SecretKey::from_bytes`: 32 big-endian bytes, 0 < sk < r. The comparison runs over
    /// every byte with no early exit.
    pub fn fromBytes(b: *const [32]u8) ?SecretKey {
        var le: [32]u8 = undefined;
        for (0..32) |i| le[i] = b[31 - i];
        const r_le = comptime blk: {
            var out: [32]u8 = undefined;
            std.mem.writeInt(u256, &out, @import("consts.zig").r, .little);
            break :blk out;
        };
        // borrow of le - r over all bytes: set iff le < r
        var borrow: u16 = 0;
        var nonzero: u8 = 0;
        for (0..32) |i| {
            const d: u16 = @as(u16, le[i]) -% @as(u16, r_le[i]) -% borrow;
            borrow = (d >> 8) & 1;
            nonzero |= le[i];
        }
        if (borrow == 0 or nonzero == 0) return null;
        return .{ .le = le };
    }

    pub fn toBytes(sk: SecretKey) [32]u8 {
        var out: [32]u8 = undefined;
        for (0..32) |i| out[i] = sk.le[31 - i];
        return out;
    }

    pub fn publicKey(sk: *const SecretKey) PublicKey {
        const p = curve.g2_generator.toJacobian().mulCt(&sk.le);
        return .{ .point = p.toAffineCt() };
    }

    /// [sk] H(msg): the min-sig signature, constant time in sk.
    pub fn sign(sk: *const SecretKey, msg: []const u8) Signature {
        const h = h2c.hashToG1(msg, min_sig_dst);
        return .{ .point = h.mulCt(&sk.le).toAffineCt() };
    }
};

// ---------------------------------------------------------------------------------------------
// committees

/// The G2 generator's Miller-loop lines, computed once per process (a caller racing the first
/// one gets null and computes its own copy; nothing waits).
var gen_lines: [pairing.n_lines]pairing.Line = undefined;
var gen_lines_state: std.atomic.Value(u8) = .init(0);

pub fn generatorLines() ?*const [pairing.n_lines]pairing.Line {
    if (gen_lines_state.load(.acquire) == 2) return &gen_lines;
    if (gen_lines_state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) {
        pairing.precomputeLines(curve.g2_generator, &gen_lines);
        gen_lines_state.store(2, .release);
        return &gen_lines;
    }
    return null;
}

pub const max_committee = 4096;

/// Outcome of one certificate check, in the order Mysten's path can fail.
pub const CertVerdict = enum {
    ok,
    /// The aggregate signature bytes do not decode (blst `Signature::from_bytes`).
    sig_decode,
    /// A signer index outside the committee (SuiError::UnknownSigner).
    unknown_signer,
    /// No signers, an infinite aggregate key, a signature outside G1, or a failed pairing check.
    invalid,
};

/// Committee keys decoded and prepared once per epoch: affine keys, their sum (for the
/// complement trick when most validators signed), and the G2 generator's Miller-loop lines.
pub const PreparedCommittee = struct {
    keys: []const G2.Affine,
    total: G2.Point,
    g2_lines: *const [pairing.n_lines]pairing.Line,

    pub const InitError = error{ InvalidCommitteeKey, CommitteeTooLarge } || std.mem.Allocator.Error;

    /// Decodes every key with blst `PublicKey::from_bytes` semantics (Committee::new does the
    /// same, without a subgroup check). Memory comes from `arena` and lives as long as it.
    /// `pubkeys` must be in committee index order (`Committee::voting_rights`, sorted by the
    /// 96-byte AuthorityName), the order certificate signer bitmaps index. Mainnet keys are
    /// validated in G2 by proof of possession on chain (`verify_proof_of_possession`).
    pub fn init(arena: std.mem.Allocator, pubkeys: []const [96]u8) InitError!PreparedCommittee {
        if (pubkeys.len > max_committee) return error.CommitteeTooLarge;
        const keys = try arena.alloc(G2.Affine, pubkeys.len);
        var total = G2.Point.infinity;
        if (!cpu.call("bls_decode_keys", decodeKeysImpl, .{ pubkeys, keys, &total })) return error.InvalidCommitteeKey;
        const lines = generatorLines() orelse blk: {
            const l = try arena.create([pairing.n_lines]pairing.Line);
            pairing.precomputeLines(curve.g2_generator, l);
            break :blk l;
        };
        return .{ .keys = keys, .total = total, .g2_lines = lines };
    }

    /// Decodes every key (G2 decompression) and sums them; false on an undecodable key.
    /// Keys go two at a time (`encoding.g2Uncompress2`: the two square roots interleaved).
    pub fn decodeKeysImpl(pubkeys: []const [96]u8, keys: []G2.Affine, total: *G2.Point) bool {
        var i: usize = 0;
        while (i + 1 < pubkeys.len) : (i += 2) {
            const r = encoding.g2Uncompress2(&pubkeys[i], &pubkeys[i + 1]);
            inline for (0..2) |k| {
                switch (r[k]) {
                    .ok => |a| {
                        keys[i + k] = a;
                        total.* = total.addAffine(a);
                    },
                    .err => return false,
                }
            }
        }
        if (i < pubkeys.len) {
            const pk = PublicKey.decode(&pubkeys[i]) orelse return false;
            keys[i] = pk.point;
            total.* = total.addAffine(pk.point);
        }
        return true;
    }

    /// The aggregate public key of `signers` (duplicates count once, as Mysten's seen-set does).
    /// No allocation.
    pub fn aggregateKey(self: *const PreparedCommittee, signers: []const u32) union(enum) { ok: G2.Affine, unknown_signer, empty } {
        var seen: [max_committee / 64]u64 = @splat(0);
        var count: usize = 0;
        for (signers) |s| {
            if (s >= self.keys.len) return .unknown_signer;
            const bit = @as(u64, 1) << @intCast(s % 64);
            if (seen[s / 64] & bit != 0) continue;
            seen[s / 64] |= bit;
            count += 1;
        }
        if (count == 0) return .empty;
        var acc = G2.Point.infinity;
        if (2 * count > self.keys.len) {
            // total minus the non-signers: fewer additions, the same group element
            var miss = G2.Point.infinity;
            for (self.keys, 0..) |k, i| {
                if (seen[i / 64] & (@as(u64, 1) << @intCast(i % 64)) == 0) miss = miss.addAffine(k);
            }
            acc = self.total.add(miss.neg());
        } else {
            for (self.keys, 0..) |k, i| {
                if (seen[i / 64] & (@as(u64, 1) << @intCast(i % 64)) != 0) acc = acc.addAffine(k);
            }
        }
        return .{ .ok = acc.toAffine() };
    }

    /// Mysten's certificate check (AuthorityQuorumSignInfo::verify_secure, BLS part): decode
    /// the aggregate signature, aggregate the signers' keys, verify over `msg`. No allocation.
    pub fn verifyAggregateVerdict(self: *const PreparedCommittee, signers: []const u32, msg: []const u8, agg_sig: *const [48]u8) CertVerdict {
        return cpu.call("bls_cert_verify", verifyAggregateVerdictImpl, .{ self, signers, msg, agg_sig });
    }

    pub fn verifyAggregateVerdictImpl(self: *const PreparedCommittee, signers: []const u32, msg: []const u8, agg_sig: *const [48]u8) CertVerdict {
        const sig = Signature.decode(agg_sig) orelse return .sig_decode;
        const pk = switch (self.aggregateKey(signers)) {
            .ok => |a| a,
            .unknown_signer => return .unknown_signer,
            .empty => return .invalid,
        };
        return if (coreVerifyImpl(pk, msg, sig.point, self.g2_lines)) .ok else .invalid;
    }

    pub fn verifyAggregate(self: *const PreparedCommittee, signers: []const u32, msg: []const u8, agg_sig: *const [48]u8) bool {
        return self.verifyAggregateVerdict(signers, msg, agg_sig) == .ok;
    }
};


// ------------------------------------------------------------------------------------------------
// Randomized batch verification (min-sig, decoded points)
//
// k signatures, each over its own key and message: with independent random 128-bit r_i,
//
//   e(-sum r_i sig_i, g2) * prod_i e(r_i H(m_i), pk_i) == 1
//
// The scalars go on the G1 side (H(m_i) and sig_i), so every key keeps its own computed lines
// and the generator's precomputed lines serve the whole batch once. One shared Miller loop
// (split over the pool's lanes, partial products multiplied) and one final exponentiation.
// Verdicts equal `verifyValidated` item by item: the key and signature group checks are decided
// per item first; a passing batch marks its items valid (a false pass has probability about
// 2^-128); a failing one is bisected (if one half passes the other must fail) down to `leaf`
// items, which run `verifyValidated`. A work budget switches to `verifyValidated` when many
// items are bad.

const Pool = @import("core").pool.Pool;

pub const BatchItem = struct { pk: G2.Affine, msg: []const u8, sig: G1.Affine };

pub const BatchOpts = struct {
    /// null: `core.pool.shared()` (inline when none is installed).
    pool: ?*Pool = null,
    /// At most this many lanes (0: all of the pool).
    max_lanes: usize = 0,
    /// Failing sub-batches of at most this many items are decided item by item.
    leaf: usize = 2,
    /// Items per batch equation; longer lists run in chunks.
    max_batch: usize = 1024,
    /// The caller guarantees every non-infinite key is in G2 (a certificate's aggregate key over
    /// a committee whose members were group-checked once): the per-item key check and the
    /// per-item fallback become `coreVerify`'s (infinity rejected, no G2 check), so verdicts
    /// equal `coreVerify` instead of `verifyValidated`.
    keys_in_group: bool = false,
};

/// `verifyValidated(items[i].pk, items[i].msg, items[i].sig, g2_lines)` for every i, as
/// randomized batches: `out[i]` is that verdict (a pass carries the ~2^-128 batch soundness).
/// `g2_lines` as in `verifyValidated` (null: `generatorLines()`, else computed here). `rng` must
/// be a CSPRNG outside tests. Never fails: without memory it runs `verifyValidated` per item.
pub fn verifyBatchValidated(gpa: std.mem.Allocator, items: []const BatchItem, g2_lines: ?*const [pairing.n_lines]pairing.Line, rng: std.Random, opts: BatchOpts, out: []bool) void {
    std.debug.assert(out.len >= items.len);
    var own_lines: [pairing.n_lines]pairing.Line = undefined;
    const lines = g2_lines orelse generatorLines() orelse blk: {
        pairing.precomputeLines(curve.g2_generator, &own_lines);
        break :blk &own_lines;
    };
    const step = @max(1, opts.max_batch);
    var lo: usize = 0;
    while (lo < items.len) : (lo += step) {
        const hi = @min(items.len, lo + step);
        BlsEngine.run(gpa, items[lo..hi], lines, rng, opts, out[lo..hi]);
    }
}

const BlsEngine = struct {
    items: []const BatchItem,
    lines: *const [pairing.n_lines]pairing.Line,
    pool: ?*Pool,
    lanes: usize,
    leaf: usize,
    keys_in_group: bool,
    r: [][16]u8,
    rh: []G1.Affine,
    tmp: []G1.Point,
    scratch: []curve.Fp,
    rs: []G1.Point,
    part_f: []Fp12,
    part_s: []G1.Point,
    set: []u32,
    sx: []u32,
    out: []bool,
    budget: usize,

    const Fp12 = @import("tower.zig").Fp12;

    fn run(gpa: std.mem.Allocator, items: []const BatchItem, lines: *const [pairing.n_lines]pairing.Line, rng: std.Random, opts: BatchOpts, out: []bool) void {
        const pool = opts.pool orelse @import("core").pool.shared();
        const pool_lanes: usize = if (pool) |p| p.lanes() else 1;
        const lanes = if (opts.max_lanes == 0) pool_lanes else @min(opts.max_lanes, pool_lanes);
        const n = items.len;
        var e: BlsEngine = .{
            .items = items,
            .lines = lines,
            .pool = pool,
            .lanes = @max(1, lanes),
            .leaf = @max(1, opts.leaf),
            .keys_in_group = opts.keys_in_group,
            .r = &.{},
            .rh = &.{},
            .tmp = &.{},
            .scratch = &.{},
            .rs = &.{},
            .part_f = &.{},
            .part_s = &.{},
            .set = &.{},
            .sx = &.{},
            .out = out,
            .budget = 2 * n,
        };
        if (n == 0) return;
        if (n <= e.leaf) return e.singles(null, n);
        e.alloc(gpa, n) catch {
            e.freeAll(gpa);
            return e.singles(null, n);
        };
        defer e.freeAll(gpa);
        for (e.r) |*r| {
            while (true) {
                rng.bytes(r);
                if (!std.mem.allEqual(u8, r, 0)) break;
            }
        }
        // per-item group checks, hash to curve and the scaled points, in parallel
        @memset(out[0..n], false);
        core_forRange(e.pool, n, (n + e.lanes - 1) / e.lanes, e.lanes, PrepJob{ .e = &e }, prep);
        // the candidate set: items whose group checks passed
        var m: usize = 0;
        for (0..n) |i| if (e.valid(i)) {
            e.set[m] = @intCast(i);
            m += 1;
        };
        const set = e.set[0..m];
        if (m == 0) return;
        if (m <= e.leaf) return e.singles(set, 0);
        if (e.check(set)) {
            for (set) |i| out[i] = true;
            return;
        }
        e.resolveFailed(set);
    }

    fn valid(e: *const BlsEngine, i: usize) bool {
        // r is zeroed for an item whose key or signature fails its group check
        return !std.mem.allEqual(u8, &e.r[i], 0);
    }

    fn alloc(e: *BlsEngine, gpa: std.mem.Allocator, n: usize) !void {
        e.r = try gpa.alloc([16]u8, n);
        e.rh = try gpa.alloc(G1.Affine, n);
        e.tmp = try gpa.alloc(G1.Point, n);
        e.scratch = try gpa.alloc(curve.Fp, n);
        e.rs = try gpa.alloc(G1.Point, n);
        e.part_f = try gpa.alloc(Fp12, n);
        e.part_s = try gpa.alloc(G1.Point, n);
        e.set = try gpa.alloc(u32, n);
        e.sx = try gpa.alloc(u32, n);
    }

    fn freeAll(e: *BlsEngine, gpa: std.mem.Allocator) void {
        gpa.free(e.r);
        gpa.free(e.rh);
        gpa.free(e.tmp);
        gpa.free(e.scratch);
        gpa.free(e.rs);
        gpa.free(e.part_f);
        gpa.free(e.part_s);
        gpa.free(e.set);
        gpa.free(e.sx);
        e.sx = &.{};
        e.r = &.{};
        e.rh = &.{};
        e.tmp = &.{};
        e.scratch = &.{};
        e.rs = &.{};
        e.part_f = &.{};
        e.part_s = &.{};
        e.set = &.{};
    }

    const PrepJob = struct { e: *BlsEngine };

    fn prep(j: PrepJob, lo: usize, hi: usize) void {
        const e = j.e;
        for (lo..hi) |i| {
            const it = e.items[i];
            // verifyValidated's own checks, in its order: key valid, signature in G1 (or infinity)
            const key_ok = if (e.keys_in_group) !it.pk.isInfinity() else (PublicKey{ .point = it.pk }).validate();
            const ok = key_ok and (it.sig.isInfinity() or curve.g1AffineInGroup(it.sig));
            if (!ok) {
                e.r[i] = @splat(0);
                e.tmp[i] = G1.Point.infinity;
                e.rs[i] = G1.Point.infinity;
                continue;
            }
            const h = h2c.hashToG1(it.msg, min_sig_dst);
            e.tmp[i] = h.mulVartime(&e.r[i], 128);
            e.rs[i] = it.sig.toJacobian().mulVartime(&e.r[i], 128);
        }
        curve.batchToAffine(G1, e.tmp[lo..hi], e.rh[lo..hi], e.scratch[lo..hi]);
    }

    const Job = struct { e: *BlsEngine, set: []const u32, grain: usize };

    fn share(j: Job, lo: usize, hi: usize) void {
        const e = j.e;
        var s = lo;
        while (s < hi) : (s += j.grain) {
            const t = @min(hi, s + j.grain);
            const m = e.millerSerial(j.set[s..t]);
            e.part_f[s / j.grain] = m.f;
            e.part_s[s / j.grain] = m.acc;
        }
    }

    const Partial = struct { f: Fp12, acc: G1.Point };

    fn millerSerial(e: *const BlsEngine, sub: []const u32) Partial {
        var f = Fp12.one;
        var acc = G1.Point.infinity;
        var k: usize = 0;
        var buf: [pairing.max_pairs]pairing.Pair = undefined;
        while (k < sub.len) {
            const m = @min(pairing.max_pairs, sub.len - k);
            for (0..m) |q| {
                const i = sub[k + q];
                buf[q] = .{ .p = e.rh[i], .q = e.items[i].pk };
            }
            const g = pairing.millerLoop(buf[0..m], &.{});
            f = if (k == 0) g else f.mul(g);
            k += m;
        }
        for (sub) |i| acc = acc.add(e.rs[i]);
        return .{ .f = f, .acc = acc };
    }

    fn equation(e: *const BlsEngine, f0: Fp12, acc: G1.Point) bool {
        const neg = acc.toAffine().neg();
        const f = f0.mul(pairing.millerLoop(&.{}, &.{.{ .p = neg, .lines = e.lines }}));
        return pairing.finalExp(f).isOne();
    }

    fn check(e: *BlsEngine, set: []const u32) bool {
        const lanes = @min(e.lanes, set.len);
        const grain = (set.len + lanes - 1) / lanes;
        core_forRange(e.pool, set.len, grain, lanes, Job{ .e = e, .set = set, .grain = grain }, share);
        const parts = (set.len + grain - 1) / grain;
        var f = e.part_f[0];
        var acc = e.part_s[0];
        for (1..parts) |g| {
            f = f.mul(e.part_f[g]);
            acc = acc.add(e.part_s[g]);
        }
        return e.equation(f, acc);
    }

    fn checkBudget(e: *BlsEngine, set: []const u32) ?bool {
        if (e.budget < set.len) return null;
        e.budget -= set.len;
        return e.check(set);
    }

    fn resolveFailed(e: *BlsEngine, set: []const u32) void {
        if (set.len <= e.leaf) return e.singles(set, 0);
        if (e.lanes > 1) return e.resolveFailedParallel(set);
        const h = set.len / 2;
        const left = set[0..h];
        const right = set[h..];
        const lv = e.checkBudget(left) orelse return e.singles(set, 0);
        if (lv) {
            for (left) |i| e.out[i] = true;
            e.resolveFailed(right);
        } else {
            e.resolveFailed(left);
            e.resolveUnknown(right);
        }
    }

    fn resolveUnknown(e: *BlsEngine, set: []const u32) void {
        if (set.len <= e.leaf) return e.singles(set, 0);
        const v = e.checkBudget(set) orelse return e.singles(set, 0);
        if (v) {
            for (set) |i| e.out[i] = true;
        } else e.resolveFailed(set);
    }

    const GroupJob = struct { e: *const BlsEngine, set: []const u32, bounds: []const usize, res: []bool };

    fn groupShare(j: GroupJob, lo: usize, hi: usize) void {
        for (lo..hi) |g| {
            const m = j.e.millerSerial(j.set[j.bounds[g]..j.bounds[g + 1]]);
            j.res[g] = j.e.equation(m.f, m.acc);
        }
    }

    /// Many lanes: one group per lane, each checked as its own batch on its own lane; small
    /// failing groups go to `verifyValidated` together, large ones are split again.
    fn resolveFailedParallel(e: *BlsEngine, set: []const u32) void {
        const small = @max(e.leaf, 4);
        if (set.len <= small or e.budget < set.len) return e.singles(set, 0);
        e.budget -= set.len;
        const g: usize = @max(2, @min(e.lanes, (set.len + small - 1) / small));
        var bounds: [Pool_max_lanes + 1]usize = undefined;
        var res: [Pool_max_lanes]bool = undefined;
        for (0..g + 1) |k| bounds[k] = k * set.len / g;
        core_forRange(e.pool, g, 1, e.lanes, GroupJob{ .e = e, .set = set, .bounds = bounds[0 .. g + 1], .res = res[0..g] }, groupShare);
        var m: usize = 0;
        for (0..g) |k| {
            const sub = set[bounds[k]..bounds[k + 1]];
            if (res[k]) {
                for (sub) |i| e.out[i] = true;
            } else if (sub.len <= small) {
                @memcpy(e.sx[m..][0..sub.len], sub);
                m += sub.len;
            }
        }
        if (m != 0) e.singles(e.sx[0..m], 0);
        for (0..g) |k| {
            const sub = set[bounds[k]..bounds[k + 1]];
            if (!res[k] and sub.len > small) e.resolveFailedParallel(sub);
        }
    }

    const SingleJob = struct { e: *BlsEngine, set: ?[]const u32 };

    fn singleShare(j: SingleJob, lo: usize, hi: usize) void {
        for (lo..hi) |k| {
            const i: usize = if (j.set) |s| s[k] else k;
            const it = j.e.items[i];
            j.e.out[i] = if (j.e.keys_in_group) coreVerify(it.pk, it.msg, it.sig, j.e.lines) else verifyValidated(it.pk, it.msg, it.sig, j.e.lines);
        }
    }

    /// `verifyValidated` on `set`, or on items 0..n when `set` is null.
    fn singles(e: *BlsEngine, set: ?[]const u32, n: usize) void {
        const len = if (set) |s| s.len else n;
        core_forRange(e.pool, len, 1, e.lanes, SingleJob{ .e = e, .set = set }, singleShare);
    }
};

const core_forRange = @import("core").pool.forRange;
const Pool_max_lanes = @import("core").pool.max_lanes;

test "sign and verify round trip, fastcrypto known answer" {
    var skb: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skb, "266f9708fd8d3b462b10cdbf5498076c021eb3acfdd47cb1fef647967fe194fb");
    const sk = SecretKey.fromBytes(&skb).?;
    const pk = sk.publicKey();
    var want_pk: [96]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_pk, "8c66dc2c1ea9e53f0985c17b4e7af19912b6d3c40e0c5920a5a12509b4eb3619f5e07ec56ea77f0b30629ba1cc72d75b139460782a5f0e2f89fb4c42b4b8a5fae3d260102220e63d0754e7e1846deefd3988eade4ed37f1385437d19de1a1618");
    try std.testing.expectEqualSlices(u8, &want_pk, &pk.toBytes());
    const sig = sk.sign("Hello, world!");
    var want_sig: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_sig, "b11f1909aa3a53cbc90b5e181c9e8de40e45ed055fad014781dd645ed7897bee9d38038d9d92c366a145f6a8a2946c11");
    try std.testing.expectEqualSlices(u8, &want_sig, &sig.toBytes());
    try std.testing.expect(verify(&pk, "Hello, world!", &sig));
    try std.testing.expect(!verify(&pk, "Hello, world?", &sig));
    // committee path
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var keys: [3][96]u8 = undefined;
    var sks: [3]SecretKey = undefined;
    for (0..3) |i| {
        var b = skb;
        b[31] +%= @intCast(i + 1);
        sks[i] = SecretKey.fromBytes(&b).?;
        keys[i] = sks[i].publicKey().toBytes();
    }
    const c = try PreparedCommittee.init(arena.allocator(), &keys);
    const msg = "checkpoint";
    const s0 = sks[0].sign(msg);
    const s2 = sks[2].sign(msg);
    const agg = aggregate(&.{ s0, s2 }).?.toBytes();
    try std.testing.expectEqual(CertVerdict.ok, c.verifyAggregateVerdict(&.{ 0, 2 }, msg, &agg));
    try std.testing.expectEqual(CertVerdict.ok, c.verifyAggregateVerdict(&.{ 2, 0, 2 }, msg, &agg));
    try std.testing.expectEqual(CertVerdict.invalid, c.verifyAggregateVerdict(&.{ 0, 1, 2 }, msg, &agg));
    try std.testing.expectEqual(CertVerdict.invalid, c.verifyAggregateVerdict(&.{}, msg, &agg));
    try std.testing.expectEqual(CertVerdict.unknown_signer, c.verifyAggregateVerdict(&.{ 0, 3 }, msg, &agg));
    const all = aggregate(&.{ s0, sks[1].sign(msg), s2 }).?.toBytes();
    try std.testing.expectEqual(CertVerdict.ok, c.verifyAggregateVerdict(&.{ 0, 1, 2 }, msg, &all));
}

/// An on-curve point outside the subgroup, from compressed bytes with a small x (decode does no
/// subgroup check).
fn offSubgroup(comptime len: usize, comptime Dec: type) Dec {
    var b: [len]u8 = @splat(0);
    var x: u8 = 1;
    while (true) : (x += 1) {
        b[0] = 0x80;
        b[len - 1] = x;
        if (Dec.decode(&b)) |d| return d;
    }
}

test "verifyBatchValidated: verdicts equal verifyValidated on valid and tampered items" {
    const gpa = std.testing.allocator;
    const pool = try Pool.init(std.testing.io, gpa, 4);
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(0xb15);
    const rng = prng.random();
    const n = 64;
    var msgs: [n][16]u8 = undefined;
    var items: [n]BatchItem = undefined;
    var valid: [n]BatchItem = undefined;
    for (0..n) |i| {
        var skb: [32]u8 = @splat(0);
        rng.bytes(skb[1..]);
        const sk = SecretKey.fromBytes(&skb).?;
        rng.bytes(&msgs[i]);
        valid[i] = .{ .pk = sk.publicKey().point, .msg = &msgs[i], .sig = sk.sign(&msgs[i]).point };
    }
    const bad_sig = offSubgroup(48, Signature).point;
    const bad_pk = offSubgroup(96, PublicKey).point;
    try std.testing.expect(!curve.g1AffineInGroup(bad_sig));
    try std.testing.expect(!curve.g2AffineInGroup(bad_pk));
    var out: [n]bool = undefined;
    var bad_seen: usize = 0;
    for ([_]usize{ 1, 2, 3, 8, 17, 64 }, 0..) |k, round| {
        for (0..k) |i| {
            items[i] = valid[i];
            if (round != 0 and rng.uintLessThan(u8, 4) == 0) switch (rng.uintLessThan(u8, 7)) {
                0 => items[i].msg = &msgs[(i + 1) % n],
                1 => items[i].sig = valid[(i + 1) % n].sig,
                2 => items[i].pk = valid[(i + 1) % n].pk,
                3 => items[i].sig = G1.Affine.infinity,
                4 => items[i].pk = G2.Affine.infinity,
                5 => items[i].sig = bad_sig,
                else => items[i].pk = bad_pk,
            };
        }
        for ([_]BatchOpts{ .{ .pool = pool }, .{ .pool = pool, .max_lanes = 1 }, .{ .pool = pool, .leaf = 1, .max_batch = 5 } }) |o| {
            verifyBatchValidated(gpa, items[0..k], null, rng, o, out[0..k]);
            for (items[0..k], out[0..k]) |it, got| {
                const want = verifyValidated(it.pk, it.msg, it.sig, null);
                try std.testing.expectEqual(want, got);
                bad_seen += @intFromBool(!want);
            }
        }
    }
    try std.testing.expect(bad_seen > 10);
    // keys_in_group: verdicts equal coreVerify (keys here are all in G2 or infinity)
    for (0..n) |i| {
        items[i] = valid[i];
        if (i % 5 == 1) items[i].msg = &msgs[(i + 2) % n];
        if (i % 7 == 3) items[i].pk = G2.Affine.infinity;
        if (i % 11 == 4) items[i].sig = bad_sig;
    }
    verifyBatchValidated(gpa, &items, null, rng, .{ .pool = pool, .keys_in_group = true }, &out);
    for (items, out) |it, got| try std.testing.expectEqual(coreVerify(it.pk, it.msg, it.sig, null), got);
    // all valid passes; all bad fails item by item
    verifyBatchValidated(gpa, &valid, null, rng, .{ .pool = pool }, &out);
    for (out) |v| try std.testing.expect(v);
    for (&items, valid, 0..) |*it, v, i| it.* = .{ .pk = v.pk, .msg = v.msg, .sig = valid[(i + 3) % n].sig };
    verifyBatchValidated(gpa, &items, null, rng, .{ .pool = pool }, &out);
    for (out) |v| try std.testing.expect(!v);
}

// Bench (skipped unless ZUI_BATCH_BENCH is set; run with -Doptimize=ReleaseFast):
// µs per certificate-shaped item (own key and message each), single vs batch, 1 lane vs all.
test "bench: BLS min-sig verifyValidated vs verifyBatchValidated" {
    if (!@import("builtin").link_libc) return error.SkipZigTest;
    _ = std.c.getenv("ZUI_BATCH_BENCH") orelse return error.SkipZigTest;
    const io = std.testing.io;
    const gpa = std.heap.page_allocator;
    var prng = std.Random.DefaultPrng.init(0xbe);
    const rng = prng.random();
    const n = 256;
    const items = try gpa.alloc(BatchItem, n);
    const msgs = try gpa.alloc([200]u8, n); // about a checkpoint summary's signed bytes
    for (items, msgs) |*it, *m| {
        var skb: [32]u8 = @splat(0);
        rng.bytes(skb[1..]);
        const sk = SecretKey.fromBytes(&skb).?;
        rng.bytes(m);
        it.* = .{ .pk = sk.publicKey().point, .msg = m, .sig = sk.sign(m).point };
    }
    const cpus = std.Thread.getCpuCount() catch 1;
    const pool = try Pool.init(io, gpa, cpus);
    defer pool.deinit();
    const out = try gpa.alloc(bool, n);
    var seed: [32]u8 = undefined;
    io.random(&seed);
    var chacha = std.Random.ChaCha.init(seed);
    const crng = chacha.random();
    const lines = generatorLines();
    const Single = struct {
        items: []const BatchItem,
        out: []bool,
        lines: ?*const [pairing.n_lines]pairing.Line,
        fn f(c: @This(), lo: usize, hi: usize) void {
            for (lo..hi) |i| c.out[i] = verifyValidated(c.items[i].pk, c.items[i].msg, c.items[i].sig, c.lines);
        }
    };
    for ([_]usize{ 1, cpus }) |lanes| {
        var best: u64 = std.math.maxInt(u64);
        for (0..3) |_| {
            const t0 = std.Io.Timestamp.now(io, .awake);
            pool.forRange(n, 1, lanes, Single{ .items = items, .out = out, .lines = lines }, Single.f);
            const t1 = std.Io.Timestamp.now(io, .awake);
            best = @min(best, @as(u64, @intCast(t0.durationTo(t1).nanoseconds)));
        }
        for (out) |v| try std.testing.expect(v);
        std.debug.print("bls min-sig lanes={d} single      us/cert={d:.1}\n", .{ lanes, @as(f64, @floatFromInt(best)) / 1000.0 / n });
        for ([_]usize{ 1, 8, 64, 256 }) |k| {
            const reps = @max(1, 512 / k);
            var bb: u64 = std.math.maxInt(u64);
            for (0..3) |_| {
                const t0 = std.Io.Timestamp.now(io, .awake);
                for (0..reps) |rep| {
                    const lo = (rep * k) % n;
                    const hi = @min(n, lo + k);
                    verifyBatchValidated(gpa, items[lo..hi], lines, crng, .{ .pool = pool, .max_lanes = lanes }, out[lo..hi]);
                }
                const t1 = std.Io.Timestamp.now(io, .awake);
                bb = @min(bb, @as(u64, @intCast(t0.durationTo(t1).nanoseconds)));
            }
            for (out[0..k]) |v| try std.testing.expect(v);
            std.debug.print("bls min-sig lanes={d} batch k={d:<3} us/cert={d:.1}\n", .{ lanes, k, @as(f64, @floatFromInt(bb)) / 1000.0 / @as(f64, @floatFromInt(reps * k)) });
            bb = std.math.maxInt(u64);
            for (0..3) |_| {
                const t0 = std.Io.Timestamp.now(io, .awake);
                for (0..reps) |rep| {
                    const lo = (rep * k) % n;
                    const hi = @min(n, lo + k);
                    verifyBatchValidated(gpa, items[lo..hi], lines, crng, .{ .pool = pool, .max_lanes = lanes, .keys_in_group = true }, out[lo..hi]);
                }
                const t1 = std.Io.Timestamp.now(io, .awake);
                bb = @min(bb, @as(u64, @intCast(t0.durationTo(t1).nanoseconds)));
            }
            std.debug.print("bls min-sig lanes={d} batch k={d:<3} keys_in_group us/cert={d:.1}\n", .{ lanes, k, @as(f64, @floatFromInt(bb)) / 1000.0 / @as(f64, @floatFromInt(reps * k)) });
        }
        // one bad certificate in 64: the failure path's cost
        const saved = items[17];
        items[17].msg = items[18].msg;
        var ob: u64 = std.math.maxInt(u64);
        for (0..3) |_| {
            const t0 = std.Io.Timestamp.now(io, .awake);
            verifyBatchValidated(gpa, items[0..64], lines, crng, .{ .pool = pool, .max_lanes = lanes }, out[0..64]);
            const t1 = std.Io.Timestamp.now(io, .awake);
            ob = @min(ob, @as(u64, @intCast(t0.durationTo(t1).nanoseconds)));
        }
        try std.testing.expect(!out[17] and out[16] and out[18]);
        items[17] = saved;
        std.debug.print("bls min-sig lanes={d} batch k=64 one bad us/cert={d:.1}\n", .{ lanes, @as(f64, @floatFromInt(ob)) / 1000.0 / 64.0 });
        // coreVerify (the checkpoint path's single check, no key group check)
        var cb: u64 = std.math.maxInt(u64);
        const Core = struct {
            items: []const BatchItem,
            out: []bool,
            lines: ?*const [pairing.n_lines]pairing.Line,
            fn f(c: @This(), lo: usize, hi: usize) void {
                for (lo..hi) |i| c.out[i] = coreVerify(c.items[i].pk, c.items[i].msg, c.items[i].sig, c.lines);
            }
        };
        for (0..3) |_| {
            const t0 = std.Io.Timestamp.now(io, .awake);
            pool.forRange(n, 1, lanes, Core{ .items = items, .out = out, .lines = lines }, Core.f);
            const t1 = std.Io.Timestamp.now(io, .awake);
            cb = @min(cb, @as(u64, @intCast(t0.durationTo(t1).nanoseconds)));
        }
        std.debug.print("bls min-sig lanes={d} single coreVerify us/cert={d:.1}\n", .{ lanes, @as(f64, @floatFromInt(cb)) / 1000.0 / n });
    }
}
