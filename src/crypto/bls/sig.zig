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
const Blake2b256 = @import("hash").Blake2b256;
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
    /// `keysInG2`'s answer once computed (0: not yet, 1: every key in G2, 2: a key outside).
    /// In the arena, so every copy of this struct shares it.
    g2_state: *std.atomic.Value(u8),

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
        const g2_state = try arena.create(std.atomic.Value(u8));
        g2_state.* = .init(0);
        return .{ .keys = keys, .total = total, .g2_lines = lines, .g2_state = g2_state };
    }

    /// Whether every key is in G2 (the identity counts: it adds nothing to an aggregate), so
    /// every aggregate key of this committee is too. Computed on first use (one subgroup check
    /// per key) and kept for the life of the committee; `init` never checks, as Mysten's
    /// `Committee::new` never does (blst `PublicKey::from_bytes`). Nor does Mysten's
    /// certificate check: `AuthorityQuorumSignInfo::verify_secure` puts the one certificate in
    /// a `VerificationObligation`, and `verify_all` runs fastcrypto's `batch_verify`
    /// (`AggregatePublicKey::aggregate(keys, false)`, then blst
    /// `verify_multiple_aggregate_signatures` with `pks_validate = false`,
    /// `sigs_groupcheck = true`). Its first coefficient is fixed at 1, so for one certificate
    /// that is the plain check `coreVerify` makes, whatever group the keys are in; further
    /// certificates in one obligation get random 96-bit coefficients in this same equation
    /// (sui 1.83.1 crypto.rs, fastcrypto da61cd4 bls12381/mod.rs, blst 0.3.16).
    ///
    /// This is what the batch equation needs and the single check does not: the batch scales
    /// each H(m_i) by r_i, and e(r H, Q) == e(H, Q)^r holds for Q in G2 only (the Miller
    /// function of a point outside G2 is not linear in its G1 argument; test below). A
    /// committee for which this is false must take the single path.
    pub fn keysInG2(self: *const PreparedCommittee) bool {
        switch (self.g2_state.load(.acquire)) {
            1 => return true,
            2 => return false,
            else => {},
        }
        // two threads may both compute it: the same answer, stored twice
        const ok = cpu.call("bls_keys_in_g2", keysInG2Impl, .{self.keys});
        self.g2_state.store(if (ok) 1 else 2, .release);
        return ok;
    }

    pub fn keysInG2Impl(keys: []const G2.Affine) bool {
        for (keys) |k| {
            if (!curve.g2AffineInGroup(k)) return false; // the identity passes
        }
        return true;
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
// k signatures, each over its own key and message: with independent random r_i,
//
//   e(-sum r_i sig_i, g2) * prod_i e(r_i H(m_i), pk_i) == 1
//
// The scalars go on the G1 side (H(m_i) and sig_i), so every key keeps its own computed lines
// and the generator's precomputed lines serve the whole batch once. One shared Miller loop
// (split over the pool's lanes, partial products multiplied) and one final exponentiation.
//
// r_i = a_i + b_i lambda mod r for random 64-bit a_i, b_i (not both zero; drawn from the
// caller's rng and the batch itself, `BlsEngine.coefficients`), lambda the
// eigenvalue of sigma on G1: uniform over 2^128 - 1 scalars (curve.zig, above `wnaf4`), so a
// batch with a failing item holds with probability at most 1 / (2^128 - 1), as with plain
// 128-bit r_i. H(m_i) and sig_i are in G1 (hash to curve clears the cofactor; the signature is
// group-checked per item first), where [r_i]P = [a_i]P + [b_i]sigma(P): 64 doublings and
// width-4 NAF additions per r_i H(m_i) (`curve.mulGlv`), and sum r_i sig_i as one
// multi-scalar multiplication over shared doublings (`curve.msmGlv`).
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
    /// What decides the items of a failed batch equation: `bisect` splits it (a half that
    /// passes is accepted, down to `leaf` items); `singles` runs the single check on every
    /// item of it, so no verdict of a failed batch comes from a batch equation.
    on_fail: enum { bisect, singles } = .bisect,
    /// Counters, added to (never reset here).
    stats: ?*BatchStats = null,
};

pub const BatchStats = struct {
    /// Batch equations evaluated, and how many of them did not hold.
    equations: usize = 0,
    failed: usize = 0,
    /// Items accepted by an equation that held.
    batch_ok: usize = 0,
    /// Items decided by the single check.
    singles: usize = 0,
};

/// `verifyValidated(items[i].pk, items[i].msg, items[i].sig, g2_lines)` for every i, as
/// randomized batches: `out[i]` is that verdict (a pass carries the ~2^-128 batch soundness).
/// `g2_lines` as in `verifyValidated` (null: `generatorLines()`, else computed here). `rng` must
/// be a CSPRNG outside tests, and is read on the calling thread only (32 bytes per equation
/// chunk; the coefficients also depend on the items, see `BlsEngine.coefficients`). Never
/// fails: without memory it runs `verifyValidated` per item.
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

// The three heavy parts (`prepImpl`, `millerImpl`, `equationImpl`) are CPU-dispatched like
// `coreVerify`, so a baseline x86-64 build runs them in the kernel object of the machine's
// tier; the engine struct crosses by pointer (plain slices and integers; the pool pointer is
// never followed on the other side).
pub const BlsEngine = struct {
    items: []const BatchItem,
    lines: *const [pairing.n_lines]pairing.Line,
    pool: ?*Pool,
    lanes: usize,
    leaf: usize,
    keys_in_group: bool,
    /// a_i then b_i, 8 little-endian bytes each; all zero marks an item that failed its group
    /// checks.
    r: [][16]u8,
    /// r_i H(m_i).
    rh: []G1.Affine,
    /// sig_i, 3 sig_i, 5 sig_i, 7 sig_i: four per item.
    ts: []G1.Affine,
    part_f: []Fp12,
    part_s: []G1.Point,
    set: []u32,
    sx: []u32,
    out: []bool,
    budget: usize,
    singles_on_fail: bool,
    /// Updated between the parallel sections only.
    st: BatchStats = .{},

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
            .ts = &.{},
            .part_f = &.{},
            .part_s = &.{},
            .set = &.{},
            .sx = &.{},
            .out = out,
            .budget = 2 * n,
            .singles_on_fail = opts.on_fail == .singles,
        };
        e.drive(gpa, rng);
        if (opts.stats) |s| {
            s.equations += e.st.equations;
            s.failed += e.st.failed;
            s.batch_ok += e.st.batch_ok;
            s.singles += e.st.singles;
        }
    }

    fn drive(e: *BlsEngine, gpa: std.mem.Allocator, rng: std.Random) void {
        const n = e.items.len;
        const out = e.out;
        if (n == 0) return;
        if (n <= e.leaf) return e.singles(null, n);
        e.alloc(gpa, n) catch {
            e.freeAll(gpa);
            return e.singles(null, n);
        };
        defer e.freeAll(gpa);
        e.coefficients(rng);
        // per-item group checks, hash to curve and the scaled points, in parallel
        @memset(out[0..n], false);
        core_forRange(e.pool, n, (n + e.lanes - 1) / e.lanes, e.lanes, PrepJob{ .e = e }, prep);
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
            e.st.batch_ok += set.len;
            return;
        }
        if (e.singles_on_fail) return e.singles(set, 0);
        e.resolveFailed(set);
    }

    /// a_i, b_i for every item of this run, never both zero: a ChaCha stream keyed by
    /// Blake2b-256 over 32 bytes of the caller's `rng` and every item (key, signature, message).
    ///
    /// The soundness of a batch equation rests on whoever chose the items not knowing the
    /// coefficients. Bytes taken straight from `rng` give that only while the caller's
    /// generator is unpredictable: with a weak or replayed one, two wrong items built around
    /// its output cancel (test below). Keyed this way the coefficients are unpredictable when
    /// the rng is, and otherwise are fixed only by the items themselves, signatures included
    /// (the form the Ed25519 batch uses), so no pair can be built around them.
    fn coefficients(e: *BlsEngine, rng: std.Random) void {
        // limbs only, no padding: the bytes hashed are the points
        comptime std.debug.assert(@sizeOf(G2.Affine) == 4 * 48 and @sizeOf(G1.Affine) == 2 * 48);
        var key: [32]u8 = undefined;
        rng.bytes(&key);
        var h = Blake2b256.init();
        h.update("zui bls batch coefficients");
        h.update(&key);
        var len: [8]u8 = undefined;
        std.mem.writeInt(u64, &len, e.items.len, .little);
        h.update(&len);
        for (e.items) |*it| {
            h.update(std.mem.asBytes(&it.pk));
            h.update(std.mem.asBytes(&it.sig));
            std.mem.writeInt(u64, &len, it.msg.len, .little);
            h.update(&len);
            h.update(it.msg);
        }
        h.final(&key);
        var stream = std.Random.ChaCha.init(key);
        const s = stream.random();
        for (e.r) |*r| {
            s.bytes(r);
            if (std.mem.allEqual(u8, r, 0)) r[0] = 1; // all zero marks a failed item
        }
    }

    fn valid(e: *const BlsEngine, i: usize) bool {
        // r is zeroed for an item whose key or signature fails its group check
        return !std.mem.allEqual(u8, &e.r[i], 0);
    }

    fn alloc(e: *BlsEngine, gpa: std.mem.Allocator, n: usize) !void {
        e.r = try gpa.alloc([16]u8, n);
        e.rh = try gpa.alloc(G1.Affine, n);
        e.ts = try gpa.alloc(G1.Affine, 4 * n);
        e.part_f = try gpa.alloc(Fp12, n);
        e.part_s = try gpa.alloc(G1.Point, n);
        e.set = try gpa.alloc(u32, n);
        e.sx = try gpa.alloc(u32, n);
    }

    fn freeAll(e: *BlsEngine, gpa: std.mem.Allocator) void {
        gpa.free(e.r);
        gpa.free(e.rh);
        gpa.free(e.ts);
        gpa.free(e.part_f);
        gpa.free(e.part_s);
        gpa.free(e.set);
        gpa.free(e.sx);
        e.sx = &.{};
        e.r = &.{};
        e.rh = &.{};
        e.ts = &.{};
        e.part_f = &.{};
        e.part_s = &.{};
        e.set = &.{};
    }

    const PrepJob = struct { e: *BlsEngine };

    fn prep(j: PrepJob, lo: usize, hi: usize) void {
        cpu.call("bls_batch_prep", prepImpl, .{ j.e, lo, hi });
    }

    pub fn prepImpl(e: *const BlsEngine, lo: usize, hi: usize) void {
        var s = lo;
        while (s < hi) : (s += prep_chunk) e.prepChunk(s, @min(hi, s + prep_chunk));
    }

    /// Items per affine conversion in `prepChunk` (two inversions per chunk; stack arrays).
    const prep_chunk = 16;

    /// Items lo..hi (at most `prep_chunk`): the per-item group checks, H(m_i), the odd
    /// multiples of H(m_i) and of sig_i, and r_i H(m_i).
    fn prepChunk(e: *const BlsEngine, lo: usize, hi: usize) void {
        const m = hi - lo;
        // per item: H, 3H, 5H, 7H, then sig, 3 sig, 5 sig, 7 sig
        var jac: [8 * prep_chunk]G1.Point = undefined;
        var aff: [8 * prep_chunk]G1.Affine = undefined;
        var scratch: [8 * prep_chunk]curve.Fp = undefined;
        for (lo..hi, 0..) |i, k| {
            const it = e.items[i];
            const t = jac[8 * k ..][0..8];
            // verifyValidated's own checks, in its order: key valid, signature in G1 (or infinity)
            const key_ok = if (e.keys_in_group) !it.pk.isInfinity() else (PublicKey{ .point = it.pk }).validate();
            const ok = key_ok and (it.sig.isInfinity() or curve.g1AffineInGroup(it.sig));
            if (!ok) {
                e.r[i] = @splat(0);
                @memset(t, G1.Point.infinity);
                continue;
            }
            curve.oddMultiples(h2c.hashToG1(it.msg, min_sig_dst), t[0..4]);
            curve.oddMultiples(it.sig.toJacobian(), t[4..8]);
        }
        curve.batchToAffine(G1, jac[0 .. 8 * m], aff[0 .. 8 * m], scratch[0 .. 8 * m]);
        var rh: [prep_chunk]G1.Point = undefined;
        for (lo..hi, 0..) |i, k| {
            @memcpy(e.ts[4 * i ..][0..4], aff[8 * k + 4 ..][0..4]);
            const a = std.mem.readInt(u64, e.r[i][0..8], .little);
            const b = std.mem.readInt(u64, e.r[i][8..16], .little);
            rh[k] = curve.mulGlv(aff[8 * k ..][0..4], a, b); // the identity for a failed item
        }
        curve.batchToAffine(G1, rh[0..m], e.rh[lo..hi], scratch[0..m]);
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

    pub const Partial = struct { f: Fp12, acc: G1.Point };

    fn millerSerial(e: *const BlsEngine, sub: []const u32) Partial {
        return cpu.call("bls_batch_miller", millerImpl, .{ e, sub });
    }

    /// The Miller loops of `sub`'s pairs (r_i H(m_i), pk_i) multiplied together, and
    /// sum r_i sig_i over `sub`.
    pub fn millerImpl(e: *const BlsEngine, sub: []const u32) Partial {
        var f = Fp12.one;
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
        return .{ .f = f, .acc = curve.msmGlv(e.ts, e.r, sub) };
    }

    fn equation(e: *const BlsEngine, f0: Fp12, acc: G1.Point) bool {
        return cpu.call("bls_batch_equation", equationImpl, .{ e.lines, &f0, &acc });
    }

    pub fn equationImpl(lines: *const [pairing.n_lines]pairing.Line, f0: *const Fp12, acc: *const G1.Point) bool {
        const neg = acc.toAffine().neg();
        const f = f0.mul(pairing.millerLoop(&.{}, &.{.{ .p = neg, .lines = lines }}));
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
        const holds = e.equation(f, acc);
        e.st.equations += 1;
        e.st.failed += @intFromBool(!holds);
        return holds;
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
            e.st.batch_ok += left.len;
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
            e.st.batch_ok += set.len;
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
            e.st.equations += 1;
            e.st.failed += @intFromBool(!res[k]);
            if (res[k]) {
                for (sub) |i| e.out[i] = true;
                e.st.batch_ok += sub.len;
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
        e.st.singles += len;
        core_forRange(e.pool, len, 1, e.lanes, SingleJob{ .e = e, .set = set }, singleShare);
    }
};

// ------------------------------------------------------------------------------------------------
// Certificate batches
//
// The contract, and nothing else, is what callers may rely on:
//
//   out[i] == certs[i].committee.verifyAggregateVerdict(certs[i].signers, certs[i].msg, certs[i].agg_sig)
//
// for every i, including which error. How it is kept:
//   - the part of `verifyAggregateVerdict` before its pairing check (signature decode, signer
//     indices, aggregate key) runs per certificate, the same code in the same order, so
//     sig_decode, unknown_signer and the no-signer case are the single path's by construction;
//   - what is left of a certificate is `coreVerify(pk, msg, sig)`. Certificates of a committee
//     with a key outside G2 (`PreparedCommittee.keysInG2` false) get exactly that call;
//   - the rest go into randomized batch equations (`verifyBatchValidated`, keys known in G2).
//     With every key in G2 and every signature group-checked per item, an equation holds
//     whenever all its `coreVerify`s hold, and holds with a failing one among them with
//     probability at most 2^-128. Items of an equation that held are ok; every item of one
//     that did not is decided by `coreVerify` itself.

/// One certificate: the arguments of `PreparedCommittee.verifyAggregateVerdict`.
pub const CertItem = struct {
    committee: *const PreparedCommittee,
    signers: []const u32,
    msg: []const u8,
    agg_sig: *const [48]u8,
};

pub const CertBatchOpts = struct {
    /// null: `core.pool.shared()` (inline when none is installed).
    pool: ?*Pool = null,
    /// At most this many lanes (0: all of the pool).
    max_lanes: usize = 0,
    /// Certificates per batch equation; longer lists run in chunks.
    max_batch: usize = 64,
    /// Counters, added to (never reset here).
    stats: ?*CertBatchStats = null,
};

pub const CertBatchStats = struct {
    /// Certificates decided before any pairing (sig_decode, unknown_signer, no signers).
    early: usize = 0,
    /// Certificates of committees with a key outside G2: the single check, never a batch.
    off_g2: usize = 0,
    /// The batch equations over the rest.
    batch: BatchStats = .{},
    /// Lists that took the single path whole for want of memory.
    no_memory: usize = 0,
};

/// `verifyAggregateVerdict` of every certificate. `rng` must be a CSPRNG outside tests. Never
/// fails: without memory every certificate takes the single path.
pub fn verifyCertBatch(gpa: std.mem.Allocator, certs: []const CertItem, rng: std.Random, opts: CertBatchOpts, out: []CertVerdict) void {
    std.debug.assert(out.len >= certs.len);
    const n = certs.len;
    if (n == 0) return;
    const pool = opts.pool orelse @import("core").pool.shared();
    var w: CertWork = .{ .certs = certs, .out = out[0..n] };
    w.alloc(gpa, n) catch {
        w.free(gpa);
        if (opts.stats) |s| s.no_memory += 1;
        return core_forRange(pool, n, 1, opts.max_lanes, &w, CertWork.wholeShare);
    };
    defer w.free(gpa);
    // per certificate, on every lane: the part before the pairing, and which path decides it
    core_forRange(pool, n, 1, opts.max_lanes, &w, CertWork.prepShare);
    var nb: usize = 0;
    var ns: usize = 0;
    for (w.path, 0..) |p, i| switch (p) {
        .done => {},
        .batch => {
            w.batch_at[nb] = @intCast(i);
            nb += 1;
        },
        .single => {
            w.single_at[ns] = @intCast(i);
            ns += 1;
        },
    };
    if (opts.stats) |s| {
        s.early += n - nb - ns;
        s.off_g2 += ns;
    }
    core_forRange(pool, ns, 1, opts.max_lanes, &w, CertWork.singleShare);
    if (nb == 0) return;
    // the batch items to the front (batch_at increases, so in place), then the equations
    for (w.batch_at[0..nb], 0..) |i, k| w.items[k] = w.items[i];
    verifyBatchValidated(gpa, w.items[0..nb], null, rng, .{
        .pool = pool,
        .max_lanes = opts.max_lanes,
        .max_batch = opts.max_batch,
        .keys_in_group = true,
        .on_fail = .singles,
        .stats = if (opts.stats) |s| &s.batch else null,
    }, w.ok[0..nb]);
    for (w.batch_at[0..nb], w.ok[0..nb]) |i, good| out[i] = if (good) .ok else .invalid;
}

pub const CertWork = struct {
    certs: []const CertItem,
    out: []CertVerdict,
    path: []Path = &.{},
    items: []BatchItem = &.{},
    batch_at: []u32 = &.{},
    single_at: []u32 = &.{},
    ok: []bool = &.{},

    const Path = enum(u8) { done, batch, single };

    fn alloc(w: *CertWork, gpa: std.mem.Allocator, n: usize) !void {
        w.path = try gpa.alloc(Path, n);
        w.items = try gpa.alloc(BatchItem, n);
        w.batch_at = try gpa.alloc(u32, n);
        w.single_at = try gpa.alloc(u32, n);
        w.ok = try gpa.alloc(bool, n);
    }

    fn free(w: *CertWork, gpa: std.mem.Allocator) void {
        gpa.free(w.path);
        gpa.free(w.items);
        gpa.free(w.batch_at);
        gpa.free(w.single_at);
        gpa.free(w.ok);
    }

    fn prepShare(w: *CertWork, lo: usize, hi: usize) void {
        cpu.call("bls_cert_prep", prepImpl, .{ w, lo, hi });
    }

    /// `verifyAggregateVerdictImpl` up to its `coreVerify`: the same steps in the same order.
    pub fn prepImpl(w: *const CertWork, lo: usize, hi: usize) void {
        for (lo..hi) |i| {
            const c = w.certs[i];
            w.path[i] = .done;
            const sig = Signature.decode(c.agg_sig) orelse {
                w.out[i] = .sig_decode;
                continue;
            };
            const pk = switch (c.committee.aggregateKey(c.signers)) {
                .ok => |a| a,
                .unknown_signer => {
                    w.out[i] = .unknown_signer;
                    continue;
                },
                .empty => {
                    w.out[i] = .invalid;
                    continue;
                },
            };
            w.items[i] = .{ .pk = pk, .msg = c.msg, .sig = sig.point };
            w.path[i] = if (c.committee.keysInG2()) .batch else .single;
        }
    }

    fn singleShare(w: *CertWork, lo: usize, hi: usize) void {
        for (w.single_at[lo..hi]) |i| {
            const it = w.items[i];
            w.out[i] = if (coreVerify(it.pk, it.msg, it.sig, w.certs[i].committee.g2_lines)) .ok else .invalid;
        }
    }

    fn wholeShare(w: *CertWork, lo: usize, hi: usize) void {
        for (w.certs[lo..hi], w.out[lo..hi]) |c, *o| o.* = c.committee.verifyAggregateVerdict(c.signers, c.msg, c.agg_sig);
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

/// Compressed bytes of an on-curve point outside the subgroup (small x).
fn offSubgroupBytes(comptime len: usize, comptime Dec: type) [len]u8 {
    var b: [len]u8 = @splat(0);
    var x: u8 = 1;
    while (true) : (x += 1) {
        b[0] = 0x80;
        b[len - 1] = x;
        if (Dec.decode(&b) != null) return b;
    }
}

const TestCommittee = struct {
    prepared: PreparedCommittee,
    /// Each member's secret key; null for a member whose key has none (a point outside G2, the
    /// identity).
    sks: []const ?SecretKey,

    const Special = struct { at: usize, key: [96]u8 };

    fn init(arena: std.mem.Allocator, rng: std.Random, n: usize, special: ?Special) !TestCommittee {
        const keys = try arena.alloc([96]u8, n);
        const sks = try arena.alloc(?SecretKey, n);
        for (keys, sks, 0..) |*k, *s, i| {
            if (special) |sp| if (sp.at == i) {
                k.* = sp.key;
                s.* = null;
                continue;
            };
            var skb: [32]u8 = @splat(0);
            rng.bytes(skb[1..]);
            const sk = SecretKey.fromBytes(&skb).?;
            s.* = sk;
            k.* = sk.publicKey().toBytes();
        }
        return .{ .prepared = try PreparedCommittee.init(arena, keys), .sks = sks };
    }

    /// The aggregate signature of `signers` over `msg`: one signature under the sum of their
    /// secret keys, the same point as the sum of their signatures. Members without a secret
    /// key add nothing.
    fn sign(tc: *const TestCommittee, signers: []const u32, msg: []const u8) [48]u8 {
        const r = @import("consts.zig").r;
        var sum: u256 = 0;
        var seen: [max_committee / 64]u64 = @splat(0);
        for (signers) |i| {
            if (i >= tc.sks.len or (seen[i / 64] >> @intCast(i % 64)) & 1 == 1) continue; // each member once
            seen[i / 64] |= @as(u64, 1) << @intCast(i % 64);
            if (tc.sks[i]) |sk| sum = (sum + std.mem.readInt(u256, &sk.le, .little)) % r; // both below r < 2^255
        }
        if (sum == 0) return encoding.g1Compress(G1.Affine.infinity);
        var le: [32]u8 = undefined;
        std.mem.writeInt(u256, &le, sum, .little);
        return (SecretKey{ .le = le }).sign(msg).toBytes();
    }
};

const cert_kinds = 21;

/// One certificate of `tc`: `kind` picks a valid one (0, 1, 16, 17) or one way of being wrong.
fn testCert(arena: std.mem.Allocator, rng: std.Random, tc: *const TestCommittee, kind: usize) !CertItem {
    const n: u32 = @intCast(tc.sks.len);
    const msg = try arena.alloc(u8, 40 + rng.uintLessThan(usize, 200));
    rng.bytes(msg);
    var set: std.ArrayList(u32) = .empty;
    for (0..n) |i| {
        const in = switch (kind) {
            16 => true, // everyone (the complement path of aggregateKey)
            17 => false, // one signer (added below)
            else => rng.uintLessThan(u8, 4) != 0,
        };
        if (in) try set.append(arena, @intCast(i));
    }
    if (set.items.len == 0) try set.append(arena, rng.uintLessThan(u32, n));
    const sig = try arena.create([48]u8);
    // 3: a valid signature of the same signers over another message
    sig.* = tc.sign(set.items, if (kind == 3) "another message" else msg);
    var cert_msg: []const u8 = msg;
    const not_canonical: [48]u8 = [1]u8{0x9f} ++ @as([47]u8, @splat(0xff)); // x >= p
    switch (kind) {
        0, 3, 16, 17 => {},
        1 => { // signers listed more than once, in any order
            const half = try arena.dupe(u32, set.items[0 .. (set.items.len + 1) / 2]);
            try set.appendSlice(arena, half);
            try set.append(arena, set.items[0]);
            rng.shuffle(u32, set.items);
        },
        2 => { // one byte of the message changed
            const m = try arena.dupe(u8, msg);
            m[rng.uintLessThan(usize, m.len)] ^= 0x10;
            cert_msg = m;
        },
        4, 5 => {
            // 4: a signer is missing from the list; 5: a listed member did not sign
            var absent: ?u32 = null;
            for (0..n) |i| {
                if (std.mem.indexOfScalar(u32, set.items, @intCast(i)) == null) absent = @intCast(i);
            }
            if (kind == 5 and absent != null) {
                try set.append(arena, absent.?);
            } else if (set.items.len > 1) {
                _ = set.swapRemove(rng.uintLessThan(usize, set.items.len));
            } else {
                set.items[0] = (set.items[0] + 1) % n;
            }
        },
        6 => try set.append(arena, n + rng.uintLessThan(u32, 5)), // unknown signer
        7 => set.clearRetainingCapacity(), // no signers
        8 => sig.* = encoding.g1Compress(G1.Affine.infinity), // the identity
        9 => sig.* = offSubgroupBytes(48, Signature), // on the curve, outside G1
        10 => sig[0] &= 0x7f, // compression flag cleared
        11 => { // infinity flag with another bit set
            sig.* = @splat(0);
            sig[0] = 0xc0;
            sig[47] = 1;
        },
        12 => sig.* = not_canonical,
        13 => { // x with no point on the curve
            sig.* = @splat(0);
            sig[0] = 0x80;
            sig[47] = 1;
            while (Signature.decode(sig) != null) sig[47] += 1;
        },
        14 => { // infinity with the sign flag
            sig.* = @splat(0);
            sig[0] = 0xe0;
        },
        15 => sig[1 + rng.uintLessThan(usize, 47)] ^= @as(u8, 1) << rng.uintLessThan(u3, 7), // any bit
        18 => { // only an unknown signer
            set.clearRetainingCapacity();
            try set.append(arena, n);
        },
        19 => { // undecodable signature and an unknown signer: the decode error comes first
            sig.* = not_canonical;
            try set.append(arena, n);
        },
        20 => { // unknown signer first, then repeats
            try set.insert(arena, 0, n + 7);
            try set.append(arena, set.items[1]);
        },
        else => unreachable,
    }
    return .{ .committee = &tc.prepared, .signers = set.items, .msg = cert_msg, .agg_sig = sig };
}

fn expectCertBatch(gpa: std.mem.Allocator, certs: []const CertItem, want: []const CertVerdict, rng: std.Random, opts: CertBatchOpts) !void {
    const got = try gpa.alloc(CertVerdict, certs.len);
    defer gpa.free(got);
    // start from a wrong answer everywhere: every slot must be written
    for (got, want) |*g, w| g.* = if (w == .ok) .invalid else .ok;
    verifyCertBatch(gpa, certs, rng, opts, got);
    try std.testing.expectEqualSlices(CertVerdict, want, got);
}

// The exactness suite of the certificate batch: on random certificates, tampered signatures,
// wrong messages, wrong signer sets, a committee key outside G2, the identity (as signature and
// as key), non-canonical encodings and duplicate signers, the batch verdict of every certificate
// is the single path's, including which error.
test "verifyCertBatch: every certificate gets verifyAggregateVerdict's verdict" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const pool = try Pool.init(std.testing.io, gpa, 4);
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(0xce57);
    const rng = prng.random();

    const bad_key = offSubgroupBytes(96, PublicKey);
    try std.testing.expect(!curve.g2AffineInGroup(PublicKey.decode(&bad_key).?.point));
    var inf_key: [96]u8 = @splat(0);
    inf_key[0] = 0xc0;
    const committees = [_]TestCommittee{
        try TestCommittee.init(arena, rng, 7, null),
        try TestCommittee.init(arena, rng, 4, null),
        try TestCommittee.init(arena, rng, 5, .{ .at = 2, .key = bad_key }), // a key outside G2
        try TestCommittee.init(arena, rng, 5, .{ .at = 1, .key = inf_key }), // the identity as a key
    };
    const nc = committees.len;

    // every kind against every committee, committees interleaved
    var certs: std.ArrayList(CertItem) = .empty;
    for (0..cert_kinds) |kind| {
        for (&committees) |*tc| try certs.append(arena, try testCert(arena, rng, tc, kind));
    }
    // the committee with a key outside G2 (member 2): signed by the others, and listing it
    for ([_][]const u32{ &.{ 0, 1, 3, 4 }, &.{ 0, 1, 2, 3, 4 }, &.{ 4, 0, 4 }, &.{2} }) |signers| {
        const sig = try arena.create([48]u8);
        sig.* = committees[2].sign(signers, "summary");
        try certs.append(arena, .{ .committee = &committees[2].prepared, .signers = signers, .msg = "summary", .agg_sig = sig });
    }
    const want = try arena.alloc(CertVerdict, certs.items.len);
    for (certs.items, want) |c, *w| w.* = c.committee.verifyAggregateVerdict(c.signers, c.msg, c.agg_sig);
    try std.testing.expectEqual(CertVerdict.ok, want[want.len - 4]);
    try std.testing.expectEqual(CertVerdict.ok, want[want.len - 2]);
    try std.testing.expectEqual(CertVerdict.invalid, want[want.len - 3]);
    try std.testing.expectEqual(CertVerdict.invalid, want[want.len - 1]);
    // the kinds are what they say (committee 0: every member has a secret key)
    for ([_]usize{ 0, 1, 16, 17 }) |k| try std.testing.expectEqual(CertVerdict.ok, want[k * nc]);
    for ([_]usize{ 2, 3, 4, 5, 7, 8, 9 }) |k| try std.testing.expectEqual(CertVerdict.invalid, want[k * nc]);
    for ([_]usize{ 6, 18, 20 }) |k| try std.testing.expectEqual(CertVerdict.unknown_signer, want[k * nc]);
    for ([_]usize{ 10, 11, 12, 13, 14, 19 }) |k| try std.testing.expectEqual(CertVerdict.sig_decode, want[k * nc]);

    for ([_]CertBatchOpts{ .{ .pool = pool }, .{ .pool = pool, .max_lanes = 1 }, .{ .pool = pool, .max_batch = 5 }, .{ .pool = pool, .max_batch = 1000 } }) |o| {
        try expectCertBatch(gpa, certs.items, want, rng, o);
    }
    for (0..4) |k| try expectCertBatch(gpa, certs.items[0..k], want[0..k], rng, .{ .pool = pool });

    // valid certificates only (committees 0, 1 and 3; in 3 the identity key signs nothing)
    var valid: std.ArrayList(CertItem) = .empty;
    for (0..24) |i| {
        const kind = ([_]usize{ 0, 1, 16, 17 })[i % 4];
        // a lone signer must have a key: committee 3's identity member alone is no certificate
        const tc = &committees[if (kind == 17) i % 2 else ([_]usize{ 0, 1, 3 })[i % 3]];
        try valid.append(arena, try testCert(arena, rng, tc, kind));
    }
    const all_ok = try arena.alloc(CertVerdict, valid.items.len);
    for (valid.items, all_ok) |c, *w| {
        w.* = c.committee.verifyAggregateVerdict(c.signers, c.msg, c.agg_sig);
        try std.testing.expectEqual(CertVerdict.ok, w.*);
    }
    try expectCertBatch(gpa, valid.items, all_ok, rng, .{ .pool = pool });
    try expectCertBatch(gpa, valid.items, all_ok, rng, .{ .pool = pool, .max_lanes = 1, .max_batch = 7 });

    // every certificate as a batch of one, and between two valid ones (the shortest list that
    // runs a batch equation)
    for (certs.items, want) |c, w| {
        try expectCertBatch(gpa, &.{c}, &.{w}, rng, .{ .pool = pool });
        try expectCertBatch(gpa, &.{ valid.items[0], c, valid.items[1] }, &.{ .ok, w, .ok }, rng, .{ .pool = pool });
    }

    // one wrong certificate at each position of a window of valid ones
    const window = try arena.dupe(CertItem, valid.items[0..9]);
    const wv = try arena.dupe(CertVerdict, all_ok[0..9]);
    for ([_]usize{ 2, 3, 4, 8, 9, 12, 6, 7, 15 }, 0..) |kind, pos| {
        const saved = window[pos];
        window[pos] = try testCert(arena, rng, &committees[pos % 2], kind);
        wv[pos] = window[pos].committee.verifyAggregateVerdict(window[pos].signers, window[pos].msg, window[pos].agg_sig);
        try std.testing.expect(wv[pos] != .ok);
        try expectCertBatch(gpa, window, wv, rng, .{ .pool = pool });
        window[pos] = saved;
        wv[pos] = .ok;
    }
}

// Why `keysInG2` gates the batch: for Q in G2 the pairing is linear in P, e(2P, Q) = e(P, Q)^2,
// and the batch equation's e(r H, pk) is the single check's e(H, pk)^r. For an on-curve Q
// outside G2 the same Miller loop and final exponentiation are not linear in P, so nothing
// ties the batch equation to the single checks.
test "the pairing is linear in its G1 argument for a key in G2, not for one outside" {
    const P = h2c.hashToG1("a message", min_sig_dst);
    const p1 = P.toAffine();
    const p2 = P.dbl().toAffine();
    try std.testing.expect(curve.g1AffineInGroup(p1));
    const e = struct {
        fn f(p: G1.Affine, q: G2.Affine) @import("tower.zig").Fp12 {
            return pairing.finalExp(pairing.millerLoop(&.{.{ .p = p, .q = q }}, &.{}));
        }
    }.f;
    const good = curve.g2_generator;
    const g1v = e(p1, good);
    try std.testing.expect(!g1v.isOne());
    try std.testing.expect(e(p2, good).eql(g1v.mul(g1v)));
    const bad = PublicKey.decode(&offSubgroupBytes(96, PublicKey)).?.point;
    try std.testing.expect(bad.onCurve() and !curve.g2AffineInGroup(bad));
    const b1v = e(p1, bad);
    try std.testing.expect(!e(p2, bad).eql(b1v.mul(b1v)));
}

test "verifyCertBatch: only committees with every key in G2 enter a batch equation" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const pool = try Pool.init(std.testing.io, gpa, 4);
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(0x62);
    const rng = prng.random();
    const in_g2 = try TestCommittee.init(arena, rng, 5, null);
    const off_g2 = try TestCommittee.init(arena, rng, 5, .{ .at = 2, .key = offSubgroupBytes(96, PublicKey) });
    var inf_key: [96]u8 = @splat(0);
    inf_key[0] = 0xc0;
    const with_identity = try TestCommittee.init(arena, rng, 3, .{ .at = 0, .key = inf_key });
    // nothing is checked until asked; the answer is kept, and shared by copies of the struct
    try std.testing.expectEqual(@as(u8, 0), off_g2.prepared.g2_state.load(.monotonic));
    const copy = off_g2.prepared;
    try std.testing.expect(!copy.keysInG2());
    try std.testing.expectEqual(@as(u8, 2), off_g2.prepared.g2_state.load(.monotonic));
    try std.testing.expect(!off_g2.prepared.keysInG2());
    try std.testing.expect(in_g2.prepared.keysInG2());
    try std.testing.expectEqual(@as(u8, 1), in_g2.prepared.g2_state.load(.monotonic));
    try std.testing.expect(with_identity.prepared.keysInG2());

    // 12 valid certificates of the G2 committee, then 6 of the other (signed without member 2)
    var certs: std.ArrayList(CertItem) = .empty;
    for (0..12) |i| try certs.append(arena, try testCert(arena, rng, &in_g2, ([_]usize{ 0, 1, 16 })[i % 3]));
    for (0..6) |i| {
        const msg = try std.fmt.allocPrint(arena, "summary {d}", .{i});
        const sig = try arena.create([48]u8);
        sig.* = off_g2.sign(&.{ 0, 1, 3, 4 }, msg);
        try certs.append(arena, .{ .committee = &off_g2.prepared, .signers = &.{ 0, 1, 3, 4 }, .msg = msg, .agg_sig = sig });
    }
    var out: [18]CertVerdict = undefined;
    var st: CertBatchStats = .{};
    verifyCertBatch(gpa, certs.items, rng, .{ .pool = pool, .stats = &st }, &out);
    for (out) |v| try std.testing.expectEqual(CertVerdict.ok, v);
    // the committee with a key outside G2: six single checks, in no equation
    try std.testing.expectEqual(@as(usize, 6), st.off_g2);
    try std.testing.expectEqual(BatchStats{ .equations = 1, .failed = 0, .batch_ok = 12, .singles = 0 }, st.batch);
    try std.testing.expectEqual(@as(usize, 0), st.early);

    // one wrong certificate: every item of its equation is decided by the single check
    const good3 = certs.items[3];
    certs.items[3] = try testCert(arena, rng, &in_g2, 2);
    st = .{};
    verifyCertBatch(gpa, certs.items, rng, .{ .pool = pool, .stats = &st }, &out);
    for (out, 0..) |v, i| try std.testing.expectEqual(if (i == 3) CertVerdict.invalid else CertVerdict.ok, v);
    try std.testing.expectEqual(BatchStats{ .equations = 1, .failed = 1, .batch_ok = 0, .singles = 12 }, st.batch);
    // in chunks of four only the first chunk falls back
    st = .{};
    verifyCertBatch(gpa, certs.items, rng, .{ .pool = pool, .max_batch = 4, .stats = &st }, &out);
    for (out, 0..) |v, i| try std.testing.expectEqual(if (i == 3) CertVerdict.invalid else CertVerdict.ok, v);
    try std.testing.expectEqual(BatchStats{ .equations = 3, .failed = 1, .batch_ok = 8, .singles = 4 }, st.batch);
    try std.testing.expectEqual(@as(usize, 6), st.off_g2);
    certs.items[3] = good3;

    // decided before any pairing: counted, and in no equation
    certs.items[0] = try testCert(arena, rng, &in_g2, 12);
    certs.items[1] = try testCert(arena, rng, &in_g2, 6);
    st = .{};
    verifyCertBatch(gpa, certs.items, rng, .{ .pool = pool, .stats = &st }, &out);
    try std.testing.expectEqual(CertVerdict.sig_decode, out[0]);
    try std.testing.expectEqual(CertVerdict.unknown_signer, out[1]);
    try std.testing.expectEqual(@as(usize, 2), st.early);
    try std.testing.expectEqual(BatchStats{ .equations = 1, .failed = 0, .batch_ok = 10, .singles = 0 }, st.batch);

    // no memory: the single path for the whole list, the same verdicts
    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    st = .{};
    var out2: [18]CertVerdict = undefined;
    verifyCertBatch(failing.allocator(), certs.items, rng, .{ .pool = pool, .stats = &st }, &out2);
    try std.testing.expectEqualSlices(CertVerdict, &out, &out2);
    try std.testing.expectEqual(@as(usize, 1), st.no_memory);
}

/// `c` with `delta` added to its signature: still a point of G1 for `delta` in G1, and no longer
/// the signature of `c` for a nonzero one.
fn shiftedCert(arena: std.mem.Allocator, c: CertItem, delta: G1.Point) !CertItem {
    const sig = try arena.create([48]u8);
    sig.* = encoding.g1Compress(Signature.decode(c.agg_sig).?.point.toJacobian().add(delta).toAffine());
    var out = c;
    out.agg_sig = sig;
    return out;
}

// Two wrong certificates whose errors cancel when the signatures are simply added (sig_0 + D
// and sig_1 - D): an equation that did not weigh each item by its own coefficient would accept
// the pair. Every list holding them must give them the single path's verdict.
test "verifyCertBatch: wrong certificates whose errors cancel in a plain sum are rejected" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const pool = try Pool.init(std.testing.io, gpa, 4);
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(0xca9ce1);
    const rng = prng.random();
    const tc = try TestCommittee.init(arena, rng, 5, null);
    var good: [5]CertItem = undefined;
    for (&good, 0..) |*c, i| c.* = try testCert(arena, rng, &tc, ([_]usize{ 0, 1, 16 })[i % 3]);
    const d = h2c.hashToG1("a point of G1 that is nobody's signature", min_sig_dst);
    const plus = try shiftedCert(arena, good[0], d);
    const minus = try shiftedCert(arena, good[1], d.neg());
    for ([_]CertItem{ plus, minus }) |c| {
        try std.testing.expect(curve.g1AffineInGroup(Signature.decode(c.agg_sig).?.point));
        try std.testing.expectEqual(CertVerdict.invalid, c.committee.verifyAggregateVerdict(c.signers, c.msg, c.agg_sig));
    }
    const lists = [_][]const CertItem{
        &.{ plus, minus, good[2] },
        &.{ plus, good[2], good[3], minus },
        &.{ good[2], plus, good[3], good[4], minus, good[2] },
        &.{ plus, minus, plus, minus }, // each twice
        &.{ plus, minus },
        &.{ plus, plus, plus }, // one wrong certificate three times
        &.{ good[2], good[2], good[2] }, // one valid certificate three times
    };
    for (lists) |list| {
        const want = try arena.alloc(CertVerdict, list.len);
        for (list, want) |c, *w| w.* = c.committee.verifyAggregateVerdict(c.signers, c.msg, c.agg_sig);
        for ([_]CertBatchOpts{ .{ .pool = pool }, .{ .pool = pool, .max_lanes = 1 } }) |o| try expectCertBatch(gpa, list, want, rng, o);
    }
}

// A committee holding a key and its negative (both in G2): signer sets with both have them
// cancel, down to the identity when nobody else signs. The single path rejects an identity
// aggregate key before anything else; so must every list.
test "verifyCertBatch: an aggregate key that is the identity" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(0x1de);
    const rng = prng.random();
    var sks: [2]SecretKey = undefined;
    for (&sks) |*sk| {
        var skb: [32]u8 = @splat(0);
        rng.bytes(skb[1..]);
        sk.* = SecretKey.fromBytes(&skb).?;
    }
    const keys = [3][96]u8{
        sks[0].publicKey().toBytes(),
        encoding.g2Compress(sks[0].publicKey().point.neg()),
        sks[1].publicKey().toBytes(),
    };
    const committee = try PreparedCommittee.init(arena, &keys);
    try std.testing.expect(committee.keysInG2());
    try std.testing.expect(committee.aggregateKey(&.{ 0, 1 }).ok.isInfinity());
    const msg = "summary";
    const sig2 = sks[1].sign(msg).toBytes();
    const sig0 = sks[0].sign(msg).toBytes();
    const identity = encoding.g1Compress(G1.Affine.infinity);
    const Case = struct { signers: []const u32, sig: *const [48]u8, want: CertVerdict };
    const cases = [_]Case{
        .{ .signers = &.{ 0, 1, 2 }, .sig = &sig2, .want = .ok }, // the pair cancels: member 2's key
        .{ .signers = &.{ 0, 1 }, .sig = &sig2, .want = .invalid }, // the identity as aggregate key
        .{ .signers = &.{ 0, 1 }, .sig = &identity, .want = .invalid }, // and the identity as signature
        .{ .signers = &.{ 1, 0, 1 }, .sig = &sig0, .want = .invalid },
        .{ .signers = &.{2}, .sig = &sig2, .want = .ok },
        .{ .signers = &.{0}, .sig = &sig0, .want = .ok },
        .{ .signers = &.{2}, .sig = &identity, .want = .invalid },
    };
    var certs: [cases.len]CertItem = undefined;
    var want: [cases.len]CertVerdict = undefined;
    for (cases, &certs, &want) |c, *item, *w| {
        item.* = .{ .committee = &committee, .signers = c.signers, .msg = msg, .agg_sig = c.sig };
        w.* = committee.verifyAggregateVerdict(c.signers, msg, c.sig);
        try std.testing.expectEqual(c.want, w.*);
    }
    try expectCertBatch(gpa, &certs, &want, rng, .{});
    try expectCertBatch(gpa, &certs, &want, rng, .{ .max_batch = 3 });
    // the valid ones alone hold as one equation
    var st: CertBatchStats = .{};
    var got: [3]CertVerdict = @splat(.invalid);
    verifyCertBatch(gpa, &.{ certs[0], certs[4], certs[5] }, rng, .{ .stats = &st }, &got);
    try std.testing.expectEqualSlices(CertVerdict, &.{ .ok, .ok, .ok }, &got);
    try std.testing.expectEqual(BatchStats{ .equations = 1, .failed = 0, .batch_ok = 3, .singles = 0 }, st.batch);
}

test "verifyCertBatch: an allocation failure at any point gives the single path's verdicts" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const pool = try Pool.init(std.testing.io, gpa, 2);
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(0xa110c);
    const rng = prng.random();
    const tc = try TestCommittee.init(arena, rng, 4, null);
    // four valid certificates and one with an undecodable signature
    var certs: [5]CertItem = undefined;
    for (&certs, [_]usize{ 0, 16, 12, 1, 0 }) |*c, kind| c.* = try testCert(arena, rng, &tc, kind);
    var want: [5]CertVerdict = undefined;
    for (certs, &want) |c, *w| w.* = c.committee.verifyAggregateVerdict(c.signers, c.msg, c.agg_sig);
    try std.testing.expectEqualSlices(CertVerdict, &.{ .ok, .ok, .sig_decode, .ok, .ok }, &want);
    var failed_runs: usize = 0;
    var index: usize = 0;
    while (true) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = index });
        var st: CertBatchStats = .{};
        var got: [5]CertVerdict = .{ .invalid, .invalid, .ok, .invalid, .invalid };
        verifyCertBatch(failing.allocator(), &certs, rng, .{ .pool = pool, .stats = &st }, &got);
        try std.testing.expectEqualSlices(CertVerdict, &want, &got);
        if (!failing.has_induced_failure) {
            // enough memory: one equation over the four
            try std.testing.expectEqual(BatchStats{ .equations = 1, .failed = 0, .batch_ok = 4, .singles = 0 }, st.batch);
            break;
        }
        // the certificate lists fail first (the whole list by the single path), then the engine's
        try std.testing.expectEqual(@as(usize, 0), st.batch.equations);
        try std.testing.expectEqual(@as(usize, if (st.no_memory == 1) 0 else 4), st.batch.singles);
        failed_runs += 1;
    }
    try std.testing.expect(failed_runs >= 12);
}

// A caller whose rng an attacker can predict (a weak generator, a reused seed). The attacker
// replays it and builds two wrong certificates around the 16 bytes per item a batch draws from
// it: sig_0 + [s_1]D and sig_1 - [s_0]D, so that s_0 sig_0 + s_1 sig_1 is unchanged. The
// coefficients must not be those bytes: the verdicts stay the single path's.
test "verifyCertBatch: wrong certificates built from the rng's own output are rejected" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(0xf0e);
    const tc = try TestCommittee.init(arena, prng.random(), 4, null);
    var certs: [3]CertItem = undefined;
    for (&certs) |*c| c.* = try testCert(arena, prng.random(), &tc, 0);

    const seed = 0x5eed;
    var theirs = std.Random.DefaultPrng.init(seed);
    var r: [3][16]u8 = undefined;
    for (&r) |*x| theirs.random().bytes(x);
    const d = curve.g1_generator.toJacobian();
    const s0_d = d.mulVartime(r[0][0..8], 64).add(curve.sigma(d).mulVartime(r[0][8..16], 64));
    const s1_d = d.mulVartime(r[1][0..8], 64).add(curve.sigma(d).mulVartime(r[1][8..16], 64));
    certs[0] = try shiftedCert(arena, certs[0], s1_d);
    certs[1] = try shiftedCert(arena, certs[1], s0_d.neg());
    var want: [3]CertVerdict = undefined;
    for (certs, &want) |c, *w| w.* = c.committee.verifyAggregateVerdict(c.signers, c.msg, c.agg_sig);
    try std.testing.expectEqualSlices(CertVerdict, &.{ .invalid, .invalid, .ok }, &want);

    var ours = std.Random.DefaultPrng.init(seed);
    var st: CertBatchStats = .{};
    var got: [3]CertVerdict = .{ .ok, .ok, .invalid };
    verifyCertBatch(gpa, &certs, ours.random(), .{ .stats = &st }, &got);
    try std.testing.expectEqualSlices(CertVerdict, &want, &got);
    try std.testing.expectEqual(BatchStats{ .equations = 1, .failed = 1, .batch_ok = 0, .singles = 3 }, st.batch);
}

/// Lanes of the benches' second pass: ZUI_BATCH_BENCH_LANES if set, else every CPU.
fn benchLanes() usize {
    const cpus = std.Thread.getCpuCount() catch 1;
    if (!@import("builtin").link_libc) return cpus;
    const v = std.c.getenv("ZUI_BATCH_BENCH_LANES") orelse return cpus;
    return @max(1, std.fmt.parseInt(usize, std.mem.span(v), 10) catch cpus);
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
    const cpus = benchLanes();
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

// Bench (skipped unless ZUI_BATCH_BENCH is set; run with -Doptimize=ReleaseFast): us per
// checkpoint certificate of a mainnet-sized committee, `verifyAggregateVerdict` against
// `verifyCertBatch` in lists of 16, 64 and 256, on one lane and on all of them.
test "bench: certificates, verifyAggregateVerdict vs verifyCertBatch" {
    if (!@import("builtin").link_libc) return error.SkipZigTest;
    _ = std.c.getenv("ZUI_BATCH_BENCH") orelse return error.SkipZigTest;
    const io = std.testing.io;
    const gpa = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(0xce);
    const rng = prng.random();
    const members = 115;
    const tc = try TestCommittee.init(arena, rng, members, null);
    const n = 256;
    const certs = try arena.alloc(CertItem, n);
    for (certs) |*c| {
        // a quorum-sized signer set: each member signs with probability 7/8
        var set: std.ArrayList(u32) = .empty;
        for (0..members) |i| {
            if (rng.uintLessThan(u8, 8) != 0) try set.append(arena, @intCast(i));
        }
        const msg = try arena.alloc(u8, 200); // about a checkpoint summary's signed bytes
        rng.bytes(msg);
        const sig = try arena.create([48]u8);
        sig.* = tc.sign(set.items, msg);
        c.* = .{ .committee = &tc.prepared, .signers = set.items, .msg = msg, .agg_sig = sig };
    }
    const Clock = struct {
        fn start(i: std.Io) std.Io.Timestamp {
            return std.Io.Timestamp.now(i, .awake);
        }
        fn ns(i: std.Io, t: std.Io.Timestamp) u64 {
            return @intCast(t.durationTo(std.Io.Timestamp.now(i, .awake)).nanoseconds);
        }
    };
    // the once-per-epoch key check
    var t0 = Clock.start(io);
    try std.testing.expect(tc.prepared.keysInG2());
    std.debug.print("bls cert keysInG2 ({d} keys, once per epoch) us={d:.0}\n", .{ members, @as(f64, @floatFromInt(Clock.ns(io, t0))) / 1000.0 });

    const cpus = benchLanes();
    const pool = try Pool.init(io, gpa, cpus);
    defer pool.deinit();
    const out = try arena.alloc(CertVerdict, n);
    var seed: [32]u8 = undefined;
    io.random(&seed);
    var chacha = std.Random.ChaCha.init(seed);
    const crng = chacha.random();
    const Single = struct {
        certs: []const CertItem,
        out: []CertVerdict,
        fn f(c: @This(), lo: usize, hi: usize) void {
            for (c.certs[lo..hi], c.out[lo..hi]) |ct, *o| o.* = ct.committee.verifyAggregateVerdict(ct.signers, ct.msg, ct.agg_sig);
        }
    };
    for ([_]usize{ 1, cpus }) |lanes| {
        var best: u64 = std.math.maxInt(u64);
        for (0..3) |_| {
            t0 = Clock.start(io);
            pool.forRange(n, 1, lanes, Single{ .certs = certs, .out = out }, Single.f);
            best = @min(best, Clock.ns(io, t0));
        }
        for (out) |v| try std.testing.expectEqual(CertVerdict.ok, v);
        const single_us = @as(f64, @floatFromInt(best)) / 1000.0 / n;
        std.debug.print("bls cert lanes={d:<2} single        us/cert={d:.1}\n", .{ lanes, single_us });
        for ([_]usize{ 16, 64, 256 }) |k| {
            var st: CertBatchStats = .{};
            best = std.math.maxInt(u64);
            for (0..3) |_| {
                @memset(out, .invalid);
                t0 = Clock.start(io);
                var lo: usize = 0;
                while (lo < n) : (lo += k) verifyCertBatch(gpa, certs[lo..][0..k], crng, .{ .pool = pool, .max_lanes = lanes, .max_batch = k, .stats = &st }, out[lo..][0..k]);
                best = @min(best, Clock.ns(io, t0));
            }
            for (out) |v| try std.testing.expectEqual(CertVerdict.ok, v);
            try std.testing.expectEqual(@as(usize, 3 * n), st.batch.batch_ok); // every one by a batch equation
            const us = @as(f64, @floatFromInt(best)) / 1000.0 / n;
            std.debug.print("bls cert lanes={d:<2} batch of {d:<3}  us/cert={d:.1}  ({d:.2}x)\n", .{ lanes, k, us, single_us / us });
        }
        // one wrong certificate in 64: the equation fails and all 64 take the single check
        const saved = certs[17].msg;
        certs[17].msg = certs[18].msg;
        best = std.math.maxInt(u64);
        for (0..3) |_| {
            t0 = Clock.start(io);
            verifyCertBatch(gpa, certs[0..64], crng, .{ .pool = pool, .max_lanes = lanes }, out[0..64]);
            best = @min(best, Clock.ns(io, t0));
        }
        try std.testing.expect(out[17] == .invalid and out[16] == .ok and out[18] == .ok);
        certs[17].msg = saved;
        std.debug.print("bls cert lanes={d:<2} batch of 64, one wrong us/cert={d:.1}\n", .{ lanes, @as(f64, @floatFromInt(best)) / 1000.0 / 64.0 });
    }
}
