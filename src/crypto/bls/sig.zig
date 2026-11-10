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
