//! fastcrypto-tbls `tbls` + `types::ThresholdBls12381MinSig`: threshold BLS with min-sig keys
//! (signatures in G1, public keys and the VSS polynomial in G2). The random beacon at
//! mainnet-v1.83.1 signs `signature_message(round)` with each share, sends the partial
//! signatures, and anyone with `t` valid partials recovers the unique full signature whose bytes
//! are the round's randomness.
const std = @import("std");
const group = @import("group.zig");
const wire = @import("wire.zig");
const poly = @import("poly.zig");
const Scalar = group.Scalar;
const G1 = group.G1;
const G2 = group.G2;
const G1P = group.G1P;
const G2P = group.G2P;

pub const Error = error{ InvalidSignature, NotEnoughInputs, InvalidInput } || std.mem.Allocator.Error;

/// A partial signature: share index (1-based) and the G1 element [share] H(msg).
pub const PartialSignature = struct {
    index: u16,
    value: G1P,

    pub const wire_len = 2 + 48;

    pub fn encode(self: *const PartialSignature, w: *wire.Writer) wire.Error!void {
        try w.u16_(self.index);
        try w.g1(self.value);
    }

    /// BCS of one `IndexedValue<G1Element>`; index 0 is rejected (NonZeroU16).
    pub fn decode(r: *wire.Reader) wire.Error!PartialSignature {
        const i = try r.u16_();
        if (i == 0) return error.InvalidEncoding;
        return .{ .index = i, .value = try r.g1() };
    }

    pub fn fromBytes(bytes: []const u8) wire.Error!PartialSignature {
        var r = wire.Reader.init(bytes);
        const p = try decode(&r);
        try r.finish();
        return p;
    }

    pub fn toBytes(self: *const PartialSignature) [wire_len]u8 {
        var out: [wire_len]u8 = undefined;
        std.mem.writeInt(u16, out[0..2], self.index, .little);
        out[2..50].* = group.g1ToBytes(self.value);
        return out;
    }
};

/// `ThresholdBls::verify`: e(sig, g2) == e(H(msg), pk).
pub fn verify(pk: G2P, msg: []const u8, sig: G1P) Error!void {
    const h = group.hashToG1(msg);
    if (!group.pairingEqG1G2(sig, h, pk)) return error.InvalidSignature;
}

pub fn partialSign(share: poly.Share, msg: []const u8) PartialSignature {
    const h = group.hashToG1(msg);
    return .{ .index = share.index, .value = group.mulSecret(G1, h, share.value) };
}

/// `partial_sign_batch`: one hash to curve for all shares of this party.
pub fn partialSignBatch(arena: std.mem.Allocator, shares: []const poly.Share, msg: []const u8) std.mem.Allocator.Error![]PartialSignature {
    const h = group.hashToG1(msg);
    const out = try arena.alloc(PartialSignature, shares.len);
    for (shares, out) |s, *o| o.* = .{ .index = s.index, .value = group.mulSecret(G1, h, s.value) };
    return out;
}

/// `partial_verify`: against the public VSS polynomial.
pub fn partialVerify(vss_pk: []const G2P, msg: []const u8, ps: PartialSignature) Error!void {
    const pk_i = poly.evalPublic(G2, vss_pk, ps.index);
    try verify(pk_i, msg, ps.value);
}

/// `partial_verify_batch`: random linear combination, one pairing check.
pub fn partialVerifyBatch(arena: std.mem.Allocator, vss_pk: []const G2P, msg: []const u8, sigs: []const PartialSignature, rng: std.Random) Error!void {
    if (poly.degreeBound(vss_pk.len) == 0 and msg.len == 0) return error.InvalidInput;
    if (sigs.len == 0) return;
    const rs = try arena.alloc(Scalar, sigs.len);
    const xs = try arena.alloc(Scalar, sigs.len);
    const pts = try arena.alloc(G1P, sigs.len);
    for (sigs, rs, xs, pts) |s, *r, *x, *p| {
        r.* = group.scalarRandSmall(rng);
        x.* = Scalar.fromU64(s.index);
        p.* = s.value;
    }
    if (poly.degreeBound(vss_pk.len) == 0) return error.InvalidInput;
    const coeffs = poly.batchCoefficients(arena, rs, xs, poly.degreeBound(vss_pk.len)) catch return error.InvalidInput;
    const pk = group.msm(G2, coeffs, vss_pk) catch return error.InvalidInput;
    const agg = group.msm(G1, rs, pts) catch return error.InvalidInput;
    try verify(pk, msg, agg);
}

/// `aggregate`: the first `threshold` partials with distinct indices (input order), recovered at
/// zero. NotEnoughInputs when fewer are available.
pub fn aggregate(arena: std.mem.Allocator, threshold: u16, partials: []const PartialSignature) Error!G1P {
    const idx = try arena.alloc(u16, threshold);
    const vals = try arena.alloc(G1P, threshold);
    var n: usize = 0;
    outer: for (partials) |p| {
        for (idx[0..n]) |seen| if (seen == p.index) continue :outer;
        if (n == threshold) break;
        idx[n] = p.index;
        vals[n] = p.value;
        n += 1;
    }
    if (n != threshold) return error.NotEnoughInputs;
    return poly.recoverC0Group(G1, arena, threshold, idx, vals) catch error.InvalidInput;
}

/// `RandomnessRound::signature_message`: "random_beacon round " ++ BCS(u64 round).
pub fn roundMessage(round: u64) [20 + 8]u8 {
    var out: [28]u8 = undefined;
    @memcpy(out[0..20], "random_beacon round ");
    std.mem.writeInt(u64, out[20..28], round, .little);
    return out;
}

test "threshold sign, partial verify, aggregate" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(5);
    const rng = prng.random();
    const t: u16 = 3;
    const sk = try poly.randPrivate(a, t - 1, rng);
    const vss = try poly.commit(a, sk);
    const msg = roundMessage(42);
    var parts: [6]PartialSignature = undefined;
    for (0..6) |i| {
        const idx: u16 = @intCast(i + 1);
        parts[i] = partialSign(.{ .index = idx, .value = poly.evalPrivate(sk, idx) }, &msg);
        try partialVerify(vss, &msg, parts[i]);
    }
    try partialVerifyBatch(a, vss, &msg, &parts, rng);
    const sig = try aggregate(a, t, parts[2..]);
    try verify(vss[0], &msg, sig);
    // another subset recovers the same signature
    const sig2 = try aggregate(a, t, parts[0..4]);
    try std.testing.expect(sig.eql(sig2));
    // a tampered partial fails the batch
    parts[1].value = parts[1].value.dbl();
    try std.testing.expectError(error.InvalidSignature, partialVerifyBatch(a, vss, &msg, &parts, rng));
    try std.testing.expectError(error.NotEnoughInputs, aggregate(a, t, parts[0..2]));
}
