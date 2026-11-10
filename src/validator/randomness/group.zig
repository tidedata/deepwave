//! BLS12-381 group plumbing for fastcrypto-tbls semantics (fastcrypto `groups::bls12381`):
//! scalars, G1/G2 points, their serde byte forms, multi-scalar multiplication, hash to group,
//! and the pairing equality check, all on src/crypto/bls.
//!
//! Serde forms (what BCS carries): scalar 32 bytes big-endian (< r, `from_byte_array`), G1 48 and
//! G2 96 bytes compressed, fixed size with no length prefix. Deserialising a point checks the
//! subgroup (`from_byte_array`: `blst_p2_in_g2`), the point at infinity is accepted.
//!
//! Secret scalars (private keys, DKG polynomials, shares) always go through `mulCt` and
//! `scalarBytesLe` is only used on public values for the variable time paths.
const std = @import("std");
const bls = @import("bls");

pub const curve = bls.curve;
pub const Scalar = bls.Fr;
pub const G1 = curve.G1;
pub const G2 = curve.G2;
pub const G1P = G1.Point;
pub const G2P = G2.Point;

pub const scalar_len = 32;
pub const g1_len = 48;
pub const g2_len = 96;

/// fastcrypto `min_pk::DST_G2` (hash to G2) and `min_sig::DST_G1` (hash to G1).
pub const dst_g2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
pub const dst_g1 = bls.min_sig_dst;

pub const Error = error{ InvalidInput, NotEnoughInputs };

// ---------------------------------------------------------------------------------------------
// scalars

pub fn scalarFromU64(x: u64) Scalar {
    return Scalar.fromU64(x);
}

pub fn scalarToBytes(s: Scalar) [32]u8 {
    return s.toBytesBE();
}

/// `Scalar::from_byte_array`: canonical big-endian, must be < r.
pub fn scalarFromBytes(b: *const [32]u8) ?Scalar {
    return Scalar.fromBytesBE(b);
}

/// Little-endian bytes for the point multiplication routines.
pub fn scalarBytesLe(s: Scalar) [32]u8 {
    const be = s.toBytesBE();
    var out: [32]u8 = undefined;
    for (0..32) |i| out[i] = be[31 - i];
    return out;
}

const two_256 = blk: {
    // 2^256 mod r as a field element.
    @setEvalBranchQuota(100_000);
    const r = @import("bls").field.r_int;
    const x: u512 = (@as(u512, 1) << 256) % @as(u512, r);
    break :blk Scalar.fromInt(@intCast(x));
};

/// `buffer_to_scalar_mod_r` (blst_scalar_from_be_bytes): a 48..64 byte big-endian number reduced
/// mod r. Used for Fiat-Shamir challenges (SHA3-512 output) and random scalars.
pub fn scalarReduceWide(buf: []const u8) Scalar {
    std.debug.assert(buf.len >= 32 and buf.len <= 64);
    const hi_len = buf.len - 32;
    var hi_b: [32]u8 = @splat(0);
    @memcpy(hi_b[32 - hi_len ..], buf[0..hi_len]);
    var lo_b: [32]u8 = undefined;
    @memcpy(&lo_b, buf[hi_len..]);
    const hi = Scalar.fromBytesBEReduce(&hi_b);
    const lo = Scalar.fromBytesBEReduce(&lo_b);
    return hi.mul(two_256).add(lo);
}

/// `ScalarType::rand`: 64 random bytes reduced mod r.
pub fn scalarRand(rng: std.Random) Scalar {
    var b: [64]u8 = undefined;
    rng.bytes(&b);
    defer std.crypto.secureZero(u8, &b);
    return scalarReduceWide(&b);
}

/// Small random scalar for batch verification (`get_random_scalars`: a u64).
pub fn scalarRandSmall(rng: std.Random) Scalar {
    return Scalar.fromU64(rng.int(u64));
}

/// 1/s; null for zero (fastcrypto returns an error).
pub fn scalarInv(s: Scalar) ?Scalar {
    if (s.isZero()) return null;
    return s.inv();
}

pub fn scalarIsZero(s: Scalar) bool {
    return s.isZero();
}

// ---------------------------------------------------------------------------------------------
// points

pub fn g2Generator() G2P {
    return curve.g2_generator.toJacobian();
}

pub fn g1Generator() G1P {
    return curve.g1_generator.toJacobian();
}

pub fn g2IsZero(p: G2P) bool {
    return p.toAffine().isInfinity();
}

pub fn g1IsZero(p: G1P) bool {
    return p.toAffine().isInfinity();
}

pub fn g2Eql(a: G2P, b: G2P) bool {
    return a.eql(b);
}

pub fn g1Eql(a: G1P, b: G1P) bool {
    return a.eql(b);
}

/// [s]P for a secret scalar (constant time).
pub fn mulSecret(comptime C: type, p: C.Point, s: Scalar) C.Point {
    var k = scalarBytesLe(s);
    defer std.crypto.secureZero(u8, &k);
    return p.mulCt(&k);
}

/// [s]P for a public scalar (variable time).
pub fn mulPublic(comptime C: type, p: C.Point, s: Scalar) C.Point {
    const k = scalarBytesLe(s);
    return p.mulVartime(&k, 255);
}

/// [x]P for a small public integer (share indexes).
pub fn mulSmall(comptime C: type, p: C.Point, x: u64) C.Point {
    var k: [8]u8 = undefined;
    std.mem.writeInt(u64, &k, x, .little);
    return p.mulVartime(&k, 64);
}

pub fn g2ToBytes(p: G2P) [96]u8 {
    return bls.encoding.g2Compress(p.toAffine());
}

pub fn g1ToBytes(p: G1P) [48]u8 {
    return bls.encoding.g1Compress(p.toAffine());
}

/// `G2Element::from_byte_array`: decode, then the subgroup check.
pub fn g2FromBytes(b: *const [96]u8) ?G2P {
    const a = switch (bls.encoding.g2Uncompress(b)) {
        .ok => |a| a,
        .err => return null,
    };
    if (a.isInfinity()) return G2P.infinity;
    if (!curve.g2AffineInGroup(a)) return null;
    return a.toJacobian();
}

pub fn g1FromBytes(b: *const [48]u8) ?G1P {
    const a = switch (bls.encoding.g1Uncompress(b)) {
        .ok => |a| a,
        .err => return null,
    };
    if (a.isInfinity()) return G1P.infinity;
    if (!curve.g1AffineInGroup(a)) return null;
    return a.toJacobian();
}

pub fn hashToG2(msg: []const u8) G2P {
    return bls.hash_to_curve.hashToG2(msg, dst_g2);
}

pub fn hashToG1(msg: []const u8) G1P {
    return bls.hash_to_curve.hashToG1(msg, dst_g1);
}

/// e(sig, g2) == e(H, pk) with H already hashed (the tbls `verify` core).
pub fn pairingEqG1G2(sig: G1P, h: G1P, pk: G2P) bool {
    const pairs = [_]bls.PairingInput{
        .{ sig.toAffine(), curve.g2_generator },
        .{ h.neg().toAffine(), pk.toAffine() },
    };
    return bls.pairingCheck(&pairs);
}

// ---------------------------------------------------------------------------------------------
// multi scalar multiplication (variable time: public scalars only, or scalars that are blinded
// by the caller; DKG verification scalars are public)

/// sum s_i P_i by bucket windows (Pippenger). Zero scalars and points are skipped like fastcrypto.
pub fn msm(comptime C: type, scalars: []const Scalar, points: []const C.Point) Error!C.Point {
    if (scalars.len != points.len or scalars.len == 0) return error.InvalidInput;
    const n = scalars.len;
    if (n <= 4) {
        var acc = C.Point.infinity;
        for (scalars, points) |s, p| {
            if (s.isZero()) continue;
            acc = acc.add(mulPublic(C, p, s));
        }
        return acc;
    }
    const w: usize = if (n < 32) 4 else if (n < 256) 6 else 8;
    const nbuckets = (@as(usize, 1) << @intCast(w)) - 1;
    const windows = (255 + w - 1) / w;
    var buckets: [255]C.Point = undefined; // w <= 8
    // One pass of scalar bytes per window; scalars as LE bytes are cached on the stack in chunks.
    var acc = C.Point.infinity;
    var win: usize = windows;
    while (win > 0) {
        win -= 1;
        var i: usize = 0;
        while (i < w) : (i += 1) acc = acc.dbl();
        for (buckets[0..nbuckets]) |*b| b.* = C.Point.infinity;
        const shift = win * w;
        for (scalars, points) |s, p| {
            if (s.isZero()) continue;
            const k = scalarBytesLe(s);
            var d: usize = 0;
            var j: usize = 0;
            while (j < w) : (j += 1) {
                const bit = shift + j;
                if (bit < 256 and (k[bit / 8] >> @intCast(bit % 8)) & 1 == 1) d |= @as(usize, 1) << @intCast(j);
            }
            if (d != 0) buckets[d - 1] = buckets[d - 1].add(p);
        }
        var run = C.Point.infinity;
        var tot = C.Point.infinity;
        var bi: usize = nbuckets;
        while (bi > 0) {
            bi -= 1;
            run = run.add(buckets[bi]);
            tot = tot.add(run);
        }
        acc = acc.add(tot);
    }
    return acc;
}

test "scalar reduce wide matches arithmetic" {
    // 2^256 mod r times one plus zero: buffer = 1 || 32 zero bytes (33 bytes is not in 48..64,
    // use 48 so hi is 16 bytes).
    var buf: [48]u8 = @splat(0);
    buf[15] = 1; // hi = 1 (big-endian 16 bytes), lo = 0
    const s = scalarReduceWide(&buf);
    try std.testing.expect(s.eql(two_256));
}

test "g2 serde roundtrip and msm" {
    const g = g2Generator();
    const b = g2ToBytes(g);
    const back = g2FromBytes(&b).?;
    try std.testing.expect(back.eql(g));
    var sc: [9]Scalar = undefined;
    var pts: [9]G2P = undefined;
    var want = G2P.infinity;
    var prng = std.Random.DefaultPrng.init(1);
    for (0..9) |i| {
        sc[i] = scalarRand(prng.random());
        pts[i] = mulPublic(G2, g, scalarRand(prng.random()));
        want = want.add(mulPublic(G2, pts[i], sc[i]));
    }
    const got = try msm(G2, &sc, &pts);
    try std.testing.expect(got.eql(want));
}
