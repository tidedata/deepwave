//! fastcrypto-tbls `nizk`: the Fiat-Shamir proofs over G2 used by the DKG (the group is G2 for
//! both the public key and the encryption key at mainnet-v1.83.1).
//!   DdhTupleNizk: proves (x_g, x_h) = (x*G, x*H); wire (A, B, z) = 96 + 96 + 32 bytes.
//!   DLNizk: proves x_g = x*G; wire (A, z).
//! Deserialization rejects a zero element or a zero z, exactly as the Rust `Deserialize` does.
const std = @import("std");
const group = @import("group.zig");
const wire = @import("wire.zig");
const oracle = @import("oracle.zig");
const G2 = group.G2;
const G2P = group.G2P;
const Scalar = group.Scalar;

pub const Error = error{InvalidProof} || oracle.RandomOracle.Error;

fn challenge(ro: *const oracle.RandomOracle, parts: []const G2P) Scalar {
    var buf: [6 * 96]u8 = undefined;
    var n: usize = 0;
    // the generator first (the Rust tuple starts with G::generator())
    buf[0..96].* = group.g2ToBytes(group.g2Generator());
    n = 96;
    for (parts) |p| {
        buf[n..][0..96].* = group.g2ToBytes(p);
        n += 96;
    }
    return ro.evaluateToScalar(buf[0..n]);
}

fn validRelation(e1: G2P, e2: G2P, e3: G2P, z: Scalar, c: Scalar) bool {
    const left = e1.add(group.mulPublic(G2, e2, c));
    const right = group.mulPublic(G2, e3, z);
    return left.eql(right);
}

pub const DdhTupleNizk = struct {
    a: G2P,
    b: G2P,
    z: Scalar,

    pub const wire_len = 96 + 96 + 32;

    pub fn create(x: Scalar, h: G2P, x_g: G2P, x_h: G2P, ro: *const oracle.RandomOracle, rng: std.Random) DdhTupleNizk {
        const r = group.scalarRand(rng);
        const a = group.mulSecret(G2, group.g2Generator(), r);
        const b = group.mulSecret(G2, h, r);
        const c = challenge(ro, &.{ h, x_g, x_h, a, b });
        const z = c.mul(x).add(r);
        return .{ .a = a, .b = b, .z = z };
    }

    pub fn verify(self: *const DdhTupleNizk, h: G2P, x_g: G2P, x_h: G2P, ro: *const oracle.RandomOracle) Error!void {
        if (group.g2IsZero(h) or group.g2IsZero(x_g) or group.g2IsZero(x_h)) return error.InvalidProof;
        const c = challenge(ro, &.{ h, x_g, x_h, self.a, self.b });
        if (!validRelation(self.a, x_g, group.g2Generator(), self.z, c) or
            !validRelation(self.b, x_h, h, self.z, c)) return error.InvalidProof;
    }

    pub fn encode(self: *const DdhTupleNizk, w: *wire.Writer) wire.Error!void {
        try w.g2(self.a);
        try w.g2(self.b);
        try w.scalar(self.z);
    }

    pub fn decode(r: *wire.Reader) wire.Error!DdhTupleNizk {
        const a = try r.g2();
        const b = try r.g2();
        const z = try r.scalar();
        if (group.g2IsZero(a) or group.g2IsZero(b) or z.isZero()) return error.InvalidEncoding;
        return .{ .a = a, .b = b, .z = z };
    }
};

pub const DLNizk = struct {
    a: G2P,
    z: Scalar,

    pub fn create(x: Scalar, x_g: G2P, ro: *const oracle.RandomOracle, rng: std.Random) DLNizk {
        const r = group.scalarRand(rng);
        const a = group.mulSecret(G2, group.g2Generator(), r);
        const c = challenge(ro, &.{ x_g, a });
        return .{ .a = a, .z = c.mul(x).add(r) };
    }

    pub fn verify(self: *const DLNizk, x_g: G2P, ro: *const oracle.RandomOracle) Error!void {
        if (group.g2IsZero(x_g)) return error.InvalidProof;
        const c = challenge(ro, &.{ x_g, self.a });
        if (!validRelation(self.a, x_g, group.g2Generator(), self.z, c)) return error.InvalidProof;
    }
};

test "ddh tuple nizk verifies and rejects" {
    var prng = std.Random.DefaultPrng.init(42);
    const rng = prng.random();
    const x = group.scalarRand(rng);
    const h = group.mulPublic(G2, group.g2Generator(), group.scalarRand(rng));
    const x_g = group.mulPublic(G2, group.g2Generator(), x);
    const x_h = group.mulPublic(G2, h, x);
    const ro = try oracle.RandomOracle.init("test");
    const p = DdhTupleNizk.create(x, h, x_g, x_h, &ro, rng);
    try p.verify(h, x_g, x_h, &ro);
    try std.testing.expectError(error.InvalidProof, p.verify(h, x_g, x_g, &ro));
    const other = try oracle.RandomOracle.init("test2");
    try std.testing.expectError(error.InvalidProof, p.verify(h, x_g, x_h, &other));
}

test "dl nizk" {
    var prng = std.Random.DefaultPrng.init(43);
    const rng = prng.random();
    const x = group.scalarRand(rng);
    const x_g = group.mulPublic(G2, group.g2Generator(), x);
    const ro = try oracle.RandomOracle.init("dl");
    const p = DLNizk.create(x, x_g, &ro, rng);
    try p.verify(x_g, &ro);
    try std.testing.expectError(error.InvalidProof, p.verify(group.g2Generator(), &ro));
}
