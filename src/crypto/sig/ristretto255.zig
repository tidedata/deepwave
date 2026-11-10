//! ristretto255 (RFC 9496) as curve25519-dalek 4.1 implements it, which is what fastcrypto's
//! `groups::ristretto255` wraps; plus `EllipticCurveMultisetHash` (fastcrypto `hash.rs`, the
//! state accumulator of sui-core's GlobalStateHasher) and RFC 9380 `expand_message_xmd` with
//! SHA-512 for `hash_to_ristretto255_with_dst`.
//!
//! Points are Edwards points in extended coordinates (the even subgroup representative of the
//! Ristretto class). Decoding and encoding follow dalek step by step; `fromUniform` evaluates its
//! two Elligator maps with their square roots interleaved.
//!
//! Decoding, encoding and the map are constant time apart from the final validity branch on
//! public data; scalar multiplication by secrets uses `ed25519.mulCT` / `mulBaseCT`.
const std = @import("std");
const hash = @import("hash");
const ed = @import("ed25519.zig");

const Fe = ed.Fe;
const Point = ed.Point;
const Sha512 = hash.Sha512;
const Sha256 = hash.Sha256;

fn feStd(comptime x: std.crypto.ecc.Edwards25519.Fe) Fe {
    const b = x.toBytes();
    return Fe.fromBytes(&b);
}

const StdFe = std.crypto.ecc.Edwards25519.Fe;
const invsqrt_a_minus_d: Fe = feStd(StdFe.edwards25519sqrtamd);
const one_minus_d_sq: Fe = feStd(StdFe.edwards25519eonemsqd);
const d_minus_one_sq: Fe = feStd(StdFe.edwards25519sqdmone);
const sqrt_ad_minus_one: Fe = feStd(StdFe.edwards25519sqrtadm1);
const minus_one: Fe = Fe.zero.sub(Fe.one);

pub const Ristretto = struct {
    p: Point,

    pub const identity: Ristretto = .{ .p = Point.identity };
    pub const generator: Ristretto = .{ .p = ed.basepoint };

    /// dalek `CompressedRistretto::decompress`: null unless s is canonical, nonnegative and the
    /// point is valid.
    pub fn decode(bytes: *const [32]u8) ?Ristretto {
        const s = Fe.fromBytes(bytes);
        if (!std.mem.eql(u8, &s.toBytes(), bytes)) return null; // also rejects bit 255 set
        if (s.isNegative()) return null;
        const ss = s.sq();
        const u_1 = Fe.one.sub(ss);
        const u_2 = Fe.one.add(ss);
        const u_2_sq = u_2.sq();
        const v = Fe.d.mul(u_1.sq()).neg().sub(u_2_sq);
        const inv = Fe.sqrtRatioI(Fe.one, v.mul(u_2_sq));
        const dx = inv.r.mul(u_2);
        const dy = inv.r.mul(dx).mul(v);
        var x = s.add(s).mul(dx);
        if (x.isNegative()) x = x.neg();
        const y = u_1.mul(dy);
        const t = x.mul(y);
        if (!inv.ok or t.isNegative() or y.isZero()) return null;
        return .{ .p = .{ .x = x, .y = y, .z = Fe.one, .t = t } };
    }

    /// dalek `RistrettoPoint::compress`.
    pub fn encode(r: Ristretto) [32]u8 {
        var X = r.p.x;
        var Y = r.p.y;
        const Z = r.p.z;
        const T = r.p.t;
        const u_1 = Z.add(Y).mul(Z.sub(Y));
        const u_2 = X.mul(Y);
        const inv = Fe.sqrtRatioI(Fe.one, u_1.mul(u_2.sq()));
        const i_1 = inv.r.mul(u_1);
        const i_2 = inv.r.mul(u_2);
        const z_inv = i_1.mul(i_2.mul(T));
        var den_inv = i_2;
        const iX = X.mul(Fe.sqrtm1);
        const iY = Y.mul(Fe.sqrtm1);
        const enchanted = i_1.mul(invsqrt_a_minus_d);
        const rotate = T.mul(z_inv).isNegative();
        X.cMov(iY, rotate);
        Y.cMov(iX, rotate);
        den_inv.cMov(enchanted, rotate);
        Y.cMov(Y.neg(), X.mul(z_inv).isNegative());
        var s = den_inv.mul(Z.sub(Y));
        s.cMov(s.neg(), s.isNegative());
        return s.toBytes();
    }

    pub fn add(a: Ristretto, b: Ristretto) Ristretto {
        return .{ .p = a.p.add(b.p) };
    }

    pub fn sub(a: Ristretto, b: Ristretto) Ristretto {
        return .{ .p = a.p.sub(b.p) };
    }

    /// dalek `RistrettoPoint::ct_eq`: X1*Y2 == Y1*X2 or Y1*Y2 == X1*X2.
    pub fn eql(a: Ristretto, b: Ristretto) bool {
        const c1 = a.p.x.mul(b.p.y).eql(a.p.y.mul(b.p.x));
        const c2 = a.p.y.mul(b.p.y).eql(a.p.x.mul(b.p.x));
        return c1 or c2;
    }

    pub fn isIdentity(a: Ristretto) bool {
        return a.eql(identity);
    }

    /// dalek `RistrettoPoint::from_uniform_bytes` (ristretto255_map): two Elligator maps, added.
    pub fn fromUniform(bytes: *const [64]u8) Ristretto {
        var b0: [32]u8 = bytes[0..32].*;
        var b1: [32]u8 = bytes[32..64].*;
        b0[31] &= 0x7f;
        b1[31] &= 0x7f;
        const pts = elligator2(Fe.fromBytes(&b0), Fe.fromBytes(&b1));
        return .{ .p = pts[0].add(pts[1]) };
    }

    /// fastcrypto `RistrettoPoint::hash_to_group_element`: SHA-512 of the message, then the map.
    pub fn hashToGroup(msg: []const u8) Ristretto {
        var d: [64]u8 = undefined;
        Sha512.hash(msg, &d);
        return fromUniform(&d);
    }

    /// fastcrypto `hash_to_ristretto255_with_dst(msgs, dst)`: expand_message_xmd(SHA-512,
    /// concatenation of msgs, dst, 64), then the map.
    pub fn hashWithDst(msgs: []const []const u8, dst: []const u8) Ristretto {
        const u = expandMessageXmd64(msgs, dst);
        return fromUniform(&u);
    }
};

/// dalek `elligator_ristretto_flavor` on two inputs, square roots interleaved.
fn elligator2(r0a: Fe, r0b: Fe) [2]Point {
    const r0 = [2]Fe{ r0a, r0b };
    var r: [2]Fe = undefined;
    var ns: [2]Fe = undefined;
    var dd: [2]Fe = undefined;
    for (0..2) |j| {
        r[j] = Fe.sqrtm1.mul(r0[j].sq());
        ns[j] = r[j].add(Fe.one).mul(one_minus_d_sq);
        dd[j] = minus_one.sub(Fe.d.mul(r[j])).mul(r[j].add(Fe.d));
    }
    const sr = ed.sqrtRatioI2(ns[0], dd[0], ns[1], dd[1]);
    var out: [2]Point = undefined;
    for (0..2) |j| {
        var s = sr[j].r;
        var c = minus_one;
        var s_prime = s.mul(r0[j]);
        s_prime.cMov(s_prime.neg(), !s_prime.isNegative());
        s.cMov(s_prime, !sr[j].ok);
        c.cMov(r[j], !sr[j].ok);
        const nt = c.mul(r[j].sub(Fe.one)).mul(d_minus_one_sq).sub(dd[j]);
        const s_sq = s.sq();
        const comp: ed.Completed = .{
            .x = s.add(s).mul(dd[j]),
            .z = nt.mul(sqrt_ad_minus_one),
            .y = Fe.one.sub(s_sq),
            .t = Fe.one.add(s_sq),
        };
        out[j] = comp.toExtended();
    }
    return out;
}

/// RFC 9380 5.3.1 expand_message_xmd with SHA-512 and len_in_bytes = 64 (ell = 1), messages
/// concatenated. `dst` must be at most 255 bytes.
pub fn expandMessageXmd64(msgs: []const []const u8, dst: []const u8) [64]u8 {
    std.debug.assert(dst.len <= 255);
    const dlen: u8 = @intCast(dst.len);
    var h = Sha512.init();
    const zpad: [128]u8 = @splat(0);
    h.update(&zpad);
    for (msgs) |m| h.update(m);
    h.update(&.{ 0, 64, 0 }); // I2OSP(64, 2) || I2OSP(0, 1)
    h.update(dst);
    h.update(&.{dlen});
    var b0: [64]u8 = undefined;
    h.final(&b0);
    var h1 = Sha512.init();
    h1.update(&b0);
    h1.update(&.{1});
    h1.update(dst);
    h1.update(&.{dlen});
    var b1: [64]u8 = undefined;
    h1.final(&b1);
    return b1;
}

// ---------------------------------------------------------------------------------------------
// EllipticCurveMultisetHash

/// fastcrypto `EllipticCurveMultisetHash`: the sum of `hashToGroup(item)` over the multiset.
/// `digest` is SHA-256 of the bincode serialization of the accumulator, which is the 32-byte
/// compressed point; `toBytes`/`fromBytes` are its BCS form (the same 32 bytes).
pub const Ecmh = struct {
    acc: Ristretto = Ristretto.identity,

    pub fn insert(self: *Ecmh, item: []const u8) void {
        self.acc = self.acc.add(Ristretto.hashToGroup(item));
    }

    pub fn remove(self: *Ecmh, item: []const u8) void {
        self.acc = self.acc.sub(Ristretto.hashToGroup(item));
    }

    /// Insert many items: SHA-512 per item, Elligator square roots paired across items.
    pub fn insertAll(self: *Ecmh, items: []const []const u8) void {
        var i: usize = 0;
        while (i + 1 < items.len) : (i += 2) {
            var d0: [64]u8 = undefined;
            var d1: [64]u8 = undefined;
            Sha512.hash(items[i], &d0);
            Sha512.hash(items[i + 1], &d1);
            const p = fromUniformPair(&d0, &d1);
            self.acc = self.acc.add(p[0]).add(p[1]);
        }
        if (i < items.len) self.insert(items[i]);
    }

    /// fastcrypto `union`.
    pub fn add(self: *Ecmh, other: *const Ecmh) void {
        self.acc = self.acc.add(other.acc);
    }

    pub fn digest(self: *const Ecmh) [32]u8 {
        const b = self.acc.encode();
        var out: [32]u8 = undefined;
        Sha256.hash(&b, &out);
        return out;
    }

    pub fn toBytes(self: *const Ecmh) [32]u8 {
        return self.acc.encode();
    }

    /// bcs::from_bytes::<EllipticCurveMultisetHash>: exactly 32 bytes of a valid encoding.
    pub fn fromBytes(bytes: []const u8) ?Ecmh {
        if (bytes.len != 32) return null;
        return .{ .acc = Ristretto.decode(bytes[0..32]) orelse return null };
    }
};

/// Two `fromUniform` maps with all four square roots paired.
fn fromUniformPair(a: *const [64]u8, b: *const [64]u8) [2]Ristretto {
    var x: [4][32]u8 = .{ a[0..32].*, a[32..64].*, b[0..32].*, b[32..64].* };
    for (&x) |*v| v[31] &= 0x7f;
    const p01 = elligator2(Fe.fromBytes(&x[0]), Fe.fromBytes(&x[1]));
    const p23 = elligator2(Fe.fromBytes(&x[2]), Fe.fromBytes(&x[3]));
    return .{ .{ .p = p01[0].add(p01[1]) }, .{ .p = p23[0].add(p23[1]) } };
}

// ---------------------------------------------------------------------------------------------

const testing = std.testing;

test "ristretto encode/decode and the map agree with std's ristretto255" {
    const R = std.crypto.ecc.Ristretto255;
    var prng: std.Random.DefaultPrng = .init(255);
    const rnd = prng.random();
    for (0..300) |_| {
        var u: [64]u8 = undefined;
        rnd.bytes(&u);
        const ours = Ristretto.fromUniform(&u);
        const theirs = R.fromUniform(u);
        const enc = ours.encode();
        try testing.expectEqual(theirs.toBytes(), enc);
        const back = Ristretto.decode(&enc).?;
        try testing.expectEqual(enc, back.encode());
        try testing.expect(back.eql(ours));
        var junk: [32]u8 = undefined;
        rnd.bytes(&junk);
        const std_ok = if (R.fromBytes(junk)) |_| true else |_| false;
        try testing.expectEqual(std_ok, Ristretto.decode(&junk) != null);
    }
    try testing.expectEqual(R.basePoint.toBytes(), Ristretto.generator.encode());
}

test "ecmh insertAll equals inserts, and remove undoes insert" {
    var a: Ecmh = .{};
    var b: Ecmh = .{};
    const items = [_][]const u8{ "a", "bb", "", "dddd", "zui" };
    for (items) |it| a.insert(it);
    b.insertAll(&items);
    try testing.expectEqual(a.digest(), b.digest());
    for (items) |it| a.remove(it);
    const e: Ecmh = .{};
    try testing.expectEqual(e.digest(), a.digest());
}
