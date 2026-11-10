//! fastcrypto-tbls `polynomial` and `dl_verification` for the beacon: polynomials as coefficient
//! slices (low degree first), Horner evaluation at share index i (1-based, u16), commitments,
//! Lagrange interpolation at zero, and the batch share verification of the DKG.
//! A `Poly` is `[]Scalar` (private) or `[]G2P` (public VSS commitment); signatures live in G1.
const std = @import("std");
const group = @import("group.zig");
const Scalar = group.Scalar;
const G1 = group.G1;
const G2 = group.G2;
const G1P = group.G1P;
const G2P = group.G2P;

pub const Error = error{ InvalidInput, NotEnoughInputs, InvalidProof } || std.mem.Allocator.Error;

pub const Share = struct { index: u16, value: Scalar };

/// degree_bound = len - 1 (a polynomial with t coefficients has degree bound t - 1).
pub fn degreeBound(len: usize) usize {
    return len -| 1;
}

/// A random polynomial with `degree + 1` coefficients.
pub fn randPrivate(arena: std.mem.Allocator, degree: u16, rng: std.Random) Error![]Scalar {
    const c = try arena.alloc(Scalar, @as(usize, degree) + 1);
    for (c) |*x| x.* = group.scalarRand(rng);
    return c;
}

/// Commit to a private polynomial in G2: coefficient i times the generator (secret scalars).
pub fn commit(arena: std.mem.Allocator, sk: []const Scalar) Error![]G2P {
    const out = try arena.alloc(G2P, sk.len);
    const g = group.g2Generator();
    for (sk, out) |s, *o| o.* = group.mulSecret(G2, g, s);
    return out;
}

pub fn evalPrivate(poly: []const Scalar, i: u16) Scalar {
    const xi = Scalar.fromU64(i);
    var acc = Scalar.zero;
    var k = poly.len;
    while (k > 0) {
        k -= 1;
        acc = acc.mul(xi).add(poly[k]);
    }
    return acc;
}

pub fn evalPublic(comptime C: type, poly: []const C.Point, i: u16) C.Point {
    var acc = C.Point.infinity;
    var k = poly.len;
    while (k > 0) {
        k -= 1;
        acc = group.mulSmall(C, acc, i).add(poly[k]);
    }
    return acc;
}

/// `PublicPoly += &other`: element-wise, extended when other is longer. Result in `arena`.
pub fn addPublic(arena: std.mem.Allocator, a: []const G2P, b: []const G2P) Error![]G2P {
    const n = @max(a.len, b.len);
    const out = try arena.alloc(G2P, n);
    for (out, 0..) |*o, i| {
        const x = if (i < a.len) a[i] else G2P.infinity;
        const y = if (i < b.len) b[i] else G2P.infinity;
        o.* = x.add(y);
    }
    return out;
}

/// Lagrange coefficients at zero for the given distinct non-zero indices:
/// L_i(0) = prod_{j != i} x_j / (x_j - x_i).
pub fn lagrangeAtZero(arena: std.mem.Allocator, indices: []const u16) Error![]Scalar {
    for (indices, 0..) |a, i| {
        if (a == 0) return error.InvalidInput;
        for (indices[0..i]) |b| if (a == b) return error.InvalidInput;
    }
    const out = try arena.alloc(Scalar, indices.len);
    for (indices, 0..) |xi, i| {
        var num = Scalar.one;
        var den = Scalar.one;
        const xi_s = Scalar.fromU64(xi);
        for (indices, 0..) |xj, j| {
            if (j == i) continue;
            const xj_s = Scalar.fromU64(xj);
            num = num.mul(xj_s);
            den = den.mul(xj_s.sub(xi_s));
        }
        out[i] = num.mul(group.scalarInv(den) orelse return error.InvalidInput);
    }
    return out;
}

/// `recover_c0` over scalars: the value at zero from exactly `t` shares.
pub fn recoverC0Scalar(arena: std.mem.Allocator, t: u16, shares: []const Share) Error!Scalar {
    if (shares.len != t) return error.InvalidInput;
    const idx = try arena.alloc(u16, shares.len);
    for (shares, idx) |s, *i| i.* = s.index;
    const co = try lagrangeAtZero(arena, idx);
    var acc = Scalar.zero;
    for (shares, co) |s, c| acc = acc.add(s.value.mul(c));
    return acc;
}

/// `recover_c0_msm` over a group: sum L_i(0) * value_i.
pub fn recoverC0Group(comptime C: type, arena: std.mem.Allocator, t: u16, indices: []const u16, values: []const C.Point) Error!C.Point {
    if (indices.len != t or values.len != t) return error.InvalidInput;
    const co = try lagrangeAtZero(arena, indices);
    return group.msm(C, co, values) catch error.InvalidInput;
}

/// `batch_coefficients(r, indexes, degree)`: coefficient k = sum_i r_i * x_i^k, k in 0..=degree.
pub fn batchCoefficients(arena: std.mem.Allocator, r: []const Scalar, indexes: []const Scalar, degree: usize) Error![]Scalar {
    if (r.len != indexes.len or degree == 0) return error.InvalidInput;
    const mult = try arena.dupe(Scalar, r);
    const res = try arena.alloc(Scalar, degree + 1);
    for (0..degree + 1) |k| {
        var s = Scalar.zero;
        for (mult) |m| s = s.add(m);
        res[k] = s;
        if (k == degree) break;
        for (mult, indexes) |*m, x| m.* = m.mul(x);
    }
    return res;
}

/// `verify_poly_evals`: all evaluations lie on the committed polynomial (random linear
/// combination with 64 bit weights).
pub fn verifyPolyEvals(arena: std.mem.Allocator, evals: []const Share, poly: []const G2P, rng: std.Random) Error!void {
    if (degreeBound(poly.len) == 0) return error.InvalidInput;
    if (evals.len == 0) return;
    const rs = try arena.alloc(Scalar, evals.len);
    for (rs) |*r| r.* = group.scalarRandSmall(rng);
    var dotv = Scalar.zero;
    const xs = try arena.alloc(Scalar, evals.len);
    for (evals, rs, xs) |e, r, *x| {
        dotv = dotv.add(r.mul(e.value));
        x.* = Scalar.fromU64(e.index);
    }
    const lhs = group.mulPublic(G2, group.g2Generator(), dotv);
    const coeffs = try batchCoefficients(arena, rs, xs, degreeBound(poly.len));
    const rhs = group.msm(G2, coeffs, poly) catch return error.InvalidInput;
    if (!lhs.eql(rhs)) return error.InvalidProof;
}

test "lagrange recovers the constant term" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(3);
    const poly = try randPrivate(arena, 2, prng.random()); // t = 3
    const shares = [_]Share{
        .{ .index = 2, .value = evalPrivate(poly, 2) },
        .{ .index = 5, .value = evalPrivate(poly, 5) },
        .{ .index = 9, .value = evalPrivate(poly, 9) },
    };
    const c0 = try recoverC0Scalar(arena, 3, &shares);
    try std.testing.expect(c0.eql(poly[0]));
}

test "verify poly evals accepts good and rejects bad" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(4);
    const rng = prng.random();
    const sk = try randPrivate(arena, 2, rng);
    const pk = try commit(arena, sk);
    var evals = [_]Share{
        .{ .index = 1, .value = evalPrivate(sk, 1) },
        .{ .index = 2, .value = evalPrivate(sk, 2) },
        .{ .index = 7, .value = evalPrivate(sk, 7) },
    };
    try verifyPolyEvals(arena, &evals, pk, rng);
    evals[1].value = evals[1].value.add(Scalar.one);
    try std.testing.expectError(error.InvalidProof, verifyPolyEvals(arena, &evals, pk, rng));
    // public evaluation agrees with the committed private one
    const e = evalPublic(G2, pk, 5);
    try std.testing.expect(e.eql(group.mulPublic(G2, group.g2Generator(), evalPrivate(sk, 5))));
}
