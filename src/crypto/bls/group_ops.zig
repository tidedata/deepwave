//! BLS12-381 arms of the Move `sui::group_ops` natives, byte for byte as fastcrypto's
//! `groups::bls12381` computes them in sui-move-natives/src/crypto/group_ops.rs
//! (mainnet-v1.83.1). Gas, feature flags and the MSM/sum length limits belong to the natives
//! lane; everything about values, parsing and errors is here.
//!
//! Encodings: scalars 32 bytes big-endian (< r), G1 48 / G2 96 bytes compressed, GT 576 bytes
//! (fastcrypto order), uncompressed G1 96 bytes. Inputs to arithmetic are parsed "trusted" as the
//! natives do (decode only, no subgroup check; scalars reduced mod r); `validate` is the untrusted
//! parse. Every function returns the output bytes in `out`, or `error.InvalidInput` exactly where
//! the native returns its error code.
//!
//! All values are public (on-chain), so the arithmetic here is variable time.
const std = @import("std");
const cpu = @import("core").cpu;
const curve = @import("curve.zig");
const encoding = @import("encoding.zig");
const h2c = @import("hash_to_curve.zig");
const pairing_mod = @import("pairing.zig");
const field = @import("field.zig");
const tower = @import("tower.zig");
const sig = @import("sig.zig");
const Fr = field.Fr;
const Fp12 = tower.Fp12;
const G1 = curve.G1;
const G2 = curve.G2;

pub const Group = enum(u8) { scalar = 0, g1 = 1, g2 = 2, gt = 3, g1_uncompressed = 4, _ };

pub const Error = error{InvalidInput};

pub const scalar_len = 32;
pub const g1_len = 48;
pub const g2_len = 96;
pub const gt_len = 576;
pub const g1_uncompressed_len = 96;
/// Big enough for any output.
pub const max_out = gt_len;

pub const dst_g1 = sig.min_sig_dst;
pub const dst_g2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

// ---------------------------------------------------------------------------------------------
// parsing (fastcrypto from_trusted_byte_array / from_byte_array)

fn fixed(comptime n: usize, b: []const u8) Error!*const [n]u8 {
    if (b.len != n) return error.InvalidInput;
    return b[0..n];
}

/// Scalar::from_trusted_byte_array: big-endian, reduced mod r (blst_fr_from_scalar).
fn scalarTrusted(b: []const u8) Error!Fr {
    return Fr.fromBytesBEReduce(try fixed(32, b));
}

/// Scalar::from_byte_array: big-endian, must be < r (blst_scalar_fr_check).
fn scalarUntrusted(b: []const u8) Error!Fr {
    return Fr.fromBytesBE(try fixed(32, b)) orelse error.InvalidInput;
}

fn g1Trusted(b: []const u8) Error!G1.Point {
    return switch (encoding.g1Uncompress(try fixed(48, b))) {
        .ok => |a| a.toJacobian(),
        .err => error.InvalidInput,
    };
}

fn g2Trusted(b: []const u8) Error!G2.Point {
    return switch (encoding.g2Uncompress(try fixed(96, b))) {
        .ok => |a| a.toJacobian(),
        .err => error.InvalidInput,
    };
}

/// GTElement::from_trusted_byte_array: every coordinate canonical, no group check.
fn gtTrusted(b: []const u8) Error!Fp12 {
    return Fp12.fromBytes(try fixed(576, b)) orelse error.InvalidInput;
}

fn g1Out(p: G1.Point, out: []u8) []const u8 {
    out[0..48].* = encoding.g1Compress(p.toAffine());
    return out[0..48];
}

fn g2Out(p: G2.Point, out: []u8) []const u8 {
    out[0..96].* = encoding.g2Compress(p.toAffine());
    return out[0..96];
}

fn gtOut(f: Fp12, out: []u8) []const u8 {
    out[0..576].* = f.toBytes();
    return out[0..576];
}

fn scalarOut(s: Fr, out: []u8) []const u8 {
    out[0..32].* = s.toBytesBE();
    return out[0..32];
}

fn scalarLe(s: Fr) [32]u8 {
    var le: [32]u8 = undefined;
    const be = s.toBytesBE();
    for (0..32) |i| le[i] = be[31 - i];
    return le;
}

fn scalarInv(s: Fr) Error!Fr {
    if (s.isZero()) return error.InvalidInput;
    return s.invVartime();
}

fn g1Mul(p: G1.Point, k: Fr) G1.Point {
    if (k.isZero()) return G1.Point.infinity;
    return p.mulVartime(&scalarLe(k), 255);
}

fn g2Mul(p: G2.Point, k: Fr) G2.Point {
    if (k.isZero()) return G2.Point.infinity;
    return p.mulVartime(&scalarLe(k), 255);
}

/// x^k by square-and-multiply (fastcrypto's GTElement * Scalar computes exactly x^k).
fn gtPow(x: Fp12, k: Fr) Fp12 {
    if (k.isZero()) return Fp12.one;
    const le = scalarLe(k);
    var acc = Fp12.one;
    var started = false;
    var i: usize = 256;
    while (i > 0) {
        i -= 1;
        if (started) acc = acc.sqr();
        if ((le[i / 8] >> @intCast(i % 8)) & 1 == 1) {
            acc = if (started) acc.mul(x) else x;
            started = true;
        }
    }
    return acc;
}

// ---------------------------------------------------------------------------------------------
// natives

/// internal_validate: the untrusted parse succeeds (false for GT and unknown groups).
fn validateRaw(g: Group, b: []const u8) bool {
    switch (g) {
        .scalar => _ = scalarUntrusted(b) catch return false,
        .g1 => {
            const p = g1Trusted(b) catch return false;
            return curve.g1InGroup(p);
        },
        .g2 => {
            const p = g2Trusted(b) catch return false;
            return curve.g2InGroup(p);
        },
        else => return false,
    }
    return true;
}

fn addRaw(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Error![]const u8 {
    return switch (g) {
        .scalar => scalarOut((try scalarTrusted(a)).add(try scalarTrusted(b)), out),
        .g1 => g1Out((try g1Trusted(a)).add(try g1Trusted(b)), out),
        .g2 => g2Out((try g2Trusted(a)).add(try g2Trusted(b)), out),
        .gt => gtOut((try gtTrusted(a)).mul(try gtTrusted(b)), out),
        else => error.InvalidInput,
    };
}

/// a - b; in GT, a * b^-1 (fastcrypto negates GT elements with a full Fp12 inverse).
fn subRaw(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Error![]const u8 {
    return switch (g) {
        .scalar => scalarOut((try scalarTrusted(a)).sub(try scalarTrusted(b)), out),
        .g1 => g1Out((try g1Trusted(a)).add((try g1Trusted(b)).neg()), out),
        .g2 => g2Out((try g2Trusted(a)).add((try g2Trusted(b)).neg()), out),
        .gt => gtOut((try gtTrusted(a)).mul((try gtTrusted(b)).invVartime()), out),
        else => error.InvalidInput,
    };
}

/// [a] b for a scalar `a` and an element `b` of group `g` (the scalar group multiplies).
fn mulRaw(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Error![]const u8 {
    return switch (g) {
        .scalar => scalarOut((try scalarTrusted(b)).mul(try scalarTrusted(a)), out),
        .g1 => blk: {
            const k = try scalarTrusted(a);
            break :blk g1Out(g1Mul(try g1Trusted(b), k), out);
        },
        .g2 => blk: {
            const k = try scalarTrusted(a);
            break :blk g2Out(g2Mul(try g2Trusted(b), k), out);
        },
        .gt => blk: {
            const k = try scalarTrusted(a);
            break :blk gtOut(gtPow(try gtTrusted(b), k), out);
        },
        else => error.InvalidInput,
    };
}

/// [a^-1] b; error when a = 0 (after both parses, as fastcrypto orders it).
fn divRaw(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Error![]const u8 {
    return switch (g) {
        .scalar => blk: {
            const k = try scalarTrusted(a);
            const x = try scalarTrusted(b);
            break :blk scalarOut(x.mul(try scalarInv(k)), out);
        },
        .g1 => blk: {
            const k = try scalarTrusted(a);
            const p = try g1Trusted(b);
            break :blk g1Out(g1Mul(p, try scalarInv(k)), out);
        },
        .g2 => blk: {
            const k = try scalarTrusted(a);
            const p = try g2Trusted(b);
            break :blk g2Out(g2Mul(p, try scalarInv(k)), out);
        },
        .gt => blk: {
            const k = try scalarTrusted(a);
            const x = try gtTrusted(b);
            break :blk gtOut(gtPow(x, try scalarInv(k)), out);
        },
        else => error.InvalidInput,
    };
}

fn hashToRaw(g: Group, msg: []const u8, out: *[max_out]u8) Error![]const u8 {
    if (msg.len == 0) return error.InvalidInput;
    return switch (g) {
        .g1 => g1Out(h2c.hashToG1(msg, dst_g1), out),
        .g2 => g2Out(h2c.hashToG2(msg, dst_g2), out),
        else => error.InvalidInput,
    };
}

/// sum k_i P_i over `scalars` (32-byte chunks) and `points` (compressed chunks). Lengths must be
/// non-zero multiples with equal counts; any parse failure is an error.
fn multiScalarMulRaw(g: Group, scalars: []const u8, points: []const u8, out: *[max_out]u8) Error![]const u8 {
    const plen: usize = switch (g) {
        .g1 => 48,
        .g2 => 96,
        else => return error.InvalidInput,
    };
    if (points.len == 0 or scalars.len == 0 or scalars.len % 32 != 0 or points.len % plen != 0 or
        points.len / plen != scalars.len / 32) return error.InvalidInput;
    const n = scalars.len / 32;
    // all scalars parse before any point, as the native collects them
    for (0..n) |i| _ = try scalarTrusted(scalars[32 * i ..][0..32]);
    switch (g) {
        .g1 => {
            var acc = G1.Point.infinity;
            for (0..n) |i| {
                const p = try g1Trusted(points[48 * i ..][0..48]);
                acc = acc.add(g1Mul(p, scalarTrusted(scalars[32 * i ..][0..32]) catch unreachable));
            }
            return g1Out(acc, out);
        },
        .g2 => {
            var acc = G2.Point.infinity;
            for (0..n) |i| {
                const p = try g2Trusted(points[96 * i ..][0..96]);
                acc = acc.add(g2Mul(p, scalarTrusted(scalars[32 * i ..][0..32]) catch unreachable));
            }
            return g2Out(acc, out);
        },
        else => unreachable,
    }
}

/// e(a, b) for G1 `a` and G2 `b` (group type must be G1), as blst_miller_loop + final_exp.
fn pairingRaw(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Error![]const u8 {
    if (g != .g1) return error.InvalidInput;
    const p = try g1Trusted(a);
    const q = try g2Trusted(b);
    return gtOut(pairing_mod.pairing(p.toAffine(), q.toAffine()), out);
}

/// G1ElementUncompressed -> G1Element::try_from: neither the compression nor the sign flag,
/// blst_p1_deserialize, and G1 membership.
fn uncompressedToG1(b: []const u8) Error!G1.Point {
    const in = try fixed(96, b);
    if (in[0] & 0x20 != 0 or in[0] & 0x80 != 0) return error.InvalidInput;
    const a = switch (encoding.g1Deserialize96(in)) {
        .ok => |a| a,
        .err => return error.InvalidInput,
    };
    const p = a.toJacobian();
    if (!curve.g1InGroup(p)) return error.InvalidInput;
    return p;
}

fn convertRaw(from: Group, to: Group, e: []const u8, out: *[max_out]u8) Error![]const u8 {
    if (from == .g1_uncompressed and to == .g1) return g1Out(try uncompressedToG1(e), out);
    if (from == .g1 and to == .g1_uncompressed) {
        const p = try g1Trusted(e);
        out[0..96].* = encoding.g1Serialize(p.toAffine());
        return out[0..96];
    }
    return error.InvalidInput;
}

/// Sum of uncompressed G1 terms (blst_p1_deserialize each, no subgroup check), uncompressed out.
fn sumRaw(g: Group, terms: []const []const u8, out: *[max_out]u8) Error![]const u8 {
    if (g != .g1_uncompressed) return error.InvalidInput;
    for (terms) |t| if (t.len != 96) return error.InvalidInput;
    var acc = G1.Point.infinity;
    for (terms) |t| {
        const a = switch (encoding.g1Deserialize96(t[0..96])) {
            .ok => |a| a,
            .err => return error.InvalidInput,
        };
        acc = acc.addAffine(a);
    }
    out[0..96].* = encoding.g1Serialize(acc.toAffine());
    return out[0..96];
}

// ---------------------------------------------------------------------------------------------
// Runtime CPU dispatch (core/cpu.zig): every entry point runs in the best x86-64 kernel object
// (mulx field kernels there), the results cross as a slice or nothing (no error unions).

pub const Res = union(enum) { ok: []const u8, err };

fn wrap(r: Error![]const u8) Res {
    return if (r) |x| .{ .ok = x } else |_| .err;
}

fn unwrap(r: Res) Error![]const u8 {
    return switch (r) {
        .ok => |x| x,
        .err => error.InvalidInput,
    };
}

pub fn validate(g: Group, b: []const u8) bool {
    return cpu.call("bls_go_validate", validateImpl, .{ g, b });
}
pub fn validateImpl(g: Group, b: []const u8) bool {
    return validateRaw(g, b);
}

pub fn add(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Error![]const u8 {
    return unwrap(cpu.call("bls_go_add", addImpl, .{ g, a, b, out }));
}
pub fn addImpl(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Res {
    return wrap(addRaw(g, a, b, out));
}

pub fn sub(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Error![]const u8 {
    return unwrap(cpu.call("bls_go_sub", subImpl, .{ g, a, b, out }));
}
pub fn subImpl(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Res {
    return wrap(subRaw(g, a, b, out));
}

pub fn mul(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Error![]const u8 {
    return unwrap(cpu.call("bls_go_mul", mulImpl, .{ g, a, b, out }));
}
pub fn mulImpl(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Res {
    return wrap(mulRaw(g, a, b, out));
}

pub fn div(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Error![]const u8 {
    return unwrap(cpu.call("bls_go_div", divImpl, .{ g, a, b, out }));
}
pub fn divImpl(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Res {
    return wrap(divRaw(g, a, b, out));
}

pub fn hashTo(g: Group, msg: []const u8, out: *[max_out]u8) Error![]const u8 {
    return unwrap(cpu.call("bls_go_hashTo", hashToImpl, .{ g, msg, out }));
}
pub fn hashToImpl(g: Group, msg: []const u8, out: *[max_out]u8) Res {
    return wrap(hashToRaw(g, msg, out));
}

pub fn multiScalarMul(g: Group, scalars: []const u8, points: []const u8, out: *[max_out]u8) Error![]const u8 {
    return unwrap(cpu.call("bls_go_multiScalarMul", multiScalarMulImpl, .{ g, scalars, points, out }));
}
pub fn multiScalarMulImpl(g: Group, scalars: []const u8, points: []const u8, out: *[max_out]u8) Res {
    return wrap(multiScalarMulRaw(g, scalars, points, out));
}

pub fn pairing(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Error![]const u8 {
    return unwrap(cpu.call("bls_go_pairing", pairingImpl, .{ g, a, b, out }));
}
pub fn pairingImpl(g: Group, a: []const u8, b: []const u8, out: *[max_out]u8) Res {
    return wrap(pairingRaw(g, a, b, out));
}

pub fn convert(from: Group, to: Group, e: []const u8, out: *[max_out]u8) Error![]const u8 {
    return unwrap(cpu.call("bls_go_convert", convertImpl, .{ from, to, e, out }));
}
pub fn convertImpl(from: Group, to: Group, e: []const u8, out: *[max_out]u8) Res {
    return wrap(convertRaw(from, to, e, out));
}

pub fn sum(g: Group, terms: []const []const u8, out: *[max_out]u8) Error![]const u8 {
    return unwrap(cpu.call("bls_go_sum", sumImpl, .{ g, terms, out }));
}
pub fn sumImpl(g: Group, terms: []const []const u8, out: *[max_out]u8) Res {
    return wrap(sumRaw(g, terms, out));
}

test "group ops basics" {
    var out: [max_out]u8 = undefined;
    const g = encoding.g1Compress(curve.g1_generator);
    const two = blk: {
        var b: [32]u8 = @splat(0);
        b[31] = 2;
        break :blk b;
    };
    const dbl = try add(.g1, &g, &g, &out);
    var d: [48]u8 = dbl[0..48].*;
    try std.testing.expectEqualSlices(u8, &d, try mul(.g1, &two, &g, &out));
    try std.testing.expectEqualSlices(u8, &g, try div(.g1, &two, &d, &out));
    try std.testing.expect(validate(.g1, &g));
    d[0] &= 0x7f;
    try std.testing.expect(!validate(.g1, &d));
}
