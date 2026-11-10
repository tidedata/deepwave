//! Groth16 over BLS12-381 as `fastcrypto_zkp::bls12381::api` computes it (fastcrypto da61cd46),
//! built from the bls module's byte-level group operations. The zk module covers BN254 only;
//! this file closes the BLS12-381 arm of `sui::groth16` until the zk lane exports one.
//!
//! Encodings: G1 48 / G2 96 bytes compressed and subgroup checked (`from_byte_array`), scalars
//! 32 bytes little-endian and canonical, GT 576 bytes in arkworks order (six Fp2 blocks
//! permuted, each Fp little-endian) at the interface, fastcrypto order inside.
//! All inputs are public, so everything here is variable time.
const std = @import("std");
const bls = @import("bls");

const go = bls.group_ops;
const g1_len = 48;
const g2_len = 96;
const gt_len = 576;
const fp_len = 48;

pub const PvkBytes = struct {
    vk_gamma_abc_g1: []u8,
    alpha_g1_beta_g2: [gt_len]u8,
    gamma_g2_neg_pc: [g2_len]u8,
    delta_g2_neg_pc: [g2_len]u8,
};
pub const PrepareResult = union(enum) { ok: PvkBytes, abort: u64 };

const INVALID_VERIFYING_KEY: u64 = 0;
const TOO_MANY_PUBLIC_INPUTS: u64 = 2;
const MAX_PUBLIC_INPUTS: usize = 8;

const g1_inf: [g1_len]u8 = infinity(g1_len);
const g2_inf: [g2_len]u8 = infinity(g2_len);

/// Compressed point at infinity: the compression and infinity flags, then zeros.
fn infinity(comptime n: usize) [n]u8 {
    var b: [n]u8 = @splat(0);
    b[0] = 0xc0;
    return b;
}

fn g1Ok(b: []const u8) bool {
    return b.len == g1_len and go.validate(.g1, b);
}

fn g2Ok(b: []const u8) bool {
    return b.len == g2_len and go.validate(.g2, b);
}

/// fastcrypto GT bytes (12 Fp big-endian) to arkworks order, and back.
fn permute(in: *const [gt_len]u8, comptime perm: [6]usize) [gt_len]u8 {
    var out: [gt_len]u8 = undefined;
    for (perm, 0..) |to, from| @memcpy(out[to * 96 ..][0..96], in[from * 96 ..][0..96]);
    var i: usize = 0;
    while (i < gt_len) : (i += fp_len) std.mem.reverse(u8, out[i..][0..fp_len]);
    return out;
}

pub fn gtToArkworks(fc: *const [gt_len]u8) [gt_len]u8 {
    return permute(fc, .{ 0, 3, 1, 4, 2, 5 });
}

pub fn arkworksToGt(ark: *const [gt_len]u8) [gt_len]u8 {
    return permute(ark, .{ 0, 2, 4, 1, 3, 5 });
}

/// `prepare_verifying_key_internal` for curve BLS12381 after the base charge.
pub fn prepare(arena: std.mem.Allocator, vk: []const u8, limit_inputs: bool) std.mem.Allocator.Error!PrepareResult {
    const fixed = g1_len + 3 * g2_len + 8;
    if (limit_inputs) {
        const prefix = 2 * g1_len + 3 * g2_len + 8;
        if (vk.len < prefix or (vk.len - prefix) % g1_len != 0) return .{ .abort = INVALID_VERIFYING_KEY };
        if ((vk.len - prefix) / g1_len > MAX_PUBLIC_INPUTS) return .{ .abort = TOO_MANY_PUBLIC_INPUTS };
    }
    const bad: PrepareResult = .{ .abort = INVALID_VERIFYING_KEY };
    if (vk.len < fixed or (vk.len - fixed) % g1_len != 0) return bad;
    const alpha = vk[0..g1_len];
    const beta = vk[g1_len..][0..g2_len];
    const gamma = vk[g1_len + g2_len ..][0..g2_len];
    const delta = vk[g1_len + 2 * g2_len ..][0..g2_len];
    if (!g1Ok(alpha) or !g2Ok(beta) or !g2Ok(gamma) or !g2Ok(delta)) return bad;
    const n_abc = std.mem.readInt(u64, vk[g1_len + 3 * g2_len ..][0..8], .little);
    if (n_abc == 0) return bad;
    const rest = vk[fixed..];
    if (rest.len / g1_len != n_abc) return bad;
    var out: [go.max_out]u8 = undefined;
    const abc = try arena.alloc(u8, rest.len);
    var i: usize = 0;
    while (i < rest.len) : (i += g1_len) {
        const p = rest[i..][0..g1_len];
        if (!g1Ok(p)) return bad;
        const r = go.add(.g1, p, &g1_inf, &out) catch return bad;
        @memcpy(abc[i..][0..g1_len], r);
    }
    var pvk: PvkBytes = .{ .vk_gamma_abc_g1 = abc, .alpha_g1_beta_g2 = undefined, .gamma_g2_neg_pc = undefined, .delta_g2_neg_pc = undefined };
    const ab = go.pairing(.g1, alpha, beta, &out) catch return bad;
    pvk.alpha_g1_beta_g2 = gtToArkworks(ab[0..gt_len]);
    pvk.gamma_g2_neg_pc = (go.sub(.g2, &g2_inf, gamma, &out) catch return bad)[0..g2_len].*;
    pvk.delta_g2_neg_pc = (go.sub(.g2, &g2_inf, delta, &out) catch return bad)[0..g2_len].*;
    return .{ .ok = pvk };
}

/// `verify_groth16_in_bytes(...).unwrap_or(false)` for BLS12381.
pub fn verify(gamma_abc: []const u8, alpha_beta: []const u8, gamma_neg: []const u8, delta_neg: []const u8, inputs: []const u8, proof: []const u8) bool {
    // public inputs: little-endian canonical scalars
    if (inputs.len % 32 != 0) return false;
    const n = inputs.len / 32;
    var be: [32 * MAX_PUBLIC_INPUTS]u8 = undefined;
    if (n > MAX_PUBLIC_INPUTS) return false;
    for (0..n) |i| {
        for (0..32) |j| be[32 * i + j] = inputs[32 * i + 31 - j];
        if (!go.validate(.scalar, be[32 * i ..][0..32])) return false;
    }
    // proof: bcs (a: G1, b: G2, c: G1) as fixed arrays
    if (proof.len != 2 * g1_len + g2_len) return false;
    const a = proof[0..g1_len];
    const b = proof[g1_len..][0..g2_len];
    const cc = proof[g1_len + g2_len ..][0..g1_len];
    if (!g1Ok(a) or !g2Ok(b) or !g1Ok(cc)) return false;
    // prepared key parts
    if (gamma_abc.len % g1_len != 0) return false;
    var i: usize = 0;
    while (i < gamma_abc.len) : (i += g1_len) if (!g1Ok(gamma_abc[i..][0..g1_len])) return false;
    if (alpha_beta.len != gt_len) return false;
    const ab_fc = arkworksToGt(alpha_beta[0..gt_len]);
    if (!g2Ok(gamma_neg) or !g2Ok(delta_neg)) return false;
    // prepare_inputs
    if (n + 1 != gamma_abc.len / g1_len) return false;
    var prep: [g1_len]u8 = gamma_abc[0..g1_len].*;
    var out: [go.max_out]u8 = undefined;
    if (n > 0) {
        const m = go.multiScalarMul(.g1, be[0 .. 32 * n], gamma_abc[g1_len..], &out) catch return false;
        prep = (go.add(.g1, m, &prep, &out) catch return false)[0..g1_len].*;
    }
    // e(a, b) e(prep, gamma_neg) e(c, delta_neg) == alpha_beta, as one shared Miller loop and
    // one final exponentiation (the product of the three pairings is the same GT element as
    // fastcrypto's three pairings multiplied; all points are decoded and subgroup checked above)
    const want = bls.Gt.fromBytes(&ab_fc) orelse return false;
    const pairs = [3]bls.PairingInput{
        .{ g1Point(a) orelse return false, g2Point(b) orelse return false },
        .{ g1Point(&prep) orelse return false, g2Point(gamma_neg[0..g2_len]) orelse return false },
        .{ g1Point(cc) orelse return false, g2Point(delta_neg[0..g2_len]) orelse return false },
    };
    return bls.pairingProductIs(&pairs, &want);
}

fn g1Point(b: *const [g1_len]u8) ?bls.G1Affine {
    return switch (bls.encoding.g1FromBytes(b)) {
        .ok => |p| p,
        .err => null,
    };
}

fn g2Point(b: *const [g2_len]u8) ?bls.G2Affine {
    return switch (bls.encoding.g2FromBytes(b)) {
        .ok => |p| p,
        .err => null,
    };
}

test "gt order round trip" {
    var x: [gt_len]u8 = undefined;
    for (&x, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    const y = gtToArkworks(&x);
    try std.testing.expectEqualSlices(u8, &x, &arkworksToGt(&y));
}
