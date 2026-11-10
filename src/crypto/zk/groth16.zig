//! Groth16 verification over BN254 with fastcrypto-zkp's byte API (the `sui::groth16` Move
//! natives and zkLogin). Results, including which error a malformed input produces, follow
//! `fastcrypto_zkp::bn254::api` at fastcrypto da61cd46 (arkworks 0.4 underneath):
//!
//!   prepare_pvk_bytes(vk)            -> [vk_gamma_abc_g1, alpha_g1_beta_g2, -gamma, -delta]
//!   verify_groth16_in_bytes(4 parts, public inputs, proof points) -> Ok(bool) or an error
//!
//! No allocation on the verify path: the prepared input point is accumulated while the
//! gamma_abc points are decoded, in the same order arkworks reads them.
const std = @import("std");
const bn = @import("bn254.zig");
const errors = @import("errors.zig");
const Fail = errors.Fail;
const Fq12 = bn.Fq12;
const Fr = bn.Fr;
const G1 = bn.G1;
const G2 = bn.G2;

pub const Curve = enum(u8) { bls12381 = 0, bn254 = 1 };

pub const scalar_size = 32;
pub const g1_size = 32;
pub const g2_size = 64;
pub const gt_size = 384;
/// Move native limit (`groth16::MAX_PUBLIC_INPUTS`).
pub const max_public_inputs = 8;

/// The ark error string for `SynthesisError::MalformedVerifyingKey`.
pub const malformed_vk = "malformed verifying key";

/// `fastcrypto_zkp::groth16::api::get_public_inputs_num` for BN254 sizes.
pub fn publicInputsNum(vk_len: usize) ?usize {
    const prefix = 2 * g1_size + 3 * g2_size + 8;
    if (vk_len < prefix) return null;
    const rest = vk_len - prefix;
    if (rest % g1_size != 0) return null;
    return rest / g1_size;
}

/// A prepared verifying key ready for repeated verification (zkLogin keeps two of these).
pub const PreparedVk = struct {
    gamma_abc: []const G1,
    alpha_beta: Fq12,
    gamma_neg: bn.G2Prepared,
    delta_neg: bn.G2Prepared,

    /// arkworks `prepare_inputs` + `verify_proof_with_prepared_inputs`. Returns null for
    /// `MalformedVerifyingKey` (wrong input count).
    pub fn verify(pvk: *const PreparedVk, inputs: []const Fr, a: G1, b: G2, c: G1) ?bool {
        if (inputs.len + 1 != pvk.gamma_abc.len) return null;
        var acc = pvk.gamma_abc[0].toJacobian();
        for (inputs, pvk.gamma_abc[1..]) |x, p| {
            const k = x.toLimbs();
            acc = acc.add(bn.G1J.mulLimbs(p, &k));
        }
        return pairingEquation(acc.toAffine(), pvk.alpha_beta, &pvk.gamma_neg, &pvk.delta_neg, a, b, c);
    }
};

/// e(A, B) * e(L, -gamma) * e(C, -delta) == alpha_beta (after final exponentiation).
pub fn pairingEquation(l: G1, alpha_beta: Fq12, gamma_neg: *const bn.G2Prepared, delta_neg: *const bn.G2Prepared, a: G1, b: G2, c: G1) bool {
    return @import("core").cpu.call("bn254_pairing_equation", pairingEquationImpl, .{ l, alpha_beta, gamma_neg, delta_neg, a, b, c });
}

pub fn pairingEquationImpl(l: G1, alpha_beta: Fq12, gamma_neg: *const bn.G2Prepared, delta_neg: *const bn.G2Prepared, a: G1, b: G2, c: G1) bool {
    const bp = bn.G2Prepared.init(b);
    const f = bn.multiMillerLoop(&.{
        .{ .p = a, .q = &bp },
        .{ .p = l, .q = gamma_neg },
        .{ .p = c, .q = delta_neg },
    });
    const e = bn.finalExponentiation(f) orelse return false; // UnexpectedIdentity: never for valid points
    return e.eql(alpha_beta);
}

/// Output of `prepare_pvk_bytes`: part 0 lives in the caller's arena.
pub const PvkBytes = struct {
    vk_gamma_abc_g1: []u8,
    alpha_g1_beta_g2: [gt_size]u8,
    gamma_g2_neg_pc: [g2_size]u8,
    delta_g2_neg_pc: [g2_size]u8,
};

/// `fastcrypto_zkp::bn254::api::prepare_pvk_bytes`. Every decode failure is InvalidInput.
/// Trailing bytes after the last gamma_abc point are ignored, as arkworks does.
pub fn preparePvkBytes(arena: std.mem.Allocator, vk: []const u8) (error{InvalidInput} || std.mem.Allocator.Error)!PvkBytes {
    var pos: usize = 0;
    const take = struct {
        fn f(b: []const u8, p: *usize, comptime n: usize) ?*const [n]u8 {
            if (b.len - p.* < n) return null;
            defer p.* += n;
            return b[p.*..][0..n];
        }
    }.f;
    const alpha = bn.curve.g1FromCompressed(take(vk, &pos, 32) orelse return error.InvalidInput) catch return error.InvalidInput;
    const beta = bn.curve.g2FromCompressed(take(vk, &pos, 64) orelse return error.InvalidInput) catch return error.InvalidInput;
    const gamma = bn.curve.g2FromCompressed(take(vk, &pos, 64) orelse return error.InvalidInput) catch return error.InvalidInput;
    const delta = bn.curve.g2FromCompressed(take(vk, &pos, 64) orelse return error.InvalidInput) catch return error.InvalidInput;
    const n = std.mem.readInt(u64, take(vk, &pos, 8) orelse return error.InvalidInput, .little);
    // Each point needs 32 bytes: a count beyond the input cannot succeed (arkworks hits EOF).
    if (n > (vk.len - pos) / 32) return error.InvalidInput;
    const part0 = try arena.alloc(u8, @intCast(n * 32));
    for (0..@intCast(n)) |i| {
        const p = bn.curve.g1FromCompressed(take(vk, &pos, 32).?) catch return error.InvalidInput;
        part0[i * 32 ..][0..32].* = bn.curve.g1ToCompressed(p);
    }
    return .{
        .vk_gamma_abc_g1 = part0,
        .alpha_g1_beta_g2 = bn.pairing(alpha, beta).toBytes(),
        .gamma_g2_neg_pc = bn.curve.g2ToCompressed(gamma.neg()),
        .delta_g2_neg_pc = bn.curve.g2ToCompressed(delta.neg()),
    };
}

/// Result of `verify_groth16_in_bytes`: Ok(bool) or the FastCryptoError.
pub const Verdict = union(enum) {
    ok: bool,
    err: Fail,
};

/// `fastcrypto_zkp::bn254::api::verify_groth16_in_bytes`, same error precedence:
/// input length, prepared key parts, proof points, input scalars, input count, pairing.
/// Allocation-free; variable time (all data is public).
pub fn verifyInBytes(
    vk_gamma_abc_g1: []const u8,
    alpha_g1_beta_g2: []const u8,
    gamma_g2_neg_pc: []const u8,
    delta_g2_neg_pc: []const u8,
    public_inputs: []const u8,
    proof_points: []const u8,
) Verdict {
    if (public_inputs.len % scalar_size != 0) return .{ .err = .{ .input_length_wrong = scalar_size } };
    const n_inputs = public_inputs.len / scalar_size;

    // Part 0: decode every point (any failure is InvalidInput) while accumulating
    // L = gamma_abc[0] + sum x_i * gamma_abc[i + 1] with the inputs read lazily.
    if (vk_gamma_abc_g1.len % scalar_size != 0) return .{ .err = .invalid_input };
    const n_points = vk_gamma_abc_g1.len / g1_size;
    var acc = bn.G1J.identity;
    var inputs_ok = true;
    for (0..n_points) |j| {
        const p = bn.curve.g1FromCompressed(vk_gamma_abc_g1[j * 32 ..][0..32]) catch return .{ .err = .invalid_input };
        if (j == 0) {
            acc = p.toJacobian();
        } else if (j - 1 < n_inputs and n_points == n_inputs + 1) {
            const xb = public_inputs[(j - 1) * 32 ..][0..32];
            const k = bn.Fr.limbsLe(xb);
            if (!bn.Fr.ltModulus(k)) {
                inputs_ok = false;
            } else if (inputs_ok) {
                acc = acc.add(bn.G1J.mulLimbs(p, &k));
            }
        }
    }
    if (alpha_g1_beta_g2.len < gt_size) return .{ .err = .invalid_input };
    const alpha_beta = Fq12.fromBytes(alpha_g1_beta_g2[0..gt_size]) orelse return .{ .err = .invalid_input };
    if (gamma_g2_neg_pc.len < g2_size) return .{ .err = .invalid_input };
    const gamma_neg = bn.curve.g2FromCompressed(gamma_g2_neg_pc[0..g2_size]) catch return .{ .err = .invalid_input };
    if (delta_g2_neg_pc.len < g2_size) return .{ .err = .invalid_input };
    const delta_neg = bn.curve.g2FromCompressed(delta_g2_neg_pc[0..g2_size]) catch return .{ .err = .invalid_input };

    if (proof_points.len < 128) return .{ .err = .invalid_input };
    const a = bn.curve.g1FromCompressed(proof_points[0..32]) catch return .{ .err = .invalid_input };
    const b = bn.curve.g2FromCompressed(proof_points[32..96]) catch return .{ .err = .invalid_input };
    const c = bn.curve.g1FromCompressed(proof_points[96..128]) catch return .{ .err = .invalid_input };

    for (0..n_inputs) |i| {
        if (!bn.Fr.ltModulus(bn.Fr.limbsLe(public_inputs[i * 32 ..][0..32]))) return .{ .err = .invalid_input };
    }
    if (n_points != n_inputs + 1) return .{ .err = .{ .general = malformed_vk } };
    std.debug.assert(inputs_ok);

    const gp = bn.G2Prepared.init(gamma_neg);
    const dp = bn.G2Prepared.init(delta_neg);
    return .{ .ok = pairingEquation(acc.toAffine(), alpha_beta, &gp, &dp, a, b, c) };
}

/// The `sui::groth16` Move natives (sui-move-natives crypto/groth16.rs) without gas: gas is the
/// natives lane's (`numPublicInputsForGas` gives the count it charges per input). BLS12-381
/// (curve 0) returns `.unsupported` until the crypto-bls lane lands its pairing.
pub const native = struct {
    pub const invalid_verifying_key: u64 = 0;
    pub const invalid_curve: u64 = 1;
    pub const too_many_public_inputs: u64 = 2;
    pub const bls12381: u8 = 0;
    pub const bn254: u8 = 1;

    pub const PrepareResult = union(enum) { ok: PvkBytes, abort: u64, unsupported };
    pub const VerifyResult = union(enum) { ok: bool, abort: u64, unsupported };

    /// `prepare_verifying_key_internal(curve, vk)`; `limit_inputs` is the protocol flag
    /// `limit_groth16_pvk_inputs`.
    pub fn prepareVerifyingKey(arena: std.mem.Allocator, curve: u8, vk: []const u8, limit_inputs: bool) std.mem.Allocator.Error!PrepareResult {
        if (curve != bls12381 and curve != bn254) return .{ .abort = invalid_curve };
        if (curve == bls12381) return .unsupported;
        if (limit_inputs) {
            const n = publicInputsNum(vk.len) orelse return .{ .abort = invalid_verifying_key };
            if (n > max_public_inputs) return .{ .abort = too_many_public_inputs };
        }
        const p = preparePvkBytes(arena, vk) catch |e| switch (e) {
            error.InvalidInput => return .{ .abort = invalid_verifying_key },
            error.OutOfMemory => return error.OutOfMemory,
        };
        return .{ .ok = p };
    }

    /// `verify_groth16_proof_internal(curve, 4 key parts, inputs, proof)` after gas: any
    /// fastcrypto error is `false`.
    pub fn verifyProof(curve: u8, parts: [4][]const u8, public_inputs: []const u8, proof_points: []const u8) VerifyResult {
        if (curve != bls12381 and curve != bn254) return .{ .abort = invalid_curve };
        if (curve == bls12381) return .unsupported;
        if (public_inputs.len > scalar_size * max_public_inputs) return .{ .abort = too_many_public_inputs };
        return switch (verifyInBytes(parts[0], parts[1], parts[2], parts[3], public_inputs, proof_points)) {
            .ok => |b| .{ .ok = b },
            .err => .{ .ok = false },
        };
    }

    /// The input count the verify native charges for (both curves use 32-byte scalars).
    pub fn numPublicInputsForGas(public_inputs_len: usize) usize {
        return (public_inputs_len + scalar_size - 1) / scalar_size;
    }
};

test "groth16 roundtrip on a tiny key" {
    // A key whose gamma_abc has one point and no inputs: verify with a forged "proof" fails.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const g1 = bn.curve.g1ToCompressed(bn.curve.g1_generator);
    const g2 = bn.curve.g2ToCompressed(bn.curve.g2_generator);
    var vk: [32 + 64 * 3 + 8 + 32]u8 = undefined;
    @memcpy(vk[0..32], &g1);
    @memcpy(vk[32..96], &g2);
    @memcpy(vk[96..160], &g2);
    @memcpy(vk[160..224], &g2);
    std.mem.writeInt(u64, vk[224..232], 1, .little);
    @memcpy(vk[232..264], &g1);
    try std.testing.expectEqual(@as(?usize, 0), publicInputsNum(vk.len));
    const pvk = try preparePvkBytes(arena_state.allocator(), &vk);
    // e(g1, g2) * e(g1, -g2) * e(C, -g2) == e(g1, g2) holds for A = g1, B = g2, C = -g1.
    var proof: [128]u8 = undefined;
    @memcpy(proof[0..32], &g1);
    @memcpy(proof[32..96], &g2);
    proof[96..128].* = bn.curve.g1ToCompressed(bn.curve.g1_generator.neg());
    const v = verifyInBytes(pvk.vk_gamma_abc_g1, &pvk.alpha_g1_beta_g2, &pvk.gamma_g2_neg_pc, &pvk.delta_g2_neg_pc, &.{}, &proof);
    try std.testing.expect(v == .ok and v.ok);
    proof[96..128].* = g1;
    const v2 = verifyInBytes(pvk.vk_gamma_abc_g1, &pvk.alpha_g1_beta_g2, &pvk.gamma_g2_neg_pc, &pvk.delta_g2_neg_pc, &.{}, &proof);
    try std.testing.expect(v2 == .ok and !v2.ok);
}
