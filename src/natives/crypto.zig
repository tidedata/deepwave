//! Crypto natives of the Sui framework (sui-move-natives latest `crypto/`, mainnet-v1.83.1):
//! gas and abort codes here, the primitives from the sig, bls and zk modules.
const std = @import("std");
const sig = @import("sig");
const bls = @import("bls");
const zk = @import("zk");
const abi = @import("abi.zig");
const protocol = @import("protocol");

const Ctx = abi.Ctx;
const Value = abi.Value;
const TyArg = abi.TyArg;
const Outcome = abi.Outcome;
const Error = abi.Error;

inline fn blocks(len: usize, block: usize) u64 {
    return @intCast((len + block - 1) / block);
}

fn msgCost(c: *Ctx, per_byte: u64, per_block: u64, len: usize, block: usize) u64 {
    _ = c;
    return per_byte *| @as(u64, len) +| per_block *| blocks(len, block);
}

// ---- ed25519 --------------------------------------------------------------------------------

pub fn ed25519_verify(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("ed25519_ed25519_verify_cost_base"))) return c.oog();
    const msg = try abi.bytesOf(c.arena, args[2]);
    const pk = try abi.bytesOf(c.arena, args[1]);
    const s = try abi.bytesOf(c.arena, args[0]);
    if (!c.charge(msgCost(c, c.p("ed25519_ed25519_verify_msg_cost_per_byte"), c.p("ed25519_ed25519_verify_msg_cost_per_block"), msg.len, 128))) return c.oog();
    const ok = s.len == 64 and pk.len == 32 and sig.ed25519.verifySlices(pk, msg, s) == .valid;
    return c.ok1(.{ .bool = ok });
}

// ---- ecdsa k1 / r1 --------------------------------------------------------------------------

const KECCAK256: u8 = 0;
const SHA256: u8 = 1;

fn EcdsaNatives(comptime is_k1: bool) type {
    const E = if (is_k1) sig.secp256k1 else sig.secp256r1;
    const pre = if (is_k1) "ecdsa_k1_" else "ecdsa_r1_";
    const vpre = if (is_k1) "ecdsa_k1_secp256k1_verify_" else "ecdsa_r1_secp256r1_verify_";
    return struct {
        pub fn ecrecover(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
            const h = args[2].u8;
            const base, const per_byte, const per_block, const block: usize, const kind: sig.HashKind = switch (h) {
                KECCAK256 => .{ c.p(pre ++ "ecrecover_keccak256_cost_base"), c.p(pre ++ "ecrecover_keccak256_msg_cost_per_byte"), c.p(pre ++ "ecrecover_keccak256_msg_cost_per_block"), 136, .keccak256 },
                SHA256 => .{ c.p(pre ++ "ecrecover_sha256_cost_base"), c.p(pre ++ "ecrecover_sha256_msg_cost_per_byte"), c.p(pre ++ "ecrecover_sha256_msg_cost_per_block"), 64, .sha256 },
                else => {
                    _ = c.charge(c.p("crypto_invalid_arguments_cost"));
                    return c.abort(0); // FAIL_TO_RECOVER_PUBKEY
                },
            };
            if (!c.charge(base)) return c.oog();
            const msg = try abi.bytesOf(c.arena, args[1]);
            const s = try abi.bytesOf(c.arena, args[0]);
            if (!c.charge(msgCost(c, per_byte, per_block, msg.len, block))) return c.oog();
            // v142 `secp256r1_ecrecover_checks_x_below_p`: r + n is no longer wrapped at 2^256.
            const strict = !is_k1 and c.cfg.feature_flags.secp256r1_ecrecover_checks_x_below_p;
            return switch (E.recoverSlicesMode(msg, s, kind, strict)) {
                .ok => |pk| c.ok1Bytes(&pk),
                .invalid => |r| c.abort(if (std.mem.startsWith(u8, @tagName(r), "sig_")) 1 else 0),
            };
        }

        pub fn verify(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
            const h = args[3].u8;
            const base, const per_byte, const per_block, const block: usize, const kind: sig.HashKind = switch (h) {
                KECCAK256 => .{ c.p(vpre ++ "keccak256_cost_base"), c.p(vpre ++ "keccak256_msg_cost_per_byte"), c.p(vpre ++ "keccak256_msg_cost_per_block"), 136, .keccak256 },
                SHA256 => .{ c.p(vpre ++ "sha256_cost_base"), c.p(vpre ++ "sha256_msg_cost_per_byte"), c.p(vpre ++ "sha256_msg_cost_per_block"), 64, .sha256 },
                else => {
                    _ = c.charge(c.p("crypto_invalid_arguments_cost"));
                    return c.ok1(.{ .bool = false });
                },
            };
            if (!c.charge(base)) return c.oog();
            const msg = try abi.bytesOf(c.arena, args[2]);
            const pk = try abi.bytesOf(c.arena, args[1]);
            const s = try abi.bytesOf(c.arena, args[0]);
            if (!c.charge(msgCost(c, per_byte, per_block, msg.len, block))) return c.oog();
            return c.ok1(.{ .bool = E.verifySlices(pk, msg, s, kind) == .valid });
        }
    };
}

pub const k1 = EcdsaNatives(true);
pub const r1 = EcdsaNatives(false);

pub fn decompress_pubkey(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("ecdsa_k1_decompress_pubkey_cost_base"))) return c.oog();
    const pk = try abi.bytesOf(c.arena, args[0]);
    const a = sig.secp256k1.parsePublicKey(pk) orelse return c.abort(2); // INVALID_PUBKEY
    var out: [65]u8 = undefined;
    out[0] = 4;
    out[1..33].* = a.x.toBytes();
    out[33..65].* = a.y.toBytes();
    return c.ok1Bytes(&out);
}

// ---- bls12381 -------------------------------------------------------------------------------

const generatorLines = bls.sig.generatorLines;

/// fastcrypto min-sig `verify` (blst, sig group-checked, pk not) with the generator's lines
/// precomputed.
pub fn minSigVerify(pk: *const bls.PublicKey, msg: []const u8, s: *const bls.Signature) bool {
    return bls.sig.coreVerify(pk.point, msg, s.point, generatorLines());
}

/// `minSigVerify` after fastcrypto `validate` on the key (proof of possession), one dispatched call.
pub fn minSigVerifyValidated(pk: *const bls.PublicKey, msg: []const u8, s: *const bls.Signature) bool {
    return bls.sig.verifyValidated(pk.point, msg, s.point, generatorLines());
}

fn blsVerify(c: *Ctx, args: []Value, comptime pre: []const u8, comptime min_sig: bool) Error!Outcome {
    if (!c.charge(c.p(pre ++ "cost_base"))) return c.oog();
    const msg = try abi.bytesOf(c.arena, args[2]);
    const pk = try abi.bytesOf(c.arena, args[1]);
    const s = try abi.bytesOf(c.arena, args[0]);
    if (!c.charge(msgCost(c, c.p(pre ++ "msg_cost_per_byte"), c.p(pre ++ "msg_cost_per_block"), msg.len, 64))) return c.oog();
    const ok = bls.sig.verifyBytes(min_sig, pk, msg, s, if (min_sig) generatorLines() else null);
    return c.ok1(.{ .bool = ok });
}

pub fn bls12381_min_sig_verify(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    return blsVerify(c, args, "bls12381_bls12381_min_sig_verify_", true);
}

pub fn bls12381_min_pk_verify(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    return blsVerify(c, args, "bls12381_bls12381_min_pk_verify_", false);
}

// ---- ecvrf ----------------------------------------------------------------------------------

pub fn ecvrf_verify(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("ecvrf_ecvrf_verify_cost_base"))) return c.oog();
    const proof = try abi.bytesOf(c.arena, args[3]);
    const pk = try abi.bytesOf(c.arena, args[2]);
    const alpha = try abi.bytesOf(c.arena, args[1]);
    const h = try abi.bytesOf(c.arena, args[0]);
    if (!c.charge(msgCost(c, c.p("ecvrf_ecvrf_verify_alpha_string_cost_per_byte"), c.p("ecvrf_ecvrf_verify_alpha_string_cost_per_block"), alpha.len, 128))) return c.oog();
    return switch (sig.ecvrf.verifyNative(h, alpha, pk, proof)) {
        .err_hash => c.abort(1),
        .err_pk => c.abort(2),
        .err_proof => c.abort(3),
        .valid => c.ok1(.{ .bool = true }),
        .invalid => c.ok1(.{ .bool = false }),
    };
}

// ---- poseidon -------------------------------------------------------------------------------

pub fn poseidon_bn254_internal(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.flag("enable_poseidon")) return c.abort(1); // NOT_SUPPORTED_ERROR
    if (!c.charge(c.popt("poseidon_bn254_cost_base") orelse return Ctx.invariant())) return c.oog();
    const n: u64 = args[0].vector.len;
    if (n > 16) return c.abort(2); // TOO_MANY_INPUTS
    const per = c.popt("poseidon_bn254_cost_per_block") orelse return Ctx.invariant();
    if (!c.charge(per *| n)) return c.oog();
    const inputs = try abi.vecOfBytesOf(c.arena, args[0]);
    var out: [32]u8 = undefined;
    if (zk.poseidon.native.poseidonBn254(inputs, &out)) |code| return c.abort(code);
    return c.ok1Bytes(&out);
}

// ---- groth16 --------------------------------------------------------------------------------

const BLS12381: u8 = 0;
const BN254: u8 = 1;

pub fn prepare_verifying_key_internal(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const vk = try abi.bytesOf(c.arena, args[1]);
    const curve = args[0].u8;
    const base = switch (curve) {
        BLS12381 => c.p("groth16_prepare_verifying_key_bls12381_cost_base"),
        BN254 => c.p("groth16_prepare_verifying_key_bn254_cost_base"),
        else => {
            _ = c.charge(c.p("crypto_invalid_arguments_cost"));
            return c.abort(1); // INVALID_CURVE
        },
    };
    if (!c.charge(base)) return c.oog();
    const limit = c.flag("limit_groth16_pvk_inputs");
    if (curve == BLS12381) return switch (try groth16Bls.prepare(c.arena, vk, limit)) {
        .ok => |pvk| pvkValue(c, pvk.vk_gamma_abc_g1, &pvk.alpha_g1_beta_g2, &pvk.gamma_g2_neg_pc, &pvk.delta_g2_neg_pc),
        .abort => |code| c.abort(code),
    };
    return switch (try zk.groth16.native.prepareVerifyingKey(c.arena, curve, vk, limit)) {
        .ok => |pvk| pvkValue(c, pvk.vk_gamma_abc_g1, &pvk.alpha_g1_beta_g2, &pvk.gamma_g2_neg_pc, &pvk.delta_g2_neg_pc),
        .abort => |code| c.abort(code),
        .unsupported => Ctx.invariant(),
    };
}

fn pvkValue(c: *Ctx, a: []const u8, b: []const u8, g: []const u8, d: []const u8) Error!Outcome {
    const f = try c.arena.alloc(Value, 4);
    f[0] = try c.bytesValue(a);
    f[1] = try c.bytesValue(b);
    f[2] = try c.bytesValue(g);
    f[3] = try c.bytesValue(d);
    return c.ok1(.{ .@"struct" = f });
}

pub fn verify_groth16_proof_internal(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const proof = try abi.bytesOf(c.arena, args[6]);
    const inputs = try abi.bytesOf(c.arena, args[5]);
    const delta = try abi.bytesOf(c.arena, args[4]);
    const gamma = try abi.bytesOf(c.arena, args[3]);
    const alpha_beta = try abi.bytesOf(c.arena, args[2]);
    const gamma_abc = try abi.bytesOf(c.arena, args[1]);
    const curve = args[0].u8;
    const base, const per_input = switch (curve) {
        BLS12381 => .{ c.p("groth16_verify_groth16_proof_internal_bls12381_cost_base"), c.p("groth16_verify_groth16_proof_internal_bls12381_cost_per_public_input") },
        BN254 => .{ c.p("groth16_verify_groth16_proof_internal_bn254_cost_base"), c.p("groth16_verify_groth16_proof_internal_bn254_cost_per_public_input") },
        else => {
            _ = c.charge(c.p("crypto_invalid_arguments_cost"));
            const cost = if (c.flag("native_charging_v2")) c.used() else c.budget;
            return .{ .abort = .{ .cost = cost, .code = 1 } };
        },
    };
    if (!c.charge(base)) return c.oog();
    const n_inputs = blocks(inputs.len, 32);
    if (!c.charge(per_input *| n_inputs +| c.p("groth16_verify_groth16_proof_internal_public_input_cost_per_byte") *| inputs.len)) return c.oog();
    if (inputs.len > 32 * 8) return c.abort(2); // TOO_MANY_PUBLIC_INPUTS
    // v142 `check_groth16_pvk_length`: a key for n inputs holds n + 1 compressed G1 points
    // (48 bytes on BLS12-381, 32 on BN254), else INVALID_VERIFYING_KEY.
    if (c.cfg.feature_flags.check_groth16_pvk_length) {
        const g1_len: u64 = if (curve == BLS12381) 48 else 32;
        if (gamma_abc.len != (n_inputs + 1) * g1_len) return c.abort(0);
    }
    const ok = if (curve == BLS12381)
        groth16Bls.verify(gamma_abc, alpha_beta, gamma, delta, inputs, proof)
    else switch (zk.groth16.native.verifyProof(curve, .{ gamma_abc, alpha_beta, gamma, delta }, inputs, proof)) {
        .ok => |b| b,
        .abort => |code| return c.abort(code),
        .unsupported => return Ctx.invariant(),
    };
    return c.ok1(.{ .bool = ok });
}

const groth16Bls = @import("groth16_bls.zig");

// ---- group_ops ------------------------------------------------------------------------------

const NOT_SUPPORTED: u64 = 0;
const INVALID_INPUT: u64 = 1;
const INPUT_TOO_LONG: u64 = 2;

const G = enum(u8) { scalar = 0, g1 = 1, g2 = 2, gt = 3, g1u = 4, r_scalar = 5, r_point = 6, _ };

/// `v2_native_charge`: the gas used under native_charging_v2, else the cost when entered.
fn v2(c: *Ctx, cost: u64) u64 {
    return if (c.flag("native_charging_v2")) c.used() else cost;
}

/// `native_charge_gas_early_exit_option!`: a missing parameter is an invariant violation.
const Charge = enum { ok, oog, missing };
fn chargeOpt(c: *Ctx, amount: ?u64) Charge {
    const a = amount orelse return .missing;
    return if (c.charge(a)) .ok else .oog;
}

fn mapResult(c: *Ctx, cost: u64, r: anyerror![]const u8) Error!Outcome {
    const bytes = r catch return .{ .abort = .{ .cost = v2(c, cost), .code = INVALID_INPUT } };
    const v = try c.bytesValue(bytes);
    const rets = try c.arena.alloc(Value, 1);
    rets[0] = v;
    return .{ .ok = .{ .cost = v2(c, cost), .rets = rets } };
}

const ristretto = struct {
    const Ristretto = sig.ristretto255.Ristretto;
    const ed = std.crypto.ecc.Edwards25519;
    const sc = ed.scalar;

    fn fixed(comptime n: usize, b: []const u8) error{InvalidInput}!*const [n]u8 {
        if (b.len != n) return error.InvalidInput;
        return b[0..n];
    }
    /// from_trusted_byte_array: reduce mod l.
    fn scalarTrusted(b: []const u8) ![32]u8 {
        return sc.reduce((try fixed(32, b)).*);
    }
    fn point(b: []const u8) !Ristretto {
        return Ristretto.decode(try fixed(32, b)) orelse error.InvalidInput;
    }
    fn isZero(s: [32]u8) bool {
        return std.mem.allEqual(u8, &s, 0);
    }
    fn inv(s: [32]u8) ![32]u8 {
        if (isZero(s)) return error.InvalidInput;
        return sc.Scalar.fromBytes(s).invert().toBytes();
    }
    fn mulPoint(p: Ristretto, s: [32]u8) Ristretto {
        return .{ .p = sig.ed25519.mulCT(p.p, &s) };
    }
    fn validate(g: G, b: []const u8) bool {
        if (b.len != 32) return false;
        return switch (g) {
            .r_scalar => blk: {
                sc.rejectNonCanonical(b[0..32].*) catch break :blk false;
                break :blk true;
            },
            .r_point => Ristretto.decode(b[0..32]) != null,
            else => false,
        };
    }
    fn op(g: G, comptime which: enum { add, sub, mul, div }, a: []const u8, b: []const u8, out: *[32]u8) ![]const u8 {
        switch (g) {
            .r_scalar => {
                const x = try scalarTrusted(a);
                const y = try scalarTrusted(b);
                out.* = switch (which) {
                    .add => sc.add(x, y),
                    .sub => sc.sub(x, y),
                    .mul => sc.mul(y, x),
                    .div => sc.mul(y, try inv(x)),
                };
            },
            .r_point => switch (which) {
                .add => out.* = (try point(a)).add(try point(b)).encode(),
                .sub => out.* = (try point(a)).sub(try point(b)).encode(),
                .mul => {
                    const k = try scalarTrusted(a);
                    out.* = mulPoint(try point(b), k).encode();
                },
                .div => {
                    const k = try scalarTrusted(a);
                    const p = try point(b);
                    out.* = mulPoint(p, try inv(k)).encode();
                },
            },
            else => unreachable,
        }
        return out;
    }
};

fn binaryOp(c: *Ctx, args: []Value, comptime which: @TypeOf(.add), comptime names: [6][]const u8) Error!Outcome {
    const cost = c.used();
    if (!c.flag("enable_group_ops_native_functions")) return c.abort(NOT_SUPPORTED);
    const e2 = try abi.bytesOf(c.arena, args[2]);
    const e1 = try abi.bytesOf(c.arena, args[1]);
    const g: G = @enumFromInt(args[0].u8);
    var out: [bls.group_ops.max_out]u8 = undefined;
    var rout: [32]u8 = undefined;
    const idx: usize = switch (g) {
        .scalar => 0,
        .g1 => 1,
        .g2 => 2,
        .gt => 3,
        .r_scalar => 4,
        .r_point => 5,
        else => return mapResult(c, cost, error.InvalidInput),
    };
    if (idx >= 4 and !c.flag("enable_ristretto255_group_ops")) return .{ .abort = .{ .cost = cost, .code = NOT_SUPPORTED } };
    const name = switch (idx) {
        inline 0...5 => |i| names[i],
        else => unreachable,
    };
    _ = name;
    const amount: ?u64 = switch (idx) {
        inline 0...5 => |i| c.popt(names[i]),
        else => unreachable,
    };
    switch (chargeOpt(c, amount)) {
        .ok => {},
        .oog => return c.oog(),
        .missing => return Ctx.invariant(),
    }
    const bg: bls.group_ops.Group = @enumFromInt(@intFromEnum(g));
    const r: anyerror![]const u8 = if (idx >= 4) ristretto.op(g, which, e1, e2, &rout) else switch (which) {
        .add => bls.group_ops.add(bg, e1, e2, &out),
        .sub => bls.group_ops.sub(bg, e1, e2, &out),
        .mul => bls.group_ops.mul(bg, e1, e2, &out),
        .div => bls.group_ops.div(bg, e1, e2, &out),
        else => unreachable,
    };
    return mapResult(c, cost, r);
}

pub fn internal_validate(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const cost = c.used();
    if (!c.flag("enable_group_ops_native_functions")) return c.abort(NOT_SUPPORTED);
    const b = try abi.bytesOf(c.arena, args[1]);
    const g: G = @enumFromInt(args[0].u8);
    const param: ?[]const u8 = switch (g) {
        .scalar => "group_ops_bls12381_decode_scalar_cost",
        .g1 => "group_ops_bls12381_decode_g1_cost",
        .g2 => "group_ops_bls12381_decode_g2_cost",
        .r_scalar => "group_ops_ristretto_decode_scalar_cost",
        .r_point => "group_ops_ristretto_decode_point_cost",
        else => null,
    };
    var result = false;
    if (param != null) {
        if ((g == .r_scalar or g == .r_point) and !c.flag("enable_ristretto255_group_ops")) return .{ .abort = .{ .cost = cost, .code = NOT_SUPPORTED } };
        const amount: ?u64 = switch (g) {
            .scalar => c.popt("group_ops_bls12381_decode_scalar_cost"),
            .g1 => c.popt("group_ops_bls12381_decode_g1_cost"),
            .g2 => c.popt("group_ops_bls12381_decode_g2_cost"),
            .r_scalar => c.popt("group_ops_ristretto_decode_scalar_cost"),
            .r_point => c.popt("group_ops_ristretto_decode_point_cost"),
            else => unreachable,
        };
        switch (chargeOpt(c, amount)) {
            .ok => {},
            .oog => return c.oog(),
            .missing => return Ctx.invariant(),
        }
        result = switch (g) {
            .scalar, .g1, .g2 => bls.group_ops.validate(@enumFromInt(@intFromEnum(g)), b),
            else => ristretto.validate(g, b),
        };
    }
    const rets = try c.arena.alloc(Value, 1);
    rets[0] = .{ .bool = result };
    return .{ .ok = .{ .cost = v2(c, cost), .rets = rets } };
}

pub fn internal_add(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    return binaryOp(c, args, .add, .{ "group_ops_bls12381_scalar_add_cost", "group_ops_bls12381_g1_add_cost", "group_ops_bls12381_g2_add_cost", "group_ops_bls12381_gt_add_cost", "group_ops_ristretto_scalar_add_cost", "group_ops_ristretto_point_add_cost" });
}

pub fn internal_sub(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    return binaryOp(c, args, .sub, .{ "group_ops_bls12381_scalar_sub_cost", "group_ops_bls12381_g1_sub_cost", "group_ops_bls12381_g2_sub_cost", "group_ops_bls12381_gt_sub_cost", "group_ops_ristretto_scalar_sub_cost", "group_ops_ristretto_point_sub_cost" });
}

pub fn internal_mul(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    return binaryOp(c, args, .mul, .{ "group_ops_bls12381_scalar_mul_cost", "group_ops_bls12381_g1_mul_cost", "group_ops_bls12381_g2_mul_cost", "group_ops_bls12381_gt_mul_cost", "group_ops_ristretto_scalar_mul_cost", "group_ops_ristretto_point_mul_cost" });
}

pub fn internal_div(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    return binaryOp(c, args, .div, .{ "group_ops_bls12381_scalar_div_cost", "group_ops_bls12381_g1_div_cost", "group_ops_bls12381_g2_div_cost", "group_ops_bls12381_gt_div_cost", "group_ops_ristretto_scalar_div_cost", "group_ops_ristretto_point_div_cost" });
}

pub fn internal_hash_to(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const cost = c.used();
    if (!c.flag("enable_group_ops_native_functions")) return c.abort(NOT_SUPPORTED);
    const m = try abi.bytesOf(c.arena, args[1]);
    const g: G = @enumFromInt(args[0].u8);
    if (m.len == 0) return .{ .abort = .{ .cost = cost, .code = INVALID_INPUT } };
    const amount: ?u64 = switch (g) {
        .g1 => if (c.popt("group_ops_bls12381_g1_hash_to_base_cost")) |b| (if (c.popt("group_ops_bls12381_g1_hash_to_cost_per_byte")) |pb| b +| pb *| m.len else null) else null,
        .g2 => if (c.popt("group_ops_bls12381_g2_hash_to_base_cost")) |b| (if (c.popt("group_ops_bls12381_g2_hash_to_cost_per_byte")) |pb| b +| pb *| m.len else null) else null,
        else => return mapResult(c, cost, error.InvalidInput),
    };
    switch (chargeOpt(c, amount)) {
        .ok => {},
        .oog => return c.oog(),
        .missing => return Ctx.invariant(),
    }
    var out: [bls.group_ops.max_out]u8 = undefined;
    return mapResult(c, cost, bls.group_ops.hashTo(@enumFromInt(@intFromEnum(g)), m, &out));
}

/// sui-move-natives `msm_num_of_additions`.
pub fn msmNumOfAdditions(n: u64) u64 {
    const wbits: u64 = 63 - @as(u64, @clz(n));
    const window: u64 = switch (wbits) {
        0 => 1,
        1...4 => 2,
        5...12 => wbits - 2,
        else => wbits - 3,
    };
    const windows = 255 / window + @as(u64, if (255 % window == 0) 0 else 1);
    return windows * (n + (@as(u64, 1) << @intCast(window)) + 1);
}

pub fn internal_multi_scalar_mul(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const cost = c.used();
    if (!c.flag("enable_group_ops_native_function_msm")) return c.abort(NOT_SUPPORTED);
    const points = try abi.bytesOf(c.arena, args[2]);
    const scalars = try abi.bytesOf(c.arena, args[1]);
    const g: G = @enumFromInt(args[0].u8);
    const max_len = c.popt("group_ops_bls12381_msm_max_len") orelse return Ctx.invariant();
    const plen: usize, const decode_point: ?u64, const base: ?u64, const per_add: ?u64 = switch (g) {
        .g1 => .{ 48, c.popt("group_ops_bls12381_decode_g1_cost"), c.popt("group_ops_bls12381_g1_msm_base_cost"), c.popt("group_ops_bls12381_g1_msm_base_cost_per_input") },
        .g2 => .{ 96, c.popt("group_ops_bls12381_decode_g2_cost"), c.popt("group_ops_bls12381_g2_msm_base_cost"), c.popt("group_ops_bls12381_g2_msm_base_cost_per_input") },
        else => return .{ .abort = .{ .cost = v2(c, cost), .code = INVALID_INPUT } },
    };
    if (points.len == 0 or scalars.len == 0 or scalars.len % 32 != 0 or points.len % plen != 0 or points.len / plen != scalars.len / 32)
        return c.abort(INVALID_INPUT);
    const n: u64 = points.len / plen;
    if (n > max_len) return c.abort(INPUT_TOO_LONG);
    var out: [bls.group_ops.max_out]u8 = undefined;
    const r = bls.group_ops.multiScalarMul(@enumFromInt(@intFromEnum(g)), scalars, points, &out);
    const decode_scalar = c.popt("group_ops_bls12381_decode_scalar_cost");
    switch (chargeOpt(c, if (decode_scalar) |d| d *| n else null)) {
        .ok => {},
        .oog => return c.oog(),
        .missing => return Ctx.invariant(),
    }
    switch (chargeOpt(c, if (decode_point) |d| d *| n else null)) {
        .ok => {},
        .oog => return c.oog(),
        .missing => return Ctx.invariant(),
    }
    const bytes = r catch return c.abort(INVALID_INPUT);
    const amount: ?u64 = if (base) |b| (if (per_add) |pa| b +| pa *| msmNumOfAdditions(n) else null) else null;
    switch (chargeOpt(c, amount)) {
        .ok => {},
        .oog => return c.oog(),
        .missing => return Ctx.invariant(),
    }
    return c.ok1Bytes(bytes);
}

pub fn internal_pairing(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const cost = c.used();
    if (!c.flag("enable_group_ops_native_functions")) return c.abort(NOT_SUPPORTED);
    const e2 = try abi.bytesOf(c.arena, args[2]);
    const e1 = try abi.bytesOf(c.arena, args[1]);
    const g: G = @enumFromInt(args[0].u8);
    if (g != .g1) return mapResult(c, cost, error.InvalidInput);
    switch (chargeOpt(c, c.popt("group_ops_bls12381_pairing_cost"))) {
        .ok => {},
        .oog => return c.oog(),
        .missing => return Ctx.invariant(),
    }
    var out: [bls.group_ops.max_out]u8 = undefined;
    return mapResult(c, cost, bls.group_ops.pairing(.g1, e1, e2, &out));
}

pub fn internal_convert(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const cost = c.used();
    if (!c.flag("uncompressed_g1_group_elements")) return c.abort(NOT_SUPPORTED);
    const e = try abi.bytesOf(c.arena, args[2]);
    const to: G = @enumFromInt(args[1].u8);
    const from: G = @enumFromInt(args[0].u8);
    const amount: ?u64 = if (from == .g1u and to == .g1)
        c.popt("group_ops_bls12381_uncompressed_g1_to_g1_cost")
    else if (from == .g1 and to == .g1u)
        c.popt("group_ops_bls12381_g1_to_uncompressed_g1_cost")
    else
        return mapResult(c, cost, error.InvalidInput);
    switch (chargeOpt(c, amount)) {
        .ok => {},
        .oog => return c.oog(),
        .missing => return Ctx.invariant(),
    }
    var out: [bls.group_ops.max_out]u8 = undefined;
    return mapResult(c, cost, bls.group_ops.convert(@enumFromInt(@intFromEnum(from)), @enumFromInt(@intFromEnum(to)), e, &out));
}

pub fn internal_sum(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const cost = c.used();
    if (!c.flag("uncompressed_g1_group_elements")) return c.abort(NOT_SUPPORTED);
    const g: G = @enumFromInt(args[0].u8);
    const n: u64 = args[1].vector.len;
    if (g != .g1u) return mapResult(c, cost, error.InvalidInput);
    const max_terms = c.popt("group_ops_bls12381_uncompressed_g1_sum_max_terms") orelse return Ctx.invariant();
    if (n > max_terms) return .{ .abort = .{ .cost = cost, .code = INPUT_TOO_LONG } };
    const amount: ?u64 = if (c.popt("group_ops_bls12381_uncompressed_g1_sum_base_cost")) |b|
        (if (c.popt("group_ops_bls12381_uncompressed_g1_sum_cost_per_term")) |pt| b +| pt *| n else null)
    else
        null;
    switch (chargeOpt(c, amount)) {
        .ok => {},
        .oog => return c.oog(),
        .missing => return Ctx.invariant(),
    }
    const terms = try abi.vecOfBytesOf(c.arena, args[1]);
    const cterms = try c.arena.alloc([]const u8, terms.len);
    for (cterms, terms) |*o, t| o.* = t;
    var out: [bls.group_ops.max_out]u8 = undefined;
    return mapResult(c, cost, bls.group_ops.sum(.g1_uncompressed, cterms, &out));
}

test "msm additions" {
    try std.testing.expectEqual(@as(u64, 1020), msmNumOfAdditions(1));
    try std.testing.expectEqual(@as(u64, 896), msmNumOfAdditions(2));
    try std.testing.expectEqual(@as(u64, 1024), msmNumOfAdditions(3));
    try std.testing.expectEqual(@as(u64, 1152), msmNumOfAdditions(4));
    try std.testing.expectEqual(@as(u64, 3485), msmNumOfAdditions(32));
}

// ---- zklogin_verified_id / zklogin_verified_issuer ------------------------------------------
//
// fastcrypto `verify_zk_login_id` / `verify_zk_login_iss`: the address is
// blake2b(0x05 || len(iss) as u8 || iss || seed as 32 BE bytes). The u256 arguments go through
// their decimal string into `Fr::from_str`, which reduces mod r. Any input error (not UTF-8, a
// claim longer than its bound, a code point above 0xff) aborts INVALID_INPUT; a mismatch is false.

const zl_invalid_input: u64 = 0;

fn frOfU256(x: u256) zk.bn254.Fr {
    var be: [32]u8 = undefined;
    std.mem.writeInt(u256, &be, x, .big);
    return zk.bn254.Fr.fromBytesBeModOrder(&be);
}

fn zkloginAddressIs(addr: *const [32]u8, seed: zk.bn254.Fr, iss: []const u8) bool {
    const be = seed.toBytesBe();
    const got = zk.zklogin.address(iss, &be, true);
    return std.mem.eql(u8, &got, addr);
}

pub fn check_zklogin_id_internal(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.popt("check_zklogin_id_cost_base") orelse return Ctx.invariant())) return c.oog();
    const addr = args[0].address;
    const name = try abi.bytesOf(c.arena, args[1]);
    const value = try abi.bytesOf(c.arena, args[2]);
    const iss = try abi.bytesOf(c.arena, args[3]);
    const aud = try abi.bytesOf(c.arena, args[4]);
    for ([_][]const u8{ name, value, aud, iss }) |s| if (!std.unicode.utf8ValidateSlice(s)) return c.abort(zl_invalid_input);
    var fail: zk.errors.Fail = .none;
    const seed = zk.zklogin.addressSeedWithSaltHash(frOfU256(args[5].u256), name, value, aud, &fail) orelse return c.abort(zl_invalid_input);
    return c.ok1(.{ .bool = zkloginAddressIs(&addr, seed, iss) });
}

pub fn check_zklogin_issuer_internal(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.popt("check_zklogin_issuer_cost_base") orelse return Ctx.invariant())) return c.oog();
    const addr = args[0].address;
    const iss = try abi.bytesOf(c.arena, args[2]);
    if (!std.unicode.utf8ValidateSlice(iss)) return c.abort(zl_invalid_input);
    return c.ok1(.{ .bool = zkloginAddressIs(&addr, frOfU256(args[1].u256), iss) });
}

// ---- natives that are off on mainnet ----------------------------------------------------------
//
// `vdf` (enable_vdf) and `rangeproofs` (enable_verify_bulletproofs_ristretto255) are enabled only
// on chains other than mainnet and testnet (vdf) or other than mainnet (bulletproofs), at every
// protocol version. On mainnet they abort NOT_SUPPORTED before charging anything. deepwave implements
// that path; with the flag on (devnet configs) they are not implemented and return an invariant
// violation rather than a made-up answer.

pub fn vdf_verify_internal(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.flag("enable_vdf")) return c.abort(1); // NOT_SUPPORTED_ERROR
    return Ctx.invariant();
}

pub fn hash_to_input_internal(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.flag("enable_vdf")) return c.abort(1); // NOT_SUPPORTED_ERROR
    return Ctx.invariant();
}

/// The pre-DST entry: disabled in Rust at every version (no Move declaration reaches it).
pub fn verify_bulletproofs_ristretto255(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    return c.abort(0); // NOT_SUPPORTED
}

pub fn verify_bulletproofs_with_dst_ristretto255(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.flag("enable_verify_bulletproofs_ristretto255")) return c.abort(0); // NOT_SUPPORTED
    return Ctx.invariant();
}

test "groth16 v142 check_groth16_pvk_length: a key for n inputs is n + 1 G1 points" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tx: abi.TxContext = .{ .sender = @splat(1), .digest = @splat(2), .epoch = 1, .epoch_timestamp_ms = 0, .rgp = 1, .gas_price = 1, .gas_budget = 1, .sponsor = null };
    var r: abi.ObjectRuntime = .{};
    const vec = struct {
        fn of(al: std.mem.Allocator, n: usize) !Value {
            const xs = try al.alloc(Value, n);
            for (xs) |*x| x.* = .{ .u8 = 0 };
            return .{ .vector = xs };
        }
    }.of;
    // BN254 (1): 2 inputs need 3 * 32 bytes; BLS12-381 (0): 2 inputs need 3 * 48
    const cases = [_]struct { u8, usize }{ .{ 1, 32 }, .{ 0, 48 } };
    for (cases) |cs| {
        var args = [_]Value{ .{ .u8 = cs[0] }, try vec(a, 2 * cs[1]), try vec(a, 576), try vec(a, 128), try vec(a, 128), try vec(a, 64), try vec(a, 128) };
        var c = abi.Ctx.init(a, try protocol.get(142, .mainnet), 10_000_000, &tx, &r);
        const out = try verify_groth16_proof_internal(&c, &.{}, &args);
        try std.testing.expectEqual(@as(u64, 0), out.abort.code); // INVALID_VERIFYING_KEY
        try std.testing.expect(out.abort.cost > 0);
    }
}
