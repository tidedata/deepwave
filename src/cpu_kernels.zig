//! Root of the per-tier kernel objects (build.zig compiles this once per x86-64 tier in
//! core/cpu_tiers.zig, with that tier's CPU model). Every entry is exported as
//! `zui_k_<tier>_<name>`; the portable code calls it through `core.cpu.call(name, f, args)`.
//! Inside this object `core.cpu` dispatch is off, so each `f` runs as compiled here.
const cpu = @import("core").cpu;
const hash = @import("hash");
const sig = @import("sig");
const bls = @import("bls");
const zk = @import("zk");

pub const entries = .{
    .{ "blake2b_blocks", hash.blake2b.compressBlocksImpl },
    .{ "blake2b256_many", hash.blake2b.blake2b256ManyImpl },
    .{ "sha512_block", hash.sha2.compress512Soft },
    .{ "keccak_f1600", hash.keccak.permuteSoft },
    .{ "keccak_absorb", hash.keccak.absorbSoft },
    .{ "ed25519_verify", sig.ed25519.verifyImpl },
    .{ "ed25519_verify_decoded", sig.ed25519.verifyDecodedImpl },
    .{ "ed25519_verify_prehashed", sig.ed25519.PublicKey.verifyPrehashedImpl },
    .{ "ed25519_verify_batch", sig.ed25519.verifyBatchImpl },
    .{ "ecdsa_k1_verify", sig.secp256k1.verifyDigestParsedImpl },
    .{ "ecdsa_k1_verify_slices", sig.secp256k1.verifyDigestSlicesImpl },
    .{ "ecdsa_k1_recover", sig.secp256k1.recoverSlicesModeImpl },
    .{ "ecdsa_r1_verify", sig.secp256r1.verifyDigestParsedImpl },
    .{ "ecdsa_r1_verify_slices", sig.secp256r1.verifyDigestSlicesImpl },
    .{ "ecdsa_r1_recover", sig.secp256r1.recoverSlicesModeImpl },
    .{ "bls_core_verify", bls.sig.coreVerifyImpl },
    .{ "bls_verify_bytes", bls.sig.verifyBytesImpl },
    .{ "bls_verify_validated", bls.sig.verifyValidatedImpl },
    .{ "bls_aggregate_verify", bls.sig.aggregateVerifyImpl },
    .{ "bls_cert_verify", bls.sig.PreparedCommittee.verifyAggregateVerdictImpl },
    .{ "bls_pairing_check", bls.pairingCheckImpl },
    .{ "bls_pairing_product_is", bls.pairingProductIsImpl },
    .{ "bls_decode_keys", bls.sig.PreparedCommittee.decodeKeysImpl },
    .{ "bls_go_validate", bls.group_ops.validateImpl },
    .{ "bls_go_add", bls.group_ops.addImpl },
    .{ "bls_go_sub", bls.group_ops.subImpl },
    .{ "bls_go_mul", bls.group_ops.mulImpl },
    .{ "bls_go_div", bls.group_ops.divImpl },
    .{ "bls_go_hashTo", bls.group_ops.hashToImpl },
    .{ "bls_go_multiScalarMul", bls.group_ops.multiScalarMulImpl },
    .{ "bls_go_pairing", bls.group_ops.pairingImpl },
    .{ "bls_go_convert", bls.group_ops.convertImpl },
    .{ "bls_go_sum", bls.group_ops.sumImpl },
    .{ "bn254_pairing_equation", zk.groth16.pairingEquationImpl },
    .{ "aes128gcm_seal", cpu.aes.gcmSealImpl },
    .{ "aes128gcm_open", cpu.aes.gcmOpenImpl },
    .{ "aes128_block", cpu.aes.encryptBlockImpl },
};

comptime {
    const t = cpu.kernel_tier orelse @compileError("cpu_kernels.zig is only built as a kernel object");
    for (entries) |en| @export(&cpu.Thunk(en[1]).run, .{ .name = cpu.symbol(t, en[0]) });
}
