//! The native function table: (package, module, function) to implementation, as
//! `all_natives` registers them for move-stdlib (0x1) and the Sui framework (0x2).
//! Test-only natives (test_scenario, test_utils, event::num_events/events_by_type,
//! random::generate_rand_seed_for_testing, ecdsa_k1 sign/keypair, tx_context::replace) are not
//! here: published bytecode cannot reach them.
const std = @import("std");
const abi = @import("abi.zig");
const stdlib = @import("stdlib.zig");
const sui = @import("sui.zig");
const crypto = @import("crypto.zig");
const obj = @import("objnatives.zig");
const nitro = @import("nitro.zig");
const validator = @import("validator.zig");

/// `since`: the protocol version whose framework first declares the native (0: older than the
/// truth corpus). Vectors generated at an earlier release may not list it yet.
pub const Entry = struct { addr: u16, module: []const u8, func: []const u8, f: abi.NativeFn, since: u64 = 0 };

pub const entries = [_]Entry{
    // move-stdlib
    .{ .addr = 1, .module = "bcs", .func = "to_bytes", .f = stdlib.to_bytes },
    .{ .addr = 1, .module = "debug", .func = "print", .f = stdlib.print },
    .{ .addr = 1, .module = "debug", .func = "print_stack_trace", .f = stdlib.print_stack_trace },
    .{ .addr = 1, .module = "hash", .func = "sha2_256", .f = stdlib.sha2_256 },
    .{ .addr = 1, .module = "hash", .func = "sha3_256", .f = stdlib.sha3_256 },
    .{ .addr = 1, .module = "string", .func = "internal_check_utf8", .f = stdlib.internal_check_utf8 },
    .{ .addr = 1, .module = "string", .func = "internal_is_char_boundary", .f = stdlib.internal_is_char_boundary },
    .{ .addr = 1, .module = "string", .func = "internal_sub_string", .f = stdlib.internal_sub_string },
    .{ .addr = 1, .module = "string", .func = "internal_index_of", .f = stdlib.internal_index_of },
    // `get` / `get_with_original_ids`: the names frameworks before `with_defining_ids` declare
    // native (execution versions 0 to 3); the latest Rust table registers both as well.
    .{ .addr = 1, .module = "type_name", .func = "get", .f = stdlib.with_defining_ids },
    .{ .addr = 1, .module = "type_name", .func = "get_with_original_ids", .f = stdlib.with_original_ids },
    .{ .addr = 1, .module = "type_name", .func = "with_defining_ids", .f = stdlib.with_defining_ids },
    .{ .addr = 1, .module = "type_name", .func = "with_original_ids", .f = stdlib.with_original_ids },
    .{ .addr = 1, .module = "type_name", .func = "defining_id", .f = stdlib.defining_id },
    .{ .addr = 1, .module = "type_name", .func = "original_id", .f = stdlib.original_id },
    .{ .addr = 1, .module = "vector", .func = "empty", .f = stdlib.empty },
    .{ .addr = 1, .module = "vector", .func = "length", .f = stdlib.length },
    .{ .addr = 1, .module = "vector", .func = "push_back", .f = stdlib.push_back },
    .{ .addr = 1, .module = "vector", .func = "pop_back", .f = stdlib.pop_back },
    .{ .addr = 1, .module = "vector", .func = "destroy_empty", .f = stdlib.destroy_empty },
    .{ .addr = 1, .module = "vector", .func = "swap", .f = stdlib.swap },
    .{ .addr = 1, .module = "vector", .func = "reverse", .f = stdlib.reverse },
    .{ .addr = 1, .module = "vector", .func = "keep_range", .f = stdlib.keep_range },
    .{ .addr = 1, .module = "vector", .func = "copy_range", .f = stdlib.copy_range },
    .{ .addr = 1, .module = "vector", .func = "replace_range", .f = stdlib.replace_range },
    // sui framework
    .{ .addr = 2, .module = "address", .func = "from_bytes", .f = sui.address_from_bytes },
    .{ .addr = 2, .module = "address", .func = "to_u256", .f = sui.address_to_u256 },
    .{ .addr = 2, .module = "address", .func = "from_u256", .f = sui.address_from_u256 },
    .{ .addr = 2, .module = "hash", .func = "blake2b256", .f = sui.blake2b256 },
    .{ .addr = 2, .module = "hash", .func = "keccak256", .f = sui.keccak256 },
    .{ .addr = 2, .module = "hmac", .func = "hmac_sha3_256", .f = sui.hmac_sha3_256 },
    .{ .addr = 2, .module = "tx_context", .func = "derive_id", .f = sui.derive_id },
    .{ .addr = 2, .module = "tx_context", .func = "fresh_id", .f = sui.fresh_id },
    .{ .addr = 2, .module = "tx_context", .func = "native_sender", .f = sui.native_sender },
    .{ .addr = 2, .module = "tx_context", .func = "native_epoch", .f = sui.native_epoch },
    .{ .addr = 2, .module = "tx_context", .func = "native_epoch_timestamp_ms", .f = sui.native_epoch_timestamp_ms },
    .{ .addr = 2, .module = "tx_context", .func = "native_sponsor", .f = sui.native_sponsor },
    .{ .addr = 2, .module = "tx_context", .func = "native_rgp", .f = sui.native_rgp },
    .{ .addr = 2, .module = "tx_context", .func = "native_gas_price", .f = sui.native_gas_price },
    .{ .addr = 2, .module = "tx_context", .func = "native_gas_budget", .f = sui.native_gas_budget },
    .{ .addr = 2, .module = "tx_context", .func = "native_ids_created", .f = sui.native_ids_created },
    .{ .addr = 2, .module = "types", .func = "is_one_time_witness", .f = sui.is_one_time_witness },
    .{ .addr = 2, .module = "protocol_config", .func = "is_feature_enabled", .f = sui.is_feature_enabled },
    .{ .addr = 2, .module = "dynamic_field", .func = "hash_type_and_key", .f = sui.hash_type_and_key },
    .{ .addr = 2, .module = "tx_context", .func = "last_created_id", .f = obj.last_created_id },
    .{ .addr = 2, .module = "object", .func = "borrow_uid", .f = obj.borrow_uid },
    .{ .addr = 2, .module = "object", .func = "delete_impl", .f = obj.delete_impl },
    .{ .addr = 2, .module = "object", .func = "record_new_uid", .f = obj.record_new_uid },
    .{ .addr = 2, .module = "object", .func = "record_new_uid_from_hash", .f = obj.record_new_uid_from_hash },
    .{ .addr = 2, .module = "object", .func = "is_shared_input_impl", .f = obj.is_shared_input_impl, .since = 142 },
    .{ .addr = 2, .module = "clock", .func = "native_borrow", .f = obj.clock_native_borrow, .since = 142 },
    .{ .addr = 2, .module = "transfer", .func = "transfer_impl", .f = obj.transfer_impl },
    .{ .addr = 2, .module = "transfer", .func = "party_transfer_impl", .f = obj.party_transfer_impl },
    .{ .addr = 2, .module = "transfer", .func = "freeze_object_impl", .f = obj.freeze_object_impl },
    .{ .addr = 2, .module = "transfer", .func = "share_object_impl", .f = obj.share_object_impl },
    .{ .addr = 2, .module = "transfer", .func = "receive_impl", .f = obj.receive_impl },
    .{ .addr = 2, .module = "event", .func = "emit", .f = obj.emit },
    .{ .addr = 2, .module = "event", .func = "emit_authenticated_impl", .f = obj.emit_authenticated_impl },
    .{ .addr = 2, .module = "dynamic_field", .func = "add_child_object", .f = obj.add_child_object },
    .{ .addr = 2, .module = "dynamic_field", .func = "borrow_child_object", .f = obj.borrow_child_object },
    .{ .addr = 2, .module = "dynamic_field", .func = "borrow_child_object_mut", .f = obj.borrow_child_object_mut },
    .{ .addr = 2, .module = "dynamic_field", .func = "remove_child_object", .f = obj.remove_child_object },
    .{ .addr = 2, .module = "dynamic_field", .func = "has_child_object", .f = obj.has_child_object },
    .{ .addr = 2, .module = "dynamic_field", .func = "has_child_object_with_ty", .f = obj.has_child_object_with_ty },
    .{ .addr = 2, .module = "accumulator", .func = "emit_deposit_event", .f = obj.emit_deposit_event },
    .{ .addr = 2, .module = "accumulator", .func = "emit_withdraw_event", .f = obj.emit_withdraw_event },
    .{ .addr = 2, .module = "accumulator_settlement", .func = "record_settlement_sui_conservation", .f = obj.record_settlement_sui_conservation },
    .{ .addr = 2, .module = "funds_accumulator", .func = "add_to_accumulator_address", .f = obj.add_to_accumulator_address },
    .{ .addr = 2, .module = "funds_accumulator", .func = "withdraw_from_accumulator_address", .f = obj.withdraw_from_accumulator_address },
    .{ .addr = 2, .module = "funds_accumulator", .func = "reserve_object_funds_for_withdrawal", .f = obj.reserve_object_funds_for_withdrawal },
    .{ .addr = 2, .module = "config", .func = "read_setting_impl", .f = obj.read_setting_impl },
    .{ .addr = 2, .module = "package", .func = "original_package_id_impl", .f = obj.original_package_id_impl },
    .{ .addr = 2, .module = "scratch", .func = "add_impl", .f = obj.scratch_add_impl },
    .{ .addr = 2, .module = "scratch", .func = "read_impl", .f = obj.scratch_read_impl },
    .{ .addr = 2, .module = "scratch", .func = "remove_impl", .f = obj.scratch_remove_impl },
    .{ .addr = 2, .module = "scratch", .func = "exists_impl", .f = obj.scratch_exists_impl },
    .{ .addr = 2, .module = "scratch", .func = "exists_with_type_impl", .f = obj.scratch_exists_with_type_impl },
    .{ .addr = 2, .module = "ed25519", .func = "ed25519_verify", .f = crypto.ed25519_verify },
    .{ .addr = 2, .module = "ecdsa_k1", .func = "secp256k1_ecrecover", .f = crypto.k1.ecrecover },
    .{ .addr = 2, .module = "ecdsa_k1", .func = "secp256k1_verify", .f = crypto.k1.verify },
    .{ .addr = 2, .module = "ecdsa_k1", .func = "decompress_pubkey", .f = crypto.decompress_pubkey },
    .{ .addr = 2, .module = "ecdsa_r1", .func = "secp256r1_ecrecover", .f = crypto.r1.ecrecover },
    .{ .addr = 2, .module = "ecdsa_r1", .func = "secp256r1_verify", .f = crypto.r1.verify },
    .{ .addr = 2, .module = "bls12381", .func = "bls12381_min_sig_verify", .f = crypto.bls12381_min_sig_verify },
    .{ .addr = 2, .module = "bls12381", .func = "bls12381_min_pk_verify", .f = crypto.bls12381_min_pk_verify },
    .{ .addr = 2, .module = "ecvrf", .func = "ecvrf_verify", .f = crypto.ecvrf_verify },
    .{ .addr = 2, .module = "poseidon", .func = "poseidon_bn254_internal", .f = crypto.poseidon_bn254_internal },
    .{ .addr = 2, .module = "zklogin_verified_id", .func = "check_zklogin_id_internal", .f = crypto.check_zklogin_id_internal },
    .{ .addr = 2, .module = "zklogin_verified_issuer", .func = "check_zklogin_issuer_internal", .f = crypto.check_zklogin_issuer_internal },
    .{ .addr = 2, .module = "vdf", .func = "vdf_verify_internal", .f = crypto.vdf_verify_internal },
    .{ .addr = 2, .module = "vdf", .func = "hash_to_input_internal", .f = crypto.hash_to_input_internal },
    .{ .addr = 2, .module = "rangeproofs", .func = "verify_bulletproofs_ristretto255_internal", .f = crypto.verify_bulletproofs_ristretto255 },
    .{ .addr = 2, .module = "rangeproofs", .func = "verify_bulletproofs_with_dst_ristretto255_internal", .f = crypto.verify_bulletproofs_with_dst_ristretto255 },
    .{ .addr = 2, .module = "nitro_attestation", .func = "load_nitro_attestation_internal", .f = nitro.load_nitro_attestation_internal },
    .{ .addr = 3, .module = "validator", .func = "validate_metadata_bcs", .f = validator.validate_metadata_bcs },
    .{ .addr = 2, .module = "groth16", .func = "prepare_verifying_key_internal", .f = crypto.prepare_verifying_key_internal },
    .{ .addr = 2, .module = "groth16", .func = "verify_groth16_proof_internal", .f = crypto.verify_groth16_proof_internal },
    .{ .addr = 2, .module = "group_ops", .func = "internal_validate", .f = crypto.internal_validate },
    .{ .addr = 2, .module = "group_ops", .func = "internal_add", .f = crypto.internal_add },
    .{ .addr = 2, .module = "group_ops", .func = "internal_sub", .f = crypto.internal_sub },
    .{ .addr = 2, .module = "group_ops", .func = "internal_mul", .f = crypto.internal_mul },
    .{ .addr = 2, .module = "group_ops", .func = "internal_div", .f = crypto.internal_div },
    .{ .addr = 2, .module = "group_ops", .func = "internal_hash_to", .f = crypto.internal_hash_to },
    .{ .addr = 2, .module = "group_ops", .func = "internal_multi_scalar_mul", .f = crypto.internal_multi_scalar_mul },
    .{ .addr = 2, .module = "group_ops", .func = "internal_pairing", .f = crypto.internal_pairing },
    .{ .addr = 2, .module = "group_ops", .func = "internal_convert", .f = crypto.internal_convert },
    .{ .addr = 2, .module = "group_ops", .func = "internal_sum", .f = crypto.internal_sum },
};

fn key(comptime e: Entry) []const u8 {
    return std.fmt.comptimePrint("{d}::{s}::{s}", .{ e.addr, e.module, e.func });
}

const map = blk: {
    @setEvalBranchQuota(100_000);
    var kvs: [entries.len]struct { []const u8, abi.NativeFn } = undefined;
    for (entries, 0..) |e, i| kvs[i] = .{ key(e), e.f };
    break :blk std.StaticStringMap(abi.NativeFn).initComptime(kvs);
};

/// The native at `addr::module::func` (addr is the short address 0x1/0x2/0x3/...).
pub fn lookup(addr: u16, module: []const u8, func: []const u8) ?abi.NativeFn {
    var buf: [256]u8 = undefined;
    const k = std.fmt.bufPrint(&buf, "{d}::{s}::{s}", .{ addr, module, func }) catch return null;
    return map.get(k);
}

test "lookup" {
    try std.testing.expect(lookup(1, "vector", "length") != null);
    try std.testing.expect(lookup(2, "group_ops", "internal_sum") != null);
    try std.testing.expect(lookup(2, "nope", "x") == null);
}
