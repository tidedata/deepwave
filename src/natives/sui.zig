//! Sui framework natives that need no object runtime beyond new ids (sui-move-natives latest,
//! mainnet-v1.83.1): address, hash, hmac, tx_context, types, protocol_config and
//! dynamic_field::hash_type_and_key.
const std = @import("std");
const hash = @import("hash");
const protocol = @import("protocol");
const abi = @import("abi.zig");

const Ctx = abi.Ctx;
const Value = abi.Value;
const TyArg = abi.TyArg;
const Outcome = abi.Outcome;
const Error = abi.Error;

inline fn blocks(len: usize, block: usize) u64 {
    return @intCast((len + block - 1) / block);
}

// ---- address --------------------------------------------------------------------------------

pub fn address_from_bytes(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("address_from_bytes_cost_base"))) return c.oog();
    const b = try abi.bytesOf(c.arena, args[0]);
    if (b.len != 32) return c.abort(0); // E_ADDRESS_PARSE_ERROR
    const a: [32]u8 = b[0..32].*;
    return c.ok1(.{ .address = a });
}

pub fn address_to_u256(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("address_to_u256_cost_base"))) return c.oog();
    return c.ok1(.{ .u256 = std.mem.readInt(u256, &args[0].address, .big) });
}

pub fn address_from_u256(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("address_from_u256_cost_base"))) return c.oog();
    var a: [32]u8 = undefined;
    std.mem.writeInt(u256, &a, args[0].u256, .big);
    return c.ok1(.{ .address = a });
}

// ---- hash / hmac ----------------------------------------------------------------------------

pub fn blake2b256(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("hash_blake2b256_cost_base"))) return c.oog();
    const m = try abi.bytesOf(c.arena, args[0]);
    if (!c.charge(c.p("hash_blake2b256_data_cost_per_byte") *| m.len +| c.p("hash_blake2b256_data_cost_per_block") *| blocks(m.len, 128))) return c.oog();
    var out: [32]u8 = undefined;
    hash.Blake2b256.hash(m, &out);
    return c.ok1Bytes(&out);
}

pub fn keccak256(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("hash_keccak256_cost_base"))) return c.oog();
    const m = try abi.bytesOf(c.arena, args[0]);
    if (!c.charge(c.p("hash_keccak256_data_cost_per_byte") *| m.len +| c.p("hash_keccak256_data_cost_per_block") *| blocks(m.len, 136))) return c.oog();
    var out: [32]u8 = undefined;
    hash.Keccak256.hash(m, &out);
    return c.ok1Bytes(&out);
}

pub fn hmac_sha3_256(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("hmac_hmac_sha3_256_cost_base"))) return c.oog();
    const msg = try abi.bytesOf(c.arena, args[1]);
    const key = try abi.bytesOf(c.arena, args[0]);
    const n = msg.len + key.len;
    if (!c.charge(c.p("hmac_hmac_sha3_256_input_cost_per_byte") *| n +| c.p("hmac_hmac_sha3_256_input_cost_per_block") *| ((n + 2 * 136 - 2) / 136))) return c.oog();
    const out = hash.hmacSha3_256(key, msg);
    return c.ok1Bytes(&out);
}

// ---- tx_context -----------------------------------------------------------------------------

pub fn derive_id(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("tx_context_derive_id_cost_base"))) return c.oog();
    const n = args[1].u64;
    const d = try abi.bytesOf(c.arena, args[0]);
    if (d.len != 32) return Ctx.invariant(); // TransactionDigest::try_from in safe_unwrap!
    const digest: [32]u8 = d[0..32].*;
    const id = abi.TxContext.deriveId(&digest, n);
    if (try c.rt.newId(c.arena, c.cfg, id)) |e| return .{ .err = e };
    return c.ok1(.{ .address = id });
}

pub fn fresh_id(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.charge(c.p("tx_context_fresh_id_cost_base"))) return c.oog();
    const id = c.tx.freshId();
    if (try c.rt.newId(c.arena, c.cfg, id)) |e| return .{ .err = e };
    return c.ok1(.{ .address = id });
}

pub fn native_sender(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.charge(c.p("tx_context_sender_cost_base"))) return c.oog();
    return c.ok1(.{ .address = c.tx.sender });
}

pub fn native_epoch(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.charge(c.p("tx_context_epoch_cost_base"))) return c.oog();
    return c.ok1(.{ .u64 = c.tx.epoch });
}

pub fn native_epoch_timestamp_ms(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.charge(c.p("tx_context_epoch_timestamp_ms_cost_base"))) return c.oog();
    return c.ok1(.{ .u64 = c.tx.epoch_timestamp_ms });
}

pub fn native_sponsor(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.charge(c.p("tx_context_sponsor_cost_base"))) return c.oog();
    if (c.tx.sponsor) |s| {
        const v = try c.arena.alloc(Value, 1);
        v[0] = .{ .address = s };
        return c.ok1(.{ .vector = v });
    }
    return c.ok1(.{ .vector = &.{} });
}

pub fn native_rgp(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    // DEFAULT_UNUSED_TX_CONTEXT_ENTRY_COST before the parameter existed
    if (!c.charge(c.popt("tx_context_rgp_cost_base") orelse 10)) return c.oog();
    return c.ok1(.{ .u64 = c.tx.rgp });
}

pub fn native_gas_price(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.charge(c.p("tx_context_gas_price_cost_base"))) return c.oog();
    return c.ok1(.{ .u64 = c.tx.gas_price });
}

pub fn native_gas_budget(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.charge(c.p("tx_context_gas_budget_cost_base"))) return c.oog();
    return c.ok1(.{ .u64 = c.tx.gas_budget });
}

pub fn native_ids_created(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.charge(c.p("tx_context_ids_created_cost_base"))) return c.oog();
    return c.ok1(.{ .u64 = c.tx.ids_created });
}

// ---- types ----------------------------------------------------------------------------------

pub fn is_one_time_witness(c: *Ctx, tys: []const TyArg, _: []Value) Error!Outcome {
    if (!c.charge(c.p("types_is_one_time_witness_cost_base"))) return c.oog();
    const t = tys[0];
    if (!c.charge(c.p("types_is_one_time_witness_type_cost_per_byte") *| abi.typeSize(t.tag))) return c.oog();
    if (!c.charge(c.p("types_is_one_time_witness_type_tag_cost_per_byte") *| abi.tagAbstractSize(t.tag))) return c.oog();
    const lay = t.layout orelse return c.ok1(.{ .bool = false });
    const sl = switch (lay.*) {
        .@"struct" => |s| s,
        else => return c.ok1(.{ .bool = false }),
    };
    const st = switch (t.tag.*) {
        .@"struct" => |s| s,
        else => return c.ok1(.{ .bool = false }),
    };
    const one_bool = sl.@"0".len == 1 and sl.@"0"[0] == .bool;
    var name_ok = st.name.@"0".len == st.module.@"0".len;
    if (name_ok) for (st.name.@"0", st.module.@"0") |n, m| {
        if (n != std.ascii.toUpper(m)) name_ok = false;
    };
    const params_ok = !c.hardened_otw_check or st.type_args.len == 0;
    return c.ok1(.{ .bool = one_bool and name_ok and params_ok });
}

// ---- protocol_config ------------------------------------------------------------------------

pub fn is_feature_enabled(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const name = try abi.bytesOf(c.arena, args[0]);
    const on = if (std.unicode.utf8ValidateSlice(name)) protocol.derived.lookupFeature(c.cfg, name) orelse false else false;
    return c.ok1(.{ .bool = on });
}

// ---- dynamic_field --------------------------------------------------------------------------

pub fn hash_type_and_key(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("dynamic_field_hash_type_and_key_cost_base"))) return c.oog();
    const t = tys[0];
    const parent = args[0].address;
    const k = &args[1];
    const walk = t.traversal() orelse return Ctx.invariant();
    const vsize: u64 = abi.objectRuntimeSize(c.cfg, k, walk); // exec-history-vm: legacy before 104
    if (!c.charge(c.p("dynamic_field_hash_type_and_key_type_cost_per_byte") *| abi.typeSize(t.tag) +|
        c.p("dynamic_field_hash_type_and_key_value_cost_per_byte") *| vsize)) return c.oog();
    if (!c.charge(c.p("dynamic_field_hash_type_and_key_type_tag_cost_per_byte") *| abi.tagAbstractSize(t.tag))) return c.oog();
    // type_to_type_layout returned None (VM layout limits): E_BCS_SERIALIZATION_FAILURE
    if (t.layout == null) return c.abort(3);
    const kb = try @import("types").layout.encodeAlloc(c.arena, k);
    const tag = try abi.tagBcs(c.arena, t.tag);
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, kb.len, .little);
    const id = hash.blake2b256(&.{ &[_]u8{0xf0}, &parent, &len_le, kb, tag });
    return c.ok1(.{ .address = id });
}
