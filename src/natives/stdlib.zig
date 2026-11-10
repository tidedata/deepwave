//! move-stdlib natives (move-vm-runtime 1.83.1 `natives/move_stdlib`) with the gas parameters
//! sui-move-natives `make_stdlib_gas_params_for_protocol_config` maps from the protocol config.
const std = @import("std");
const hash = @import("hash");
const types = @import("types");
const abi = @import("abi.zig");

const Ctx = abi.Ctx;
const Value = abi.Value;
const TyArg = abi.TyArg;
const Outcome = abi.Outcome;
const Error = abi.Error;

// ---- hash -----------------------------------------------------------------------------------

fn hashCost(c: *Ctx, comptime base: []const u8, comptime per_byte: []const u8, comptime min_len: []const u8, n: usize) u64 {
    return c.p(base) +| c.p(per_byte) *| @max(@as(u64, n), c.p(min_len));
}

pub fn sha2_256(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const data = try abi.bytesOf(c.arena, args[0]);
    if (!c.charge(hashCost(c, "hash_sha2_256_base_cost", "hash_sha2_256_per_byte_cost", "hash_sha2_256_legacy_min_input_len_cost", data.len))) return c.oog();
    var out: [32]u8 = undefined;
    hash.Sha256.hash(data, &out);
    return c.ok1Bytes(&out);
}

pub fn sha3_256(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const data = try abi.bytesOf(c.arena, args[0]);
    if (!c.charge(hashCost(c, "hash_sha3_256_base_cost", "hash_sha3_256_per_byte_cost", "hash_sha3_256_legacy_min_input_len_cost", data.len))) return c.oog();
    var out: [32]u8 = undefined;
    hash.Sha3_256.hash(data, &out);
    return c.ok1Bytes(&out);
}

// ---- bcs ------------------------------------------------------------------------------------

pub fn to_bytes(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    const layout = tys[0].layout orelse {
        _ = c.charge(c.p("bcs_failure_cost"));
        return c.abort(abi.NFE_BCS_SERIALIZATION_FAILURE);
    };
    _ = layout;
    const bytes = try types.layout.encodeAlloc(c.arena, &args[0]);
    if (!c.charge(c.p("bcs_per_byte_serialized_cost") *| @max(@as(u64, bytes.len), c.p("bcs_legacy_min_output_size_cost")))) return c.oog();
    return c.ok1Bytes(bytes);
}

// ---- string ---------------------------------------------------------------------------------

pub fn internal_check_utf8(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const s = try abi.bytesOf(c.arena, args[0]);
    if (!c.charge(c.p("string_check_utf8_base_cost") +| c.p("string_check_utf8_per_byte_cost") *| s.len)) return c.oog();
    return c.ok1(.{ .bool = std.unicode.utf8ValidateSlice(s) });
}

/// Rust `str::is_char_boundary` over bytes the caller vouched are UTF-8.
fn isCharBoundary(s: []const u8, i: u64) bool {
    if (i == 0) return true;
    if (i >= s.len) return i == s.len;
    // not a continuation byte (as i8 >= -0x40)
    return @as(i8, @bitCast(s[@intCast(i)])) >= -0x40;
}

pub fn internal_is_char_boundary(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("string_is_char_boundary_base_cost"))) return c.oog();
    const i = args[1].u64;
    const s = try abi.bytesOf(c.arena, args[0]);
    return c.ok1(.{ .bool = isCharBoundary(s, i) });
}

pub fn internal_sub_string(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const j = args[2].u64;
    const i = args[1].u64;
    if (!c.charge(c.p("string_sub_string_base_cost"))) return c.oog();
    if (j < i) return c.abort(1);
    // exec-history: the v0 to v3 stdlib charges the base a second time with the bytes
    const again = if ((c.cfg.execution_version orelse 0) < 4) c.p("string_sub_string_base_cost") else 0;
    if (!c.charge(again +| c.p("string_sub_string_per_byte_cost") *| (j - i))) return c.oog();
    const s = try abi.bytesOf(c.arena, args[0]);
    // `safe_get(i..j)` on the bytes: out of range is an invariant violation
    if (j > s.len) return Ctx.invariant();
    return c.ok1Bytes(s[@intCast(i)..@intCast(j)]);
}

pub fn internal_index_of(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("string_index_of_base_cost"))) return c.oog();
    const r = try abi.bytesOf(c.arena, args[1]);
    if (!c.charge(c.p("string_index_of_per_byte_pattern_cost") *| r.len)) return c.oog();
    const s = try abi.bytesOf(c.arena, args[0]);
    // exec-history: the v0 to v3 stdlib charges the searched bytes after the search, up to the match
    const legacy = (c.cfg.execution_version orelse 0) < 4;
    if (!legacy and !c.charge(c.p("string_index_of_per_byte_searched_cost") *| s.len)) return c.oog();
    const pos = std.mem.indexOf(u8, s, r) orelse s.len;
    if (legacy and !c.charge(c.p("string_index_of_per_byte_searched_cost") *| pos)) return c.oog();
    return c.ok1(.{ .u64 = pos });
}

// ---- type_name ------------------------------------------------------------------------------

fn typeNameGet(c: *Ctx, tys: []const TyArg, original: bool) Error!Outcome {
    if (!c.charge(c.p("type_name_get_base_cost"))) return c.oog();
    const tag = if (original) tys[0].runtimeTag() else tys[0].tag;
    const name = try abi.canonicalString(c.arena, tag, false);
    if (!c.charge(c.p("type_name_get_per_byte_cost") *| name.len)) return c.oog();
    const str_fields = try c.arena.alloc(Value, 1);
    str_fields[0] = try c.bytesValue(name);
    const tn_fields = try c.arena.alloc(Value, 1);
    tn_fields[0] = .{ .@"struct" = str_fields };
    return c.ok1(.{ .@"struct" = tn_fields });
}

pub fn with_defining_ids(c: *Ctx, tys: []const TyArg, _: []Value) Error!Outcome {
    return typeNameGet(c, tys, false);
}

pub fn with_original_ids(c: *Ctx, tys: []const TyArg, _: []Value) Error!Outcome {
    return typeNameGet(c, tys, true);
}

fn typeNameId(c: *Ctx, tys: []const TyArg, original: bool) Error!Outcome {
    const base = c.popt("type_name_id_base_cost") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    const tag = if (original) tys[0].runtimeTag() else tys[0].tag;
    return switch (tag.*) {
        .@"struct" => |s| c.ok1(.{ .address = s.address.@"0" }),
        else => c.abort(0), // E_NON_MODULE_TYPE
    };
}

pub fn defining_id(c: *Ctx, tys: []const TyArg, _: []Value) Error!Outcome {
    return typeNameId(c, tys, false);
}

pub fn original_id(c: *Ctx, tys: []const TyArg, _: []Value) Error!Outcome {
    return typeNameId(c, tys, true);
}

// ---- vector ---------------------------------------------------------------------------------

/// move-core-types vm_status sub statuses for vector operations.
const INDEX_OUT_OF_BOUNDS: u64 = 1;
const POP_EMPTY_VEC: u64 = 2;
const VEC_UNPACK_PARITY_MISMATCH: u64 = 3;
const VEC_SIZE_LIMIT_REACHED: u64 = 4;

pub fn empty(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.charge(c.p("vector_empty_base_cost"))) return c.oog();
    return c.ok1(.{ .vector = &.{} });
}

pub fn length(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("vector_length_base_cost"))) return c.oog();
    return c.ok1(.{ .u64 = args[0].vecLen() });
}

pub fn push_back(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("vector_push_back_base_cost"))) return c.oog();
    const legacy = c.p("vector_push_back_legacy_per_abstract_memory_unit_cost");
    if (legacy != 0) {
        const lay = tys[0].traversal() orelse return Ctx.invariant();
        // exec-history: the v0 to v3 stdlib measures with `fine_grained_value_size: false`
        const size = abi.abstractSize(&args[1], lay, .{ .include_vector_size = false, .fine_grained = (c.cfg.execution_version orelse 0) >= 4 });
        if (!c.charge(legacy *| @max(size, 1))) return c.oog();
    }
    const v = try args[0].items(c.arena);
    // push_back maps no error to an abort (no native_error_to_abort): the VM error surfaces as is
    if (v.len >= c.vector_len_max) return Ctx.err(.VECTOR_OPERATION_ERROR, VEC_SIZE_LIMIT_REACHED);
    const nv = try c.arena.alloc(Value, v.len + 1);
    @memcpy(nv[0..v.len], v);
    nv[v.len] = args[1];
    args[0] = .{ .vector = nv };
    return c.ok0();
}

pub fn pop_back(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("vector_pop_back_base_cost"))) return c.oog();
    const v = try args[0].items(c.arena);
    if (v.len == 0) return c.abort(POP_EMPTY_VEC);
    args[0] = .{ .vector = v[0 .. v.len - 1] };
    return c.ok1(v[v.len - 1]);
}

pub fn destroy_empty(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("vector_destroy_empty_base_cost"))) return c.oog();
    if (args[0].vecLen() != 0) return c.abort(VEC_UNPACK_PARITY_MISMATCH);
    return c.ok0();
}

pub fn swap(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("vector_swap_base_cost"))) return c.oog();
    const j = args[2].u64;
    const i = args[1].u64;
    const v = try args[0].items(c.arena);
    if (i >= v.len or j >= v.len) return c.abort(INDEX_OUT_OF_BOUNDS);
    const nv = try c.arena.dupe(Value, v);
    std.mem.swap(Value, &nv[@intCast(i)], &nv[@intCast(j)]);
    args[0] = .{ .vector = nv };
    return c.ok0();
}

pub fn reverse(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("vector_reverse_base_cost"))) return c.oog();
    const v = try args[0].items(c.arena);
    if (!c.charge(c.p("vector_reverse_per_elem_cost") *| v.len)) return c.oog();
    const nv = try c.arena.dupe(Value, v);
    std.mem.reverse(Value, nv);
    args[0] = .{ .vector = nv };
    return c.ok0();
}

fn validRange(len: u64, i: u64, j: u64) bool {
    return i <= j and j <= len;
}

pub fn keep_range(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("vector_keep_range_base_cost"))) return c.oog();
    const end = args[2].u64;
    const start = args[1].u64;
    const v = try args[0].items(c.arena);
    const len: u64 = v.len;
    var dropped: u64 = 0;
    var moved: u64 = 0;
    if (validRange(len, start, end)) {
        const retained = end - start;
        dropped = len - retained;
        moved = if (start == 0) 0 else retained;
    }
    if (!c.charge(c.p("vector_keep_range_per_dropped_elem_cost") *| dropped)) return c.oog();
    if (!c.charge(c.p("vector_keep_range_per_moved_elem_cost") *| moved)) return c.oog();
    if (!validRange(len, start, end)) return c.abort(INDEX_OUT_OF_BOUNDS);
    args[0] = .{ .vector = v[@intCast(start)..@intCast(end)] };
    return c.ok0();
}

pub fn copy_range(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("vector_copy_range_base_cost"))) return c.oog();
    const j = args[2].u64;
    const i = args[1].u64;
    const v = try args[0].items(c.arena);
    if (!validRange(v.len, i, j)) return c.abort(INDEX_OUT_OF_BOUNDS);
    return c.ok1(.{ .vector = v[@intCast(i)..@intCast(j)] });
}

pub fn replace_range(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("vector_replace_range_base_cost"))) return c.oog();
    const other = try args[3].items(c.arena);
    const j = args[2].u64;
    const i = args[1].u64;
    const v = try args[0].items(c.arena);
    const len: u64 = v.len;
    const n_in: u64 = other.len;
    var count: u64 = 0;
    if (validRange(len, i, j)) {
        const tail_moved: u64 = if (n_in == j - i) 0 else len - j;
        count = n_in +| tail_moved;
    }
    if (!c.charge(c.p("vector_replace_range_per_elem_cost") *| count)) return c.oog();
    if (!validRange(len, i, j)) return c.abort(INDEX_OUT_OF_BOUNDS);
    const new_len = len - (j - i) + n_in;
    if (new_len > c.vector_len_max) return c.abort(VEC_SIZE_LIMIT_REACHED);
    const ii: usize = @intCast(i);
    const jj: usize = @intCast(j);
    const nv = try c.arena.alloc(Value, @intCast(new_len));
    @memcpy(nv[0..ii], v[0..ii]);
    @memcpy(nv[ii .. ii + other.len], other);
    @memcpy(nv[ii + other.len ..], v[jj..]);
    args[0] = .{ .vector = nv };
    return c.ok1(.{ .vector = v[ii..jj] });
}

// ---- debug ----------------------------------------------------------------------------------

/// Silent (production) print: the base cost is returned without being charged.
pub fn print(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    return Ctx.okWith(c.p("debug_print_base_cost"), &.{});
}

pub fn print_stack_trace(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    return Ctx.okWith(c.p("debug_print_stack_trace_base_cost"), &.{});
}

test "char boundary" {
    const s = "héllo";
    try std.testing.expect(isCharBoundary(s, 0));
    try std.testing.expect(isCharBoundary(s, 1));
    try std.testing.expect(!isCharBoundary(s, 2));
    try std.testing.expect(isCharBoundary(s, s.len));
    try std.testing.expect(!isCharBoundary(s, s.len + 1));
}
