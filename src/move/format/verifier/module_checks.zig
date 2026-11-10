//! Module-level passes of `verify_module_with_config_metered_up_to_code_units` after the bounds
//! checker: LimitsVerifier, DuplicationChecker, SignatureChecker, InstructionConsistency,
//! constants, friends, ability_field_requirements, RecursiveDataDefChecker,
//! InstantiationLoopChecker (move-bytecode-verifier 1.83.1).
const std = @import("std");
const ff = @import("../file_format.zig");
const c = @import("common.zig");

const Ctx = c.Ctx;
const E = c.E;
const Token = c.Token;
const AbilitySet = c.AbilitySet;
const PartialVmError = c.PartialVmError;
const CompiledModule = ff.CompiledModule;
const Allocator = std.mem.Allocator;

// =============================================================================================
// LimitsVerifier

const STRUCT_SIZE_WEIGHT: usize = 4;
const PARAM_SIZE_WEIGHT: usize = 4;

fn weightedTypeSize(t: Token) usize {
    var size: usize = 0;
    for (t) |n| size +|= switch (n.tag) {
        .Datatype, .DatatypeInstantiation => STRUCT_SIZE_WEIGHT,
        .TypeParameter => PARAM_SIZE_WEIGHT,
        else => 1,
    };
    return size;
}

pub fn limits(ctx: *Ctx, arena: Allocator, cfg: *const c.Config, m: *const CompiledModule) E!void {
    // verify_constants
    for (m.constant_pool, 0..) |k, idx| {
        if (k.type_[0].tag != .Vector) continue;
        const n = constantVectorLen(k) orelse return ctx.fail(ff.verificationError(.MALFORMED_CONSTANT_DATA, .ConstantPool, @intCast(idx)));
        // (a vector layout always yields MoveValue::Vector, so INVALID_CONSTANT_TYPE is unreachable here)
        if (cfg.max_constant_vector_len) |lim| if (n > lim) return ctx.status(.TOO_MANY_VECTOR_ELEMENTS);
    }
    // verify_function_handles
    for (m.function_handles, 0..) |fh, idx| {
        if (cfg.max_generic_instantiation_length) |lim| if (fh.type_parameters.len > lim)
            return ctx.fail(PartialVmError.new(.TOO_MANY_TYPE_PARAMETERS).atIndex(.FunctionHandle, @intCast(idx)));
        if (cfg.max_function_parameters) |lim| if (m.signatures[fh.parameters].len > lim)
            return ctx.fail(PartialVmError.new(.TOO_MANY_PARAMETERS).atIndex(.FunctionHandle, @intCast(idx)));
    }
    // verify_datatype_handles
    if (cfg.max_generic_instantiation_length) |lim| for (m.datatype_handles, 0..) |dh, idx| {
        if (dh.type_parameters.len > lim)
            return ctx.fail(PartialVmError.new(.TOO_MANY_TYPE_PARAMETERS).atIndex(.DatatypeHandle, @intCast(idx)));
    };
    // verify_type_nodes
    if (cfg.max_type_nodes) |max| {
        for (m.signatures) |sig| for (sig) |t| if (weightedTypeSize(t) > max) return ctx.status(.TOO_MANY_TYPE_NODES);
        for (m.constant_pool) |k| if (weightedTypeSize(k.type_) > max) return ctx.status(.TOO_MANY_TYPE_NODES);
        for (m.struct_defs) |sd| if (!sd.native) for (sd.fields) |f| if (weightedTypeSize(f.signature) > max) return ctx.status(.TOO_MANY_TYPE_NODES);
        for (m.enum_defs) |ed| for (ed.variants) |v| for (v.fields) |f| if (weightedTypeSize(f.signature) > max) return ctx.status(.TOO_MANY_TYPE_NODES);
    }
    // verify_identifiers
    for (m.identifiers, 0..) |id, idx| {
        if (cfg.max_identifier_len) |max| if (id.len > max)
            return ctx.fail(ff.verificationError(.IDENTIFIER_TOO_LONG, .Identifier, @intCast(idx)));
        if (cfg.disallow_self_identifier and std.mem.eql(u8, id, "<SELF>"))
            return ctx.fail(ff.verificationError(.INVALID_IDENTIFIER, .Identifier, @intCast(idx)));
    }
    // verify_definitions
    if (cfg.max_function_definitions) |max| if (m.function_defs.len > max) return ctx.status(.MAX_FUNCTION_DEFINITIONS_REACHED);
    if (cfg.max_data_definitions) |max| if (m.struct_defs.len + m.enum_defs.len > max) return ctx.status(.MAX_STRUCT_DEFINITIONS_REACHED);
    if (cfg.max_fields_in_struct) |max| {
        for (m.struct_defs) |sd| if (!sd.native and sd.fields.len > max) return ctx.status(.MAX_FIELD_DEFINITIONS_REACHED);
        for (m.enum_defs) |ed| {
            if (cfg.max_variants_in_enum) |mv| if (ed.variants.len > mv) return ctx.status(.MAX_VARIANTS_REACHED);
            var num_fields: usize = 0;
            for (ed.variants) |v| {
                num_fields += v.fields.len;
                if (num_fields > max) return ctx.status(.MAX_FIELD_DEFINITIONS_REACHED);
            }
        }
    }
    // verify_generic_instantiations
    try genericInstantiations(ctx, arena, cfg, m);
}

fn genericInstantiations(ctx: *Ctx, arena: Allocator, cfg: *const c.Config, m: *const CompiledModule) E!void {
    const max_fun = cfg.max_generic_instantiation_type_nodes_per_function;
    const max_mod = cfg.max_generic_instantiation_type_nodes_per_module;
    if (max_fun == null and max_mod == null) return;
    const size_table = try arena.alloc(?usize, m.signatures.len);
    @memset(size_table, null);
    var module_total: usize = 0;
    const function_totals = try arena.alloc(usize, m.function_handles.len);
    @memset(function_totals, 0);
    const S = struct {
        fn sigSize(mm: *const CompiledModule, tab: []?usize, idx: u16) usize {
            if (tab[idx]) |s| return s;
            var acc: usize = 0;
            for (mm.signatures[idx]) |t| acc +|= weightedTypeSize(t);
            tab[idx] = acc;
            return acc;
        }
        fn charge(cx: *Ctx, mf: ?usize, mm: ?usize, fn_total: *usize, mod_total: *usize, w: usize) E!void {
            fn_total.* +|= w;
            mod_total.* +|= w;
            if (mf) |max| if (fn_total.* > max) return cx.status(.TOO_MANY_TYPE_NODES);
            if (mm) |max| if (mod_total.* > max) return cx.status(.TOO_MANY_TYPE_NODES);
        }
    };
    if (cfg.include_function_signatures_in_instantiation_limits) {
        for (m.function_handles, 0..) |fh, idx| {
            var fn_total: usize = 0;
            const w = S.sigSize(m, size_table, fh.return_) +| S.sigSize(m, size_table, fh.parameters);
            try S.charge(ctx, max_fun, max_mod, &fn_total, &module_total, w);
            function_totals[idx] = fn_total;
        }
    }
    for (m.function_defs) |fd| {
        const code = fd.code orelse continue;
        var fn_total: usize = if (fd.function < function_totals.len) function_totals[fd.function] else 0;
        if (cfg.include_function_signatures_in_instantiation_limits)
            try S.charge(ctx, max_fun, max_mod, &fn_total, &module_total, S.sigSize(m, size_table, code.locals));
        for (code.code) |ins| {
            const sig: u16 = switch (ins.op) {
                .CallGeneric => m.function_instantiations[ins.idx].type_parameters,
                .PackGeneric, .UnpackGeneric, .ExistsGenericDeprecated, .MoveFromGenericDeprecated, .MoveToGenericDeprecated, .ImmBorrowGlobalGenericDeprecated, .MutBorrowGlobalGenericDeprecated => m.struct_def_instantiations[ins.idx].type_parameters,
                .ImmBorrowFieldGeneric, .MutBorrowFieldGeneric => m.field_instantiations[ins.idx].type_parameters,
                .VecPack, .VecLen, .VecImmBorrow, .VecMutBorrow, .VecPushBack, .VecPopBack, .VecUnpack, .VecSwap => ins.idx,
                .PackVariantGeneric, .UnpackVariantGeneric, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => m.enum_def_instantiations[m.variant_instantiation_handles[ins.idx].enum_def].type_parameters,
                else => continue,
            };
            try S.charge(ctx, max_fun, max_mod, &fn_total, &module_total, S.sigSize(m, size_table, sig));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Constant data (`Constant::deserialize_constant`: BCS of the constant's layout, no trailing bytes)

/// Element count of a vector constant, or null when the data does not deserialize.
fn constantVectorLen(k: ff.Constant) ?u64 {
    for (k.type_) |n| switch (n.tag) {
        .Reference, .MutableReference, .Datatype, .DatatypeInstantiation, .TypeParameter => return null,
        else => {},
    };
    var r: BcsReader = .{ .data = k.data };
    const n = r.peekLen() orelse return null;
    if (!r.value(k.type_)) return null;
    if (r.pos != r.data.len) return null;
    return n;
}

pub fn constantValid(k: ff.Constant) bool {
    var r: BcsReader = .{ .data = k.data };
    if (!validForConstant(k.type_)) return false;
    if (!r.value(k.type_)) return false;
    return r.pos == r.data.len;
}

pub fn validForConstant(t: Token) bool {
    for (t) |n| switch (n.tag) {
        .Bool, .U8, .U16, .U32, .U64, .U128, .U256, .Address, .Vector => {},
        else => return false,
    };
    return true;
}

const BcsReader = struct {
    data: []const u8,
    pos: usize = 0,

    fn take(r: *BcsReader, n: usize) bool {
        if (r.data.len - r.pos < n) return false;
        r.pos += n;
        return true;
    }
    /// bcs `parse_length`: canonical ULEB128 u32, at most 2^31 - 1.
    fn len(r: *BcsReader) ?u64 {
        var v: u64 = 0;
        var shift: u6 = 0;
        while (shift < 32) : (shift += 7) {
            if (r.pos >= r.data.len) return null;
            const byte = r.data[r.pos];
            r.pos += 1;
            const digit = byte & 0x7f;
            v |= @as(u64, digit) << shift;
            if (digit == byte) {
                if (shift > 0 and digit == 0) return null;
                if (v > std.math.maxInt(u32)) return null;
                if (v > 0x7fff_ffff) return null;
                return v;
            }
        }
        return null;
    }
    fn peekLen(r: *BcsReader) ?u64 {
        const save = r.pos;
        defer r.pos = save;
        return r.len();
    }
    /// Deserializes one value of the layout of `t` (a constant-valid type); false on error.
    fn value(r: *BcsReader, t: Token) bool {
        return switch (t[0].tag) {
            .Bool => blk: {
                if (r.pos >= r.data.len) break :blk false;
                const b = r.data[r.pos];
                r.pos += 1;
                break :blk b <= 1;
            },
            .U8 => r.take(1),
            .U16 => r.take(2),
            .U32 => r.take(4),
            .U64 => r.take(8),
            .U128 => r.take(16),
            .U256 => r.take(32),
            .Address, .Signer => r.take(32),
            .Vector => blk: {
                const n = r.len() orelse break :blk false;
                const inner = t[1..];
                // fixed-size elements: one bounds check
                const w: usize = switch (inner[0].tag) {
                    .U8 => 1,
                    .U16 => 2,
                    .U32 => 4,
                    .U64 => 8,
                    .U128 => 16,
                    .U256, .Address => 32,
                    else => 0,
                };
                if (w != 0) {
                    if ((r.data.len - r.pos) / w < n) break :blk false;
                    r.pos += @as(usize, @intCast(n)) * w;
                    break :blk true;
                }
                var i: u64 = 0;
                while (i < n) : (i += 1) if (!r.value(inner)) break :blk false;
                break :blk true;
            },
            else => false,
        };
    }
};

pub fn constants(ctx: *Ctx, m: *const CompiledModule) E!void {
    for (m.constant_pool, 0..) |k, idx| {
        if (!validForConstant(k.type_)) return ctx.fail(ff.verificationError(.INVALID_CONSTANT_TYPE, .ConstantPool, @intCast(idx)));
        if (!constantValid(k)) return ctx.fail(ff.verificationError(.MALFORMED_CONSTANT_DATA, .ConstantPool, @intCast(idx)));
    }
}

// =============================================================================================
// DuplicationChecker

fn IdxSet(comptime C: type) type {
    return struct {
        const Self = @This();
        const HCtx = struct {
            inner: C,
            pub fn hash(s: HCtx, k: u32) u64 {
                return s.inner.hash(k);
            }
            pub fn eql(s: HCtx, a: u32, b: u32) bool {
                return s.inner.eql(a, b);
            }
        };
        fn firstDup(arena: Allocator, n: usize, inner: C) E!?u16 {
            var set: std.HashMapUnmanaged(u32, void, HCtx, 80) = .empty;
            const hc: HCtx = .{ .inner = inner };
            try set.ensureTotalCapacityContext(arena, @intCast(n), hc);
            for (0..n) |i| {
                const gop = set.getOrPutAssumeCapacityContext(@intCast(i), hc);
                if (gop.found_existing) return @intCast(i);
            }
            return null;
        }
    };
}

fn firstDup(arena: Allocator, n: usize, inner: anytype) E!?u16 {
    return IdxSet(@TypeOf(inner)).firstDup(arena, n, inner);
}

fn hashBytes(b: []const u8) u64 {
    return std.hash.Wyhash.hash(0, b);
}
fn hashTok(h: *std.hash.Wyhash, t: Token) void {
    h.update(std.mem.asBytes(&t.len));
    h.update(std.mem.sliceAsBytes(t));
}

/// Hashing over a slice of values with plain equality (u16 pairs etc.), via a key function.
fn KeyCtx(comptime T: type, comptime K: type, comptime key: fn (T) K) type {
    return struct {
        items: []const T,
        pub fn hash(s: @This(), i: u32) u64 {
            const k = key(s.items[i]);
            return std.hash.Wyhash.hash(0, std.mem.asBytes(&k));
        }
        pub fn eql(s: @This(), a: u32, b: u32) bool {
            return std.meta.eql(key(s.items[a]), key(s.items[b]));
        }
    };
}

fn keyCtx(comptime T: type, comptime K: type, comptime key: fn (T) K, items: []const T) KeyCtx(T, K, key) {
    return .{ .items = items };
}

const K2 = struct { a: u16, b: u16 };
fn kMh(x: ff.ModuleHandle) K2 {
    return .{ .a = x.address, .b = x.name };
}
fn kDh(x: ff.DatatypeHandle) K2 {
    return .{ .a = x.module, .b = x.name };
}
fn kFh(x: ff.FunctionHandle) K2 {
    return .{ .a = x.module, .b = x.name };
}
fn kVh(x: ff.VariantHandle) K2 {
    return .{ .a = x.enum_def, .b = x.variant };
}
fn kFi(x: ff.FunctionInstantiation) K2 {
    return .{ .a = x.handle, .b = x.type_parameters };
}
fn kFldH(x: ff.FieldHandle) K2 {
    return .{ .a = x.owner, .b = x.field };
}
fn kFldI(x: ff.FieldInstantiation) K2 {
    return .{ .a = x.handle, .b = x.type_parameters };
}
fn kSi(x: ff.StructDefInstantiation) K2 {
    return .{ .a = x.def, .b = x.type_parameters };
}
fn kEi(x: ff.EnumDefInstantiation) K2 {
    return .{ .a = x.def, .b = x.type_parameters };
}
fn kU16(x: u16) u16 {
    return x;
}
fn kSd(x: ff.StructDefinition) u16 {
    return x.struct_handle;
}
fn kFd(x: ff.FunctionDefinition) u16 {
    return x.function;
}
fn kField(x: ff.FieldDefinition) u16 {
    return x.name;
}
fn kVariant(x: ff.VariantDefinition) u16 {
    return x.variant_name;
}

const IdentCtx = struct {
    items: []const []const u8,
    pub fn hash(s: @This(), i: u32) u64 {
        return hashBytes(s.items[i]);
    }
    pub fn eql(s: @This(), a: u32, b: u32) bool {
        return std.mem.eql(u8, s.items[a], s.items[b]);
    }
};
const AddrCtx = struct {
    items: []const [32]u8,
    pub fn hash(s: @This(), i: u32) u64 {
        return hashBytes(&s.items[i]);
    }
    pub fn eql(s: @This(), a: u32, b: u32) bool {
        return std.mem.eql(u8, &s.items[a], &s.items[b]);
    }
};
const ConstCtx = struct {
    items: []const ff.Constant,
    pub fn hash(s: @This(), i: u32) u64 {
        var h = std.hash.Wyhash.init(0);
        hashTok(&h, s.items[i].type_);
        h.update(s.items[i].data);
        return h.final();
    }
    pub fn eql(s: @This(), a: u32, b: u32) bool {
        return ff.tokenEql(s.items[a].type_, s.items[b].type_) and std.mem.eql(u8, s.items[a].data, s.items[b].data);
    }
};
const SigCtx = struct {
    items: []const []const Token,
    pub fn hash(s: @This(), i: u32) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&s.items[i].len));
        for (s.items[i]) |t| hashTok(&h, t);
        return h.final();
    }
    pub fn eql(s: @This(), a: u32, b: u32) bool {
        const x = s.items[a];
        const y = s.items[b];
        if (x.len != y.len) return false;
        for (x, y) |p, q| if (!ff.tokenEql(p, q)) return false;
        return true;
    }
};
/// Struct defs and enum defs chained, keyed by handle.
const DefHandleCtx = struct {
    m: *const CompiledModule,
    fn at(s: @This(), i: u32) u16 {
        return if (i < s.m.struct_defs.len) s.m.struct_defs[i].struct_handle else s.m.enum_defs[i - s.m.struct_defs.len].enum_handle;
    }
    pub fn hash(s: @This(), i: u32) u64 {
        const k = s.at(i);
        return std.hash.Wyhash.hash(0, std.mem.asBytes(&k));
    }
    pub fn eql(s: @This(), a: u32, b: u32) bool {
        return s.at(a) == s.at(b);
    }
};

pub fn duplication(ctx: *Ctx, arena: Allocator, m: *const CompiledModule) E!void {
    const vErr = ff.verificationError;
    if (try firstDup(arena, m.identifiers.len, IdentCtx{ .items = m.identifiers })) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .Identifier, i));
    if (try firstDup(arena, m.address_identifiers.len, AddrCtx{ .items = m.address_identifiers })) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .AddressIdentifier, i));
    if (try firstDup(arena, m.constant_pool.len, ConstCtx{ .items = m.constant_pool })) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .ConstantPool, i));
    if (try firstDup(arena, m.signatures.len, SigCtx{ .items = m.signatures })) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .Signature, i));
    if (try firstDup(arena, m.module_handles.len, keyCtx(ff.ModuleHandle, K2, kMh, m.module_handles))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .ModuleHandle, i));
    if (try firstDup(arena, m.friend_decls.len, keyCtx(ff.ModuleHandle, K2, kMh, m.friend_decls))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .ModuleHandle, i));
    if (try firstDup(arena, m.datatype_handles.len, keyCtx(ff.DatatypeHandle, K2, kDh, m.datatype_handles))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .DatatypeHandle, i));
    if (try firstDup(arena, m.function_handles.len, keyCtx(ff.FunctionHandle, K2, kFh, m.function_handles))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .FunctionHandle, i));
    if (try firstDup(arena, m.function_instantiations.len, keyCtx(ff.FunctionInstantiation, K2, kFi, m.function_instantiations))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .FunctionInstantiation, i));
    if (try firstDup(arena, m.variant_handles.len, keyCtx(ff.VariantHandle, K2, kVh, m.variant_handles))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .VariantHandle, i));
    // field handles / instantiations
    if (try firstDup(arena, m.field_handles.len, keyCtx(ff.FieldHandle, K2, kFldH, m.field_handles))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .FieldHandle, i));
    if (try firstDup(arena, m.field_instantiations.len, keyCtx(ff.FieldInstantiation, K2, kFldI, m.field_instantiations))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .FieldInstantiation, i));
    // function definitions
    if (try firstDup(arena, m.function_defs.len, keyCtx(ff.FunctionDefinition, u16, kFd, m.function_defs))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .FunctionDefinition, i));
    for (m.function_defs, 0..) |fd, idx| {
        if (try firstDup(arena, fd.acquires.len, keyCtx(u16, u16, kU16, fd.acquires)) != null)
            return ctx.fail(vErr(.DUPLICATE_ACQUIRES_ANNOTATION, .FunctionDefinition, @intCast(idx)));
    }
    for (m.function_defs, 0..) |fd, idx| {
        if (m.function_handles[fd.function].module != m.self_module_handle_idx)
            return ctx.fail(vErr(.INVALID_MODULE_HANDLE, .FunctionDefinition, @intCast(idx)));
    }
    {
        const implemented = try arena.alloc(bool, m.function_handles.len);
        @memset(implemented, false);
        for (m.function_defs) |fd| implemented[fd.function] = true;
        for (m.function_handles, 0..) |fh, idx| {
            if (fh.module == m.self_module_handle_idx and !implemented[idx])
                return ctx.fail(vErr(.UNIMPLEMENTED_HANDLE, .FunctionHandle, @intCast(idx)));
        }
    }
    // struct definitions
    if (try firstDup(arena, m.struct_defs.len, keyCtx(ff.StructDefinition, u16, kSd, m.struct_defs))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .StructDefinition, i));
    for (m.struct_defs, 0..) |sd, idx| {
        if (sd.native) continue;
        if (sd.fields.len == 0) return ctx.fail(vErr(.ZERO_SIZED_STRUCT, .StructDefinition, @intCast(idx)));
        if (try firstDup(arena, sd.fields.len, keyCtx(ff.FieldDefinition, u16, kField, sd.fields))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .FieldDefinition, i));
    }
    for (m.struct_defs, 0..) |sd, idx| {
        if (m.datatype_handles[sd.struct_handle].module != m.self_module_handle_idx)
            return ctx.fail(vErr(.INVALID_MODULE_HANDLE, .StructDefinition, @intCast(idx)));
    }
    if (try firstDup(arena, m.struct_def_instantiations.len, keyCtx(ff.StructDefInstantiation, K2, kSi, m.struct_def_instantiations))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .StructDefInstantiation, i));
    // enum definitions
    if (try firstDup(arena, m.struct_defs.len + m.enum_defs.len, DefHandleCtx{ .m = m })) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .EnumDefinition, i));
    for (m.enum_defs, 0..) |ed, eidx| {
        if (ed.variants.len == 0) return ctx.fail(vErr(.ZERO_SIZED_ENUM, .EnumDefinition, @intCast(eidx)));
        if (try firstDup(arena, ed.variants.len, keyCtx(ff.VariantDefinition, u16, kVariant, ed.variants))) |i|
            return ctx.fail(vErr(.DUPLICATE_ELEMENT, .EnumDefinition, @intCast(eidx)).atIndex(.VariantTag, i));
        for (ed.variants, 0..) |v, tag| {
            if (try firstDup(arena, v.fields.len, keyCtx(ff.FieldDefinition, u16, kField, v.fields))) |i|
                return ctx.fail(vErr(.DUPLICATE_ELEMENT, .FieldDefinition, i).atIndex(.VariantTag, @intCast(tag)).atIndex(.EnumDefinition, @intCast(eidx)));
        }
    }
    for (m.enum_defs, 0..) |ed, idx| {
        if (m.datatype_handles[ed.enum_handle].module != m.self_module_handle_idx)
            return ctx.fail(vErr(.INVALID_MODULE_HANDLE, .EnumDefinition, @intCast(idx)));
    }
    if (try firstDup(arena, m.enum_def_instantiations.len, keyCtx(ff.EnumDefInstantiation, K2, kEi, m.enum_def_instantiations))) |i| return ctx.fail(vErr(.DUPLICATE_ELEMENT, .EnumDefInstantiation, i));
    // datatype handles implemented
    {
        const implemented = try arena.alloc(bool, m.datatype_handles.len);
        @memset(implemented, false);
        for (m.struct_defs) |sd| implemented[sd.struct_handle] = true;
        for (m.enum_defs) |ed| implemented[ed.enum_handle] = true;
        for (m.datatype_handles, 0..) |dh, idx| {
            if (dh.module == m.self_module_handle_idx and !implemented[idx])
                return ctx.fail(vErr(.UNIMPLEMENTED_HANDLE, .DatatypeHandle, @intCast(idx)));
        }
    }
}

// =============================================================================================
// SignatureChecker

const Sig = struct {
    ctx: *Ctx,
    arena: Allocator,
    m: *const CompiledModule,
    cache: *c.AbilityCache,
    meter: *c.Meter,
    /// abilities_cache: (signature index, type parameter abilities) already checked.
    checked: std.StringHashMapUnmanaged(void) = .empty,

    fn checkSignatureToken(s: *Sig, t: Token) E!void {
        for (t) |n| if (n.tag == .Reference or n.tag == .MutableReference) return s.ctx.status(.INVALID_SIGNATURE_TOKEN);
    }

    fn checkSignature(s: *Sig, idx: u16) E!void {
        for (s.m.signatures[idx]) |t| {
            if (t[0].tag == .Reference or t[0].tag == .MutableReference) {
                try s.checkSignatureToken(t[1..]);
            } else try s.checkSignatureToken(t);
        }
    }

    fn checkInstantiation(s: *Sig, idx: u16, tparams: []const AbilitySet) E!void {
        var key_buf: [2 + 256]u8 = undefined;
        std.mem.writeInt(u16, key_buf[0..2], idx, .little);
        for (tparams, 0..) |a, i| key_buf[2 + i] = a.bits;
        const key = key_buf[0 .. 2 + tparams.len];
        if (s.checked.contains(key)) return;
        for (s.m.signatures[idx]) |t| try s.checkTypeInstantiation(t, tparams);
        try s.checked.put(s.arena, try s.arena.dupe(u8, key), {});
    }

    fn checkTypeInstantiation(s: *Sig, t: Token, tparams: []const AbilitySet) E!void {
        if (s.m.version >= ff.VERSION_6) {
            var i: usize = 0;
            while (i < t.len) : (i += 1) {
                if (t[i].tag == .DatatypeInstantiation) try s.checkInst(t[i..], tparams);
            }
        } else if (t[0].tag == .DatatypeInstantiation) try s.checkInst(t, tparams);
    }

    fn checkInst(s: *Sig, t: Token, tparams: []const AbilitySet) E!void {
        const sh = &s.m.datatype_handles[t[0].idx];
        var it = ff.ArgIter.init(t);
        var args: [256]Token = undefined;
        var k: usize = 0;
        while (it.next()) |a| : (k += 1) args[k] = a;
        var cons: [256]AbilitySet = undefined;
        for (sh.type_parameters, 0..) |p, i| cons[i] = p.constraints;
        try s.checkGenericInstance(args[0..k], cons[0..sh.type_parameters.len], tparams);
    }

    fn checkGenericInstance(s: *Sig, args: []const Token, constraints: []const AbilitySet, global: []const AbilitySet) E!void {
        if (args.len != constraints.len) return s.ctx.status(.NUMBER_OF_TYPE_ARGUMENTS_MISMATCH);
        for (constraints, args) |cons, ty| {
            const given = try s.cache.abilities(s.ctx, .Module, s.meter, global, ty);
            if (!cons.isSubset(given)) return s.ctx.status(.CONSTRAINT_NOT_SATISFIED);
        }
    }

    fn checkPhantom(s: *Sig, t: Token, is_phantom_pos: bool, tparams: []const ff.DatatypeTyParameter) E!void {
        switch (t[0].tag) {
            .Vector => try s.checkPhantom(t[1..], false, tparams),
            .DatatypeInstantiation => {
                const sh = &s.m.datatype_handles[t[0].idx];
                var it = ff.ArgIter.init(t);
                var i: usize = 0;
                while (it.next()) |a| : (i += 1) try s.checkPhantom(a, sh.type_parameters[i].is_phantom, tparams);
            },
            .TypeParameter => if (tparams[t[0].idx].is_phantom and !is_phantom_pos) return s.ctx.status(.INVALID_PHANTOM_TYPE_PARAM_POSITION),
            else => {},
        }
    }

    fn tokens(s: *Sig, idx: u16) []const Token {
        return s.m.signatures[idx];
    }

    fn handleConstraints(s: *Sig, buf: *[256]AbilitySet, dh: u16) []const AbilitySet {
        const sh = &s.m.datatype_handles[dh];
        for (sh.type_parameters, 0..) |p, i| buf[i] = p.constraints;
        return buf[0..sh.type_parameters.len];
    }

    fn verifyCode(s: *Sig, code: ff.CodeUnit, tparams: []const AbilitySet) E!void {
        try s.checkInstantiation(code.locals, tparams);
        const m = s.m;
        var cbuf: [256]AbilitySet = undefined;
        for (code.code) |ins| switch (ins.op) {
            .CallGeneric => {
                const fi = m.function_instantiations[ins.idx];
                const fh = &m.function_handles[fi.handle];
                const targs = s.tokens(fi.type_parameters);
                for (targs) |t| try s.checkSignatureToken(t);
                try s.checkGenericInstance(targs, fh.type_parameters, tparams);
            },
            .PackGeneric, .UnpackGeneric, .ExistsGenericDeprecated, .MoveFromGenericDeprecated, .MoveToGenericDeprecated, .ImmBorrowGlobalGenericDeprecated, .MutBorrowGlobalGenericDeprecated => {
                const si = m.struct_def_instantiations[ins.idx];
                const sd = m.struct_defs[si.def];
                const targs = s.tokens(si.type_parameters);
                for (targs) |t| try s.checkSignatureToken(t);
                try s.checkGenericInstance(targs, s.handleConstraints(&cbuf, sd.struct_handle), tparams);
            },
            .ImmBorrowFieldGeneric, .MutBorrowFieldGeneric => {
                const fi = m.field_instantiations[ins.idx];
                const fh = m.field_handles[fi.handle];
                const sd = m.struct_defs[fh.owner];
                const targs = s.tokens(fi.type_parameters);
                for (targs) |t| try s.checkSignatureToken(t);
                try s.checkGenericInstance(targs, s.handleConstraints(&cbuf, sd.struct_handle), tparams);
            },
            .VecPack, .VecLen, .VecImmBorrow, .VecMutBorrow, .VecPushBack, .VecPopBack, .VecUnpack, .VecSwap => {
                const targs = s.tokens(ins.idx);
                if (targs.len != 1) return s.ctx.status(.NUMBER_OF_TYPE_ARGUMENTS_MISMATCH);
                for (targs) |t| try s.checkSignatureToken(t);
            },
            .PackVariantGeneric, .UnpackVariantGeneric, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => {
                const vh = m.variant_instantiation_handles[ins.idx];
                const ei = m.enum_def_instantiations[vh.enum_def];
                const ed = m.enum_defs[ei.def];
                const targs = s.tokens(ei.type_parameters);
                for (targs) |t| try s.checkSignatureToken(t);
                try s.checkGenericInstance(targs, s.handleConstraints(&cbuf, ed.enum_handle), tparams);
            },
            else => {},
        };
    }
};

pub fn signatures(ctx: *Ctx, arena: Allocator, m: *const CompiledModule, cache: *c.AbilityCache, meter: *c.Meter) E!void {
    var s: Sig = .{ .ctx = ctx, .arena = arena, .m = m, .cache = cache, .meter = meter };
    for (0..m.signatures.len) |i| try s.checkSignature(@intCast(i));
    for (m.function_handles, 0..) |fh, idx| {
        const i: u16 = @intCast(idx);
        s.checkInstantiation(fh.return_, fh.type_parameters) catch |e| {
            if (e == error.Vm) {
                ctx.atIndex(.Signature, i);
                ctx.atIndex(.FunctionHandle, i);
            }
            return e;
        };
        s.checkInstantiation(fh.parameters, fh.type_parameters) catch |e| {
            if (e == error.Vm) {
                ctx.atIndex(.Signature, i);
                ctx.atIndex(.FunctionHandle, i);
            }
            return e;
        };
    }
    var cbuf: [256]AbilitySet = undefined;
    for (m.struct_defs, 0..) |sd, sidx| {
        if (sd.native) continue;
        const sh = &m.datatype_handles[sd.struct_handle];
        const cons = s.handleConstraints(&cbuf, sd.struct_handle);
        for (sd.fields, 0..) |f, fo| {
            (blk: {
                s.checkSignatureToken(f.signature) catch |e| break :blk e;
                s.checkTypeInstantiation(f.signature, cons) catch |e| break :blk e;
                s.checkPhantom(f.signature, false, sh.type_parameters) catch |e| break :blk e;
            }) catch |e| {
                if (e == error.Vm) {
                    ctx.atIndex(.FieldDefinition, @intCast(fo));
                    ctx.atIndex(.StructDefinition, @intCast(sidx));
                }
                return e;
            };
        }
    }
    for (m.enum_defs, 0..) |ed, eidx| {
        const eh = &m.datatype_handles[ed.enum_handle];
        const cons = s.handleConstraints(&cbuf, ed.enum_handle);
        for (ed.variants, 0..) |v, tag| for (v.fields, 0..) |f, fi| {
            (blk: {
                s.checkSignatureToken(f.signature) catch |e| break :blk e;
                s.checkTypeInstantiation(f.signature, cons) catch |e| break :blk e;
                s.checkPhantom(f.signature, false, eh.type_parameters) catch |e| break :blk e;
            }) catch |e| {
                if (e == error.Vm) {
                    ctx.atIndex(.FieldDefinition, @intCast(fi));
                    ctx.atIndex(.VariantTag, @intCast(tag));
                    ctx.atIndex(.EnumDefinition, @intCast(eidx));
                }
                return e;
            };
        };
    }
    for (m.function_defs, 0..) |fd, fidx| {
        const code = fd.code orelse continue;
        const fh = &m.function_handles[fd.function];
        s.verifyCode(code, fh.type_parameters) catch |e| {
            if (e == error.Vm) {
                ctx.atIndex(.Signature, code.locals);
                ctx.atIndex(.FunctionDefinition, @intCast(fidx));
            }
            return e;
        };
    }
}

// =============================================================================================
// InstructionConsistency

pub fn instructionConsistency(ctx: *Ctx, cfg: *const c.Config, m: *const CompiledModule) E!void {
    for (m.function_defs, 0..) |fd, fidx| {
        const code = fd.code orelse continue;
        const f: u16 = @intCast(fidx);
        for (code.code, 0..) |ins, off| {
            const o: u16 = @intCast(off);
            const S = struct {
                fn typeOp(cx: *Ctx, mm: *const CompiledModule, ff_: u16, of: u16, dh: u16, generic: bool) E!void {
                    if ((mm.datatype_handles[dh].type_parameters.len == 0) == generic)
                        return cx.fail(PartialVmError.new(.GENERIC_MEMBER_OPCODE_MISMATCH).atCodeOffset(ff_, of));
                }
                fn structOp(cx: *Ctx, mm: *const CompiledModule, ff_: u16, of: u16, sd: u16, generic: bool) E!void {
                    return typeOp(cx, mm, ff_, of, mm.struct_defs[sd].struct_handle, generic);
                }
            };
            const deprecated = cfg.deprecate_global_storage_ops;
            switch (ins.op) {
                .MutBorrowField, .ImmBorrowField => try S.structOp(ctx, m, f, o, m.field_handles[ins.idx].owner, false),
                .MutBorrowFieldGeneric, .ImmBorrowFieldGeneric => try S.structOp(ctx, m, f, o, m.field_handles[m.field_instantiations[ins.idx].handle].owner, true),
                .Call => if ((m.function_handles[ins.idx].type_parameters.len == 0) == false)
                    return ctx.fail(PartialVmError.new(.GENERIC_MEMBER_OPCODE_MISMATCH).atCodeOffset(f, o)),
                .CallGeneric => if ((m.function_handles[m.function_instantiations[ins.idx].handle].type_parameters.len == 0) == true)
                    return ctx.fail(PartialVmError.new(.GENERIC_MEMBER_OPCODE_MISMATCH).atCodeOffset(f, o)),
                .Pack, .Unpack => try S.structOp(ctx, m, f, o, ins.idx, false),
                .PackGeneric, .UnpackGeneric => try S.structOp(ctx, m, f, o, m.struct_def_instantiations[ins.idx].def, true),
                .MutBorrowGlobalDeprecated, .ImmBorrowGlobalDeprecated, .ExistsDeprecated, .MoveFromDeprecated, .MoveToDeprecated => {
                    if (deprecated) return ctx.invariant();
                    try S.structOp(ctx, m, f, o, ins.idx, false);
                },
                .MutBorrowGlobalGenericDeprecated, .ImmBorrowGlobalGenericDeprecated, .ExistsGenericDeprecated, .MoveFromGenericDeprecated, .MoveToGenericDeprecated => {
                    if (deprecated) return ctx.invariant();
                    try S.structOp(ctx, m, f, o, m.struct_def_instantiations[ins.idx].def, true);
                },
                .VecPack, .VecUnpack => if (ins.imm > std.math.maxInt(u16))
                    return ctx.fail(PartialVmError.new(.CONSTRAINT_NOT_SATISFIED).atCodeOffset(f, o)),
                .PackVariant, .UnpackVariant, .UnpackVariantImmRef, .UnpackVariantMutRef => try S.typeOp(ctx, m, f, o, m.enum_defs[m.variant_handles[ins.idx].enum_def].enum_handle, false),
                .PackVariantGeneric, .UnpackVariantGeneric, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => {
                    const vh = m.variant_instantiation_handles[ins.idx];
                    try S.typeOp(ctx, m, f, o, m.enum_defs[m.enum_def_instantiations[vh.enum_def].def].enum_handle, true);
                },
                else => {},
            }
        }
    }
}

// =============================================================================================
// friends, ability_field_requirements

pub fn friends(ctx: *Ctx, m: *const CompiledModule) E!void {
    const self = m.module_handles[m.self_module_handle_idx];
    for (m.friend_decls) |fdecl| if (fdecl.address == self.address and fdecl.name == self.name) return ctx.status(.INVALID_FRIEND_DECL_WITH_SELF);
    const self_addr = &m.address_identifiers[self.address];
    for (m.friend_decls) |fdecl| if (!std.mem.eql(u8, &m.address_identifiers[fdecl.address], self_addr))
        return ctx.status(.INVALID_FRIEND_DECL_WITH_MODULES_OUTSIDE_ACCOUNT_ADDRESS);
}

fn requiredAbilities(declared: AbilitySet) AbilitySet {
    var r: AbilitySet = .EMPTY;
    inline for (.{ ff.Ability.Copy, ff.Ability.Drop, ff.Ability.Store, ff.Ability.Key }) |ab| {
        if (declared.has(ab)) r = r.with(AbilitySet.requires(ab));
    }
    return r;
}

pub fn abilityFieldRequirements(ctx: *Ctx, m: *const CompiledModule, cache: *c.AbilityCache, meter: *c.Meter) E!void {
    var all: [256]AbilitySet = @splat(AbilitySet.ALL);
    for (m.struct_defs, 0..) |sd, idx| {
        if (sd.native) continue;
        const sh = &m.datatype_handles[sd.struct_handle];
        const req = requiredAbilities(sh.abilities);
        const tps = all[0..sh.type_parameters.len];
        for (sd.fields) |f| {
            const fa = try cache.abilities(ctx, .Module, meter, tps, f.signature);
            if (!req.isSubset(fa)) return ctx.fail(ff.verificationError(.FIELD_MISSING_TYPE_ABILITY, .StructDefinition, @intCast(idx)));
        }
    }
    for (m.enum_defs, 0..) |ed, idx| {
        const sh = &m.datatype_handles[ed.enum_handle];
        const req = requiredAbilities(sh.abilities);
        const tps = all[0..sh.type_parameters.len];
        for (ed.variants, 0..) |v, i| for (v.fields, 0..) |f, fi| {
            const fa = try cache.abilities(ctx, .Module, meter, tps, f.signature);
            if (!req.isSubset(fa)) return ctx.fail(ff.verificationError(.FIELD_MISSING_TYPE_ABILITY, .EnumDefinition, @intCast(idx)).atIndex(.VariantTag, @intCast(i)).atIndex(.FieldDefinition, @intCast(fi)));
        };
    }
}

// =============================================================================================
// RecursiveDataDefChecker (petgraph 0.8.1 GraphMap + toposort, node order included)

/// A petgraph `GraphMap` over u32 node ids: nodes in insertion order, per-node adjacency lists
/// of (neighbor, outgoing) in edge insertion order.
const GraphMap = struct {
    const Adj = struct { n: u32, out: bool };
    nodes: std.ArrayList(u32) = .empty,
    adj: std.ArrayList(std.ArrayList(Adj)) = .empty,
    index: std.AutoHashMapUnmanaged(u32, u32) = .empty,
    edges: std.AutoHashMapUnmanaged(u64, void) = .empty,

    fn node(g: *GraphMap, a: Allocator, id: u32) E!u32 {
        const gop = try g.index.getOrPut(a, id);
        if (!gop.found_existing) {
            gop.value_ptr.* = @intCast(g.nodes.items.len);
            try g.nodes.append(a, id);
            try g.adj.append(a, .empty);
        }
        return gop.value_ptr.*;
    }

    fn addEdge(g: *GraphMap, a: Allocator, x: u32, y: u32) E!void {
        const key = (@as(u64, x) << 32) | y;
        const gop = try g.edges.getOrPut(a, key);
        if (gop.found_existing) return;
        const xi = try g.node(a, x);
        try g.adj.items[xi].append(a, .{ .n = y, .out = true });
        if (x != y) {
            const yi = try g.node(a, y);
            try g.adj.items[yi].append(a, .{ .n = x, .out = false });
        }
    }

    /// `petgraph::algo::toposort`; returns the node id of the reported cycle, or null.
    fn toposortCycle(g: *GraphMap, a: Allocator) E!?u32 {
        const n = g.nodes.items.len;
        const discovered = try a.alloc(bool, n);
        @memset(discovered, false);
        const finished = try a.alloc(bool, n);
        @memset(finished, false);
        var stack: std.ArrayList(u32) = .empty;
        var finish_stack: std.ArrayList(u32) = .empty;
        for (0..n) |ii| {
            const i: u32 = @intCast(ii);
            if (discovered[i]) continue;
            try stack.append(a, i);
            while (stack.items.len > 0) {
                const nx = stack.items[stack.items.len - 1];
                if (!discovered[nx]) {
                    discovered[nx] = true;
                    for (g.adj.items[nx].items) |e| {
                        if (!e.out) continue;
                        const succ = g.index.get(e.n).?;
                        if (succ == nx) return g.nodes.items[nx];
                        if (!discovered[succ]) try stack.append(a, succ);
                    }
                } else {
                    _ = stack.pop();
                    if (!finished[nx]) {
                        finished[nx] = true;
                        try finish_stack.append(a, nx);
                    }
                }
            }
        }
        std.mem.reverse(u32, finish_stack.items);
        @memset(discovered, false);
        for (finish_stack.items) |i| {
            stack.clearRetainingCapacity();
            try stack.append(a, i);
            var cycle = false;
            // Dfs::next over Reversed(g): incoming neighbors (and self loops)
            while (true) {
                const j = blk: {
                    while (stack.pop()) |node_| {
                        if (!discovered[node_]) {
                            discovered[node_] = true;
                            for (g.adj.items[node_].items) |e| {
                                const nb = g.index.get(e.n).?;
                                if (!e.out or nb == node_) {
                                    if (!discovered[nb]) try stack.append(a, nb);
                                }
                            }
                            break :blk node_;
                        }
                    }
                    break :blk null;
                } orelse break;
                if (cycle) return g.nodes.items[j];
                cycle = true;
            }
        }
        return null;
    }
};

pub fn recursiveDataDefs(ctx: *Ctx, arena: Allocator, m: *const CompiledModule) E!void {
    // DataIndex: Struct(i) -> i, Enum(i) -> 0x10000 + i (Struct < Enum, as Rust's derived Ord)
    const handle_to_def = try arena.alloc(?u32, m.datatype_handles.len);
    @memset(handle_to_def, null);
    for (m.struct_defs, 0..) |sd, i| {
        if (handle_to_def[sd.struct_handle] != null) return ctx.invariant();
        handle_to_def[sd.struct_handle] = @intCast(i);
    }
    for (m.enum_defs, 0..) |ed, i| {
        if (handle_to_def[ed.enum_handle] != null) return ctx.invariant();
        handle_to_def[ed.enum_handle] = 0x10000 + @as(u32, @intCast(i));
    }
    // neighbors: BTreeMap<DataIndex, BTreeSet<DataIndex>>
    const total = m.struct_defs.len + m.enum_defs.len;
    const neigh = try arena.alloc(std.ArrayList(u32), total);
    for (neigh) |*l| l.* = .empty;
    const S = struct {
        fn addTok(cx: *Ctx, al: Allocator, h2d: []const ?u32, list: *std.ArrayList(u32), t: Token) E!void {
            for (t) |n| switch (n.tag) {
                .Reference, .MutableReference => return cx.invariant(),
                .Datatype, .DatatypeInstantiation => if (h2d[n.idx]) |d| {
                    if (std.mem.indexOfScalar(u32, list.items, d) == null) try list.append(al, d);
                },
                else => {},
            };
        }
    };
    for (m.struct_defs, 0..) |sd, i| {
        if (sd.native) continue;
        for (sd.fields) |f| try S.addTok(ctx, arena, handle_to_def, &neigh[i], f.signature);
    }
    for (m.enum_defs, 0..) |ed, i| for (ed.variants) |v| for (v.fields) |f| try S.addTok(ctx, arena, handle_to_def, &neigh[m.struct_defs.len + i], f.signature);
    var g: GraphMap = .{};
    for (neigh, 0..) |*l, i| {
        std.mem.sort(u32, l.items, {}, std.sort.asc(u32));
        const parent: u32 = if (i < m.struct_defs.len) @intCast(i) else 0x10000 + @as(u32, @intCast(i - m.struct_defs.len));
        for (l.items) |child| try g.addEdge(arena, parent, child);
    }
    if (try g.toposortCycle(arena)) |id| {
        if (id >= 0x10000) return ctx.fail(ff.verificationError(.RECURSIVE_DATATYPE_DEFINITION, .EnumDefinition, @intCast(id - 0x10000)));
        return ctx.fail(ff.verificationError(.RECURSIVE_DATATYPE_DEFINITION, .StructDefinition, @intCast(id)));
    }
}

// =============================================================================================
// InstantiationLoopChecker: is there a strongly connected component with a TyConApp edge?

pub fn instantiationLoops(ctx: *Ctx, arena: Allocator, m: *const CompiledModule) E!void {
    // handle -> def
    const h2d = try arena.alloc(?u16, m.function_handles.len);
    @memset(h2d, null);
    for (m.function_defs, 0..) |fd, i| h2d[fd.function] = @intCast(i);
    // nodes: (def, type param) -> dense id
    var ids: std.AutoHashMapUnmanaged(u32, u32) = .empty;
    const Edge = struct { from: u32, to: u32, tycon: bool };
    var edges: std.ArrayList(Edge) = .empty;
    const S = struct {
        fn id(al: Allocator, map: *std.AutoHashMapUnmanaged(u32, u32), def: u16, p: u16) E!u32 {
            const gop = try map.getOrPut(al, (@as(u32, def) << 16) | p);
            if (!gop.found_existing) gop.value_ptr.* = map.count() - 1;
            return gop.value_ptr.*;
        }
    };
    var seen_params: std.ArrayList(u16) = .empty;
    for (m.function_defs, 0..) |fd, caller_| {
        const code = fd.code orelse continue;
        const caller: u16 = @intCast(caller_);
        for (code.code) |ins| {
            if (ins.op != .CallGeneric) continue;
            const fi = m.function_instantiations[ins.idx];
            const callee = h2d[fi.handle] orelse continue;
            for (m.signatures[fi.type_parameters], 0..) |ty, formal_| {
                const formal: u16 = @intCast(formal_);
                if (ty[0].tag == .TypeParameter) {
                    try edges.append(arena, .{ .from = try S.id(arena, &ids, caller, ty[0].idx), .to = try S.id(arena, &ids, callee, formal), .tycon = false });
                } else {
                    seen_params.clearRetainingCapacity();
                    for (ty) |n| if (n.tag == .TypeParameter and std.mem.indexOfScalar(u16, seen_params.items, n.idx) == null) try seen_params.append(arena, n.idx);
                    for (seen_params.items) |p| try edges.append(arena, .{ .from = try S.id(arena, &ids, caller, p), .to = try S.id(arena, &ids, callee, formal), .tycon = true });
                }
            }
        }
    }
    const n = ids.count();
    if (n == 0) return;
    // adjacency (CSR)
    const deg = try arena.alloc(u32, n + 1);
    @memset(deg, 0);
    for (edges.items) |e| deg[e.from + 1] += 1;
    for (1..n + 1) |i| deg[i] += deg[i - 1];
    const adj = try arena.alloc(u32, edges.items.len);
    const fill = try arena.dupe(u32, deg[0..n]);
    for (edges.items) |e| {
        adj[fill[e.from]] = e.to;
        fill[e.from] += 1;
    }
    // iterative Tarjan SCC
    const comp = try arena.alloc(u32, n);
    @memset(comp, std.math.maxInt(u32));
    const index = try arena.alloc(u32, n);
    @memset(index, std.math.maxInt(u32));
    const low = try arena.alloc(u32, n);
    const on = try arena.alloc(bool, n);
    @memset(on, false);
    var st: std.ArrayList(u32) = .empty;
    const Frame = struct { v: u32, next: u32 };
    var call: std.ArrayList(Frame) = .empty;
    var counter: u32 = 0;
    var ncomp: u32 = 0;
    for (0..n) |root_| {
        const root: u32 = @intCast(root_);
        if (index[root] != std.math.maxInt(u32)) continue;
        try call.append(arena, .{ .v = root, .next = deg[root] });
        index[root] = counter;
        low[root] = counter;
        counter += 1;
        try st.append(arena, root);
        on[root] = true;
        while (call.items.len > 0) {
            const fr = &call.items[call.items.len - 1];
            if (fr.next < deg[fr.v + 1]) {
                const w = adj[fr.next];
                fr.next += 1;
                if (index[w] == std.math.maxInt(u32)) {
                    index[w] = counter;
                    low[w] = counter;
                    counter += 1;
                    try st.append(arena, w);
                    on[w] = true;
                    try call.append(arena, .{ .v = w, .next = deg[w] });
                } else if (on[w]) low[fr.v] = @min(low[fr.v], index[w]);
            } else {
                const v = fr.v;
                _ = call.pop();
                if (call.items.len > 0) {
                    const p = call.items[call.items.len - 1].v;
                    low[p] = @min(low[p], low[v]);
                }
                if (low[v] == index[v]) {
                    while (st.pop()) |w| {
                        on[w] = false;
                        comp[w] = ncomp;
                        if (w == v) break;
                    }
                    ncomp += 1;
                }
            }
        }
    }
    for (edges.items) |e| if (e.tycon and comp[e.from] == comp[e.to]) return ctx.status(.LOOP_IN_INSTANTIATION_GRAPH);
}
