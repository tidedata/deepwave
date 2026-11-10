//! Package upgrade compatibility (`check_compatibility` in the static PTB context.rs, over
//! move-binary-format `compatibility.rs` and `normalized.rs`). The normalized modules are not
//! built: types, signatures and bytecode are compared in place across the two compiled modules,
//! resolving every handle to what normalization would produce (datatypes to address, module and
//! name; function references to module and name; struct, field and variant references to
//! names). Every failure is the same `IncompatibleUpgrade`, so the checks return a bool.
const std = @import("std");
const types = @import("types");
const move_format = @import("move_format");
const ff = move_format.file_format;

const CM = ff.CompiledModule;
const Token = ff.Token;

pub const COMPATIBLE: u8 = 0;
pub const ADDITIVE: u8 = 128;
pub const DEP_ONLY: u8 = 192;

pub const Outcome = union(enum) { ok, err: types.PackageUpgradeError };

/// `check_compatibility(existing package, upgrading modules, policy)`. `existing` is sorted by
/// module name (the package's module map).
pub fn check(existing: []const *const CM, upgrading: []const CM, policy: u8) Outcome {
    return checkOpts(existing, upgrading, policy, .{});
}

pub const Opts = struct {
    /// `disallow_new_modules_in_deps_only_packages` (protocol 68): a dep-only upgrade keeps the
    /// module count.
    dep_only_same_modules: bool = true,
};

pub fn checkOpts(existing: []const *const CM, upgrading: []const CM, policy: u8, opts: Opts) Outcome {
    if (policy != COMPATIBLE and policy != ADDITIVE and policy != DEP_ONLY)
        return .{ .err = .{ .UnknownUpgradePolicy = .{ .policy = policy } } };
    const incompatible: Outcome = .{ .err = .IncompatibleUpgrade };
    if (opts.dep_only_same_modules and policy == DEP_ONLY and existing.len != upgrading.len) return incompatible;
    for (existing) |cur| {
        const new = for (upgrading) |*m| {
            if (std.mem.eql(u8, m.selfName(), cur.selfName())) break m;
        } else return incompatible;
        const ok = switch (policy) {
            COMPATIBLE => compatible(cur, new),
            ADDITIVE => inclusion(cur, new, .subset),
            else => inclusion(cur, new, .equal),
        };
        if (!ok) return incompatible;
    }
    return .ok;
}

// ---------------------------------------------------------------------------------------------
// Names and types

const DtKey = struct { addr: *const [32]u8, module: []const u8, name: []const u8 };

fn dtKey(m: *const CM, h: u16) DtKey {
    const dh = m.datatype_handles[h];
    const mh = m.module_handles[dh.module];
    return .{ .addr = &m.address_identifiers[mh.address], .module = m.identifiers[mh.name], .name = m.identifiers[dh.name] };
}

fn dtKeyEql(a: DtKey, b: DtKey) bool {
    return std.mem.eql(u8, a.addr, b.addr) and std.mem.eql(u8, a.module, b.module) and std.mem.eql(u8, a.name, b.name);
}

/// `normalized::Type` equality of two signature tokens.
fn typeEq(ma: *const CM, a: Token, mb: *const CM, b: Token) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x.tag != y.tag or x.arity != y.arity) return false;
        switch (x.tag) {
            .Datatype, .DatatypeInstantiation => if (!dtKeyEql(dtKey(ma, x.idx), dtKey(mb, y.idx))) return false,
            .TypeParameter => if (x.idx != y.idx) return false,
            else => {},
        }
    }
    return true;
}

fn sigEq(ma: *const CM, a: []const Token, mb: *const CM, b: []const Token) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!typeEq(ma, x, mb, y)) return false;
    return true;
}

fn sigIdxEq(ma: *const CM, a: u16, mb: *const CM, b: u16) bool {
    return sigEq(ma, ma.signatures[a], mb, mb.signatures[b]);
}

fn ident(m: *const CM, i: u16) []const u8 {
    return m.identifiers[i];
}

fn structName(m: *const CM, def: u16) []const u8 {
    return m.identifiers[m.datatype_handles[m.struct_defs[def].struct_handle].name];
}

fn enumName(m: *const CM, def: u16) []const u8 {
    return m.identifiers[m.datatype_handles[m.enum_defs[def].enum_handle].name];
}

fn findStruct(m: *const CM, name: []const u8) ?u16 {
    for (m.struct_defs, 0..) |_, i| if (std.mem.eql(u8, structName(m, @intCast(i)), name)) return @intCast(i);
    return null;
}

fn findEnum(m: *const CM, name: []const u8) ?u16 {
    for (m.enum_defs, 0..) |_, i| if (std.mem.eql(u8, enumName(m, @intCast(i)), name)) return @intCast(i);
    return null;
}

fn funcName(m: *const CM, def: usize) []const u8 {
    return m.identifiers[m.function_handles[m.function_defs[def].function].name];
}

fn findFunc(m: *const CM, name: []const u8) ?usize {
    for (m.function_defs, 0..) |_, i| if (std.mem.eql(u8, funcName(m, i), name)) return i;
    return null;
}

fn fieldsEq(ma: *const CM, a: []const ff.FieldDefinition, mb: *const CM, b: []const ff.FieldDefinition) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, ident(ma, x.name), ident(mb, y.name))) return false;
        if (!typeEq(ma, x.signature, mb, y.signature)) return false;
    }
    return true;
}

fn structFields(m: *const CM, def: u16) []const ff.FieldDefinition {
    // a native struct normalizes to no fields
    const sd = &m.struct_defs[def];
    return if (sd.native) &.{} else sd.fields;
}

fn tyParamsEq(a: []const ff.DatatypeTyParameter, b: []const ff.DatatypeTyParameter) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x.is_phantom != y.is_phantom or x.constraints.bits != y.constraints.bits) return false;
    return true;
}

fn selfIdEq(a: *const CM, b: *const CM) bool {
    return std.mem.eql(u8, a.selfAddress(), b.selfAddress()) and std.mem.eql(u8, a.selfName(), b.selfName());
}

// ---------------------------------------------------------------------------------------------
// Compatibility::upgrade_check (datatype layout checked, private entry linking not, no new
// abilities): ExecutionCompatibilityMode, where only entry linking is ignored.

fn compatible(old: *const CM, new: *const CM) bool {
    if (!selfIdEq(old, new)) return false;
    for (old.struct_defs, 0..) |sd, i| {
        const name = structName(old, @intCast(i));
        const j = findStruct(new, name) orelse return false;
        const oh = old.datatype_handles[sd.struct_handle];
        const nh = new.datatype_handles[new.struct_defs[j].struct_handle];
        // old <= new and nothing new (every ability disallowed): equal
        if (oh.abilities.bits != nh.abilities.bits) return false;
        if (!tyParamsEq(oh.type_parameters, nh.type_parameters)) return false;
        if (!fieldsEq(old, structFields(old, @intCast(i)), new, structFields(new, j))) return false;
    }
    for (old.enum_defs, 0..) |ed, i| {
        const name = enumName(old, @intCast(i));
        const j = findEnum(new, name) orelse return false;
        const ned = new.enum_defs[j];
        const oh = old.datatype_handles[ed.enum_handle];
        const nh = new.datatype_handles[ned.enum_handle];
        if (oh.abilities.bits != nh.abilities.bits) return false;
        if (!tyParamsEq(oh.type_parameters, nh.type_parameters)) return false;
        if (ned.variants.len > ed.variants.len) return false;
        for (ed.variants, 0..) |ov, tag| {
            if (tag >= ned.variants.len) return false;
            const nv = ned.variants[tag];
            if (!std.mem.eql(u8, ident(old, ov.variant_name), ident(new, nv.variant_name))) return false;
            if (!fieldsEq(old, ov.fields, new, nv.fields)) return false;
        }
    }
    for (old.function_defs, 0..) |of, i| {
        const name = funcName(old, i);
        const public = of.visibility == .Public;
        const j = findFunc(new, name) orelse {
            if (public) return false;
            continue;
        };
        const nf = new.function_defs[j];
        if (public and nf.visibility != .Public) return false;
        if (!public) continue; // a signature change only breaks public linking (entry ignored)
        const oh = old.function_handles[of.function];
        const nh = new.function_handles[nf.function];
        if (!sigIdxEq(old, oh.parameters, new, nh.parameters) or !sigIdxEq(old, oh.return_, new, nh.return_)) return false;
        if (oh.type_parameters.len != nh.type_parameters.len) return false;
        for (oh.type_parameters, nh.type_parameters) |o, n| if (!n.isSubset(o)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------------------------
// InclusionCheck (Subset for ADDITIVE, Equal for DEP_ONLY): items compared with code.

const Mode = enum { subset, equal };

fn inclusion(old: *const CM, new: *const CM, mode: Mode) bool {
    if (!selfIdEq(old, new)) return false;
    if (old.version > new.version) return false;
    var equal = true;
    // structs
    for (old.struct_defs, 0..) |_, i| {
        const j = findStruct(new, structName(old, @intCast(i))) orelse return false;
        if (!structEquiv(old, @intCast(i), new, j)) return false;
    }
    if (new.struct_defs.len != old.struct_defs.len) equal = false;
    for (old.enum_defs, 0..) |_, i| {
        const j = findEnum(new, enumName(old, @intCast(i))) orelse return false;
        if (!enumEquiv(old, @intCast(i), new, j)) return false;
    }
    if (new.enum_defs.len != old.enum_defs.len) equal = false;
    for (old.function_defs, 0..) |_, i| {
        const j = findFunc(new, funcName(old, i)) orelse return false;
        if (!funcEquiv(old, i, new, j)) return false;
    }
    if (new.function_defs.len != old.function_defs.len) equal = false;
    if (old.friend_decls.len != new.friend_decls.len) equal = false;
    return switch (mode) {
        .subset => true,
        .equal => equal,
    };
}

fn structEquiv(ma: *const CM, a: u16, mb: *const CM, b: u16) bool {
    const ha = ma.datatype_handles[ma.struct_defs[a].struct_handle];
    const hb = mb.datatype_handles[mb.struct_defs[b].struct_handle];
    if (!dtKeyEql(dtKey(ma, ma.struct_defs[a].struct_handle), dtKey(mb, mb.struct_defs[b].struct_handle))) return false;
    if (ha.abilities.bits != hb.abilities.bits) return false;
    if (!tyParamsEq(ha.type_parameters, hb.type_parameters)) return false;
    return fieldsEq(ma, structFields(ma, a), mb, structFields(mb, b));
}

fn enumEquiv(ma: *const CM, a: u16, mb: *const CM, b: u16) bool {
    const ea = ma.enum_defs[a];
    const eb = mb.enum_defs[b];
    const ha = ma.datatype_handles[ea.enum_handle];
    const hb = mb.datatype_handles[eb.enum_handle];
    if (!dtKeyEql(dtKey(ma, ea.enum_handle), dtKey(mb, eb.enum_handle))) return false;
    if (ha.abilities.bits != hb.abilities.bits) return false;
    if (!tyParamsEq(ha.type_parameters, hb.type_parameters)) return false;
    if (ea.variants.len != eb.variants.len) return false;
    for (ea.variants, eb.variants) |x, y| {
        if (!std.mem.eql(u8, ident(ma, x.variant_name), ident(mb, y.variant_name))) return false;
        if (!fieldsEq(ma, x.fields, mb, y.fields)) return false;
    }
    return true;
}

fn funcEquiv(ma: *const CM, a: usize, mb: *const CM, b: usize) bool {
    const fa = ma.function_defs[a];
    const fb = mb.function_defs[b];
    const ha = ma.function_handles[fa.function];
    const hb = mb.function_handles[fb.function];
    if (fa.visibility != fb.visibility or fa.is_entry != fb.is_entry) return false;
    if (ha.type_parameters.len != hb.type_parameters.len) return false;
    for (ha.type_parameters, hb.type_parameters) |x, y| if (x.bits != y.bits) return false;
    if (!sigIdxEq(ma, ha.parameters, mb, hb.parameters) or !sigIdxEq(ma, ha.return_, mb, hb.return_)) return false;
    const ca: []const ff.Instr = if (fa.code) |c| c.code else &.{};
    const cb: []const ff.Instr = if (fb.code) |c| c.code else &.{};
    const ja: []const ff.JumpTable = if (fa.code) |c| c.jump_tables else &.{};
    const jb: []const ff.JumpTable = if (fb.code) |c| c.jump_tables else &.{};
    if (ja.len != jb.len) return false;
    for (ja, jb) |x, y| if (!jumpTableEq(ma, x, mb, y)) return false;
    if (ca.len != cb.len) return false;
    for (ca, cb) |x, y| if (!instrEq(ma, fa, x, mb, fb, y)) return false;
    return true;
}

fn jumpTableEq(ma: *const CM, a: ff.JumpTable, mb: *const CM, b: ff.JumpTable) bool {
    return std.mem.eql(u8, enumName(ma, a.head_enum), enumName(mb, b.head_enum)) and std.mem.eql(u16, a.offsets, b.offsets);
}

/// Normalization folds the generic forms into the plain ones.
fn normOp(op: ff.Opcode) ff.Opcode {
    return switch (op) {
        .CallGeneric => .Call,
        .PackGeneric => .Pack,
        .UnpackGeneric => .Unpack,
        .MutBorrowFieldGeneric => .MutBorrowField,
        .ImmBorrowFieldGeneric => .ImmBorrowField,
        .MutBorrowGlobalGenericDeprecated => .MutBorrowGlobalDeprecated,
        .ImmBorrowGlobalGenericDeprecated => .ImmBorrowGlobalDeprecated,
        .ExistsGenericDeprecated => .ExistsDeprecated,
        .MoveFromGenericDeprecated => .MoveFromDeprecated,
        .MoveToGenericDeprecated => .MoveToDeprecated,
        .PackVariantGeneric => .PackVariant,
        .UnpackVariantGeneric => .UnpackVariant,
        .UnpackVariantGenericImmRef => .UnpackVariantImmRef,
        .UnpackVariantGenericMutRef => .UnpackVariantMutRef,
        else => op,
    };
}

fn isGeneric(op: ff.Opcode) bool {
    return normOp(op) != op;
}

/// A struct reference: (definition, type argument signature or none).
const SRef = struct { def: u16, sig: ?u16 };

fn structRef(m: *const CM, i: ff.Instr) SRef {
    if (isGeneric(i.op)) {
        const inst = m.struct_def_instantiations[i.idx];
        return .{ .def = inst.def, .sig = inst.type_parameters };
    }
    return .{ .def = i.idx, .sig = null };
}

fn optSigEq(ma: *const CM, a: ?u16, mb: *const CM, b: ?u16) bool {
    const sa: []const Token = if (a) |x| ma.signatures[x] else &.{};
    const sb: []const Token = if (b) |x| mb.signatures[x] else &.{};
    return sigEq(ma, sa, mb, sb);
}

const FRef = struct { handle: u16, sig: ?u16 };

fn fieldRef(m: *const CM, i: ff.Instr) FRef {
    if (isGeneric(i.op)) {
        const inst = m.field_instantiations[i.idx];
        return .{ .handle = inst.handle, .sig = inst.type_parameters };
    }
    return .{ .handle = i.idx, .sig = null };
}

const VRef = struct { def: u16, variant: u16, sig: ?u16 };

fn variantRef(m: *const CM, i: ff.Instr) VRef {
    if (isGeneric(i.op)) {
        const vih = m.variant_instantiation_handles[i.idx];
        const inst = m.enum_def_instantiations[vih.enum_def];
        return .{ .def = inst.def, .variant = vih.variant, .sig = inst.type_parameters };
    }
    const vh = m.variant_handles[i.idx];
    return .{ .def = vh.enum_def, .variant = vh.variant, .sig = null };
}

fn instrEq(ma: *const CM, fa: ff.FunctionDefinition, a: ff.Instr, mb: *const CM, fb: ff.FunctionDefinition, b: ff.Instr) bool {
    const op = normOp(a.op);
    if (op != normOp(b.op)) return false;
    return switch (op) {
        .BrTrue, .BrFalse, .Branch, .CopyLoc, .MoveLoc, .StLoc, .MutBorrowLoc, .ImmBorrowLoc => a.idx == b.idx,
        .LdU8, .LdU16, .LdU32, .LdU64 => a.imm == b.imm,
        .LdU128, .LdU256 => std.mem.eql(u8, &ma.wide[@intCast(a.imm)], &mb.wide[@intCast(b.imm)]),
        .LdConst => blk: {
            const x = ma.constant_pool[a.idx];
            const y = mb.constant_pool[b.idx];
            break :blk typeEq(ma, x.type_, mb, y.type_) and std.mem.eql(u8, x.data, y.data);
        },
        .Call => blk: {
            const ha_idx: u16, const sa: ?u16 = if (a.op == .CallGeneric) .{ ma.function_instantiations[a.idx].handle, ma.function_instantiations[a.idx].type_parameters } else .{ a.idx, null };
            const hb_idx: u16, const sb: ?u16 = if (b.op == .CallGeneric) .{ mb.function_instantiations[b.idx].handle, mb.function_instantiations[b.idx].type_parameters } else .{ b.idx, null };
            const ha = ma.function_handles[ha_idx];
            const hb = mb.function_handles[hb_idx];
            const mha = ma.module_handles[ha.module];
            const mhb = mb.module_handles[hb.module];
            if (!std.mem.eql(u8, &ma.address_identifiers[mha.address], &mb.address_identifiers[mhb.address])) break :blk false;
            if (!std.mem.eql(u8, ident(ma, mha.name), ident(mb, mhb.name))) break :blk false;
            if (!std.mem.eql(u8, ident(ma, ha.name), ident(mb, hb.name))) break :blk false;
            break :blk optSigEq(ma, sa, mb, sb);
        },
        .Pack, .Unpack, .MutBorrowGlobalDeprecated, .ImmBorrowGlobalDeprecated, .ExistsDeprecated, .MoveFromDeprecated, .MoveToDeprecated => blk: {
            const x = structRef(ma, a);
            const y = structRef(mb, b);
            break :blk std.mem.eql(u8, structName(ma, x.def), structName(mb, y.def)) and optSigEq(ma, x.sig, mb, y.sig);
        },
        .MutBorrowField, .ImmBorrowField => blk: {
            const x = fieldRef(ma, a);
            const y = fieldRef(mb, b);
            const fha = ma.field_handles[x.handle];
            const fhb = mb.field_handles[y.handle];
            if (!std.mem.eql(u8, structName(ma, fha.owner), structName(mb, fhb.owner))) break :blk false;
            const fa_fields = structFields(ma, fha.owner);
            const fb_fields = structFields(mb, fhb.owner);
            if (fha.field >= fa_fields.len or fhb.field >= fb_fields.len) break :blk false;
            if (!std.mem.eql(u8, ident(ma, fa_fields[fha.field].name), ident(mb, fb_fields[fhb.field].name))) break :blk false;
            break :blk optSigEq(ma, x.sig, mb, y.sig);
        },
        .VecPack, .VecUnpack => a.imm == b.imm and typeEq(ma, ma.signatures[a.idx][0], mb, mb.signatures[b.idx][0]),
        .VecLen, .VecImmBorrow, .VecMutBorrow, .VecPushBack, .VecPopBack, .VecSwap => typeEq(ma, ma.signatures[a.idx][0], mb, mb.signatures[b.idx][0]),
        .PackVariant, .UnpackVariant, .UnpackVariantImmRef, .UnpackVariantMutRef => blk: {
            const x = variantRef(ma, a);
            const y = variantRef(mb, b);
            if (!std.mem.eql(u8, enumName(ma, x.def), enumName(mb, y.def))) break :blk false;
            const va = ma.enum_defs[x.def].variants[x.variant];
            const vb = mb.enum_defs[y.def].variants[y.variant];
            if (!std.mem.eql(u8, ident(ma, va.variant_name), ident(mb, vb.variant_name))) break :blk false;
            break :blk optSigEq(ma, x.sig, mb, y.sig);
        },
        .VariantSwitch => blk: {
            const ja = (fa.code orelse break :blk false).jump_tables;
            const jb = (fb.code orelse break :blk false).jump_tables;
            break :blk jumpTableEq(ma, ja[a.idx], mb, jb[b.idx]);
        },
        else => true,
    };
}
