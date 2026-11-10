//! Bounds checker: a check-for-check port of move-binary-format `check_bounds.rs`.
//! Returns null when the module is in bounds, else the first PartialVmError Rust reports.
const std = @import("std");
const ff = @import("file_format.zig");
const Allocator = std.mem.Allocator;
const PartialVmError = ff.PartialVmError;
const IndexKind = ff.IndexKind;
const Token = ff.Token;

const Fail = error{ Vm, OutOfMemory };

const B = struct {
    m: *const ff.CompiledModule,
    deprecate_global_storage_ops: bool,
    /// per signature: max type parameter index used, or null
    sig_max_tp: []?u16 = &.{},
    /// set while checking a function definition (BoundsCheckingContext::ModuleFunction)
    cur_fn: ?u16 = null,
    err: PartialVmError = undefined,

    fn fail(b: *B, e: PartialVmError) Fail {
        b.err = e;
        return error.Vm;
    }

    fn check(b: *B, len: usize, idx: u16, kind: IndexKind) Fail!void {
        if (idx >= len) return b.fail(ff.boundsError(kind, idx));
    }

    fn checkCode(b: *B, len: usize, idx: u16, kind: IndexKind, offset: usize) Fail!void {
        if (idx >= len) return b.fail(b.offsetOutOfBounds(kind, offset));
    }

    fn offsetOutOfBounds(b: *B, _: IndexKind, offset: usize) PartialVmError {
        if (b.cur_fn) |f| return PartialVmError.new(.INDEX_OUT_OF_BOUNDS).atCodeOffset(f, @intCast(offset));
        return PartialVmError.new(.UNKNOWN_INVARIANT_VIOLATION_ERROR);
    }
};

pub fn verifyModule(arena: Allocator, m: *const ff.CompiledModule, deprecate_global_storage_ops: bool) Allocator.Error!?PartialVmError {
    if (m.module_handles.len == 0) return ff.verificationError(.NO_MODULE_HANDLES, .ModuleHandle, 0);
    var b: B = .{ .m = m, .deprecate_global_storage_ops = deprecate_global_storage_ops };
    verifyImpl(arena, &b) catch |e| switch (e) {
        error.Vm => return b.err,
        error.OutOfMemory => return error.OutOfMemory,
    };
    return null;
}

fn verifyImpl(arena: Allocator, b: *B) Fail!void {
    const m = b.m;
    // signatures (memoize max type parameter)
    b.sig_max_tp = try arena.alloc(?u16, m.signatures.len);
    for (m.signatures, 0..) |sig, i| {
        var mx: ?u16 = null;
        for (sig) |ty| {
            const t = try checkType(b, ty);
            mx = maxOpt(mx, t);
        }
        b.sig_max_tp[i] = mx;
    }
    for (m.constant_pool) |c| _ = try checkType(b, c.type_);
    for (m.module_handles) |mh| try checkModuleHandle(b, mh);
    try b.check(m.module_handles.len, m.self_module_handle_idx, .ModuleHandle);
    for (m.datatype_handles) |h| {
        try b.check(m.module_handles.len, h.module, .ModuleHandle);
        try b.check(m.identifiers.len, h.name, .Identifier);
    }
    for (m.function_handles) |h| {
        try b.check(m.module_handles.len, h.module, .ModuleHandle);
        try b.check(m.identifiers.len, h.name, .Identifier);
        try b.check(m.signatures.len, h.parameters, .Signature);
        try b.check(m.signatures.len, h.return_, .Signature);
        try checkSigTypeParams(b, h.parameters, h.type_parameters.len);
        try checkSigTypeParams(b, h.return_, h.type_parameters.len);
    }
    for (m.field_handles) |h| {
        try b.check(m.struct_defs.len, h.owner, .StructDefinition);
        const sd = &m.struct_defs[h.owner];
        const n = if (sd.native) 0 else sd.fields.len;
        if (h.field >= n) return b.fail(ff.boundsError(.MemberCount, h.field));
    }
    for (m.friend_decls) |mh| try checkModuleHandle(b, mh);
    for (m.struct_def_instantiations) |si| {
        try b.check(m.struct_defs.len, si.def, .StructDefinition);
        try b.check(m.signatures.len, si.type_parameters, .Signature);
    }
    for (m.function_instantiations) |fi| {
        try b.check(m.function_handles.len, fi.handle, .FunctionHandle);
        try b.check(m.signatures.len, fi.type_parameters, .Signature);
    }
    for (m.field_instantiations) |fi| {
        try b.check(m.field_handles.len, fi.handle, .FieldHandle);
        try b.check(m.signatures.len, fi.type_parameters, .Signature);
    }
    for (m.struct_defs) |sd| {
        try b.check(m.datatype_handles.len, sd.struct_handle, .DatatypeHandle);
        if (!sd.native) {
            const tpc = if (sd.struct_handle < m.datatype_handles.len) m.datatype_handles[sd.struct_handle].type_parameters.len else 0;
            for (sd.fields) |f| {
                try b.check(m.identifiers.len, f.name, .Identifier);
                _ = try checkType(b, f.signature);
                try checkTypeParameter(b, f.signature, tpc);
            }
        }
    }
    for (m.enum_defs) |ed| {
        try b.check(m.datatype_handles.len, ed.enum_handle, .DatatypeHandle);
        const tpc = if (ed.enum_handle < m.datatype_handles.len) m.datatype_handles[ed.enum_handle].type_parameters.len else 0;
        for (ed.variants) |v| {
            try b.check(m.identifiers.len, v.variant_name, .Identifier);
            for (v.fields) |f| {
                try b.check(m.identifiers.len, f.name, .Identifier);
                _ = try checkType(b, f.signature);
                try checkTypeParameter(b, f.signature, tpc);
            }
        }
    }
    for (m.enum_def_instantiations) |ei| {
        try b.check(m.enum_defs.len, ei.def, .EnumDefinition);
        try b.check(m.signatures.len, ei.type_parameters, .Signature);
    }
    for (m.variant_handles) |vh| {
        try b.check(m.enum_defs.len, vh.enum_def, .EnumDefinition);
        const n = m.enum_defs[vh.enum_def].variants.len;
        if (vh.variant >= n) return b.fail(ff.boundsError(.VariantTag, vh.variant));
    }
    for (m.variant_instantiation_handles) |vh| {
        try b.check(m.enum_def_instantiations.len, vh.enum_def, .EnumDefInstantiation);
        const ei = m.enum_def_instantiations[vh.enum_def];
        const n = m.enum_defs[ei.def].variants.len;
        if (vh.variant >= n) return b.fail(ff.boundsError(.VariantTag, vh.variant));
    }
    for (m.function_defs, 0..) |*fd, i| try checkFunctionDef(b, @intCast(i), fd);
}

fn maxOpt(a: ?u16, b: ?u16) ?u16 {
    if (a == null) return b;
    if (b == null) return a;
    return @max(a.?, b.?);
}

fn checkModuleHandle(b: *B, mh: ff.ModuleHandle) Fail!void {
    try b.check(b.m.address_identifiers.len, mh.address, .AddressIdentifier);
    try b.check(b.m.identifiers.len, mh.name, .Identifier);
}

fn checkType(b: *B, ty: Token) Fail!?u16 {
    const m = b.m;
    var mx: ?u16 = null;
    for (ty) |n| switch (n.tag) {
        .TypeParameter => mx = maxOpt(mx, n.idx),
        .Datatype => {
            try b.check(m.datatype_handles.len, n.idx, .DatatypeHandle);
            if (m.datatype_handles[n.idx].type_parameters.len != 0)
                return b.fail(PartialVmError.new(.NUMBER_OF_TYPE_ARGUMENTS_MISMATCH));
        },
        .DatatypeInstantiation => {
            try b.check(m.datatype_handles.len, n.idx, .DatatypeHandle);
            if (m.datatype_handles[n.idx].type_parameters.len != n.arity)
                return b.fail(PartialVmError.new(.NUMBER_OF_TYPE_ARGUMENTS_MISMATCH));
        },
        else => {},
    };
    return mx;
}

fn checkTypeParameter(b: *B, ty: Token, count: usize) Fail!void {
    for (ty) |n| if (n.tag == .TypeParameter and n.idx >= count) return b.fail(ff.boundsError(.TypeParameter, n.idx));
}

fn checkSigTypeParams(b: *B, sig_idx: u16, count: usize) Fail!void {
    if (sig_idx >= b.sig_max_tp.len) return b.fail(PartialVmError.new(.UNKNOWN_INVARIANT_VIOLATION_ERROR));
    const mx = b.sig_max_tp[sig_idx] orelse return;
    if (mx < count) return;
    for (b.m.signatures[sig_idx]) |ty| try checkTypeParameter(b, ty, count);
    return b.fail(PartialVmError.new(.UNKNOWN_INVARIANT_VIOLATION_ERROR));
}

fn checkFunctionDef(b: *B, fi: u16, fd: *const ff.FunctionDefinition) Fail!void {
    const m = b.m;
    b.cur_fn = fi;
    try b.check(m.function_handles.len, fd.function, .FunctionHandle);
    for (fd.acquires) |a| try b.check(m.struct_defs.len, a, .StructDefinition);
    const cu = fd.code orelse return;
    const fh = &m.function_handles[fd.function];
    if (fh.parameters >= m.signatures.len) return b.fail(ff.verificationError(.INDEX_OUT_OF_BOUNDS, .FunctionDefinition, fi));
    const params = m.signatures[fh.parameters];

    try b.check(m.signatures.len, cu.locals, .Signature);
    const locals = m.signatures[cu.locals];
    const locals_count = locals.len + params.len;
    if (locals_count > 255) return b.fail(ff.verificationError(.TOO_MANY_LOCALS, .FunctionDefinition, fi));
    const tpc = fh.type_parameters.len;
    try checkSigTypeParams(b, cu.locals, tpc);

    const code_len = cu.code.len;
    for (cu.code, 0..) |ins, off| {
        switch (ins.op) {
            .LdConst => try b.checkCode(m.constant_pool.len, ins.idx, .ConstantPool, off),
            .MutBorrowField, .ImmBorrowField => try b.checkCode(m.field_handles.len, ins.idx, .FieldHandle, off),
            .MutBorrowFieldGeneric, .ImmBorrowFieldGeneric => {
                try b.checkCode(m.field_instantiations.len, ins.idx, .FieldInstantiation, off);
                try checkSigTypeParams(b, m.field_instantiations[ins.idx].type_parameters, tpc);
            },
            .Call => try b.checkCode(m.function_handles.len, ins.idx, .FunctionHandle, off),
            .CallGeneric => {
                try b.checkCode(m.function_instantiations.len, ins.idx, .FunctionInstantiation, off);
                try checkSigTypeParams(b, m.function_instantiations[ins.idx].type_parameters, tpc);
            },
            .Pack, .Unpack => try b.checkCode(m.struct_defs.len, ins.idx, .StructDefinition, off),
            .ExistsDeprecated, .ImmBorrowGlobalDeprecated, .MutBorrowGlobalDeprecated, .MoveFromDeprecated, .MoveToDeprecated => {
                if (b.deprecate_global_storage_ops) return b.fail(PartialVmError.new(.UNKNOWN_INVARIANT_VIOLATION_ERROR));
                try b.checkCode(m.struct_defs.len, ins.idx, .StructDefinition, off);
            },
            .PackGeneric, .UnpackGeneric => {
                try b.checkCode(m.struct_def_instantiations.len, ins.idx, .StructDefInstantiation, off);
                try checkSigTypeParams(b, m.struct_def_instantiations[ins.idx].type_parameters, tpc);
            },
            .ExistsGenericDeprecated, .ImmBorrowGlobalGenericDeprecated, .MutBorrowGlobalGenericDeprecated, .MoveFromGenericDeprecated, .MoveToGenericDeprecated => {
                if (b.deprecate_global_storage_ops) return b.fail(PartialVmError.new(.UNKNOWN_INVARIANT_VIOLATION_ERROR));
                try b.checkCode(m.struct_def_instantiations.len, ins.idx, .StructDefInstantiation, off);
                try checkSigTypeParams(b, m.struct_def_instantiations[ins.idx].type_parameters, tpc);
            },
            .BrTrue, .BrFalse, .Branch => {
                if (ins.idx >= code_len) return b.fail(b.offsetOutOfBounds(.CodeDefinition, off));
            },
            .CopyLoc, .MoveLoc, .StLoc, .MutBorrowLoc, .ImmBorrowLoc => {
                if (ins.idx >= locals_count) return b.fail(b.offsetOutOfBounds(.LocalPool, off));
            },
            .VecPack, .VecLen, .VecImmBorrow, .VecMutBorrow, .VecPushBack, .VecPopBack, .VecUnpack, .VecSwap => {
                try b.checkCode(m.signatures.len, ins.idx, .Signature, off);
                try checkSigTypeParams(b, ins.idx, tpc);
            },
            .PackVariant, .UnpackVariant, .UnpackVariantImmRef, .UnpackVariantMutRef => try b.checkCode(m.variant_handles.len, ins.idx, .VariantHandle, off),
            .PackVariantGeneric, .UnpackVariantGeneric, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => {
                try b.checkCode(m.variant_instantiation_handles.len, ins.idx, .VariantInstantiationHandle, off);
                const h = m.variant_instantiation_handles[ins.idx];
                try checkSigTypeParams(b, m.enum_def_instantiations[h.enum_def].type_parameters, tpc);
            },
            .VariantSwitch => try b.checkCode(cu.jump_tables.len, ins.idx, .VariantJumpTable, off),
            else => {},
        }
    }
    for (cu.jump_tables) |jt| {
        try b.check(m.enum_defs.len, jt.head_enum, .EnumDefinition);
        const nv = m.enum_defs[jt.head_enum].variants.len;
        if (jt.offsets.len != nv) return b.fail(ff.verificationError(.INVALID_ENUM_SWITCH, .VariantTag, @intCast(jt.offsets.len)));
        for (jt.offsets) |o| if (o >= code_len) return b.fail(ff.boundsError(.CodeDefinition, o));
    }
}
