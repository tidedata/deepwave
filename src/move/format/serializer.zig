//! CompiledModule serializer: a port of move-binary-format `serializer.rs`
//! (`serialize_with_version`). Output is byte-identical to Rust's; every case where Rust bails
//! returns `error.Unserializable`.
const std = @import("std");
const ff = @import("file_format.zig");
const Allocator = std.mem.Allocator;

pub const Error = error{ Unserializable, OutOfMemory };

const W = struct {
    gpa: Allocator,
    buf: *std.ArrayList(u8),

    fn push(w: W, b: u8) Error!void {
        try w.buf.append(w.gpa, b);
    }
    fn bytes(w: W, b: []const u8) Error!void {
        try w.buf.appendSlice(w.gpa, b);
    }
    fn uleb(w: W, v_: u64) Error!void {
        var v = v_;
        while (true) {
            const cur: u8 = @intCast(v & 0x7f);
            if (cur != v) {
                try w.push(cur | 0x80);
                v >>= 7;
            } else {
                try w.push(cur);
                return;
            }
        }
    }
    fn ulebMax(w: W, v: u64, max: u64) Error!void {
        if (v > max) return error.Unserializable;
        try w.uleb(v);
    }
    fn idx(w: W, v: u16) Error!void {
        try w.uleb(v);
    }
    fn len(w: W) u32 {
        return @intCast(w.buf.items.len);
    }
};

/// Serialize `m` at bytecode `version` (Rust `serialize_with_version`), appending to `out`.
pub fn serialize(gpa: Allocator, m: *const ff.CompiledModule, version: u32, out: *std.ArrayList(u8)) Error!void {
    if (version < ff.VERSION_MIN or version > ff.VERSION_MAX) return error.Unserializable;
    var temp: std.ArrayList(u8) = .empty;
    defer temp.deinit(gpa);
    const t: W = .{ .gpa = gpa, .buf = &temp };

    const Entry = struct { kind: ff.TableType, off: u32, size: u32 };
    var entries: [20]Entry = undefined;
    var n: usize = 0;
    const Rec = struct {
        fn begin(w: W) u32 {
            return w.len();
        }
    };
    // Content order: common tables, then module tables (serialize_tables).
    const order = [_]ff.TableType{ .MODULE_HANDLES, .DATATYPE_HANDLES, .FUNCTION_HANDLES, .FUNCTION_INST, .SIGNATURES, .IDENTIFIERS, .ADDRESS_IDENTIFIERS, .CONSTANT_POOL, .METADATA, .STRUCT_DEFS, .STRUCT_DEF_INST, .FUNCTION_DEFS, .FIELD_HANDLE, .FIELD_INST, .FRIEND_DECLS, .ENUM_DEFS, .ENUM_DEF_INST, .VARIANT_HANDLES, .VARIANT_INST_HANDLES };
    var offs: [256]?struct { off: u32, size: u32 } = @splat(null);
    for (order) |kind| {
        const start = Rec.begin(t);
        const wrote = try writeTable(t, m, version, kind);
        if (wrote) offs[@intFromEnum(kind)] = .{ .off = start, .size = t.len() - start };
    }
    if (temp.items.len > std.math.maxInt(u32)) return error.Unserializable;

    // Header order (serialize_table_indices): common header incl. metadata (v5+), then module.
    const header_order = [_]ff.TableType{ .MODULE_HANDLES, .DATATYPE_HANDLES, .FUNCTION_HANDLES, .FUNCTION_INST, .SIGNATURES, .IDENTIFIERS, .ADDRESS_IDENTIFIERS, .CONSTANT_POOL, .METADATA, .STRUCT_DEFS, .STRUCT_DEF_INST, .FUNCTION_DEFS, .FIELD_HANDLE, .FIELD_INST, .FRIEND_DECLS, .ENUM_DEFS, .ENUM_DEF_INST, .VARIANT_HANDLES, .VARIANT_INST_HANDLES };
    for (header_order) |kind| {
        if (offs[@intFromEnum(kind)]) |e| {
            entries[n] = .{ .kind = kind, .off = e.off, .size = e.size };
            n += 1;
        }
    }

    const w: W = .{ .gpa = gpa, .buf = out };
    try w.bytes(if (m.publishable) &ff.MOVE_MAGIC else &ff.UNPUBLISHABLE_MAGIC);
    var vb: [4]u8 = undefined;
    std.mem.writeInt(u32, &vb, ff.encodeVersion(version), .little);
    try w.bytes(&vb);
    try w.ulebMax(n, ff.TABLE_COUNT_MAX);
    for (entries[0..n]) |e| {
        if (e.size == 0) continue;
        try w.push(@intFromEnum(e.kind));
        try w.ulebMax(e.off, ff.TABLE_OFFSET_MAX);
        try w.ulebMax(e.size, ff.TABLE_SIZE_MAX);
    }
    try w.bytes(temp.items);
    try w.idx(m.self_module_handle_idx);
}

/// Serialize into a fresh slice owned by `gpa`.
pub fn serializeAlloc(gpa: Allocator, m: *const ff.CompiledModule, version: u32) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try serialize(gpa, m, version, &out);
    return out.toOwnedSlice(gpa);
}

fn writeTable(w: W, m: *const ff.CompiledModule, version: u32, kind: ff.TableType) Error!bool {
    switch (kind) {
        .MODULE_HANDLES => {
            if (m.module_handles.len == 0) return false;
            for (m.module_handles) |h| {
                try w.idx(h.address);
                try w.idx(h.name);
            }
        },
        .DATATYPE_HANDLES => {
            if (m.datatype_handles.len == 0) return false;
            for (m.datatype_handles) |h| {
                try w.idx(h.module);
                try w.idx(h.name);
                try abilitySet(w, h.abilities);
                try w.ulebMax(h.type_parameters.len, ff.TYPE_PARAMETER_COUNT_MAX);
                for (h.type_parameters) |tp| {
                    try abilitySet(w, tp.constraints);
                    try w.ulebMax(@intFromBool(tp.is_phantom), 1);
                }
            }
        },
        .FUNCTION_HANDLES => {
            if (m.function_handles.len == 0) return false;
            for (m.function_handles) |h| {
                try w.idx(h.module);
                try w.idx(h.name);
                try w.idx(h.parameters);
                try w.idx(h.return_);
                try w.ulebMax(h.type_parameters.len, ff.TYPE_PARAMETER_COUNT_MAX);
                for (h.type_parameters) |a| try abilitySet(w, a);
            }
        },
        .FUNCTION_INST => {
            if (m.function_instantiations.len == 0) return false;
            for (m.function_instantiations) |x| {
                try w.idx(x.handle);
                try w.idx(x.type_parameters);
            }
        },
        .SIGNATURES => {
            if (m.signatures.len == 0) return false;
            for (m.signatures) |sig| {
                try w.ulebMax(sig.len, ff.SIGNATURE_SIZE_MAX);
                for (sig) |tok| try token(w, tok);
            }
        },
        .IDENTIFIERS => {
            if (m.identifiers.len == 0) return false;
            for (m.identifiers) |s| {
                try w.ulebMax(s.len, ff.IDENTIFIER_SIZE_MAX);
                try w.bytes(s);
            }
        },
        .ADDRESS_IDENTIFIERS => {
            if (m.address_identifiers.len == 0) return false;
            for (m.address_identifiers) |*a| try w.bytes(a);
        },
        .CONSTANT_POOL => {
            if (m.constant_pool.len == 0) return false;
            for (m.constant_pool) |c| {
                try token(w, c.type_);
                try w.ulebMax(c.data.len, ff.CONSTANT_SIZE_MAX);
                try w.bytes(c.data);
            }
        },
        .METADATA => {
            if (version < ff.VERSION_5 or m.metadata.len == 0) return false;
            for (m.metadata) |md| {
                try w.ulebMax(md.key.len, ff.METADATA_KEY_SIZE_MAX);
                try w.bytes(md.key);
                try w.ulebMax(md.value.len, ff.METADATA_VALUE_SIZE_MAX);
                try w.bytes(md.value);
            }
        },
        .STRUCT_DEFS => {
            if (m.struct_defs.len == 0) return false;
            for (m.struct_defs) |sd| {
                try w.idx(sd.struct_handle);
                if (sd.native) {
                    try w.push(0x1);
                } else {
                    try w.push(0x2);
                    try fieldDefs(w, sd.fields);
                }
            }
        },
        .STRUCT_DEF_INST => {
            if (m.struct_def_instantiations.len == 0) return false;
            for (m.struct_def_instantiations) |x| {
                try w.idx(x.def);
                try w.idx(x.type_parameters);
            }
        },
        .FUNCTION_DEFS => {
            if (m.function_defs.len == 0) return false;
            for (m.function_defs) |*fd| try functionDef(w, m, version, fd);
        },
        .FIELD_HANDLE => {
            if (m.field_handles.len == 0) return false;
            for (m.field_handles) |h| {
                try w.idx(h.owner);
                try w.ulebMax(h.field, ff.FIELD_OFFSET_MAX);
            }
        },
        .FIELD_INST => {
            if (m.field_instantiations.len == 0) return false;
            for (m.field_instantiations) |x| {
                try w.idx(x.handle);
                try w.idx(x.type_parameters);
            }
        },
        .FRIEND_DECLS => {
            if (m.friend_decls.len == 0) return false;
            for (m.friend_decls) |h| {
                try w.idx(h.address);
                try w.idx(h.name);
            }
        },
        .ENUM_DEFS => {
            if (m.enum_defs.len == 0) return false;
            if (version < ff.VERSION_7) return error.Unserializable;
            for (m.enum_defs) |ed| {
                try w.idx(ed.enum_handle);
                try w.push(0x2);
                try w.ulebMax(ed.variants.len, ff.VARIANT_COUNT_MAX);
                for (ed.variants) |v| {
                    try w.idx(v.variant_name);
                    try fieldDefs(w, v.fields);
                }
            }
        },
        .ENUM_DEF_INST => {
            if (m.enum_def_instantiations.len == 0) return false;
            if (version < ff.VERSION_7) return error.Unserializable;
            for (m.enum_def_instantiations) |x| {
                try w.idx(x.def);
                try w.idx(x.type_parameters);
            }
        },
        .VARIANT_HANDLES => {
            if (m.variant_handles.len == 0) return false;
            if (version < ff.VERSION_7) return error.Unserializable;
            for (m.variant_handles) |h| {
                try w.idx(h.enum_def);
                try w.ulebMax(h.variant, ff.VARIANT_TAG_MAX_VALUE);
            }
        },
        .VARIANT_INST_HANDLES => {
            if (m.variant_instantiation_handles.len == 0) return false;
            if (version < ff.VERSION_7) return error.Unserializable;
            for (m.variant_instantiation_handles) |h| {
                try w.idx(h.enum_def);
                try w.ulebMax(h.variant, ff.VARIANT_TAG_MAX_VALUE);
            }
        },
        _ => unreachable,
    }
    return true;
}

fn abilitySet(w: W, a: ff.AbilitySet) Error!void {
    try w.ulebMax(a.bits, 0xF);
}

fn fieldDefs(w: W, fields: []const ff.FieldDefinition) Error!void {
    try w.ulebMax(fields.len, ff.FIELD_COUNT_MAX);
    for (fields) |f| {
        try w.idx(f.name);
        try token(w, f.signature);
    }
}

fn token(w: W, tok: ff.Token) Error!void {
    if (ff.maxDepth(tok) > ff.SIGNATURE_TOKEN_DEPTH_MAX) return error.Unserializable;
    for (tok) |n| switch (n.tag) {
        .Bool => try w.push(0x1),
        .U8 => try w.push(0x2),
        .U64 => try w.push(0x3),
        .U128 => try w.push(0x4),
        .Address => try w.push(0x5),
        .Reference => try w.push(0x6),
        .MutableReference => try w.push(0x7),
        .Datatype => {
            try w.push(0x8);
            try w.idx(n.idx);
        },
        .TypeParameter => {
            try w.push(0x9);
            try w.ulebMax(n.idx, ff.TYPE_PARAMETER_INDEX_MAX);
        },
        .Vector => try w.push(0xA),
        .DatatypeInstantiation => {
            try w.push(0xB);
            try w.idx(n.idx);
            try w.ulebMax(n.arity, ff.SIGNATURE_SIZE_MAX);
        },
        .Signer => try w.push(0xC),
        .U16 => try w.push(0xD),
        .U32 => try w.push(0xE),
        .U256 => try w.push(0xF),
    };
}

fn functionDef(w: W, m: *const ff.CompiledModule, version: u32, fd: *const ff.FunctionDefinition) Error!void {
    try w.idx(fd.function);
    var flags: u8 = 0;
    if (version < ff.VERSION_5) {
        const vis: u8 = if (fd.visibility == .Public and fd.is_entry) ff.Visibility.DEPRECATED_SCRIPT else @intFromEnum(fd.visibility);
        try w.push(vis);
    } else {
        try w.push(@intFromEnum(fd.visibility));
        if (fd.is_entry) flags |= ff.FunctionDefinition.ENTRY;
    }
    if (fd.code == null) flags |= ff.FunctionDefinition.NATIVE;
    try w.push(flags);
    try w.ulebMax(fd.acquires.len, ff.ACQUIRES_COUNT_MAX);
    for (fd.acquires) |a| try w.idx(a);
    const cu = fd.code orelse return;
    try w.idx(cu.locals);
    try w.ulebMax(cu.code.len, ff.BYTECODE_COUNT_MAX);
    for (cu.code) |ins| try instr(w, m, version, ins);
    if (version < ff.VERSION_7) {
        if (cu.jump_tables.len != 0) return error.Unserializable;
    } else {
        try w.ulebMax(@as(u8, @truncate(cu.jump_tables.len)), ff.JUMP_TABLE_INDEX_MAX);
        for (cu.jump_tables) |jt| {
            try w.idx(jt.head_enum);
            try w.ulebMax(jt.offsets.len, ff.VARIANT_COUNT_MAX);
            try w.push(0x1);
            for (jt.offsets) |o| try w.ulebMax(o, ff.BYTECODE_INDEX_MAX);
        }
    }
}

fn instr(w: W, m: *const ff.CompiledModule, version: u32, ins: ff.Instr) Error!void {
    switch (ins.op) {
        .LdU16, .LdU32, .LdU256, .CastU16, .CastU32, .CastU256 => if (version < ff.VERSION_6) return error.Unserializable,
        .PackVariant, .PackVariantGeneric, .UnpackVariant, .UnpackVariantImmRef, .UnpackVariantMutRef, .UnpackVariantGeneric, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef, .VariantSwitch => if (version < ff.VERSION_7) return error.Unserializable,
        else => {},
    }
    try w.push(@intFromEnum(ins.op));
    var le: [8]u8 = undefined;
    switch (ins.op) {
        .BrTrue, .BrFalse, .Branch => try w.ulebMax(ins.idx, ff.BYTECODE_INDEX_MAX),
        .LdU8 => try w.push(@intCast(ins.imm)),
        .LdU16 => {
            std.mem.writeInt(u16, le[0..2], @intCast(ins.imm), .little);
            try w.bytes(le[0..2]);
        },
        .LdU32 => {
            std.mem.writeInt(u32, le[0..4], @intCast(ins.imm), .little);
            try w.bytes(le[0..4]);
        },
        .LdU64 => {
            std.mem.writeInt(u64, &le, ins.imm, .little);
            try w.bytes(&le);
        },
        .LdU128 => try w.bytes(m.wide[ins.imm][0..16]),
        .LdU256 => try w.bytes(&m.wide[ins.imm]),
        .CopyLoc, .MoveLoc, .StLoc, .MutBorrowLoc, .ImmBorrowLoc => try w.ulebMax(ins.idx, ff.LOCAL_INDEX_MAX),
        .VecPack, .VecUnpack => {
            try w.idx(ins.idx);
            std.mem.writeInt(u64, &le, ins.imm, .little);
            try w.bytes(&le);
        },
        .PackVariant, .UnpackVariant, .UnpackVariantImmRef, .UnpackVariantMutRef => try w.ulebMax(ins.idx, ff.VARIANT_HANDLE_INDEX_MAX),
        .PackVariantGeneric, .UnpackVariantGeneric, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => try w.ulebMax(ins.idx, ff.VARIANT_INSTANTIATION_HANDLE_INDEX_MAX),
        .VariantSwitch => try w.ulebMax(ins.idx, ff.JUMP_TABLE_INDEX_MAX),
        .Pop, .Ret, .CastU8, .CastU64, .CastU128, .LdTrue, .LdFalse, .ReadRef, .WriteRef, .Add, .Sub, .Mul, .Mod, .Div, .BitOr, .BitAnd, .Xor, .Shl, .Shr, .Or, .And, .Not, .Eq, .Neq, .Lt, .Gt, .Le, .Ge, .Abort, .Nop, .FreezeRef, .CastU16, .CastU32, .CastU256 => {},
        else => try w.idx(ins.idx),
    }
}
