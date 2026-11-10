//! Per-function passes run by code_unit_verifier before reference safety: StackUsageVerifier,
//! type_safety, locals_safety, jump_table_usage_verifier, AcquiresVerifier (1.83.1).
const std = @import("std");
const ff = @import("../file_format.zig");
const c = @import("common.zig");
const cfgm = @import("cfg.zig");

const Ctx = c.Ctx;
const E = c.E;
const Token = c.Token;
const Node = c.Node;
const AbilitySet = c.AbilitySet;
const PartialVmError = ff.PartialVmError;
const CompiledModule = ff.CompiledModule;
const Instr = ff.Instr;
const Allocator = std.mem.Allocator;
const Cfg = cfgm.Cfg;

/// What every per-function pass sees (`FunctionContext`).
pub const Fn = struct {
    m: *const CompiledModule,
    fidx: u16,
    code: *const ff.CodeUnit,
    params: []const Token,
    ret: []const Token,
    locals: []const Token,
    tparams: []const AbilitySet,
    g: *const Cfg,

    pub fn localAt(f: *const Fn, i: u16) Token {
        return if (i < f.params.len) f.params[i] else f.locals[i - f.params.len];
    }
    pub fn numLocals(f: *const Fn) usize {
        return f.params.len + f.locals.len;
    }
    pub fn err(f: *const Fn, ctx: *Ctx, s: c.StatusCode, off: u16) error{Vm} {
        return ctx.fail(PartialVmError.new(s).atCodeOffset(f.fidx, off));
    }
};

// =============================================================================================
// StackUsageVerifier

fn instructionEffect(f: *const Fn, ins: Instr) [2]u64 {
    const m = f.m;
    return switch (ins.op) {
        .Pop, .BrTrue, .BrFalse, .StLoc, .Abort, .VariantSwitch => .{ 1, 0 },
        .LdU8, .LdU16, .LdU32, .LdU64, .LdU128, .LdU256, .LdTrue, .LdFalse, .LdConst, .CopyLoc, .MoveLoc, .MutBorrowLoc, .ImmBorrowLoc => .{ 0, 1 },
        .Not, .FreezeRef, .ReadRef, .ExistsDeprecated, .ExistsGenericDeprecated, .MutBorrowGlobalDeprecated, .MutBorrowGlobalGenericDeprecated, .ImmBorrowGlobalDeprecated, .ImmBorrowGlobalGenericDeprecated, .MutBorrowField, .MutBorrowFieldGeneric, .ImmBorrowField, .ImmBorrowFieldGeneric, .MoveFromDeprecated, .MoveFromGenericDeprecated, .CastU8, .CastU16, .CastU32, .CastU64, .CastU128, .CastU256, .VecLen, .VecPopBack => .{ 1, 1 },
        .Add, .Sub, .Mul, .Mod, .Div, .BitOr, .BitAnd, .Xor, .Shl, .Shr, .Or, .And, .Eq, .Neq, .Lt, .Gt, .Le, .Ge => .{ 2, 1 },
        .VecPack => .{ ins.imm, 1 },
        .VecUnpack => .{ 1, ins.imm },
        .VecImmBorrow, .VecMutBorrow => .{ 2, 1 },
        .MoveToDeprecated, .MoveToGenericDeprecated, .WriteRef, .VecPushBack => .{ 2, 0 },
        .VecSwap => .{ 3, 0 },
        .Branch, .Nop => .{ 0, 0 },
        .Ret => .{ f.ret.len, 0 },
        .Call => blk: {
            const fh = m.function_handles[ins.idx];
            break :blk .{ m.signatures[fh.parameters].len, m.signatures[fh.return_].len };
        },
        .CallGeneric => blk: {
            const fh = m.function_handles[m.function_instantiations[ins.idx].handle];
            break :blk .{ m.signatures[fh.parameters].len, m.signatures[fh.return_].len };
        },
        .Pack => .{ m.struct_defs[ins.idx].fields.len, 1 },
        .PackGeneric => .{ m.struct_defs[m.struct_def_instantiations[ins.idx].def].fields.len, 1 },
        .Unpack => .{ 1, m.struct_defs[ins.idx].fields.len },
        .UnpackGeneric => .{ 1, m.struct_defs[m.struct_def_instantiations[ins.idx].def].fields.len },
        .PackVariant => blk: {
            const h = m.variant_handles[ins.idx];
            break :blk .{ m.enum_defs[h.enum_def].variants[h.variant].fields.len, 1 };
        },
        .PackVariantGeneric => blk: {
            const h = m.variant_instantiation_handles[ins.idx];
            break :blk .{ m.enum_defs[m.enum_def_instantiations[h.enum_def].def].variants[h.variant].fields.len, 1 };
        },
        .UnpackVariant, .UnpackVariantImmRef, .UnpackVariantMutRef => blk: {
            const h = m.variant_handles[ins.idx];
            break :blk .{ 1, m.enum_defs[h.enum_def].variants[h.variant].fields.len };
        },
        .UnpackVariantGeneric, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => blk: {
            const h = m.variant_instantiation_handles[ins.idx];
            break :blk .{ 1, m.enum_defs[m.enum_def_instantiations[h.enum_def].def].variants[h.variant].fields.len };
        },
        else => .{ 0, 0 },
    };
}

pub fn stackUsage(ctx: *Ctx, cfg: *const c.Config, f: *const Fn) E!void {
    const g = f.g;
    const code = f.code.code;
    for (0..g.numBlocks()) |b| {
        const start = g.starts[b];
        var incr: u64 = 0;
        var overall: u64 = 0;
        var pc: usize = start;
        while (pc <= g.ends[b]) : (pc += 1) {
            const pops, const pushes = instructionEffect(f, code[pc]);
            if (std.math.add(u64, overall, pushes)) |v| overall = v else |_| {}
            if (cfg.max_push_size) |mx| if (overall > mx) return f.err(ctx, .VALUE_STACK_PUSH_OVERFLOW, start);
            if (incr < pops) return f.err(ctx, .NEGATIVE_STACK_SIZE_WITHIN_BLOCK, start);
            incr -= pops;
            incr = std.math.add(u64, incr, pushes) catch return f.err(ctx, .POSITIVE_STACK_SIZE_AT_BLOCK_END, start);
            if (incr > cfg.max_value_stack_size) return f.err(ctx, .VALUE_STACK_OVERFLOW, start);
        }
        if (incr != 0) return f.err(ctx, .POSITIVE_STACK_SIZE_AT_BLOCK_END, start);
    }
}

// =============================================================================================
// type_safety

const TYPE_NODE_COST: u128 = 6;
const TYPE_NODE_QUADRATIC_THRESHOLD: usize = 10;
const TYPE_PUSH_COST: u128 = 3;

/// `move_abstract_stack::AbstractStack` (run-length encoded).
pub fn AbstractStack(comptime T: type, comptime eql: fn (T, T) bool) type {
    return struct {
        const Self = @This();
        pub const Error = error{ ElementNotEqual, Underflow, Overflow };
        values: std.ArrayList(struct { n: u64, v: T }) = .empty,
        len: u64 = 0,

        pub fn pushN(s: *Self, a: Allocator, item: T, n: u64) (Error || Allocator.Error)!void {
            if (n == 0) return;
            s.len = std.math.add(u64, s.len, n) catch return error.Overflow;
            if (s.values.items.len > 0) {
                const last = &s.values.items[s.values.items.len - 1];
                if (eql(item, last.v)) {
                    last.n += n;
                    return;
                }
            }
            try s.values.append(a, .{ .n = n, .v = item });
        }
        pub fn popEqN(s: *Self, n: u64) Error!T {
            if (s.values.items.len == 0 or n > s.len) return error.Underflow;
            const last = &s.values.items[s.values.items.len - 1];
            const r = last.v;
            if (last.n < n) return error.ElementNotEqual;
            if (last.n == n) _ = s.values.pop() else last.n -= n;
            s.len -= n;
            return r;
        }
        pub fn pop(s: *Self) Error!T {
            return s.popEqN(1);
        }
    };
}

const TokStack = AbstractStack(Token, ff.tokenEql);

const TypeSafety = struct {
    ctx: *Ctx,
    cfg: *const c.Config,
    f: *const Fn,
    cache: *c.AbilityCache,
    meter: *c.Meter,
    arena: Allocator,
    tb: c.TokBuf,
    stack: TokStack = .{},

    fn err(t: *TypeSafety, s: c.StatusCode, off: u16) error{Vm} {
        return t.f.err(t.ctx, s, off);
    }
    fn pop(t: *TypeSafety) E!Token {
        return t.stack.pop() catch t.ctx.invariant();
    }
    fn push(t: *TypeSafety, ty: Token) E!void {
        try t.meter.add(t.ctx, .Function, TYPE_PUSH_COST);
        t.stack.pushN(t.arena, ty, 1) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else t.ctx.invariant();
    }
    fn pushN(t: *TypeSafety, ty: Token, n: u64) E!void {
        try t.meter.addItems(t.ctx, .Function, TYPE_PUSH_COST, @intCast(n));
        t.stack.pushN(t.arena, ty, n) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else t.ctx.invariant();
    }
    fn chargeTy(t: *TypeSafety, ty: Token) E!void {
        const size = ty.len;
        try t.meter.addItems(t.ctx, .Function, TYPE_NODE_COST, @max(size, (size *| size) / TYPE_NODE_QUADRATIC_THRESHOLD));
    }
    fn abilities(t: *TypeSafety, ty: Token) E!AbilitySet {
        return t.cache.abilities(t.ctx, .Function, t.meter, t.f.tparams, ty);
    }
    fn materialize(t: *TypeSafety, handle: u16, targs: []const Token) E!Token {
        const ty = try t.tb.datatype(handle, targs);
        try t.chargeTy(ty);
        return ty;
    }
    fn instantiate(t: *TypeSafety, ty: Token, subst: []const Token) E!Token {
        const r = try t.tb.instantiate(ty, subst);
        try t.chargeTy(r);
        return r;
    }
    fn wrap(t: *TypeSafety, tag: ff.Tag, inner: Token) E!Token {
        return t.tb.wrap(tag, inner);
    }
    fn sig(t: *TypeSafety, idx: u16) []const Token {
        return t.f.m.signatures[idx];
    }

    fn borrowField(t: *TypeSafety, off: u16, mut: bool, fh_idx: u16, targs: []const Token) E!void {
        const m = t.f.m;
        const operand = try t.pop();
        if (mut and operand[0].tag != .MutableReference) return t.err(.BORROWFIELD_TYPE_MISMATCH_ERROR, off);
        const fh = m.field_handles[fh_idx];
        const sd = &m.struct_defs[fh.owner];
        const expected = try t.materialize(sd.struct_handle, targs);
        if (!(ff.isReference(operand) and ff.tokenEql(expected, operand[1..]))) return t.err(.BORROWFIELD_TYPE_MISMATCH_ERROR, off);
        if (sd.native) return t.err(.BORROWFIELD_BAD_FIELD_ERROR, off);
        const ft = try t.instantiate(sd.fields[fh.field].signature, targs);
        try t.push(try t.wrap(if (mut) .MutableReference else .Reference, ft));
    }

    fn borrowLoc(t: *TypeSafety, off: u16, mut: bool, idx: u16) E!void {
        const ls = t.f.localAt(idx);
        try t.chargeTy(ls);
        if (ff.isReference(ls)) return t.err(.BORROWLOC_REFERENCE_ERROR, off);
        try t.push(try t.wrap(if (mut) .MutableReference else .Reference, ls));
    }

    fn borrowGlobal(t: *TypeSafety, off: u16, mut: bool, sd_idx: u16, targs: []const Token) E!void {
        const operand = try t.pop();
        if (operand[0].tag != .Address) return t.err(.BORROWGLOBAL_TYPE_MISMATCH_ERROR, off);
        const st = try t.materialize(t.f.m.struct_defs[sd_idx].struct_handle, targs);
        if (!(try t.abilities(st)).hasKey()) return t.err(.BORROWGLOBAL_WITHOUT_KEY_ABILITY, off);
        try t.push(try t.wrap(if (mut) .MutableReference else .Reference, st));
    }

    fn call(t: *TypeSafety, off: u16, fh: *const ff.FunctionHandle, targs: []const Token) E!void {
        const params = t.sig(fh.parameters);
        var i = params.len;
        while (i > 0) {
            i -= 1;
            const arg = try t.pop();
            const expected = if (targs.len == 0) params[i] else try t.instantiate(params[i], targs);
            if (!ff.tokenEql(arg, expected)) return t.err(.CALL_TYPE_MISMATCH_ERROR, off);
        }
        for (t.sig(fh.return_)) |rt| try t.push(try t.instantiate(rt, targs));
    }

    fn fieldSigs(t: *TypeSafety, off: u16, sd: *const ff.StructDefinition, targs: []const Token) E![]Token {
        if (sd.native) return t.err(.PACK_TYPE_MISMATCH_ERROR, off);
        const out = try t.arena.alloc(Token, sd.fields.len);
        for (sd.fields, out) |fd, *o| o.* = try t.instantiate(fd.signature, targs);
        return out;
    }

    fn packStruct(t: *TypeSafety, off: u16, sd: *const ff.StructDefinition, targs: []const Token) E!void {
        const fs = try t.fieldSigs(off, sd, targs);
        var i = fs.len;
        while (i > 0) {
            i -= 1;
            const arg = try t.pop();
            if (!ff.tokenEql(arg, fs[i])) return t.err(.PACK_TYPE_MISMATCH_ERROR, off);
        }
        try t.push(try t.materialize(sd.struct_handle, targs));
    }

    fn unpackStruct(t: *TypeSafety, off: u16, sd: *const ff.StructDefinition, targs: []const Token) E!void {
        const st = try t.materialize(sd.struct_handle, targs);
        const arg = try t.pop();
        if (!ff.tokenEql(arg, st)) return t.err(.UNPACK_TYPE_MISMATCH_ERROR, off);
        const fs = try t.fieldSigs(off, sd, targs);
        for (fs) |s| try t.push(s);
    }

    fn packVariant(t: *TypeSafety, off: u16, ed: *const ff.EnumDefinition, v: *const ff.VariantDefinition, targs: []const Token) E!void {
        var i = v.fields.len;
        while (i > 0) {
            i -= 1;
            const s = try t.instantiate(v.fields[i].signature, targs);
            const arg = try t.pop();
            if (!ff.tokenEql(arg, s)) return t.err(.PACK_TYPE_MISMATCH_ERROR, off);
        }
        try t.push(try t.materialize(ed.enum_handle, targs));
    }

    fn unpackVariant(t: *TypeSafety, off: u16, ed: *const ff.EnumDefinition, v: *const ff.VariantDefinition, targs: []const Token) E!void {
        const et = try t.materialize(ed.enum_handle, targs);
        const arg = try t.pop();
        if (!ff.tokenEql(arg, et)) return t.err(.UNPACK_TYPE_MISMATCH_ERROR, off);
        for (v.fields) |fd| try t.push(try t.instantiate(fd.signature, targs));
    }

    fn unpackVariantRef(t: *TypeSafety, off: u16, mut: bool, ed: *const ff.EnumDefinition, v: *const ff.VariantDefinition, targs: []const Token) E!void {
        const arg = try t.pop();
        const want: ff.Tag = if (mut) .MutableReference else .Reference;
        if (arg[0].tag != want) return t.err(.UNPACK_TYPE_MISMATCH_ERROR, off);
        const et = try t.materialize(ed.enum_handle, targs);
        if (!ff.tokenEql(arg[1..], et)) return t.err(.UNPACK_TYPE_MISMATCH_ERROR, off);
        for (v.fields) |fd| try t.push(try t.wrap(want, try t.instantiate(fd.signature, targs)));
    }

    fn exists(t: *TypeSafety, off: u16, sd: *const ff.StructDefinition, targs: []const Token) E!void {
        const st = try t.materialize(sd.struct_handle, targs);
        if (!(try t.abilities(st)).hasKey()) return t.err(.EXISTS_WITHOUT_KEY_ABILITY_OR_BAD_ARGUMENT, off);
        const operand = try t.pop();
        if (operand[0].tag != .Address) return t.err(.EXISTS_WITHOUT_KEY_ABILITY_OR_BAD_ARGUMENT, off);
        try t.push(&BOOL);
    }

    fn moveFrom(t: *TypeSafety, off: u16, sd: *const ff.StructDefinition, targs: []const Token) E!void {
        const st = try t.materialize(sd.struct_handle, targs);
        if (!(try t.abilities(st)).hasKey()) return t.err(.MOVEFROM_WITHOUT_KEY_ABILITY, off);
        const operand = try t.pop();
        if (operand[0].tag != .Address) return t.err(.MOVEFROM_TYPE_MISMATCH_ERROR, off);
        try t.push(st);
    }

    fn moveTo(t: *TypeSafety, off: u16, sd: *const ff.StructDefinition, targs: []const Token) E!void {
        const st = try t.materialize(sd.struct_handle, targs);
        if (!(try t.abilities(st)).hasKey()) return t.err(.MOVETO_WITHOUT_KEY_ABILITY, off);
        const key_op = try t.pop();
        const signer_ref = try t.pop();
        if (!ff.tokenEql(key_op, st)) return t.err(.MOVETO_TYPE_MISMATCH_ERROR, off);
        if (!(signer_ref[0].tag == .Reference and signer_ref[1].tag == .Signer)) return t.err(.MOVETO_TYPE_MISMATCH_ERROR, off);
    }

    /// `get_vector_element_type`.
    fn vecElem(ty: Token, mut_only: bool) ?Token {
        switch (ty[0].tag) {
            .Reference => {
                if (mut_only) return null;
                return if (ty[1].tag == .Vector) ty[2..] else null;
            },
            .MutableReference => return if (ty[1].tag == .Vector) ty[2..] else null,
            else => return null,
        }
    }

    fn borrowVecElem(t: *TypeSafety, declared: Token, off: u16, mut: bool) E!void {
        const idx = try t.pop();
        const vec = try t.pop();
        if (idx[0].tag != .U64) return t.err(.TYPE_MISMATCH, off);
        const et = vecElem(vec, mut) orelse return t.err(.TYPE_MISMATCH, off);
        if (!ff.tokenEql(et, declared)) return t.err(.TYPE_MISMATCH, off);
        try t.push(try t.wrap(if (mut) .MutableReference else .Reference, et));
    }

    fn structInst(t: *TypeSafety, idx: u16) struct { *const ff.StructDefinition, []const Token } {
        const si = t.f.m.struct_def_instantiations[idx];
        return .{ &t.f.m.struct_defs[si.def], t.sig(si.type_parameters) };
    }

    fn global(t: *TypeSafety) E!void {
        if (t.cfg.deprecate_global_storage_ops) return t.ctx.invariant();
    }

    fn intOp1(t: *TypeSafety, off: u16, result: *const [1]Node) E!void {
        const operand = try t.pop();
        if (!ff.isInteger(operand)) return t.err(.INTEGER_OP_TYPE_MISMATCH_ERROR, off);
        try t.push(result);
    }

    fn instr(t: *TypeSafety, ins: Instr, off: u16) E!void {
        const m = t.f.m;
        switch (ins.op) {
            .Pop => {
                const operand = try t.pop();
                if (!(try t.abilities(operand)).hasDrop()) return t.err(.POP_WITHOUT_DROP_ABILITY, off);
            },
            .BrTrue, .BrFalse => {
                const operand = try t.pop();
                if (operand[0].tag != .Bool) return t.err(.BR_TYPE_MISMATCH_ERROR, off);
            },
            .StLoc => {
                const operand = try t.pop();
                if (!ff.tokenEql(operand, t.f.localAt(ins.idx))) return t.err(.STLOC_TYPE_MISMATCH_ERROR, off);
            },
            .Abort => {
                const operand = try t.pop();
                if (operand[0].tag != .U64) return t.err(.ABORT_TYPE_MISMATCH_ERROR, off);
            },
            .Ret => {
                var i = t.f.ret.len;
                while (i > 0) {
                    i -= 1;
                    const operand = try t.pop();
                    if (!ff.tokenEql(operand, t.f.ret[i])) return t.err(.RET_TYPE_MISMATCH_ERROR, off);
                }
            },
            .Branch, .Nop => {},
            .FreezeRef => {
                const operand = try t.pop();
                if (operand[0].tag != .MutableReference) return t.err(.FREEZEREF_TYPE_MISMATCH_ERROR, off);
                try t.push(try t.wrap(.Reference, operand[1..]));
            },
            .MutBorrowField => try t.borrowField(off, true, ins.idx, &.{}),
            .ImmBorrowField => try t.borrowField(off, false, ins.idx, &.{}),
            .MutBorrowFieldGeneric, .ImmBorrowFieldGeneric => {
                const fi = m.field_instantiations[ins.idx];
                try t.borrowField(off, ins.op == .MutBorrowFieldGeneric, fi.handle, t.sig(fi.type_parameters));
            },
            .LdU8 => try t.push(&U8),
            .LdU16 => try t.push(&U16),
            .LdU32 => try t.push(&U32),
            .LdU64 => try t.push(&U64),
            .LdU128 => try t.push(&U128),
            .LdU256 => try t.push(&U256),
            .LdConst => {
                const ty = m.constant_pool[ins.idx].type_;
                try t.chargeTy(ty);
                try t.push(ty);
            },
            .LdTrue, .LdFalse => try t.push(&BOOL),
            .CopyLoc => {
                const ls = t.f.localAt(ins.idx);
                try t.chargeTy(ls);
                if (!(try t.abilities(ls)).hasCopy()) return t.err(.COPYLOC_WITHOUT_COPY_ABILITY, off);
                try t.push(ls);
            },
            .MoveLoc => {
                const ls = t.f.localAt(ins.idx);
                try t.chargeTy(ls);
                try t.push(ls);
            },
            .MutBorrowLoc => try t.borrowLoc(off, true, ins.idx),
            .ImmBorrowLoc => try t.borrowLoc(off, false, ins.idx),
            .Call => try t.call(off, &m.function_handles[ins.idx], &.{}),
            .CallGeneric => {
                const fi = m.function_instantiations[ins.idx];
                try t.call(off, &m.function_handles[fi.handle], t.sig(fi.type_parameters));
            },
            .Pack => try t.packStruct(off, &m.struct_defs[ins.idx], &.{}),
            .PackGeneric => {
                const sd, const targs = t.structInst(ins.idx);
                try t.packStruct(off, sd, targs);
            },
            .Unpack => try t.unpackStruct(off, &m.struct_defs[ins.idx], &.{}),
            .UnpackGeneric => {
                const sd, const targs = t.structInst(ins.idx);
                try t.unpackStruct(off, sd, targs);
            },
            .ReadRef => {
                const operand = try t.pop();
                if (!ff.isReference(operand)) return t.err(.READREF_TYPE_MISMATCH_ERROR, off);
                if (!(try t.abilities(operand[1..])).hasCopy()) return t.err(.READREF_WITHOUT_COPY_ABILITY, off);
                try t.push(operand[1..]);
            },
            .WriteRef => {
                const ref = try t.pop();
                const val = try t.pop();
                if (ref[0].tag != .MutableReference) return t.err(.WRITEREF_NO_MUTABLE_REFERENCE_ERROR, off);
                const inner = ref[1..];
                if (!(try t.abilities(inner)).hasDrop()) return t.err(.WRITEREF_WITHOUT_DROP_ABILITY, off);
                if (!ff.tokenEql(val, inner)) return t.err(.WRITEREF_TYPE_MISMATCH_ERROR, off);
            },
            .CastU8 => try t.intOp1(off, &U8),
            .CastU16 => try t.intOp1(off, &U16),
            .CastU32 => try t.intOp1(off, &U32),
            .CastU64 => try t.intOp1(off, &U64),
            .CastU128 => try t.intOp1(off, &U128),
            .CastU256 => try t.intOp1(off, &U256),
            .Add, .Sub, .Mul, .Mod, .Div, .BitOr, .BitAnd, .Xor => {
                const a = try t.pop();
                const b = try t.pop();
                if (!(ff.isInteger(a) and ff.tokenEql(a, b))) return t.err(.INTEGER_OP_TYPE_MISMATCH_ERROR, off);
                try t.push(a);
            },
            .Shl, .Shr => {
                const a = try t.pop();
                const b = try t.pop();
                if (!(ff.isInteger(b) and a[0].tag == .U8)) return t.err(.INTEGER_OP_TYPE_MISMATCH_ERROR, off);
                try t.push(b);
            },
            .Or, .And => {
                const a = try t.pop();
                const b = try t.pop();
                if (!(a[0].tag == .Bool and b[0].tag == .Bool)) return t.err(.BOOLEAN_OP_TYPE_MISMATCH_ERROR, off);
                try t.push(&BOOL);
            },
            .Not => {
                const a = try t.pop();
                if (a[0].tag != .Bool) return t.err(.BOOLEAN_OP_TYPE_MISMATCH_ERROR, off);
                try t.push(&BOOL);
            },
            .Eq, .Neq => {
                const a = try t.pop();
                const b = try t.pop();
                if (!((try t.abilities(a)).hasDrop() and ff.tokenEql(a, b))) return t.err(.EQUALITY_OP_TYPE_MISMATCH_ERROR, off);
                try t.push(&BOOL);
            },
            .Lt, .Gt, .Le, .Ge => {
                const a = try t.pop();
                const b = try t.pop();
                if (!(ff.isInteger(a) and ff.tokenEql(a, b))) return t.err(.INTEGER_OP_TYPE_MISMATCH_ERROR, off);
                try t.push(&BOOL);
            },
            .MutBorrowGlobalDeprecated, .ImmBorrowGlobalDeprecated => {
                try t.global();
                try t.borrowGlobal(off, ins.op == .MutBorrowGlobalDeprecated, ins.idx, &.{});
            },
            .MutBorrowGlobalGenericDeprecated, .ImmBorrowGlobalGenericDeprecated => {
                try t.global();
                const si = m.struct_def_instantiations[ins.idx];
                try t.borrowGlobal(off, ins.op == .MutBorrowGlobalGenericDeprecated, si.def, t.sig(si.type_parameters));
            },
            .ExistsDeprecated => {
                try t.global();
                try t.exists(off, &m.struct_defs[ins.idx], &.{});
            },
            .ExistsGenericDeprecated => {
                try t.global();
                const sd, const targs = t.structInst(ins.idx);
                try t.exists(off, sd, targs);
            },
            .MoveFromDeprecated => {
                try t.global();
                try t.moveFrom(off, &m.struct_defs[ins.idx], &.{});
            },
            .MoveFromGenericDeprecated => {
                try t.global();
                const sd, const targs = t.structInst(ins.idx);
                try t.moveFrom(off, sd, targs);
            },
            .MoveToDeprecated => {
                try t.global();
                try t.moveTo(off, &m.struct_defs[ins.idx], &.{});
            },
            .MoveToGenericDeprecated => {
                try t.global();
                const sd, const targs = t.structInst(ins.idx);
                try t.moveTo(off, sd, targs);
            },
            .VecPack => {
                const et = t.sig(ins.idx)[0];
                if (ins.imm != 0) {
                    const mismatched = if (t.stack.popEqN(ins.imm)) |x| !ff.tokenEql(et, x) else |_| true;
                    if (mismatched) return t.err(.TYPE_MISMATCH, off);
                }
                try t.chargeTy(et);
                try t.push(try t.wrap(.Vector, et));
            },
            .VecLen => {
                const operand = try t.pop();
                const declared = t.sig(ins.idx)[0];
                const et = vecElem(operand, false) orelse return t.err(.TYPE_MISMATCH, off);
                if (!ff.tokenEql(et, declared)) return t.err(.TYPE_MISMATCH, off);
                try t.push(&U64);
            },
            .VecImmBorrow => try t.borrowVecElem(t.sig(ins.idx)[0], off, false),
            .VecMutBorrow => try t.borrowVecElem(t.sig(ins.idx)[0], off, true),
            .VecPushBack => {
                const elem = try t.pop();
                const vec = try t.pop();
                const declared = t.sig(ins.idx)[0];
                if (!ff.tokenEql(declared, elem)) return t.err(.TYPE_MISMATCH, off);
                const et = vecElem(vec, true) orelse return t.err(.TYPE_MISMATCH, off);
                if (!ff.tokenEql(et, declared)) return t.err(.TYPE_MISMATCH, off);
            },
            .VecPopBack => {
                const vec = try t.pop();
                const declared = t.sig(ins.idx)[0];
                const et = vecElem(vec, true) orelse return t.err(.TYPE_MISMATCH, off);
                if (!ff.tokenEql(et, declared)) return t.err(.TYPE_MISMATCH, off);
                try t.push(et);
            },
            .VecUnpack => {
                const vec = try t.pop();
                const declared = t.sig(ins.idx)[0];
                if (!(vec[0].tag == .Vector and ff.tokenEql(vec[1..], declared))) return t.err(.TYPE_MISMATCH, off);
                try t.chargeTy(declared);
                try t.pushN(declared, ins.imm);
            },
            .VecSwap => {
                const idx2 = try t.pop();
                const idx1 = try t.pop();
                const vec = try t.pop();
                if (idx1[0].tag != .U64 or idx2[0].tag != .U64) return t.err(.TYPE_MISMATCH, off);
                const declared = t.sig(ins.idx)[0];
                const et = vecElem(vec, true) orelse return t.err(.TYPE_MISMATCH, off);
                if (!ff.tokenEql(et, declared)) return t.err(.TYPE_MISMATCH, off);
            },
            .PackVariant, .UnpackVariant, .UnpackVariantImmRef, .UnpackVariantMutRef => {
                const h = m.variant_handles[ins.idx];
                const ed = &m.enum_defs[h.enum_def];
                const v = &ed.variants[h.variant];
                switch (ins.op) {
                    .PackVariant => try t.packVariant(off, ed, v, &.{}),
                    .UnpackVariant => try t.unpackVariant(off, ed, v, &.{}),
                    else => try t.unpackVariantRef(off, ins.op == .UnpackVariantMutRef, ed, v, &.{}),
                }
            },
            .PackVariantGeneric, .UnpackVariantGeneric, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => {
                const h = m.variant_instantiation_handles[ins.idx];
                const ei = m.enum_def_instantiations[h.enum_def];
                const targs = t.sig(ei.type_parameters);
                const ed = &m.enum_defs[ei.def];
                const v = &ed.variants[h.variant];
                switch (ins.op) {
                    .PackVariantGeneric => try t.packVariant(off, ed, v, targs),
                    .UnpackVariantGeneric => try t.unpackVariant(off, ed, v, targs),
                    else => try t.unpackVariantRef(off, ins.op == .UnpackVariantGenericMutRef, ed, v, targs),
                }
            },
            .VariantSwitch => {
                const jt = t.f.code.jump_tables[ins.idx];
                const operand = try t.pop();
                if (operand[0].tag != .Reference) return t.err(.ENUM_SWITCH_BAD_OPERAND, off);
                const inner = operand[1];
                if (inner.tag != .Datatype and inner.tag != .DatatypeInstantiation) return t.err(.ENUM_TYPE_MISMATCH, off);
                const ed = &m.enum_defs[jt.head_enum];
                if (inner.idx != ed.enum_handle) return t.err(.ENUM_TYPE_MISMATCH, off);
                if (jt.offsets.len != ed.variants.len) return t.err(.INVALID_ENUM_SWITCH, off);
            },
            else => return t.ctx.invariant(),
        }
    }
};

const BOOL = [1]Node{.{ .tag = .Bool }};
const U8 = [1]Node{.{ .tag = .U8 }};
const U16 = [1]Node{.{ .tag = .U16 }};
const U32 = [1]Node{.{ .tag = .U32 }};
const U64 = [1]Node{.{ .tag = .U64 }};
const U128 = [1]Node{.{ .tag = .U128 }};
const U256 = [1]Node{.{ .tag = .U256 }};

pub fn typeSafety(ctx: *Ctx, arena: Allocator, cfg: *const c.Config, f: *const Fn, cache: *c.AbilityCache, meter: *c.Meter) E!void {
    var t: TypeSafety = .{ .ctx = ctx, .cfg = cfg, .f = f, .cache = cache, .meter = meter, .arena = arena, .tb = .{ .arena = arena } };
    const g = f.g;
    for (0..g.numBlocks()) |b| {
        var pc: usize = g.starts[b];
        while (pc <= g.ends[b]) : (pc += 1) try t.instr(f.code.code[pc], @intCast(pc));
    }
}

// =============================================================================================
// locals_safety

const LocalState = enum(u8) { Unavailable, MaybeAvailable, Available };
const STEP_BASE_COST: u128 = 1;
const RET_COST: u128 = 10;
const JOIN_COST: u128 = 10;

const LocalsSafety = struct {
    pub const State = []LocalState;
    ctx: *Ctx,
    meter: *c.Meter,
    arena: Allocator,
    f: *const Fn,
    abilities: []const AbilitySet,

    pub fn clone(a: *LocalsSafety, s: *const State) E!State {
        return a.arena.dupe(LocalState, s.*);
    }
    pub fn join(a: *LocalsSafety, pre: *State, post: *const State) E!bool {
        try a.meter.add(a.ctx, .Function, JOIN_COST);
        var changed = false;
        for (pre.*, post.*) |*x, y| {
            const j: LocalState = if (x.* == .Unavailable and y == .Unavailable) .Unavailable else if (x.* == .Available and y == .Available) .Available else .MaybeAvailable;
            if (j != x.*) changed = true;
        }
        if (changed) for (pre.*, post.*) |*x, y| {
            x.* = if (x.* == .Unavailable and y == .Unavailable) .Unavailable else if (x.* == .Available and y == .Available) .Available else .MaybeAvailable;
        };
        return changed;
    }
    pub fn execute(a: *LocalsSafety, s: *State, ins: Instr, off: u16, _: u16, _: u16) E!void {
        try a.meter.add(a.ctx, .Function, STEP_BASE_COST);
        const st = s.*;
        switch (ins.op) {
            .StLoc => {
                if (st[ins.idx] != .Unavailable and !a.abilities[ins.idx].hasDrop()) return a.f.err(a.ctx, .STLOC_UNSAFE_TO_DESTROY_ERROR, off);
                st[ins.idx] = .Available;
            },
            .MoveLoc => {
                if (st[ins.idx] != .Available) return a.f.err(a.ctx, .MOVELOC_UNAVAILABLE_ERROR, off);
                st[ins.idx] = .Unavailable;
            },
            .CopyLoc => if (st[ins.idx] != .Available) return a.f.err(a.ctx, .COPYLOC_UNAVAILABLE_ERROR, off),
            .MutBorrowLoc, .ImmBorrowLoc => if (st[ins.idx] != .Available) return a.f.err(a.ctx, .BORROWLOC_UNAVAILABLE_ERROR, off),
            .Ret => {
                try a.meter.addItems(a.ctx, .Function, RET_COST, st.len);
                for (st, a.abilities) |ls, ab| if (ls != .Unavailable and !ab.hasDrop()) return a.f.err(a.ctx, .UNSAFE_RET_UNUSED_VALUES_WITHOUT_DROP, off);
            },
            else => {},
        }
    }
};

pub fn localsSafety(ctx: *Ctx, arena: Allocator, f: *const Fn, cache: *c.AbilityCache, meter: *c.Meter) E!void {
    const n = f.numLocals();
    const initial = try arena.alloc(LocalState, n);
    const abilities = try arena.alloc(AbilitySet, n);
    for (0..n) |i| {
        initial[i] = if (i < f.params.len) .Available else .Unavailable;
        abilities[i] = try cache.abilities(ctx, .Function, meter, f.tparams, f.localAt(@intCast(i)));
    }
    var a: LocalsSafety = .{ .ctx = ctx, .meter = meter, .arena = arena, .f = f, .abilities = abilities };
    try cfgm.analyze(LocalsSafety, &a, ctx, meter, arena, f.g, f.code.code, initial);
}

// =============================================================================================
// jump_table_usage_verifier, AcquiresVerifier

pub fn jumpTableUsage(ctx: *Ctx, arena: Allocator, f: *const Fn) E!void {
    const seen = try arena.alloc(bool, f.code.jump_tables.len);
    @memset(seen, false);
    var n: usize = 0;
    for (f.code.code) |ins| if (ins.op == .VariantSwitch and !seen[ins.idx]) {
        seen[ins.idx] = true;
        n += 1;
    };
    if (n != f.code.jump_tables.len) return ctx.status(.INVALID_ENUM_SWITCH);
}

pub fn acquires(ctx: *Ctx, arena: Allocator, cfg: *const c.Config, m: *const CompiledModule, fidx: u16) E!void {
    if (cfg.deprecate_global_storage_ops) return;
    const fd = &m.function_defs[fidx];
    const code = fd.code orelse return ctx.invariant();
    const nsd = m.struct_defs.len;
    const annotated = try arena.alloc(bool, nsd);
    @memset(annotated, false);
    const actual = try arena.alloc(bool, annotated.len);
    @memset(actual, false);
    for (fd.acquires) |a| annotated[a] = true;
    // handle_to_def: last definition per handle wins (HashMap insert)
    const h2d = try arena.alloc(?u16, m.function_handles.len);
    @memset(h2d, null);
    for (m.function_defs, 0..) |d, i| h2d[d.function] = @intCast(i);
    for (code.code, 0..) |ins, off_| {
        const off: u16 = @intCast(off_);
        switch (ins.op) {
            .Call, .CallGeneric => {
                const fh_idx = if (ins.op == .Call) ins.idx else m.function_instantiations[ins.idx].handle;
                if (m.function_handles[fh_idx].module != m.self_module_handle_idx) continue;
                const d = &m.function_defs[h2d[fh_idx] orelse continue];
                for (d.acquires) |r| if (!annotated[r]) return ctx.fail(PartialVmError.new(.MISSING_ACQUIRES_ANNOTATION).atCodeOffset(fidx, off));
                for (d.acquires) |r| actual[r] = true;
            },
            .MoveFromDeprecated, .MutBorrowGlobalDeprecated, .ImmBorrowGlobalDeprecated, .MoveFromGenericDeprecated, .MutBorrowGlobalGenericDeprecated, .ImmBorrowGlobalGenericDeprecated => {
                const sd = switch (ins.op) {
                    .MoveFromDeprecated, .MutBorrowGlobalDeprecated, .ImmBorrowGlobalDeprecated => ins.idx,
                    else => m.struct_def_instantiations[ins.idx].def,
                };
                if (!annotated[sd]) return ctx.fail(PartialVmError.new(.MISSING_ACQUIRES_ANNOTATION).atCodeOffset(fidx, off));
                actual[sd] = true;
            },
            else => {},
        }
    }
    const sorted = try arena.dupe(u16, fd.acquires);
    std.mem.sort(u16, sorted, {}, std.sort.asc(u16));
    for (sorted) |a| {
        if (!actual[a]) return ctx.status(.EXTRANEOUS_ACQUIRES_ANNOTATION);
        if (!m.datatype_handles[m.struct_defs[a].struct_handle].abilities.hasKey()) return ctx.status(.INVALID_ACQUIRES_ANNOTATION);
    }
}
