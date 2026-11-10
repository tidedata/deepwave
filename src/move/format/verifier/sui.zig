//! sui-verifier (sui-execution/latest, 1.83.1): `sui_verify_module_metered` with an empty
//! FnInfoMap (publish path: no test functions).
const std = @import("std");
const ff = @import("../file_format.zig");
const c = @import("common.zig");
const cfgm = @import("cfg.zig");
const cp = @import("code_passes.zig");

const Ctx = c.Ctx;
const Token = c.Token;
const AbilitySet = c.AbilitySet;
const CompiledModule = ff.CompiledModule;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

pub const Kind = enum { SuiMoveVerificationError, InvariantViolation, SuiMoveVerificationTimedout };

pub const SuiError = struct { kind: Kind, msg: []const u8 };

pub const Error = error{ Sui, OutOfMemory, Vm };

const S = struct {
    arena: Allocator,
    m: *const CompiledModule,
    out: ?SuiError = null,

    fn fail(s: *S, kind: Kind, comptime fmt: []const u8, args: anytype) Error {
        s.out = .{ .kind = kind, .msg = try std.fmt.allocPrint(s.arena, fmt, args) };
        return error.Sui;
    }
    fn ident(s: *const S, i: u16) []const u8 {
        return s.m.identifiers[i];
    }
    fn fnName(s: *const S, fd: *const ff.FunctionDefinition) []const u8 {
        return s.ident(s.m.function_handles[fd.function].name);
    }
    fn selfAddr(s: *const S) *const [32]u8 {
        return &s.m.address_identifiers[s.m.module_handles[s.m.self_module_handle_idx].address];
    }
    fn selfName(s: *const S) []const u8 {
        return s.ident(s.m.module_handles[s.m.self_module_handle_idx].name);
    }
    /// ModuleId Display.
    fn selfId(s: *const S) Error![]const u8 {
        return std.fmt.allocPrint(s.arena, "{x}::{s}", .{ s.selfAddr(), s.selfName() });
    }
    fn fmtTok(s: *const S, t: Token) Error![]const u8 {
        var w: Writer.Allocating = .init(s.arena);
        c.formatToken(&w.writer, s.m, t) catch return error.OutOfMemory;
        return w.written();
    }
    fn dbgTok(s: *const S, t: Token) Error![]const u8 {
        var w: Writer.Allocating = .init(s.arena);
        debugToken(&w.writer, t) catch return error.OutOfMemory;
        return w.written();
    }
    /// (address, module, name) of a datatype handle.
    fn resolveStruct(s: *const S, dh: u16) struct { *const [32]u8, []const u8, []const u8 } {
        const h = s.m.datatype_handles[dh];
        const mh = s.m.module_handles[h.module];
        return .{ &s.m.address_identifiers[mh.address], s.ident(mh.name), s.ident(h.name) };
    }
    fn isStruct(s: *const S, dh: u16, addr: u16, module: []const u8, name: []const u8) bool {
        const a, const mo, const n = s.resolveStruct(dh);
        return std.mem.eql(u8, a, &c.addrFromU16(addr)) and std.mem.eql(u8, mo, module) and std.mem.eql(u8, n, name);
    }
    fn modIs(s: *const S, mh_idx: u16, addr: u16, module: []const u8) bool {
        const mh = s.m.module_handles[mh_idx];
        return std.mem.eql(u8, &s.m.address_identifiers[mh.address], &c.addrFromU16(addr)) and std.mem.eql(u8, s.ident(mh.name), module);
    }
    fn selfIs(s: *const S, addr: u16, module: []const u8) bool {
        return s.modIs(s.m.self_module_handle_idx, addr, module);
    }
};

/// Rust `Debug for SignatureToken`.
pub fn debugToken(w: *Writer, t: Token) Writer.Error!void {
    const n = t[0];
    switch (n.tag) {
        .Bool => try w.writeAll("Bool"),
        .U8 => try w.writeAll("U8"),
        .U16 => try w.writeAll("U16"),
        .U32 => try w.writeAll("U32"),
        .U64 => try w.writeAll("U64"),
        .U128 => try w.writeAll("U128"),
        .U256 => try w.writeAll("U256"),
        .Address => try w.writeAll("Address"),
        .Signer => try w.writeAll("Signer"),
        .Vector, .Reference, .MutableReference => {
            try w.writeAll(switch (n.tag) {
                .Vector => "Vector(",
                .Reference => "Reference(",
                else => "MutableReference(",
            });
            try debugToken(w, t[1..]);
            try w.writeAll(")");
        },
        .Datatype => try w.print("Struct(DatatypeHandleIndex({d}))", .{n.idx}),
        .DatatypeInstantiation => {
            try w.print("StructInstantiation(DatatypeHandleIndex({d}), [", .{n.idx});
            var it = ff.ArgIter.init(t);
            var first = true;
            while (it.next()) |a| {
                if (!first) try w.writeAll(", ");
                first = false;
                try debugToken(w, a);
            }
            try w.writeAll("])");
        },
        .TypeParameter => try w.print("TypeParameter({d})", .{n.idx}),
    }
}

// ---------------------------------------------------------------------------------------------

fn structWithKey(s: *S) Error!void {
    const m = s.m;
    for (m.struct_defs) |*def| {
        const h = m.datatype_handles[def.struct_handle];
        if (!h.abilities.hasKey()) continue;
        const name = s.ident(h.name);
        if (def.native or def.fields.len == 0)
            return s.fail(.SuiMoveVerificationError, "First field of struct {s} must be 'id', no field found", .{name});
        const ff0 = def.fields[0];
        const fname = s.ident(ff0.name);
        if (!std.mem.eql(u8, fname, "id"))
            return s.fail(.SuiMoveVerificationError, "First field of struct {s} must be 'id', {s} found", .{ name, fname });
        const t = ff0.signature;
        if (t[0].tag != .Datatype)
            return s.fail(.SuiMoveVerificationError, "First field of struct {s} must be of type {x}::object::UID, {s} type found", .{ name, &c.addrFromU16(2), try s.dbgTok(t) });
        const a, const mo, const n = s.resolveStruct(t[0].idx);
        if (!(std.mem.eql(u8, n, "UID") and std.mem.eql(u8, a, &c.addrFromU16(2)) and std.mem.eql(u8, mo, "object")))
            return s.fail(.SuiMoveVerificationError, "First field of struct {s} must be of type {x}::object::UID, {x}::{s}::{s} type found", .{ name, &c.addrFromU16(2), a, mo, n });
    }
    for (m.enum_defs) |def| {
        const h = m.datatype_handles[def.enum_handle];
        if (h.abilities.hasKey())
            return s.fail(.SuiMoveVerificationError, "Enum {s} cannot have the 'key' ability. Enums cannot have the 'key' ability.", .{s.ident(h.name)});
    }
}

fn debugInstr(w: *Writer, ins: ff.Instr) Writer.Error!void {
    switch (ins.op) {
        .MutBorrowGlobalDeprecated => try w.print("MutBorrowGlobal(StructDefinitionIndex({d}))", .{ins.idx}),
        .MutBorrowGlobalGenericDeprecated => try w.print("MutBorrowGlobalGeneric(StructDefInstantiationIndex({d}))", .{ins.idx}),
        .ImmBorrowGlobalDeprecated => try w.print("ImmBorrowGlobal(StructDefinitionIndex({d}))", .{ins.idx}),
        .ImmBorrowGlobalGenericDeprecated => try w.print("ImmBorrowGlobalGeneric(StructDefInstantiationIndex({d}))", .{ins.idx}),
        .ExistsDeprecated => try w.print("Exists(StructDefinitionIndex({d}))", .{ins.idx}),
        .ExistsGenericDeprecated => try w.print("ExistsGeneric(StructDefInstantiationIndex({d}))", .{ins.idx}),
        .MoveFromDeprecated => try w.print("MoveFrom(StructDefinitionIndex({d}))", .{ins.idx}),
        .MoveFromGenericDeprecated => try w.print("MoveFromGeneric(StructDefInstantiationIndex({d}))", .{ins.idx}),
        .MoveToDeprecated => try w.print("MoveTo(StructDefinitionIndex({d}))", .{ins.idx}),
        .MoveToGenericDeprecated => try w.print("MoveToGeneric(StructDefInstantiationIndex({d}))", .{ins.idx}),
        else => try w.print("{s}", .{@tagName(ins.op)}),
    }
}

fn globalStorage(s: *S) Error!void {
    for (s.m.function_defs) |*fd| {
        const code = fd.code orelse continue;
        var w: Writer.Allocating = .init(s.arena);
        var n: usize = 0;
        for (code.code) |ins| switch (ins.op) {
            .MoveFromDeprecated, .MoveFromGenericDeprecated, .MoveToDeprecated, .MoveToGenericDeprecated, .ImmBorrowGlobalDeprecated, .MutBorrowGlobalDeprecated, .ImmBorrowGlobalGenericDeprecated, .MutBorrowGlobalGenericDeprecated, .ExistsDeprecated, .ExistsGenericDeprecated => {
                w.writer.writeAll(if (n == 0) "[" else ", ") catch return error.OutOfMemory;
                debugInstr(&w.writer, ins) catch return error.OutOfMemory;
                n += 1;
            },
            else => {},
        };
        if (n > 0) {
            w.writer.writeAll("]") catch return error.OutOfMemory;
            return s.fail(.SuiMoveVerificationError, "Access to Move global storage is not allowed. Found in function {s}: {s}", .{ s.fnName(fd), w.written() });
        }
    }
}

// ---------------------------------------------------------------------------------------------
// id_leak_verifier

const FRESH_ID_FUNCTIONS = [_][3][]const u8{
    .{ "2", "object", "new" },
    .{ "2", "object", "new_uid_from_hash" },
    .{ "2", "derived_object", "claim" },
    .{ "2", "test_scenario", "new_object" },
};
const FUNCTIONS_TO_SKIP = [_][3][]const u8{
    .{ "3", "sui_system", "create" },
    .{ "2", "clock", "create" },
    .{ "2", "authenticator_state", "create" },
    .{ "2", "random", "create" },
    .{ "2", "deny_list", "create" },
    .{ "b", "bridge", "create" },
    .{ "2", "accumulator", "create" },
    .{ "2", "coin_registry", "create" },
    .{ "2", "display_registry", "create" },
    .{ "2", "address_alias", "create" },
    .{ "2", "forwarding_address", "create" },
};

fn identIn(list: []const [3][]const u8, addr: *const [32]u8, module: []const u8, func: []const u8) bool {
    for (list) |e| {
        const a = std.fmt.parseInt(u16, e[0], 16) catch unreachable;
        if (std.mem.eql(u8, addr, &c.addrFromU16(a)) and std.mem.eql(u8, module, e[1]) and std.mem.eql(u8, func, e[2])) return true;
    }
    return false;
}

const IdVal = enum(u8) { absent, Fresh, Other };
const ID_JOIN_BASE_COST: u128 = 10;
const ID_JOIN_PER_LOCAL_COST: u128 = 5;
const ID_STEP_BASE_COST: u128 = 15;

const IdStack = cp.AbstractStack(IdVal, struct {
    fn eq(x: IdVal, y: IdVal) bool {
        return x == y;
    }
}.eq);

const IdLeak = struct {
    pub const State = []IdVal;
    s: *S,
    ctx: *Ctx,
    meter: *c.Meter,
    arena: Allocator,
    f: *const cp.Fn,
    stack: IdStack = .{},
    /// PartialVMError Display text of a failure (`err.to_string()`).
    msg: ?[]const u8 = null,

    pub fn clone(a: *IdLeak, st: *const State) c.E!State {
        return a.arena.dupe(IdVal, st.*);
    }
    pub fn join(a: *IdLeak, pre: *State, post: *const State) c.E!bool {
        try a.meter.add(a.ctx, .Function, ID_JOIN_BASE_COST);
        var n: usize = 0;
        for (post.*) |v| if (v != .absent) {
            n += 1;
        };
        try a.meter.addItems(a.ctx, .Function, ID_JOIN_PER_LOCAL_COST, n);
        var changed = false;
        for (pre.*, post.*) |*x, y| {
            if (y == .absent) continue;
            const old: IdVal = if (x.* == .absent) .Other else x.*;
            const new: IdVal = if (y == old) old else .Other;
            if (new != old) changed = true;
            x.* = new;
        }
        return changed;
    }

    fn vmFail(a: *IdLeak, comptime fmt: []const u8, args: anytype) c.E {
        a.msg = std.fmt.allocPrint(a.arena, fmt, args) catch return error.OutOfMemory;
        return error.Vm;
    }
    fn invariant(a: *IdLeak, what: []const u8, e: anyerror) c.E {
        const ename: []const u8 = switch (e) {
            error.ElementNotEqual => "Popped element is not equal to specified item",
            error.Underflow => "Popped more values than are on the stack",
            else => "Pushed too many elements on the stack",
        };
        return a.vmFail("PartialVMError with status VERIFIER_INVARIANT_VIOLATION and message Unexpected stack error on {s}: {s}", .{ what, ename });
    }
    fn pop(a: *IdLeak) c.E!IdVal {
        return a.stack.pop() catch return error.Vm; // Rust unwrap (panic); unreachable after the Move verifier
    }
    fn popN(a: *IdLeak, n: u64) c.E!void {
        if (n == 0) return;
        a.popAnyN(n) catch |e| return a.invariant("pop_n", e);
    }
    fn popAnyN(a: *IdLeak, n: u64) !void {
        const st = &a.stack;
        if (st.values.items.len == 0 or n > st.len) return error.Underflow;
        var rem = n;
        while (rem > 0) {
            const last = &st.values.items[st.values.items.len - 1];
            if (last.n <= rem) {
                rem -= last.n;
                _ = st.values.pop();
            } else {
                last.n -= rem;
                break;
            }
        }
        st.len -= n;
    }
    fn push(a: *IdLeak, v: IdVal) c.E!void {
        a.stack.pushN(a.arena, v, 1) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else a.invariant("push", e);
    }
    fn pushN(a: *IdLeak, n: u64, v: IdVal) c.E!void {
        a.stack.pushN(a.arena, v, n) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else a.invariant("push_n", e);
    }

    fn call(a: *IdLeak, fh: *const ff.FunctionHandle) c.E!void {
        const m = a.f.m;
        try a.popN(m.signatures[fh.parameters].len);
        const nret = m.signatures[fh.return_].len;
        const mh = m.module_handles[fh.module];
        if (identIn(&FRESH_ID_FUNCTIONS, &m.address_identifiers[mh.address], m.identifiers[mh.name], m.identifiers[fh.name])) {
            if (nret != 1) return a.vmFail("PartialVMError with status UNKNOWN_VERIFICATION_ERROR with sub status 0 and message Should have a single return value", .{});
            try a.push(.Fresh);
        } else try a.pushN(nret, .Other);
    }

    fn pack(a: *IdLeak, sd: *const ff.StructDefinition) c.E!void {
        const m = a.f.m;
        const h = m.datatype_handles[sd.struct_handle];
        const nf: u64 = sd.fields.len;
        try a.popN(nf -% 1);
        const last = try a.pop();
        if (h.abilities.hasKey() and last != .Fresh) {
            const fh = m.function_handles[m.function_defs[a.f.fidx].function];
            const mh = m.module_handles[fh.module];
            return a.vmFail("PartialVMError with status UNKNOWN_VERIFICATION_ERROR with sub status 1 and message Invalid object creation in {x}::{s}::{s}. Object created without a newly created UID. The UID must come directly from `sui::object::new`, or `sui::derived_object::claim`. For tests, it can also come from `sui::test_scenario::new_object`", .{ &m.address_identifiers[mh.address], m.identifiers[mh.name], m.identifiers[fh.name] });
        }
        try a.push(.Other);
    }

    pub fn execute(a: *IdLeak, st: *State, ins: ff.Instr, off: u16, _: u16, last: u16) c.E!void {
        try a.exec(st, ins);
        if (off == last and a.stack.len != 0)
            return a.vmFail("PartialVMError with status VERIFIER_INVARIANT_VIOLATION and message Invalid stack transitions. Non-zero stack size at the end of the block", .{});
    }

    fn exec(a: *IdLeak, st: *State, ins: ff.Instr) c.E!void {
        try a.meter.add(a.ctx, .Function, ID_STEP_BASE_COST);
        const m = a.f.m;
        const locals = st.*;
        switch (ins.op) {
            .Pop, .BrTrue, .BrFalse, .Abort, .VariantSwitch => _ = try a.pop(),
            .CopyLoc, .MutBorrowLoc, .ImmBorrowLoc, .LdTrue, .LdFalse, .LdU8, .LdU16, .LdU32, .LdU64, .LdU128, .LdU256, .LdConst => try a.push(.Other),
            .MoveLoc => {
                const v = locals[ins.idx];
                if (v == .absent) return error.Vm; // Rust unwrap
                locals[ins.idx] = .absent;
                try a.push(v);
            },
            .StLoc => locals[ins.idx] = try a.pop(),
            .FreezeRef, .ReadRef, .CastU8, .CastU16, .CastU32, .CastU64, .CastU128, .CastU256, .Not, .VecLen, .VecPopBack, .MutBorrowField, .MutBorrowFieldGeneric, .ImmBorrowField, .ImmBorrowFieldGeneric => {
                _ = try a.pop();
                try a.push(.Other);
            },
            .Branch, .Nop => {},
            .Eq, .Neq, .Add, .Sub, .Mul, .Mod, .Div, .BitOr, .BitAnd, .Xor, .Shl, .Shr, .Or, .And, .Lt, .Gt, .Le, .Ge, .VecImmBorrow, .VecMutBorrow => {
                _ = try a.pop();
                _ = try a.pop();
                try a.push(.Other);
            },
            .WriteRef, .VecPushBack => {
                _ = try a.pop();
                _ = try a.pop();
            },
            .VecSwap => {
                _ = try a.pop();
                _ = try a.pop();
                _ = try a.pop();
            },
            .Call => try a.call(&m.function_handles[ins.idx]),
            .CallGeneric => try a.call(&m.function_handles[m.function_instantiations[ins.idx].handle]),
            .Ret => try a.popN(a.f.ret.len),
            .Pack => try a.pack(&m.struct_defs[ins.idx]),
            .PackGeneric => try a.pack(&m.struct_defs[m.struct_def_instantiations[ins.idx].def]),
            .Unpack, .UnpackGeneric => {
                const sd = if (ins.op == .Unpack) ins.idx else m.struct_def_instantiations[ins.idx].def;
                _ = try a.pop();
                try a.pushN(m.struct_defs[sd].fields.len, .Other);
            },
            .VecPack => {
                try a.popN(ins.imm);
                try a.push(.Other);
            },
            .VecUnpack => {
                _ = try a.pop();
                try a.pushN(ins.imm, .Other);
            },
            .PackVariant, .PackVariantGeneric, .UnpackVariant, .UnpackVariantImmRef, .UnpackVariantMutRef, .UnpackVariantGeneric, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => {
                const ed, const tag = switch (ins.op) {
                    .PackVariant, .UnpackVariant, .UnpackVariantImmRef, .UnpackVariantMutRef => .{ m.variant_handles[ins.idx].enum_def, m.variant_handles[ins.idx].variant },
                    else => .{ m.enum_def_instantiations[m.variant_instantiation_handles[ins.idx].enum_def].def, m.variant_instantiation_handles[ins.idx].variant },
                };
                const nf = m.enum_defs[ed].variants[tag].fields.len;
                if (ins.op == .PackVariant or ins.op == .PackVariantGeneric) {
                    try a.popN(nf);
                    try a.push(.Other);
                } else {
                    _ = try a.pop();
                    try a.pushN(nf, .Other);
                }
            },
            else => return error.Vm, // global storage: panics in Rust, rejected earlier
        }
    }
};

fn idLeak(s: *S, ctx: *Ctx, meter: *c.Meter, scratch: *std.heap.ArenaAllocator) Error!void {
    const m = s.m;
    for (m.function_defs, 0..) |*fd, idx| {
        const code = &(fd.code orelse continue);
        _ = scratch.reset(.retain_capacity);
        const a = scratch.allocator();
        const fh = &m.function_handles[fd.function];
        const g = try cfgm.Cfg.init(a, code.code, code.jump_tables);
        const f: cp.Fn = .{
            .m = m,
            .fidx = @intCast(idx),
            .code = code,
            .params = m.signatures[fh.parameters],
            .ret = m.signatures[fh.return_],
            .locals = m.signatures[code.locals],
            .tparams = fh.type_parameters,
            .g = &g,
        };
        const mh = m.module_handles[fh.module];
        if (identIn(&FUNCTIONS_TO_SKIP, &m.address_identifiers[mh.address], m.identifiers[mh.name], m.identifiers[fh.name])) continue;
        const init = try a.alloc(IdVal, f.numLocals());
        @memset(init, .absent);
        for (0..f.params.len) |i| init[i] = .Other;
        var an: IdLeak = .{ .s = s, .ctx = ctx, .meter = meter, .arena = a, .f = &f };
        cfgm.analyze(IdLeak, &an, ctx, meter, a, &g, code.code, init) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Vm => {
                const msg = an.msg orelse return error.Vm; // a Rust panic path; never in valid input
                return s.fail(.SuiMoveVerificationError, "{s}", .{msg});
            },
        };
    }
}

// ---------------------------------------------------------------------------------------------
// private generics

fn definedHere(m: *const CompiledModule, t: Token) bool {
    return switch (t[0].tag) {
        .Datatype, .DatatypeInstantiation => m.datatype_handles[t[0].idx].module == m.self_module_handle_idx,
        else => false,
    };
}

fn privateGenericsV1(s: *S, cfg: *const c.Config) Error!void {
    const m = s.m;
    if (s.selfIs(2, "test_scenario")) return;
    const PUBLIC = [_][]const u8{ "public_transfer", "public_freeze_object", "public_share_object", "public_receive", "receiving_object_id", "public_party_transfer" };
    const PRIVATE = [_][]const u8{ "transfer", "freeze_object", "share_object", "receive", "party_transfer" };
    for (m.function_defs) |*fd| {
        const code = fd.code orelse continue;
        for (code.code) |ins| {
            if (ins.op != .CallGeneric) continue;
            const fi = m.function_instantiations[ins.idx];
            const fh = m.function_handles[fi.handle];
            const targs = m.signatures[fi.type_parameters];
            const fident = s.ident(fh.name);
            const err: ?[]const u8 = blk: {
                if (s.modIs(fh.module, 2, "transfer")) {
                    const pubs = if (cfg.allow_receiving_object_id) PUBLIC[0..] else PUBLIC[0..4];
                    if (s.selfIs(2, "transfer")) break :blk null;
                    if (inList(pubs, fident)) break :blk null;
                    if (!inList(&PRIVATE, fident)) break :blk try std.fmt.allocPrint(s.arena, "Calling unknown transfer function, {s}", .{fident});
                    if (targs.len != 1) break :blk try std.fmt.allocPrint(s.arena, "Expected 1 type argument for {s}", .{fident});
                    if (!definedHere(m, targs[0])) break :blk try std.fmt.allocPrint(s.arena, "Invalid call to '{x}::transfer::{s}' on an object of type '{s}'. The transferred object's type must be defined in the current module. If the object has the 'store' type ability, you can use the non-internal variant instead, i.e. '{x}::transfer::public_{s}'", .{ &c.addrFromU16(2), fident, try s.fmtTok(targs[0]), &c.addrFromU16(2), fident });
                    break :blk null;
                } else if (s.modIs(fh.module, 2, "event")) {
                    if (std.mem.eql(u8, fident, "events_by_type")) break :blk null;
                    if (std.mem.eql(u8, fident, "emit_authenticated_impl")) {
                        if (!s.selfIs(2, "event")) break :blk try std.fmt.allocPrint(s.arena, "Calling emit_authenticated_impl outside of event which is impossible", .{});
                        break :blk null;
                    }
                    if (!(std.mem.eql(u8, fident, "emit") or std.mem.eql(u8, fident, "emit_authenticated"))) break :blk try std.fmt.allocPrint(s.arena, "Calling unknown event function, {s}", .{fident});
                    if (targs.len != 1) break :blk try std.fmt.allocPrint(s.arena, "Expected 1 type argument for {s}", .{fident});
                    if (!definedHere(m, targs[0])) break :blk try std.fmt.allocPrint(s.arena, "Invalid call to '{x}::event::{s}' with an event type '{s}'. The event's type must be defined in the current module", .{ &c.addrFromU16(2), fident, try s.fmtTok(targs[0]) });
                    break :blk null;
                } else if (s.modIs(fh.module, 2, "coin_registry")) {
                    if (!std.mem.eql(u8, fident, "new_currency")) break :blk null;
                    if (targs.len != 1) break :blk try std.fmt.allocPrint(s.arena, "Expected 1 type argument for {s}", .{fident});
                    if (!definedHere(m, targs[0])) break :blk try std.fmt.allocPrint(s.arena, "Invalid call to '{x}::coin_registry::{s}' with type '{s}'. The coin's type must be defined in the current module", .{ &c.addrFromU16(2), fident, try s.fmtTok(targs[0]) });
                    break :blk null;
                }
                break :blk null;
            };
            if (err) |e| return s.fail(.SuiMoveVerificationError, "{s}::{s}. {s}", .{ try s.selfId(), s.fnName(fd), e });
        }
    }
}

fn inList(list: []const []const u8, x: []const u8) bool {
    for (list) |e| if (std.mem.eql(u8, e, x)) return true;
    return false;
}

const Rule = struct { addr: u16, module: []const u8, func: []const u8, internal: []const bool };
const FUNCTIONS_TO_CHECK = [_]Rule{
    .{ .addr = 1, .module = "internal", .func = "permit", .internal = &.{true} },
    .{ .addr = 2, .module = "event", .func = "emit", .internal = &.{true} },
    .{ .addr = 2, .module = "event", .func = "emit_authenticated", .internal = &.{true} },
    .{ .addr = 2, .module = "event", .func = "num_events", .internal = &.{} },
    .{ .addr = 2, .module = "event", .func = "events_by_type", .internal = &.{false} },
    .{ .addr = 2, .module = "transfer", .func = "public_transfer", .internal = &.{false} },
    .{ .addr = 2, .module = "transfer", .func = "public_freeze_object", .internal = &.{false} },
    .{ .addr = 2, .module = "transfer", .func = "public_share_object", .internal = &.{false} },
    .{ .addr = 2, .module = "transfer", .func = "public_receive", .internal = &.{false} },
    .{ .addr = 2, .module = "transfer", .func = "receiving_object_id", .internal = &.{false} },
    .{ .addr = 2, .module = "transfer", .func = "public_party_transfer", .internal = &.{false} },
    .{ .addr = 2, .module = "transfer", .func = "transfer", .internal = &.{true} },
    .{ .addr = 2, .module = "transfer", .func = "freeze_object", .internal = &.{true} },
    .{ .addr = 2, .module = "transfer", .func = "share_object", .internal = &.{true} },
    .{ .addr = 2, .module = "transfer", .func = "receive", .internal = &.{true} },
    .{ .addr = 2, .module = "transfer", .func = "party_transfer", .internal = &.{true} },
    .{ .addr = 2, .module = "coin_registry", .func = "new_currency", .internal = &.{true} },
};

fn findRule(addr: *const [32]u8, module: []const u8, func: []const u8) ?*const Rule {
    for (&FUNCTIONS_TO_CHECK) |*r| {
        if (std.mem.eql(u8, addr, &c.addrFromU16(r.addr)) and std.mem.eql(u8, module, r.module) and std.mem.eql(u8, func, r.func)) return r;
    }
    return null;
}

fn privateGenericsV2(s: *S) Error!void {
    const m = s.m;
    const self_addr = s.selfAddr();
    const self_name = s.selfName();
    if (s.selfIs(2, "test_scenario")) return;
    if (s.selfIs(2, "event") or s.selfIs(2, "transfer")) {
        for (m.function_defs) |*fd| {
            if (fd.visibility != .Public) continue;
            const fname = s.fnName(fd);
            if (findRule(self_addr, self_name, fname) == null) {
                const id = try s.selfId();
                return s.fail(.InvariantViolation, "Unknown function '{s}::{s}'. All functions in '{s}' must be listed in FUNCTIONS_TO_CHECK", .{ id, fname, id });
            }
        }
    }
    for (m.function_defs) |*fd| {
        const code = fd.code orelse continue;
        for (code.code) |ins| {
            const fh, const targs: []const Token = switch (ins.op) {
                .Call => .{ m.function_handles[ins.idx], &.{} },
                .CallGeneric => .{ m.function_handles[m.function_instantiations[ins.idx].handle], m.signatures[m.function_instantiations[ins.idx].type_parameters] },
                else => continue,
            };
            const mh = m.module_handles[fh.module];
            const ca = &m.address_identifiers[mh.address];
            const cm = s.ident(mh.name);
            const cf = s.ident(fh.name);
            const rule = findRule(ca, cm, cf) orelse continue;
            if (targs.len != rule.internal.len) {
                return s.fail(.InvariantViolation, "{s}::{s}. '{x}::{s}::{s}' expects {d} type arguments found {d}", .{ try s.selfId(), s.fnName(fd), ca, cm, cf, rule.internal.len, targs.len });
            }
            for (targs, rule.internal, 0..) |t, internal, i| {
                if (!internal) continue;
                if (definedHere(m, t)) continue;
                const pkg: []const u8 = if (rule.addr == 2) "sui" else "std";
                var help: []const u8 = "";
                if (rule.addr == 2 and std.mem.eql(u8, cm, "transfer"))
                    help = try std.fmt.allocPrint(s.arena, " If the type has the 'store' ability, use the public variant instead: 'sui::transfer::public_{s}'.", .{cf});
                return s.fail(.SuiMoveVerificationError, "{s}::{s}. Invalid call to '{s}::{s}::{s}'. Type argument #{d} must be a type defined in the current module, found '{s}'.{s}", .{ try s.selfId(), s.fnName(fd), pkg, cm, cf, i, try s.fmtTok(t), help });
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// entry points

const TxKind = enum { None, Mutable, Immutable };

fn txContextKind(s: *const S, t: Token) TxKind {
    const kind: TxKind = switch (t[0].tag) {
        .MutableReference => .Mutable,
        .Reference => .Immutable,
        else => return .None,
    };
    if (t[1].tag != .Datatype) return .None;
    return if (s.isStruct(t[1].idx, 2, "tx_context", "TxContext")) kind else .None;
}

fn clockIsMutable(s: *const S, t: Token) bool {
    return switch (t[0].tag) {
        .MutableReference => clockIsMutable(s, t[1..]),
        .Datatype => s.isStruct(t[0].idx, 2, "clock", "Clock"),
        else => false,
    };
}
fn isMutableRandom(s: *const S, t: Token) bool {
    return switch (t[0].tag) {
        .MutableReference => isMutableRandom(s, t[1..]),
        .Datatype => s.isStruct(t[0].idx, 2, "random", "Random"),
        else => false,
    };
}
fn isPrimitive(s: *const S, tps: []const AbilitySet, t: Token) bool {
    return switch (t[0].tag) {
        .Bool, .U8, .U16, .U32, .U64, .U128, .U256, .Address => true,
        .Signer => false,
        .TypeParameter => !tps[t[0].idx].hasKey(),
        .Datatype => s.isStruct(t[0].idx, 2, "object", "ID") or s.isStruct(t[0].idx, 1, "ascii", "String") or s.isStruct(t[0].idx, 1, "string", "String"),
        .DatatypeInstantiation => s.isStruct(t[0].idx, 1, "option", "Option") and t[0].arity == 1 and isPrimitive(s, tps, t[1..]),
        .Vector => isPrimitive(s, tps, t[1..]),
        .Reference, .MutableReference => false,
    };
}
/// Err = the CompiledModule::abilities error text.
fn isObjectStruct(s: *const S, tps: []const AbilitySet, t: Token) error{Abilities}!bool {
    return switch (t[0].tag) {
        .TypeParameter => if (t[0].idx < tps.len) tps[t[0].idx].hasKey() else false,
        .Datatype, .DatatypeInstantiation => (c.moduleAbilities(s.m, t, tps) orelse return error.Abilities).hasKey(),
        else => false,
    };
}
fn isObject(s: *const S, tps: []const AbilitySet, t: Token) error{Abilities}!bool {
    return switch (t[0].tag) {
        .Reference, .MutableReference => isObject(s, tps, t[1..]),
        else => isObjectStruct(s, tps, t),
    };
}
fn isObjectVector(s: *const S, tps: []const AbilitySet, t: Token) error{Abilities}!bool {
    return switch (t[0].tag) {
        .Vector => isObjectStruct(s, tps, t[1..]),
        else => isObjectStruct(s, tps, t),
    };
}
fn isReceiving(s: *const S, t: Token) bool {
    return switch (t[0].tag) {
        .MutableReference, .Reference => isReceiving(s, t[1..]),
        .DatatypeInstantiation => s.isStruct(t[0].idx, 2, "transfer", "Receiving") and t[0].arity == 1,
        else => false,
    };
}

fn entryPoints(s: *S, cfg: *const c.Config) Error!void {
    const m = s.m;
    const tx = "0000000000000000000000000000000000000000000000000000000000000002::tx_context::TxContext";
    for (m.function_defs) |*fd| {
        const fh = &m.function_handles[fd.function];
        const name = s.ident(fh.name);
        // verify_init_not_called
        if (fd.code) |code| for (code.code, 0..) |ins, off| {
            const callee = switch (ins.op) {
                .Call => m.function_handles[ins.idx],
                .CallGeneric => m.function_handles[m.function_instantiations[ins.idx].handle],
                else => continue,
            };
            if (std.mem.eql(u8, s.ident(callee.name), "init"))
                return s.fail(.SuiMoveVerificationError, "{s}::init at offset {d}. Cannot call a module's 'init' function from another Move function", .{ try s.selfId(), off });
        };
        if (std.mem.eql(u8, name, "init")) {
            const id = try s.selfId();
            if (fd.visibility != .Private) return s.fail(.SuiMoveVerificationError, "{s}. 'init' function must be private", .{id});
            if (fd.is_entry) return s.fail(.SuiMoveVerificationError, "{s}. 'init' cannot be 'entry'", .{id});
            if (fh.type_parameters.len != 0) return s.fail(.SuiMoveVerificationError, "{s}. 'init' function cannot have type parameters", .{id});
            if (m.signatures[fh.return_].len != 0) return s.fail(.SuiMoveVerificationError, "{s}, 'init' function cannot have return values", .{id});
            const params = m.signatures[fh.parameters];
            if (params.len == 0 or params.len > 2) return s.fail(.SuiMoveVerificationError, "Expected at least one and at most two parameters for {s}::init", .{id});
            if (txContextKind(s, params[params.len - 1]) == .None)
                return s.fail(.SuiMoveVerificationError, "Expected last parameter for {s}::init to be &mut {s} or &{s}, but found {s}", .{ id, tx, tx, try s.fmtTok(params[0]) });
            continue;
        }
        if (!fd.is_entry or cfg.disable_entry_point_signature_check) continue;
        const params = m.signatures[fh.parameters];
        const non_ctx = if (params.len > 0 and txContextKind(s, params[params.len - 1]) != .None) params[0 .. params.len - 1] else params;
        const tps = fh.type_parameters;
        for (non_ctx) |p| {
            if (clockIsMutable(s, p))
                return s.fail(.SuiMoveVerificationError, "Invalid entry point parameter type. Clock must be passed by immutable reference. got: {s}", .{try s.fmtTok(p)});
            if (cfg.reject_mutable_random_on_entry_functions and isMutableRandom(s, p))
                return s.fail(.SuiMoveVerificationError, "Invalid entry point parameter type. Random must be passed by immutable reference. got: {s}", .{try s.fmtTok(p)});
            const ok = isPrimitive(s, tps, p) or
                (isObject(s, tps, p) catch return s.fail(.SuiMoveVerificationError, "PartialVMError with status VERIFIER_INVARIANT_VIOLATION", .{})) or
                (isObjectVector(s, tps, p) catch return s.fail(.SuiMoveVerificationError, "PartialVMError with status VERIFIER_INVARIANT_VIOLATION", .{})) or
                isReceiving(s, p);
            if (!ok) return s.fail(.SuiMoveVerificationError, "Invalid entry point parameter type. Expected primitive or object type. Got: {s}", .{try s.fmtTok(p)});
        }
        for (m.signatures[fh.return_]) |r| {
            if (ff.isReference(r)) return s.fail(.SuiMoveVerificationError, "Invalid entry point return type. Expected a non reference type.", .{});
            const ab = c.moduleAbilities(m, r, tps) orelse return s.fail(.SuiMoveVerificationError, "Unexpected CompiledModule error: PartialVMError with status VERIFIER_INVARIANT_VIOLATION", .{});
            if (!ab.hasDrop()) return s.fail(.SuiMoveVerificationError, "Invalid entry point return type. The specified return type does not have the 'drop' ability: {s}", .{try s.fmtTok(r)});
        }
    }
}

// ---------------------------------------------------------------------------------------------
// tx_context restrictions, one-time witness

fn txContextRestrictions(s: *S, cfg: *const c.Config) Error!void {
    if (!cfg.framework_tx_context_mut_restrictions) return;
    const a = s.selfAddr();
    var system = false;
    for ([_]u16{ 1, 2, 3, 0xb, 0xdee9 }) |x| if (std.mem.eql(u8, a, &c.addrFromU16(x))) {
        system = true;
    };
    if (!system) return;
    const m = s.m;
    for (m.function_defs) |*fd| {
        const fh = m.function_handles[fd.function];
        var safe = true;
        for (m.signatures[fh.return_]) |t| if (t[0].tag == .MutableReference) {
            safe = false;
        };
        if (safe) continue;
        var ctx_muts: usize = 0;
        var other: usize = 0;
        for (m.signatures[fh.parameters]) |t| {
            if (t[0].tag != .MutableReference) continue;
            if (txContextKind(s, t) == .Mutable) ctx_muts += 1 else other += 1;
        }
        if (ctx_muts > 0 and other == 0)
            return s.fail(.SuiMoveVerificationError, "{s}::{s}. Function takes `&mut TxContext` and returns a mutable reference, but has no non-`TxContext` `&mut U` parameter. `TxContext` cannot serve as the mutable root for a returned reference; add a mutable reference parameter of another type or return by value.", .{ try s.selfId(), s.ident(fh.name) });
    }
}

fn dhEql(a: *const ff.DatatypeHandle, b: *const ff.DatatypeHandle) bool {
    if (a.module != b.module or a.name != b.name or a.abilities.bits != b.abilities.bits) return false;
    if (a.type_parameters.len != b.type_parameters.len) return false;
    for (a.type_parameters, b.type_parameters) |x, y| if (x.constraints.bits != y.constraints.bits or x.is_phantom != y.is_phantom) return false;
    return true;
}

fn oneTimeWitness(s: *S) Error!void {
    const m = s.m;
    if (s.selfIs(2, "sui")) return;
    for ([_][]const u8{ "btc", "eth", "usdc", "usdt" }) |tok| if (s.selfIs(0xb, tok)) return;
    const mod_name = s.selfName();
    const upper = try s.arena.alloc(u8, mod_name.len);
    _ = std.ascii.upperString(upper, mod_name);
    var cand: ?struct { name: []const u8, handle: *const ff.DatatypeHandle, sd: u16 } = null;
    for (m.struct_defs, 0..) |*def, i| {
        const h = &m.datatype_handles[def.struct_handle];
        const sname = s.ident(h.name);
        if (!std.mem.eql(u8, upper, sname)) continue;
        if (def.native) continue;
        if (def.fields.len == 1 and def.fields[0].signature[0].tag == .Bool and def.fields[0].signature.len == 1) {
            if (!(h.abilities.bits == (AbilitySet{ .bits = 0 }).with(.Drop).bits))
                return s.fail(.SuiMoveVerificationError, "one-time witness type candidate {s}::{s} must have a single ability: drop", .{ try s.selfId(), sname });
            if (h.type_parameters.len != 0)
                return s.fail(.SuiMoveVerificationError, "one-time witness type candidate {s}::{s} cannot have type parameters", .{ try s.selfId(), sname });
            cand = .{ .name = sname, .handle = h, .sd = @intCast(i) };
            break;
        }
    }
    for (m.function_defs) |*fd| {
        const fh = &m.function_handles[fd.function];
        const fname = s.ident(fh.name);
        if (std.mem.eql(u8, fname, "init")) {
            const params = m.signatures[fh.parameters];
            if (cand) |cd| {
                const ok = params.len == 2 and params[0][0].tag == .Datatype and dhEql(&m.datatype_handles[params[0][0].idx], cd.handle);
                if (!ok) return s.fail(.SuiMoveVerificationError, "init function of a module containing one-time witness type candidate must have {s}::{s} as the first parameter (a struct which has no fields or a single field of type bool)", .{ try s.selfId(), cd.name });
            } else if (params.len != 1) {
                const id = try s.selfId();
                const tx = "0000000000000000000000000000000000000000000000000000000000000002::tx_context::TxContext";
                const up = try s.arena.alloc(u8, mod_name.len);
                _ = std.ascii.upperString(up, mod_name);
                return s.fail(.SuiMoveVerificationError, "Expected last (and at most second) parameter for {s}::init to be &mut {s} or &{s}; optional first parameter must be of one-time witness type whose name is the same as the capitalized module name ({s}::{s}) and which has no fields or a single field of type bool", .{ id, tx, tx, id, up });
            }
        }
        if (cand) |cd| {
            const code = fd.code orelse continue;
            for (code.code) |ins| {
                if (ins.op != .Pack) continue;
                if (m.struct_defs[ins.idx].struct_handle == m.struct_defs[cd.sd].struct_handle) {
                    const id = try s.selfId();
                    return s.fail(.SuiMoveVerificationError, "one-time witness type {s}::{s} is instantiated in the {s}::{s} function and must never be", .{ id, cd.name, id, fname });
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------

/// `sui_verify_module_metered`. Returns null when the module passes.
pub fn verify(arena: Allocator, scratch: *std.heap.ArenaAllocator, ctx: *Ctx, cfg: *const c.Config, m: *const CompiledModule, meter: *c.Meter) error{ OutOfMemory, Vm }!?SuiError {
    var s: S = .{ .arena = arena, .m = m };
    run(&s, ctx, cfg, meter, scratch) catch |e| switch (e) {
        error.Sui => return s.out.?,
        error.OutOfMemory => return error.OutOfMemory,
        error.Vm => return error.Vm,
    };
    return null;
}

fn run(s: *S, ctx: *Ctx, cfg: *const c.Config, meter: *c.Meter, scratch: *std.heap.ArenaAllocator) Error!void {
    try structWithKey(s);
    try globalStorage(s);
    if (!cfg.disable_id_leak_verifier) try idLeak(s, ctx, meter, scratch);
    if (cfg.private_generics_verifier_v2) try privateGenericsV2(s) else try privateGenericsV1(s, cfg);
    try entryPoints(s, cfg);
    try txContextRestrictions(s, cfg);
    try oneTimeWitness(s);
}
