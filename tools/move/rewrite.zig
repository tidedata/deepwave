//! Bytecode rewriting primitives shared by the optimizer and the superoptimizer: jump targets,
//! successors, windows replaced with other instruction sequences (all branch operands and jump
//! tables remapped), reachability, and verification of a module with one function replaced.
const std = @import("std");
const common = @import("common.zig");
const mf = @import("move_format");
const protocol = @import("protocol");

const Allocator = std.mem.Allocator;
const ff = common.ff;
const Instr = ff.Instr;
const Op = ff.Opcode;

pub const Code = struct {
    code: []const Instr,
    jump_tables: []const ff.JumpTable,
};

/// Replace `code[start .. start + len]` with `repl`.
pub const Edit = struct { start: u32, len: u32, repl: []const Instr };

/// Marks every instruction some branch or jump table jumps to.
pub fn jumpTargets(arena: Allocator, c: Code) Allocator.Error![]bool {
    const t = try arena.alloc(bool, c.code.len + 1);
    @memset(t, false);
    for (c.code) |ins| {
        if (ins.op.hasOffset() and ins.idx < t.len) t[ins.idx] = true;
    }
    for (c.jump_tables) |jt| for (jt.offsets) |o| {
        if (o < t.len) t[o] = true;
    };
    return t;
}

pub fn ins0(op: Op) Instr {
    return .{ .op = op };
}
pub fn insIdx(op: Op, idx: u16) Instr {
    return .{ .op = op, .idx = idx };
}
pub fn insImm(op: Op, imm: u64) Instr {
    return .{ .op = op, .imm = imm };
}

pub const RewriteError = error{ BadEdit, TooLong } || Allocator.Error;

/// Applies non-overlapping `edits` (sorted by start). Branch operands and jump-table offsets are
/// remapped through the old-to-new offset map. A position inside a replaced window maps to the
/// first instruction after the replacement (only unreachable code or a deliberate removal jumps there).
pub fn applyEdits(arena: Allocator, c: Code, edits: []const Edit) RewriteError!Code {
    var out: std.ArrayList(Instr) = .empty;
    const map = try arena.alloc(u32, c.code.len + 1);
    var i: usize = 0;
    var e: usize = 0;
    while (i < c.code.len) {
        if (e < edits.len and edits[e].start == i) {
            const ed = edits[e];
            if (ed.start + ed.len > c.code.len) return error.BadEdit;
            map[i] = @intCast(out.items.len);
            var k: usize = 1;
            const after = out.items.len + ed.repl.len;
            while (k < ed.len) : (k += 1) map[i + k] = @intCast(after);
            try out.appendSlice(arena, ed.repl);
            i += ed.len;
            e += 1;
            if (ed.len == 0) return error.BadEdit;
        } else {
            map[i] = @intCast(out.items.len);
            try out.append(arena, c.code[i]);
            i += 1;
        }
    }
    if (e != edits.len) return error.BadEdit;
    map[c.code.len] = @intCast(out.items.len);
    if (out.items.len > ff.BYTECODE_COUNT_MAX) return error.TooLong;
    for (out.items) |*ins| {
        if (ins.op.hasOffset()) {
            if (ins.idx >= map.len) return error.BadEdit;
            ins.idx = @intCast(map[ins.idx]);
        }
    }
    // Replacement instructions copied branch operands in OLD coordinates only when they were
    // taken from existing instructions; callers pass fresh ones in old coordinates as well, so
    // the loop above remapped them all consistently.
    const jts = try arena.alloc(ff.JumpTable, c.jump_tables.len);
    for (c.jump_tables, jts) |jt, *o| {
        const offs = try arena.alloc(ff.CodeOffset, jt.offsets.len);
        for (jt.offsets, offs) |old, *n| n.* = if (old < map.len) @intCast(map[old]) else return error.BadEdit;
        o.* = .{ .head_enum = jt.head_enum, .offsets = offs };
    }
    return .{ .code = out.items, .jump_tables = jts };
}

/// Instruction offsets control can reach from offset 0.
pub fn reachable(arena: Allocator, c: Code) Allocator.Error![]bool {
    const r = try arena.alloc(bool, c.code.len);
    @memset(r, false);
    var work: std.ArrayList(u32) = .empty;
    if (c.code.len > 0) try work.append(arena, 0);
    while (work.pop()) |at| {
        var i = at;
        while (i < c.code.len and !r[i]) {
            r[i] = true;
            const ins = c.code[i];
            switch (ins.op) {
                .Ret, .Abort => break,
                .Branch => {
                    if (ins.idx < c.code.len) try work.append(arena, ins.idx);
                    break;
                },
                .BrTrue, .BrFalse => {
                    if (ins.idx < c.code.len) try work.append(arena, ins.idx);
                    i += 1;
                },
                .VariantSwitch => {
                    if (ins.idx < c.jump_tables.len) for (c.jump_tables[ins.idx].offsets) |o| {
                        if (o < c.code.len) try work.append(arena, o);
                    };
                    break;
                },
                else => i += 1,
            }
        }
    }
    return r;
}

// ---------------------------------------------------------------------------------------------
// Verification

pub const VerifyOutcome = union(enum) { ok, move: []const u8, sui: []const u8 };

pub const Verifier = struct {
    cfg: mf.verifier.verify.Config,

    pub fn init(version: ?u64) !Verifier {
        const pv = version orelse protocol.max_protocol_version;
        const pc = try protocol.get(pv, .mainnet);
        const v = try protocol.derived.verifierConfig(pc, null);
        var out: mf.verifier.verify.Config = .{};
        inline for (@typeInfo(@TypeOf(v)).@"struct".field_names) |f| @field(out, f) = @field(v, f);
        return .{ .cfg = out };
    }

    /// The Move verifier and the Sui verifier over `m` (what publishing runs).
    pub fn check(v: *const Verifier, arena: Allocator, m: *const ff.CompiledModule) Allocator.Error!VerifyOutcome {
        var scratch: std.heap.ArenaAllocator = .init(arena);
        defer scratch.deinit();
        const res = try mf.verifier.verify.verifyModule(arena, &scratch, &v.cfg, m, null);
        if (res.move) |me| return .{ .move = try std.fmt.allocPrint(arena, "{s}", .{@tagName(me.err.major)}) };
        if (res.sui) |se| return .{ .sui = try arena.dupe(u8, se.msg) };
        return .ok;
    }
};

/// A copy of `m` whose function `fi` has `new` as its code.
pub fn withFunction(arena: Allocator, m: *const ff.CompiledModule, fi: usize, new: Code) Allocator.Error!ff.CompiledModule {
    const defs = try arena.dupe(ff.FunctionDefinition, m.function_defs);
    var cu = defs[fi].code.?;
    cu.code = new.code;
    cu.jump_tables = new.jump_tables;
    defs[fi].code = cu;
    var out = m.*;
    out.function_defs = defs;
    return out;
}

pub fn opName(op: Op) []const u8 {
    return std.enums.tagName(Op, op) orelse "?";
}

test "applyEdits remaps branches" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // 0: LdTrue 1: Nop 2: BrTrue 4 3: Nop 4: Ret
    const code = [_]Instr{ ins0(.LdTrue), ins0(.Nop), insIdx(.BrTrue, 4), ins0(.Nop), ins0(.Ret) };
    const edits = [_]Edit{ .{ .start = 1, .len = 1, .repl = &.{} }, .{ .start = 3, .len = 1, .repl = &.{} } };
    const r = try applyEdits(a, .{ .code = &code, .jump_tables = &.{} }, &edits);
    try std.testing.expectEqual(@as(usize, 3), r.code.len);
    try std.testing.expectEqual(@as(u16, 2), r.code[1].idx);
}
