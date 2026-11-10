//! Small-function inlining (optimizer pass `inline`): a call to a non-generic, branch-free function
//! of the same module is replaced by its body, with the arguments stored into fresh locals of the
//! caller. Instruction count per call site changes by (2 - parameters) (the Call and the Ret go,
//! one StLoc per parameter comes), so by default only callees with at most two parameters are
//! inlined; the saving in gas is measured by `deepwave-move equiv`, not assumed. Every inlined function
//! is verified as part of its module; a caller that fails verification keeps its calls.
const std = @import("std");
const common = @import("common.zig");
const rw = @import("rewrite.zig");

const Allocator = std.mem.Allocator;
const ff = common.ff;
const Instr = ff.Instr;
const Code = rw.Code;

pub const max_callee_instructions = 24;
pub const max_params = 2;

pub const Outcome = struct {
    module: ff.CompiledModule,
    before: usize,
    after: usize,
    applied: []const @import("optimize.zig").Applied,
};

const Callee = struct { def: usize, params: usize, nlocals: usize, sig: []const ff.Token };

fn isLocalOp(op: ff.Opcode) bool {
    return switch (op) {
        .CopyLoc, .MoveLoc, .StLoc, .MutBorrowLoc, .ImmBorrowLoc => true,
        else => false,
    };
}

/// The callee behind function handle `fh` if it can be inlined.
fn calleeOf(m: *const ff.CompiledModule, fh_idx: u16, caller_def: usize) ?Callee {
    const fh = m.functionHandleAt(fh_idx);
    if (!m.isSelfHandle(fh.module)) return null;
    if (fh.type_parameters.len != 0) return null;
    for (m.function_defs, 0..) |d, i| {
        if (d.function != fh_idx or i == caller_def) continue;
        const cu = d.code orelse return null;
        if (d.acquires.len != 0) return null;
        if (cu.code.len < 1 or cu.code.len > max_callee_instructions) return null;
        if (cu.code[cu.code.len - 1].op != .Ret) return null;
        const params = m.signatureAt(fh.parameters);
        if (params.len > max_params) return null;
        for (cu.code, 0..) |ins, k| {
            switch (ins.op) {
                .Ret => if (k != cu.code.len - 1) return null,
                .Branch, .BrTrue, .BrFalse, .VariantSwitch, .Abort => return null,
                // direct recursion is left alone
                .Call => if (ins.idx == fh_idx) return null,
                else => {},
            }
        }
        return .{ .def = i, .params = params.len, .nlocals = m.signatureAt(cu.locals).len, .sig = params };
    }
    return null;
}

pub fn inlineModule(arena: Allocator, v: *const rw.Verifier, cur: *ff.CompiledModule, only_fn: ?[]const u8) !?Outcome {
    var m = cur.*;
    var applied: std.ArrayList(@import("optimize.zig").Applied) = .empty;
    var before_total: usize = 0;
    var after_total: usize = 0;
    const n_defs = m.function_defs.len;
    for (0..n_defs) |fi| {
        const fd = m.function_defs[fi];
        const cu = fd.code orelse continue;
        const fname = m.identifierAt(m.functionHandleAt(fd.function).name);
        if (only_fn) |n| if (!std.mem.eql(u8, n, fname)) continue;
        const fh = m.functionHandleAt(fd.function);
        const base_params = m.signatureAt(fh.parameters);
        const base_locals = m.signatureAt(cu.locals);
        var next_local: usize = base_params.len + base_locals.len;
        var extra: std.ArrayList(ff.Token) = .empty;
        var edits: std.ArrayList(rw.Edit) = .empty;
        for (cu.code, 0..) |ins, i| {
            if (ins.op != .Call) continue;
            const ce = calleeOf(&m, ins.idx, fi) orelse continue;
            const cd = m.function_defs[ce.def];
            const ccu = cd.code.?;
            const cfh = m.functionHandleAt(cd.function);
            const cparams = m.signatureAt(cfh.parameters);
            const clocals = m.signatureAt(ccu.locals);
            const total = cparams.len + clocals.len;
            if (next_local + total > 255) continue;
            const base: u16 = @intCast(next_local);
            var repl: std.ArrayList(Instr) = .empty;
            var p = cparams.len;
            while (p > 0) {
                p -= 1;
                try repl.append(arena, rw.insIdx(.StLoc, base + @as(u16, @intCast(p))));
            }
            for (ccu.code[0 .. ccu.code.len - 1]) |ci| {
                var x = ci;
                if (isLocalOp(x.op)) x.idx += base;
                try repl.append(arena, x);
            }
            try extra.appendSlice(arena, cparams);
            try extra.appendSlice(arena, clocals);
            next_local += total;
            try edits.append(arena, .{ .start = @intCast(i), .len = 1, .repl = repl.items });
        }
        if (edits.items.len == 0) continue;
        const new_code = rw.applyEdits(arena, .{ .code = cu.code, .jump_tables = cu.jump_tables }, edits.items) catch continue;
        // locals signature of the caller: its own locals, then every inlined callee's parameters and locals
        const sig = try arena.alloc(ff.Token, base_locals.len + extra.items.len);
        @memcpy(sig[0..base_locals.len], base_locals);
        @memcpy(sig[base_locals.len..], extra.items);
        if (m.signatures.len >= ff.TABLE_INDEX_MAX) continue;
        const sigs = try arena.alloc([]const ff.Token, m.signatures.len + 1);
        @memcpy(sigs[0..m.signatures.len], m.signatures);
        sigs[m.signatures.len] = sig;
        var trial = try rw.withFunction(arena, &m, fi, new_code);
        trial.signatures = sigs;
        const defs = try arena.dupe(ff.FunctionDefinition, trial.function_defs);
        var ncu = defs[fi].code.?;
        ncu.locals = @intCast(m.signatures.len);
        defs[fi].code = ncu;
        trial.function_defs = defs;
        if ((try v.check(arena, &trial)) != .ok) continue;
        before_total += cu.code.len;
        after_total += new_code.code.len;
        m = trial;
        try applied.append(arena, .{ .pass = "inline", .rounds = @intCast(edits.items.len), .saved_instructions = @as(i64, @intCast(cu.code.len)) - @as(i64, @intCast(new_code.code.len)) });
    }
    if (applied.items.len == 0) return null;
    return .{ .module = m, .before = before_total, .after = after_total, .applied = applied.items };
}
