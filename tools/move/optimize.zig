//! Bytecode-to-bytecode optimizer. Passes run per function over deepwave's move-format
//! module; every pass application is checked by the Move and Sui verifiers (move-format/verifier)
//! on the whole module, and a pass whose result fails verification is rejected and reported, never
//! emitted. Output is the optimized module in Move binary format and a JSON report with the
//! instruction counts before and after (Sui's computation gas is charged per instruction executed,
//! so fewer instructions on a path is less gas) and which passes applied.
//!
//! Passes (names for --passes, default all):
//!   thread       branch to a branch retargeted, branch to Ret/Abort replaced by it
//!   const-fold   LdU* a; LdU* b; op -> constant; LdTrue; Not ...; casts of constants
//!   bool-branch  LdTrue; BrTrue -> Branch (and the three other constant conditions)
//!   not-branch   Not; BrTrue -> BrFalse (and back)
//!   const-pop    a constant or a pure load followed by Pop
//!   identity     x + 0, x - 0, x | 0, x ^ 0, x << 0, x >> 0, x * 1, x / 1 with a constant operand
//!   borrow-read  ImmBorrowLoc; ReadRef -> CopyLoc, FreezeRef; ReadRef -> ReadRef
//!   copy-store   MoveLoc x; StLoc x and CopyLoc x; StLoc x removed
//!   nop          Nop removal
//!   branch-next  Branch to the next instruction removed
//!   dead         unreachable code removed
//!   inline       small straight-line functions of the same module inlined at their call sites
//!
//! Suggested changes with evidence, never silent rewrites: `deepwave-move equiv` proves the result against
//! recorded calls.
const std = @import("std");
const common = @import("common.zig");
const rw = @import("rewrite.zig");
const inl = @import("inline.zig");
const mf = @import("move_format");

const Allocator = std.mem.Allocator;
const ff = common.ff;
const Instr = ff.Instr;
const Op = ff.Opcode;
const Code = rw.Code;
const Edit = rw.Edit;

pub const Pass = enum { thread, @"const-fold", @"bool-branch", @"not-branch", @"const-pop", identity, @"borrow-read", @"copy-store", nop, @"branch-next", dead, inline_calls };

pub const pass_names = [_][]const u8{ "thread", "const-fold", "bool-branch", "not-branch", "const-pop", "identity", "borrow-read", "copy-store", "nop", "branch-next", "dead", "inline" };

pub fn passByName(n: []const u8) ?Pass {
    inline for (pass_names, 0..) |name, i| if (std.mem.eql(u8, n, name)) return @enumFromInt(i);
    return null;
}

pub const PassSet = std.EnumSet(Pass);

fn isConstLoad(op: Op) bool {
    return switch (op) {
        .LdU8, .LdU16, .LdU32, .LdU64, .LdTrue, .LdFalse, .LdU128, .LdU256, .LdConst => true,
        else => false,
    };
}

fn widthOf(op: Op) ?u7 {
    return switch (op) {
        .LdU8 => 8,
        .LdU16 => 16,
        .LdU32 => 32,
        .LdU64 => 64,
        else => null,
    };
}

fn maxOf(w: u7) u128 {
    return (@as(u128, 1) << w) - 1;
}

fn mkLd(w: u7, v: u128) Instr {
    const op: Op = switch (w) {
        8 => .LdU8,
        16 => .LdU16,
        32 => .LdU32,
        else => .LdU64,
    };
    return rw.insImm(op, @intCast(v));
}

fn boolIns(b: bool) Instr {
    return rw.ins0(if (b) .LdTrue else .LdFalse);
}

fn isBoolLd(op: Op) bool {
    return op == .LdTrue or op == .LdFalse;
}

/// A window starting at `i` for the enabled passes, or null. Interior offsets must not be jump targets.
fn matchAt(arena: Allocator, c: Code, targets: []const bool, i: usize, set: PassSet) Allocator.Error!?Edit {
    const code = c.code;
    const a = code[i];
    const have2 = i + 1 < code.len and !targets[i + 1];
    const b: Instr = if (have2) code[i + 1] else rw.ins0(.Nop);
    const have3 = have2 and i + 2 < code.len and !targets[i + 2];
    const d: Instr = if (have3) code[i + 2] else rw.ins0(.Nop);

    if (set.contains(.nop) and a.op == .Nop) return .{ .start = @intCast(i), .len = 1, .repl = &.{} };
    if (set.contains(.@"branch-next") and a.op == .Branch and a.idx == i + 1) return .{ .start = @intCast(i), .len = 1, .repl = &.{} };

    if (have2) {
        // constant / pure load, Pop
        if (set.contains(.@"const-pop") and b.op == .Pop) {
            if (isConstLoad(a.op) or a.op == .CopyLoc or a.op == .ImmBorrowLoc or a.op == .MutBorrowLoc) return .{ .start = @intCast(i), .len = 2, .repl = &.{} };
        }
        // constant condition
        if (set.contains(.@"bool-branch") and isBoolLd(a.op) and (b.op == .BrTrue or b.op == .BrFalse)) {
            const v = a.op == .LdTrue;
            const taken = (b.op == .BrTrue) == v;
            if (taken) {
                const r = try arena.dupe(Instr, &.{rw.insIdx(.Branch, b.idx)});
                return .{ .start = @intCast(i), .len = 2, .repl = r };
            }
            return .{ .start = @intCast(i), .len = 2, .repl = &.{} };
        }
        if (set.contains(.@"not-branch") and a.op == .Not and (b.op == .BrTrue or b.op == .BrFalse)) {
            const r = try arena.dupe(Instr, &.{rw.insIdx(if (b.op == .BrTrue) .BrFalse else .BrTrue, b.idx)});
            return .{ .start = @intCast(i), .len = 2, .repl = r };
        }
        // folds of unary ops on constants
        if (set.contains(.@"const-fold")) {
            if (isBoolLd(a.op) and b.op == .Not) {
                const r = try arena.dupe(Instr, &.{boolIns(a.op != .LdTrue)});
                return .{ .start = @intCast(i), .len = 2, .repl = r };
            }
            if (widthOf(a.op)) |w| {
                const to: ?u7 = switch (b.op) {
                    .CastU8 => 8,
                    .CastU16 => 16,
                    .CastU32 => 32,
                    .CastU64 => 64,
                    else => null,
                };
                if (to) |tw| {
                    if (a.imm <= maxOf(tw)) {
                        _ = w;
                        const r = try arena.dupe(Instr, &.{mkLd(tw, a.imm)});
                        return .{ .start = @intCast(i), .len = 2, .repl = r };
                    }
                }
            }
        }
        if (set.contains(.@"borrow-read") and b.op == .ReadRef and (a.op == .ImmBorrowLoc or a.op == .MutBorrowLoc)) {
            const r = try arena.dupe(Instr, &.{rw.insIdx(.CopyLoc, a.idx)});
            return .{ .start = @intCast(i), .len = 2, .repl = r };
        }
        if (set.contains(.@"borrow-read") and a.op == .FreezeRef and b.op == .ReadRef) {
            const r = try arena.dupe(Instr, &.{b});
            return .{ .start = @intCast(i), .len = 2, .repl = r };
        }
        if (set.contains(.@"copy-store")) {
            if ((a.op == .MoveLoc or a.op == .CopyLoc) and b.op == .StLoc and a.idx == b.idx) return .{ .start = @intCast(i), .len = 2, .repl = &.{} };
        }
        // identity with a constant right operand
        if (set.contains(.identity)) {
            if (widthOf(a.op)) |w| {
                const zero_neutral = switch (b.op) {
                    .Add, .Sub, .BitOr, .Xor => true,
                    else => false,
                };
                const one_neutral = b.op == .Mul or b.op == .Div;
                if ((zero_neutral and a.imm == 0) or (one_neutral and a.imm == 1)) {
                    _ = w;
                    return .{ .start = @intCast(i), .len = 2, .repl = &.{} };
                }
                // shifts: the amount is a u8 constant
                if ((b.op == .Shl or b.op == .Shr) and a.op == .LdU8 and a.imm == 0) return .{ .start = @intCast(i), .len = 2, .repl = &.{} };
            }
        }
    }

    if (have3 and set.contains(.@"const-fold")) {
        // binary folds on two constants of the same width
        if (widthOf(a.op)) |w| {
            if (a.op == b.op) {
                const x: u128 = a.imm;
                const y: u128 = b.imm;
                const m = maxOf(w);
                var res: ?Instr = null;
                switch (d.op) {
                    .Add => if (x + y <= m) {
                        res = mkLd(w, x + y);
                    },
                    .Sub => if (x >= y) {
                        res = mkLd(w, x - y);
                    },
                    .Mul => if (x * y <= m) {
                        res = mkLd(w, x * y);
                    },
                    .Div => if (y != 0) {
                        res = mkLd(w, x / y);
                    },
                    .Mod => if (y != 0) {
                        res = mkLd(w, x % y);
                    },
                    .BitOr => res = mkLd(w, x | y),
                    .BitAnd => res = mkLd(w, x & y),
                    .Xor => res = mkLd(w, x ^ y),
                    .Lt => res = boolIns(x < y),
                    .Gt => res = boolIns(x > y),
                    .Le => res = boolIns(x <= y),
                    .Ge => res = boolIns(x >= y),
                    .Eq => res = boolIns(x == y),
                    .Neq => res = boolIns(x != y),
                    else => {},
                }
                if (res) |r| return .{ .start = @intCast(i), .len = 3, .repl = try arena.dupe(Instr, &.{r}) };
            }
            // shifts: u8 amount
            if (b.op == .LdU8 and (d.op == .Shl or d.op == .Shr)) {
                const x: u128 = a.imm;
                if (b.imm < w) {
                    const sh: u7 = @intCast(b.imm);
                    const v: u128 = if (d.op == .Shl) (x << sh) & maxOf(w) else x >> sh;
                    return .{ .start = @intCast(i), .len = 3, .repl = try arena.dupe(Instr, &.{mkLd(w, v)}) };
                }
            }
        }
        if (isBoolLd(a.op) and isBoolLd(b.op)) {
            const x = a.op == .LdTrue;
            const y = b.op == .LdTrue;
            const r: ?bool = switch (d.op) {
                .And => x and y,
                .Or => x or y,
                .Eq => x == y,
                .Neq => x != y,
                else => null,
            };
            if (r) |v| return .{ .start = @intCast(i), .len = 3, .repl = try arena.dupe(Instr, &.{boolIns(v)}) };
        }
    }
    return null;
}

/// One sweep of window passes: greedy, left to right, non-overlapping.
fn sweep(arena: Allocator, c: Code, set: PassSet) Allocator.Error!?Code {
    const targets = try rw.jumpTargets(arena, c);
    var edits: std.ArrayList(Edit) = .empty;
    var i: usize = 0;
    while (i < c.code.len) {
        if (try matchAt(arena, c, targets, i, set)) |e| {
            try edits.append(arena, e);
            i += e.len;
        } else i += 1;
    }
    if (edits.items.len == 0) return null;
    return rw.applyEdits(arena, c, edits.items) catch null;
}

/// Branch threading: a branch whose target is an unconditional branch jumps to its target; an
/// unconditional branch to Ret or Abort becomes that instruction.
fn threadBranches(arena: Allocator, c: Code) Allocator.Error!?Code {
    const out = try arena.dupe(Instr, c.code);
    var changed = false;
    for (out) |*ins| {
        if (!ins.op.hasOffset()) continue;
        var t: u16 = ins.idx;
        var hops: u8 = 0;
        while (hops < 8 and t < c.code.len and c.code[t].op == .Branch and c.code[t].idx != t) : (hops += 1) t = c.code[t].idx;
        if (t != ins.idx) {
            ins.idx = t;
            changed = true;
        }
        if (ins.op == .Branch and ins.idx < c.code.len) {
            const tgt = c.code[ins.idx];
            if (tgt.op == .Ret or tgt.op == .Abort) {
                ins.* = tgt;
                changed = true;
            }
        }
    }
    if (!changed) return null;
    return .{ .code = out, .jump_tables = c.jump_tables };
}

fn removeDead(arena: Allocator, c: Code) Allocator.Error!?Code {
    const r = try rw.reachable(arena, c);
    var edits: std.ArrayList(Edit) = .empty;
    var i: usize = 0;
    while (i < r.len) {
        if (r[i]) {
            i += 1;
            continue;
        }
        var j = i;
        while (j < r.len and !r[j]) j += 1;
        try edits.append(arena, .{ .start = @intCast(i), .len = @intCast(j - i), .repl = &.{} });
        i = j;
    }
    if (edits.items.len == 0) return null;
    return rw.applyEdits(arena, c, edits.items) catch null;
}

pub const Applied = struct { pass: []const u8, rounds: u32, saved_instructions: i64 };
pub const Rejected = struct { pass: []const u8, reason: []const u8 };

pub const FnReport = struct {
    module: []const u8,
    function: []const u8,
    before: usize,
    after: usize,
    applied: []const Applied = &.{},
    rejected: []const Rejected = &.{},
};

pub const Result = struct {
    module: ff.CompiledModule,
    functions: []const FnReport,
    original_verifies: bool,
};

const order = [_]Pass{ .thread, .@"const-fold", .@"bool-branch", .@"not-branch", .@"const-pop", .identity, .@"borrow-read", .@"copy-store", .nop, .@"branch-next", .dead };

fn applyPass(arena: Allocator, p: Pass, c: Code) Allocator.Error!?Code {
    return switch (p) {
        .thread => threadBranches(arena, c),
        .dead => removeDead(arena, c),
        .inline_calls => null,
        else => sweep(arena, c, PassSet.initOne(p)),
    };
}

/// Optimizes every function of `m` with the passes in `enabled`. A rewrite is kept only if the
/// whole module still verifies. `only_fn` limits the work to one function.
pub fn optimizeModule(arena: Allocator, v: *const rw.Verifier, m: *const ff.CompiledModule, enabled: PassSet, only_fn: ?[]const u8) !Result {
    var cur = m.*;
    const orig_ok = (try v.check(arena, m)) == .ok;
    var reports: std.ArrayList(FnReport) = .empty;
    const mname = m.selfName();

    if (enabled.contains(.inline_calls)) {
        if (try inl.inlineModule(arena, v, &cur, only_fn)) |res| {
            cur = res.module;
            try reports.append(arena, .{ .module = mname, .function = "<inline>", .before = res.before, .after = res.after, .applied = res.applied });
        }
    }

    for (cur.function_defs, 0..) |fd, fi| {
        const cu = fd.code orelse continue;
        const fname = cur.identifierAt(cur.functionHandleAt(fd.function).name);
        if (only_fn) |n| if (!std.mem.eql(u8, n, fname)) continue;
        var code: Code = .{ .code = cu.code, .jump_tables = cu.jump_tables };
        const before = code.code.len;
        var applied: std.ArrayList(Applied) = .empty;
        var rejected: std.ArrayList(Rejected) = .empty;
        var banned = PassSet.empty;
        var cycle: u32 = 0;
        while (cycle < 6) : (cycle += 1) {
            var any = false;
            for (order) |p| {
                if (!enabled.contains(p) or banned.contains(p)) continue;
                var rounds: u32 = 0;
                const start_len = code.code.len;
                while (rounds < 16) : (rounds += 1) {
                    const next = (try applyPass(arena, p, code)) orelse break;
                    const trial = try rw.withFunction(arena, &cur, fi, next);
                    switch (try v.check(arena, &trial)) {
                        .ok => {
                            code = next;
                            any = true;
                        },
                        .move => |msg| {
                            try rejected.append(arena, .{ .pass = pass_names[@intFromEnum(p)], .reason = msg });
                            banned.insert(p);
                            break;
                        },
                        .sui => |msg| {
                            try rejected.append(arena, .{ .pass = pass_names[@intFromEnum(p)], .reason = msg });
                            banned.insert(p);
                            break;
                        },
                    }
                }
                if (rounds > 0) try applied.append(arena, .{ .pass = pass_names[@intFromEnum(p)], .rounds = rounds, .saved_instructions = @as(i64, @intCast(start_len)) - @as(i64, @intCast(code.code.len)) });
            }
            if (!any) break;
        }
        if (code.code.len != before or !std.mem.eql(u8, std.mem.sliceAsBytes(code.code), std.mem.sliceAsBytes(cu.code))) {
            cur = try rw.withFunction(arena, &cur, fi, code);
        }
        try reports.append(arena, .{ .module = mname, .function = fname, .before = before, .after = code.code.len, .applied = applied.items, .rejected = rejected.items });
    }
    return .{ .module = cur, .functions = reports.items, .original_verifies = orig_ok };
}

pub fn parsePasses(text: ?[]const u8) !PassSet {
    // `inline` is opt-in: its gain is measured by `equiv`, not guaranteed.
    const t = text orelse {
        var all = PassSet.full;
        all.remove(.inline_calls);
        return all;
    };
    var set = PassSet.empty;
    var it = std.mem.tokenizeScalar(u8, t, ',');
    while (it.next()) |n| set.insert(passByName(n) orelse return error.UnknownPass);
    return set;
}

pub fn run(ctx: *common.Ctx) !u8 {
    const arena = ctx.arena;
    const enabled = try parsePasses(ctx.opts.get("--passes"));
    const v = try rw.Verifier.init(try common.protocolOpt(ctx.opts));
    const only_fn = ctx.opts.get("--function");

    var name: []const u8 = "";
    var cm: ff.CompiledModule = undefined;
    var raw_len: usize = 0;
    if (ctx.opts.get("--module-file")) |path| {
        const raw = try std.Io.Dir.cwd().readFileAlloc(ctx.io, path, arena, .limited(16 << 20));
        raw_len = raw.len;
        switch (try mf.deserialize(arena, raw, &.{})) {
            .ok => |m| cm = m,
            .err => return error.BadModule,
        }
        name = cm.selfName();
    } else {
        const dir = ctx.opts.get("--dir") orelse return error.MissingDir;
        const pid = try common.parseId(ctx.opts.get("--package") orelse return error.MissingPackage);
        const mod = ctx.opts.get("--module") orelse return error.MissingModule;
        var o = try common.openNode(ctx.gpa, ctx.io, arena, dir);
        defer o.close();
        var snap = o.st.snapshot();
        defer snap.release();
        const pkg = try common.loadPackage(arena, &snap, &pid);
        const lm = common.moduleByName(&pkg, mod) orelse return error.ModuleNotFound;
        cm = lm.cm;
        raw_len = lm.raw.len;
        name = lm.name;
    }

    const res = try optimizeModule(arena, &v, &cm, enabled, only_fn);
    const out_bytes = try mf.serializeAlloc(arena, &res.module, cm.version);
    if (ctx.opts.get("--out")) |path| {
        try std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = path, .data = out_bytes });
    }

    // module totals come from the modules themselves; the '<inline>' pseudo-row (callers before
    // inlining) would double-count if summed
    var before_total: usize = 0;
    var after_total: usize = 0;
    for (cm.function_defs) |fd| if (fd.code) |cu| {
        before_total += cu.code.len;
    };
    for (res.module.function_defs) |fd| if (fd.code) |cu| {
        after_total += cu.code.len;
    };
    var j: common.Json = .{ .w = ctx.w };
    try j.beginObj();
    try j.str("module", name);
    try j.boolean("original_verifies", res.original_verifies);
    try j.int("module_bytes_before", raw_len);
    try j.int("module_bytes_after", out_bytes.len);
    try j.int("instructions_before", before_total);
    try j.int("instructions_after", after_total);
    try j.arrIn("functions");
    for (res.functions) |f| {
        if (f.before == f.after and f.rejected.len == 0 and f.applied.len == 0) continue;
        try j.beginObj();
        try j.str("function", f.function);
        try j.int("instructions_before", f.before);
        try j.int("instructions_after", f.after);
        try j.arrIn("applied");
        for (f.applied) |a| {
            try j.beginObj();
            try j.str("pass", a.pass);
            try j.int("rounds", a.rounds);
            try j.int("saved_instructions", a.saved_instructions);
            try j.endObj();
        }
        try j.endArr();
        try j.arrIn("rejected_by_verifier");
        for (f.rejected) |r| {
            try j.beginObj();
            try j.str("pass", r.pass);
            try j.str("reason", r.reason);
            try j.endObj();
        }
        try j.endArr();
        try j.endObj();
    }
    try j.endArr();
    try j.endObj();
    try ctx.w.writeByte('\n');
    return 0;
}

fn testCode(a: Allocator, instrs: []const Instr) Code {
    _ = a;
    return .{ .code = instrs, .jump_tables = &.{} };
}

test "constant folding keeps overflow and division by zero" {
    var st: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const fold = PassSet.initOne(.@"const-fold");
    const ok = (try sweep(a, testCode(a, &.{ rw.insImm(.LdU64, 2), rw.insImm(.LdU64, 3), rw.ins0(.Add), rw.ins0(.Ret) }), fold)).?;
    try std.testing.expectEqual(@as(usize, 2), ok.code.len);
    try std.testing.expectEqual(@as(u64, 5), ok.code[0].imm);
    // 200 + 100 overflows u8: it aborts at run time, so it must stay
    try std.testing.expect((try sweep(a, testCode(a, &.{ rw.insImm(.LdU8, 200), rw.insImm(.LdU8, 100), rw.ins0(.Add), rw.ins0(.Ret) }), fold)) == null);
    try std.testing.expect((try sweep(a, testCode(a, &.{ rw.insImm(.LdU64, 1), rw.insImm(.LdU64, 0), rw.ins0(.Div), rw.ins0(.Ret) }), fold)) == null);
    // shifts by the width abort
    try std.testing.expect((try sweep(a, testCode(a, &.{ rw.insImm(.LdU8, 1), rw.insImm(.LdU8, 8), rw.ins0(.Shl), rw.ins0(.Ret) }), fold)) == null);
    const sh = (try sweep(a, testCode(a, &.{ rw.insImm(.LdU8, 0x81), rw.insImm(.LdU8, 1), rw.ins0(.Shl), rw.ins0(.Ret) }), fold)).?;
    try std.testing.expectEqual(@as(u64, 0x02), sh.code[0].imm);
}

test "window passes respect jump targets inside the window" {
    var st: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const pop = PassSet.initOne(.@"const-pop");
    // a branch lands on the Pop: the pair must stay
    const code = [_]Instr{ rw.insIdx(.BrTrue, 3), rw.insImm(.LdU64, 7), rw.ins0(.Nop), rw.ins0(.Pop), rw.ins0(.Ret) };
    try std.testing.expect((try sweep(a, testCode(a, &code), pop)) == null);
    const plain = (try sweep(a, testCode(a, &.{ rw.insImm(.LdU64, 7), rw.ins0(.Pop), rw.ins0(.Ret) }), pop)).?;
    try std.testing.expectEqual(@as(usize, 1), plain.code.len);
}

test "constant conditions become branches and dead code goes" {
    var st: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    // 0: LdTrue 1: BrTrue 4 2: LdU64 9 3: Pop 4: Ret
    const code = [_]Instr{ rw.ins0(.LdTrue), rw.insIdx(.BrTrue, 4), rw.insImm(.LdU64, 9), rw.ins0(.Pop), rw.ins0(.Ret) };
    const b = (try sweep(a, testCode(a, &code), PassSet.initOne(.@"bool-branch"))).?;
    try std.testing.expectEqual(Op.Branch, b.code[0].op);
    try std.testing.expectEqual(@as(usize, 4), b.code.len);
    try std.testing.expectEqual(@as(u16, 3), b.code[0].idx);
    const d = (try removeDead(a, b)).?;
    try std.testing.expectEqual(@as(usize, 2), d.code.len);
    try std.testing.expectEqual(@as(u16, 1), d.code[0].idx);
}
