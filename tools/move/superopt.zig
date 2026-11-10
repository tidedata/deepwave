//! Superoptimizer search skeleton. A fast simulator for straight-line integer
//! and boolean Move bytecode ("microvm": u8 to u64 and bool values, locals read with CopyLoc, abort
//! on overflow, division by zero and over-wide shifts, exactly as the VM does) drives an enumerative
//! search for a shorter instruction sequence with the same observable behaviour: same values on the
//! stack, and an abort on exactly the inputs where the original aborts.
//!
//! Search: iterative deepening over a typed alphabet (CopyLoc of the window's locals, a pool of
//! constants, every operator, casts), pruned by static stack types and by early aborts on inputs
//! where the original does not abort, evaluated on a vector set of corner values plus random
//! inputs. A candidate that matches every vector is then checked on a much larger set (exhaustively
//! when the input space is at most 2^20 combinations) and reported with the strength of that check.
//! Nothing is applied unless `--out` is given, and then every rewritten function must pass the Move
//! and Sui verifiers; `deepwave-move equiv` adds differential execution on recorded calls.
//!
//! Modes:
//!   superopt --window "CopyLoc 0; LdU64 1; Mul" --params u64      one window given as text
//!   superopt --module-file F.mv [--function NAME] [--out OUT.mv]   every integer window of a module
//!   superopt --dir D --package 0xID --module NAME [--out OUT.mv]   the same on a package from the store
const std = @import("std");
const common = @import("common.zig");
const rw = @import("rewrite.zig");
const mf = @import("move_format");

const Allocator = std.mem.Allocator;
const ff = common.ff;
const Instr = ff.Instr;

pub const Ty = enum(u8) { b, u8, u16, u32, u64 };

fn width(t: Ty) u7 {
    return switch (t) {
        .b => 1,
        .u8 => 8,
        .u16 => 16,
        .u32 => 32,
        .u64 => 64,
    };
}
fn maxv(t: Ty) u64 {
    return if (t == .u64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(width(t))) - 1;
}
fn tyName(t: Ty) []const u8 {
    return switch (t) {
        .b => "bool",
        .u8 => "u8",
        .u16 => "u16",
        .u32 => "u32",
        .u64 => "u64",
    };
}

pub const Kind = enum { ld, copy, add, sub, mul, div, mod, bitor, bitand, xor, shl, shr, lt, gt, le, ge, eq, neq, and_, or_, not, cast, pop };

pub const MOp = struct {
    kind: Kind,
    ty: Ty = .u64,
    arg: u64 = 0,

    pub fn eql(a: MOp, b: MOp) bool {
        return a.kind == b.kind and a.ty == b.ty and a.arg == b.arg;
    }
};

pub const max_depth = 16;

const TyStack = struct {
    t: [max_depth]Ty = undefined,
    n: usize = 0,

    fn push(s: *TyStack, t: Ty) bool {
        if (s.n == max_depth) return false;
        s.t[s.n] = t;
        s.n += 1;
        return true;
    }
    fn eql(a: *const TyStack, b: *const TyStack) bool {
        return a.n == b.n and std.mem.eql(Ty, a.t[0..a.n], b.t[0..b.n]);
    }
};

/// Static typing of one operator on the type stack; false when ill-typed.
fn typeStep(s: *TyStack, op: MOp, params: []const Ty) bool {
    switch (op.kind) {
        .ld => return s.push(op.ty),
        .copy => return if (op.arg < params.len) s.push(params[@intCast(op.arg)]) else false,
        .add, .sub, .mul, .div, .mod, .bitor, .bitand, .xor => {
            if (s.n < 2) return false;
            const b = s.t[s.n - 1];
            const a = s.t[s.n - 2];
            if (a != b or a == .b) return false;
            s.n -= 1;
            return true;
        },
        .shl, .shr => {
            if (s.n < 2) return false;
            const b = s.t[s.n - 1];
            const a = s.t[s.n - 2];
            if (b != .u8 or a == .b) return false;
            s.n -= 1;
            return true;
        },
        .lt, .gt, .le, .ge => {
            if (s.n < 2) return false;
            const b = s.t[s.n - 1];
            const a = s.t[s.n - 2];
            if (a != b or a == .b) return false;
            s.n -= 2;
            return s.push(.b);
        },
        .eq, .neq => {
            if (s.n < 2) return false;
            if (s.t[s.n - 1] != s.t[s.n - 2]) return false;
            s.n -= 2;
            return s.push(.b);
        },
        .and_, .or_ => {
            if (s.n < 2) return false;
            if (s.t[s.n - 1] != .b or s.t[s.n - 2] != .b) return false;
            s.n -= 1;
            return true;
        },
        .not => return s.n >= 1 and s.t[s.n - 1] == .b,
        .cast => {
            if (s.n < 1 or s.t[s.n - 1] == .b or op.ty == .b) return false;
            s.t[s.n - 1] = op.ty;
            return true;
        },
        .pop => {
            if (s.n < 1) return false;
            s.n -= 1;
            return true;
        },
    }
}

/// One value-level step on a value stack whose types were checked; true: aborted.
fn valStep(v: []u64, sp: *usize, tys: *const TyStack, op: MOp, params_vals: []const u64) bool {
    switch (op.kind) {
        .ld => {
            v[sp.*] = op.arg;
            sp.* += 1;
        },
        .copy => {
            v[sp.*] = params_vals[@intCast(op.arg)];
            sp.* += 1;
        },
        .add, .sub, .mul, .div, .mod, .bitor, .bitand, .xor => {
            const ty = tys.t[tys.n - 1]; // type of the result: same as operands
            const b = v[sp.* - 1];
            const a = v[sp.* - 2];
            sp.* -= 1;
            const mx: u128 = maxv(ty);
            var r: u128 = 0;
            switch (op.kind) {
                .add => {
                    r = @as(u128, a) + b;
                    if (r > mx) return true;
                },
                .sub => {
                    if (a < b) return true;
                    r = a - b;
                },
                .mul => {
                    r = @as(u128, a) * b;
                    if (r > mx) return true;
                },
                .div => {
                    if (b == 0) return true;
                    r = a / b;
                },
                .mod => {
                    if (b == 0) return true;
                    r = a % b;
                },
                .bitor => r = a | b,
                .bitand => r = a & b,
                .xor => r = a ^ b,
                else => unreachable,
            }
            v[sp.* - 1] = @intCast(r);
        },
        .shl, .shr => {
            const ty = tys.t[tys.n - 2]; // the shifted value's type (the amount is a u8 on top)
            const b = v[sp.* - 1];
            const a = v[sp.* - 2];
            sp.* -= 1;
            if (b >= width(ty)) return true;
            const sh: u6 = @intCast(b);
            v[sp.* - 1] = if (op.kind == .shl) (a << sh) & maxv(ty) else a >> sh;
        },
        .lt, .gt, .le, .ge, .eq, .neq => {
            const b = v[sp.* - 1];
            const a = v[sp.* - 2];
            sp.* -= 1;
            const r = switch (op.kind) {
                .lt => a < b,
                .gt => a > b,
                .le => a <= b,
                .ge => a >= b,
                .eq => a == b,
                else => a != b,
            };
            v[sp.* - 1] = @intFromBool(r);
        },
        .and_ => {
            const b = v[sp.* - 1];
            sp.* -= 1;
            v[sp.* - 1] &= b;
        },
        .or_ => {
            const b = v[sp.* - 1];
            sp.* -= 1;
            v[sp.* - 1] |= b;
        },
        .not => v[sp.* - 1] ^= 1,
        .cast => if (v[sp.* - 1] > maxv(op.ty)) return true,
        .pop => sp.* -= 1,
    }
    return false;
}

pub const Run = struct { aborted: bool, sp: usize, vals: [max_depth]u64 };

/// Evaluates a sequence whose typing is already known good. `tys_per_step` recomputed here (cheap).
pub fn evalSeq(ops: []const MOp, params: []const Ty, pv: []const u64) Run {
    var r: Run = .{ .aborted = false, .sp = 0, .vals = undefined };
    var tys: TyStack = .{};
    for (ops) |op| {
        // value step needs the operand type: the pre-step type stack
        const pre = tys;
        if (!typeStep(&tys, op, params)) {
            r.aborted = true; // ill typed: treated as a non-match by callers (never equal)
            r.sp = max_depth;
            return r;
        }
        if (valStep(&r.vals, &r.sp, &pre, op, pv)) {
            r.aborted = true;
            return r;
        }
    }
    return r;
}

pub fn typeOf(ops: []const MOp, params: []const Ty) ?TyStack {
    var tys: TyStack = .{};
    for (ops) |op| if (!typeStep(&tys, op, params)) return null;
    return tys;
}

// ---------------------------------------------------------------------------------------------
// Text form

pub fn opText(arena: Allocator, op: MOp) ![]const u8 {
    return switch (op.kind) {
        .ld => if (op.ty == .b) (if (op.arg != 0) "LdTrue" else "LdFalse") else try std.fmt.allocPrint(arena, "Ld{s} {d}", .{ upperTy(op.ty), op.arg }),
        .copy => try std.fmt.allocPrint(arena, "CopyLoc {d}", .{op.arg}),
        .add => "Add",
        .sub => "Sub",
        .mul => "Mul",
        .div => "Div",
        .mod => "Mod",
        .bitor => "BitOr",
        .bitand => "BitAnd",
        .xor => "Xor",
        .shl => "Shl",
        .shr => "Shr",
        .lt => "Lt",
        .gt => "Gt",
        .le => "Le",
        .ge => "Ge",
        .eq => "Eq",
        .neq => "Neq",
        .and_ => "And",
        .or_ => "Or",
        .not => "Not",
        .cast => try std.fmt.allocPrint(arena, "Cast{s}", .{upperTy(op.ty)}),
        .pop => "Pop",
    };
}

fn upperTy(t: Ty) []const u8 {
    return switch (t) {
        .b => "Bool",
        .u8 => "U8",
        .u16 => "U16",
        .u32 => "U32",
        .u64 => "U64",
    };
}

pub fn seqText(arena: Allocator, ops: []const MOp) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (ops, 0..) |op, i| {
        if (i > 0) try out.appendSlice(arena, "; ");
        try out.appendSlice(arena, try opText(arena, op));
    }
    return out.items;
}

fn parseTy(s: []const u8) ?Ty {
    inline for (.{ .{ "bool", Ty.b }, .{ "u8", Ty.u8 }, .{ "u16", Ty.u16 }, .{ "u32", Ty.u32 }, .{ "u64", Ty.u64 } }) |p| if (std.mem.eql(u8, s, p[0])) return p[1];
    return null;
}

pub fn parseOps(arena: Allocator, text: []const u8) ![]MOp {
    var out: std.ArrayList(MOp) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, ';');
    while (it.next()) |part| {
        var toks = std.mem.tokenizeAny(u8, part, " \t");
        const name = toks.next() orelse continue;
        const arg = toks.next();
        const Entry = struct { []const u8, Kind };
        const simple = [_]Entry{
            .{ "Add", .add }, .{ "Sub", .sub }, .{ "Mul", .mul },       .{ "Div", .div },  .{ "Mod", .mod }, .{ "BitOr", .bitor }, .{ "BitAnd", .bitand }, .{ "Xor", .xor },
            .{ "Shl", .shl }, .{ "Shr", .shr }, .{ "Lt", .lt },         .{ "Gt", .gt },    .{ "Le", .le },   .{ "Ge", .ge },         .{ "Eq", .eq },         .{ "Neq", .neq },
            .{ "And", .and_ }, .{ "Or", .or_ }, .{ "Not", .not },       .{ "Pop", .pop },
        };
        var done = false;
        for (simple) |e| if (std.mem.eql(u8, name, e[0])) {
            try out.append(arena, .{ .kind = e[1] });
            done = true;
        };
        if (done) continue;
        if (std.mem.eql(u8, name, "LdTrue")) {
            try out.append(arena, .{ .kind = .ld, .ty = .b, .arg = 1 });
        } else if (std.mem.eql(u8, name, "LdFalse")) {
            try out.append(arena, .{ .kind = .ld, .ty = .b, .arg = 0 });
        } else if (std.mem.eql(u8, name, "CopyLoc")) {
            try out.append(arena, .{ .kind = .copy, .arg = try std.fmt.parseInt(u64, arg orelse return error.BadWindow, 10) });
        } else if (std.mem.startsWith(u8, name, "Ld")) {
            var lower: [8]u8 = undefined;
            const tn = std.ascii.lowerString(&lower, name[2..]);
            try out.append(arena, .{ .kind = .ld, .ty = parseTy(tn) orelse return error.BadWindow, .arg = try std.fmt.parseInt(u64, arg orelse return error.BadWindow, 10) });
        } else if (std.mem.startsWith(u8, name, "Cast")) {
            var lower: [8]u8 = undefined;
            const tn = std.ascii.lowerString(&lower, name[4..]);
            try out.append(arena, .{ .kind = .cast, .ty = parseTy(tn) orelse return error.BadWindow });
        } else return error.BadWindow;
    }
    return out.items;
}

// ---------------------------------------------------------------------------------------------
// Search

pub const Proof = struct {
    kind: enum { exhaustive, sampled },
    vectors: u64,
    ok: bool,
};

pub const Config = struct {
    max_len: usize = 4,
    /// Node expansions before the search gives up on a window.
    budget: u64 = 20_000_000,
    seed: u64 = 1,
    vectors: usize = 64,
    /// When set, `search` adds the node expansions it spent here (also when nothing is found).
    nodes_out: ?*u64 = null,
};

/// Constants of a window (and +1/-1 of each); mixed into every test-vector set so comparisons
/// against the window's own literals are exercised.
const ConstSet = struct {
    v: [32]u64 = undefined,
    n: usize = 0,
    fn add(c: *ConstSet, x: u64) void {
        for (c.v[0..c.n]) |y| if (y == x) return;
        if (c.n < c.v.len) {
            c.v[c.n] = x;
            c.n += 1;
        }
    }
    fn addOps(c: *ConstSet, ops: []const MOp) void {
        for (ops) |op| if (op.kind == .ld) {
            c.add(op.arg);
            c.add(op.arg +% 1);
            c.add(op.arg -% 1);
        };
    }
    fn pick(c: *const ConstSet, ty: Ty, i: usize) u64 {
        const x = c.v[i % c.n];
        return if (ty == .b) x & 1 else x & maxv(ty);
    }
};

const NV = 128;
const MAXD = 8;

const Rng = struct {
    s: u64,
    fn next(r: *Rng) u64 {
        r.s ^= r.s << 13;
        r.s ^= r.s >> 7;
        r.s ^= r.s << 17;
        return r.s;
    }
};

fn cornerVal(ty: Ty, r: *Rng, cs: *const ConstSet) u64 {
    const mx = maxv(ty);
    const pick = r.next() % 14;
    return switch (pick) {
        8, 9 => if (cs.n > 0) cs.pick(ty, @intCast(r.next() >> 8)) else if (ty == .b) r.next() & 1 else r.next() & mx,
        0 => 0,
        1 => 1,
        2 => 2,
        3 => mx,
        4 => mx - 1,
        5 => mx / 2,
        6 => mx / 2 + 1,
        7 => 3,
        else => if (ty == .b) r.next() & 1 else r.next() & mx,
    };
}

const Search = struct {
    params: []const Ty,
    nvec: usize,
    pvals: [NV][4]u64,
    target_ty: TyStack,
    t_abort: [NV]bool,
    t_vals: [NV][max_depth]u64,
    alphabet: []const MOp,
    budget: u64,
    nodes: u64 = 0,
    found: bool = false,
    seq: [MAXD]MOp = undefined,
    out_len: usize = 0,
    out: [MAXD]MOp = undefined,
    goal_len: usize = 0,

    fn dfs(s: *Search, len: usize, want: usize, tys: TyStack, vals: *const [NV][MAXD]u64, sps: *const [NV]u8, ab: *const [NV]bool) void {
        if (s.found or s.nodes > s.budget) return;
        if (len == want) {
            if (!tys.eql(&s.target_ty)) return;
            var v: usize = 0;
            while (v < s.nvec) : (v += 1) {
                if (ab[v] != s.t_abort[v]) return;
                if (!ab[v]) for (0..tys.n) |k| if (vals[v][k] != s.t_vals[v][k]) return;
            }
            s.found = true;
            s.out_len = len;
            @memcpy(s.out[0..len], s.seq[0..len]);
            return;
        }
        const remaining = want - len;
        for (s.alphabet) |op| {
            s.nodes += 1;
            if (s.nodes > s.budget) return;
            var nt = tys;
            if (!typeStep(&nt, op, s.params)) continue;
            // the stack must be able to reach the goal depth in the remaining steps
            const need = if (nt.n > s.target_ty.n) nt.n - s.target_ty.n else s.target_ty.n - nt.n;
            if (need > remaining - 1) continue;
            if (nt.n > MAXD) continue;
            var nvals: [NV][MAXD]u64 = undefined;
            var nsps: [NV]u8 = undefined;
            var nab: [NV]bool = undefined;
            var bad = false;
            var v: usize = 0;
            while (v < s.nvec) : (v += 1) {
                nab[v] = ab[v];
                nsps[v] = sps[v];
                if (ab[v]) continue;
                nvals[v] = vals[v];
                var sp: usize = sps[v];
                // operand types: the type stack before the step
                const ab_now = valStep(&nvals[v], &sp, &tys, op, &s.pvals[v]);
                nsps[v] = @intCast(sp);
                if (ab_now) {
                    if (!s.t_abort[v]) {
                        bad = true;
                        break;
                    }
                    nab[v] = true;
                }
            }
            if (bad) continue;
            s.seq[len] = op;
            s.dfs(len + 1, want, nt, &nvals, &nsps, &nab);
            if (s.found) return;
        }
    }
};

pub const Found = struct { ops: []const MOp, proof: Proof, nodes: u64 };

fn constPool(arena: Allocator, target: []const MOp, params: []const Ty) ![]MOp {
    var out: std.ArrayList(MOp) = .empty;
    var tys_used = std.EnumSet(Ty).empty;
    for (params) |t| tys_used.insert(t);
    for (target) |op| switch (op.kind) {
        .ld => tys_used.insert(op.ty),
        .cast => tys_used.insert(op.ty),
        else => {},
    };
    tys_used.insert(.u8); // shift amounts
    tys_used.insert(.b);
    var it = tys_used.iterator();
    while (it.next()) |t| {
        if (t == .b) {
            try out.append(arena, .{ .kind = .ld, .ty = .b, .arg = 0 });
            try out.append(arena, .{ .kind = .ld, .ty = .b, .arg = 1 });
            continue;
        }
        const base = [_]u64{ 0, 1, 2, maxv(t) };
        for (base) |c| try out.append(arena, .{ .kind = .ld, .ty = t, .arg = c });
        for (target) |op| if (op.kind == .ld and op.ty == t) {
            var dup = false;
            for (out.items) |x| if (x.kind == .ld and x.ty == t and x.arg == op.arg) {
                dup = true;
            };
            if (!dup) try out.append(arena, op);
        };
    }
    return out.items;
}

fn alphabetFor(arena: Allocator, target: []const MOp, params: []const Ty) ![]MOp {
    var al: std.ArrayList(MOp) = .empty;
    for (0..params.len) |i| try al.append(arena, .{ .kind = .copy, .arg = i });
    try al.appendSlice(arena, try constPool(arena, target, params));
    const bin = [_]Kind{ .add, .sub, .mul, .div, .mod, .bitor, .bitand, .xor, .shl, .shr, .lt, .gt, .le, .ge, .eq, .neq, .and_, .or_, .not };
    for (bin) |k| try al.append(arena, .{ .kind = k });
    for ([_]Ty{ .u8, .u16, .u32, .u64 }) |t| try al.append(arena, .{ .kind = .cast, .ty = t });
    return al.items;
}

/// Searches for a sequence strictly shorter than `target` with the same behaviour.
pub fn search(arena: Allocator, target: []const MOp, params: []const Ty, cfg: Config) !?Found {
    const goal = typeOf(target, params) orelse return error.IllTypedWindow;
    if (target.len < 2 or params.len > 4) return null;
    var s: Search = undefined;
    s.params = params;
    s.nvec = @min(cfg.vectors, NV);
    s.nodes = 0;
    s.budget = cfg.budget;
    s.found = false;
    s.target_ty = goal;
    s.alphabet = try alphabetFor(arena, target, params);
    defer if (cfg.nodes_out) |no| {
        no.* += s.nodes;
    };
    var cs: ConstSet = .{};
    cs.addOps(target);
    var rng: Rng = .{ .s = cfg.seed | 1 };
    var v: usize = 0;
    while (v < s.nvec) : (v += 1) {
        for (params, 0..) |t, k| s.pvals[v][k] = cornerVal(t, &rng, &cs);
        // deterministic coverage of the window's constants on the first parameter
        if (cs.n > 0 and params.len > 0 and v % 2 == 0) s.pvals[v][0] = cs.pick(params[0], v / 2);
        const r = evalSeq(target, params, &s.pvals[v]);
        s.t_abort[v] = r.aborted;
        s.t_vals[v] = r.vals;
    }
    var ab0: [NV]bool = @splat(false);
    var sp0: [NV]u8 = @splat(0);
    var vals0: [NV][MAXD]u64 = undefined;
    var want: usize = 1;
    while (want < target.len and want <= MAXD and want <= cfg.max_len) : (want += 1) {
        s.found = false;
        s.dfs(0, want, .{}, &vals0, &sp0, &ab0);
        if (s.found) {
            const cand = try arena.dupe(MOp, s.out[0..s.out_len]);
            const proof = prove(target, cand, params, cfg.seed ^ 0x9e3779b97f4a7c15);
            if (!proof.ok) {
                // a sampled mismatch: keep searching longer (rare: the vector set missed an input)
                continue;
            }
            return .{ .ops = cand, .proof = proof, .nodes = s.nodes };
        }
        if (s.nodes > s.budget) break;
    }
    return null;
}

/// Equivalence of `a` and `b` over all inputs when the total input width is at most 20 bits,
/// else on 2^20 sampled inputs (corner values, the windows' own constants and uniform ones).
/// Only an exhaustive proof is a proof; a sampled one is a suggestion.
pub fn prove(a: []const MOp, b: []const MOp, params: []const Ty, seed: u64) Proof {
    var bits: u32 = 0;
    for (params) |t| bits += width(t);
    var cs: ConstSet = .{};
    cs.addOps(a);
    cs.addOps(b);
    var pv: [4]u64 = @splat(0);
    if (bits <= 20) {
        const space: u64 = @as(u64, 1) << @intCast(bits);
        var n: u64 = 0;
        var idx: u64 = 0;
        while (idx < space) : (idx += 1) {
            var rest = idx;
            for (params, 0..) |t, k| {
                const w = width(t);
                pv[k] = rest & ((@as(u64, 1) << @intCast(w)) - 1);
                rest >>= @intCast(w);
            }
            n += 1;
            if (!sameRun(a, b, params, &pv)) return .{ .kind = .exhaustive, .vectors = n, .ok = false };
        }
        return .{ .kind = .exhaustive, .vectors = n, .ok = true };
    }
    var rng: Rng = .{ .s = seed | 1 };
    var n: u64 = 0;
    while (n < (1 << 20)) : (n += 1) {
        for (params, 0..) |t, k| pv[k] = if (rng.next() & 1 == 0) cornerVal(t, &rng, &cs) else (if (t == .b) rng.next() & 1 else rng.next() & maxv(t));
        if (!sameRun(a, b, params, &pv)) return .{ .kind = .sampled, .vectors = n + 1, .ok = false };
    }
    return .{ .kind = .sampled, .vectors = n, .ok = true };
}

fn sameRun(a: []const MOp, b: []const MOp, params: []const Ty, pv: []const u64) bool {
    const ra = evalSeq(a, params, pv);
    const rb = evalSeq(b, params, pv);
    if (ra.aborted != rb.aborted) return false;
    if (ra.aborted) return true;
    if (ra.sp != rb.sp) return false;
    return std.mem.eql(u64, ra.vals[0..ra.sp], rb.vals[0..rb.sp]);
}

// ---------------------------------------------------------------------------------------------
// Bytecode windows

fn tokenTy(t: ff.Token) ?Ty {
    return switch (t[0].tag) {
        .Bool => .b,
        .U8 => .u8,
        .U16 => .u16,
        .U32 => .u32,
        .U64 => .u64,
        else => null,
    };
}

fn toMOp(ins: Instr) ?MOp {
    return switch (ins.op) {
        .LdU8 => .{ .kind = .ld, .ty = .u8, .arg = ins.imm },
        .LdU16 => .{ .kind = .ld, .ty = .u16, .arg = ins.imm },
        .LdU32 => .{ .kind = .ld, .ty = .u32, .arg = ins.imm },
        .LdU64 => .{ .kind = .ld, .ty = .u64, .arg = ins.imm },
        .LdTrue => .{ .kind = .ld, .ty = .b, .arg = 1 },
        .LdFalse => .{ .kind = .ld, .ty = .b, .arg = 0 },
        .CopyLoc => .{ .kind = .copy, .arg = ins.idx },
        .Add => .{ .kind = .add },
        .Sub => .{ .kind = .sub },
        .Mul => .{ .kind = .mul },
        .Div => .{ .kind = .div },
        .Mod => .{ .kind = .mod },
        .BitOr => .{ .kind = .bitor },
        .BitAnd => .{ .kind = .bitand },
        .Xor => .{ .kind = .xor },
        .Shl => .{ .kind = .shl },
        .Shr => .{ .kind = .shr },
        .Lt => .{ .kind = .lt },
        .Gt => .{ .kind = .gt },
        .Le => .{ .kind = .le },
        .Ge => .{ .kind = .ge },
        .Eq => .{ .kind = .eq },
        .Neq => .{ .kind = .neq },
        .And => .{ .kind = .and_ },
        .Or => .{ .kind = .or_ },
        .Not => .{ .kind = .not },
        .CastU8 => .{ .kind = .cast, .ty = .u8 },
        .CastU16 => .{ .kind = .cast, .ty = .u16 },
        .CastU32 => .{ .kind = .cast, .ty = .u32 },
        .CastU64 => .{ .kind = .cast, .ty = .u64 },
        else => null,
    };
}

fn toInstr(op: MOp, real_local: []const u16) Instr {
    return switch (op.kind) {
        .ld => switch (op.ty) {
            .b => rw.ins0(if (op.arg != 0) .LdTrue else .LdFalse),
            .u8 => rw.insImm(.LdU8, op.arg),
            .u16 => rw.insImm(.LdU16, op.arg),
            .u32 => rw.insImm(.LdU32, op.arg),
            .u64 => rw.insImm(.LdU64, op.arg),
        },
        .copy => rw.insIdx(.CopyLoc, real_local[@intCast(op.arg)]),
        .add => rw.ins0(.Add),
        .sub => rw.ins0(.Sub),
        .mul => rw.ins0(.Mul),
        .div => rw.ins0(.Div),
        .mod => rw.ins0(.Mod),
        .bitor => rw.ins0(.BitOr),
        .bitand => rw.ins0(.BitAnd),
        .xor => rw.ins0(.Xor),
        .shl => rw.ins0(.Shl),
        .shr => rw.ins0(.Shr),
        .lt => rw.ins0(.Lt),
        .gt => rw.ins0(.Gt),
        .le => rw.ins0(.Le),
        .ge => rw.ins0(.Ge),
        .eq => rw.ins0(.Eq),
        .neq => rw.ins0(.Neq),
        .and_ => rw.ins0(.And),
        .or_ => rw.ins0(.Or),
        .not => rw.ins0(.Not),
        .cast => rw.ins0(switch (op.ty) {
            .u8 => .CastU8,
            .u16 => .CastU16,
            .u32 => .CastU32,
            else => .CastU64,
        }),
        .pop => rw.ins0(.Pop),
    };
}

pub const Improvement = struct {
    module: []const u8,
    function: []const u8,
    fdef: usize,
    start: u32,
    len: u32,
    window: []const u8,
    replacement: []const u8,
    repl: []const Instr,
    proof: Proof,
};

pub const ModuleResult = struct {
    improvements: []const Improvement,
    windows_tried: u64,
    nodes: u64,
    module: ff.CompiledModule,
    applied: u32,
    rejected_by_verifier: u32,
};

const max_window = 10;
/// Total node expansions per module in module mode.
const module_budget: u64 = 400_000_000;

/// Finds improvements in every function of `m` (or just `only_fn`); with `apply`, rewrites the
/// functions whose result still verifies.
pub fn searchModule(arena: Allocator, v: *const rw.Verifier, m: *const ff.CompiledModule, only_fn: ?[]const u8, cfg: Config, apply: bool) !ModuleResult {
    var imps: std.ArrayList(Improvement) = .empty;
    var tried: u64 = 0;
    var nodes: u64 = 0;
    var cur = m.*;
    var applied: u32 = 0;
    var rejected: u32 = 0;
    var cache: std.StringHashMapUnmanaged(?Found) = .empty;
    var spent: u64 = 0;
    var wcfg = cfg;
    wcfg.nodes_out = &spent;
    const mname = m.selfName();
    for (m.function_defs, 0..) |fd, fi| {
        const cu = fd.code orelse continue;
        const fh = m.functionHandleAt(fd.function);
        const fname = m.identifierAt(fh.name);
        if (only_fn) |n| if (!std.mem.eql(u8, n, fname)) continue;
        const ptoks = m.signatureAt(fh.parameters);
        const ltoks = m.signatureAt(cu.locals);
        const targets = try rw.jumpTargets(arena, .{ .code = cu.code, .jump_tables = cu.jump_tables });
        var edits: std.ArrayList(rw.Edit) = .empty;
        var fn_imps: std.ArrayList(Improvement) = .empty;
        var s: usize = 0;
        while (s < cu.code.len) {
            // grow a window [s, e) of supported instructions, depth never negative
            var best: ?struct { e: usize, found: Found, real: []const u16, ops: []const MOp } = null;
            var tys: TyStack = .{};
            var e = s;
            var used: std.ArrayList(u16) = .empty;
            var ops: std.ArrayList(MOp) = .empty;
            while (e < cu.code.len and e - s < max_window) {
                if (e > s and targets[e]) break;
                const mo = toMOp(cu.code[e]) orelse break;
                var op = mo;
                if (op.kind == .copy) {
                    const li = op.arg;
                    const lt: ?Ty = if (li < ptoks.len) tokenTy(ptoks[li]) else if (li - ptoks.len < ltoks.len) tokenTy(ltoks[li - ptoks.len]) else null;
                    if (lt == null) break;
                    // dense index into `used`
                    var di: ?usize = null;
                    for (used.items, 0..) |u, k| if (u == li) {
                        di = k;
                    };
                    if (di == null) {
                        if (used.items.len == 4) break;
                        try used.append(arena, @intCast(li));
                        di = used.items.len - 1;
                    }
                    op.arg = di.?;
                }
                // typing against the dense params
                const ptys = try arena.alloc(Ty, used.items.len);
                for (used.items, ptys) |u, *o| o.* = if (u < ptoks.len) tokenTy(ptoks[u]).? else tokenTy(ltoks[u - ptoks.len]).?;
                if (!typeStep(&tys, op, ptys)) break;
                try ops.append(arena, op);
                e += 1;
                if (ops.items.len >= 2 and tys.n >= 1) {
                    const key = try std.fmt.allocPrint(arena, "{s}|{any}", .{ try seqText(arena, ops.items), ptys });
                    var res: ?Found = undefined;
                    if (cache.get(key)) |c| {
                        res = c;
                    } else {
                        tried += 1;
                        // total node budget per module: past it, windows are no longer searched
                        res = if (spent >= module_budget) null else try search(arena, ops.items, ptys, wcfg);
                        nodes = spent;
                        try cache.put(arena, key, res);
                    }
                    if (res) |f| {
                        const saved = ops.items.len - f.ops.len;
                        const prev_saved: usize = if (best) |b| b.ops.len - b.found.ops.len else 0;
                        if (saved > prev_saved) best = .{ .e = e, .found = f, .real = try arena.dupe(u16, used.items), .ops = try arena.dupe(MOp, ops.items) };
                    }
                }
            }
            if (best) |b| {
                var repl: std.ArrayList(Instr) = .empty;
                for (b.found.ops) |op| try repl.append(arena, toInstr(op, b.real));
                const imp: Improvement = .{ .module = mname, .function = fname, .fdef = fi, .start = @intCast(s), .len = @intCast(b.e - s), .window = try seqTextReal(arena, b.ops, b.real), .replacement = try seqTextReal(arena, b.found.ops, b.real), .repl = repl.items, .proof = b.found.proof };
                try fn_imps.append(arena, imp);
                // only exhaustive proofs are applied; sampled ones stay suggestions
                if (b.found.proof.kind == .exhaustive) try edits.append(arena, .{ .start = imp.start, .len = imp.len, .repl = repl.items });
                s = b.e;
            } else s += 1;
        }
        try imps.appendSlice(arena, fn_imps.items);
        if (apply and edits.items.len > 0) {
            const new_code = rw.applyEdits(arena, .{ .code = cu.code, .jump_tables = cu.jump_tables }, edits.items) catch continue;
            const trial = try rw.withFunction(arena, &cur, fi, new_code);
            if ((try v.check(arena, &trial)) == .ok) {
                cur = trial;
                applied += @intCast(edits.items.len);
            } else rejected += @intCast(edits.items.len);
        }
    }
    return .{ .improvements = imps.items, .windows_tried = tried, .nodes = nodes, .module = cur, .applied = applied, .rejected_by_verifier = rejected };
}

/// Like seqText but CopyLoc shows the real local index.
fn seqTextReal(arena: Allocator, ops: []const MOp, real: []const u16) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (ops, 0..) |op, i| {
        if (i > 0) try out.appendSlice(arena, "; ");
        if (op.kind == .copy) {
            try out.print(arena, "CopyLoc {d}", .{real[@intCast(op.arg)]});
        } else try out.appendSlice(arena, try opText(arena, op));
    }
    return out.items;
}

pub fn run(ctx: *common.Ctx) !u8 {
    const arena = ctx.arena;
    const cfg: Config = .{
        .max_len = @intCast(try ctx.opts.num("--max-len", 4)),
        .budget = try ctx.opts.num("--budget", if (ctx.opts.get("--window") != null) 20_000_000 else 1_000_000),
        .seed = try ctx.opts.num("--seed", 1),
    };
    var j: common.Json = .{ .w = ctx.w };

    if (ctx.opts.get("--window")) |wt| {
        const target = try parseOps(arena, wt);
        var ptys: std.ArrayList(Ty) = .empty;
        if (ctx.opts.get("--params")) |pt| {
            var it = std.mem.tokenizeScalar(u8, pt, ',');
            while (it.next()) |t| try ptys.append(arena, parseTy(std.mem.trim(u8, t, " ")) orelse return error.BadParams);
        }
        const res = try search(arena, target, ptys.items, cfg);
        try j.beginObj();
        try j.str("window", try seqText(arena, target));
        try j.int("instructions", target.len);
        if (res) |f| {
            try j.str("replacement", try seqText(arena, f.ops));
            try j.int("replacement_instructions", f.ops.len);
            try j.str("proof", @tagName(f.proof.kind));
            try j.int("proof_inputs", f.proof.vectors);
            try j.int("search_nodes", f.nodes);
        } else try j.str("replacement", "none found within the budget");
        try j.endObj();
        try ctx.w.writeByte('\n');
        return 0;
    }

    const v = try rw.Verifier.init(try common.protocolOpt(ctx.opts));
    var cm: ff.CompiledModule = undefined;
    if (ctx.opts.get("--module-file")) |path| {
        const raw = try std.Io.Dir.cwd().readFileAlloc(ctx.io, path, arena, .limited(16 << 20));
        switch (try mf.deserialize(arena, raw, &.{})) {
            .ok => |m| cm = m,
            .err => return error.BadModule,
        }
    } else {
        const dir = ctx.opts.get("--dir") orelse return error.MissingDir;
        const pid = try common.parseId(ctx.opts.get("--package") orelse return error.MissingPackage);
        const mod = ctx.opts.get("--module") orelse return error.MissingModule;
        var o = try common.openNode(ctx.gpa, ctx.io, arena, dir);
        defer o.close();
        var snap = o.st.snapshot();
        defer snap.release();
        const pkg = try common.loadPackage(arena, &snap, &pid);
        cm = (common.moduleByName(&pkg, mod) orelse return error.ModuleNotFound).cm;
    }
    const out_path = ctx.opts.get("--out");
    const res = try searchModule(arena, &v, &cm, ctx.opts.get("--function"), cfg, out_path != null);
    if (out_path) |p| {
        const bytes = try mf.serializeAlloc(arena, &res.module, cm.version);
        try std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = p, .data = bytes });
    }
    try j.beginObj();
    try j.str("module", cm.selfName());
    try j.int("windows_searched", res.windows_tried);
    try j.int("search_nodes", res.nodes);
    try j.int("improvements", res.improvements.len);
    try j.int("applied", res.applied);
    try j.int("rejected_by_verifier", res.rejected_by_verifier);
    try j.arrIn("found");
    for (res.improvements) |i| {
        try j.beginObj();
        try j.str("function", i.function);
        try j.int("pc", i.start);
        try j.int("instructions", i.len);
        try j.str("window", i.window);
        try j.str("replacement", i.replacement);
        try j.int("replacement_instructions", i.repl.len);
        try j.str("proof", @tagName(i.proof.kind));
        try j.int("proof_inputs", i.proof.vectors);
        try j.endObj();
    }
    try j.endArr();
    try j.endObj();
    try ctx.w.writeByte('\n');
    return 0;
}

test "search finds x * 1 -> x and x - x -> 0" {
    var st: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const t1 = try parseOps(a, "CopyLoc 0; LdU64 1; Mul");
    const r1 = (try search(a, t1, &.{.u64}, .{})).?;
    try std.testing.expectEqual(@as(usize, 1), r1.ops.len);
    try std.testing.expect(r1.proof.ok);
    const t2 = try parseOps(a, "CopyLoc 0; CopyLoc 0; Sub");
    const r2 = (try search(a, t2, &.{.u8}, .{})).?;
    try std.testing.expectEqual(@as(usize, 1), r2.ops.len);
    try std.testing.expect(r2.proof.kind == .exhaustive);
}

test "abort behaviour is part of equivalence: (a + b) - b is not a" {
    var st: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const t = try parseOps(a, "CopyLoc 0; CopyLoc 1; Add; CopyLoc 1; Sub");
    const only_a = try parseOps(a, "CopyLoc 0");
    const p = prove(t, only_a, &.{ .u8, .u8 }, 1);
    try std.testing.expect(!p.ok);
}

test "two u64 locals: no overflow, sampled proof, and window constants are tested" {
    var st: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const t = try parseOps(a, "CopyLoc 0; CopyLoc 1; Add");
    const same = try parseOps(a, "CopyLoc 1; CopyLoc 0; Add");
    const p = prove(t, same, &.{ .u64, .u64 }, 1);
    try std.testing.expect(p.ok and p.kind == .sampled and p.vectors > 0);
    const eq = try parseOps(a, "CopyLoc 0; LdU64 12345; Eq");
    const f = try parseOps(a, "LdFalse");
    try std.testing.expect(!prove(eq, f, &.{.u64}, 1).ok);
    try std.testing.expect((try search(a, eq, &.{.u64}, .{})) == null);
}
