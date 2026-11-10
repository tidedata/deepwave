//! `VMControlFlowGraph` (move-abstract-interpreter control_flow_graph.rs), control flow checks
//! (control_flow.rs, control_flow_v5.rs, loop_summary.rs) and the abstract interpretation driver
//! (absint.rs), 1.83.1.
const std = @import("std");
const ff = @import("../file_format.zig");
const c = @import("common.zig");

const Ctx = c.Ctx;
const E = c.E;
const Allocator = std.mem.Allocator;
const PartialVmError = ff.PartialVmError;
const Instr = ff.Instr;

/// Block ids are code offsets of block starts; internally blocks are numbered in start order.
pub const Cfg = struct {
    /// Start offset of block i (ascending: `blocks()` order).
    starts: []u16,
    /// Exit offset of block i.
    ends: []u16,
    /// Successor offsets of block i: succ[succ_off[i]..succ_off[i+1]] (sorted, may repeat).
    succ: []u16,
    succ_off: []u32,
    /// Block number of each start offset (only meaningful at block starts).
    block_of: []u16,
    /// `traversal_successors`, by block number; maxInt = none.
    next: []u16,
    /// Back edges (from block start << 16 | to block start).
    back: std.AutoHashMapUnmanaged(u32, void),
    num_back_edges: usize,

    pub fn numBlocks(g: *const Cfg) usize {
        return g.starts.len;
    }
    pub fn successors(g: *const Cfg, b: usize) []const u16 {
        return g.succ[g.succ_off[b]..g.succ_off[b + 1]];
    }
    pub fn isBackEdge(g: *const Cfg, cur: u16, nxt: u16) bool {
        return g.back.contains((@as(u32, cur) << 16) | nxt);
    }

    pub fn init(arena: Allocator, code: []const Instr, jts: []const ff.JumpTable) E!Cfg {
        const n = code.len;
        const is_start = try arena.alloc(bool, n + 1);
        @memset(is_start, false);
        is_start[0] = true;
        for (code, 0..) |ins, pc| {
            if (ins.op.hasOffset()) is_start[ins.idx] = true;
            if (ins.op == .VariantSwitch) for (jts[ins.idx].offsets) |o| {
                is_start[o] = true;
            };
            if (ins.op.isBranch() and pc + 1 < n) is_start[pc + 1] = true;
        }
        var nb: usize = 0;
        for (0..n) |pc| {
            if (pc + 1 == n or is_start[pc + 1]) nb += 1;
        }
        const block_of = try arena.alloc(u16, n);
        const starts = try arena.alloc(u16, nb);
        const ends = try arena.alloc(u16, nb);
        const succ_off = try arena.alloc(u32, nb + 1);
        var succ: std.ArrayList(u16) = .empty;
        var entry: usize = 0;
        var b: usize = 0;
        for (0..n) |pc| {
            if (!(pc + 1 == n or is_start[pc + 1])) continue;
            starts[b] = @intCast(entry);
            ends[b] = @intCast(pc);
            block_of[entry] = @intCast(b);
            succ_off[b] = @intCast(succ.items.len);
            // Bytecode::get_successors
            const ins = code[pc];
            const first = succ.items.len;
            if (ins.op.hasOffset()) try succ.append(arena, ins.idx);
            if (ins.op == .VariantSwitch) try succ.appendSlice(arena, jts[ins.idx].offsets);
            const next_pc: u16 = @intCast(pc + 1);
            if (pc + 1 < n and !ins.op.isUnconditionalBranch() and std.mem.indexOfScalar(u16, succ.items[first..], next_pc) == null)
                try succ.append(arena, next_pc);
            std.mem.sort(u16, succ.items[first..], {}, std.sort.asc(u16));
            entry = pc + 1;
            b += 1;
        }
        succ_off[nb] = @intCast(succ.items.len);
        var g: Cfg = .{
            .starts = starts,
            .ends = ends,
            .succ = succ.items,
            .succ_off = succ_off,
            .block_of = block_of,
            .next = try arena.alloc(u16, nb),
            .back = .empty,
            .num_back_edges = 0,
        };
        @memset(g.next, std.math.maxInt(u16));
        if (n == 0) return g;
        // DFS: back edges and reverse postorder
        const State = enum(u8) { none, in_progress, done };
        const expl = try arena.alloc(State, nb);
        @memset(expl, .none);
        var stack: std.ArrayList(u16) = .empty;
        var post: std.ArrayList(u16) = .empty;
        try stack.append(arena, 0);
        while (stack.pop()) |blk| {
            const bi = block_of[blk];
            switch (expl[bi]) {
                .none => {
                    expl[bi] = .in_progress;
                    try stack.append(arena, blk);
                    for (g.successors(bi)) |s| switch (expl[block_of[s]]) {
                        .none => try stack.append(arena, s),
                        .in_progress => {
                            const gop = try g.back.getOrPut(arena, (@as(u32, blk) << 16) | s);
                            if (!gop.found_existing) g.num_back_edges += 1;
                        },
                        .done => {},
                    };
                },
                .done => continue,
                .in_progress => {
                    try post.append(arena, blk);
                    expl[bi] = .done;
                },
            }
        }
        std.mem.reverse(u16, post.items);
        if (post.items.len > 1) for (post.items[0 .. post.items.len - 1], post.items[1..]) |x, y| {
            g.next[block_of[x]] = y;
        };
        return g;
    }
};

// =============================================================================================
// control_flow.rs

pub fn verifyFallthrough(ctx: *Ctx, fidx: u16, code: []const Instr) E!void {
    if (code.len == 0) return ctx.status(.EMPTY_CODE_UNIT);
    if (!code[code.len - 1].op.isUnconditionalBranch())
        return ctx.fail(PartialVmError.new(.INVALID_FALL_THROUGH).atCodeOffset(fidx, @intCast(code.len - 1)));
}

/// `control_flow::verify_function` minus building the CFG for v6+ (the caller builds it once).
pub fn verifyV5(ctx: *Ctx, arena: Allocator, cfg: *const c.Config, fidx: u16, code: []const Instr) E!void {
    try verifyFallthrough(ctx, fidx, code);
    const n = code.len;
    // labels: last_continue per loop head (maxInt = Code)
    const NONE = std.math.maxInt(u32);
    const labels = try arena.alloc(u32, n);
    @memset(labels, NONE);
    for (code, 0..) |ins, i| {
        if (ins.op.hasOffset() and ins.idx <= i) labels[ins.idx] = @intCast(i);
    }
    const LoopEntry = struct { head: u16, last: u16 };
    var stack: std.ArrayList(LoopEntry) = .empty;
    const Pass = enum { continues, breaks, splits, depth };
    // count_loop_depth
    const is_last = try arena.alloc(bool, n);
    @memset(is_last, false);
    for (labels) |l| if (l != NONE) {
        is_last[l] = true;
    };
    const depth = try arena.alloc(usize, n);
    {
        var count: usize = 0;
        for (labels, 0..) |l, i| {
            if (l != NONE) count += 1;
            depth[i] = count;
            if (is_last[i]) count -%= 1;
        }
    }
    inline for (.{ Pass.continues, Pass.breaks, Pass.splits, Pass.depth }) |pass| {
        if (pass == .depth and cfg.max_loop_depth == null) return;
        stack.clearRetainingCapacity();
        for (code, 0..) |ins, i_| {
            const i: u16 = @intCast(i_);
            if (labels[i] != NONE) try stack.append(arena, .{ .head = i, .last = @intCast(labels[i]) });
            const br = ins.op.hasOffset();
            const t = ins.idx;
            switch (pass) {
                .continues => if (br and t <= i) {
                    const top = stack.getLastOrNull() orelse return ctx.invariant();
                    if (t != top.head) return ctx.fail(PartialVmError.new(.INVALID_LOOP_CONTINUE).atCodeOffset(fidx, i));
                },
                .breaks => if (br and !(t <= i)) {
                    if (stack.getLastOrNull()) |top| if (t > top.last and t != top.last + 1)
                        return ctx.fail(PartialVmError.new(.INVALID_LOOP_BREAK).atCodeOffset(fidx, i));
                },
                .splits => if (br and t > i) {
                    const is_break = if (stack.getLastOrNull()) |top| t > top.last else false;
                    if (!is_break) {
                        const before = depth[i];
                        const after = if (labels[t] != NONE) depth[t] - 1 else depth[t];
                        if (before != after) return ctx.fail(PartialVmError.new(.INVALID_LOOP_SPLIT).atCodeOffset(fidx, i));
                    }
                },
                .depth => if (depth[i] > cfg.max_loop_depth.?)
                    return ctx.fail(PartialVmError.new(.LOOP_MAX_DEPTH_REACHED).atCodeOffset(fidx, i)),
            }
            if (br and t <= i) {
                const top = stack.getLastOrNull() orelse return ctx.invariant();
                if (i == top.last) _ = stack.pop();
            }
        }
    }
}

/// `verify_reducibility` (LoopSummary + LoopPartition).
pub fn verifyReducibility(ctx: *Ctx, arena: Allocator, cfg: *const c.Config, fidx: u16, g: *const Cfg) E!void {
    const nb = g.numBlocks();
    if (nb == 0) return;
    const NIL = std.math.maxInt(u16);
    const blocks = try arena.alloc(u16, nb);
    @memset(blocks, 0);
    const descs = try arena.alloc(u16, nb);
    @memset(descs, 0);
    const backs = try arena.alloc(std.ArrayList(u16), nb);
    const preds = try arena.alloc(std.ArrayList(u16), nb);
    for (backs, preds) |*x, *y| {
        x.* = .empty;
        y.* = .empty;
    }
    // exploration per block number: node id, in progress?
    const node_of = try arena.alloc(u16, nb);
    @memset(node_of, NIL);
    const done = try arena.alloc(bool, nb);
    @memset(done, false);
    const Frontier = struct { finish: bool, a: u16, b: u16, parent: u16 };
    var stack: std.ArrayList(Frontier) = .empty;
    var next_node: u16 = 0;
    const root = next_node;
    next_node += 1;
    blocks[root] = 0;
    node_of[0] = root;
    for (g.successors(0)) |s| try stack.append(arena, .{ .finish = false, .a = root, .b = s, .parent = 0 });
    while (stack.pop()) |act| {
        if (act.finish) {
            // a = block, b = node_id
            descs[act.parent] += 1 + descs[act.b];
            done[g.block_of[act.a]] = true;
        } else {
            const to_b = g.block_of[act.b];
            const from = act.a;
            if (node_of[to_b] != NIL) {
                const to_node = node_of[to_b];
                if (!done[to_b]) try backs[to_node].append(arena, from) else try preds[to_node].append(arena, from);
            } else {
                const to_node = next_node;
                next_node += 1;
                node_of[to_b] = to_node;
                blocks[to_node] = act.b;
                try preds[to_node].append(arena, from);
                try stack.append(arena, .{ .finish = true, .a = act.b, .b = to_node, .parent = from });
                for (g.successors(to_b)) |s| try stack.append(arena, .{ .finish = false, .a = to_node, .b = s, .parent = 0 });
            }
        }
    }
    // LoopPartition
    const parents = try arena.alloc(u16, nb);
    for (parents, 0..) |*p, i| p.* = @intCast(i);
    const depths = try arena.alloc(u16, nb);
    @memset(depths, 0);
    const P = struct {
        fn containing(par: []u16, al: Allocator, id: u16, scratch: *std.ArrayList(u16)) E!u16 {
            var child = id;
            var parent = par[child];
            var grand = par[parent];
            if (child == parent or parent == grand) return parent;
            scratch.clearRetainingCapacity();
            while (true) {
                try scratch.append(al, child);
                child = parent;
                parent = grand;
                grand = par[grand];
                if (parent == grand) break;
            }
            for (scratch.items) |d| par[d] = parent;
            return parent;
        }
    };
    var scratch: std.ArrayList(u16) = .empty;
    const in_body = try arena.alloc(bool, nb);
    @memset(in_body, false);
    var body: std.ArrayList(u16) = .empty;
    var frontier: std.ArrayList(u16) = .empty;
    var head_: usize = nb;
    while (head_ > 0) {
        head_ -= 1;
        const head: u16 = @intCast(head_);
        if (backs[head].items.len == 0) continue;
        for (body.items) |x| in_body[x] = false;
        body.clearRetainingCapacity();
        for (backs[head].items) |node| {
            const l = try P.containing(parents, arena, node, &scratch);
            if (l != head and !in_body[l]) {
                in_body[l] = true;
                try body.append(arena, l);
            }
        }
        std.mem.sort(u16, body.items, {}, std.sort.asc(u16));
        frontier.clearRetainingCapacity();
        try frontier.appendSlice(arena, body.items);
        while (frontier.pop()) |node| {
            for (preds[node].items) |pred_| {
                const pred = try P.containing(parents, arena, pred_, &scratch);
                const is_desc = head <= pred and pred <= head + descs[head];
                if (!is_desc) return ctx.fail(PartialVmError.new(.INVALID_LOOP_SPLIT).atCodeOffset(fidx, blocks[pred]));
                if (pred != head and !in_body[pred]) {
                    in_body[pred] = true;
                    try body.append(arena, pred);
                    try frontier.append(arena, pred);
                }
            }
        }
        // collapse_loop
        var d = depths[head];
        for (body.items) |x| {
            parents[x] = head;
            d = @max(d, depths[x]);
        }
        d += 1;
        depths[head] = d;
        if (cfg.max_loop_depth) |max| if (d > max)
            return ctx.fail(PartialVmError.new(.LOOP_MAX_DEPTH_REACHED).atCodeOffset(fidx, blocks[head]));
    }
}

// =============================================================================================
// absint.rs: `analyze_function` with the verifier's meter costs.

const ANALYZE_FUNCTION_BASE_COST: u128 = 10;
const EXECUTE_BLOCK_BASE_COST: u128 = 10;
const PER_BACKEDGE_COST: u128 = 10;
const PER_SUCCESSOR_COST: u128 = 10;

/// `A` provides: `State`, `clone(*A, *const State) E!State`, `join(*A, *State, *const State) E!bool`
/// (true = Changed), `execute(*A, *State, Instr, offset u16, start u16, end u16) E!void`.
pub fn analyze(comptime A: type, a: *A, ctx: *Ctx, meter: *c.Meter, arena: Allocator, g: *const Cfg, code: []const Instr, initial: A.State) E!void {
    try meter.add(ctx, .Function, ANALYZE_FUNCTION_BASE_COST);
    const nb = g.numBlocks();
    const pre = try arena.alloc(?A.State, nb);
    @memset(pre, null);
    pre[0] = try a.clone(&initial);
    var next_block: ?u16 = 0;
    while (next_block) |blk| {
        const bi = g.block_of[blk];
        if (pre[bi] == null) pre[bi] = try a.clone(&initial);
        try meter.add(ctx, .Function, EXECUTE_BLOCK_BASE_COST);
        var post = try a.clone(&pre[bi].?);
        const start = g.starts[bi];
        const end = g.ends[bi];
        var pc: usize = start;
        while (pc <= end) : (pc += 1) try a.execute(&post, code[pc], @intCast(pc), start, end);
        const nx = g.next[bi];
        var cand: ?u16 = if (nx == std.math.maxInt(u16)) null else nx;
        for (g.successors(bi)) |s| {
            try meter.add(ctx, .Function, PER_SUCCESSOR_COST);
            const si = g.block_of[s];
            if (pre[si]) |*sp| {
                if (try a.join(sp, &post)) {
                    if (g.isBackEdge(blk, s)) {
                        try meter.add(ctx, .Function, PER_BACKEDGE_COST);
                        cand = s;
                        break;
                    }
                }
            } else pre[si] = try a.clone(&post);
        }
        next_block = cand;
    }
}
