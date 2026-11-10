//! reference_safety (move-bytecode-verifier 1.83.1) over a port of move-borrow-graph.
//!
//! The borrow graph is kept flat: a sorted ref table and one edge list sorted by
//! (parent, child, strong, path). `borrows_from` is implied by the edges (the Rust graph keeps
//! both sides consistent, so nothing is lost).
const std = @import("std");
const ff = @import("../file_format.zig");
const c = @import("common.zig");
const cfgm = @import("cfg.zig");
const cp = @import("code_passes.zig");

const Ctx = c.Ctx;
const E = c.E;
const Token = c.Token;
const PartialVmError = ff.PartialVmError;
const CompiledModule = ff.CompiledModule;
const Instr = ff.Instr;
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------------------------
// Labels: Local(u8) < Global(u16) < StructField(u16) < VariantField(u16, u16, u16)

const Label = u64;
fn lLocal(i: u16) Label {
    return i;
}
fn lGlobal(i: u16) Label {
    return (1 << 48) | @as(u64, i);
}
fn lField(i: u16) Label {
    return (2 << 48) | @as(u64, i);
}
fn lVariant(e: u16, tag: u16, f: u16) Label {
    return (3 << 48) | (@as(u64, e) << 32) | (@as(u64, tag) << 16) | f;
}

fn pathOrder(a: []const Label, b: []const Label) std.math.Order {
    return std.mem.order(u64, a, b);
}
fn pathLeq(lhs: []const Label, rhs: []const Label) bool {
    return lhs.len <= rhs.len and std.mem.eql(u64, lhs, rhs[0..lhs.len]);
}

const MAX_EDGE_SET_SIZE = 10;

const Edge = struct {
    parent: u32,
    child: u32,
    strong: bool,
    /// The (parent, child) edge set overflowed (only ever on a lone weak, empty-path edge).
    overflown: bool = false,
    path: []const Label,

    fn order(a: Edge, b: Edge) std.math.Order {
        if (a.parent != b.parent) return std.math.order(a.parent, b.parent);
        if (a.child != b.child) return std.math.order(a.child, b.child);
        return edgeOrder(a, b);
    }
    /// BorrowEdge ordering: (strong, path), loc ignored.
    fn edgeOrder(a: Edge, b: Edge) std.math.Order {
        if (a.strong != b.strong) return if (!a.strong) .lt else .gt;
        return pathOrder(a.path, b.path);
    }
    fn lessThan(_: void, a: Edge, b: Edge) bool {
        return order(a, b) == .lt;
    }
    /// BorrowEdge::leq
    fn leq(self: Edge, other: Edge) bool {
        return (self.strong == other.strong and std.mem.eql(u64, self.path, other.path)) or
            (!self.strong and pathLeq(self.path, other.path));
    }
};

const RefInfo = struct { id: u32, mutable: bool };

const Graph = struct {
    refs: std.ArrayList(RefInfo) = .empty,
    edges: std.ArrayList(Edge) = .empty,

    fn clone(g: *const Graph, a: Allocator) E!Graph {
        var r: Graph = .{};
        try r.refs.appendSlice(a, g.refs.items);
        try r.edges.appendSlice(a, g.edges.items);
        return r;
    }

    fn size(g: *const Graph) usize {
        return g.refs.items.len + g.edges.items.len;
    }

    fn refIndex(g: *const Graph, id: u32) ?usize {
        var lo: usize = 0;
        var hi: usize = g.refs.items.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            const x = g.refs.items[mid].id;
            if (x == id) return mid;
            if (x < id) lo = mid + 1 else hi = mid;
        }
        return null;
    }

    fn isMutable(g: *const Graph, id: u32) bool {
        return g.refs.items[g.refIndex(id).?].mutable;
    }

    fn newRef(g: *Graph, a: Allocator, id: u32, mutable: bool) E!void {
        var i = g.refs.items.len;
        while (i > 0 and g.refs.items[i - 1].id > id) i -= 1;
        try g.refs.insert(a, i, .{ .id = id, .mutable = mutable });
    }

    /// First edge index with (parent, child) >= key.
    fn lower(g: *const Graph, parent: u32, child: u32) usize {
        var lo: usize = 0;
        var hi: usize = g.edges.items.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            const e = g.edges.items[mid];
            const lt = e.parent < parent or (e.parent == parent and e.child < child);
            if (lt) lo = mid + 1 else hi = mid;
        }
        return lo;
    }
    fn parentRange(g: *const Graph, parent: u32) [2]usize {
        const lo = g.lower(parent, 0);
        const hi = if (parent == std.math.maxInt(u32)) g.edges.items.len else g.lower(parent + 1, 0);
        return .{ lo, hi };
    }
    fn groupRange(g: *const Graph, parent: u32, child: u32) [2]usize {
        const lo = g.lower(parent, child);
        var hi = lo;
        while (hi < g.edges.items.len and g.edges.items[hi].parent == parent and g.edges.items[hi].child == child) hi += 1;
        return .{ lo, hi };
    }

    /// `add_edge` with BorrowEdgeSet::insert semantics.
    fn addEdge(g: *Graph, a: Allocator, parent: u32, strong: bool, path: []const Label, child: u32) E!void {
        const lo, const hi = g.groupRange(parent, child);
        if (lo < hi and g.edges.items[lo].overflown) return;
        const e: Edge = .{ .parent = parent, .child = child, .strong = strong, .path = path };
        if (hi - lo + 1 > MAX_EDGE_SET_SIZE) {
            g.edges.replaceRangeAssumeCapacity(lo, hi - lo, &.{.{ .parent = parent, .child = child, .strong = false, .overflown = true, .path = &.{} }});
            return;
        }
        var i = lo;
        while (i < hi) : (i += 1) switch (Edge.edgeOrder(g.edges.items[i], e)) {
            .lt => {},
            .eq => return,
            .gt => break,
        };
        try g.edges.insert(a, i, e);
    }

    /// `factor`: strong borrow of `path` from `parent` by `inter`.
    fn factor(g: *Graph, a: Allocator, parent: u32, path: []const Label, inter: u32) E!void {
        const lo, const hi = g.parentRange(parent);
        var moved: std.ArrayList(Edge) = .empty;
        var kept_end = lo;
        for (g.edges.items[lo..hi]) |e| {
            if (pathLeq(path, e.path)) {
                try moved.append(a, e);
            } else {
                g.edges.items[kept_end] = e;
                kept_end += 1;
            }
        }
        g.edges.replaceRangeAssumeCapacity(kept_end, hi - kept_end, &.{});
        for (moved.items) |e| try g.addEdge(a, inter, e.strong, e.path[path.len..], e.child);
        try g.addEdge(a, parent, true, path, inter);
    }

    /// `release`; returns the number of released (spliced) edge pairs.
    fn release(g: *Graph, a: Allocator, id: u32) E!usize {
        const ri = g.refIndex(id).?;
        _ = g.refs.orderedRemove(ri);
        // borrowed_by of id
        const lo, const hi = g.parentRange(id);
        const out = try a.dupe(Edge, g.edges.items[lo..hi]);
        g.edges.replaceRangeAssumeCapacity(lo, hi - lo, &.{});
        // in-edges grouped by parent (sorted by parent, then edge order)
        var inn: std.ArrayList(Edge) = .empty;
        var w: usize = 0;
        for (g.edges.items) |e| {
            if (e.child == id) {
                try inn.append(a, e);
            } else {
                g.edges.items[w] = e;
                w += 1;
            }
        }
        g.edges.shrinkRetainingCapacity(w);
        var released: usize = 0;
        for (inn.items) |pe| {
            for (out) |ce| {
                released += 1;
                if (pe.parent == ce.child) continue;
                const path = if (pe.strong) try std.mem.concat(a, Label, &.{ pe.path, ce.path }) else pe.path;
                try g.addEdge(a, pe.parent, pe.strong and ce.strong, path, ce.child);
            }
        }
        return released;
    }

    fn remap(g: *Graph, map: []const ?u32) void {
        const f = struct {
            fn m(mp: []const ?u32, x: u32) u32 {
                return if (x < mp.len) (mp[x] orelse x) else x;
            }
        }.m;
        for (g.refs.items) |*r| r.id = f(map, r.id);
        for (g.edges.items) |*e| {
            e.parent = f(map, e.parent);
            e.child = f(map, e.child);
        }
        std.mem.sort(RefInfo, g.refs.items, {}, struct {
            fn lt(_: void, x: RefInfo, y: RefInfo) bool {
                return x.id < y.id;
            }
        }.lt);
        std.mem.sort(Edge, g.edges.items, {}, Edge.lessThan);
    }

    /// Is `other_edge` (parent -> child) matched by some edge of `g`?
    fn matched(g: *const Graph, oe: Edge) bool {
        const lo, const hi = g.groupRange(oe.parent, oe.child);
        for (g.edges.items[lo..hi]) |se| if (se.leq(oe)) return true;
        return false;
    }

    fn leq(g: *const Graph, other: *const Graph) bool {
        for (other.edges.items) |oe| if (!g.matched(oe)) return false;
        return true;
    }

    /// `join`: self plus the unmatched edges of `other` (collected per edge set, with overflow).
    fn join(g: *const Graph, a: Allocator, other: *const Graph) E!Graph {
        var joined = try g.clone(a);
        var i: usize = 0;
        const oes = other.edges.items;
        var set: std.ArrayList(Edge) = .empty;
        while (i < oes.len) {
            var j = i;
            while (j < oes.len and oes[j].parent == oes[i].parent and oes[j].child == oes[i].child) j += 1;
            set.clearRetainingCapacity();
            var overflown = false;
            for (oes[i..j]) |oe| {
                if (g.matched(oe)) continue;
                if (overflown) continue;
                if (set.items.len + 1 > MAX_EDGE_SET_SIZE) {
                    set.clearRetainingCapacity();
                    try set.append(a, .{ .parent = oe.parent, .child = oe.child, .strong = false, .path = &.{} });
                    overflown = true;
                } else try set.append(a, oe); // other's edges are distinct and sorted
            }
            for (set.items) |e| try joined.addEdge(a, e.parent, e.strong, e.path, e.child);
            i = j;
        }
        return joined;
    }
};

// ---------------------------------------------------------------------------------------------
// AbstractState

const NONREF: u32 = std.math.maxInt(u32);

const STEP_BASE_COST: u128 = 1;
const JOIN_BASE_COST: u128 = 10;
const PER_GRAPH_ITEM_COST: u128 = 4;
const RELEASE_ITEM_COST: u128 = 3;
const RELEASE_ITEM_QUADRATIC_THRESHOLD: usize = 5;
const JOIN_ITEM_COST: u128 = 4;
const JOIN_ITEM_QUADRATIC_THRESHOLD: usize = 10;
const ADD_BORROW_COST: u128 = 3;

const RState = struct {
    locals: []u32,
    graph: Graph,
    next_id: u32,
};

const ValStack = cp.AbstractStack(u32, struct {
    fn eq(x: u32, y: u32) bool {
        return x == y;
    }
}.eq);

const RS = struct {
    pub const State = RState;
    const St = RState;
    ctx: *Ctx,
    cfg: *const c.Config,
    meter: *c.Meter,
    arena: Allocator,
    f: *const cp.Fn,
    name_def: *const std.AutoHashMapUnmanaged(u16, u16),
    stack: ValStack = .{},

    fn err(r: *RS, s: c.StatusCode, off: u16) error{Vm} {
        return r.f.err(r.ctx, s, off);
    }
    fn chargeGraph(r: *RS, n: usize) E!void {
        try r.meter.addItems(r.ctx, .Function, PER_GRAPH_ITEM_COST, @max(n, 1));
    }
    fn chargeRelease(r: *RS, released: usize) E!void {
        const s = @max(released, 1);
        try r.meter.addItems(r.ctx, .Function, RELEASE_ITEM_COST, @max(s, (s *| s) / RELEASE_ITEM_QUADRATIC_THRESHOLD));
    }
    fn frameRoot(st: *const St) u32 {
        return @intCast(st.locals.len);
    }

    pub fn clone(r: *RS, s: *const St) E!St {
        return .{ .locals = try r.arena.dupe(u32, s.locals), .graph = try s.graph.clone(r.arena), .next_id = s.next_id };
    }

    fn newRef(r: *RS, st: *St, mutable: bool) E!u32 {
        const id = st.next_id;
        try st.graph.newRef(r.arena, id, mutable);
        st.next_id += 1;
        return id;
    }
    fn valueFor(r: *RS, st: *St, t: Token) E!u32 {
        return switch (t[0].tag) {
            .Reference => r.newRef(st, false),
            .MutableReference => r.newRef(st, true),
            else => NONREF,
        };
    }
    fn addCopy(r: *RS, st: *St, parent: u32, child: u32) E!void {
        try r.meter.add(r.ctx, .Function, ADD_BORROW_COST);
        try st.graph.factor(r.arena, parent, &.{}, child);
    }
    fn addBorrow(r: *RS, st: *St, parent: u32, child: u32) E!void {
        try r.meter.add(r.ctx, .Function, ADD_BORROW_COST);
        try st.graph.addEdge(r.arena, parent, false, &.{}, child);
    }
    fn label1(r: *RS, l: Label) E![]const Label {
        const p = try r.arena.alloc(Label, 1);
        p[0] = l;
        return p;
    }
    fn addStrongField(r: *RS, st: *St, parent: u32, l: Label, child: u32) E!void {
        try r.meter.add(r.ctx, .Function, ADD_BORROW_COST);
        try st.graph.factor(r.arena, parent, try r.label1(l), child);
    }
    fn addResourceBorrow(r: *RS, st: *St, res: u16, child: u32) E!void {
        try r.meter.add(r.ctx, .Function, ADD_BORROW_COST);
        try st.graph.addEdge(r.arena, frameRoot(st), false, try r.label1(lGlobal(res)), child);
    }
    fn release(r: *RS, st: *St, id: u32) E!void {
        const n = try st.graph.release(r.arena, id);
        try r.chargeRelease(n);
    }
    fn releaseValue(r: *RS, st: *St, v: u32) E!void {
        if (v != NONREF) try r.release(st, v);
    }

    fn hasFullBorrows(st: *const St, id: u32) bool {
        const lo, const hi = st.graph.parentRange(id);
        for (st.graph.edges.items[lo..hi]) |e| if (e.path.len == 0) return true;
        return false;
    }
    fn hasConsistentBorrows(st: *const St, id: u32, label: ?Label) bool {
        const lo, const hi = st.graph.parentRange(id);
        for (st.graph.edges.items[lo..hi]) |e| {
            if (e.path.len == 0) return true;
            if (label) |l| {
                if (e.path[0] == l) return true;
            } else return true;
        }
        return false;
    }
    fn hasConsistentMutableBorrows(st: *const St, id: u32, label: ?Label) bool {
        const lo, const hi = st.graph.parentRange(id);
        for (st.graph.edges.items[lo..hi]) |e| {
            if (!st.graph.isMutable(e.child)) continue;
            if (e.path.len == 0) return true;
            if (label) |l| {
                if (e.path[0] == l) return true;
            } else return true;
        }
        return false;
    }
    fn isWritable(r: *RS, st: *const St, id: u32) E!bool {
        try r.chargeGraph(st.graph.size());
        return !hasConsistentBorrows(st, id, null);
    }
    fn isFreezable(r: *RS, st: *const St, id: u32, field: ?u16) E!bool {
        try r.chargeGraph(st.graph.size());
        return !hasConsistentMutableBorrows(st, id, if (field) |f| lField(f) else null);
    }
    fn isReadable(r: *RS, st: *const St, id: u32, field: ?u16) E!bool {
        return !st.graph.isMutable(id) or try r.isFreezable(st, id, field);
    }
    fn isLocalBorrowed(r: *RS, st: *const St, idx: u16) E!bool {
        try r.chargeGraph(st.graph.size());
        return hasConsistentBorrows(st, frameRoot(st), lLocal(idx));
    }
    fn isLocalMutablyBorrowed(r: *RS, st: *const St, idx: u16) E!bool {
        if (r.cfg.additional_borrow_checks and hasFullBorrows(st, frameRoot(st))) return true;
        try r.chargeGraph(st.graph.size());
        return hasConsistentMutableBorrows(st, frameRoot(st), lLocal(idx));
    }
    fn isGlobalBorrowed(r: *RS, st: *const St, res: u16) E!bool {
        try r.chargeGraph(st.graph.size());
        return hasConsistentBorrows(st, frameRoot(st), lGlobal(res));
    }
    fn isGlobalMutablyBorrowed(r: *RS, st: *const St, res: u16) E!bool {
        try r.chargeGraph(st.graph.size());
        return hasConsistentMutableBorrows(st, frameRoot(st), lGlobal(res));
    }

    // -- canonical form and join ---------------------------------------------------------

    fn canonical(r: *RS, st: *St) E!void {
        const n = st.locals.len;
        const map = try r.arena.alloc(?u32, @max(st.next_id, @as(u32, @intCast(n + 1))));
        @memset(map, null);
        for (st.locals, 0..) |*v, i| if (v.* != NONREF) {
            map[v.*] = @intCast(i);
            v.* = @intCast(i);
        };
        st.graph.remap(map);
        st.next_id = @intCast(n + 1);
    }

    pub fn join(r: *RS, pre: *St, post: *const St) E!bool {
        try r.meter.add(r.ctx, .Function, JOIN_BASE_COST);
        const self_size = pre.graph.size();
        const state_size = post.graph.size();
        var sg = try pre.graph.clone(r.arena);
        var og = try post.graph.clone(r.arena);
        var released: usize = 0;
        const locals = try r.arena.alloc(u32, pre.locals.len);
        for (pre.locals, post.locals, locals) |x, y, *o| {
            if (x != NONREF and y == NONREF) {
                released += try sg.release(r.arena, x);
                o.* = NONREF;
            } else if (x == NONREF and y != NONREF) {
                released += try og.release(r.arena, y);
                o.* = NONREF;
            } else o.* = x;
        }
        const joined = try sg.join(r.arena, &og);
        const max_size = @max(@max(self_size, state_size), joined.size());
        {
            const s1 = @max(self_size, 1);
            const s2 = @max(state_size, 1);
            const s = s1 +| s2;
            try r.meter.addItems(r.ctx, .Function, JOIN_ITEM_COST, @max(s, (s *| s) / JOIN_ITEM_QUADRATIC_THRESHOLD));
        }
        try r.chargeGraph(max_size);
        try r.chargeRelease(released);
        if (std.mem.eql(u32, pre.locals, locals) and pre.graph.leq(&joined)) return false;
        pre.* = .{ .locals = locals, .graph = joined, .next_id = pre.next_id };
        return true;
    }

    // -- instructions ------------------------------------------------------------------------

    fn pop(r: *RS) E!u32 {
        return r.stack.pop() catch r.ctx.invariant();
    }
    fn popRef(r: *RS) E!u32 {
        const v = try r.pop();
        if (v == NONREF) return r.ctx.invariant();
        return v;
    }
    fn popValue(r: *RS) E!void {
        if ((try r.pop()) != NONREF) return r.ctx.invariant();
    }
    fn push(r: *RS, v: u32) E!void {
        r.stack.pushN(r.arena, v, 1) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else r.ctx.invariant();
    }
    fn pushN(r: *RS, v: u32, n: u64) E!void {
        r.stack.pushN(r.arena, v, n) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else r.ctx.invariant();
    }
    fn global(r: *RS) E!void {
        if (r.cfg.deprecate_global_storage_ops) return r.ctx.invariant();
    }

    fn borrowField(r: *RS, st: *St, off: u16, mut: bool, id: u32, field: u16) E!void {
        if ((mut and hasFullBorrows(st, id)) or (!mut and !try r.isReadable(st, id, field)))
            return r.err(.FIELD_EXISTS_MUTABLE_BORROW_ERROR, off);
        const fid = try r.newRef(st, mut);
        try r.addStrongField(st, id, lField(field), fid);
        try r.release(st, id);
        try r.push(fid);
    }

    fn unpackVariantRef(r: *RS, st: *St, off: u16, ed: u16, tag: u16, nfields: usize, mut: bool) E!void {
        const id = try r.popRef();
        if ((mut and hasFullBorrows(st, id)) or (!mut and !try r.isReadable(st, id, null)))
            return r.err(.FIELD_EXISTS_MUTABLE_BORROW_ERROR, off);
        const out = try r.arena.alloc(u32, nfields);
        for (out, 0..) |*o, i| {
            o.* = try r.newRef(st, mut);
            try r.addStrongField(st, id, lVariant(ed, tag, @intCast(i)), o.*);
        }
        try r.release(st, id);
        for (out) |v| try r.push(v);
    }

    fn borrowGlobal(r: *RS, st: *St, off: u16, mut: bool, res: u16) E!void {
        try r.global();
        try r.popValue();
        if ((mut and try r.isGlobalBorrowed(st, res)) or try r.isGlobalMutablyBorrowed(st, res))
            return r.err(.GLOBAL_REFERENCE_ERROR, off);
        const id = try r.newRef(st, mut);
        try r.addResourceBorrow(st, res, id);
        try r.push(id);
    }

    fn moveFrom(r: *RS, st: *St, off: u16, res: u16) E!void {
        try r.global();
        try r.popValue();
        if (try r.isGlobalBorrowed(st, res)) return r.err(.GLOBAL_REFERENCE_ERROR, off);
        try r.push(NONREF);
    }

    fn vectorOp(r: *RS, st: *St, off: u16, vec: u32, mut: bool) E!void {
        if (vec == NONREF) return r.ctx.invariant();
        if (mut and !try r.isWritable(st, vec)) return r.err(.VEC_UPDATE_EXISTS_MUTABLE_BORROW_ERROR, off);
        try r.release(st, vec);
    }

    /// `call` / `call_v2`: `args` in argument order, `acq` sorted acquired resources.
    fn callRefs(r: *RS, st: *St, off: u16, args: []const u32, acq: []const u16, rets: []const Token, code: c.StatusCode) E!void {
        for (acq) |res| if (try r.isGlobalBorrowed(st, res)) return r.err(.GLOBAL_REFERENCE_ERROR, off);
        var all: std.ArrayList(u32) = .empty;
        var muts: std.ArrayList(u32) = .empty;
        for (args) |id| {
            if (id == NONREF) continue;
            if (st.graph.isMutable(id)) {
                if (!try r.isWritable(st, id)) return r.err(code, off);
                try sortedInsert(r.arena, &muts, id);
            }
            try sortedInsert(r.arena, &all, id);
        }
        for (rets) |t| switch (t[0].tag) {
            .MutableReference => {
                const id = try r.newRef(st, true);
                for (muts.items) |p| try r.addBorrow(st, p, id);
                try r.push(id);
            },
            .Reference => {
                const id = try r.newRef(st, false);
                for (all.items) |p| try r.addBorrow(st, p, id);
                try r.push(id);
            },
            else => try r.push(NONREF),
        };
        for (all.items) |id| try r.release(st, id);
    }

    fn call(r: *RS, st: *St, off: u16, fh_idx: u16) E!void {
        const m = r.f.m;
        const fh = &m.function_handles[fh_idx];
        const np = m.signatures[fh.parameters].len;
        // Rust builds the arguments with `parameters.iter().map(|_| stack.pop()).rev()`: `rev`
        // drives the closure from the back, so the first pop (the last argument) comes first.
        // The order shows in which `is_writable` check fails first, and so in the meter units.
        const args = try r.arena.alloc(u32, np);
        for (args) |*a| a.* = r.stack.pop() catch return r.ctx.invariant();
        var acq: []const u16 = &.{};
        if (r.name_def.get(fh.name)) |di| {
            const fd = &m.function_defs[di];
            const other = &m.function_handles[fd.function];
            if (fhEql(fh, other) and fd.acquires.len > 0) {
                const s = try r.arena.dupe(u16, fd.acquires);
                std.mem.sort(u16, s, {}, std.sort.asc(u16));
                var w: usize = 0;
                for (s) |x| if (w == 0 or s[w - 1] != x) {
                    s[w] = x;
                    w += 1;
                };
                acq = s[0..w];
            }
        }
        if (r.cfg.deprecate_global_storage_ops and acq.len > 0) return r.ctx.invariant();
        try r.callRefs(st, off, args, acq, m.signatures[fh.return_], .CALL_BORROWED_MUTABLE_REFERENCE_ERROR);
    }

    fn ret(r: *RS, st: *St, off: u16) E!void {
        const n = r.f.ret.len;
        const vals = try r.arena.alloc(u32, n);
        var i = n;
        while (i > 0) {
            i -= 1;
            vals[i] = try r.pop();
        }
        var released: std.ArrayList(u32) = .empty;
        for (st.locals) |v| if (v != NONREF) try sortedInsert(r.arena, &released, v);
        for (released.items) |id| try r.release(st, id);
        try r.chargeGraph(st.graph.size());
        if (hasConsistentBorrows(st, frameRoot(st), null)) return r.err(.UNSAFE_RET_LOCAL_OR_RESOURCE_STILL_BORROWED, off);
        for (vals) |id| {
            if (id == NONREF) continue;
            if (st.graph.isMutable(id) and !try r.isWritable(st, id)) return r.err(.RET_BORROWED_MUTABLE_REFERENCE_ERROR, off);
        }
    }

    pub fn execute(r: *RS, st: *St, ins: Instr, off: u16, _: u16, last: u16) E!void {
        try r.exec(st, ins, off);
        if (off == last) {
            if (r.stack.len != 0) return r.ctx.invariant();
            try r.canonical(st);
        }
    }

    fn exec(r: *RS, st: *St, ins: Instr, off: u16) E!void {
        try r.meter.add(r.ctx, .Function, STEP_BASE_COST);
        const m = r.f.m;
        switch (ins.op) {
            .Pop => try r.releaseValue(st, try r.pop()),
            .CopyLoc => {
                const v = st.locals[ins.idx];
                if (v != NONREF) {
                    const nid = try r.newRef(st, st.graph.isMutable(v));
                    try r.addCopy(st, v, nid);
                    try r.push(nid);
                } else {
                    if (try r.isLocalMutablyBorrowed(st, ins.idx)) return r.err(.COPYLOC_EXISTS_BORROW_ERROR, off);
                    try r.push(NONREF);
                }
            },
            .MoveLoc => {
                const v = st.locals[ins.idx];
                st.locals[ins.idx] = NONREF;
                if (v != NONREF) {
                    try r.push(v);
                } else {
                    if (try r.isLocalBorrowed(st, ins.idx)) return r.err(.MOVELOC_EXISTS_BORROW_ERROR, off);
                    try r.push(NONREF);
                }
            },
            .StLoc => {
                const nv = try r.pop();
                const old = st.locals[ins.idx];
                st.locals[ins.idx] = nv;
                if (old != NONREF) {
                    try r.release(st, old);
                } else if (try r.isLocalBorrowed(st, ins.idx)) return r.err(.STLOC_UNSAFE_TO_DESTROY_ERROR, off);
            },
            .FreezeRef => {
                const id = try r.popRef();
                if (!try r.isFreezable(st, id, null)) return r.err(.FREEZEREF_EXISTS_MUTABLE_BORROW_ERROR, off);
                const frozen = try r.newRef(st, false);
                try r.addCopy(st, id, frozen);
                try r.release(st, id);
                try r.push(frozen);
            },
            .Eq, .Neq => {
                const v1 = try r.pop();
                const v2 = try r.pop();
                if (v1 != NONREF and v2 != NONREF) {
                    if (!try r.isReadable(st, v1, null) or !try r.isReadable(st, v2, null))
                        return r.err(.READREF_EXISTS_MUTABLE_BORROW_ERROR, off);
                    try r.release(st, v1);
                    try r.release(st, v2);
                } else if (v1 != NONREF or v2 != NONREF) return r.ctx.invariant();
                try r.push(NONREF);
            },
            .ReadRef => {
                const id = try r.popRef();
                if (!try r.isReadable(st, id, null)) return r.err(.READREF_EXISTS_MUTABLE_BORROW_ERROR, off);
                try r.release(st, id);
                try r.push(NONREF);
            },
            .WriteRef => {
                const id = try r.popRef();
                try r.popValue();
                if (!try r.isWritable(st, id)) return r.err(.WRITEREF_EXISTS_BORROW_ERROR, off);
                try r.release(st, id);
            },
            .MutBorrowLoc, .ImmBorrowLoc => {
                const mut = ins.op == .MutBorrowLoc;
                if (!mut and try r.isLocalMutablyBorrowed(st, ins.idx)) return r.err(.BORROWLOC_EXISTS_BORROW_ERROR, off);
                if (r.cfg.additional_borrow_checks and mut and hasFullBorrows(st, frameRoot(st))) return r.err(.BORROWLOC_EXISTS_BORROW_ERROR, off);
                const id = try r.newRef(st, mut);
                try r.addStrongField(st, frameRoot(st), lLocal(ins.idx), id);
                try r.push(id);
            },
            .MutBorrowField, .ImmBorrowField => {
                const id = try r.popRef();
                try r.borrowField(st, off, ins.op == .MutBorrowField, id, ins.idx);
            },
            .MutBorrowFieldGeneric, .ImmBorrowFieldGeneric => {
                const fi = m.field_instantiations[ins.idx];
                const id = try r.popRef();
                try r.borrowField(st, off, ins.op == .MutBorrowFieldGeneric, id, fi.handle);
            },
            .MutBorrowGlobalDeprecated => try r.borrowGlobal(st, off, true, ins.idx),
            .MutBorrowGlobalGenericDeprecated => try r.borrowGlobal(st, off, true, m.struct_def_instantiations[ins.idx].def),
            .ImmBorrowGlobalDeprecated => try r.borrowGlobal(st, off, false, ins.idx),
            .ImmBorrowGlobalGenericDeprecated => try r.borrowGlobal(st, off, false, m.struct_def_instantiations[ins.idx].def),
            .MoveFromDeprecated => try r.moveFrom(st, off, ins.idx),
            .MoveFromGenericDeprecated => try r.moveFrom(st, off, m.struct_def_instantiations[ins.idx].def),
            .Call => try r.call(st, off, ins.idx),
            .CallGeneric => try r.call(st, off, m.function_instantiations[ins.idx].handle),
            .Ret => try r.ret(st, off),
            .Branch, .Nop, .CastU8, .CastU16, .CastU32, .CastU64, .CastU128, .CastU256, .Not => {},
            .ExistsDeprecated, .ExistsGenericDeprecated => try r.global(),
            .BrTrue, .BrFalse, .Abort => try r.popValue(),
            .MoveToDeprecated, .MoveToGenericDeprecated => {
                try r.global();
                try r.popValue();
                try r.releaseValue(st, try r.pop());
            },
            .LdTrue, .LdFalse, .LdU8, .LdU16, .LdU32, .LdU64, .LdU128, .LdU256 => try r.push(NONREF),
            .LdConst => try r.push(try r.valueFor(st, m.constant_pool[ins.idx].type_)),
            .Add, .Sub, .Mul, .Mod, .Div, .BitOr, .BitAnd, .Xor, .Shl, .Shr, .Or, .And, .Lt, .Gt, .Le, .Ge => {
                try r.popValue();
                try r.popValue();
                try r.push(NONREF);
            },
            .Pack, .PackGeneric => {
                const sd = if (ins.op == .Pack) ins.idx else m.struct_def_instantiations[ins.idx].def;
                for (0..m.struct_defs[sd].fields.len) |_| try r.popValue();
                try r.push(NONREF);
            },
            .Unpack, .UnpackGeneric => {
                const sd = if (ins.op == .Unpack) ins.idx else m.struct_def_instantiations[ins.idx].def;
                try r.popValue();
                try r.pushN(NONREF, m.struct_defs[sd].fields.len);
            },
            .VecPack => {
                if (ins.imm != 0) {
                    const v = r.stack.popEqN(ins.imm) catch return r.ctx.invariant();
                    if (v != NONREF) return r.ctx.invariant();
                }
                const sig = m.signatures[ins.idx];
                if (sig.len == 0) return r.ctx.status(.VERIFIER_INVARIANT_VIOLATION);
                try r.push(NONREF); // value_for(Vector(_))
            },
            .VecLen => {
                const v = try r.pop();
                try r.vectorOp(st, off, v, false);
                try r.push(NONREF);
            },
            .VecImmBorrow, .VecMutBorrow => {
                const mut = ins.op == .VecMutBorrow;
                try r.popValue();
                const vec = try r.pop();
                if (r.cfg.deprecate_global_storage_ops) {
                    const rk = [1]ff.Node{.{ .tag = if (mut) .MutableReference else .Reference }};
                    const rets = [1]Token{&rk};
                    try r.callRefs(st, off, &.{vec}, &.{}, &rets, .VEC_BORROW_ELEMENT_EXISTS_MUTABLE_BORROW_ERROR);
                } else {
                    if (vec == NONREF) return r.ctx.invariant();
                    if (mut and !try r.isWritable(st, vec)) return r.err(.VEC_BORROW_ELEMENT_EXISTS_MUTABLE_BORROW_ERROR, off);
                    const elem = try r.newRef(st, mut);
                    try r.addBorrow(st, vec, elem);
                    try r.release(st, vec);
                    try r.push(elem);
                }
            },
            .VecPushBack => {
                try r.popValue();
                const vec = try r.pop();
                try r.vectorOp(st, off, vec, true);
            },
            .VecPopBack => {
                const vec = try r.pop();
                try r.vectorOp(st, off, vec, true);
                const sig = m.signatures[ins.idx];
                if (sig.len == 0) return r.ctx.status(.VERIFIER_INVARIANT_VIOLATION);
                try r.push(try r.valueFor(st, sig[0]));
            },
            .VecUnpack => {
                try r.popValue();
                const sig = m.signatures[ins.idx];
                if (sig.len == 0) return r.ctx.status(.VERIFIER_INVARIANT_VIOLATION);
                try r.pushN(try r.valueFor(st, sig[0]), ins.imm);
            },
            .VecSwap => {
                try r.popValue();
                try r.popValue();
                const vec = try r.pop();
                try r.vectorOp(st, off, vec, true);
            },
            .PackVariant, .PackVariantGeneric => {
                const ed, const tag = variantOf(m, ins);
                for (0..m.enum_defs[ed].variants[tag].fields.len) |_| try r.popValue();
                try r.push(NONREF);
            },
            .UnpackVariant, .UnpackVariantGeneric => {
                const ed, const tag = variantOf(m, ins);
                try r.popValue();
                try r.pushN(NONREF, m.enum_defs[ed].variants[tag].fields.len);
            },
            .UnpackVariantImmRef, .UnpackVariantMutRef, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => {
                const ed, const tag = variantOf(m, ins);
                const mut = ins.op == .UnpackVariantMutRef or ins.op == .UnpackVariantGenericMutRef;
                try r.unpackVariantRef(st, off, ed, tag, m.enum_defs[ed].variants[tag].fields.len, mut);
            },
            .VariantSwitch => try r.releaseValue(st, try r.pop()),
            else => return r.ctx.invariant(),
        }
    }
};

fn variantOf(m: *const CompiledModule, ins: Instr) struct { u16, u16 } {
    return switch (ins.op) {
        .PackVariant, .UnpackVariant, .UnpackVariantImmRef, .UnpackVariantMutRef => .{ m.variant_handles[ins.idx].enum_def, m.variant_handles[ins.idx].variant },
        else => blk: {
            const h = m.variant_instantiation_handles[ins.idx];
            break :blk .{ m.enum_def_instantiations[h.enum_def].def, h.variant };
        },
    };
}

fn fhEql(a: *const ff.FunctionHandle, b: *const ff.FunctionHandle) bool {
    if (a == b) return true;
    if (a.module != b.module or a.name != b.name or a.parameters != b.parameters or a.return_ != b.return_) return false;
    if (a.type_parameters.len != b.type_parameters.len) return false;
    for (a.type_parameters, b.type_parameters) |x, y| if (x.bits != y.bits) return false;
    return true;
}

fn sortedInsert(a: Allocator, l: *std.ArrayList(u32), x: u32) E!void {
    var i: usize = l.items.len;
    while (i > 0 and l.items[i - 1] > x) i -= 1;
    if (i > 0 and l.items[i - 1] == x) return;
    try l.insert(a, i, x);
}

pub fn verify(ctx: *Ctx, arena: Allocator, cfg: *const c.Config, f: *const cp.Fn, name_def: *const std.AutoHashMapUnmanaged(u16, u16), meter: *c.Meter) E!void {
    const n = f.numLocals();
    var st: RState = .{ .locals = try arena.alloc(u32, n), .graph = .{}, .next_id = @intCast(n + 1) };
    @memset(st.locals, NONREF);
    for (f.params, 0..) |p, i| if (ff.isReference(p)) {
        try st.graph.newRef(arena, @intCast(i), ff.isMutableReference(p));
        st.locals[i] = @intCast(i);
    };
    try st.graph.newRef(arena, @intCast(n), true);
    var r: RS = .{ .ctx = ctx, .cfg = cfg, .meter = meter, .arena = arena, .f = f, .name_def = name_def };
    try cfgm.analyze(RS, &r, ctx, meter, arena, f.g, f.code.code, st);
}
