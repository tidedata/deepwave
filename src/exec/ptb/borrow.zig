//! The regex borrow graph of `move-regex-borrow-graph` (collections.rs, regex.rs) as the PTB
//! memory-safety pass uses it (typing/verify/memory_safety.rs): references are nodes, an edge
//! p -> s says s borrows from p along a set of paths (regexes: a label sequence, optionally
//! ending in `.*`). New references get every edge they imply up front
//! (`determine_all_new_edges`), so releasing a reference only removes its node. The pass never
//! meters (`DummyMeter`), so neither does this.
const std = @import("std");
const typing = @import("typing.zig");

const Allocator = std.mem.Allocator;
pub const Label = typing.Loc;

pub const Regex = struct {
    labels: []const Label = &.{},
    dot_star: bool = false,

    pub const epsilon: Regex = .{};
    pub const dotStar: Regex = .{ .dot_star = true };

    pub fn isEpsilon(r: Regex) bool {
        return r.labels.len == 0 and !r.dot_star;
    }
    pub fn isDotStar(r: Regex) bool {
        return r.labels.len == 0 and r.dot_star;
    }
    /// `Path::starts_with`.
    pub fn startsWith(r: Regex, l: Label) bool {
        return r.isDotStar() or (r.labels.len > 0 and r.labels[0].eql(l));
    }
    fn eql(a: Regex, b: Regex) bool {
        if (a.dot_star != b.dot_star or a.labels.len != b.labels.len) return false;
        for (a.labels, b.labels) |x, y| if (!x.eql(y)) return false;
        return true;
    }
};

pub const Ext = union(enum) { epsilon, label: Label, dot_star };

fn extRegex(arena: Allocator, e: Ext) Allocator.Error!Regex {
    return switch (e) {
        .epsilon => Regex.epsilon,
        .label => |l| .{ .labels = try arena.dupe(Label, &.{l}) },
        .dot_star => Regex.dotStar,
    };
}

pub const Ref = u32;

const Edge = std.ArrayList(Regex);

pub const Graph = struct {
    arena: Allocator,
    mut: std.ArrayList(bool) = .empty,
    alive: std.ArrayList(bool) = .empty,
    /// Per node: successors (borrowers) and their edge.
    out: std.ArrayList(std.AutoArrayHashMapUnmanaged(Ref, Edge)) = .empty,
    /// Per node: predecessors.
    in: std.ArrayList(std.AutoArrayHashMapUnmanaged(Ref, void)) = .empty,

    pub fn init(arena: Allocator) Graph {
        return .{ .arena = arena };
    }

    fn addRef(g: *Graph, is_mut: bool) Allocator.Error!Ref {
        const r: Ref = @intCast(g.mut.items.len);
        try g.mut.append(g.arena, is_mut);
        try g.alive.append(g.arena, true);
        try g.out.append(g.arena, .empty);
        try g.in.append(g.arena, .empty);
        return r;
    }

    pub fn isMutable(g: *const Graph, r: Ref) bool {
        return g.mut.items[r];
    }

    /// Edges into `r` (the implicit epsilon self edge included).
    fn incoming(g: *const Graph, r: Ref, out: *std.ArrayList(struct { Ref, []const Regex })) Allocator.Error!void {
        try out.append(g.arena, .{ r, &[_]Regex{Regex.epsilon} });
        for (g.in.items[r].keys()) |p| try out.append(g.arena, .{ p, g.out.items[p].get(r).?.items });
    }

    fn outgoing(g: *const Graph, r: Ref, out: *std.ArrayList(struct { Ref, []const Regex })) Allocator.Error!void {
        try out.append(g.arena, .{ r, &[_]Regex{Regex.epsilon} });
        for (g.out.items[r].keys(), g.out.items[r].values()) |s, e| try out.append(g.arena, .{ s, e.items });
    }

    const Acc = std.AutoArrayHashMapUnmanaged(u64, Edge);

    fn accAdd(g: *Graph, acc: *Acc, p: Ref, r: Regex, s: Ref) Allocator.Error!void {
        const gop = try acc.getOrPut(g.arena, (@as(u64, p) << 32) | s);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        for (gop.value_ptr.items) |x| if (x.eql(r)) return;
        try gop.value_ptr.append(g.arena, r);
    }

    fn determine(g: *Graph, acc: *Acc, sources: []const Ref, ext: Ext, new_refs: []const Ref) Allocator.Error!void {
        var buf: std.ArrayList(struct { Ref, []const Regex }) = .empty;
        var tmp: std.ArrayList(Regex) = .empty;
        for (sources) |source| {
            buf.clearRetainingCapacity();
            try g.incoming(source, &buf);
            for (buf.items) |e| for (e[1]) |x_to_source| {
                const extended = try extend(g.arena, x_to_source, ext);
                for (new_refs) |n| try g.accAdd(acc, e[0], extended, n);
            };
            buf.clearRetainingCapacity();
            try g.outgoing(source, &buf);
            for (buf.items) |e| for (e[1]) |source_to_x| {
                tmp.clearRetainingCapacity();
                try removePrefixOfRegex(g.arena, source_to_x, ext, &tmp);
                for (tmp.items) |suf| for (new_refs) |n| try g.accAdd(acc, n, suf, e[0]);
                tmp.clearRetainingCapacity();
                try removePrefixOfExt(g.arena, ext, source_to_x, &tmp);
                for (tmp.items) |suf| for (new_refs) |n| try g.accAdd(acc, e[0], suf, n);
            };
        }
    }

    fn addNewEdges(g: *Graph, acc: *const Acc) Allocator.Error!void {
        for (acc.keys(), acc.values()) |k, rs| {
            const p: Ref = @intCast(k >> 32);
            const s: Ref = @truncate(k);
            if (p == s) continue; // self edges are epsilon (checked by Rust)
            const gop = try g.out.items[p].getOrPut(g.arena, s);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            outer: for (rs.items) |r| {
                for (gop.value_ptr.items) |x| if (x.eql(r)) continue :outer;
                try gop.value_ptr.append(g.arena, r);
            }
            try g.in.items[s].put(g.arena, p, {});
        }
    }

    /// `extend_by_epsilon` (no sources: a fresh root).
    pub fn extendByEpsilon(g: *Graph, sources: []const Ref, is_mut: bool) Allocator.Error!Ref {
        const n = try g.addRef(is_mut);
        var acc: Acc = .empty;
        try g.determine(&acc, sources, .epsilon, &.{n});
        try g.addNewEdges(&acc);
        return n;
    }

    pub fn extendByLabel(g: *Graph, source: Ref, is_mut: bool, l: Label) Allocator.Error!Ref {
        const n = try g.addRef(is_mut);
        var acc: Acc = .empty;
        try g.determine(&acc, &.{source}, .{ .label = l }, &.{n});
        try g.addNewEdges(&acc);
        return n;
    }

    /// `extend_by_dot_star_for_call`: `sources` ascending and distinct.
    pub fn extendByDotStarForCall(g: *Graph, sources: []const Ref, mutabilities: []const bool) Allocator.Error![]Ref {
        var mut_sources: std.ArrayList(Ref) = .empty;
        for (sources) |s| if (g.isMutable(s)) try mut_sources.append(g.arena, s);
        var mut_new: std.ArrayList(Ref) = .empty;
        var imm_new: std.ArrayList(Ref) = .empty;
        const out = try g.arena.alloc(Ref, mutabilities.len);
        for (mutabilities, out) |m, *o| {
            o.* = try g.addRef(m);
            try (if (m) &mut_new else &imm_new).append(g.arena, o.*);
        }
        var acc: Acc = .empty;
        try g.determine(&acc, mut_sources.items, .dot_star, mut_new.items);
        try g.determine(&acc, sources, .dot_star, imm_new.items);
        for (imm_new.items) |x| for (imm_new.items) |y| {
            if (x != y) try g.accAdd(&acc, x, Regex.dotStar, y);
        };
        try g.addNewEdges(&acc);
        return out;
    }

    pub fn release(g: *Graph, r: Ref) void {
        g.alive.items[r] = false;
        for (g.in.items[r].keys()) |p| _ = g.out.items[p].orderedRemove(r);
        for (g.out.items[r].keys()) |s| _ = g.in.items[s].orderedRemove(r);
        g.out.items[r].clearRetainingCapacity();
        g.in.items[r].clearRetainingCapacity();
    }

    /// `borrowed_by`: (borrower, paths), borrowers ascending.
    pub fn borrowedBy(g: *const Graph, r: Ref, out: *std.ArrayList(struct { Ref, []const Regex })) Allocator.Error!void {
        out.clearRetainingCapacity();
        for (g.out.items[r].keys(), g.out.items[r].values()) |s, e| try out.append(g.arena, .{ s, e.items });
        std.mem.sort(struct { Ref, []const Regex }, out.items, {}, struct {
            fn lt(_: void, a: struct { Ref, []const Regex }, b: struct { Ref, []const Regex }) bool {
                return a[0] < b[0];
            }
        }.lt);
    }

    pub fn hasBorrowers(g: *const Graph, r: Ref) bool {
        return g.out.items[r].count() != 0;
    }
};

/// `Regex::extend`.
fn extend(arena: Allocator, r: Regex, ext: Ext) Allocator.Error!Regex {
    if (r.dot_star) return r;
    return switch (ext) {
        .epsilon => r,
        .label => |l| blk: {
            const labels = try arena.alloc(Label, r.labels.len + 1);
            @memcpy(labels[0..r.labels.len], r.labels);
            labels[r.labels.len] = l;
            break :blk .{ .labels = labels, .dot_star = false };
        },
        .dot_star => .{ .labels = r.labels, .dot_star = true },
    };
}

/// The walk's `remaining` after skipping `i` labels (i <= labels.len): at the end of the labels a
/// regex without `.*` is epsilon, one with `.*` is `.*`.
fn suffix(r: Regex, i: usize) Regex {
    return .{ .labels = r.labels[i..], .dot_star = r.dot_star };
}

/// `Regex::remove_prefix(ext)`: the regexes x with r = ext . x.
fn removePrefixOfRegex(arena: Allocator, r: Regex, ext: Ext, out: *std.ArrayList(Regex)) Allocator.Error!void {
    switch (ext) {
        .epsilon => try out.append(arena, r),
        .label => |l| {
            if (r.isEpsilon()) return;
            if (r.labels.len == 0) return out.append(arena, Regex.dotStar);
            if (!r.labels[0].eql(l)) return;
            try out.append(arena, suffix(r, 1));
        },
        .dot_star => {
            if (r.dot_star) return out.append(arena, Regex.dotStar);
            var i: usize = 0;
            while (i <= r.labels.len) : (i += 1) try out.append(arena, suffix(r, i));
        },
    }
}

/// `Extension::remove_prefix(p)`: the regexes x with ext = p . x.
fn removePrefixOfExt(arena: Allocator, ext: Ext, p: Regex, out: *std.ArrayList(Regex)) Allocator.Error!void {
    if (p.isEpsilon()) return out.append(arena, try extRegex(arena, ext));
    if (p.labels.len > 0) {
        switch (ext) {
            .epsilon => {},
            .label => |l| {
                if (!p.labels[0].eql(l)) return;
                // after the label: epsilon or `.*` remain -> epsilon; more labels -> nothing
                if (p.labels.len == 1) try out.append(arena, Regex.epsilon);
            },
            .dot_star => try out.append(arena, Regex.dotStar),
        }
        return;
    }
    // p is `.*`
    switch (ext) {
        .dot_star => try out.append(arena, Regex.dotStar),
        .epsilon => try out.append(arena, Regex.epsilon),
        .label => {
            try out.append(arena, try extRegex(arena, ext));
            try out.append(arena, Regex.epsilon);
        },
    }
}

test "siblings borrowed from the same location see each other through epsilon" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    var g = Graph.init(a.allocator());
    const root = try g.extendByEpsilon(&.{}, true);
    const x = try g.extendByLabel(root, true, .gas);
    const y = try g.extendByLabel(root, false, .gas);
    const z = try g.extendByLabel(root, false, .{ .object = 0 });
    var buf: std.ArrayList(struct { Ref, []const Regex }) = .empty;
    try g.borrowedBy(x, &buf);
    try std.testing.expectEqual(@as(usize, 1), buf.items.len);
    try std.testing.expectEqual(y, buf.items[0][0]);
    try std.testing.expect(buf.items[0][1][0].isEpsilon());
    try g.borrowedBy(root, &buf);
    try std.testing.expectEqual(@as(usize, 3), buf.items.len);
    try std.testing.expect(buf.items[2][1][0].startsWith(.{ .object = 0 }));
    _ = z;
    // a call result from x borrows x along `.*`
    const r = try g.extendByDotStarForCall(&.{x}, &.{true});
    try g.borrowedBy(x, &buf);
    var found = false;
    for (buf.items) |e| if (e[0] == r[0]) {
        found = e[1][0].isDotStar();
    };
    try std.testing.expect(found);
    g.release(x);
    try g.borrowedBy(root, &buf);
    // the result still borrows from the gas coin: gas._*
    for (buf.items) |e| if (e[0] == r[0]) try std.testing.expect(e[1][0].startsWith(.gas));
}
