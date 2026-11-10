//! `CausalOrder::order_for_checkpoint` (sui-core `checkpoints/causal_order.rs`, 1.83.1): the
//! deterministic order of the transactions of one consensus commit inside a checkpoint.
//!
//! The consensus commit prologue (when present) stays first. The rest is sorted topologically
//! over `effects.dependencies` plus the read/write-lock edges: a transaction that overwrites
//! shared object version N depends on every transaction that read version N. Ties are broken by
//! transaction digest (smallest first), dependencies are visited largest digest first: the
//! output does not depend on the input order. With `disable_effects_tx_dependencies` the input
//! order is kept as is.
const std = @import("std");
const ev = @import("effects_view.zig");

const Digest = [32]u8;

pub const Error = error{ NoPrologue, OutOfMemory } || ev.Error;

const Node = struct {
    digest: Digest,
    /// Index into the input.
    input: u32,
    /// Sorted, deduplicated (a BTreeSet in Rust).
    deps: []const Digest,
};

fn digestLess(_: void, a: Digest, b: Digest) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn nodeLess(_: void, a: Node, b: Node) bool {
    const o = std.mem.order(u8, &a.digest, &b.digest);
    if (o != .eq) return o == .lt;
    return a.input < b.input;
}

/// Orders `effects` for a checkpoint. `ccp_first`: the first effects are the consensus commit
/// prologue's (`ccp_digest` is Some in Rust; it is asserted to be effects[0]). The result is
/// allocated in `arena`; the views are copied by value (their decoded data is shared).
pub fn orderForCheckpoint(
    arena: std.mem.Allocator,
    effects: []const ev.View,
    ccp_first: bool,
    disable_effects_tx_dependencies: bool,
) Error![]ev.View {
    if (ccp_first and effects.len == 0) return error.NoPrologue;
    if (disable_effects_tx_dependencies) return arena.dupe(ev.View, effects);
    const out = try arena.alloc(ev.View, effects.len);
    var n: usize = 0;
    var rest = effects;
    if (ccp_first) {
        out[0] = effects[0];
        n = 1;
        rest = effects[1..];
    }
    try causalSort(arena, rest, out[n..]);
    return out;
}

/// `CausalOrder::causal_sort`.
pub fn causalSort(arena: std.mem.Allocator, effects: []const ev.View, out: []ev.View) Error!void {
    std.debug.assert(out.len == effects.len);
    if (effects.len == 0) return;

    // RWLockDependencyBuilder: object version -> readers (as input indices).
    var readers: std.AutoHashMapUnmanaged([40]u8, std.ArrayList(u32)) = .empty;
    var accesses: std.ArrayList(ev.Access) = .empty;
    // accesses of effect i are accesses[off[i]..off[i + 1]]
    const off = try arena.alloc(u32, effects.len + 1);
    for (effects, 0..) |*e, i| {
        off[i] = @intCast(accesses.items.len);
        try e.accessed(arena, &accesses);
    }
    off[effects.len] = @intCast(accesses.items.len);
    for (effects, 0..) |_, i| {
        for (accesses.items[off[i]..off[i + 1]]) |a| {
            if (a.kind != .read) continue;
            const gop = try readers.getOrPut(arena, a.key.bytes());
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(arena, @intCast(i));
        }
    }

    // TransactionDependencies per effect, then `not_seen`: a map by digest (a later duplicate
    // replaces an earlier one, as BTreeMap::collect does).
    const nodes = try arena.alloc(Node, effects.len);
    var tmp: std.ArrayList(Digest) = .empty;
    for (effects, 0..) |*e, i| {
        tmp.clearRetainingCapacity();
        for (e.dependencies()) |d| try tmp.append(arena, d.@"0".@"0");
        for (accesses.items[off[i]..off[i + 1]]) |a| {
            if (a.kind != .overwrite) continue;
            if (readers.get(a.key.bytes())) |rs| {
                for (rs.items) |r| try tmp.append(arena, effects[r].tx);
            }
        }
        std.mem.sort(Digest, tmp.items, {}, digestLess);
        var m: usize = 0;
        for (tmp.items, 0..) |d, k| {
            if (k > 0 and std.mem.eql(u8, &d, &tmp.items[m - 1])) continue;
            tmp.items[m] = d;
            m += 1;
        }
        nodes[i] = .{ .digest = e.tx, .input = @intCast(i), .deps = try arena.dupe(Digest, tmp.items[0..m]) };
    }
    std.mem.sort(Node, nodes, {}, nodeLess);
    // dedup by digest: keep the last of each run
    var uniq: usize = 0;
    for (nodes, 0..) |nd, k| {
        if (k + 1 < nodes.len and std.mem.eql(u8, &nodes[k + 1].digest, &nd.digest)) continue;
        nodes[uniq] = nd;
        uniq += 1;
    }
    const sorted = nodes[0..uniq];
    const seen = try arena.alloc(bool, sorted.len); // true = already removed from not_seen
    @memset(seen, false);

    var written: usize = 0;
    var first: usize = 0; // pop_first scans from here
    const Frame = struct { node: u32, dep_left: u32 };
    var stack: std.ArrayList(Frame) = .empty;
    while (true) {
        while (first < sorted.len and seen[first]) first += 1;
        if (first >= sorted.len) break;
        seen[first] = true;
        try stack.append(arena, .{ .node = @intCast(first), .dep_left = @intCast(sorted[first].deps.len) });
        // InsertState::process loop
        while (stack.items.len > 0) {
            const top = &stack.items[stack.items.len - 1];
            const nd = &sorted[top.node];
            var pushed = false;
            while (top.dep_left > 0) {
                top.dep_left -= 1;
                const dep = nd.deps[top.dep_left]; // pop from the back: largest first
                const at = findNode(sorted, &dep) orelse continue;
                if (seen[at]) continue;
                seen[at] = true;
                try stack.append(arena, .{ .node = @intCast(at), .dep_left = @intCast(sorted[at].deps.len) });
                pushed = true;
                break;
            }
            if (pushed) continue;
            out[written] = effects[nd.input];
            written += 1;
            _ = stack.pop();
        }
    }
    // duplicates of a digest in the input were collapsed by the map: Rust returns fewer effects
    // in that case; callers never pass duplicates (one effects per executed transaction).
    std.debug.assert(written == out.len);
}

fn findNode(sorted: []const Node, d: *const Digest) ?usize {
    var lo: usize = 0;
    var hi: usize = sorted.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, &sorted[mid].digest, d)) {
            .eq => return mid,
            .lt => lo = mid + 1,
            .gt => hi = mid,
        }
    }
    return null;
}

// ---- tests (the unit tests of causal_order.rs)

const types = @import("types");
const bcs = @import("bcs");

fn testEffects(a: std.mem.Allocator, id: u8, deps: []const u8, reads: []const u8, writes: []const u8) !ev.View {
    var d: std.ArrayList(types.TransactionDigest) = .empty;
    for (deps) |x| {
        var b: [32]u8 = @splat(0);
        b[0] = x;
        try d.append(a, .{ .@"0" = .{ .@"0" = b } });
    }
    const Unch = std.meta.Child(@FieldType(types.TransactionEffectsV2, "unchanged_consensus_objects"));
    const Ch = std.meta.Child(@FieldType(types.TransactionEffectsV2, "changed_objects"));
    var unl: std.ArrayList(Unch) = .empty;
    var chl: std.ArrayList(Ch) = .empty;
    for (reads) |o| {
        var b: [32]u8 = @splat(0);
        b[0] = o;
        try unl.append(a, .{ .{ .@"0" = .{ .@"0" = b } }, .{ .ReadOnlyRoot = .{ .{ .@"0" = 1 }, .{ .@"0" = .{ .@"0" = @splat(0) } } } } });
    }
    for (writes) |o| {
        var b: [32]u8 = @splat(0);
        b[0] = o;
        try chl.append(a, .{ .{ .@"0" = .{ .@"0" = b } }, .{
            .input_state = .{ .Exist = .{ .{ .{ .@"0" = 1 }, .{ .@"0" = .{ .@"0" = @splat(0) } } }, .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 1 } } } } },
            .output_state = .NotExist,
            .id_operation = .None,
        } });
    }
    var tb: [32]u8 = @splat(0);
    tb[0] = id;
    const fx: types.TransactionEffects = .{ .V2 = .{
        .status = .Success,
        .executed_epoch = 0,
        .gas_used = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .transaction_digest = .{ .@"0" = .{ .@"0" = tb } },
        .gas_object_index = null,
        .events_digest = null,
        .dependencies = d.items,
        .lamport_version = .{ .@"0" = 2 },
        .changed_objects = chl.items,
        .unchanged_consensus_objects = unl.items,
        .aux_data_digest = null,
    } };
    const raw = try bcs.encodeAlloc(types.TransactionEffects, a, &fx);
    return ev.View.parse(a, raw);
}

fn firstBytes(a: std.mem.Allocator, v: []const ev.View) ![]u8 {
    const r = try a.alloc(u8, v.len);
    for (v, r) |x, *o| o.* = x.tx[0];
    return r;
}

test "causal order: dependencies, ties by digest" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const e1 = try testEffects(a, 1, &.{ 2, 3 }, &.{}, &.{});
    const e2 = try testEffects(a, 2, &.{ 3, 4 }, &.{}, &.{});
    const e3 = try testEffects(a, 3, &.{}, &.{}, &.{});
    const e4 = try testEffects(a, 4, &.{}, &.{}, &.{});
    const r = try orderForCheckpoint(a, &.{ e1, e2, e3, e4 }, false, false);
    try std.testing.expectEqualSlices(u8, &.{ 3, 4, 2, 1 }, try firstBytes(a, r));
    const r2 = try orderForCheckpoint(a, &.{ e1, e4 }, false, false);
    try std.testing.expectEqualSlices(u8, &.{ 1, 4 }, try firstBytes(a, r2));
    const r3 = try orderForCheckpoint(a, &.{ e4, e1 }, false, false);
    try std.testing.expectEqualSlices(u8, &.{ 1, 4 }, try firstBytes(a, r3));
    // dependencies disabled: input order kept
    const r4 = try orderForCheckpoint(a, &.{ e4, e1 }, false, true);
    try std.testing.expectEqualSlices(u8, &.{ 4, 1 }, try firstBytes(a, r4));
}

test "causal order: a writer of version N comes after the readers of N, prologue stays first" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const e5 = try testEffects(a, 5, &.{}, &.{1}, &.{});
    const e2 = try testEffects(a, 2, &.{}, &.{1}, &.{});
    const e3 = try testEffects(a, 3, &.{}, &.{}, &.{1});
    const r = try orderForCheckpoint(a, &.{ e5, e2, e3 }, false, false);
    try std.testing.expectEqual(@as(usize, 3), r.len);
    try std.testing.expectEqual(@as(u8, 3), r[2].tx[0]);
    const ccp = try testEffects(a, 200, &.{}, &.{}, &.{});
    const r2 = try orderForCheckpoint(a, &.{ ccp, e5, e2, e3 }, true, false);
    try std.testing.expectEqual(@as(u8, 200), r2[0].tx[0]);
    try std.testing.expectEqual(@as(u8, 3), r2[3].tx[0]);
}
