//! consensus_core::block_manager::BlockManager at mainnet-v1.83.1: holds verified blocks whose
//! ancestors are missing ("suspended") until the ancestors arrive, and reports the missing refs for
//! the synchronizer. Owner lane: val-consensus-core. Fixed budget: at most `max_suspended` blocks;
//! over budget a new block is skipped (counted in `dropped`) and re-fetched later by the
//! synchronizer, never a panic.
const std = @import("std");
const types = @import("types.zig");
const err = @import("error.zig");
const digest_mod = @import("digest.zig");
const dag_mod = @import("dag_state.zig");
const store_mod = @import("store.zig");
const Context = @import("context.zig").Context;

const Allocator = std.mem.Allocator;
const refSetInsert = dag_mod.refSetInsert;

fn refCmp(ctx: types.BlockRef, item: types.BlockRef) std.math.Order {
    return ctx.order(item);
}
fn refSetRemove(list: *std.ArrayList(types.BlockRef), r: types.BlockRef) bool {
    const pos = std.sort.lowerBound(types.BlockRef, list.items, r, refCmp);
    if (pos < list.items.len and list.items[pos].eql(r)) {
        _ = list.orderedRemove(pos);
        return true;
    }
    return false;
}
fn refSetContains(list: []const types.BlockRef, r: types.BlockRef) bool {
    const pos = std.sort.lowerBound(types.BlockRef, list, r, refCmp);
    return pos < list.len and list[pos].eql(r);
}

const Suspended = struct {
    arena: std.heap.ArenaAllocator,
    block: types.VerifiedBlock,
    missing: std.ArrayList(types.BlockRef) = .empty,
};

/// missing ancestor -> suspended blocks waiting for it (sorted refs). Entries sorted by ref.
const MissEntry = struct {
    ref: types.BlockRef,
    children: std.ArrayList(types.BlockRef) = .empty,
};
fn missCmp(ctx: types.BlockRef, item: MissEntry) std.math.Order {
    return ctx.order(item.ref);
}

pub const TryAccept = struct {
    /// Accepted blocks (the DAG's copies, valid until the next flush), in acceptance order.
    accepted: []const types.VerifiedBlock,
    /// Refs the manager newly needs (sorted, unique).
    missing: []const types.BlockRef,
};

pub const BlockManager = struct {
    gpa: Allocator,
    context: *const Context,
    dag: *dag_mod.DagState,
    max_suspended: usize = 100_000,
    dropped: u64 = 0,

    suspended: std.HashMapUnmanaged(types.BlockRef, *Suspended, store_mod.RefContext, 80) = .empty,
    missing_ancestors: std.ArrayList(MissEntry) = .empty,
    missing_blocks: std.ArrayList(types.BlockRef) = .empty,

    pub fn init(gpa: Allocator, context: *const Context, dag: *dag_mod.DagState) BlockManager {
        return .{ .gpa = gpa, .context = context, .dag = dag };
    }

    pub fn deinit(self: *BlockManager) void {
        var it = self.suspended.valueIterator();
        while (it.next()) |p| {
            p.*.arena.deinit();
            p.*.missing.deinit(self.gpa);
            self.gpa.destroy(p.*);
        }
        self.suspended.deinit(self.gpa);
        for (self.missing_ancestors.items) |*e| e.children.deinit(self.gpa);
        self.missing_ancestors.deinit(self.gpa);
        self.missing_blocks.deinit(self.gpa);
    }

    pub fn isEmpty(self: *const BlockManager) bool {
        return self.suspended.count() == 0 and self.missing_ancestors.items.len == 0 and self.missing_blocks.items.len == 0;
    }
    pub fn suspendedCount(self: *const BlockManager) usize {
        return self.suspended.count();
    }

    // ---- missing_ancestors helpers

    fn missEntry(self: *BlockManager, r: types.BlockRef) Allocator.Error!*MissEntry {
        const pos = std.sort.lowerBound(MissEntry, self.missing_ancestors.items, r, missCmp);
        if (pos < self.missing_ancestors.items.len and self.missing_ancestors.items[pos].ref.eql(r)) return &self.missing_ancestors.items[pos];
        try self.missing_ancestors.insert(self.gpa, pos, .{ .ref = r });
        return &self.missing_ancestors.items[pos];
    }
    fn missEntryFind(self: *BlockManager, r: types.BlockRef) ?usize {
        const pos = std.sort.lowerBound(MissEntry, self.missing_ancestors.items, r, missCmp);
        if (pos < self.missing_ancestors.items.len and self.missing_ancestors.items[pos].ref.eql(r)) return pos;
        return null;
    }

    // ---- public entry points

    /// `try_accept_blocks`: accepts blocks whose ancestors are all present (and then suspended
    /// blocks that become acceptable), suspends the rest, reports missing ancestors to fetch.
    pub fn tryAcceptBlocks(self: *BlockManager, arena: Allocator, blocks: []const types.VerifiedBlock) err.Error!TryAccept {
        return self.tryAcceptInternal(arena, blocks, false);
    }

    /// `try_accept_committed_blocks`: blocks that came with a certified commit are accepted without
    /// waiting for ancestors. Never suspends.
    pub fn tryAcceptCommittedBlocks(self: *BlockManager, arena: Allocator, blocks: []const types.VerifiedBlock) err.Error![]const types.VerifiedBlock {
        const r = try self.tryAcceptInternal(arena, blocks, true);
        if (r.missing.len != 0) return error.Invariant;
        return r.accepted;
    }

    const One = union(enum) { accepted, suspended: []const types.BlockRef, processed, skipped };

    fn tryAcceptInternal(self: *BlockManager, arena: Allocator, blocks_in: []const types.VerifiedBlock, committed: bool) err.Error!TryAccept {
        const blocks = arena.dupe(types.VerifiedBlock, blocks_in) catch return error.OutOfMemory;
        std.sort.block(types.VerifiedBlock, blocks, {}, struct {
            fn lt(_: void, a: types.VerifiedBlock, b: types.VerifiedBlock) bool {
                return a.block.inner.round() < b.block.inner.round();
            }
        }.lt);

        var accepted: std.ArrayList(types.VerifiedBlock) = .empty;
        var missing_out: std.ArrayList(types.BlockRef) = .empty;

        for (blocks) |*block| {
            const ref = block.reference();
            var to_accept: std.ArrayList(types.VerifiedBlock) = .empty;
            if (committed) {
                switch (try self.acceptOneCommitted(block)) {
                    .accepted => accepted.append(arena, (self.dag.getBlock(ref) orelse return error.Invariant).*) catch return error.OutOfMemory,
                    .processed => continue,
                    else => return error.Invariant,
                }
            } else {
                switch (try self.acceptOne(arena, block)) {
                    .accepted => to_accept.append(arena, block.*) catch return error.OutOfMemory,
                    .suspended => |fetch| {
                        for (fetch) |f| refSetInsert(arena, &missing_out, f) catch return error.OutOfMemory;
                        continue;
                    },
                    .processed, .skipped => continue,
                }
            }
            const unsuspended = try self.unsuspendChildren(arena, ref);
            to_accept.appendSlice(arena, unsuspended) catch return error.OutOfMemory;
            try self.dag.acceptBlocks(to_accept.items);
            for (to_accept.items) |b| {
                accepted.append(arena, (self.dag.getBlock(b.reference()) orelse return error.Invariant).*) catch return error.OutOfMemory;
            }
        }
        return .{ .accepted = accepted.items, .missing = missing_out.items };
    }

    fn acceptOneCommitted(self: *BlockManager, block: *const types.VerifiedBlock) err.Error!One {
        const ref = block.reference();
        if (try self.dag.containsBlock(ref)) return .processed;
        _ = refSetRemove(&self.missing_blocks, ref);
        if (self.suspended.fetchRemove(ref)) |kv| {
            const s = kv.value;
            for (s.missing.items) |anc| {
                if (self.missEntryFind(anc)) |pos| _ = refSetRemove(&self.missing_ancestors.items[pos].children, ref);
            }
            s.arena.deinit();
            s.missing.deinit(self.gpa);
            self.gpa.destroy(s);
        }
        try self.dag.acceptBlock(block);
        return .accepted;
    }

    fn acceptOne(self: *BlockManager, arena: Allocator, block: *const types.VerifiedBlock) err.Error!One {
        const ref = block.reference();
        const gc = self.dag.gcRound();
        if (self.suspended.contains(ref) or try self.dag.containsBlock(ref)) return .processed;
        if (ref.round <= gc) return .skipped;

        var missing: std.ArrayList(types.BlockRef) = .empty;
        defer missing.deinit(self.gpa);
        var to_fetch: std.ArrayList(types.BlockRef) = .empty;
        for (block.block.inner.ancestors()) |anc| {
            if (!(anc.round == types.GENESIS_ROUND or anc.round > gc)) continue;
            if (try self.dag.containsBlock(anc)) continue;
            refSetInsert(self.gpa, &missing, anc) catch return error.OutOfMemory;
        }
        if (missing.items.len > 0 and self.suspended.count() >= self.max_suspended) {
            // Over budget: drop, but keep the block and its missing ancestors in missing_blocks so
            // the synchronizer's periodic check fetches them again once there is room.
            self.dropped += 1;
            refSetInsert(self.gpa, &self.missing_blocks, ref) catch return error.OutOfMemory;
            for (missing.items) |anc| {
                if (!self.suspended.contains(anc)) refSetInsert(self.gpa, &self.missing_blocks, anc) catch return error.OutOfMemory;
            }
            return .skipped;
        }
        if (missing.items.len == 0) {
            _ = refSetRemove(&self.missing_blocks, ref);
            return .accepted;
        }
        for (missing.items) |anc| {
            const e = self.missEntry(anc) catch return error.OutOfMemory;
            refSetInsert(self.gpa, &e.children, ref) catch return error.OutOfMemory;
            if (!self.suspended.contains(anc)) {
                refSetInsert(arena, &to_fetch, anc) catch return error.OutOfMemory;
                refSetInsert(self.gpa, &self.missing_blocks, anc) catch return error.OutOfMemory;
            }
        }
        _ = refSetRemove(&self.missing_blocks, ref);

        const s = self.gpa.create(Suspended) catch return error.OutOfMemory;
        s.* = .{ .arena = std.heap.ArenaAllocator.init(self.gpa), .block = undefined };
        s.block = digest_mod.cloneVerified(s.arena.allocator(), block) catch |e| {
            s.arena.deinit();
            self.gpa.destroy(s);
            return e;
        };
        s.missing = missing;
        missing = .empty;
        self.suspended.put(self.gpa, ref, s) catch return error.OutOfMemory;
        return .{ .suspended = to_fetch.items };
    }

    /// `try_unsuspend_children_blocks`: blocks (deep copies in `arena`) that become acceptable once
    /// `accepted` is in the DAG, in Rust's processing order.
    fn unsuspendChildren(self: *BlockManager, arena: Allocator, accepted: types.BlockRef) err.Error![]const types.VerifiedBlock {
        var out: std.ArrayList(types.VerifiedBlock) = .empty;
        var work: std.ArrayList(types.BlockRef) = .empty;
        work.append(arena, accepted) catch return error.OutOfMemory;
        while (work.pop()) |r| {
            const pos = self.missEntryFind(r) orelse continue;
            var entry = self.missing_ancestors.orderedRemove(pos);
            defer entry.children.deinit(self.gpa);
            for (entry.children.items) |child| {
                const s = self.suspended.get(child) orelse return error.Invariant;
                if (!refSetRemove(&s.missing, r)) return error.Invariant;
                if (s.missing.items.len == 0) {
                    _ = self.suspended.remove(child);
                    const copy = digest_mod.cloneVerified(arena, &s.block) catch |e| return e;
                    s.arena.deinit();
                    s.missing.deinit(self.gpa);
                    self.gpa.destroy(s);
                    work.append(arena, child) catch return error.OutOfMemory;
                    out.append(arena, copy) catch return error.OutOfMemory;
                }
            }
        }
        return out.items;
    }

    /// `try_find_blocks`: of `refs` above the GC round, those neither in the DAG nor suspended are
    /// recorded as missing and returned (sorted).
    pub fn tryFindBlocks(self: *BlockManager, arena: Allocator, refs: []const types.BlockRef) err.Error![]const types.BlockRef {
        const gc = self.dag.gcRound();
        var out: std.ArrayList(types.BlockRef) = .empty;
        for (refs) |r| {
            if (r.round <= gc) continue;
            if (self.suspended.contains(r) or try self.dag.containsBlock(r)) continue;
            refSetInsert(arena, &out, r) catch return error.OutOfMemory;
            if (!refSetContains(self.missing_blocks.items, r)) {
                refSetInsert(self.gpa, &self.missing_blocks, r) catch return error.OutOfMemory;
                _ = self.missEntry(r) catch return error.OutOfMemory;
            }
        }
        return out.items;
    }

    /// `try_unsuspend_blocks_for_latest_gc_round`: missing ancestors at or below the new GC round
    /// no longer block their children; those are accepted (returned, DAG copies).
    pub fn tryUnsuspendBlocksForLatestGcRound(self: *BlockManager, arena: Allocator) err.Error![]const types.VerifiedBlock {
        const gc = self.dag.gcRound();
        var accepted: std.ArrayList(types.VerifiedBlock) = .empty;
        while (self.missing_ancestors.items.len > 0) {
            const first = self.missing_ancestors.items[0].ref;
            if (first.round > gc) break;
            if (self.suspended.contains(first)) return error.Invariant;
            _ = refSetRemove(&self.missing_blocks, first);
            const unsuspended = try self.unsuspendChildren(arena, first);
            try self.dag.acceptBlocks(unsuspended);
            for (unsuspended) |b| {
                accepted.append(arena, (self.dag.getBlock(b.reference()) orelse return error.Invariant).*) catch return error.OutOfMemory;
            }
        }
        return accepted.items;
    }

    pub fn missingBlocks(self: *const BlockManager) []const types.BlockRef {
        return self.missing_blocks.items;
    }
};

test "block manager suspends a block until its ancestor arrives, then accepts both" {
    const test_dag = @import("test_dag.zig");
    const gpa = std.testing.allocator;
    var stakes = test_dag.Fixture.equalStakes(4);
    const f = try test_dag.Fixture.init(gpa, .{ .stakes = &stakes });
    defer f.deinit();
    const a = f.arena();

    // Build blocks outside the DAG: round 1 block of author 1, and its child at round 2 by author 2.
    const mk = struct {
        fn block(fx: *test_dag.Fixture, round: u32, author: u32, anc: []const types.BlockRef) !types.VerifiedBlock {
            const b: types.Block = .{ .V2 = .{ .epoch = 0, .round = round, .author = author, .timestamp_ms = round, .ancestors = anc, .transactions = &.{}, .transaction_votes = &.{}, .commit_votes = &.{}, .misbehavior_reports = &.{} } };
            return digest_mod.verifiedForTest(fx.arena(), b);
        }
    };
    const g = f.genesisRefs();
    const parent = try mk.block(f, 1, 1, g[0..1]);
    const parent_ref = parent.reference();
    const child_anc = try a.dupe(types.BlockRef, &.{parent_ref});
    const child = try mk.block(f, 2, 2, child_anc);

    var bm = BlockManager.init(gpa, f.context, f.dag);
    defer bm.deinit();
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();

    const r1 = try bm.tryAcceptBlocks(scratch.allocator(), &.{child});
    try std.testing.expectEqual(@as(usize, 0), r1.accepted.len);
    try std.testing.expectEqual(@as(usize, 1), r1.missing.len);
    try std.testing.expect(r1.missing[0].eql(parent_ref));
    try std.testing.expectEqual(@as(usize, 1), bm.suspendedCount());

    const r2 = try bm.tryAcceptBlocks(scratch.allocator(), &.{parent});
    try std.testing.expectEqual(@as(usize, 2), r2.accepted.len);
    try std.testing.expect(bm.isEmpty());
    try std.testing.expectEqual(@as(types.Round, 2), f.dag.highestAcceptedRound());
}
