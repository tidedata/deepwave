//! consensus_core::commit_finalizer::CommitFinalizer at mainnet-v1.83.1: a commit's transactions
//! become final when each is either certified (2f+1 accept votes, direct from the committed blocks'
//! vote tracker or indirect through descendants in later commits) or rejected (2f+1 reject votes, or
//! still pending `INDIRECT_REJECT_DEPTH` rounds after the leader). It records
//! `rejected_transactions_by_block` for the consensus handler. Owner lane: val-consensus-core.
//!
//! Synchronous version of Rust's finalizer task: `process` takes one committed sub-dag and returns
//! the commits that are finalized now, in commit order (Rust runs the indirect pass on blocking
//! tasks; the result is the same). The finalizer copies each sub-dag into its own arena; a
//! finalized commit hands that arena (and so the sub-dag memory) over to the caller.
//!
//! Switches (`Switches`, all off by default; off is the path the replay vectors prove against
//! Mysten and what the train ran before): `walk` picks how the indirect walk keeps its sets
//! (`reference`: sorted lists as before; `sets`: hash sets, a ref queued at most once; `dense`:
//! slot numbers, bitsets and a heap in Rust's BTreeSet order), `lanes` runs the walks of one pass
//! on a small persistent pool. Every setting must give byte-identical finalized commits: the
//! exactness test in gen_dag.zig compares them on generated DAGs and on Mysten's vectors.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("core");
const types = @import("types.zig");
const err = @import("error.zig");
const committee_mod = @import("committee.zig");
const dag_mod = @import("dag_state.zig");
const digest_mod = @import("digest.zig");
const tracker_mod = @import("transaction_vote_tracker.zig");
const store_mod = @import("store.zig");
const Context = @import("context.zig").Context;

const Allocator = std.mem.Allocator;
const Agg = committee_mod.StakeAggregator(committee_mod.max_committee_size);
pub const TransactionVoteTracker = tracker_mod.TransactionVoteTracker;

pub const INDIRECT_REJECT_DEPTH: types.Round = 3;
/// Rust's BLOCKS_PER_INDIRECT_COMMIT_TASK: pending blocks per indirect-finalization task.
pub const BLOCKS_PER_INDIRECT_COMMIT_TASK: usize = 8;
/// Most lanes the pool is given (the caller is one of them), and what `lanes = 0` (auto) asks
/// for at most. Rust spawns one blocking task per 8 pending blocks; a pass is short, so a few
/// lanes are enough and a CPU quota is not overrun.
pub const MAX_LANES: usize = 8;
pub const AUTO_LANES: usize = 4;
/// Memory a task keeps between passes.
const task_arena_keep: usize = 1 << 20;

/// How the indirect walk keeps `to_visit`, `visited` and `ignored`. The visit order and the
/// result are the same for all three.
pub const Walk = enum {
    /// Sorted ref lists and a heap that may hold a ref twice (the path before the switches).
    reference,
    /// Hash sets. A ref is pushed only if it was never queued, so it is popped at most once and
    /// no `visited` set is needed (Rust: a BTreeSet `to_visit` plus the `!visited.contains` filter).
    sets,
    /// Slot numbers per linked block, bitsets per walk, and a heap keyed (round, author) with the
    /// digest as tie-break: Rust's BTreeSet<BlockRef> order.
    dense,
};

pub const Switches = struct {
    walk: Walk = .reference,
    /// Lanes for the walks of one indirect pass, the calling thread included. 1: inline, as
    /// before. 0: auto, min(AUTO_LANES, cgroup-aware CPU count); only `ZUI_FINALIZER_LANES=auto`
    /// or code asks for it, the variable's `0` is refused. A count from the variable is capped by
    /// the CPU count as auto is (`parseSwitches`); a count set in code (`setSwitches`, tests) is
    /// taken as given, up to MAX_LANES. A pass over at most one task (`blocks_per_task` pending
    /// blocks) always runs inline.
    lanes: usize = 1,
    /// Tests only: also runs the reference walk for every pending block and checks the dense
    /// lists against the ref lists; any difference is `error.Invariant`.
    cross_check: bool = false,
    /// Pending blocks per task. Tests lower it to put small passes on lanes.
    blocks_per_task: usize = BLOCKS_PER_INDIRECT_COMMIT_TASK,
    /// A queued commit holds the DAG window's box of each of its blocks (one more holder per
    /// block, as Mysten clones an Arc) instead of copying and decoding the block again. A block
    /// that is no longer in the window (a commit replayed from the store) is copied as before.
    share_blocks: bool = false,
};

/// The text of the switch variables (null: unset).
pub const EnvText = struct {
    walk: ?[]const u8 = null,
    lanes: ?[]const u8 = null,
    share_blocks: ?[]const u8 = null,
};

/// What `parseSwitches` made of the variables. A variable whose value it does not know leaves
/// its switch at the default and is flagged in `unknown`, so the caller can say so.
pub const ParsedSwitches = struct {
    sw: Switches = .{},
    unknown: Unknown = .{},

    pub const Unknown = struct { walk: bool = false, lanes: bool = false, share_blocks: bool = false };
};

/// `ZUI_FINALIZER_WALK=reference|sets|dense`, `ZUI_FINALIZER_LANES=<n>|auto`,
/// `ZUI_FINALIZER_SHARE_BLOCKS=0|1`. Unset leaves a switch at its default. So does any other
/// value (wrong case, an empty string, `true`), but never silently: it is flagged, and the
/// finalizer's first `init` prints a warning that names the variable and the value. This is what
/// the repo does with ZUI_CPU (core/cpu.zig `override_ignored`): a typo in a switch must not stop
/// a node, and must not pass for "the switch is on" either.
///
/// Lanes: `<n>` is 1 or more. `0` is refused as unknown (it used to mean auto, which nobody who
/// writes 0 expects; auto is spelled `auto`). `cpus` is the cgroup-aware CPU count: a lane count
/// above it, or above MAX_LANES, is lowered to it, so a seat under a CPU quota of one core runs
/// its passes inline whatever the variable says, as auto already does.
pub fn parseSwitches(t: EnvText, cpus: usize) ParsedSwitches {
    var p: ParsedSwitches = .{};
    if (t.walk) |v| {
        if (std.meta.stringToEnum(Walk, v)) |w| p.sw.walk = w else p.unknown.walk = true;
    }
    if (t.lanes) |v| {
        if (std.mem.eql(u8, v, "auto")) {
            p.sw.lanes = 0;
        } else if (std.fmt.parseInt(usize, v, 10)) |n| {
            if (n == 0) p.unknown.lanes = true else p.sw.lanes = @min(n, @max(cpus, 1), MAX_LANES);
        } else |_| p.unknown.lanes = true;
    }
    if (t.share_blocks) |v| {
        if (store_mod.parseOnOff(v)) |on| p.sw.share_blocks = on else p.unknown.share_blocks = true;
    }
    return p;
}

/// What the finalizer says once at startup: a warning for every variable it did not understand
/// (`rehash_unknown`: store.zig's ZUI_CONSENSUS_REHASH), and one `switches` line when any switch
/// is not at its default (`rehash`: the rehash switch as it stands). Empty when every switch is
/// off and every value was understood, so a default node prints nothing.
pub fn writeStartupLines(w: *std.Io.Writer, t: EnvText, p: ParsedSwitches, rehash: bool, rehash_unknown: ?[]const u8) std.Io.Writer.Error!void {
    const stays = "the switch stays at its default";
    if (p.unknown.walk) try w.print("consensus finalizer: WARNING ZUI_FINALIZER_WALK={s} is not reference, sets or dense; {s}\n", .{ t.walk orelse "", stays });
    if (p.unknown.lanes) try w.print("consensus finalizer: WARNING ZUI_FINALIZER_LANES={s} is not a lane count (1 or more) or auto; {s}\n", .{ t.lanes orelse "", stays });
    if (p.unknown.share_blocks) try w.print("consensus finalizer: WARNING ZUI_FINALIZER_SHARE_BLOCKS={s} is not 0 or 1; {s}\n", .{ t.share_blocks orelse "", stays });
    if (rehash_unknown) |v| try w.print("consensus finalizer: WARNING ZUI_CONSENSUS_REHASH={s} is not 0 or 1; {s}\n", .{ v, stays });
    const d: Switches = .{};
    if (p.sw.walk == d.walk and p.sw.lanes == d.lanes and p.sw.share_blocks == d.share_blocks and !rehash) return;
    try w.print("consensus finalizer: switches walk={s} lanes=", .{@tagName(p.sw.walk)});
    if (p.sw.lanes == 0) try w.writeAll("auto") else try w.print("{d}", .{p.sw.lanes});
    try w.print(" share_blocks={d} rehash={d}\n", .{ @intFromBool(p.sw.share_blocks), @intFromBool(rehash) });
}

fn envText(name: [*:0]const u8) ?[]const u8 {
    if (!builtin.link_libc) return null;
    return std.mem.span(std.c.getenv(name) orelse return null);
}

/// The startup lines are printed by the first finalizer of the process only: the environment
/// does not change, and a replay makes thousands of finalizers.
var startup_said: std.atomic.Value(bool) = .init(false);

/// The cgroup-aware CPU count (core.hw), read once: 0 until then.
var cpu_count: std.atomic.Value(u32) = .init(0);

fn cpuCount() usize {
    var n = cpu_count.load(.monotonic);
    if (n == 0) {
        n = @max(1, core.hw.detect(null).logical_cores);
        cpu_count.store(n, .monotonic);
    }
    return n;
}

/// The switches the environment asks for (`parseSwitches`). The first call prints the startup
/// lines (`writeStartupLines`) to stderr, where the seat's own lines go: a run with a switch on
/// shows it in its log, a run with a mistyped value shows the warning.
pub fn switchesFromEnv() Switches {
    const t: EnvText = .{ .walk = envText("ZUI_FINALIZER_WALK"), .lanes = envText("ZUI_FINALIZER_LANES"), .share_blocks = envText("ZUI_FINALIZER_SHARE_BLOCKS") };
    // the CPU count is needed only to cap a lane count
    const p = parseSwitches(t, if (t.lanes != null) cpuCount() else 1);
    if (!startup_said.swap(true, .monotonic)) {
        var buf: [1024]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        const rehash = store_mod.rehashOnEvict();
        // a value too long for the buffer cuts the text short; the lines before it stand
        writeStartupLines(&w, t, p, rehash, store_mod.rehashEnvUnknown()) catch {};
        if (w.buffered().len > 0) std.debug.print("{s}", .{w.buffered()});
    }
    return p.sw;
}

/// A finalized commit. `arena` owns the memory of `sub_dag`, except the blocks shared with the
/// DAG window (`boxes`, switch `share_blocks`), which it holds. The caller frees it with `deinit`.
pub const Finalized = struct {
    arena: std.heap.ArenaAllocator,
    sub_dag: types.CommittedSubDag,
    already_finalized: bool,
    /// The DAG boxes some of `sub_dag.blocks` point into (the list lives in `arena`).
    boxes: []const *dag_mod.BlockInfo = &.{},

    pub fn deinit(self: *Finalized) void {
        for (self.boxes) |b| b.release();
        self.arena.deinit();
    }
};

fn refCmp(ctx: types.BlockRef, item: types.BlockRef) std.math.Order {
    return ctx.order(item);
}
fn idxCmp(ctx: types.TransactionIndex, item: types.TransactionIndex) std.math.Order {
    return std.math.order(ctx, item);
}
fn idxInsert(gpa: Allocator, l: *std.ArrayList(types.TransactionIndex), v: types.TransactionIndex) Allocator.Error!void {
    const pos = std.sort.lowerBound(types.TransactionIndex, l.items, v, idxCmp);
    if (pos < l.items.len and l.items[pos] == v) return;
    try l.insert(gpa, pos, v);
}
fn idxRemove(l: *std.ArrayList(types.TransactionIndex), v: types.TransactionIndex) void {
    const pos = std.sort.lowerBound(types.TransactionIndex, l.items, v, idxCmp);
    if (pos < l.items.len and l.items[pos] == v) _ = l.orderedRemove(pos);
}
fn idxContains(l: []const types.TransactionIndex, v: types.TransactionIndex) bool {
    const pos = std.sort.lowerBound(types.TransactionIndex, l, v, idxCmp);
    return pos < l.len and l[pos] == v;
}

/// BTreeMap<BlockRef, BTreeSet<TransactionIndex>>: sorted entries, sets of indices.
const TxSets = struct {
    const E = struct { ref: types.BlockRef, idx: std.ArrayList(types.TransactionIndex) = .empty };
    entries: std.ArrayList(E) = .empty,

    fn deinit(self: *TxSets, gpa: Allocator) void {
        for (self.entries.items) |*e| e.idx.deinit(gpa);
        self.entries.deinit(gpa);
    }
    fn pos(self: *const TxSets, ref: types.BlockRef) usize {
        return std.sort.lowerBound(E, self.entries.items, ref, struct {
            fn c(ctx: types.BlockRef, item: E) std.math.Order {
                return ctx.order(item.ref);
            }
        }.c);
    }
    fn getOrPut(self: *TxSets, gpa: Allocator, ref: types.BlockRef) Allocator.Error!*E {
        const p = self.pos(ref);
        if (p < self.entries.items.len and self.entries.items[p].ref.eql(ref)) return &self.entries.items[p];
        try self.entries.insert(gpa, p, .{ .ref = ref });
        return &self.entries.items[p];
    }
    fn find(self: *TxSets, ref: types.BlockRef) ?*E {
        const p = self.pos(ref);
        if (p < self.entries.items.len and self.entries.items[p].ref.eql(ref)) return &self.entries.items[p];
        return null;
    }
    fn isEmpty(self: *const TxSets) bool {
        return self.entries.items.len == 0;
    }
    /// `remove_pending_transactions`: removes the indices, and the entry when it becomes empty.
    fn removeIdxs(self: *TxSets, gpa: Allocator, ref: types.BlockRef, idxs: []const types.TransactionIndex) void {
        const p = self.pos(ref);
        if (p >= self.entries.items.len or !self.entries.items[p].ref.eql(ref)) return;
        for (idxs) |i| idxRemove(&self.entries.items[p].idx, i);
        if (self.entries.items[p].idx.items.len == 0) {
            var e = self.entries.orderedRemove(p);
            e.idx.deinit(gpa);
        }
    }
};

const PendingBlock = struct { ref: types.BlockRef, num_transactions: usize };

const CommitState = struct {
    arena: std.heap.ArenaAllocator,
    commit: types.CommittedSubDag,
    already_finalized: bool,
    pending_blocks: std.ArrayList(PendingBlock) = .empty,
    pending_transactions: TxSets = .{},
    rejected_transactions: TxSets = .{},
    /// DAG boxes this commit's blocks point into (switch `share_blocks`), one hold each.
    boxes: std.ArrayList(*dag_mod.BlockInfo) = .empty,

    fn deinit(self: *CommitState, gpa: Allocator) void {
        for (self.boxes.items) |b| b.release();
        self.boxes.deinit(gpa);
        self.pending_blocks.deinit(gpa);
        self.pending_transactions.deinit(gpa);
        self.rejected_transactions.deinit(gpa);
        self.arena.deinit();
    }
};

const no_slot: u32 = std.math.maxInt(u32);

/// A child link of the dense walk: the child's slot and its heap key, so a push needs no lookup.
const DenseItem = struct { key: u64, slot: u32 };

fn denseKey(ref: types.BlockRef) u64 {
    return (@as(u64, ref.round) << 32) | ref.author;
}

const BlockState = struct {
    ref: types.BlockRef,
    block: *const types.VerifiedBlock,
    children: std.ArrayList(types.BlockRef) = .empty,
    /// target block -> its rejected indices, from this block's `transaction_votes`.
    reject_votes: []const types.BlockTransactionVotes,
    origin_descendants: std.ArrayList(types.BlockRef) = .empty,
    commit_index: types.CommitIndex,
    /// Dense walk only: this block's slot, and `children` and `origin_descendants` as slots.
    slot: u32 = no_slot,
    child_slots: std.ArrayList(DenseItem) = .empty,
    origin_descendant_slots: std.ArrayList(u32) = .empty,
};

/// (commit index, gc round of that commit's leader round) of a pending commit.
const GcRound = struct { index: types.CommitIndex, gc: types.Round };

const Acc = struct { idx: types.TransactionIndex, agg: Agg = .{} };

const RefSet = std.HashMapUnmanaged(types.BlockRef, void, store_mod.RefContext, 80);
const RefQueue = std.PriorityQueue(types.BlockRef, void, struct {
    fn lt(_: void, a: types.BlockRef, b: types.BlockRef) std.math.Order {
        return a.order(b);
    }
}.lt);
const DenseQueue = std.PriorityQueue(DenseItem, *const CommitFinalizer, CommitFinalizer.denseOrder);

/// Buffers of the dense walk, shared by the walks of one task in one pass. All memory comes from
/// the allocator of the first `reset`, which must be the one every later call passes.
const WalkScratch = struct {
    queued: []u64 = &.{},
    ignored: []u64 = &.{},
    to_visit: ?DenseQueue = null,

    fn reset(ws: *WalkScratch, a: Allocator, words: usize, fin: *const CommitFinalizer) Allocator.Error!void {
        if (ws.queued.len < words) {
            ws.queued = try a.alloc(u64, words);
            ws.ignored = try a.alloc(u64, words);
        }
        @memset(ws.queued[0..words], 0);
        @memset(ws.ignored[0..words], 0);
        if (ws.to_visit) |*q| q.clearRetainingCapacity() else ws.to_visit = DenseQueue.initContext(fin);
    }
};

fn bitSet(bits: []u64, i: u32) void {
    bits[i >> 6] |= @as(u64, 1) << @as(u6, @truncate(i));
}
/// Sets bit `i`; true when it was already set.
fn bitTestAndSet(bits: []u64, i: u32) bool {
    const m = @as(u64, 1) << @as(u6, @truncate(i));
    const was = bits[i >> 6] & m != 0;
    bits[i >> 6] |= m;
    return was;
}

/// One task's memory, kept between passes. Each on its own cache line: lanes allocate at once.
const TaskScratch = struct {
    arena: std.heap.ArenaAllocator align(std.atomic.cache_line),
};

/// Observation only: tests read these to prove that a case ran a path (a generated DAG that never
/// finalizes indirectly proves nothing about the indirect pass). Nothing decides on them.
pub const Counters = struct {
    /// Indirect passes over the first pending commit, and those over two or more pending blocks.
    indirect_passes: u64 = 0,
    multi_block_passes: u64 = 0,
    /// Passes in which indirect finalization emptied one pending block and a later pending block
    /// of the same pass still had finalized transactions to apply: the shape e272188b got wrong.
    emptied_then_later: u64 = 0,
    /// Transactions finalized by the indirect walk, rejected by a late reject quorum
    /// (`check_pending_transactions_in_first_commit`) and rejected after INDIRECT_REJECT_DEPTH.
    indirect_finalized: u64 = 0,
    late_rejected: u64 = 0,
    indirect_rejected: u64 = 0,
};

pub const CommitFinalizer = struct {
    gpa: Allocator,
    context: *const Context,
    dag: *dag_mod.DagState,
    votes: *TransactionVoteTracker,

    last_processed_commit: ?types.CommitIndex = null,
    pending_commits: std.ArrayList(*CommitState) = .empty,
    blocks: std.HashMapUnmanaged(types.BlockRef, *BlockState, store_mod.RefContext, 80) = .empty,
    counters: Counters = .{},
    /// Removals from `blocks` since its last rehash (store.zig `Churn`).
    blocks_churn: store_mod.Churn = .{},

    sw: Switches = .{},
    /// Dense walk: the linked block of every slot (null: free) and the free slots. `free_slots`
    /// always has room for every slot, so releasing one cannot fail.
    slots: std.ArrayList(?*BlockState) = .empty,
    free_slots: std.ArrayList(u32) = .empty,
    /// Lanes: the pool (made on first use, kept until `deinit`) and one scratch per task.
    pool: ?*core.pool.Pool = null,
    pool_tried: bool = false,
    task_scratch: std.ArrayList(*TaskScratch) = .empty,
    /// What the task arenas allocate from (tests inject failures here).
    lane_backing: Allocator = std.heap.page_allocator,
    /// Passes that ran on the pool, and passes that fell back to inline after a lane failed.
    lane_passes: u64 = 0,
    lane_fallbacks: u64 = 0,

    pub fn init(gpa: Allocator, context: *const Context, dag: *dag_mod.DagState, votes: *TransactionVoteTracker) CommitFinalizer {
        return .{ .gpa = gpa, .context = context, .dag = dag, .votes = votes, .sw = switchesFromEnv() };
    }

    /// Sets the switches. Only before the first commit: the dense walk numbers blocks as they are
    /// linked, so a finalizer that already holds blocks cannot change over.
    pub fn setSwitches(self: *CommitFinalizer, sw: Switches) err.Error!void {
        if (!self.isEmpty() or self.last_processed_commit != null) return error.Invariant;
        if (self.pool) |p| p.deinit();
        self.pool = null;
        self.pool_tried = false;
        self.sw = sw;
    }

    /// Lanes the indirect pass runs on (1: inline).
    pub fn lanesInUse(self: *CommitFinalizer) usize {
        if (self.sw.lanes == 1) return 1;
        const p = self.lanePool() orelse return 1;
        return p.lanes();
    }

    fn lanePool(self: *CommitFinalizer) ?*core.pool.Pool {
        if (self.pool) |p| return p;
        if (self.pool_tried) return null;
        self.pool_tried = true;
        const want = if (self.sw.lanes != 0) self.sw.lanes else @min(AUTO_LANES, @as(usize, core.hw.detect(null).logical_cores));
        const lanes = @min(want, MAX_LANES);
        if (lanes <= 1) return null;
        const p = core.pool.Pool.init(std.Io.Threaded.global_single_threaded.io(), self.gpa, lanes) catch return null;
        if (p.lanes() <= 1) {
            // no worker thread could be started: inline
            p.deinit();
            return null;
        }
        self.pool = p;
        return p;
    }

    pub fn deinit(self: *CommitFinalizer) void {
        for (self.pending_commits.items) |c| {
            c.deinit(self.gpa);
            self.gpa.destroy(c);
        }
        self.pending_commits.deinit(self.gpa);
        var it = self.blocks.valueIterator();
        while (it.next()) |b| self.freeBlockState(b.*);
        self.blocks.deinit(self.gpa);
        self.slots.deinit(self.gpa);
        self.free_slots.deinit(self.gpa);
        if (self.pool) |p| p.deinit();
        for (self.task_scratch.items) |ts| {
            ts.arena.deinit();
            self.gpa.destroy(ts);
        }
        self.task_scratch.deinit(self.gpa);
    }

    fn freeBlockState(self: *CommitFinalizer, b: *BlockState) void {
        b.children.deinit(self.gpa);
        b.origin_descendants.deinit(self.gpa);
        b.child_slots.deinit(self.gpa);
        b.origin_descendant_slots.deinit(self.gpa);
        self.gpa.destroy(b);
    }

    fn releaseSlot(self: *CommitFinalizer, slot: u32) void {
        self.slots.items[slot] = null;
        self.free_slots.appendAssumeCapacity(slot);
    }

    pub fn isEmpty(self: *const CommitFinalizer) bool {
        return self.pending_commits.items.len == 0 and self.blocks.count() == 0;
    }

    /// The finalizer task's loop body: finalizes `sub_dag` (or passes it through when voting is off
    /// or its rejects were recovered), updates the vote tracker's GC round, records finalized commits
    /// in the DagState and flushes it. Returns the finalized commits in commit order.
    pub fn process(self: *CommitFinalizer, out: Allocator, sub_dag: *const types.CommittedSubDag) err.Error![]Finalized {
        const already = !self.context.protocol_config.transaction_voting_enabled or sub_dag.recovered_rejected_transactions;
        var finalized: []Finalized = undefined;
        if (!already) {
            finalized = try self.processCommit(out, sub_dag);
        } else {
            var arena = std.heap.ArenaAllocator.init(self.gpa);
            errdefer arena.deinit();
            const copy = try copySubDag(arena.allocator(), sub_dag);
            const one = out.alloc(Finalized, 1) catch return error.OutOfMemory;
            one[0] = .{ .arena = arena, .sub_dag = copy, .already_finalized = true };
            finalized = one;
        }
        // The finalized commits own memory only the caller frees (an arena each, and a hold on
        // every block shared with the DAG window). If a step below fails the caller never sees
        // them, so they are freed here: a hold that stays keeps its block alive for good.
        errdefer for (finalized) |*f| f.deinit();
        if (finalized.len > 0) {
            const last_round = finalized[finalized.len - 1].sub_dag.leader.round;
            try self.votes.runGc(self.dag.calculateGcRound(last_round));
            for (finalized) |f| {
                if (!f.already_finalized) try self.dag.addFinalizedCommit(f.sub_dag.commit_ref, f.sub_dag.rejected_transactions_by_block);
            }
            try self.dag.flush();
        }
        return finalized;
    }

    /// `process_commit`: queues the commit, direct-finalizes what can be, then indirect-finalizes
    /// the first pending commit while possible. Commits must arrive in index order.
    pub fn processCommit(self: *CommitFinalizer, out: Allocator, sub_dag: *const types.CommittedSubDag) err.Error![]Finalized {
        if (self.last_processed_commit) |l| {
            if (l + 1 != sub_dag.commit_ref.index) return error.Invariant;
        }
        self.last_processed_commit = sub_dag.commit_ref.index;

        _ = try self.queueCommit(sub_dag);

        var finalized: std.ArrayList(Finalized) = .empty;
        // Arenas already handed to `finalized` are ours until the caller gets the list.
        errdefer for (finalized.items) |*f| f.deinit();

        var i: usize = 0;
        while (i < self.pending_commits.items.len) : (i += 1) {
            const st = self.pending_commits.items[i];
            if (st.pending_blocks.items.len == 0) continue;
            if (!st.commit.decided_with_local_blocks) {
                const last = self.pending_commits.items[self.pending_commits.items.len - 1];
                if (st.commit.leader.round + types.MINIMUM_WAVE_LENGTH > last.commit.leader.round) break;
            }
            try self.tryDirectFinalizeCommit(out, i);
        }
        try self.popFinalizedCommits(out, &finalized);

        if (self.pending_commits.items.len > 0) {
            try self.linkBlocksInLastCommit();
            try self.appendOriginDescendantsFromLastCommit();
            while (self.pending_commits.items.len > 1) {
                if (self.pending_commits.items[0].pending_blocks.items.len != 0) break;
                try self.tryIndirectFinalizeFirstCommit(out);
                const before = finalized.items.len;
                try self.popFinalizedCommits(out, &finalized);
                if (finalized.items.len == before) break;
            }
        }
        if (self.sw.cross_check and self.sw.walk == .dense) try self.verifyDense();
        return finalized.items;
    }

    /// Builds the CommitState and appends it to `pending_commits`. Cleanup on failure is scoped to
    /// the setup; once appended, `CommitFinalizer.deinit` owns it.
    fn queueCommit(self: *CommitFinalizer, sub_dag: *const types.CommittedSubDag) err.Error!*CommitState {
        const cs = self.gpa.create(CommitState) catch return error.OutOfMemory;
        cs.* = .{ .arena = std.heap.ArenaAllocator.init(self.gpa), .commit = undefined, .already_finalized = false };
        errdefer {
            cs.deinit(self.gpa);
            self.gpa.destroy(cs);
        }
        cs.commit = if (self.sw.share_blocks) try self.shareSubDag(cs, sub_dag) else try copySubDag(cs.arena.allocator(), sub_dag);
        if (cs.commit.blocks.len == 0) return error.Invariant;
        for (cs.commit.blocks) |b| {
            try insertPendingBlock(self.gpa, &cs.pending_blocks, b.reference(), b.block.inner.transactions().len);
        }
        self.pending_commits.append(self.gpa, cs) catch return error.OutOfMemory;
        return cs;
    }

    /// `copySubDag` with the blocks shared: a block the DAG window still caches is not copied,
    /// the commit takes a hold on its box and points into it. The block has the sub-dag block's
    /// ref, so the same bytes.
    fn shareSubDag(self: *CommitFinalizer, cs: *CommitState, s: *const types.CommittedSubDag) err.Error!types.CommittedSubDag {
        const arena = cs.arena.allocator();
        const blocks = arena.alloc(types.VerifiedBlock, s.blocks.len) catch return error.OutOfMemory;
        cs.boxes.ensureUnusedCapacity(self.gpa, s.blocks.len) catch return error.OutOfMemory;
        for (blocks, s.blocks) |*o, *b| {
            if (self.dag.shareBlock(b.reference())) |box| {
                cs.boxes.appendAssumeCapacity(box);
                o.* = box.block;
            } else o.* = try digest_mod.cloneVerified(arena, b);
        }
        const rej = arena.alloc(types.RejectedInBlock, s.rejected_transactions_by_block.len) catch return error.OutOfMemory;
        for (rej, s.rejected_transactions_by_block) |*o, r| o.* = .{ .block = r.block, .indices = arena.dupe(types.TransactionIndex, r.indices) catch return error.OutOfMemory };
        var c = s.*;
        c.blocks = blocks;
        c.rejected_transactions_by_block = rej;
        return c;
    }

    fn insertPendingBlock(gpa: Allocator, l: *std.ArrayList(PendingBlock), ref: types.BlockRef, n: usize) err.Error!void {
        const pos = std.sort.lowerBound(PendingBlock, l.items, ref, struct {
            fn c(ctx: types.BlockRef, item: PendingBlock) std.math.Order {
                return ctx.order(item.ref);
            }
        }.c);
        if (pos < l.items.len and l.items[pos].ref.eql(ref)) return;
        l.insert(gpa, pos, .{ .ref = ref, .num_transactions = n }) catch return error.OutOfMemory;
    }

    fn tryDirectFinalizeCommit(self: *CommitFinalizer, scratch: Allocator, index: usize) err.Error!void {
        const st = self.pending_commits.items[index];
        const vote_gc_round = self.dag.calculateGcRound(st.commit.leader.round + INDIRECT_REJECT_DEPTH);
        if (st.pending_blocks.items.len == 0) return error.Invariant;
        const pending = st.pending_blocks;
        st.pending_blocks = .empty;
        defer {
            var p = pending;
            p.deinit(self.gpa);
        }
        const quorum = self.context.committee.quorum_threshold;

        for (pending.items) |pb| {
            if (pb.ref.round <= vote_gc_round and pb.num_transactions > 0) {
                const e = st.pending_transactions.getOrPut(self.gpa, pb.ref) catch return error.OutOfMemory;
                var k: usize = 0;
                while (k < pb.num_transactions) : (k += 1) idxInsert(self.gpa, &e.idx, @intCast(k)) catch return error.OutOfMemory;
                continue;
            }
            const reject_votes = (try self.votes.getRejectVotes(scratch, pb.ref)) orelse return error.MissingBlock;
            for (reject_votes) |rv| {
                if (rv.stake < quorum) {
                    const e = st.pending_transactions.getOrPut(self.gpa, pb.ref) catch return error.OutOfMemory;
                    idxInsert(self.gpa, &e.idx, rv.index) catch return error.OutOfMemory;
                } else {
                    const e = st.rejected_transactions.getOrPut(self.gpa, pb.ref) catch return error.OutOfMemory;
                    idxInsert(self.gpa, &e.idx, rv.index) catch return error.OutOfMemory;
                }
            }
        }
    }

    fn linkBlocksInLastCommit(self: *CommitFinalizer) err.Error!void {
        const st = self.pending_commits.items[self.pending_commits.items.len - 1];
        const sorted = st.arena.allocator().dupe(types.VerifiedBlock, st.commit.blocks) catch return error.OutOfMemory;
        std.sort.block(types.VerifiedBlock, sorted, {}, struct {
            fn lt(_: void, a: types.VerifiedBlock, b: types.VerifiedBlock) bool {
                return a.block.inner.round() < b.block.inner.round();
            }
        }.lt);
        const dense = self.sw.walk == .dense;
        // The dense walk reads slots only; the ref lists are kept for the other walks and for the
        // cross-check.
        const keep_refs = !dense or self.sw.cross_check;
        for (sorted) |*b| {
            const ref = b.reference();
            // Dense: the block's own state first, its slot is what the ancestors link to. The
            // order makes no difference to the result: a block is not its own ancestor.
            const own_slot: u32 = if (dense) (try self.blockStateOf(st, b, ref)).slot else no_slot;
            for (b.block.inner.ancestors()) |anc| {
                const ab = self.blocks.get(anc) orelse continue;
                if (keep_refs) dag_mod.refSetInsert(self.gpa, &ab.children, ref) catch return error.OutOfMemory;
                if (dense) {
                    // `children` is a set: a block naming one ancestor twice appends twice in a
                    // row, so comparing with the last link keeps it one.
                    const l = ab.child_slots.items;
                    if (l.len == 0 or l[l.len - 1].slot != own_slot) ab.child_slots.append(self.gpa, .{ .key = denseKey(ref), .slot = own_slot }) catch return error.OutOfMemory;
                }
            }
            if (!dense) _ = try self.blockStateOf(st, b, ref);
        }
    }

    /// The block's state, created on first sight (Rust: `blocks_map.entry(ref).or_insert_with`).
    fn blockStateOf(self: *CommitFinalizer, st: *CommitState, b: *const types.VerifiedBlock, ref: types.BlockRef) err.Error!*BlockState {
        if (self.blocks.get(ref)) |bs| return bs;
        const rv = try normalizeVotes(st.arena.allocator(), b.block.inner.transactionVotes());
        const bs = self.gpa.create(BlockState) catch return error.OutOfMemory;
        errdefer self.gpa.destroy(bs);
        bs.* = .{ .ref = ref, .block = b, .reject_votes = rv, .commit_index = st.commit.commit_ref.index };
        if (self.sw.walk == .dense) {
            if (self.free_slots.pop()) |s| {
                self.slots.items[s] = bs;
                bs.slot = s;
            } else {
                self.free_slots.ensureTotalCapacity(self.gpa, self.slots.items.len + 1) catch return error.OutOfMemory;
                self.slots.append(self.gpa, bs) catch return error.OutOfMemory;
                bs.slot = @intCast(self.slots.items.len - 1);
            }
        }
        errdefer if (bs.slot != no_slot) self.releaseSlot(bs.slot);
        self.blocks.put(self.gpa, ref, bs) catch return error.OutOfMemory;
        return bs;
    }

    /// Test switch: the slot lists must name exactly the blocks the ref lists name, and every
    /// slot a linked block points at must hold a linked block (a block leaves the map only with
    /// its whole commit, and a child or origin descendant is never in an earlier commit).
    fn verifyDense(self: *const CommitFinalizer) err.Error!void {
        var it = self.blocks.valueIterator();
        while (it.next()) |p| {
            const b = p.*;
            if (b.slot >= self.slots.items.len or self.slots.items[b.slot] != b) return error.Invariant;
            if (b.child_slots.items.len != b.children.items.len) return error.Invariant;
            for (b.child_slots.items) |c| {
                if (c.slot >= self.slots.items.len) return error.Invariant;
                const cb = self.slots.items[c.slot] orelse return error.Invariant;
                if (denseKey(cb.ref) != c.key) return error.Invariant;
                const pos = std.sort.lowerBound(types.BlockRef, b.children.items, cb.ref, refCmp);
                if (pos >= b.children.items.len or !b.children.items[pos].eql(cb.ref)) return error.Invariant;
            }
            // distinct slots: with equal counts and every slot in `children`, a repeat would
            // leave one child unnamed
            for (b.child_slots.items, 0..) |c, i| {
                for (b.child_slots.items[0..i]) |d| if (d.slot == c.slot) return error.Invariant;
            }
            if (b.origin_descendant_slots.items.len != b.origin_descendants.items.len) return error.Invariant;
            for (b.origin_descendant_slots.items, b.origin_descendants.items) |s, r| {
                if (s >= self.slots.items.len) return error.Invariant;
                const ob = self.slots.items[s] orelse return error.Invariant;
                if (!ob.ref.eql(r)) return error.Invariant;
            }
        }
    }

    /// BlockState::new: BTreeMap<BlockRef, BTreeSet<TransactionIndex>> from the raw votes. A later
    /// entry for the same target replaces an earlier one; indices are a set whatever their order.
    /// V2 blocks are not checked for ordering or uniqueness by the verifier, so this must not assume it.
    fn normalizeVotes(a: Allocator, raw: []const types.BlockTransactionVotes) err.Error![]const types.BlockTransactionVotes {
        var table: std.ArrayList(types.BlockTransactionVotes) = .empty;
        for (raw) |tv| {
            const idxs = a.dupe(types.TransactionIndex, tv.rejects) catch return error.OutOfMemory;
            std.sort.block(types.TransactionIndex, idxs, {}, std.sort.asc(types.TransactionIndex));
            var w: usize = 0;
            for (idxs) |x| {
                if (w > 0 and idxs[w - 1] == x) continue;
                idxs[w] = x;
                w += 1;
            }
            const entry: types.BlockTransactionVotes = .{ .block_ref = tv.block_ref, .rejects = idxs[0..w] };
            const p = std.sort.lowerBound(types.BlockTransactionVotes, table.items, tv.block_ref, voteCmp);
            if (p < table.items.len and table.items[p].block_ref.eql(tv.block_ref)) {
                table.items[p] = entry;
            } else {
                table.insert(a, p, entry) catch return error.OutOfMemory;
            }
        }
        return table.items;
    }

    fn voteCmp(ctx: types.BlockRef, item: types.BlockTransactionVotes) std.math.Order {
        return ctx.order(item.block_ref);
    }

    fn appendOriginDescendantsFromLastCommit(self: *CommitFinalizer) err.Error!void {
        const st = self.pending_commits.items[self.pending_commits.items.len - 1];
        const sorted = st.arena.allocator().dupe(types.VerifiedBlock, st.commit.blocks) catch return error.OutOfMemory;
        std.sort.block(types.VerifiedBlock, sorted, {}, struct {
            fn lt(_: void, a: types.VerifiedBlock, b: types.VerifiedBlock) bool {
                return a.block.inner.round() < b.block.inner.round();
            }
        }.lt);
        for (sorted) |*b| {
            const ref = b.reference();
            const own = self.blocks.get(ref) orelse return error.Invariant;
            const anc = own.block.block.inner.ancestors();
            if (anc.len == 0) return error.Invariant;
            var origin = anc[0];
            const dense = self.sw.walk == .dense;
            while (origin.author == ref.author) {
                const ob = self.blocks.get(origin) orelse break;
                if (!dense or self.sw.cross_check) ob.origin_descendants.append(self.gpa, ref) catch return error.OutOfMemory;
                if (dense) ob.origin_descendant_slots.append(self.gpa, own.slot) catch return error.OutOfMemory;
                const oa = ob.block.block.inner.ancestors();
                if (oa.len == 0) return error.Invariant;
                origin = oa[0];
            }
        }
    }

    fn tryIndirectFinalizeFirstCommit(self: *CommitFinalizer, scratch: Allocator) err.Error!void {
        if (self.pending_commits.items.len == 0 or self.pending_commits.items[0].pending_blocks.items.len != 0) return error.Invariant;
        try self.checkPendingTransactionsInFirstCommit(scratch);
        try self.tryIndirectFinalizePendingTransactionsInFirstCommit(scratch);
        self.tryIndirectRejectPendingTransactionsInFirstCommit();
    }

    fn checkPendingTransactionsInFirstCommit(self: *CommitFinalizer, scratch: Allocator) err.Error!void {
        const st = self.pending_commits.items[0];
        const quorum = self.context.committee.quorum_threshold;
        const Rej = struct { ref: types.BlockRef, idxs: []types.TransactionIndex };
        var all: std.ArrayList(Rej) = .empty;
        for (st.pending_transactions.entries.items) |e| {
            const rv = (try self.votes.getRejectVotes(scratch, e.ref)) orelse return error.MissingBlock;
            var rejected: std.ArrayList(types.TransactionIndex) = .empty;
            for (e.idx.items) |idx| {
                var stake: types.Stake = 0;
                for (rv) |r| if (r.index == idx) {
                    stake = r.stake;
                    break;
                };
                if (stake < quorum) continue;
                rejected.append(scratch, idx) catch return error.OutOfMemory;
            }
            if (rejected.items.len > 0) all.append(scratch, .{ .ref = e.ref, .idxs = rejected.items }) catch return error.OutOfMemory;
        }
        for (all.items) |r| {
            self.counters.late_rejected += r.idxs.len;
            st.pending_transactions.removeIdxs(self.gpa, r.ref, r.idxs);
            const e = st.rejected_transactions.getOrPut(self.gpa, r.ref) catch return error.OutOfMemory;
            for (r.idxs) |i| idxInsert(self.gpa, &e.idx, i) catch return error.OutOfMemory;
        }
    }

    fn tryIndirectFinalizePendingTransactionsInFirstCommit(self: *CommitFinalizer, scratch: Allocator) err.Error!void {
        const st = self.pending_commits.items[0];
        // (commit index, gc round of that commit's leader round) for every pending commit.
        const gc_rounds = scratch.alloc(GcRound, self.pending_commits.items.len) catch return error.OutOfMemory;
        for (gc_rounds, self.pending_commits.items) |*g, c| g.* = .{ .index = c.commit.commit_ref.index, .gc = self.dag.calculateGcRound(c.commit.leader.round) };

        // (block ref, finalized indices) by value, collected for every pending block before
        // anything is removed (Rust: `all_finalized_transactions`). Removing an emptied entry
        // shifts the entries after it, so the removal must not read `entries` again.
        const Fin = struct { ref: types.BlockRef, idxs: []const types.TransactionIndex };
        var all: std.ArrayList(Fin) = .empty;
        const entries = st.pending_transactions.entries.items;
        if (try self.walkOnLanes(scratch, gc_rounds, entries)) |results| {
            for (entries, results) |e, r| {
                if (r.len > 0) all.append(scratch, .{ .ref = e.ref, .idxs = r }) catch return error.OutOfMemory;
            }
        } else {
            var ws: WalkScratch = .{};
            for (entries) |e| {
                const fin = try self.finalizeInBlock(scratch, &ws, gc_rounds, e.ref, e.idx.items);
                if (fin.len > 0) all.append(scratch, .{ .ref = e.ref, .idxs = fin }) catch return error.OutOfMemory;
            }
        }
        self.counters.indirect_passes += 1;
        if (entries.len >= 2) self.counters.multi_block_passes += 1;
        var emptied = false;
        var emptied_then_later = false;
        for (all.items) |f| {
            if (emptied) emptied_then_later = true;
            self.counters.indirect_finalized += f.idxs.len;
            st.pending_transactions.removeIdxs(self.gpa, f.ref, f.idxs);
            if (st.pending_transactions.find(f.ref) == null) emptied = true;
        }
        if (emptied_then_later) self.counters.emptied_then_later += 1;
    }

    const LaneJob = struct {
        fin: *const CommitFinalizer,
        gc_rounds: []const GcRound,
        entries: []const TxSets.E,
        results: [][]const types.TransactionIndex,
        per_task: usize,
        failed: *std.atomic.Value(bool),

        /// [lo, hi) is one task (or, when the pool runs the job inline, all of them): task `t`
        /// covers the pending blocks [t * per_task, (t + 1) * per_task) and owns scratch `t`.
        fn run(j: LaneJob, lo: usize, hi: usize) void {
            var i = lo;
            while (i < hi) {
                const end = @min(hi, i + j.per_task);
                const a = j.fin.task_scratch.items[i / j.per_task].arena.allocator();
                var ws: WalkScratch = .{};
                for (i..end) |k| {
                    if (j.failed.load(.acquire)) return;
                    j.results[k] = j.fin.finalizeInBlock(a, &ws, j.gc_rounds, j.entries[k].ref, j.entries[k].idx.items) catch {
                        j.failed.store(true, .release);
                        return;
                    };
                }
                i = end;
            }
        }
    };

    /// Runs the walks of one pass on the lane pool, as Rust runs chunks of pending blocks on
    /// blocking tasks. The lanes only read (`blocks`, `slots`, the block states); the caller
    /// applies the results in pending-block order, so the outcome is the serial one. Null when
    /// the pass runs inline instead: the switch is off, the pending set fits one task, there is
    /// no pool, or a lane failed. After a failure the inline run decides: it reports the error
    /// the serial path reports (the one of the first failing block), or succeeds if the failure
    /// was the lanes' own (out of memory in a task).
    fn walkOnLanes(self: *CommitFinalizer, scratch: Allocator, gc_rounds: []const GcRound, entries: []const TxSets.E) err.Error!?[]const []const types.TransactionIndex {
        if (self.sw.lanes == 1) return null;
        const per_task = @max(1, self.sw.blocks_per_task);
        const tasks = (entries.len + per_task - 1) / per_task;
        if (tasks <= 1) return null;
        const pool = self.lanePool() orelse return null;
        while (self.task_scratch.items.len < tasks) {
            const ts = self.gpa.create(TaskScratch) catch return null;
            ts.* = .{ .arena = .init(self.lane_backing) };
            self.task_scratch.append(self.gpa, ts) catch {
                self.gpa.destroy(ts);
                return null;
            };
        }
        // The results of the previous pass were applied before it returned.
        for (self.task_scratch.items[0..tasks]) |ts| _ = ts.arena.reset(.{ .retain_with_limit = task_arena_keep });
        const results = scratch.alloc([]const types.TransactionIndex, entries.len) catch return error.OutOfMemory;
        var failed: std.atomic.Value(bool) = .init(false);
        const job: LaneJob = .{ .fin = self, .gc_rounds = gc_rounds, .entries = entries, .results = results, .per_task = per_task, .failed = &failed };
        pool.forRange(entries.len, per_task, 0, job, LaneJob.run);
        if (failed.load(.acquire)) {
            self.lane_fallbacks += 1;
            return null;
        }
        self.lane_passes += 1;
        return results;
    }

    fn tryIndirectRejectPendingTransactionsInFirstCommit(self: *CommitFinalizer) void {
        const st = self.pending_commits.items[0];
        const last = self.pending_commits.items[self.pending_commits.items.len - 1];
        if (st.commit.leader.round + INDIRECT_REJECT_DEPTH > last.commit.leader.round) return;
        var pend = st.pending_transactions;
        st.pending_transactions = .{};
        defer pend.deinit(self.gpa);
        for (pend.entries.items) |e| {
            self.counters.indirect_rejected += e.idx.items.len;
            const r = st.rejected_transactions.getOrPut(self.gpa, e.ref) catch return;
            for (e.idx.items) |i| idxInsert(self.gpa, &r.idx, i) catch return;
        }
    }

    fn gcedVotes(gc_rounds: []const GcRound, pending_block_round: types.Round, pending_commit_index: types.CommitIndex, current_commit_index: types.CommitIndex) err.Error!bool {
        if (pending_commit_index > current_commit_index) return error.Invariant;
        if (pending_commit_index == current_commit_index) return false;
        const k = current_commit_index - 1 - pending_commit_index;
        if (k >= gc_rounds.len) return error.Invariant;
        const g = gc_rounds[k];
        if (g.index != current_commit_index - 1) return error.Invariant;
        return pending_block_round <= g.gc;
    }

    /// `try_indirect_finalize_pending_transactions_in_block` under the selected walk. Read-only on
    /// the finalizer: lanes call it at once. `a` and `ws` belong to the calling lane.
    fn finalizeInBlock(self: *const CommitFinalizer, a: Allocator, ws: *WalkScratch, gc_rounds: []const GcRound, pending_ref: types.BlockRef, pending: []const types.TransactionIndex) err.Error![]types.TransactionIndex {
        const got = switch (self.sw.walk) {
            .reference => return self.finalizeInBlockReference(a, gc_rounds, pending_ref, pending),
            .sets => try self.finalizeInBlockSets(a, gc_rounds, pending_ref, pending),
            .dense => try self.finalizeInBlockDense(a, ws, gc_rounds, pending_ref, pending),
        };
        if (self.sw.cross_check) {
            // The reference walk must fail where the new one fails and finalize the same set (the
            // order within the list does not matter: the caller removes the indices from a set).
            const want = try self.finalizeInBlockReference(a, gc_rounds, pending_ref, pending);
            if (want.len != got.len) return error.Invariant;
            std.mem.sort(types.TransactionIndex, want, {}, std.sort.asc(types.TransactionIndex));
            std.mem.sort(types.TransactionIndex, got, {}, std.sort.asc(types.TransactionIndex));
            if (!std.mem.eql(types.TransactionIndex, want, got)) return error.Invariant;
        }
        return got;
    }

    /// The vote step for one visited block that is not ignored: every transaction still waiting
    /// that `cur` did not reject gets the stake of `cur`'s author; those reaching a quorum move
    /// to `finalized`. True when none is left to wait for.
    fn countVotes(self: *const CommitFinalizer, a: Allocator, cur: *const BlockState, pending_ref: types.BlockRef, accs: []Acc, n_acc: *usize, finalized: *std.ArrayList(types.TransactionIndex)) err.Error!bool {
        const committee = &self.context.committee;
        var cur_rejects: []const types.TransactionIndex = &.{};
        {
            const vp = std.sort.lowerBound(types.BlockTransactionVotes, cur.reject_votes, pending_ref, voteCmp);
            if (vp < cur.reject_votes.len and cur.reject_votes[vp].block_ref.eql(pending_ref)) cur_rejects = cur.reject_votes[vp].rejects;
        }
        var k: usize = 0;
        while (k < n_acc.*) {
            const x = &accs[k];
            if (idxContains(cur_rejects, x.idx)) {
                k += 1;
                continue;
            }
            if (!x.agg.add(cur.ref.author, committee, committee.quorum_threshold)) {
                k += 1;
                continue;
            }
            finalized.append(a, x.idx) catch return error.OutOfMemory;
            accs[k] = accs[n_acc.* - 1];
            n_acc.* -= 1;
        }
        return n_acc.* == 0;
    }

    /// The walk with hash sets. Rust's `to_visit` is a BTreeSet and children are added only if
    /// not yet visited, so a ref enters it at most once over the whole walk: `queued` (every ref
    /// ever pushed) is that rule, and a popped ref is never seen again, so no `visited` set.
    fn finalizeInBlockSets(self: *const CommitFinalizer, a: Allocator, gc_rounds: []const GcRound, pending_ref: types.BlockRef, pending: []const types.TransactionIndex) err.Error![]types.TransactionIndex {
        if (pending.len == 0) return &.{};
        const accs = a.alloc(Acc, pending.len) catch return error.OutOfMemory;
        for (accs, pending) |*x, p| x.* = .{ .idx = p };
        var n_acc: usize = accs.len;
        var finalized: std.ArrayList(types.TransactionIndex) = .empty;

        const pbs = self.blocks.get(pending_ref) orelse return error.MissingBlock;
        var to_visit: RefQueue = RefQueue.initContext({});
        var queued: RefSet = .empty;
        var ignored: RefSet = .empty;
        for (pbs.children.items) |c| {
            const g = queued.getOrPut(a, c) catch return error.OutOfMemory;
            if (!g.found_existing) to_visit.push(a, c) catch return error.OutOfMemory;
        }
        while (to_visit.pop()) |cur_ref| {
            const cur = self.blocks.get(cur_ref) orelse return error.MissingBlock;
            const votes_gced = try gcedVotes(gc_rounds, pending_ref.round, pbs.commit_index, cur.commit_index);
            const ig = ignored.getOrPut(a, cur_ref) catch return error.OutOfMemory;
            if (!ig.found_existing) {
                for (cur.origin_descendants.items) |od| ignored.put(a, od, {}) catch return error.OutOfMemory;
                if (votes_gced) continue;
                if (try self.countVotes(a, cur, pending_ref, accs, &n_acc, &finalized)) break;
            }
            for (cur.children.items) |c| {
                const g = queued.getOrPut(a, c) catch return error.OutOfMemory;
                if (!g.found_existing) to_visit.push(a, c) catch return error.OutOfMemory;
            }
        }
        return finalized.items;
    }

    /// Heap order of the dense walk: (round, author), then the digest: `BlockRef`'s order, so
    /// blocks are visited exactly as Rust's BTreeSet yields them, equivocating blocks included.
    fn denseOrder(self: *const CommitFinalizer, x: DenseItem, y: DenseItem) std.math.Order {
        if (x.key != y.key) return std.math.order(x.key, y.key);
        if (x.slot == y.slot) return .eq;
        const bx = self.slots.items[x.slot] orelse return std.math.order(x.slot, y.slot);
        const by = self.slots.items[y.slot] orelse return std.math.order(x.slot, y.slot);
        return std.mem.order(u8, &bx.ref.digest, &by.ref.digest);
    }

    /// The walk on slots: the same steps as the reference walk, with `queued` and `ignored` as
    /// bitsets over the slots and the children and origin descendants as slot lists.
    fn finalizeInBlockDense(self: *const CommitFinalizer, a: Allocator, ws: *WalkScratch, gc_rounds: []const GcRound, pending_ref: types.BlockRef, pending: []const types.TransactionIndex) err.Error![]types.TransactionIndex {
        if (pending.len == 0) return &.{};
        const accs = a.alloc(Acc, pending.len) catch return error.OutOfMemory;
        for (accs, pending) |*x, p| x.* = .{ .idx = p };
        var n_acc: usize = accs.len;
        var finalized: std.ArrayList(types.TransactionIndex) = .empty;

        const pbs = self.blocks.get(pending_ref) orelse return error.MissingBlock;
        ws.reset(a, (self.slots.items.len + 63) / 64, self) catch return error.OutOfMemory;
        const to_visit = &ws.to_visit.?;
        for (pbs.child_slots.items) |c| {
            if (!bitTestAndSet(ws.queued, c.slot)) to_visit.push(a, c) catch return error.OutOfMemory;
        }
        while (to_visit.pop()) |item| {
            // A slot that is free, or was given to another block, is a block that left the map.
            const cur = self.slots.items[item.slot] orelse return error.MissingBlock;
            if (denseKey(cur.ref) != item.key) return error.MissingBlock;
            const votes_gced = try gcedVotes(gc_rounds, pending_ref.round, pbs.commit_index, cur.commit_index);
            if (!bitTestAndSet(ws.ignored, item.slot)) {
                for (cur.origin_descendant_slots.items) |od| bitSet(ws.ignored, od);
                if (votes_gced) continue;
                if (try self.countVotes(a, cur, pending_ref, accs, &n_acc, &finalized)) break;
            }
            for (cur.child_slots.items) |c| {
                if (!bitTestAndSet(ws.queued, c.slot)) to_visit.push(a, c) catch return error.OutOfMemory;
            }
        }
        return finalized.items;
    }

    /// `try_indirect_finalize_pending_transactions_in_block`: walks the descendants of the pending
    /// block in ref order; a transaction is finalized once descendants of 2f+1 stake (one per
    /// authority and origin chain) did not reject it.
    fn finalizeInBlockReference(self: *const CommitFinalizer, scratch: Allocator, gc_rounds: []const GcRound, pending_ref: types.BlockRef, pending: []const types.TransactionIndex) err.Error![]types.TransactionIndex {
        if (pending.len == 0) return &.{};
        const accs = scratch.alloc(Acc, pending.len) catch return error.OutOfMemory;
        for (accs, pending) |*a, p| a.* = .{ .idx = p };
        var n_acc: usize = accs.len;
        var finalized: std.ArrayList(types.TransactionIndex) = .empty;

        const pbs = self.blocks.get(pending_ref) orelse return error.MissingBlock;
        const pending_commit_index = pbs.commit_index;
        const Q = std.PriorityQueue(types.BlockRef, void, struct {
            fn lt(_: void, a: types.BlockRef, b: types.BlockRef) std.math.Order {
                return a.order(b);
            }
        }.lt);
        var to_visit: Q = Q.initContext({});
        for (pbs.children.items) |c| to_visit.push(scratch, c) catch return error.OutOfMemory;
        var visited: std.ArrayList(types.BlockRef) = .empty;
        var ignored: std.ArrayList(types.BlockRef) = .empty;
        const committee = &self.context.committee;

        while (to_visit.pop()) |cur_ref| {
            const vpos = std.sort.lowerBound(types.BlockRef, visited.items, cur_ref, refCmp);
            if (vpos < visited.items.len and visited.items[vpos].eql(cur_ref)) continue;
            visited.insert(scratch, vpos, cur_ref) catch return error.OutOfMemory;

            const cur = self.blocks.get(cur_ref) orelse return error.MissingBlock;
            const votes_gced = try gcedVotes(gc_rounds, pending_ref.round, pending_commit_index, cur.commit_index);
            const ipos = std.sort.lowerBound(types.BlockRef, ignored.items, cur_ref, refCmp);
            const already_ignored = ipos < ignored.items.len and ignored.items[ipos].eql(cur_ref);
            if (!already_ignored) {
                ignored.insert(scratch, ipos, cur_ref) catch return error.OutOfMemory;
                for (cur.origin_descendants.items) |od| dag_mod.refSetInsert(scratch, &ignored, od) catch return error.OutOfMemory;
                if (votes_gced) continue;

                // Reject votes of `cur` on the pending block.
                var cur_rejects: []const types.TransactionIndex = &.{};
                {
                    const vp = std.sort.lowerBound(types.BlockTransactionVotes, cur.reject_votes, pending_ref, voteCmp);
                    if (vp < cur.reject_votes.len and cur.reject_votes[vp].block_ref.eql(pending_ref)) cur_rejects = cur.reject_votes[vp].rejects;
                }
                var k: usize = 0;
                while (k < n_acc) {
                    const a = &accs[k];
                    if (idxContains(cur_rejects, a.idx)) {
                        k += 1;
                        continue;
                    }
                    if (!a.agg.add(cur_ref.author, committee, committee.quorum_threshold)) {
                        k += 1;
                        continue;
                    }
                    finalized.append(scratch, a.idx) catch return error.OutOfMemory;
                    accs[k] = accs[n_acc - 1];
                    n_acc -= 1;
                }
                if (n_acc == 0) break;
            }
            for (cur.children.items) |c| {
                const cp = std.sort.lowerBound(types.BlockRef, visited.items, c, refCmp);
                if (cp < visited.items.len and visited.items[cp].eql(c)) continue;
                to_visit.push(scratch, c) catch return error.OutOfMemory;
            }
        }
        return finalized.items;
    }

    fn popFinalizedCommits(self: *CommitFinalizer, out: Allocator, finalized: *std.ArrayList(Finalized)) err.Error!void {
        while (self.pending_commits.items.len > 0) {
            const st = self.pending_commits.items[0];
            if (st.pending_blocks.items.len != 0 or !st.pending_transactions.isEmpty()) break;

            // Rejected transactions by block, sorted by block ref (a BTreeMap in Rust).
            const a = st.arena.allocator();
            const rej = a.alloc(types.RejectedInBlock, st.rejected_transactions.entries.items.len) catch return error.OutOfMemory;
            for (rej, st.rejected_transactions.entries.items) |*o, e| {
                o.* = .{ .block = e.ref, .indices = a.dupe(types.TransactionIndex, e.idx.items) catch return error.OutOfMemory };
            }
            var commit = st.commit;
            commit.rejected_transactions_by_block = rej;
            // The holds on shared blocks go to the caller with the arena.
            const boxes = a.dupe(*dag_mod.BlockInfo, st.boxes.items) catch return error.OutOfMemory;
            finalized.ensureUnusedCapacity(out, 1) catch return error.OutOfMemory;
            _ = self.pending_commits.orderedRemove(0);

            var dropped: usize = 0;
            for (commit.blocks) |b| {
                if (self.blocks.fetchRemove(b.reference())) |kv| {
                    if (kv.value.slot != no_slot) self.releaseSlot(kv.value.slot);
                    self.freeBlockState(kv.value);
                    dropped += 1;
                }
            }
            self.blocks_churn.after(&self.blocks, store_mod.RefContext{}, dropped);
            // Transfer the arena to the caller.
            const arena = st.arena;
            st.pending_blocks.deinit(self.gpa);
            st.pending_transactions.deinit(self.gpa);
            st.rejected_transactions.deinit(self.gpa);
            st.boxes.deinit(self.gpa);
            self.gpa.destroy(st);
            finalized.appendAssumeCapacity(.{ .arena = arena, .sub_dag = commit, .already_finalized = false, .boxes = boxes });
        }
    }
};

/// Deep copy of a sub-dag into `arena`.
pub fn copySubDag(arena: Allocator, s: *const types.CommittedSubDag) err.Error!types.CommittedSubDag {
    const blocks = arena.alloc(types.VerifiedBlock, s.blocks.len) catch return error.OutOfMemory;
    for (blocks, s.blocks) |*o, *b| o.* = try digest_mod.cloneVerified(arena, b);
    const rej = arena.alloc(types.RejectedInBlock, s.rejected_transactions_by_block.len) catch return error.OutOfMemory;
    for (rej, s.rejected_transactions_by_block) |*o, r| o.* = .{ .block = r.block, .indices = arena.dupe(types.TransactionIndex, r.indices) catch return error.OutOfMemory };
    var c = s.*;
    c.blocks = blocks;
    c.rejected_transactions_by_block = rej;
    return c;
}

// ---------------------------------------------------------------- tests (ported from commit_finalizer.rs)

const test_dag = @import("test_dag.zig");
const verifier_mod = @import("verifier.zig");

const tx_data: [16]u8 = @splat(1);

const TestEnv = struct {
    f: *test_dag.Fixture,
    noop: verifier_mod.NoopTransactionVerifier = .{},
    tracker: TransactionVoteTracker,
    fin: CommitFinalizer,
    lin: @import("linearizer.zig").Linearizer,

    fn init(gpa: Allocator) !*TestEnv {
        var stakes = test_dag.Fixture.equalStakes(4);
        const self = try gpa.create(TestEnv);
        self.f = try test_dag.Fixture.init(gpa, .{ .stakes = &stakes, .protocol = .{ .gc_depth = 5, .transaction_voting_enabled = true, .num_leaders_per_round = 1, .bad_nodes_stake_threshold = 30 }, .parameters = .{ .skip_equivocation_validation = true } });
        self.noop = .{};
        self.tracker = TransactionVoteTracker.init(gpa, self.f.context, self.f.dag, self.noop.verifier());
        self.fin = CommitFinalizer.init(gpa, self.f.context, self.f.dag, &self.tracker);
        self.lin = self.f.linearizer();
        return self;
    }
    fn deinit(self: *TestEnv, gpa: Allocator) void {
        self.fin.deinit();
        self.tracker.deinit();
        self.f.deinit();
        gpa.destroy(self);
    }

    /// `create_block`: own authority first among ancestors, `n` transactions of 16 bytes.
    fn createBlock(self: *TestEnv, round: types.Round, author: types.AuthorityIndex, ancestors: []const types.BlockRef, n: usize, votes: []const types.BlockTransactionVotes) !types.VerifiedBlock {
        const a = self.f.arena();
        const anc = try a.dupe(types.BlockRef, ancestors);
        const i = for (anc, 0..) |r, k| {
            if (r.author == author) break k;
        } else return error.NoSelfAncestor;
        const first = anc[i];
        std.mem.copyBackwards(types.BlockRef, anc[1 .. i + 1], anc[0..i]);
        anc[0] = first;
        const txs = try a.alloc(types.Transaction, n);
        for (txs) |*t| t.* = .{ .data = &tx_data };
        const block: types.Block = .{ .V2 = .{ .epoch = 0, .round = round, .author = author, .timestamp_ms = round * 1000 + author, .ancestors = anc, .transactions = txs, .transaction_votes = try a.dupe(types.BlockTransactionVotes, votes), .commit_votes = &.{}, .misbehavior_reports = &.{} } };
        return digest_mod.verifiedForTest(a, block);
    }

    fn addBlocks(self: *TestEnv, blocks: []const types.VerifiedBlock) !void {
        for (blocks) |*b| {
            try self.tracker.addVotedBlock(b, &.{});
            try self.f.dag.acceptBlock(b);
        }
    }
    fn refs(self: *TestEnv, blocks: []const types.VerifiedBlock) ![]types.BlockRef {
        const out = try self.f.arena().alloc(types.BlockRef, blocks.len);
        for (out, blocks) |*o, b| o.* = b.reference();
        return out;
    }
};

test "V2 vote normalization: last duplicate target wins, rejects are a set" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const x: types.BlockRef = .{ .round = 1, .author = 2, .digest = @splat(3) };
    const y: types.BlockRef = .{ .round = 1, .author = 1, .digest = @splat(3) };
    const raw = [_]types.BlockTransactionVotes{
        .{ .block_ref = x, .rejects = &.{1} },
        .{ .block_ref = y, .rejects = &.{ 5, 1, 5 } },
        .{ .block_ref = x, .rejects = &.{} },
    };
    const t = try CommitFinalizer.normalizeVotes(arena.allocator(), &raw);
    try std.testing.expectEqual(@as(usize, 2), t.len);
    try std.testing.expect(t[0].block_ref.eql(y)); // sorted by block ref
    try std.testing.expectEqualSlices(types.TransactionIndex, &.{ 1, 5 }, t[0].rejects);
    try std.testing.expect(t[1].block_ref.eql(x));
    try std.testing.expectEqual(@as(usize, 0), t[1].rejects.len); // last entry wins: no reject
}

test "direct finalize with no reject votes" {
    const gpa = std.testing.allocator;
    const env = try TestEnv.init(gpa);
    defer env.deinit(gpa);
    const a = env.f.arena();

    var prev: []const types.BlockRef = env.f.genesisRefs();
    var round2_leader: ?types.VerifiedBlock = null;
    for (1..5) |r| {
        const blocks = try a.alloc(types.VerifiedBlock, 4);
        for (blocks, 0..) |*b, au| b.* = try env.createBlock(@intCast(r), @intCast(au), prev, 10, &.{});
        try env.addBlocks(blocks);
        if (r == 2) round2_leader = blocks[1];
        prev = try env.refs(blocks);
    }
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const leader = env.f.dag.getBlock(round2_leader.?.reference()).?;
    const subs = try env.lin.handleCommit(scratch.allocator(), &.{leader});
    try std.testing.expectEqual(@as(usize, 1), subs.len);
    const out = try env.fin.processCommit(scratch.allocator(), &subs[0]);
    try std.testing.expectEqual(@as(usize, 1), out.len);
    try std.testing.expectEqual(subs[0].commit_ref.index, out[0].sub_dag.commit_ref.index);
    try std.testing.expectEqual(@as(usize, 0), out[0].sub_dag.rejected_transactions_by_block.len);
    for (out) |*o| @constCast(o).deinit();
    try std.testing.expect(env.fin.isEmpty());
}

test "direct finalize with reject votes" {
    const gpa = std.testing.allocator;
    const env = try TestEnv.init(gpa);
    defer env.deinit(gpa);
    const a = env.f.arena();

    const r1 = try a.alloc(types.VerifiedBlock, 4);
    for (r1, 0..) |*b, au| b.* = try env.createBlock(1, @intCast(au), env.f.genesisRefs(), 10, &.{});
    // Our own reject votes (txns 0 and 3) for authority 3's block.
    for (r1) |*b| {
        const rej: []const types.TransactionIndex = if (b.block.inner.author() == 3) &.{ 0, 3 } else &.{};
        try env.tracker.addVotedBlock(b, rej);
        try env.f.dag.acceptBlock(b);
    }
    const rejected_block = r1[3].reference();
    const reject_vote: types.BlockTransactionVotes = .{ .block_ref = rejected_block, .rejects = &.{ 0, 3 } };
    const r1_refs = try env.refs(r1);

    const r2 = [_]types.VerifiedBlock{
        try env.createBlock(2, 0, r1_refs, 10, &.{reject_vote}),
        try env.createBlock(2, 1, r1_refs[0..3], 10, &.{}),
        try env.createBlock(2, 2, r1_refs[0..3], 10, &.{}),
    };
    try env.addBlocks(&r2);
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const leader = env.f.dag.getBlock(r2[0].reference()).?;
    const subs = try env.lin.handleCommit(scratch.allocator(), &.{leader});
    try std.testing.expectEqual(@as(usize, 5), subs[0].blocks.len);

    const r2_refs = try env.refs(&r2);
    const self_anc = try a.dupe(types.BlockRef, &.{rejected_block});
    const r3_anc3 = try std.mem.concat(a, types.BlockRef, &.{ self_anc, r2_refs });
    const r3 = [_]types.VerifiedBlock{
        try env.createBlock(3, 0, r2_refs, 0, &.{}),
        try env.createBlock(3, 1, r2_refs, 0, &.{reject_vote}),
        try env.createBlock(3, 2, r2_refs, 0, &.{reject_vote}),
        try env.createBlock(3, 3, r3_anc3, 0, &.{reject_vote}),
    };
    try env.addBlocks(&r3);
    const r3_refs = try env.refs(&r3);
    var r4: [4]types.VerifiedBlock = undefined;
    for (&r4, 0..) |*b, au| b.* = try env.createBlock(4, @intCast(au), r3_refs, 0, &.{});
    try env.addBlocks(&r4);

    const out = try env.fin.processCommit(scratch.allocator(), &subs[0]);
    try std.testing.expectEqual(@as(usize, 1), out.len);
    const rej = out[0].sub_dag.rejected_transactions_by_block;
    try std.testing.expectEqual(@as(usize, 1), rej.len);
    try std.testing.expect(rej[0].block.eql(rejected_block));
    try std.testing.expectEqualSlices(types.TransactionIndex, &.{ 0, 3 }, rej[0].indices);
    for (out) |*o| @constCast(o).deinit();
    try std.testing.expect(env.fin.isEmpty());
}

test "indirect finalize: late reject quorum, indirect reject, indirect finalize" {
    const gpa = std.testing.allocator;
    const env = try TestEnv.init(gpa);
    defer env.deinit(gpa);
    const a = env.f.arena();

    const r1 = try a.alloc(types.VerifiedBlock, 4);
    for (r1, 0..) |*b, au| b.* = try env.createBlock(1, @intCast(au), env.f.genesisRefs(), 10, &.{});
    for (r1) |*b| {
        const rej: []const types.TransactionIndex = if (b.block.inner.author() == 3) &.{ 0, 3 } else &.{};
        try env.tracker.addVotedBlock(b, rej);
        try env.f.dag.acceptBlock(b);
    }
    const target = r1[3].reference();
    const r1_refs = try env.refs(r1);

    const r2 = [_]types.VerifiedBlock{
        try env.createBlock(2, 0, r1_refs, 10, &.{.{ .block_ref = target, .rejects = &.{ 1, 4 } }}),
        try env.createBlock(2, 1, r1_refs[0..3], 10, &.{}),
        try env.createBlock(2, 2, r1_refs[0..3], 10, &.{}),
    };
    try env.addBlocks(&r2);
    var leaders: std.ArrayList(*const types.VerifiedBlock) = .empty;
    try leaders.append(a, env.f.dag.getBlock(r2[0].reference()).?);

    const r2_refs = try env.refs(&r2);
    const r3_anc3 = try std.mem.concat(a, types.BlockRef, &.{ &[_]types.BlockRef{target}, r2_refs });
    const r3 = [_]types.VerifiedBlock{
        try env.createBlock(3, 0, r2_refs, 0, &.{}),
        try env.createBlock(3, 1, r2_refs, 0, &.{.{ .block_ref = target, .rejects = &.{ 1, 4, 7 } }}),
        try env.createBlock(3, 3, r3_anc3, 0, &.{}),
    };
    try env.addBlocks(&r3);
    try leaders.append(a, env.f.dag.getBlock(r3[2].reference()).?);

    const r3_refs = try env.refs(&r3);
    const r4_anc2 = try std.mem.concat(a, types.BlockRef, &.{ &[_]types.BlockRef{r2[2].reference()}, r3_refs });
    const r4 = [_]types.VerifiedBlock{
        try env.createBlock(4, 0, r3_refs, 0, &.{}),
        try env.createBlock(4, 1, r3_refs, 0, &.{}),
        try env.createBlock(4, 2, r4_anc2, 0, &.{.{ .block_ref = target, .rejects = &.{1} }}),
        try env.createBlock(4, 3, r3_refs, 0, &.{}),
    };
    try env.addBlocks(&r4);
    try leaders.append(a, env.f.dag.getBlock(r4[1].reference()).?);

    var last: []const types.BlockRef = try env.refs(&r4);
    for (5..6) |r| {
        const bl = try a.alloc(types.VerifiedBlock, 4);
        for (bl, 0..) |*b, au| b.* = try env.createBlock(@intCast(r), @intCast(au), last, 0, &.{});
        try env.addBlocks(bl);
        try leaders.append(a, env.f.dag.getBlock(bl[0].reference()).?);
        last = try env.refs(bl);
    }
    try std.testing.expectEqual(@as(usize, 4), leaders.items.len);

    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const subs = try env.lin.handleCommit(scratch.allocator(), leaders.items);
    for (subs[0..3]) |*s| {
        const out = try env.fin.processCommit(scratch.allocator(), s);
        try std.testing.expectEqual(@as(usize, 0), out.len);
    }
    const out = try env.fin.processCommit(scratch.allocator(), &subs[3]);
    try std.testing.expectEqual(@as(usize, 4), out.len);
    const rej = out[0].sub_dag.rejected_transactions_by_block;
    try std.testing.expectEqual(@as(usize, 1), rej.len);
    try std.testing.expect(rej[0].block.eql(target));
    try std.testing.expectEqualSlices(types.TransactionIndex, &.{ 1, 4 }, rej[0].indices);
    for (out[1..]) |o| try std.testing.expectEqual(@as(usize, 0), o.sub_dag.rejected_transactions_by_block.len);
    for (out) |*o| @constCast(o).deinit();
    try std.testing.expect(env.fin.isEmpty());
}

// Three more of commit_finalizer.rs, each under every switch setting (`switch_settings`).

const no_votes: []const types.BlockTransactionVotes = &.{};

fn subDagHas(s: *const types.CommittedSubDag, ref: types.BlockRef) bool {
    for (s.blocks) |*b| {
        if (b.reference().eql(ref)) return true;
    }
    return false;
}

// test_direct_finalize_with_gc: direct finalization when a block is at or below the GC round
// seen from the leader that commits it.
test "direct finalize with GC: every transaction of a block below the GC round of its voters is rejected" {
    const gpa = std.testing.allocator;
    const t = std.testing;
    for (switch_settings) |sw| {
        const env = try TestEnv.init(gpa);
        defer env.deinit(gpa);
        try env.fin.setSwitches(sw);
        const a = env.f.arena();
        try t.expectEqual(@as(u32, 5), env.f.context.protocol_config.gc_depth);

        // Round 1 with 10 transactions per block. B1(3) is the block to be rejected.
        const r1 = try a.alloc(types.VerifiedBlock, 4);
        for (r1, 0..) |*b, au| b.* = try env.createBlock(1, @intCast(au), env.f.genesisRefs(), 10, no_votes);
        try env.addBlocks(r1);
        const rejected = r1[3].reference();

        // Rounds 2 to 5 without authority 3 and without a link to B1(3).
        var last: []const types.BlockRef = try env.refs(r1[0..3]);
        for (2..6) |r| {
            const bl = try a.alloc(types.VerifiedBlock, 3);
            for (bl, 0..) |*b, au| b.* = try env.createBlock(@intCast(r), @intCast(au), last, 0, no_votes);
            try env.addBlocks(bl);
            last = try env.refs(bl);
        }
        // Rounds 6 to 9 without authority 3. Authority 0 leads each round, and only its blocks
        // link to B1(3).
        var leaders: std.ArrayList(*const types.VerifiedBlock) = .empty;
        for (6..10) |r| {
            const bl = try a.alloc(types.VerifiedBlock, 3);
            for (bl, 0..) |*b, au| {
                const anc = if (au == 0) try std.mem.concat(a, types.BlockRef, &.{ last, &[_]types.BlockRef{rejected} }) else last;
                b.* = try env.createBlock(@intCast(r), @intCast(au), anc, 0, no_votes);
            }
            try env.addBlocks(bl);
            try leaders.append(a, env.f.dag.getBlock(bl[0].reference()).?);
            last = try env.refs(bl);
        }

        var scratch = std.heap.ArenaAllocator.init(gpa);
        defer scratch.deinit();
        const subs = try env.lin.handleCommit(scratch.allocator(), leaders.items);
        try t.expectEqual(@as(usize, 4), subs.len);
        try t.expect(subDagHas(&subs[0], rejected));

        for (subs[0..3]) |*s| {
            try t.expect(s.decided_with_local_blocks);
            try t.expectEqual(@as(usize, 0), (try env.fin.processCommit(scratch.allocator(), s)).len);
        }
        const out = try env.fin.processCommit(scratch.allocator(), &subs[3]);
        defer for (out) |*o| o.deinit();
        try t.expectEqual(@as(usize, 4), out.len);
        // B1(3) is voted on by its own author and by authority 0 only (the first block of
        // authority 0 that links to it counts; its later blocks are origin descendants). For
        // B7(1) and B7(2), committed by the round 8 leader, B1(3) is below the GC round, so
        // authorities 1 and 2 give no accept vote: every transaction ends rejected.
        const rej = out[0].sub_dag.rejected_transactions_by_block;
        try t.expectEqual(@as(usize, 1), rej.len);
        try t.expect(rej[0].block.eql(rejected));
        try t.expectEqualSlices(types.TransactionIndex, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, rej[0].indices);
        for (out[1..]) |o| try t.expectEqual(@as(usize, 0), o.sub_dag.rejected_transactions_by_block.len);
        try t.expect(env.fin.isEmpty());
    }
}

// test_indirect_reject_with_gc: a transaction with one reject vote ends rejected because a
// block that would have accepted it was garbage collected.
test "indirect reject with GC: two accept votes are not a quorum once the third voter's block is garbage collected" {
    const gpa = std.testing.allocator;
    const t = std.testing;
    for (switch_settings) |sw| {
        const env = try TestEnv.init(gpa);
        defer env.deinit(gpa);
        try env.fin.setSwitches(sw);
        const a = env.f.arena();
        try t.expectEqual(@as(u32, 5), env.f.context.protocol_config.gc_depth);

        const r1 = try a.alloc(types.VerifiedBlock, 4);
        for (r1, 0..) |*b, au| b.* = try env.createBlock(1, @intCast(au), env.f.genesisRefs(), 10, no_votes);
        try env.addBlocks(r1);
        const target = r1[3].reference();
        const r1_refs = try env.refs(r1);

        // Round 2: all four link to B1(3); B2(1) rejects its transaction 1, the others do not.
        const reject_1 = [_]types.BlockTransactionVotes{.{ .block_ref = target, .rejects = &.{1} }};
        const r2 = try a.alloc(types.VerifiedBlock, 4);
        for (r2, 0..) |*b, au| b.* = try env.createBlock(2, @intCast(au), r1_refs, 0, if (au == 1) &reject_1 else no_votes);
        try env.addBlocks(r2);

        // Rounds 3 to 6 without authority 2 and without a link to B2(2), so B2(2) is garbage
        // collected.
        const three = [_]types.AuthorityIndex{ 0, 1, 3 };
        var last: []const types.BlockRef = try a.dupe(types.BlockRef, &.{ r2[0].reference(), r2[1].reference(), r2[3].reference() });
        for (3..7) |r| {
            const bl = try a.alloc(types.VerifiedBlock, 3);
            for (bl, three) |*b, au| b.* = try env.createBlock(@intCast(r), au, last, 0, no_votes);
            try env.addBlocks(bl);
            last = try env.refs(bl);
        }
        // Rounds 7 to 10 with all four; authority 0 leads each round. B7(2) links to B2(2).
        var leaders: std.ArrayList(*const types.VerifiedBlock) = .empty;
        for (7..11) |r| {
            const bl = try a.alloc(types.VerifiedBlock, 4);
            for (bl, 0..) |*b, au| {
                const anc = if (r == 7 and au == 2) try std.mem.concat(a, types.BlockRef, &.{ last, &[_]types.BlockRef{r2[2].reference()} }) else last;
                b.* = try env.createBlock(@intCast(r), @intCast(au), anc, 0, no_votes);
            }
            try env.addBlocks(bl);
            try leaders.append(a, env.f.dag.getBlock(bl[0].reference()).?);
            last = try env.refs(bl);
        }

        var scratch = std.heap.ArenaAllocator.init(gpa);
        defer scratch.deinit();
        const subs = try env.lin.handleCommit(scratch.allocator(), leaders.items);
        try t.expectEqual(@as(usize, 4), subs.len);
        // the reject vote of B2(1) is in the first commit; B2(2) is in none
        try t.expect(subDagHas(&subs[0], r2[1].reference()));
        for (subs) |*s| try t.expect(!subDagHas(s, r2[2].reference()));

        for (subs[0..3]) |*s| {
            try t.expect(s.decided_with_local_blocks);
            try t.expectEqual(@as(usize, 0), (try env.fin.processCommit(scratch.allocator(), s)).len);
        }
        const out = try env.fin.processCommit(scratch.allocator(), &subs[3]);
        defer for (out) |*o| o.deinit();
        try t.expectEqual(@as(usize, 4), out.len);
        // Three blocks link to B1(3) without rejecting transaction 1, but B2(2) is gone: two
        // accept votes are below the quorum.
        const rej = out[0].sub_dag.rejected_transactions_by_block;
        try t.expectEqual(@as(usize, 1), rej.len);
        try t.expect(rej[0].block.eql(target));
        try t.expectEqualSlices(types.TransactionIndex, &.{1}, rej[0].indices);
        for (out[1..]) |o| try t.expectEqual(@as(usize, 0), o.sub_dag.rejected_transactions_by_block.len);
        try t.expect(env.fin.isEmpty());
    }
}

// test_finalize_remote_commits_with_reject_votes: commits decided from certified commits of
// peers (`decided_with_local_blocks` false) wait until a later commit is MINIMUM_WAVE_LENGTH
// leader rounds ahead; local commits finalize what is behind them.
test "remote commits: a commit decided without local blocks is finalized once a commit three leader rounds later arrives" {
    const gpa = std.testing.allocator;
    const t = std.testing;
    const Want = struct { index: types.CommitIndex, round: types.Round };
    const Step = struct { local: bool, want: []const Want };
    const steps = [_]Step{
        // commits 1 to 3 (rounds 1 to 3) as remote commits: nothing is finalized
        .{ .local = false, .want = &.{} },
        .{ .local = false, .want = &.{} },
        .{ .local = false, .want = &.{} },
        // the round 4 commit, remote: finalizes the round 1 commit
        .{ .local = false, .want = &.{.{ .index = 1, .round = 1 }} },
        // the round 6 commit, local: finalizes the commits of rounds 2 and 3
        .{ .local = true, .want = &.{ .{ .index = 2, .round = 2 }, .{ .index = 3, .round = 3 } } },
        // the round 7 commit, local: finalizes rounds 4, 6 and itself
        .{ .local = true, .want = &.{ .{ .index = 4, .round = 4 }, .{ .index = 5, .round = 6 }, .{ .index = 6, .round = 7 } } },
    };
    for (switch_settings) |sw| {
        const env = try TestEnv.init(gpa);
        defer env.deinit(gpa);
        try env.fin.setSwitches(sw);
        const a = env.f.arena();

        // Rounds 1 to 9, full; round 1 with 10 transactions per block. Not added to the DAG yet.
        var rounds: [9][]types.VerifiedBlock = undefined;
        var leaders: std.ArrayList(types.BlockRef) = .empty;
        var prev: []const types.BlockRef = env.f.genesisRefs();
        for (1..10) |r| {
            const bl = try a.alloc(types.VerifiedBlock, 4);
            for (bl, 0..) |*b, au| b.* = try env.createBlock(@intCast(r), @intCast(au), prev, if (r == 1) 10 else 0, no_votes);
            rounds[r - 1] = bl;
            // leader rounds 1, 2, 3, 4, 6, 7
            if (r == 1) try leaders.append(a, bl[0].reference()) else if (r <= 7 and r != 5) try leaders.append(a, bl[r % 4].reference());
            prev = try env.refs(bl);
        }
        try t.expectEqual(steps.len, leaders.items.len);

        var scratch = std.heap.ArenaAllocator.init(gpa);
        defer scratch.deinit();
        var added: usize = 0; // rounds in the DAG and the vote tracker so far
        for (steps, leaders.items) |st, leader| {
            // A remote commit comes with the blocks up to its leader's round; a local one was
            // decided from blocks two rounds above the leader.
            const upto = @min(rounds.len, leader.round + @as(usize, if (st.local) 2 else 0));
            while (added < upto) : (added += 1) try env.addBlocks(rounds[added]);
            const subs = try env.lin.handleCommit(scratch.allocator(), &.{env.f.dag.getBlock(leader).?});
            try t.expectEqual(@as(usize, 1), subs.len);
            subs[0].decided_with_local_blocks = st.local;
            const out = try env.fin.processCommit(scratch.allocator(), &subs[0]);
            defer for (out) |*o| o.deinit();
            try t.expectEqual(st.want.len, out.len);
            for (st.want, out) |w, o| {
                try t.expectEqual(w.index, o.sub_dag.commit_ref.index);
                try t.expectEqual(w.round, o.sub_dag.leader.round);
            }
        }
        try t.expect(env.fin.isEmpty());
    }
}

// ---------------------------------------------------------------- tests of the switches

test "switch variables: known values set the switch, an unknown value keeps the default and is flagged, the startup lines name it" {
    const t = std.testing;
    // unset: every switch off, nothing flagged, nothing to say
    {
        const p = parseSwitches(.{}, 8);
        try t.expectEqual(Switches{}, p.sw);
        try t.expectEqual(ParsedSwitches.Unknown{}, p.unknown);
        var buf: [256]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try writeStartupLines(&w, .{}, p, false, null);
        try t.expectEqualStrings("", w.buffered());
    }
    // every known value
    for ([_]Walk{ .reference, .sets, .dense }) |walk| {
        const p = parseSwitches(.{ .walk = @tagName(walk) }, 8);
        try t.expectEqual(walk, p.sw.walk);
        try t.expect(!p.unknown.walk);
    }
    try t.expectEqual(@as(usize, 0), parseSwitches(.{ .lanes = "auto" }, 8).sw.lanes);
    try t.expectEqual(@as(usize, 1), parseSwitches(.{ .lanes = "1" }, 8).sw.lanes);
    try t.expectEqual(@as(usize, 4), parseSwitches(.{ .lanes = "4" }, 8).sw.lanes);
    try t.expect(parseSwitches(.{ .share_blocks = "1" }, 8).sw.share_blocks);
    try t.expect(!parseSwitches(.{ .share_blocks = "0" }, 8).sw.share_blocks);
    try t.expect(!parseSwitches(.{ .share_blocks = "0" }, 8).unknown.share_blocks);
    // unknown values: the default, flagged, and only the variable at fault
    for ([_][]const u8{ "Dense", "fast", "", "dense ", "1" }) |v| {
        const p = parseSwitches(.{ .walk = v, .lanes = "4", .share_blocks = "1" }, 8);
        try t.expectEqual(Walk.reference, p.sw.walk);
        try t.expectEqual(ParsedSwitches.Unknown{ .walk = true }, p.unknown);
        try t.expectEqual(@as(usize, 4), p.sw.lanes);
        try t.expect(p.sw.share_blocks);
    }
    for ([_][]const u8{ "four", "", "-1", "4x", "Auto", "1.5" }) |v| {
        const p = parseSwitches(.{ .lanes = v }, 8);
        try t.expectEqual(@as(usize, 1), p.sw.lanes);
        try t.expectEqual(ParsedSwitches.Unknown{ .lanes = true }, p.unknown);
    }
    for ([_][]const u8{ "true", "yes", "", "2", "on" }) |v| {
        const p = parseSwitches(.{ .share_blocks = v }, 8);
        try t.expect(!p.sw.share_blocks);
        try t.expectEqual(ParsedSwitches.Unknown{ .share_blocks = true }, p.unknown);
    }
    try t.expectEqual(@as(?bool, true), store_mod.parseOnOff("1"));
    try t.expectEqual(@as(?bool, false), store_mod.parseOnOff("0"));
    try t.expectEqual(@as(?bool, null), store_mod.parseOnOff("true"));
    try t.expectEqual(@as(?bool, null), store_mod.parseOnOff(""));

    // The startup lines: one `switches` line when anything is on, with every switch in it.
    var buf: [1024]u8 = undefined;
    {
        var w: std.Io.Writer = .fixed(&buf);
        const env: EnvText = .{ .walk = "dense", .lanes = "4", .share_blocks = "1" };
        try writeStartupLines(&w, env, parseSwitches(env, 8), true, null);
        try t.expectEqualStrings("consensus finalizer: switches walk=dense lanes=4 share_blocks=1 rehash=1\n", w.buffered());
    }
    {
        // one switch on is enough, the rehash switch included; auto lanes are named
        var w: std.Io.Writer = .fixed(&buf);
        try writeStartupLines(&w, .{}, parseSwitches(.{}, 8), true, null);
        try t.expectEqualStrings("consensus finalizer: switches walk=reference lanes=1 share_blocks=0 rehash=1\n", w.buffered());
        w = .fixed(&buf);
        try writeStartupLines(&w, .{ .lanes = "auto" }, parseSwitches(.{ .lanes = "auto" }, 8), false, null);
        try t.expectEqualStrings("consensus finalizer: switches walk=reference lanes=auto share_blocks=0 rehash=0\n", w.buffered());
    }
    {
        // A mistyped walk with the other switches on: the warning names variable and value, and
        // the switches line shows the walk that really runs.
        var w: std.Io.Writer = .fixed(&buf);
        const env: EnvText = .{ .walk = "Dense", .lanes = "4", .share_blocks = "yes" };
        try writeStartupLines(&w, env, parseSwitches(env, 8), false, "true");
        try t.expectEqualStrings(
            "consensus finalizer: WARNING ZUI_FINALIZER_WALK=Dense is not reference, sets or dense; the switch stays at its default\n" ++
                "consensus finalizer: WARNING ZUI_FINALIZER_SHARE_BLOCKS=yes is not 0 or 1; the switch stays at its default\n" ++
                "consensus finalizer: WARNING ZUI_CONSENSUS_REHASH=true is not 0 or 1; the switch stays at its default\n" ++
                "consensus finalizer: switches walk=reference lanes=4 share_blocks=0 rehash=0\n",
            w.buffered(),
        );
    }
    {
        // only unknown values, every switch at its default: warnings, no switches line
        var w: std.Io.Writer = .fixed(&buf);
        const env: EnvText = .{ .lanes = "many" };
        try writeStartupLines(&w, env, parseSwitches(env, 8), false, null);
        try t.expectEqualStrings("consensus finalizer: WARNING ZUI_FINALIZER_LANES=many is not a lane count (1 or more) or auto; the switch stays at its default\n", w.buffered());
    }
}

test "ZUI_FINALIZER_LANES: 0 is refused, a count is capped by the CPU count and by MAX_LANES, auto stays auto" {
    const t = std.testing;
    // 0 used to mean auto: now unknown, the pass stays inline, and the startup lines say so
    for ([_][]const u8{ "0", "00", "+0" }) |v| {
        const p = parseSwitches(.{ .lanes = v }, 8);
        try t.expectEqual(@as(usize, 1), p.sw.lanes);
        try t.expectEqual(ParsedSwitches.Unknown{ .lanes = true }, p.unknown);
    }
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeStartupLines(&w, .{ .lanes = "0" }, parseSwitches(.{ .lanes = "0" }, 8), false, null);
    try t.expectEqualStrings("consensus finalizer: WARNING ZUI_FINALIZER_LANES=0 is not a lane count (1 or more) or auto; the switch stays at its default\n", w.buffered());

    // (asked, CPUs, lanes)
    const rows = [_]struct { []const u8, usize, usize }{
        .{ "4", 8, 4 }, // fits
        .{ "4", 4, 4 },
        .{ "4", 2, 2 }, // a quota of two cores
        .{ "4", 1, 1 }, // a quota of one core: inline
        .{ "8", 3, 3 },
        .{ "8", 64, 8 },
        .{ "64", 64, MAX_LANES },
        .{ "1", 1, 1 },
        .{ "2", 0, 1 }, // a CPU count that could not be read counts as one
    };
    for (rows) |r| {
        const p = parseSwitches(.{ .lanes = r[0] }, r[1]);
        try t.expectEqual(r[2], p.sw.lanes);
        try t.expect(!p.unknown.lanes);
    }
    // auto is resolved when the pool is made (min(AUTO_LANES, CPU count)), not here
    for ([_]usize{ 1, 2, 64 }) |cpus| try t.expectEqual(@as(usize, 0), parseSwitches(.{ .lanes = "auto" }, cpus).sw.lanes);
    // a capped count shows in the switches line as what runs
    w = .fixed(&buf);
    try writeStartupLines(&w, .{ .lanes = "8" }, parseSwitches(.{ .lanes = "8" }, 2), false, null);
    try t.expectEqualStrings("consensus finalizer: switches walk=reference lanes=2 share_blocks=0 rehash=0\n", w.buffered());
    // and a count capped to 1 is the default: nothing to announce
    w = .fixed(&buf);
    try writeStartupLines(&w, .{ .lanes = "8" }, parseSwitches(.{ .lanes = "8" }, 1), false, null);
    try t.expectEqualStrings("", w.buffered());
}

/// Every switch setting the unit tests run. One pending block per task puts the three-block
/// passes of `applyOrderDag` on lanes.
const switch_settings = [_]Switches{
    .{},
    .{ .share_blocks = true },
    .{ .walk = .dense, .lanes = 3, .blocks_per_task = 1, .share_blocks = true },
    .{ .walk = .sets, .cross_check = true },
    .{ .walk = .dense, .cross_check = true },
    .{ .walk = .dense },
    .{ .lanes = 3, .blocks_per_task = 1 },
    .{ .walk = .sets, .lanes = 3, .blocks_per_task = 1 },
    .{ .walk = .dense, .lanes = 3, .blocks_per_task = 1, .cross_check = true },
    .{ .walk = .dense, .lanes = 3, .blocks_per_task = 1 },
};

/// The DAG of the apply-order tests (4 authorities of stake 1, quorum 3). Round 1: B0..B3 with 10
/// transactions each. Round 2: C0..C3, each linking all of round 1, with the reject votes
///   C0: B1 {2}, B2 {1, 5}     C1: B0 {0}, B2 {1, 5}     C2: B1 {1, 2}     C3: none
/// so no transaction has a reject quorum, and the accept stake over C0..C3 is
///   B0 tx 0: 3 (final)     B1 tx 1: 3 (final)     B1 tx 2: 2     B2 tx 1 and tx 5: 2.
/// Rounds 3 to 5 are full, carry no transactions and vote on nothing (they are origin descendants
/// of round 2, so they add no stake). The leaders C0, D1, E2, F3 give four commits; the first
/// holds B0..B3 and C0, so its indirect pass sees the pending blocks B0 {0}, B1 {1, 2}, B2 {1, 5}
/// and must leave B1 {2}, B2 {1, 5}: the result of B1 belongs to B1 although B0 left the list.
const ApplyDag = struct { subs: []types.CommittedSubDag, b: []types.BlockRef, d1: types.BlockRef };

fn applyOrderDag(env: *TestEnv, scratch: Allocator) !ApplyDag {
    const a = env.f.arena();
    const r1 = try a.alloc(types.VerifiedBlock, 4);
    for (r1, 0..) |*blk, au| blk.* = try env.createBlock(1, @intCast(au), env.f.genesisRefs(), 10, &.{});
    try env.addBlocks(r1);
    const b = try env.refs(r1);
    const v0 = [_]types.BlockTransactionVotes{ .{ .block_ref = b[1], .rejects = &.{2} }, .{ .block_ref = b[2], .rejects = &.{ 1, 5 } } };
    const v1 = [_]types.BlockTransactionVotes{ .{ .block_ref = b[0], .rejects = &.{0} }, .{ .block_ref = b[2], .rejects = &.{ 1, 5 } } };
    const v2 = [_]types.BlockTransactionVotes{.{ .block_ref = b[1], .rejects = &.{ 1, 2 } }};
    const votes = [4][]const types.BlockTransactionVotes{ &v0, &v1, &v2, &.{} };

    var leaders: std.ArrayList(*const types.VerifiedBlock) = .empty;
    var d1: types.BlockRef = undefined;
    var prev: []const types.BlockRef = b;
    for (2..6) |r| {
        const blocks = try a.alloc(types.VerifiedBlock, 4);
        for (blocks, 0..) |*blk, au| blk.* = try env.createBlock(@intCast(r), @intCast(au), prev, 0, if (r == 2) votes[au] else &.{});
        try env.addBlocks(blocks);
        // leaders: C0, D1, E2, F3
        try leaders.append(a, env.f.dag.getBlock(blocks[r - 2].reference()).?);
        if (r == 3) d1 = blocks[1].reference();
        prev = try env.refs(blocks);
    }
    const subs = try env.lin.handleCommit(scratch, leaders.items);
    try std.testing.expectEqual(@as(usize, 4), subs.len);
    try std.testing.expectEqual(@as(usize, 5), subs[0].blocks.len);
    return .{ .subs = subs, .b = b, .d1 = d1 };
}

/// Runs the four commits of `applyOrderDag` and checks what the first commit ends with.
fn expectApplyOrder(env: *TestEnv, scratch: Allocator, d: *const ApplyDag) !void {
    const t = std.testing;
    try t.expectEqual(@as(usize, 0), (try env.fin.processCommit(scratch, &d.subs[0])).len);
    try t.expectEqual(@as(usize, 0), (try env.fin.processCommit(scratch, &d.subs[1])).len);
    // The pass after commit 2 arrived: B0 emptied, B1 lost transaction 1, B2 untouched.
    try t.expectEqual(@as(u64, 1), env.fin.counters.emptied_then_later);
    const pt = env.fin.pending_commits.items[0].pending_transactions.entries.items;
    try t.expectEqual(@as(usize, 2), pt.len);
    try t.expect(pt[0].ref.eql(d.b[1]));
    try t.expectEqualSlices(types.TransactionIndex, &.{2}, pt[0].idx.items);
    try t.expect(pt[1].ref.eql(d.b[2]));
    try t.expectEqualSlices(types.TransactionIndex, &.{ 1, 5 }, pt[1].idx.items);

    try t.expectEqual(@as(usize, 0), (try env.fin.processCommit(scratch, &d.subs[2])).len);
    const out = try env.fin.processCommit(scratch, &d.subs[3]);
    defer for (out) |*o| o.deinit();
    try t.expectEqual(@as(usize, 4), out.len);
    // What stayed pending is rejected INDIRECT_REJECT_DEPTH rounds after the leader.
    const rej = out[0].sub_dag.rejected_transactions_by_block;
    try t.expectEqual(@as(usize, 2), rej.len);
    try t.expect(rej[0].block.eql(d.b[1]));
    try t.expectEqualSlices(types.TransactionIndex, &.{2}, rej[0].indices);
    try t.expect(rej[1].block.eql(d.b[2]));
    try t.expectEqualSlices(types.TransactionIndex, &.{ 1, 5 }, rej[1].indices);
    for (out[1..]) |o| try t.expectEqual(@as(usize, 0), o.sub_dag.rejected_transactions_by_block.len);
}

test "indirect finalization applies each block's result to that block when an earlier pending block empties (every switch setting, inline and on lanes)" {
    const gpa = std.testing.allocator;
    for (switch_settings) |sw| {
        const env = try TestEnv.init(gpa);
        defer env.deinit(gpa);
        try env.fin.setSwitches(sw);
        var scratch = std.heap.ArenaAllocator.init(gpa);
        defer scratch.deinit();
        const d = try applyOrderDag(env, scratch.allocator());
        try expectApplyOrder(env, scratch.allocator(), &d);
        try std.testing.expect(env.fin.isEmpty());
        try std.testing.expectEqual(@as(u64, 0), env.fin.lane_fallbacks);
        // the lane settings really ran on lanes: three passes of two or three tasks
        if (sw.lanes != 1) try std.testing.expectEqual(@as(u64, 3), env.fin.lane_passes) else try std.testing.expectEqual(@as(u64, 0), env.fin.lane_passes);
        // every dense slot was given back
        if (sw.walk == .dense) try std.testing.expectEqual(env.fin.slots.items.len, env.fin.free_slots.items.len);
    }
}

test "a failing walk reports the serial path's error under every switch setting: missing block, invariant" {
    const gpa = std.testing.allocator;
    const Tamper = enum { drop_block, bad_commit_index };
    for ([_]Tamper{ .drop_block, .bad_commit_index }) |tamper| {
        for (switch_settings) |sw| {
            const env = try TestEnv.init(gpa);
            defer env.deinit(gpa);
            try env.fin.setSwitches(sw);
            var scratch = std.heap.ArenaAllocator.init(gpa);
            defer scratch.deinit();
            const d = try applyOrderDag(env, scratch.allocator());
            try std.testing.expectEqual(@as(usize, 0), (try env.fin.processCommit(scratch.allocator(), &d.subs[0])).len);
            try std.testing.expectEqual(@as(usize, 0), (try env.fin.processCommit(scratch.allocator(), &d.subs[1])).len);
            // D1 is a child of C0..C3, so the walks of B1 and B2 both reach it in the next pass.
            const bs = env.fin.blocks.get(d.d1).?;
            switch (tamper) {
                .drop_block => {
                    _ = env.fin.blocks.remove(d.d1);
                    if (bs.slot != no_slot) env.fin.releaseSlot(bs.slot);
                    env.fin.freeBlockState(bs);
                },
                // a block of an earlier commit than the pending block it descends from
                .bad_commit_index => bs.commit_index = 0,
            }
            const want: err.Error = if (tamper == .drop_block) error.MissingBlock else error.Invariant;
            try std.testing.expectError(want, env.fin.processCommit(scratch.allocator(), &d.subs[2]));
            // on lanes both tasks failed; the inline run named the error
            if (sw.lanes != 1) try std.testing.expectEqual(@as(u64, 1), env.fin.lane_fallbacks);
        }
    }
}

/// A thread-safe backing allocator that refuses every allocation after the first `left`.
const FailingBacking = struct {
    left: std.atomic.Value(isize),

    fn allocator(self: *FailingBacking) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }
    const vtable: Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *FailingBacking = @ptrCast(@alignCast(ctx));
        if (self.left.fetchSub(1, .monotonic) <= 0) return null;
        return std.heap.page_allocator.rawAlloc(len, alignment, ra);
    }
    fn resize(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        return std.heap.page_allocator.rawResize(memory, alignment, new_len, ra);
    }
    fn remap(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        return std.heap.page_allocator.rawRemap(memory, alignment, new_len, ra);
    }
    fn free(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        std.heap.page_allocator.rawFree(memory, alignment, ra);
    }
};

test "out of memory in a lane: the pass runs inline, same result, nothing leaks, no deadlock" {
    const gpa = std.testing.allocator;
    for ([_]isize{ 0, 1, 2, 5 }) |allowed| {
        for ([_]Switches{ .{ .lanes = 3, .blocks_per_task = 1 }, .{ .walk = .dense, .lanes = 3, .blocks_per_task = 1 } }) |sw| {
            const env = try TestEnv.init(gpa);
            defer env.deinit(gpa);
            try env.fin.setSwitches(sw);
            var failing: FailingBacking = .{ .left = .init(allowed) };
            env.fin.lane_backing = failing.allocator();
            var scratch = std.heap.ArenaAllocator.init(gpa);
            defer scratch.deinit();
            const d = try applyOrderDag(env, scratch.allocator());
            try expectApplyOrder(env, scratch.allocator(), &d);
            try std.testing.expect(env.fin.isEmpty());
            // with no memory at all every lane pass fell back
            if (allowed == 0) {
                try std.testing.expectEqual(@as(u64, 3), env.fin.lane_fallbacks);
                try std.testing.expectEqual(@as(u64, 0), env.fin.lane_passes);
            }
            try std.testing.expectEqual(@as(u64, 3), env.fin.lane_fallbacks + env.fin.lane_passes);
        }
    }
}

test "dense walk heap order is BlockRef order: round, author, then digest for equivocating blocks" {
    const gpa = std.testing.allocator;
    const env = try TestEnv.init(gpa);
    defer env.deinit(gpa);
    // three states in slots 0..2: two blocks of one slot (round 5, author 2) and one of round 4
    var states: [3]BlockState = undefined;
    const refs = [3]types.BlockRef{
        .{ .round = 5, .author = 2, .digest = @splat(0xf0) },
        .{ .round = 4, .author = 3, .digest = @splat(0xff) },
        .{ .round = 5, .author = 2, .digest = @splat(0x0f) },
    };
    for (&states, refs, 0..) |*s, r, i| {
        s.* = .{ .ref = r, .block = undefined, .reject_votes = &.{}, .commit_index = 1, .slot = @intCast(i) };
        try env.fin.slots.append(gpa, s);
    }
    defer env.fin.slots.clearRetainingCapacity();
    var q = DenseQueue.initContext(&env.fin);
    defer q.deinit(gpa);
    for (states) |s| try q.push(gpa, .{ .key = denseKey(s.ref), .slot = s.slot });
    var sorted = refs;
    std.mem.sort(types.BlockRef, &sorted, {}, struct {
        fn lt(_: void, x: types.BlockRef, y: types.BlockRef) bool {
            return x.order(y) == .lt;
        }
    }.lt);
    for (sorted) |want| {
        const got = q.pop().?;
        try std.testing.expect(states[got.slot].ref.eql(want));
    }
    try std.testing.expect(q.pop() == null);
}

test "a shared block outlives its eviction from the DAG window while a finalized sub-dag holds it" {
    const gpa = std.testing.allocator;
    var stakes = test_dag.Fixture.equalStakes(4);
    // A window of 2 cached rounds: blocks leave the DAG once they are below the GC round.
    const f = try test_dag.Fixture.init(gpa, .{
        .stakes = &stakes,
        .own_index = null,
        .protocol = .{ .gc_depth = 5, .transaction_voting_enabled = true, .num_leaders_per_round = 1, .bad_nodes_stake_threshold = 30 },
        .parameters = .{ .skip_equivocation_validation = true, .dag_state_cached_rounds = 2 },
    });
    defer f.deinit();
    var noop: verifier_mod.NoopTransactionVerifier = .{};
    var tracker = TransactionVoteTracker.init(gpa, f.context, f.dag, noop.verifier());
    defer tracker.deinit();
    var fin = CommitFinalizer.init(gpa, f.context, f.dag, &tracker);
    defer fin.deinit();
    try fin.setSwitches(.{ .share_blocks = true });
    var lin = f.linearizer();
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const a = scratch.allocator();

    // The finalized commits, kept (not freed) while the DAG moves on.
    var held: std.ArrayList(Finalized) = .empty;
    defer {
        for (held.items) |*h| h.deinit();
        held.deinit(gpa);
    }
    // Rounds 1 to 12, full, 2 transactions per block, no reject votes: a commit is final at once.
    var prev: []const types.BlockRef = f.genesisRefs();
    var first_bytes: []const u8 = &.{};
    var first_ref: types.BlockRef = undefined;
    for (1..13) |r| {
        const refs = try a.alloc(types.BlockRef, 4);
        for (refs, 0..) |*o, au| {
            const anc = try a.dupe(types.BlockRef, prev);
            std.mem.swap(types.BlockRef, &anc[0], &anc[au]);
            const txs = try a.alloc(types.Transaction, 2);
            for (txs) |*t| t.* = .{ .data = &tx_data };
            const vb = try digest_mod.verifiedForTest(a, .{ .V2 = .{ .epoch = 0, .round = @intCast(r), .author = @intCast(au), .timestamp_ms = r * 1000 + au, .ancestors = anc, .transactions = txs, .transaction_votes = &.{}, .commit_votes = &.{}, .misbehavior_reports = &.{} } });
            try tracker.addVotedBlock(&vb, &.{});
            try f.dag.acceptBlock(&vb);
            o.* = vb.reference();
            if (r == 1 and au == 0) {
                first_bytes = try a.dupe(u8, vb.serialized);
                first_ref = vb.reference();
            }
        }
        prev = refs;
        if (r < 2) continue;
        // Commit the block of round r - 1 in its round-robin slot, then finalize through
        // `process`, which flushes the DAG: that is where blocks are evicted.
        const at = try f.dag.getUncommittedBlocksAtSlot(a, .{ .round = @intCast(r - 1), .authority = @intCast((r - 1) % 4) });
        try std.testing.expectEqual(@as(usize, 1), at.len);
        const subs = try lin.handleCommit(a, &.{at[0]});
        for (subs) |*s| {
            const out = try fin.process(a, s);
            try held.appendSlice(gpa, out);
        }
    }
    try std.testing.expectEqual(@as(usize, 11), held.items.len);
    try std.testing.expect(fin.isEmpty());
    // Every block of every sub-dag is shared, none copied.
    var shared: usize = 0;
    var blocks: usize = 0;
    for (held.items) |h| {
        shared += h.boxes.len;
        blocks += h.sub_dag.blocks.len;
    }
    try std.testing.expectEqual(blocks, shared);
    // The round-1 block of authority 0 has left the window; the sub-dag that committed it still
    // reads it (bytes and decoded view), and is the only holder of its box.
    try std.testing.expect(f.dag.getBlock(first_ref) == null);
    var found = false;
    for (held.items) |h| {
        for (h.sub_dag.blocks) |*b| {
            if (!b.reference().eql(first_ref)) continue;
            found = true;
            try std.testing.expectEqualSlices(u8, first_bytes, b.serialized);
            try std.testing.expectEqual(@as(usize, 2), b.block.inner.transactions().len);
            try std.testing.expectEqualSlices(u8, &tx_data, b.block.inner.transactions()[1].data);
            for (h.boxes) |box| {
                if (box.block.reference().eql(first_ref)) try std.testing.expectEqual(@as(u32, 1), box.holders.load(.monotonic));
            }
        }
    }
    try std.testing.expect(found);
    // A block still in the window has two holders: the window and its sub-dag.
    const last = &held.items[held.items.len - 1];
    try std.testing.expect(f.dag.getBlock(last.boxes[0].block.reference()) != null);
    try std.testing.expectEqual(@as(u32, 2), last.boxes[0].holders.load(.monotonic));
}

/// One `process` of a commit that finalizes at once (rounds 1 to 4 full, the leader in round 2,
/// blocks shared with the DAG window), with the allocator of the finalizer, the DAG, the store
/// and the vote tracker refusing every allocation from number `fail_at` of the call on (null:
/// none). `already`: the commit carries recovered rejects and passes through.
const ProcessFailure = struct { allocs: usize, failed: bool, commit_left: bool };
fn processWithFailure(fail_at: ?usize, already: bool) !ProcessFailure {
    const t = std.testing;
    var failing = t.FailingAllocator.init(t.allocator, .{});
    const gpa = failing.allocator();
    const env = try TestEnv.init(gpa);
    defer env.deinit(gpa);
    try env.fin.setSwitches(.{ .share_blocks = true });
    const a = env.f.arena();
    var all: std.ArrayList(types.BlockRef) = .empty;
    var prev: []const types.BlockRef = env.f.genesisRefs();
    var leader: types.BlockRef = undefined;
    for (1..5) |r| {
        const blocks = try a.alloc(types.VerifiedBlock, 4);
        for (blocks, 0..) |*b, au| b.* = try env.createBlock(@intCast(r), @intCast(au), prev, 10, &.{});
        try env.addBlocks(blocks);
        if (r == 2) leader = blocks[1].reference();
        prev = try env.refs(blocks);
        try all.appendSlice(a, prev);
    }
    // The caller's own memory does not fail here: the failures are those of the steps `process`
    // runs on the finalizer's, the DAG's, the store's and the tracker's allocator.
    var scratch = std.heap.ArenaAllocator.init(t.allocator);
    defer scratch.deinit();
    const subs = try env.lin.handleCommit(scratch.allocator(), &.{env.f.dag.getBlock(leader).?});
    try t.expectEqual(@as(usize, 1), subs.len);
    subs[0].recovered_rejected_transactions = already;

    const before = failing.alloc_index;
    if (fail_at) |k| failing.fail_index = before + k;
    const res = env.fin.process(scratch.allocator(), &subs[0]);
    failing.fail_index = std.math.maxInt(usize);
    const allocs = failing.alloc_index - before;
    if (res) |out| {
        try t.expectEqual(@as(usize, 1), out.len);
        for (out) |*o| o.deinit();
        return .{ .allocs = allocs, .failed = false, .commit_left = true };
    } else |_| {
        try t.expect(failing.has_induced_failure);
        // The finalizer holds no commit: either the commit never got in, or it was finalized and
        // the failure came after (the finalized record, the flush). Either way nobody but the
        // DAG window may still hold a block: a hold kept here is a block that is never freed.
        const left = env.fin.pending_commits.items.len == 0;
        if (left) for (all.items) |ref| {
            const box = env.f.dag.shareBlock(ref) orelse continue;
            defer box.release();
            try t.expectEqual(@as(u32, 2), box.holders.load(.monotonic)); // the window and this check
        };
        return .{ .allocs = allocs, .failed = true, .commit_left = left };
    }
}

test "process: a failure after the commits were finalized (finalized record, flush) frees their arenas and their block holds, at every allocation of the call" {
    for ([_]bool{ false, true }) |already| {
        const clean = try processWithFailure(null, already);
        try std.testing.expect(!clean.failed);
        try std.testing.expect(clean.allocs > 0);
        var failed: usize = 0;
        var after_finalize: usize = 0;
        for (0..clean.allocs) |k| {
            const r = try processWithFailure(k, already);
            if (r.failed) failed += 1;
            if (r.failed and r.commit_left) after_finalize += 1;
        }
        // the sweep reached the steps after the finalization, not only the queueing
        try std.testing.expect(failed > 0);
        try std.testing.expect(after_finalize > 0);
    }
    // What is not freed is reported by std.testing.allocator when the test ends: the arena of a
    // finalized commit, and the box of every block it still held after the DAG let go.
}
