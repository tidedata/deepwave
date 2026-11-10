//! The authority's per-epoch state (`AuthorityEpochTables` subset of docs/VALIDATOR-DESIGN 6.2):
//! processed ConsensusTransactionKeys, the last processed commit (`ExecutionIndices`), owned
//! object locks, next shared-object versions, assigned versions of scheduled transactions,
//! deferred transactions, congestion debts, execution time observations, the checkpoint queue
//! and pending checkpoints. It lives in memory and is rebuilt at open from the durable log
//! (epoch_log.zig): one `Batch` per consensus commit, applied atomically.
//!
//! The single mutation path is `apply(group_bytes)`: `commit` encodes a Batch to a group, makes
//! it durable, then applies the same bytes, so replay after a crash and normal operation cannot
//! diverge. Locks are never removed within an epoch (Rust keeps `owned_object_locked_transactions`
//! for the whole epoch): that is the no-equivocation guarantee.
const std = @import("std");
const codec = @import("codec.zig");
const log_mod = @import("epoch_log.zig");
const tx_mod = @import("tx.zig");
const versions = @import("versions.zig");
const deferral = @import("deferral.zig");
const Spin = @import("sync.zig").Spin;

const Allocator = std.mem.Allocator;
pub const Id = tx_mod.Id;
pub const ObjRef = tx_mod.ObjRef;
pub const DeferralKey = deferral.DeferralKey;
pub const Key = versions.Assignable.Key;

pub const group_version: u8 = 1;

pub const Error = error{ Corrupt, OutOfMemory, Io };

/// `ExecutionIndices`.
pub const Indices = struct {
    last_committed_round: u64 = 0,
    /// The consensus commit index (`sub_dag_index` in Rust).
    sub_dag_index: u64 = 0,
    transaction_index: u64 = 0,
};

pub const CommitRef = struct { index: u32, digest: [32]u8 };

/// One queued set of checkpoint roots (`QueuedCheckpointRoots`).
pub const QueuedRoots = struct {
    height: u64,
    tx_roots: []const Key,
    settlement_root: ?Key,
    timestamp: u64,
    commit_ref: CommitRef,
    rejected_digest: [32]u8,
};

pub const PendingCheckpoint = struct {
    roots: []const QueuedRoots,
    timestamp_ms: u64,
    last_of_epoch: bool,
    checkpoint_height: u64,
    commit_ref: CommitRef,
    rejected_digest: [32]u8,
    checkpoint_seq: u64,
};

/// What the executor needs to run a scheduled item again after a restart.
pub const ExecPayload = struct {
    /// `exec_bridge.ItemKind` as an integer.
    kind: u8,
    td_bcs: ?[]const u8,
    digest: ?Id,
    owned: []const ObjRef,
};

pub const AssignedRecord = struct {
    key: Key,
    shared: []const versions.SharedVersion,
    system: []const versions.SystemVersion,
    exec: ?ExecPayload = null,
    /// Insertion order (set by apply), so a restart re-enqueues in the original order.
    seq: u64 = 0,
};

pub const Debt = struct { round: u64, debt: u64 };

pub const QueueOp = union(enum) { push: QueuedRoots, flush: PendingCheckpoint };

/// `user_signatures_for_checkpoints`: the signatures of an executed user transaction and the
/// alias versions used to verify them.
pub const UserSigs = struct { digest: Id, sigs: []const []const u8, alias_versions: []const ?u64 };

pub const ObsRecord = struct { authority: u32, generation: u64, estimates_bcs: []const u8 };

// ------------------------------------------------------------------------ batch

/// Everything one consensus commit writes (`ConsensusCommitOutput`). Slices live in `arena`.
pub const Batch = struct {
    arena: Allocator,
    indices: Indices,
    processed: std.ArrayList([32]u8) = .empty,
    locks: std.ArrayList(struct { ref: ObjRef, tx: Id }) = .empty,
    next_versions: std.ArrayList(struct { key: versions.ObjKey, version: u64 }) = .empty,
    assigned: std.ArrayList(AssignedRecord) = .empty,
    deferred_set: std.ArrayList(struct { key: DeferralKey, txs: []const []const u8 }) = .empty,
    deferred_del: std.ArrayList(DeferralKey) = .empty,
    debts: std.ArrayList(struct { randomness: bool, id: Id, round: u64, debt: u64 }) = .empty,
    commit_times: std.ArrayList(u64) = .empty,
    assigned_acked: std.ArrayList(Key) = .empty,
    sigs_acked: std.ArrayList([32]u8) = .empty,
    /// Pending checkpoints up to and including this sequence number were built.
    pending_acked: ?u64 = null,
    /// The randomness round this commit reserved (`reserve_next_randomness`).
    randomness_round: ?u64 = null,
    /// Checkpoint queue operations in the order the handler performed them.
    queue_ops: std.ArrayList(QueueOp) = .empty,
    /// Signatures of the user transactions scheduled by this commit (for the checkpoint builder).
    user_sigs: std.ArrayList(UserSigs) = .empty,
    observations: std.ArrayList(ObsRecord) = .empty,
    /// Sequence number the queue assigns next after this commit's flushes (`current_checkpoint_seq`).
    queue_next_seq: ?u64 = null,
    queue_height: ?u64 = null,
    queue_drained: bool = true,

    pub fn init(arena: Allocator, indices: Indices) Batch {
        return .{ .arena = arena, .indices = indices };
    }
    pub fn recordProcessed(b: *Batch, key: [32]u8) Allocator.Error!void {
        try b.processed.append(b.arena, key);
    }
    pub fn addLock(b: *Batch, ref: ObjRef, tx: Id) Allocator.Error!void {
        try b.locks.append(b.arena, .{ .ref = ref, .tx = tx });
    }
};

// ------------------------------------------------------------------------ encoding

const T = struct {
    const end: u8 = 0;
    const processed: u8 = 1;
    const lock: u8 = 2;
    const next_version: u8 = 3;
    const deferred_set: u8 = 4;
    const deferred_del: u8 = 5;
    const debt: u8 = 6;
    const commit_time: u8 = 7;
    const queue_push: u8 = 8;
    const queue_flush: u8 = 9;
    const assigned: u8 = 10;
    const observation: u8 = 11;
    const pending_ack: u8 = 12;
    const assigned_del: u8 = 13;
    const queue_meta: u8 = 14;
    const user_sigs: u8 = 15;
    const sigs_del: u8 = 16;
    const randomness_round: u8 = 17;
};

fn putKey(w: *codec.Writer, k: DeferralKey) !void {
    switch (k) {
        .randomness => |r| {
            try w.u8_(0);
            try w.u64_(r.deferred_from_round);
            try w.u64_(0);
        },
        .consensus_round => |c| {
            try w.u8_(1);
            try w.u64_(c.future_round);
            try w.u64_(c.deferred_from_round);
        },
    }
}
fn getKey(r: *codec.Reader) !DeferralKey {
    const kind = try r.u8_();
    const a = try r.u64_();
    const b = try r.u64_();
    return switch (kind) {
        0 => DeferralKey.newForRandomness(a),
        1 => DeferralKey.newForConsensusRound(a, b),
        else => error.Corrupt,
    };
}

fn putTxKey(w: *codec.Writer, k: Key) !void {
    switch (k) {
        .digest => |d| {
            try w.u8_(0);
            try w.raw(&d);
        },
        .randomness_round => |x| {
            try w.u8_(1);
            try w.u64_(x.epoch);
            try w.u64_(x.round);
        },
        .accumulator_settlement => |x| {
            try w.u8_(2);
            try w.u64_(x.epoch);
            try w.u64_(x.height);
        },
        .consensus_commit_prologue => |x| {
            try w.u8_(3);
            try w.u64_(x.epoch);
            try w.u64_(x.round);
            try w.u32_(x.sub_dag_index);
        },
    }
}
fn getTxKey(r: *codec.Reader) !Key {
    return switch (try r.u8_()) {
        0 => .{ .digest = try r.id() },
        1 => .{ .randomness_round = .{ .epoch = try r.u64_(), .round = try r.u64_() } },
        2 => .{ .accumulator_settlement = .{ .epoch = try r.u64_(), .height = try r.u64_() } },
        3 => .{ .consensus_commit_prologue = .{ .epoch = try r.u64_(), .round = try r.u64_(), .sub_dag_index = try r.u32_() } },
        else => error.Corrupt,
    };
}

fn putRoots(w: *codec.Writer, q: QueuedRoots) !void {
    try w.u64_(q.height);
    try w.u32_(@intCast(q.tx_roots.len));
    for (q.tx_roots) |k| try putTxKey(w, k);
    if (q.settlement_root) |s| {
        try w.u8_(1);
        try putTxKey(w, s);
    } else try w.u8_(0);
    try w.u64_(q.timestamp);
    try w.u32_(q.commit_ref.index);
    try w.raw(&q.commit_ref.digest);
    try w.raw(&q.rejected_digest);
}
fn getRoots(arena: Allocator, r: *codec.Reader) !QueuedRoots {
    const height = try r.u64_();
    const n = try r.u32_();
    if (n > r.remaining()) return error.Corrupt;
    const roots = try arena.alloc(Key, n);
    for (roots) |*k| k.* = try getTxKey(r);
    const settle: ?Key = if ((try r.u8_()) == 1) try getTxKey(r) else null;
    const ts = try r.u64_();
    const idx = try r.u32_();
    const dig = try r.id();
    const rej = try r.id();
    return .{ .height = height, .tx_roots = roots, .settlement_root = settle, .timestamp = ts, .commit_ref = .{ .index = idx, .digest = dig }, .rejected_digest = rej };
}

/// Serializes a batch to one group payload.
pub fn encodeBatch(gpa: Allocator, b: *const Batch) Error![]u8 {
    var w = codec.Writer.init(gpa);
    errdefer w.deinit();
    encodeInto(&w, b) catch return error.OutOfMemory;
    return w.buf.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

fn encodeInto(w: *codec.Writer, b: *const Batch) !void {
    try w.u8_(group_version);
    try w.u64_(b.indices.last_committed_round);
    try w.u64_(b.indices.sub_dag_index);
    try w.u64_(b.indices.transaction_index);
    for (b.processed.items) |k| {
        try w.u8_(T.processed);
        try w.raw(&k);
    }
    for (b.locks.items) |l| {
        try w.u8_(T.lock);
        try w.raw(&l.ref.id);
        try w.u64_(l.ref.version);
        try w.raw(&l.ref.digest);
        try w.raw(&l.tx);
    }
    for (b.next_versions.items) |v| {
        try w.u8_(T.next_version);
        try w.raw(&v.key.id);
        try w.u64_(v.key.isv);
        try w.u64_(v.version);
    }
    for (b.assigned.items) |a| {
        try w.u8_(T.assigned);
        try putTxKey(w, a.key);
        try w.u32_(@intCast(a.shared.len));
        for (a.shared) |s| {
            try w.raw(&s.id);
            try w.u64_(s.isv);
            try w.u64_(s.version);
        }
        try w.u32_(@intCast(a.system.len));
        for (a.system) |s| {
            try w.raw(&s.id);
            try w.u64_(s.isv);
            try w.u64_(s.version);
        }
        if (a.exec) |x| {
            try w.u8_(1);
            try w.u8_(x.kind);
            if (x.td_bcs) |t| {
                try w.u8_(1);
                try w.blob(t);
            } else try w.u8_(0);
            if (x.digest) |d| {
                try w.u8_(1);
                try w.raw(&d);
            } else try w.u8_(0);
            try w.u32_(@intCast(x.owned.len));
            for (x.owned) |o| {
                try w.raw(&o.id);
                try w.u64_(o.version);
                try w.raw(&o.digest);
            }
        } else try w.u8_(0);
    }
    for (b.deferred_set.items) |d| {
        try w.u8_(T.deferred_set);
        try putKey(w, d.key);
        try w.u32_(@intCast(d.txs.len));
        for (d.txs) |t| try w.blob(t);
    }
    for (b.deferred_del.items) |k| {
        try w.u8_(T.deferred_del);
        try putKey(w, k);
    }
    for (b.debts.items) |d| {
        try w.u8_(T.debt);
        try w.u8_(@intFromBool(d.randomness));
        try w.raw(&d.id);
        try w.u64_(d.round);
        try w.u64_(d.debt);
    }
    for (b.commit_times.items) |t| {
        try w.u8_(T.commit_time);
        try w.u64_(t);
    }
    for (b.observations.items) |o| {
        try w.u8_(T.observation);
        try w.u32_(o.authority);
        try w.u64_(o.generation);
        try w.blob(o.estimates_bcs);
    }
    for (b.queue_ops.items) |op| switch (op) {
        .push => |q| {
            try w.u8_(T.queue_push);
            try putRoots(w, q);
        },
        .flush => |p| {
            try w.u8_(T.queue_flush);
            try w.u32_(@intCast(p.roots.len));
            for (p.roots) |q| try putRoots(w, q);
            try w.u64_(p.timestamp_ms);
            try w.u8_(@intFromBool(p.last_of_epoch));
            try w.u64_(p.checkpoint_height);
            try w.u32_(p.commit_ref.index);
            try w.raw(&p.commit_ref.digest);
            try w.raw(&p.rejected_digest);
            try w.u64_(p.checkpoint_seq);
        },
    };
    for (b.user_sigs.items) |us| {
        try w.u8_(T.user_sigs);
        try w.raw(&us.digest);
        try w.u32_(@intCast(us.sigs.len));
        for (us.sigs) |sg| try w.blob(sg);
        try w.u32_(@intCast(us.alias_versions.len));
        for (us.alias_versions) |av| {
            if (av) |v| {
                try w.u8_(1);
                try w.u64_(v);
            } else try w.u8_(0);
        }
    }
    for (b.assigned_acked.items) |k| {
        try w.u8_(T.assigned_del);
        try putTxKey(w, k);
    }
    if (b.randomness_round) |rr| {
        try w.u8_(T.randomness_round);
        try w.u64_(rr);
    }
    if (b.pending_acked) |q| {
        try w.u8_(T.pending_ack);
        try w.u64_(q);
    }
    for (b.sigs_acked.items) |d| {
        try w.u8_(T.sigs_del);
        try w.raw(&d);
    }
    if (b.queue_next_seq != null or b.queue_height != null) {
        try w.u8_(T.queue_meta);
        try w.u64_(b.queue_next_seq orelse std.math.maxInt(u64));
        try w.u64_(b.queue_height orelse std.math.maxInt(u64));
        try w.u8_(@intFromBool(b.queue_drained));
    }
    try w.u8_(T.end);
}

// ------------------------------------------------------------------------ state

pub const LockMap = std.AutoHashMapUnmanaged([72]u8, [32]u8);

pub fn lockKey(r: ObjRef) [72]u8 {
    var k: [72]u8 = undefined;
    k[0..32].* = r.id;
    std.mem.writeInt(u64, k[32..40], r.version, .little);
    k[40..72].* = r.digest;
    return k;
}

pub const Deferred = struct { key: DeferralKey, txs: std.ArrayList([]u8) };

pub const EpochState = struct {
    gpa: Allocator,
    processed: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
    indices: Indices = .{},
    locks: LockMap = .empty,
    next_versions: std.AutoHashMapUnmanaged(versions.ObjKey, u64) = .empty,
    /// Assigned versions of scheduled transactions, until execution acknowledges them.
    assigned: std.AutoHashMapUnmanaged(Key, AssignedOwned) = .empty,
    assigned_seq: u64 = 0,
    /// Last randomness round reserved by a durable commit.
    randomness_last: ?u64 = null,
    /// Guards `processed` and `locks`: API threads (SubmitTransaction) read them while the
    /// handler thread applies commits.
    shared_lock: Spin = .{},
    /// Sorted by key.
    deferred: std.ArrayList(Deferred) = .empty,
    debts: [2]std.AutoHashMapUnmanaged(Id, Debt) = .{ .empty, .empty },
    /// Commit timestamps (ms), the last `window` of them (`CommitIntervalObserver`).
    commit_times: std.ArrayList(u64) = .empty,
    observations: std.ArrayList(ObsOwned) = .empty,
    queue: std.ArrayList(QueuedOwned) = .empty,
    queue_seq: u64 = 0,
    queue_height: u64 = 0,
    queue_last_built_ts: u64 = 0,
    queue_pending_tx: u64 = 0,
    queue_drained: bool = true,
    pending: std.ArrayList(PendingOwned) = .empty,
    sigs: std.AutoHashMapUnmanaged(Id, UserSigs) = .empty,
    /// The arena that owns decoded slices (roots, assigned versions); freed in `deinit`.
    arena: std.heap.ArenaAllocator,
    /// `additional_consensus_state_window_size`: commit times kept.
    window: usize = commit_window,

    const AssignedOwned = AssignedRecord;
    const ObsOwned = ObsRecord;
    const QueuedOwned = QueuedRoots;
    const PendingOwned = PendingCheckpoint;

    pub fn init(gpa: Allocator) EpochState {
        return .{ .gpa = gpa, .arena = .init(gpa) };
    }

    pub fn deinit(s: *EpochState) void {
        s.processed.deinit(s.gpa);
        s.locks.deinit(s.gpa);
        s.next_versions.deinit(s.gpa);
        s.assigned.deinit(s.gpa);
        for (s.deferred.items) |*d| {
            for (d.txs.items) |t| s.gpa.free(t);
            d.txs.deinit(s.gpa);
        }
        s.deferred.deinit(s.gpa);
        s.debts[0].deinit(s.gpa);
        s.debts[1].deinit(s.gpa);
        s.commit_times.deinit(s.gpa);
        s.observations.deinit(s.gpa);
        s.queue.deinit(s.gpa);
        s.pending.deinit(s.gpa);
        s.sigs.deinit(s.gpa);
        s.arena.deinit();
    }

    // ---- reads (handler thread, or readers behind the handler's lock)

    pub fn isProcessed(s: *EpochState, key: *const [32]u8) bool {
        s.shared_lock.lock();
        defer s.shared_lock.unlock();
        return s.processed.contains(key.*);
    }

    /// The lock holder of `ref`, if any.
    pub fn lockHolder(s: *EpochState, ref: ObjRef) ?[32]u8 {
        s.shared_lock.lock();
        defer s.shared_lock.unlock();
        return s.locks.get(lockKey(ref));
    }

    pub fn nextVersion(s: *const EpochState, k: versions.ObjKey) ?u64 {
        return s.next_versions.get(k);
    }

    pub fn assignedFor(s: *const EpochState, key: Key) ?AssignedRecord {
        return s.assigned.get(key);
    }

    fn findDeferred(s: *const EpochState, key: DeferralKey) union(enum) { found: usize, insert_at: usize } {
        var lo: usize = 0;
        var hi: usize = s.deferred.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (DeferralKey.order(s.deferred.items[mid].key, key)) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => return .{ .found = mid },
            }
        }
        return .{ .insert_at = lo };
    }

    pub fn deferredFor(s: *const EpochState, key: DeferralKey) ?[]const []u8 {
        return switch (s.findDeferred(key)) {
            .found => |i| s.deferred.items[i].txs.items,
            .insert_at => null,
        };
    }

    pub fn debtOf(s: *const EpochState, randomness: bool, id: *const Id) ?Debt {
        return s.debts[@intFromBool(randomness)].get(id.*);
    }

    // ---- mutation

    /// Applies one durable group (the only mutation path; replay uses it too).
    pub fn apply(s: *EpochState, group: []const u8) Error!void {
        s.shared_lock.lock();
        defer s.shared_lock.unlock();
        var r = codec.Reader.init(group);
        applyInner(s, &r) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Corrupt,
        };
    }

    fn applyInner(s: *EpochState, r: *codec.Reader) !void {
        const gpa = s.gpa;
        const a = s.arena.allocator();
        if ((try r.u8_()) != group_version) return error.Corrupt;
        s.indices = .{ .last_committed_round = try r.u64_(), .sub_dag_index = try r.u64_(), .transaction_index = try r.u64_() };
        while (true) {
            const tag = try r.u8_();
            switch (tag) {
                T.end => break,
                T.processed => try s.processed.put(gpa, try r.id(), {}),
                T.lock => {
                    const ref: ObjRef = .{ .id = try r.id(), .version = try r.u64_(), .digest = try r.id() };
                    const txd = try r.id();
                    // first writer wins: a lock is never replaced within an epoch
                    const gop = try s.locks.getOrPut(gpa, lockKey(ref));
                    if (!gop.found_existing) gop.value_ptr.* = txd;
                },
                T.next_version => {
                    const k: versions.ObjKey = .{ .id = try r.id(), .isv = try r.u64_() };
                    try s.next_versions.put(gpa, k, try r.u64_());
                },
                T.assigned => {
                    const key = try getTxKey(r);
                    const ns = try r.u32_();
                    if (ns > r.remaining()) return error.Corrupt;
                    const shared = try a.alloc(versions.SharedVersion, ns);
                    for (shared) |*x| x.* = .{ .id = try r.id(), .isv = try r.u64_(), .version = try r.u64_() };
                    const ny = try r.u32_();
                    if (ny > r.remaining()) return error.Corrupt;
                    const sys = try a.alloc(versions.SystemVersion, ny);
                    for (sys) |*x| x.* = .{ .id = try r.id(), .isv = try r.u64_(), .version = try r.u64_() };
                    var exec: ?ExecPayload = null;
                    if ((try r.u8_()) == 1) {
                        const kind = try r.u8_();
                        if (kind > 4) return error.Corrupt;
                        const td: ?[]const u8 = if ((try r.u8_()) == 1) try a.dupe(u8, try r.blob()) else null;
                        const dg: ?Id = if ((try r.u8_()) == 1) try r.id() else null;
                        const no = try r.u32_();
                        if (no > r.remaining()) return error.Corrupt;
                        const owned = try a.alloc(ObjRef, no);
                        for (owned) |*o| o.* = .{ .id = try r.id(), .version = try r.u64_(), .digest = try r.id() };
                        exec = .{ .kind = kind, .td_bcs = td, .digest = dg, .owned = owned };
                    }
                    s.assigned_seq += 1;
                    try s.assigned.put(gpa, key, .{ .key = key, .shared = shared, .system = sys, .exec = exec, .seq = s.assigned_seq });
                },
                T.deferred_set => {
                    const key = try getKey(r);
                    const n = try r.u32_();
                    if (n > r.remaining()) return error.Corrupt;
                    var list: std.ArrayList([]u8) = .empty;
                    errdefer {
                        for (list.items) |t| gpa.free(t);
                        list.deinit(gpa);
                    }
                    var i: u32 = 0;
                    while (i < n) : (i += 1) try list.append(gpa, try gpa.dupe(u8, try r.blob()));
                    switch (s.findDeferred(key)) {
                        .found => |idx| {
                            for (s.deferred.items[idx].txs.items) |t| gpa.free(t);
                            s.deferred.items[idx].txs.deinit(gpa);
                            s.deferred.items[idx].txs = list;
                        },
                        .insert_at => |idx| try s.deferred.insert(gpa, idx, .{ .key = key, .txs = list }),
                    }
                },
                T.deferred_del => {
                    const key = try getKey(r);
                    switch (s.findDeferred(key)) {
                        .found => |idx| {
                            var d = s.deferred.orderedRemove(idx);
                            for (d.txs.items) |t| gpa.free(t);
                            d.txs.deinit(gpa);
                        },
                        .insert_at => {},
                    }
                },
                T.debt => {
                    const rnd = (try r.u8_()) != 0;
                    const id = try r.id();
                    const round = try r.u64_();
                    const debt = try r.u64_();
                    try s.debts[@intFromBool(rnd)].put(gpa, id, .{ .round = round, .debt = debt });
                },
                T.commit_time => try s.commit_times.append(gpa, try r.u64_()),
                T.observation => {
                    const auth = try r.u32_();
                    const gen = try r.u64_();
                    const blob = try a.dupe(u8, try r.blob());
                    try s.observations.append(gpa, .{ .authority = auth, .generation = gen, .estimates_bcs = blob });
                },
                T.queue_push => {
                    const q = try getRoots(a, r);
                    try s.queue.append(gpa, q);
                    s.queue_pending_tx += q.tx_roots.len;
                },
                T.queue_flush => {
                    const n = try r.u32_();
                    if (n > r.remaining()) return error.Corrupt;
                    const roots = try a.alloc(QueuedRoots, n);
                    for (roots) |*q| q.* = try getRoots(a, r);
                    const ts = try r.u64_();
                    const last = (try r.u8_()) != 0;
                    const h = try r.u64_();
                    const idx = try r.u32_();
                    const dig = try r.id();
                    const rej = try r.id();
                    const seq = try r.u64_();
                    try s.pending.append(gpa, .{ .roots = roots, .timestamp_ms = ts, .last_of_epoch = last, .checkpoint_height = h, .commit_ref = .{ .index = idx, .digest = dig }, .rejected_digest = rej, .checkpoint_seq = seq });
                    // the queue drains on every flush (flush_forced takes all pending roots)
                    s.queue.clearRetainingCapacity();
                    s.queue_pending_tx = 0;
                    s.queue_last_built_ts = ts;
                    s.queue_seq = seq + 1;
                },
                T.user_sigs => {
                    const d = try r.id();
                    const n = try r.u32_();
                    if (n > r.remaining()) return error.Corrupt;
                    const sg = try a.alloc([]const u8, n);
                    for (sg) |*x| x.* = try a.dupe(u8, try r.blob());
                    const na = try r.u32_();
                    if (na > r.remaining()) return error.Corrupt;
                    const av = try a.alloc(?u64, na);
                    for (av) |*x| x.* = if ((try r.u8_()) == 1) try r.u64_() else null;
                    try s.sigs.put(gpa, d, .{ .digest = d, .sigs = sg, .alias_versions = av });
                },
                T.assigned_del => {
                    const k = try getTxKey(r);
                    s.ackAssigned(k);
                },
                T.randomness_round => s.randomness_last = try r.u64_(),
                T.pending_ack => s.ackPending(try r.u64_()),
                T.sigs_del => _ = s.sigs.remove(try r.id()),
                T.queue_meta => {
                    const seq = try r.u64_();
                    const h = try r.u64_();
                    s.queue_drained = (try r.u8_()) != 0;
                    if (seq != std.math.maxInt(u64)) s.queue_seq = seq;
                    if (h != std.math.maxInt(u64)) s.queue_height = h;
                },
                else => return error.Corrupt,
            }
        }
    }

    /// Drops pending checkpoints up to and including `seq` (the builder built them).
    pub fn ackPending(s: *EpochState, seq: u64) void {
        var i: usize = 0;
        while (i < s.pending.items.len) {
            if (s.pending.items[i].checkpoint_seq <= seq) _ = s.pending.orderedRemove(i) else i += 1;
        }
    }

    /// Forgets the assigned versions of `key` once executed.
    pub fn ackAssigned(s: *EpochState, key: Key) void {
        _ = s.assigned.remove(key);
    }

    /// `CommitIntervalObserver` after `observe_commit_time(new_time)`: the ring holds the last
    /// `window` timestamps; the estimate is (last - first) div_ceil count, null with fewer than
    /// two samples. In milliseconds.
    pub fn commitIntervalAfter(s: *const EpochState, new_time: u64) ?u64 {
        const have = s.commit_times.items;
        const keep = @min(have.len, s.window -| 1);
        const first_existing = if (keep > 0) have[have.len - keep] else new_time;
        const n = keep + 1;
        if (n <= 1) return null;
        const dur = new_time -| first_existing;
        return (dur + n - 1) / n;
    }

    /// The ring buffer after `observe_commit_time(new_time)`: the last `window - 1` retained
    /// timestamps then the new one (`window == 0` keeps none: Rust's zero-capacity ring would
    /// push then never pop, but a zero window never reaches the handler with the digest on).
    pub fn ringAfter(s: *const EpochState, arena: Allocator, new_time: u64) Allocator.Error![]u64 {
        const have = s.commit_times.items;
        const keep = @min(have.len, s.window -| 1);
        const out = try arena.alloc(u64, keep + 1);
        @memcpy(out[0..keep], have[have.len - keep ..]);
        out[keep] = new_time;
        return out;
    }

    /// `commit_interval_estimate` of a ring, milliseconds.
    pub fn intervalOf(ring: []const u64) ?u64 {
        if (ring.len <= 1) return null;
        const dur = ring[ring.len - 1] -| ring[0];
        return (dur + ring.len - 1) / ring.len;
    }

    pub fn commitIntervalMs(s: *const EpochState) ?u64 {
        const n = s.commit_times.items.len;
        if (n <= 1) return null;
        const dur = s.commit_times.items[n - 1] -| s.commit_times.items[0];
        return (dur + n - 1) / n;
    }

    /// Keeps only the last `window` commit times (`ring_buffer` capacity).
    pub fn trimCommitTimes(s: *EpochState, window: usize) void {
        if (s.commit_times.items.len > window) {
            const drop = s.commit_times.items.len - window;
            std.mem.copyForwards(u64, s.commit_times.items[0..window], s.commit_times.items[drop..]);
            s.commit_times.shrinkRetainingCapacity(window);
        }
    }
};

/// Hash used for ConsensusTransactionKey dedup (blake2b256 over its canonical bytes).
pub fn keyHash(canonical: []const u8) [32]u8 {
    const hash = @import("hash");
    return hash.blake2b256(&.{canonical});
}

/// Opens an epoch state from a log: replays every group.
pub const Replay = struct {
    state: *EpochState,
    pub fn visit(self: Replay, group: []const u8) anyerror!void {
        try self.state.apply(group);
    }
};

/// Durable commit: append the encoded batch to `log` (any of MemLog/FileLog), then apply it.
pub fn commit(s: *EpochState, log: anytype, b: *const Batch) Error!void {
    const bytes = try encodeBatch(s.gpa, b);
    defer s.gpa.free(bytes);
    log.appendGroup(bytes) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Io,
    };
    try s.apply(bytes);
    s.trimCommitTimes(s.window);
}

/// `additional_consensus_state_window_size` upper bound kept in memory (the protocol value is
/// applied by the handler before computing the estimate; this only bounds memory).
pub const commit_window: usize = 4096;

// ------------------------------------------------------------------------ tests

test "batch round trip through mem log" {
    const gpa = std.testing.allocator;
    var log = log_mod.MemLog.init(gpa);
    defer log.deinit();
    var st = EpochState.init(gpa);
    defer st.deinit();

    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    var b = Batch.init(ar.allocator(), .{ .last_committed_round = 5, .sub_dag_index = 9, .transaction_index = 2 });
    const ref: ObjRef = .{ .id = @splat(1), .version = 4, .digest = @splat(2) };
    try b.addLock(ref, @splat(7));
    try b.recordProcessed(@splat(3));
    try b.next_versions.append(ar.allocator(), .{ .key = .{ .id = @splat(8), .isv = 1 }, .version = 12 });
    try b.deferred_set.append(ar.allocator(), .{ .key = DeferralKey.newForConsensusRound(10, 9), .txs = &.{ "aa", "bbb" } });
    try b.debts.append(ar.allocator(), .{ .randomness = false, .id = @splat(8), .round = 5, .debt = 100 });
    try b.commit_times.append(ar.allocator(), 1000);
    try commit(&st, &log, &b);

    try std.testing.expectEqual(@as(?[32]u8, @as([32]u8, @splat(7))), st.lockHolder(ref));
    try std.testing.expect(st.isProcessed(&@as([32]u8, @splat(3))));
    try std.testing.expectEqual(@as(?u64, 12), st.nextVersion(.{ .id = @splat(8), .isv = 1 }));
    try std.testing.expectEqual(@as(usize, 2), st.deferredFor(DeferralKey.newForConsensusRound(10, 9)).?.len);
    try std.testing.expectEqual(@as(u64, 9), st.indices.sub_dag_index);

    // a second commit cannot steal the lock
    var b2 = Batch.init(ar.allocator(), .{ .last_committed_round = 6, .sub_dag_index = 10, .transaction_index = 0 });
    try b2.addLock(ref, @splat(9));
    try b2.deferred_del.append(ar.allocator(), DeferralKey.newForConsensusRound(10, 9));
    try commit(&st, &log, &b2);
    try std.testing.expectEqual(@as(?[32]u8, @as([32]u8, @splat(7))), st.lockHolder(ref));
    try std.testing.expect(st.deferredFor(DeferralKey.newForConsensusRound(10, 9)) == null);

    // rebuild from the log: same state
    var st2 = EpochState.init(gpa);
    defer st2.deinit();
    try log.replay(Replay{ .state = &st2 }, Replay.visit);
    try std.testing.expectEqual(@as(?[32]u8, @as([32]u8, @splat(7))), st2.lockHolder(ref));
    try std.testing.expectEqual(@as(u64, 10), st2.indices.sub_dag_index);
    try std.testing.expect(st2.deferredFor(DeferralKey.newForConsensusRound(10, 9)) == null);
}

test "commit interval estimate" {
    var st = EpochState.init(std.testing.allocator);
    defer st.deinit();
    try std.testing.expect(st.commitIntervalMs() == null);
    try st.commit_times.appendSlice(std.testing.allocator, &.{ 1000, 1200, 1400, 1600 });
    // (1600-1000)=600 ceil-div 4 = 150
    try std.testing.expectEqual(@as(?u64, 150), st.commitIntervalMs());
}
