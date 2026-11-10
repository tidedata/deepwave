//! `CheckpointQueue` (sui-core `consensus_handler.rs`, 1.83.1, `split_checkpoints_in_consensus_handler`):
//! the consensus handler's accumulator of checkpoint roots. The handler turns every consensus
//! commit into one or more *chunks* of at most `max_transactions_per_checkpoint` schedulables
//! (`chunkSizes`), pushes each chunk here, and the queue decides when the buffered roots become a
//! PendingCheckpoint:
//!
//!   - before a chunk is added: if the buffer is non-empty and would exceed `max_tx`, the buffer
//!     is flushed first (a forced flush),
//!   - after a commit: `flush(timestamp, force)`, which only flushes once
//!     `min_checkpoint_interval_ms` elapsed since the last flushed checkpoint (the end of an epoch
//!     forces it),
//!   - a flush drains every buffered root into ONE PendingCheckpoint whose timestamp, height,
//!     commit ref and rejected-transactions digest are those of the last buffered root, and
//!     whose sequence number is the next one.
//!
//! The execution scheduler side of `push_chunk` (sending schedulables for execution) is the
//! handler's (val-authority). Roots are copied into the queue; the PendingCheckpoint a flush
//! returns is allocated in the arena the caller passes.
const std = @import("std");
const types = @import("types");
const iface = @import("../iface.zig");

pub const Error = error{OutOfMemory};

const Queued = struct {
    roots: iface.CheckpointRoots,
    timestamp_ms: u64,
    commit: @FieldType(iface.PendingCheckpointInfo, "consensus_commit_ref"),
    rejected: types.Digest,
};

pub const Queue = struct {
    gpa: std.mem.Allocator,
    last_built_timestamp: u64,
    pending: std.ArrayList(Queued) = .empty,
    height: u64,
    pending_tx_count: usize = 0,
    current_seq: u64,
    max_tx: usize,
    min_interval_ms: u64,

    /// `last_built_timestamp`/`height`/`next_seq` resume from the last pending checkpoint written.
    pub fn init(gpa: std.mem.Allocator, last_built_timestamp: u64, height: u64, next_seq: u64, max_tx: usize, min_interval_ms: u64) Queue {
        return .{ .gpa = gpa, .last_built_timestamp = last_built_timestamp, .height = height, .current_seq = next_seq, .max_tx = max_tx, .min_interval_ms = min_interval_ms };
    }

    pub fn deinit(q: *Queue) void {
        for (q.pending.items) |*p| freeRoots(q.gpa, p.roots);
        q.pending.deinit(q.gpa);
    }

    pub fn isEmpty(q: *const Queue) bool {
        return q.pending.items.len == 0;
    }

    /// `next_height`: the height of the next chunk.
    pub fn nextHeight(q: *Queue) u64 {
        q.height += 1;
        return q.height;
    }

    /// The sequence number of the last assigned checkpoint (`checkpoint_seq`).
    pub fn lastAssignedSeq(q: *const Queue) ?u64 {
        return if (q.current_seq == 0) null else q.current_seq - 1;
    }

    /// `push_chunk`: returns the checkpoint flushed because the chunk would overflow `max_tx`.
    pub fn pushChunk(
        q: *Queue,
        arena: std.mem.Allocator,
        chunk_roots: iface.CheckpointRoots,
        timestamp_ms: u64,
        commit: @FieldType(iface.PendingCheckpointInfo, "consensus_commit_ref"),
        rejected: types.Digest,
    ) Error!?iface.PendingCheckpoint {
        const user_tx_count = chunk_roots.tx_roots.len;
        var flushed: ?iface.PendingCheckpoint = null;
        if (q.pending_tx_count > 0 and q.pending_tx_count + user_tx_count > q.max_tx) {
            flushed = try q.flushForced(arena);
        }
        const copy = try copyRoots(q.gpa, chunk_roots);
        errdefer freeRoots(q.gpa, copy);
        try q.pending.append(q.gpa, .{ .roots = copy, .timestamp_ms = timestamp_ms, .commit = commit, .rejected = rejected });
        q.pending_tx_count += user_tx_count;
        return flushed;
    }

    /// `flush`: honours `min_checkpoint_interval_ms` unless `force`.
    pub fn flush(q: *Queue, arena: std.mem.Allocator, current_timestamp_ms: u64, force: bool) Error!?iface.PendingCheckpoint {
        if (!force and current_timestamp_ms < q.last_built_timestamp +| q.min_interval_ms) return null;
        return q.flushForced(arena);
    }

    fn flushForced(q: *Queue, arena: std.mem.Allocator) Error!?iface.PendingCheckpoint {
        if (q.pending.items.len == 0) return null;
        const n = q.pending.items.len;
        const out_roots = try arena.alloc(iface.CheckpointRoots, n);
        for (q.pending.items, out_roots) |*p, *r| r.* = try copyRoots(arena, p.roots);
        const last = q.pending.items[n - 1];
        const out: iface.PendingCheckpoint = .{
            .roots = out_roots,
            .details = .{
                .timestamp_ms = last.timestamp_ms,
                .last_of_epoch = false,
                .checkpoint_height = last.roots.height,
                .consensus_commit_ref = last.commit,
                .rejected_transactions_digest = last.rejected,
                .checkpoint_seq = q.current_seq,
            },
        };
        q.last_built_timestamp = last.timestamp_ms;
        q.pending_tx_count = 0;
        q.current_seq += 1;
        for (q.pending.items) |*p| freeRoots(q.gpa, p.roots);
        q.pending.clearRetainingCapacity();
        return out;
    }
};

/// Sizes of the chunks `schedulables.chunks(max)` yields: full chunks then the remainder
/// (none for no schedulables). The caller allocates the heights with `Queue.nextHeight`.
pub fn chunkSizes(arena: std.mem.Allocator, n_schedulables: usize, max_per_chunk: usize) Error![]usize {
    if (n_schedulables == 0 or max_per_chunk == 0) return &.{};
    const n = (n_schedulables + max_per_chunk - 1) / max_per_chunk;
    const out = try arena.alloc(usize, n);
    for (out, 0..) |*s, i| s.* = @min(max_per_chunk, n_schedulables - i * max_per_chunk);
    return out;
}

fn copyRoots(a: std.mem.Allocator, r: iface.CheckpointRoots) Error!iface.CheckpointRoots {
    return .{ .tx_roots = try a.dupe(iface.TransactionKey, r.tx_roots), .settlement_root = r.settlement_root, .height = r.height };
}

fn freeRoots(a: std.mem.Allocator, r: iface.CheckpointRoots) void {
    a.free(r.tx_roots);
}

// ---------------------------------------------------------------- tests (the queue tests of consensus_handler.rs)

const testing = std.testing;

fn mkRoots(a: std.mem.Allocator, n: usize, height: u64) !iface.CheckpointRoots {
    const keys = try a.alloc(iface.TransactionKey, n);
    for (keys, 0..) |*k, i| k.* = .{ .digest = .{ .@"0" = .{ .@"0" = @splat(@intCast(i)) } } };
    return .{ .tx_roots = keys, .settlement_root = null, .height = height };
}

fn commitRef(i: u32) @FieldType(iface.PendingCheckpointInfo, "consensus_commit_ref") {
    return .{ .index = i, .digest = std.mem.zeroes(@FieldType(@FieldType(iface.PendingCheckpointInfo, "consensus_commit_ref"), "digest")) };
}

const zero_digest: types.Digest = .{ .@"0" = @splat(0) };

test "flush drains all roots into one checkpoint" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var q = Queue.init(testing.allocator, 0, 0, 0, 1000, 0);
    defer q.deinit();
    try testing.expect((try q.pushChunk(a, try mkRoots(a, 5, 1), 1000, commitRef(1), zero_digest)) == null);
    try testing.expect((try q.pushChunk(a, try mkRoots(a, 3, 2), 1000, commitRef(1), zero_digest)) == null);
    const p = (try q.flush(a, 1000, true)).?;
    try testing.expect(q.isEmpty());
    try testing.expectEqual(@as(usize, 2), p.roots.len);
    try testing.expectEqual(@as(u64, 0), p.details.checkpoint_seq);
    try testing.expectEqual(@as(u64, 2), p.details.checkpoint_height);
    try testing.expectEqual(@as(?u64, 0), q.lastAssignedSeq());
}

test "flush respects the minimum checkpoint interval" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var q = Queue.init(testing.allocator, 1000, 0, 0, 1000, 200);
    defer q.deinit();
    _ = try q.pushChunk(a, try mkRoots(a, 5, 1), 1000, commitRef(1), zero_digest);
    try testing.expect((try q.flush(a, 1199, false)) == null);
    try testing.expectEqual(@as(usize, 1), q.pending.items.len);
    try testing.expect((try q.flush(a, 1200, false)) != null);
    try testing.expect(q.isEmpty());
}

test "a chunk that would exceed max_tx flushes the buffer first" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var q = Queue.init(testing.allocator, 1000, 0, 0, 10, 0);
    defer q.deinit();
    _ = try q.pushChunk(a, try mkRoots(a, 6, 1), 1000, commitRef(1), zero_digest);
    const flushed = try q.pushChunk(a, try mkRoots(a, 6, 2), 1000, commitRef(2), zero_digest);
    try testing.expect(flushed != null);
    try testing.expectEqual(@as(usize, 1), q.pending.items.len);
    try testing.expectEqual(@as(u64, 1), q.current_seq);
}

test "chunk sizes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualSlices(usize, &.{ 10, 10, 5 }, try chunkSizes(a, 25, 10));
    try testing.expectEqualSlices(usize, &.{3}, try chunkSizes(a, 3, 10));
    try testing.expectEqual(@as(usize, 0), (try chunkSizes(a, 0, 10)).len);
}
