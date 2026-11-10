//! Owned-object locks (`owned_object_locked_transactions`, mainnet-v1.83.1 with
//! `disable_preconsensus_locking`): one lock per owned ObjectRef per epoch, taken after
//! sequencing in the consensus handler. The first transaction in consensus order that names an
//! ObjectRef holds it for the whole epoch; any later transaction naming the same ObjectRef with
//! another digest conflicts and is dropped. This is the no-equivocation guarantee: a lock is never
//! replaced or removed within an epoch, and a commit's locks are made durable in the same group as
//! everything else the commit decided (state.zig), so a crash cannot split them.
//!
//! `try_acquire_owned_object_locks_post_consensus`: all refs are checked against the locks taken
//! earlier in this commit (`current`) and the locks of earlier commits (`existing`, the epoch
//! state); a ref already held by the same digest is fine (duplicates, replays). Either every ref
//! is acquired or none.
const std = @import("std");
const state_mod = @import("state.zig");
const tx_mod = @import("tx.zig");

const Allocator = std.mem.Allocator;
pub const ObjRef = tx_mod.ObjRef;
pub const Id = tx_mod.Id;

pub const Outcome = enum { acquired, already_ours, conflict };

pub const OwnedLocks = struct {
    existing: *state_mod.EpochState,
    /// Locks taken by earlier transactions of the commit being processed.
    current: state_mod.LockMap = .empty,
    arena: Allocator,

    pub fn init(arena: Allocator, existing: *state_mod.EpochState) OwnedLocks {
        return .{ .existing = existing, .arena = arena };
    }

    /// The holder of `ref` in this commit or an earlier one.
    pub fn holder(l: *const OwnedLocks, ref: ObjRef) ?Id {
        const k = state_mod.lockKey(ref);
        if (l.current.get(k)) |h| return h;
        return l.existing.lockHolder(ref);
    }

    /// The holder of `ref` in this commit only (an intra-commit contest).
    pub fn holderInCommit(l: *const OwnedLocks, ref: ObjRef) ?Id {
        return l.current.get(state_mod.lockKey(ref));
    }

    /// Checks `refs` for `tx` and, when free, records them as held by `tx` in this commit
    /// (the caller adds them to the commit batch). Does not mutate anything on conflict.
    pub fn tryAcquirePostConsensus(l: *OwnedLocks, refs: []const ObjRef, tx: *const Id) Allocator.Error!Outcome {
        var all_ours = refs.len != 0;
        for (refs) |r| {
            if (l.holder(r)) |h| {
                if (!std.mem.eql(u8, &h, tx)) return .conflict;
            } else all_ours = false;
        }
        if (all_ours) return .already_ours;
        for (refs) |r| {
            const gop = try l.current.getOrPut(l.arena, state_mod.lockKey(r));
            if (!gop.found_existing) gop.value_ptr.* = tx.*;
        }
        return .acquired;
    }
};

fn mkref(b: u8, v: u64) ObjRef {
    return .{ .id = @splat(b), .version = v, .digest = @splat(b +% 1) };
}

test "first in order wins, same digest is idempotent, all or nothing" {
    const gpa = std.testing.allocator;
    var st = state_mod.EpochState.init(gpa);
    defer st.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    var l = OwnedLocks.init(ar.allocator(), &st);
    const a: Id = @splat(0xa);
    const b: Id = @splat(0xb);
    try std.testing.expectEqual(Outcome.acquired, try l.tryAcquirePostConsensus(&.{ mkref(1, 1), mkref(2, 1) }, &a));
    // b wants ref 2 (taken) and ref 3 (free): conflict, and ref 3 stays free
    try std.testing.expectEqual(Outcome.conflict, try l.tryAcquirePostConsensus(&.{ mkref(3, 1), mkref(2, 1) }, &b));
    try std.testing.expect(l.holder(mkref(3, 1)) == null);
    try std.testing.expectEqual(Outcome.already_ours, try l.tryAcquirePostConsensus(&.{mkref(1, 1)}, &a));
    // a different version of the same object is a different ref
    try std.testing.expectEqual(Outcome.acquired, try l.tryAcquirePostConsensus(&.{mkref(1, 2)}, &b));
    // no owned inputs: acquired (nothing to lock), never a conflict
    try std.testing.expectEqual(Outcome.acquired, try l.tryAcquirePostConsensus(&.{}, &b));
}

test "locks of earlier commits conflict" {
    const gpa = std.testing.allocator;
    var st = state_mod.EpochState.init(gpa);
    defer st.deinit();
    var log = @import("epoch_log.zig").MemLog.init(gpa);
    defer log.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    var batch = state_mod.Batch.init(ar.allocator(), .{ .last_committed_round = 1, .sub_dag_index = 1, .transaction_index = 0 });
    try batch.addLock(mkref(7, 3), @splat(1));
    try state_mod.commit(&st, &log, &batch);
    var l = OwnedLocks.init(ar.allocator(), &st);
    try std.testing.expectEqual(Outcome.conflict, try l.tryAcquirePostConsensus(&.{mkref(7, 3)}, &@as(Id, @splat(2))));
    try std.testing.expectEqual(Outcome.already_ours, try l.tryAcquirePostConsensus(&.{mkref(7, 3)}, &@as(Id, @splat(1))));
}
