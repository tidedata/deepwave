//! The exec store as the readers the authority and the executor take:
//!   - `objectReader`: authority.versions.ObjectReader (version assignment: the current version
//!     and start version of a shared object, tombstones answer null),
//!   - `State`: rpc_exec.State over the store, optionally pinned to the versions consensus
//!     assigned (shared and implicit system inputs of one transaction),
//!   - `checkerEnv`: authority.checker.Env for one epoch (TxValidator votes), with the store's
//!     per-epoch markers (signing reads of ended consensus streams and received objects).
//! zkLogin: `sigEnv` leaves `zklogin` null; the runtime sets it to the epoch's JWK map and
//! `ZkLoginEnv` (zklogin.zig) before any check runs.
const std = @import("std");
const exec = @import("exec");
const rpc_exec = @import("rpc_exec");
const sig = @import("sig");
const versions = @import("../authority/versions.zig");
const checker = @import("../authority/checker.zig");
const store_mod = @import("exec_store.zig");
const runner_mod = @import("runner.zig");

const ExecStore = store_mod.ExecStore;
const ObjectView = exec.objects.ObjectView;
const Id = [32]u8;

/// One pinned version: reads of `id` through `State.latest` answer this version.
pub const Pin = struct { id: Id, version: u64 };

/// `start_version` of an object's owner: the initial shared version of a shared object, the
/// start version of a consensus-address-owned or party object, null otherwise.
pub fn startVersion(raw: []const u8) ?u64 {
    const v = ObjectView.parse(raw) catch return null;
    const o = v.ownerBytes();
    if (o.len < 9) return null;
    return switch (o[0]) {
        2, 4, 5 => std.mem.readInt(u64, o[1..9], .little),
        else => null,
    };
}

fn current(ctx: *anyopaque, id: *const Id) ?versions.ObjectReader.Current {
    const s: *ExecStore = @ptrCast(@alignCast(ctx));
    const raw = s.latest(id) orelse return null;
    const v = ObjectView.parse(raw) catch return null;
    return .{ .version = v.version, .start_version = startVersion(raw) };
}
const reader_vt: versions.ObjectReader.VTable = .{ .current = current };

pub fn objectReader(s: *ExecStore) versions.ObjectReader {
    return .{ .ctx = s, .vtable = &reader_vt };
}

/// rpc_exec.State over the store. `pins` (borrowed) answer `latest` for their ids at the pinned
/// version: a transaction reads its shared inputs and the accumulator root at the versions
/// consensus assigned, not at whatever later version the store holds.
pub const State = struct {
    store: *ExecStore,
    pins: []const Pin = &.{},

    fn pinned(st: *const State, id: *const Id) ?u64 {
        for (st.pins) |p| if (std.mem.eql(u8, &p.id, id)) return p.version;
        return null;
    }
    fn latestFn(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
        const st: *const State = @ptrCast(@alignCast(ctx));
        if (st.pinned(id)) |v| return st.store.objectAt(id, v);
        return st.store.latest(id);
    }
    fn atFn(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const st: *const State = @ptrCast(@alignCast(ctx));
        return st.store.objectAt(id, version);
    }
    fn childFn(ctx: *const anyopaque, id: *const Id, upper: u64) ?[]const u8 {
        const st: *const State = @ptrCast(@alignCast(ctx));
        return st.store.atMost(id, upper);
    }
    const vt: rpc_exec.state.State.VTable = .{ .latest = latestFn, .at = atFn, .child_at_most = childFn };

    pub fn state(st: *const State) rpc_exec.State {
        return .{ .ctx = st, .vtable = &vt };
    }
};

/// `SignatureVerifier`'s parameters for an epoch (zkLogin: see the file comment).
pub fn sigEnv(ctx: *const runner_mod.EpochCtx) sig.user.UserSigEnv {
    return .{ .epoch = ctx.epoch, .flags = rpc_exec.live.usersig.flagsOf(ctx.cfg) orelse .{} };
}

/// The TxValidator environment of an epoch over the store (`st` and `sig_env` must outlive it).
pub fn checkerEnv(ctx: *const runner_mod.EpochCtx, st: *const State, sig_env: *const sig.user.UserSigEnv) checker.Env {
    return .{
        .cfg = ctx.cfg,
        .epoch = ctx.epoch,
        .chain_id = ctx.chain_id,
        .rgp = ctx.rgp,
        .committee_size = ctx.committee_size,
        .state = st.state(),
        .sig_env = sig_env,
        .markers = markers(st.store),
    };
}

fn receivedFn(ctx: *anyopaque, epoch: u64, id: *const Id, version: u64) bool {
    const s: *ExecStore = @ptrCast(@alignCast(ctx));
    return s.receivedAt(epoch, id, version);
}
fn streamEndedFn(ctx: *anyopaque, epoch: u64, id: *const Id, start_version: u64) bool {
    const s: *ExecStore = @ptrCast(@alignCast(ctx));
    return s.streamEnded(epoch, id, start_version);
}

/// The store's per-epoch markers as the signing checks read them.
pub fn markers(s: *ExecStore) checker.Markers {
    return .{ .ctx = s, .received = receivedFn, .stream_ended = streamEndedFn };
}

/// `transactions_executed_in_cur_epoch` (executed with effects of `epoch`).
pub fn executedInEpoch(s: *ExecStore, digest: *const Id, epoch: u64) bool {
    const x = s.executed(digest) orelse return false;
    return x.epoch == epoch;
}

/// `transaction_executed_in_last_epoch`: false in epoch 0, else executed in `epoch - 1`.
pub fn executedInLastEpoch(s: *ExecStore, digest: *const Id, epoch: u64) bool {
    if (epoch == 0) return false;
    return executedInEpoch(s, digest, epoch - 1);
}

test "objects: reader and pinned state over the store" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var s = ExecStore.openMem(gpa, std.testing.io);
    defer s.close();
    const id: Id = @splat(4);
    try s.commitTx(&.{ .digest = @splat(1), .td_bcs = "", .effects_bcs = "", .written = &.{try store_mod.testObject(a, id, 3, @splat(7))} });
    try s.commitTx(&.{ .digest = @splat(2), .td_bcs = "", .effects_bcs = "", .written = &.{try store_mod.testObject(a, id, 8, @splat(7))} });
    const r = objectReader(&s);
    try std.testing.expectEqual(@as(u64, 8), r.current(&id).?.version);
    try std.testing.expectEqual(@as(?u64, null), r.current(&id).?.start_version);
    const pinned: State = .{ .store = &s, .pins = &.{.{ .id = id, .version = 3 }} };
    const st = pinned.state();
    try std.testing.expectEqual(@as(u64, 3), (try ObjectView.parse(st.latest(&id).?)).version);
    try std.testing.expectEqual(@as(u64, 3), (try ObjectView.parse(st.childAtMost(&id, 7).?)).version);
    try std.testing.expect(st.at(&id, 8) != null);
}
