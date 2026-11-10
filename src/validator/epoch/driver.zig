//! Drives epoch switches from certified checkpoints: implements `iface.CertifiedSink` for the
//! validator. A certified checkpoint whose summary carries `end_of_epoch_data` is the last of its
//! epoch; the next committee, protocol version and start time come out of it
//! (`EndOfEpochData.next_epoch_committee`, `next_epoch_protocol_version`, and the summary's
//! `timestamp_ms`, which ChangeEpoch writes as the new epoch's start time), so the switch does not
//! have to wait for the system state to be re-read.
//!
//! The switch itself runs on the driver's own thread: it stops the old epoch's components, which
//! include the thread that certified the checkpoint, so it must never run inline.
//!
//! The certifying threads never look at the manager: they decode against `reach`, the epoch the
//! queue will have reached once every queued switch ran (read and written under `mu`). Switches
//! are asynchronous, so the last checkpoint of epoch N+1 can arrive while the switch to N+1 is
//! still running; it is compared with `reach` (N+1), queued behind it and applied in order. A
//! checkpoint for an epoch below `reach` (a repeat, state sync replay) is dropped.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const iface = @import("../iface.zig");
const manager = @import("manager.zig");
const reconfig = @import("reconfig.zig");

pub const Error = error{ OutOfMemory, BadSummary, WrongEpoch };

/// The facts of the next epoch that the summary does not carry: its system parameters. Null reuses
/// the previous epoch's duration and assumes no safe mode.
pub const Params = struct { epoch_duration_ms: u64, safe_mode: bool };

/// Reads the next epoch's system parameters once its ChangeEpoch executed (called on the driver
/// thread when the switch runs, so it may wait a little). Null reuses the previous epoch's
/// duration and assumes no safe mode.
pub const ParamsSource = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, next_epoch: u64) ?Params,
};

const Queued = struct { next: *Next, arena: *std.heap.ArenaAllocator };

pub const Next = struct {
    info: reconfig.EpochInfo,
    transition: manager.Transition,
};

const Certified = types.hand.Envelope(types.CheckpointSummary, types.AuthorityQuorumSignInfo);

pub const Driver = struct {
    gpa: std.mem.Allocator,
    io: Io,
    mgr: *manager.EpochManager,
    params: ?ParamsSource = null,
    mu: Io.Mutex = .init,
    cond: Io.Condition = .init,
    /// Switches in order, each with the arena that holds its committee.
    queue: std.ArrayList(Queued) = .empty,
    /// Epoch the queue will reach (null until the first checkpoint is looked at, or after a failed
    /// switch emptied the queue); epoch duration the last queued switch carries.
    reach: ?u64 = null,
    duration_ms: u64 = 0,
    stopping: bool = false,
    thread: ?std.Thread = null,
    /// Last failure of a switch (for health and logs); null when the last one worked.
    last_error: ?manager.Error = null,

    pub fn start(d: *Driver) std.Thread.SpawnError!void {
        d.thread = try std.Thread.spawn(.{}, loop, .{d});
    }

    pub fn stop(d: *Driver) void {
        d.mu.lockUncancelable(d.io);
        d.stopping = true;
        d.cond.broadcast(d.io);
        d.mu.unlock(d.io);
        if (d.thread) |t| t.join();
        d.thread = null;
        d.mu.lockUncancelable(d.io);
        defer d.mu.unlock(d.io);
        for (d.queue.items) |q| freeQueued(d.gpa, q);
        d.queue.deinit(d.gpa);
        d.queue = .empty;
    }

    fn freeQueued(gpa: std.mem.Allocator, q: Queued) void {
        q.arena.deinit();
        gpa.destroy(q.arena);
    }

    pub fn certifiedSink(d: *Driver) iface.CertifiedSink {
        return .{ .ctx = d, .vtable = &sink_vtable };
    }

    /// Decodes the certified summary; when it ends the epoch `reach` (the epoch the queue will
    /// have reached), builds the next epoch's description in `arena`. Null when the checkpoint is
    /// not the last of that epoch, or belongs to an older one (already queued, or a replay).
    pub fn nextFromSummary(d: *const Driver, arena: std.mem.Allocator, summary_bcs: []const u8, reach: u64, duration_ms: u64) Error!?Next {
        const c = bcs.decode(Certified, arena, summary_bcs) catch return error.BadSummary;
        const s = c.data;
        const eoe = s.end_of_epoch_data orelse return null;
        if (s.epoch < reach) return null;
        if (s.epoch > reach) return error.WrongEpoch; // a gap: epochs between were never seen
        const members = try arena.alloc(reconfig.CommitteeMember, eoe.nextEpochCommittee.len);
        for (eoe.nextEpochCommittee, members) |m, *o| o.* = .{ .name = m[0].@"0", .stake = m[1] };
        std.mem.sort(reconfig.CommitteeMember, members, {}, struct {
            fn lt(_: void, a: reconfig.CommitteeMember, b: reconfig.CommitteeMember) bool {
                return std.mem.lessThan(u8, &a.name, &b.name);
            }
        }.lt);
        var own: ?u32 = null;
        if (d.mgr.own_name) |n| {
            for (members, 0..) |m, i| {
                if (std.mem.eql(u8, &m.name, &n)) own = @intCast(i);
            }
        }
        return .{
            .info = .{
                .epoch = s.epoch + 1,
                .protocol_version = eoe.nextEpochProtocolVersion.@"0",
                .chain_id = d.mgr.chain_id,
                .epoch_start_timestamp_ms = s.timestamp_ms,
                .committee = members,
                .own_index = own,
            },
            // the duration is looked up when the switch runs (the ChangeEpoch has executed by then)
            .transition = .{ .epoch_duration_ms = duration_ms, .safe_mode = false, .from_epoch = s.epoch },
        };
    }

    /// The sink body: decode against the queue's epoch, and hand the switch to the driver thread.
    fn certified(ctx: *anyopaque, seq: u64, summary_bcs: []const u8, contents_bcs: []const u8) error{ Io, Unimplemented }!void {
        _ = .{ seq, contents_bcs };
        const d: *Driver = @ptrCast(@alignCast(ctx));
        const arena = d.gpa.create(std.heap.ArenaAllocator) catch return error.Io;
        arena.* = std.heap.ArenaAllocator.init(d.gpa);
        var keep = false;
        defer if (!keep) {
            arena.deinit();
            d.gpa.destroy(arena);
        };
        d.mu.lockUncancelable(d.io);
        defer d.mu.unlock(d.io);
        if (d.reach == null) {
            // nothing was ever queued (or the queue was dropped after a failure), so no switch is
            // running and the manager is stable
            const cur = d.mgr.current orelse return;
            d.reach = cur.info.epoch;
            d.duration_ms = d.mgr.last.epoch_duration_ms;
        }
        const next = (d.nextFromSummary(arena.allocator(), summary_bcs, d.reach.?, d.duration_ms) catch return error.Io) orelse return;
        const slot = arena.allocator().create(Next) catch return error.Io;
        slot.* = next;
        d.queue.append(d.gpa, .{ .next = slot, .arena = arena }) catch return error.Io;
        keep = true;
        d.reach = next.info.epoch;
        d.duration_ms = next.transition.epoch_duration_ms;
        d.cond.broadcast(d.io);
    }

    /// Applies the oldest queued switch now (the thread's body; also used directly by tests).
    pub fn switchNow(d: *Driver) bool {
        d.mu.lockUncancelable(d.io);
        if (d.queue.items.len == 0) {
            d.mu.unlock(d.io);
            return false;
        }
        const q = d.queue.orderedRemove(0);
        d.mu.unlock(d.io);
        defer freeQueued(d.gpa, q);
        var t = q.next.transition;
        if (d.params) |p| if (p.get(p.ctx, q.next.info.epoch)) |v| {
            t.epoch_duration_ms = v.epoch_duration_ms;
            t.safe_mode = v.safe_mode;
        };
        if (d.mgr.switchEpoch(q.next.info, t)) {
            d.last_error = null;
            d.mu.lockUncancelable(d.io);
            d.duration_ms = t.epoch_duration_ms;
            d.mu.unlock(d.io);
        } else |e| {
            d.last_error = e;
            // the queue's order is broken: drop it and look at the manager again at the next
            // checkpoint
            d.mu.lockUncancelable(d.io);
            for (d.queue.items) |r| freeQueued(d.gpa, r);
            d.queue.clearRetainingCapacity();
            d.reach = null;
            d.mu.unlock(d.io);
        }
        return true;
    }

    fn loop(d: *Driver) void {
        while (true) {
            d.mu.lockUncancelable(d.io);
            while (d.queue.items.len == 0 and !d.stopping) d.cond.waitUncancelable(d.io, &d.mu);
            const done = d.stopping;
            d.mu.unlock(d.io);
            if (done) return;
            _ = d.switchNow();
        }
    }

    const sink_vtable: iface.CertifiedSink.VTable = .{ .certified = certified };
};

// ------------------------------------------------------------------ tests

const TestComponents = struct {
    started: u32 = 0,
    stopped: u32 = 0,
    fn stop(ctx: *anyopaque, _: u64) void {
        const s: *TestComponents = @ptrCast(@alignCast(ctx));
        s.stopped += 1;
    }
    fn startFn(ctx: *anyopaque, _: *reconfig.EpochState, _: *const manager.Transition) error{ComponentFailed}!void {
        const s: *TestComponents = @ptrCast(@alignCast(ctx));
        s.started += 1;
    }
    const vt: manager.Components.VTable = .{ .stop = stop, .start = startFn };
};

fn summaryBcs(arena: std.mem.Allocator, epoch: u64, eoe: ?types.EndOfEpochData) ![]u8 {
    const digest: types.CheckpointContentsDigest = .{ .@"0" = .{ .@"0" = @splat(1) } };
    const c: Certified = .{
        .data = .{
            .epoch = epoch,
            .sequence_number = 77,
            .network_total_transactions = 5,
            .content_digest = digest,
            .previous_digest = null,
            .epoch_rolling_gas_cost_summary = .{ .computationCost = 1, .storageCost = 2, .storageRebate = 3, .nonRefundableStorageFee = 4 },
            .timestamp_ms = 123_456,
            .checkpoint_commitments = &.{},
            .end_of_epoch_data = eoe,
            .version_specific_data = &.{},
        },
        .auth_signature = .{ .epoch = epoch, .signature = @splat(0), .signers_map = .{ .@"0" = &.{ 0x3a, 0x30, 0, 0, 0, 0, 0, 0 } } },
    };
    return bcs.encodeAlloc(Certified, arena, &c);
}

test "the last checkpoint of an epoch switches to the committee it announces" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pb[0..try tmp.dir.realPath(std.testing.io, &pb)];
    var tc: TestComponents = .{};
    var m = manager.EpochManager.init(std.testing.allocator, std.testing.io, dir, null, "0badc0de".*, .{ .ctx = &tc, .vtable = &TestComponents.vt });
    defer m.deinit();
    var ms: [4]reconfig.CommitteeMember = undefined;
    for (&ms, 0..) |*x, i| x.* = .{ .name = @splat(@intCast(i + 1)), .stake = 2500 };
    try m.start(.{ .epoch = 9, .protocol_version = 141, .chain_id = "0badc0de".*, .epoch_start_timestamp_ms = 1, .committee = &ms, .own_index = null }, .{ .epoch_duration_ms = 600_000, .safe_mode = false, .from_epoch = 8 });
    var d: Driver = .{ .gpa = std.testing.allocator, .io = std.testing.io, .mgr = &m };
    defer d.stop();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const sink = d.certifiedSink();

    // a mid-epoch checkpoint does nothing
    try sink.certified(10, try summaryBcs(arena, 9, null), "");
    try std.testing.expect(!d.switchNow());

    // the next committee is listed out of order: it is sorted by key like Committee::new
    const next = [_]struct { types.AuthorityPublicKeyBytes, u64 }{
        .{ .{ .@"0" = @splat(4) }, 3000 },
        .{ .{ .@"0" = @splat(2) }, 7000 },
    };
    const eoe: types.EndOfEpochData = .{ .nextEpochCommittee = &next, .nextEpochProtocolVersion = .{ .@"0" = 142 }, .epochCommitments = &.{} };
    try sink.certified(11, try summaryBcs(arena, 9, eoe), "");
    try std.testing.expect(d.switchNow());
    try std.testing.expectEqual(@as(u64, 10), m.current.?.info.epoch);
    try std.testing.expectEqual(@as(u64, 142), m.current.?.info.protocol_version);
    try std.testing.expectEqual(@as(u64, 123_456), m.current.?.info.epoch_start_timestamp_ms);
    try std.testing.expectEqual(@as(u8, 2), m.current.?.info.committee[0].name[0]);
    try std.testing.expectEqual(@as(u64, 600_000), m.last.epoch_duration_ms);
    try std.testing.expectEqual(@as(u32, 2), tc.started);

    // replaying the same checkpoint later (state sync) is ignored: it belongs to an older epoch
    try sink.certified(11, try summaryBcs(arena, 9, eoe), "");
    try std.testing.expect(!d.switchNow());
    // garbage is an error, not a switch
    try std.testing.expectError(error.Io, sink.certified(12, "xx", ""));
}

test "a final checkpoint that arrives before the switch ran is queued in order; repeats are dropped" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pb[0..try tmp.dir.realPath(std.testing.io, &pb)];
    var tc: TestComponents = .{};
    var m = manager.EpochManager.init(std.testing.allocator, std.testing.io, dir, null, "0badc0de".*, .{ .ctx = &tc, .vtable = &TestComponents.vt });
    defer m.deinit();
    var ms: [4]reconfig.CommitteeMember = undefined;
    for (&ms, 0..) |*x, i| x.* = .{ .name = @splat(@intCast(i + 1)), .stake = 2500 };
    try m.start(.{ .epoch = 9, .protocol_version = 141, .chain_id = "0badc0de".*, .epoch_start_timestamp_ms = 1, .committee = &ms, .own_index = null }, .{ .epoch_duration_ms = 600_000, .safe_mode = false, .from_epoch = 8 });
    var d: Driver = .{ .gpa = std.testing.allocator, .io = std.testing.io, .mgr = &m };
    defer d.stop();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const sink = d.certifiedSink();
    const next = [_]struct { types.AuthorityPublicKeyBytes, u64 }{
        .{ .{ .@"0" = @splat(2) }, 5000 },
        .{ .{ .@"0" = @splat(4) }, 5000 },
    };
    const eoe: types.EndOfEpochData = .{ .nextEpochCommittee = &next, .nextEpochProtocolVersion = .{ .@"0" = 142 }, .epochCommitments = &.{} };
    // the last checkpoints of epochs 9 and 10 both arrive before any switch ran; 9's arrives twice
    try sink.certified(11, try summaryBcs(arena, 9, eoe), "");
    try sink.certified(11, try summaryBcs(arena, 9, eoe), "");
    try sink.certified(20, try summaryBcs(arena, 10, eoe), "");
    // an epoch nobody has seen the start of is an error, not a queued switch
    try std.testing.expectError(error.Io, sink.certified(40, try summaryBcs(arena, 12, eoe), ""));
    try std.testing.expectEqual(@as(usize, 2), d.queue.items.len);
    try std.testing.expect(d.switchNow());
    try std.testing.expect(d.switchNow());
    try std.testing.expect(!d.switchNow());
    try std.testing.expectEqual(@as(u64, 11), m.current.?.info.epoch);
    try std.testing.expect(d.last_error == null);
    // a repeat of epoch 10's last checkpoint after both switches ran is dropped
    try sink.certified(20, try summaryBcs(arena, 10, eoe), "");
    try std.testing.expect(!d.switchNow());
}
