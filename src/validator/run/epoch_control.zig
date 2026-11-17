//! `authority/env.EpochControl` over the epoch lane's `reconfig.EpochState` (the request of
//!: "the epoch lane should implement EpochControl over its epoch
//! store and write the reconfig state in the same durable group").
//!
//! EndOfPublish votes go to the epoch store as they are sequenced: recording one is idempotent, so
//! when a crash leaves the store ahead of the authority's durable group the replayed commit records
//! the same votes and reaches the same quorum.
//!
//! The reconfig state is not idempotent: `handle_close_epoch` reads "was the state already
//! RejectAllTx" to decide the final round. Were it stored ahead of the commit group, the replay of
//! the epoch's last commit would see RejectAllTx, decide it is not the final round, and never build
//! the last checkpoint of the epoch. So the state is written as a side-record in the authority's
//! commit group (`state.ext_epoch`, via `take_records`) and folded back at restart (`restore`); the
//! epoch store's own copy is only the starting value.
const std = @import("std");
const env = @import("../authority/env.zig");
const reconfig = @import("../epoch/reconfig.zig");

const log = std.log.scoped(.epoch_control);

pub const Control = struct {
    es: *reconfig.EpochState,
    epoch_duration_ms: u64,
    /// A state changed by this commit, not yet handed to the group.
    dirty: bool = false,
    /// Store errors (EndOfPublish): the validator stops treating commits as durable.
    errors: u64 = 0,

    pub fn init(es: *reconfig.EpochState, epoch_duration_ms: u64) Control {
        return .{ .es = es, .epoch_duration_ms = epoch_duration_ms };
    }

    pub fn control(c: *Control) env.EpochControl {
        return .{ .ctx = c, .vtable = &vtable };
    }

    /// Folds one `ext_epoch` record (in group order) after a restart.
    pub fn restore(c: *Control, bytes: []const u8) error{Corrupt}!void {
        if (bytes.len != 2 or bytes[0] != 1 or bytes[1] > 3) return error.Corrupt;
        c.es.reconfig = @enumFromInt(bytes[1]);
    }

    /// The commit's record, when the state changed (one byte version, one byte state).
    pub fn takeRecords(c: *Control, arena: std.mem.Allocator) error{OutOfMemory}!?[]const u8 {
        if (!c.dirty) return null;
        c.dirty = false;
        const out = try arena.alloc(u8, 2);
        out[0] = 1;
        out[1] = @intFromEnum(c.es.reconfig);
        return out;
    }

    fn self(ctx: *anyopaque) *Control {
        return @ptrCast(@alignCast(ctx));
    }
    fn toEnv(s: reconfig.ReconfigState) env.ReconfigState {
        return .{ .status = @enumFromInt(@intFromEnum(s)) };
    }

    fn reconfigState(ctx: *anyopaque) env.ReconfigState {
        return toEnv(self(ctx).es.reconfig);
    }
    fn storeReconfigState(ctx: *anyopaque, s: env.ReconfigState) void {
        const c = self(ctx);
        const next: reconfig.ReconfigState = @enumFromInt(@intFromEnum(s.status));
        if (next == c.es.reconfig) return;
        c.es.reconfig = next;
        c.dirty = true;
    }
    fn hasFrom(ctx: *anyopaque, i: u32) bool {
        const c = self(ctx);
        return i < c.es.eop_voted.len and c.es.eop_voted[i];
    }
    fn recordEop(ctx: *anyopaque, i: u32) bool {
        const c = self(ctx);
        if (i >= c.es.info.committee.len) return c.es.hasEndOfPublishQuorum();
        return c.es.recordEndOfPublish(&c.es.info.committee[i].name) catch |e| {
            c.errors += 1;
            log.err("EndOfPublish from {d} not stored: {s}", .{ i, @errorName(e) });
            return c.es.hasEndOfPublishQuorum();
        };
    }
    fn hasQuorum(ctx: *anyopaque) bool {
        return self(ctx).es.hasEndOfPublishQuorum();
    }
    fn nextReconfig(ctx: *anyopaque) u64 {
        const c = self(ctx);
        return c.es.nextReconfigurationTimestampMs(c.epoch_duration_ms);
    }

    const vtable: env.EpochControl.VTable = .{
        .reconfig_state = reconfigState,
        .store_reconfig_state = storeReconfigState,
        .has_received_end_of_publish_from = hasFrom,
        .record_end_of_publish = recordEop,
        .has_end_of_publish_quorum = hasQuorum,
        .next_reconfiguration_timestamp_ms = nextReconfig,
        .take_records = takeRecordsVt,
    };
    fn takeRecordsVt(ctx: *anyopaque, arena: std.mem.Allocator) error{OutOfMemory}!?[]const u8 {
        return self(ctx).takeRecords(arena);
    }
};

test "reconfig state travels in the commit group; EndOfPublish quorum by stake" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pb[0..try tmp.dir.realPath(std.testing.io, &pb)];
    var ms: [4]reconfig.CommitteeMember = undefined;
    for (&ms, 0..) |*m, i| m.* = .{ .name = @splat(@intCast(i + 1)), .stake = 2500 };
    const info: reconfig.EpochInfo = .{ .epoch = 3, .protocol_version = 141, .chain_id = "0badc0de".*, .epoch_start_timestamp_ms = 1000, .committee = &ms, .own_index = 0 };
    var group: ?[]u8 = null;
    defer if (group) |g| gpa.free(g);
    {
        const es = try reconfig.EpochState.open(gpa, std.testing.io, dir, info);
        defer es.close();
        var c = Control.init(es, 60_000);
        const ctl = c.control();
        try std.testing.expectEqual(@as(u64, 61_000), ctl.nextReconfigurationTimestampMs());
        try std.testing.expect(!ctl.recordEndOfPublish(0));
        try std.testing.expect(!ctl.recordEndOfPublish(1));
        try std.testing.expect(ctl.hasReceivedEndOfPublishFrom(1) and !ctl.hasReceivedEndOfPublishFrom(2));
        try std.testing.expect(ctl.recordEndOfPublish(2)); // 7500 of 10000
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        try std.testing.expect((try c.takeRecords(arena.allocator())) == null);
        ctl.storeReconfigState(.{ .status = .reject_all_tx });
        group = try gpa.dupe(u8, (try c.takeRecords(arena.allocator())).?);
        try std.testing.expect((try c.takeRecords(arena.allocator())) == null);
    }
    // restart: the store has the votes, the group gives the state back
    const es = try reconfig.EpochState.open(gpa, std.testing.io, dir, info);
    defer es.close();
    var c = Control.init(es, 60_000);
    try std.testing.expect(c.control().hasEndOfPublishQuorum());
    try std.testing.expect(!c.control().reconfigState().isRejectAllTx());
    try c.restore(group.?);
    try std.testing.expect(c.control().reconfigState().isRejectAllTx());
    try std.testing.expectError(error.Corrupt, c.restore(&.{ 1, 9 }));
}
