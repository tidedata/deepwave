//! `iface.EpochHooks` over an `EpochState`: how the consensus handler's SystemTxRouter delivers
//! sequenced EndOfPublish, CapabilityNotification(V2) and deny-config messages to the epoch store.
//! Calls stage into the commit's batch when the handler opened a commit scope (`beginCommit`),
//! otherwise each call commits by itself. Store errors are fatal for the validator's consistency,
//! so they are counted and the next `status()` check reports them instead of being dropped.
const std = @import("std");
const iface = @import("../iface.zig");
const messages = @import("../messages.zig");
const reconfig = @import("reconfig.zig");

pub const Hooks = struct {
    state: *reconfig.EpochState,
    /// Errors from hook calls (the interface returns void); non-zero means the commit must not be
    /// treated as durable.
    errors: std.atomic.Value(u64) = .init(0),
    /// Set when a sequenced EndOfPublish completed the quorum.
    quorum_seen: std.atomic.Value(bool) = .init(false),

    pub fn init(state: *reconfig.EpochState) Hooks {
        return .{ .state = state };
    }

    pub fn epochHooks(h: *Hooks) iface.EpochHooks {
        return .{ .ctx = h, .vtable = &vtable };
    }

    pub fn failed(h: *const Hooks) bool {
        return h.errors.load(.acquire) != 0;
    }

    fn self(ctx: *anyopaque) *Hooks {
        return @ptrCast(@alignCast(ctx));
    }

    fn endOfPublish(ctx: *anyopaque, from: *const iface.AuthorityName) void {
        const h = self(ctx);
        const q = h.state.recordEndOfPublish(&from.@"0") catch {
            _ = h.errors.fetchAdd(1, .acq_rel);
            return;
        };
        if (q) h.quorum_seen.store(true, .release);
    }

    fn capabilities(ctx: *anyopaque, caps: *const messages.AuthorityCapabilitiesV2) void {
        const h = self(ctx);
        _ = h.state.recordCapabilities(caps) catch {
            _ = h.errors.fetchAdd(1, .acq_rel);
        };
    }

    fn denyConfig(ctx: *anyopaque, cfg: *const messages.SharedTransactionDenyConfig) void {
        const h = self(ctx);
        h.state.recordDenyConfig(cfg) catch {
            _ = h.errors.fetchAdd(1, .acq_rel);
        };
    }

    const vtable: iface.EpochHooks.VTable = .{
        .end_of_publish = endOfPublish,
        .capabilities = capabilities,
        .deny_config = denyConfig,
    };
};

test "hooks record EndOfPublish into the commit batch and flag the quorum" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pb[0..try tmp.dir.realPath(std.testing.io, &pb)];
    var ms: [4]reconfig.CommitteeMember = undefined;
    for (&ms, 0..) |*m, i| m.* = .{ .name = @splat(@intCast(i + 1)), .stake = 2500 };
    const st = try reconfig.EpochState.open(std.testing.allocator, std.testing.io, dir, .{ .epoch = 1, .protocol_version = 141, .chain_id = "0badc0de".*, .epoch_start_timestamp_ms = 0, .committee = &ms, .own_index = null });
    defer st.close();
    var h = Hooks.init(st);
    const eh = h.epochHooks();
    var b = st.store.batch();
    defer b.deinit();
    st.beginCommit(&b);
    for ([_]u8{ 1, 2, 3 }) |i| {
        const name: iface.AuthorityName = .{ .@"0" = @splat(i) };
        eh.vtable.end_of_publish(eh.ctx, &name);
    }
    st.endCommit();
    try std.testing.expect(h.quorum_seen.load(.acquire));
    // staged, not yet durable: a reopen before the commit sees nothing
    try std.testing.expectEqual(@as(usize, 0), st.store.count(.end_of_publish));
    try st.store.commit(&b);
    try std.testing.expectEqual(@as(usize, 3), st.store.count(.end_of_publish));
    try std.testing.expect(!h.failed());
}
