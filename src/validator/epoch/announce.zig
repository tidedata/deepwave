//! The consensus messages the epoch lifecycle sends: CapabilityNotificationV2 at epoch start
//! (sui-node `lib.rs`: after reconfiguration, `ConsensusAdapter::submit` of
//! `ConsensusTransaction::new_capability_notification_v2`) and EndOfPublish
//! (`ConsensusTransaction::new_end_of_publish`, after a manual epoch close left the reconfig state at
//! RejectUserCerts). `tracking_id` is 8 random bytes (`ConsensusTransaction::new_*` take it from the
//! thread rng); the bytes only matter for log correlation.
const std = @import("std");
const bcs = @import("bcs");
const protocol = @import("protocol");
const iface = @import("../iface.zig");
const messages = @import("../messages.zig");
const capabilities = @import("capabilities.zig");

pub const Error = error{ OutOfMemory, Encode, Overloaded, EpochEnding, Unimplemented, Capabilities };

pub fn encodeTransaction(arena: std.mem.Allocator, tracking_id: [8]u8, kind: messages.ConsensusTransactionKind) Error![]u8 {
    const tx: messages.ConsensusTransaction = .{ .tracking_id = tracking_id, .kind = kind };
    return bcs.encodeAlloc(messages.ConsensusTransaction, arena, &tx) catch return error.Encode;
}

pub fn encodeEndOfPublish(arena: std.mem.Allocator, tracking_id: [8]u8, authority: [96]u8) Error![]u8 {
    return encodeTransaction(arena, tracking_id, .{ .EndOfPublish = .{ .@"0" = authority } });
}

pub fn encodeCapabilities(arena: std.mem.Allocator, tracking_id: [8]u8, caps: messages.AuthorityCapabilitiesV2) Error![]u8 {
    return encodeTransaction(arena, tracking_id, .{ .CapabilityNotificationV2 = caps });
}

pub const Announcer = struct {
    authority: [96]u8,
    chain: protocol.Chain,
    table: ?*const capabilities.DigestTable = null,
    /// ProtocolVersion::MIN/MAX of this binary.
    min_version: u64 = capabilities.supported_min,
    max_version: u64 = capabilities.supported_max,
    /// System packages this binary carries (`get_available_system_packages`); empty votes against upgrades.
    system_packages: []const messages.ObjectRef = &.{},
    /// Grows with every notification (sui-node: wall clock ms).
    generation: u64 = 0,

    /// Builds and submits this validator's capability notification. sui-node (lib.rs, at each
    /// epoch start) sends `supported_protocol_versions.truncate_below(current)`: the versions
    /// from the epoch's protocol version up to MAX, never the ones below it.
    pub fn announce(a: *Announcer, arena: std.mem.Allocator, submit: iface.ConsensusSubmit, tracking_id: [8]u8, now_ms: u64, current_version: u64) Error!void {
        a.generation = @max(a.generation + 1, now_ms);
        const min = @max(a.min_version, current_version);
        const caps = capabilities.buildCapabilities(arena, a.table, a.chain, a.authority, a.generation, min, a.max_version, a.system_packages) catch return error.Capabilities;
        const body = try encodeCapabilities(arena, tracking_id, caps);
        submit.submit(&.{body}, .system) catch |e| return switch (e) {
            error.Overloaded => error.Overloaded,
            error.EpochEnding => error.EpochEnding,
            error.Unimplemented => error.Unimplemented,
        };
    }

    pub fn sendEndOfPublish(a: *const Announcer, arena: std.mem.Allocator, submit: iface.ConsensusSubmit, tracking_id: [8]u8) Error!void {
        const body = try encodeEndOfPublish(arena, tracking_id, a.authority);
        submit.submit(&.{body}, .system) catch |e| return switch (e) {
            error.Overloaded => error.Overloaded,
            error.EpochEnding => error.EpochEnding,
            error.Unimplemented => error.Unimplemented,
        };
    }
};

const Capture = struct {
    got: std.ArrayList([]const u8) = .empty,
    prio: ?iface.ConsensusSubmit.Priority = null,
    fn submit(ctx: *anyopaque, txs: []const []const u8, p: iface.ConsensusSubmit.Priority) iface.ConsensusSubmit.Error!void {
        const c: *Capture = @ptrCast(@alignCast(ctx));
        for (txs) |t| c.got.append(std.testing.allocator, std.testing.allocator.dupe(u8, t) catch return error.Overloaded) catch return error.Overloaded;
        c.prio = p;
    }
    const vt: iface.ConsensusSubmit.VTable = .{ .submit = submit };
};

test "announcements are system consensus transactions that decode back" {
    var cap: Capture = .{};
    defer {
        for (cap.got.items) |t| std.testing.allocator.free(t);
        cap.got.deinit(std.testing.allocator);
    }
    const sub: iface.ConsensusSubmit = .{ .ctx = &cap, .vtable = &Capture.vt };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var a: Announcer = .{ .authority = @splat(7), .chain = .unknown, .min_version = 1, .max_version = 141 };
    try a.announce(arena, sub, @splat(1), 5000, 139);
    try a.sendEndOfPublish(arena, sub, @splat(2));
    try std.testing.expectEqual(iface.ConsensusSubmit.Priority.system, cap.prio.?);
    try std.testing.expectEqual(@as(usize, 2), cap.got.items.len);
    const t0 = try bcs.decode(messages.ConsensusTransaction, arena, cap.got.items[0]);
    try std.testing.expect(t0.kind == .CapabilityNotificationV2);
    try std.testing.expectEqual(@as(u64, 5000), t0.kind.CapabilityNotificationV2.generation);
    try std.testing.expectEqual(@as(usize, 3), t0.kind.CapabilityNotificationV2.supported_protocol_versions.versions.len);
    const t1 = try bcs.decode(messages.ConsensusTransaction, arena, cap.got.items[1]);
    try std.testing.expect(t1.kind == .EndOfPublish);
    try std.testing.expectEqual(@as(u8, 7), t1.kind.EndOfPublish.@"0"[0]);
    // generations only grow, even when the clock does not
    try a.announce(arena, sub, @splat(1), 100, 141);
    try std.testing.expect(a.generation > 5000);
    // versions below the current one are not announced (truncate_below)
    const t2 = try bcs.decode(messages.ConsensusTransaction, arena, cap.got.items[2]);
    try std.testing.expectEqual(@as(usize, 1), t2.kind.CapabilityNotificationV2.supported_protocol_versions.versions.len);
    try std.testing.expectEqual(@as(u64, 141), t2.kind.CapabilityNotificationV2.supported_protocol_versions.versions[0][0].@"0");
}
