//! Epoch switching (sui-node `monitor_reconfiguration` / `reconfigure_state`, authority.rs
//! `reconfigure`): when the last checkpoint of an epoch (the one holding the EndOfEpochTransaction)
//! is certified and executed, the validator stops the old epoch's components, closes the old epoch
//! store, opens the next one with the new committee and starts the components again.
//!
//! Order (as `reconfigure_state`): 1. stop consensus and the handler of the old epoch, so nothing
//! of the old epoch signs or sequences any more; 2. close the old epoch store; 3. open the next
//! epoch store (its identity record pins epoch, protocol version, start time and committee);
//! 4. start the components for the new epoch. A failure in 3 leaves the manager stopped (no
//! components running), never half switched.
//!
//! The committee comes from the system state after the EndOfEpochTransaction executed
//! (`serve.sysstate`: validators sorted by protocol key bytes = consensus AuthorityIndex order).
//! Safe mode (advance_epoch aborted and executed natively) changes nothing here except the flag
//! the caller passes in, which is kept and exported to metrics.
const std = @import("std");
const serve = @import("serve");
const sysstate = serve.sysstate;
const reconfig = @import("reconfig.zig");
const iface = @import("../iface.zig");
const fsutil = @import("../keys/fsutil.zig");

pub const Error = error{ EpochOrder, OutOfMemory, Io, BadCommittee, BatchTooLarge, BadSystemState, ComponentFailed };

/// What the rest of the validator needs to restart per epoch (val-authority's handler and
/// adapter, consensus authority node, checkpoint builder, randomness and JWK, the API's epoch
/// view). `stop` must not return before the epoch's threads no longer touch its store.
pub const Components = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        stop: *const fn (ctx: *anyopaque, epoch: u64) void,
        start: *const fn (ctx: *anyopaque, state: *reconfig.EpochState, transition: *const Transition) error{ComponentFailed}!void,
    };
};

/// The facts of a switch beyond the committee.
pub const Transition = struct {
    /// Epoch duration of the new epoch's system parameters.
    epoch_duration_ms: u64,
    safe_mode: bool,
    /// The previous epoch (0 for the first start).
    from_epoch: u64,
};

pub const SystemStateInfo = struct { info: reconfig.EpochInfo, transition: Transition };

// ------------------------------------------------------------------ the epoch the validator reached

/// `<db>/validator/current-epoch`: the epoch description of the last epoch this validator started,
/// written atomically before the epoch's components start. A restart resumes from it where the
/// committee does not come from the node store's system state (local test committees), so a
/// validator that switched epochs does not reopen epoch 0.
pub fn persistedPath(buf: []u8, db_dir: []const u8) error{Io}![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/validator/current-epoch", .{db_dir}) catch error.Io;
}

const persist_magic = "ZEP1";

fn encodePersisted(gpa: std.mem.Allocator, info: reconfig.EpochInfo, t: Transition) error{OutOfMemory}![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, persist_magic);
    inline for (.{ info.epoch, info.protocol_version, info.epoch_start_timestamp_ms, t.from_epoch, t.epoch_duration_ms }) |v| {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try out.appendSlice(gpa, &b);
    }
    try out.appendSlice(gpa, &info.chain_id);
    try out.append(gpa, @intFromBool(t.safe_mode));
    var n: [4]u8 = undefined;
    std.mem.writeInt(u32, &n, @intCast(info.committee.len), .little);
    try out.appendSlice(gpa, &n);
    for (info.committee) |m| {
        try out.appendSlice(gpa, &m.name);
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, m.stake, .little);
        try out.appendSlice(gpa, &b);
    }
    return out.toOwnedSlice(gpa);
}

/// The persisted epoch, or null when there is none, it is for another chain, or it is damaged
/// (the caller then starts from its own description). The committee is allocated in `arena`.
pub fn loadPersisted(arena: std.mem.Allocator, io: std.Io, db_dir: []const u8, own_name: ?[96]u8, chain_id: [8]u8) ?SystemStateInfo {
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const path = persistedPath(&pb, db_dir) catch return null;
    const data = (fsutil.readAll(arena, io, path, 1 << 24) catch return null) orelse return null;
    const fixed = 4 + 5 * 8 + 8 + 1 + 4;
    if (data.len < fixed or !std.mem.eql(u8, data[0..4], persist_magic)) return null;
    var at: usize = 4;
    var v: [5]u64 = undefined;
    for (&v) |*x| {
        x.* = std.mem.readInt(u64, data[at..][0..8], .little);
        at += 8;
    }
    if (!std.mem.eql(u8, data[at..][0..8], &chain_id)) return null;
    at += 8;
    const safe = data[at] != 0;
    at += 1;
    const n = std.mem.readInt(u32, data[at..][0..4], .little);
    at += 4;
    if (n == 0 or data.len != fixed + @as(usize, n) * 104) return null;
    const members = arena.alloc(reconfig.CommitteeMember, n) catch return null;
    var own: ?u32 = null;
    for (members, 0..) |*m, i| {
        m.name = data[at..][0..96].*;
        m.stake = std.mem.readInt(u64, data[at + 96 ..][0..8], .little);
        at += 104;
        if (own_name) |o| {
            if (std.mem.eql(u8, &o, &m.name)) own = @intCast(i);
        }
    }
    return .{
        .info = .{ .epoch = v[0], .protocol_version = v[1], .chain_id = chain_id, .epoch_start_timestamp_ms = v[2], .committee = members, .own_index = own },
        .transition = .{ .epoch_duration_ms = v[4], .safe_mode = safe, .from_epoch = v[3] },
    };
}

/// `EpochInfo` of the epoch a system state describes (committee sorted by protocol key bytes, which
/// is consensus AuthorityIndex order). `arena` holds the committee.
pub fn infoFromState(arena: std.mem.Allocator, own_name: ?[96]u8, chain_id: [8]u8, st: sysstate.State) Error!SystemStateInfo {
    const sum = sysstate.summary(st) catch return error.BadSystemState;
    const params = sysstate.epochParams(st) catch return error.BadSystemState;
    const members = sysstate.committee(arena, st) catch return error.BadSystemState;
    const out = try arena.alloc(reconfig.CommitteeMember, members.len);
    var own: ?u32 = null;
    for (members, out, 0..) |mem, *o, i| {
        if (mem.key.len != 96) return error.BadCommittee;
        o.* = .{ .name = mem.key[0..96].*, .stake = mem.weight };
        if (own_name) |n| {
            if (std.mem.eql(u8, &n, &o.name)) own = @intCast(i);
        }
    }
    return .{
        .info = .{
            .epoch = sum.epoch,
            .protocol_version = sum.protocol_version,
            .chain_id = chain_id,
            .epoch_start_timestamp_ms = sum.epoch_start_timestamp_ms,
            .committee = out,
            .own_index = own,
        },
        .transition = .{ .epoch_duration_ms = params.epoch_duration_ms, .safe_mode = params.safe_mode, .from_epoch = if (sum.epoch > 0) sum.epoch - 1 else 0 },
    };
}

pub const EpochManager = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    db_dir: []const u8,
    own_name: ?[96]u8,
    chain_id: [8]u8,
    components: Components,
    current: ?*reconfig.EpochState = null,
    last: Transition = .{ .epoch_duration_ms = 0, .safe_mode = false, .from_epoch = 0 },
    switches: u64 = 0,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, db_dir: []const u8, own_name: ?[96]u8, chain_id: [8]u8, components: Components) EpochManager {
        return .{ .gpa = gpa, .io = io, .db_dir = db_dir, .own_name = own_name, .chain_id = chain_id, .components = components };
    }

    pub fn deinit(m: *EpochManager) void {
        if (m.current) |c| {
            m.components.vtable.stop(m.components.ctx, c.info.epoch);
            c.close();
            m.current = null;
        }
    }

    /// `EpochInfo` of the epoch a system state describes. `arena` holds the committee.
    pub fn infoFromSystemState(m: *const EpochManager, arena: std.mem.Allocator, st: sysstate.State) Error!SystemStateInfo {
        return infoFromState(arena, m.own_name, m.chain_id, st);
    }

    /// Opens `info`'s epoch store and starts the components. Used at process start (recovering the
    /// epoch the node's store is in).
    pub fn start(m: *EpochManager, info: reconfig.EpochInfo, t: Transition) Error!void {
        std.debug.assert(m.current == null);
        const st = reconfig.EpochState.open(m.gpa, m.io, m.db_dir, info) catch |e| return mapOpen(e);
        errdefer st.close();
        m.persist(info, t) catch return error.Io;
        m.components.vtable.start(m.components.ctx, st, &t) catch return error.ComponentFailed;
        m.current = st;
        m.last = t;
    }

    fn persist(m: *EpochManager, info: reconfig.EpochInfo, t: Transition) !void {
        const bytes = try encodePersisted(m.gpa, info, t);
        defer m.gpa.free(bytes);
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        const path = try persistedPath(&pb, m.db_dir);
        if (std.fs.path.dirname(path)) |d| try fsutil.makePath(m.io, d);
        try fsutil.writeAtomic(m.io, path, bytes);
    }

    /// Switches to `info`, which must be the next epoch.
    pub fn switchEpoch(m: *EpochManager, info: reconfig.EpochInfo, t: Transition) Error!void {
        const cur = m.current orelse return error.EpochOrder;
        if (info.epoch != cur.info.epoch + 1) return error.EpochOrder;
        const old_epoch = cur.info.epoch;
        // nothing may reach the closing epoch through `current` while it is torn down
        m.current = null;
        m.components.vtable.stop(m.components.ctx, old_epoch);
        cur.close();
        m.start(info, .{ .epoch_duration_ms = t.epoch_duration_ms, .safe_mode = t.safe_mode, .from_epoch = old_epoch }) catch |e| return e;
        m.switches += 1;
    }

    fn mapOpen(e: reconfig.Error) Error {
        return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.BadCommittee, error.BadCapabilities => error.BadCommittee,
            error.BatchTooLarge => error.BatchTooLarge,
            error.Io => error.Io,
        };
    }
};

// ------------------------------------------------------------------ tests

const TestComponents = struct {
    started: std.ArrayList(u64) = .empty,
    stopped: std.ArrayList(u64) = .empty,
    fail_start: bool = false,

    fn stop(ctx: *anyopaque, epoch: u64) void {
        const s: *TestComponents = @ptrCast(@alignCast(ctx));
        s.stopped.append(std.testing.allocator, epoch) catch {};
    }
    fn startFn(ctx: *anyopaque, st: *reconfig.EpochState, _: *const Transition) error{ComponentFailed}!void {
        const s: *TestComponents = @ptrCast(@alignCast(ctx));
        if (s.fail_start) return error.ComponentFailed;
        s.started.append(std.testing.allocator, st.info.epoch) catch return error.ComponentFailed;
    }
    const vt: Components.VTable = .{ .stop = stop, .start = startFn };
};

fn testInfo(epoch: u64, members: []reconfig.CommitteeMember) reconfig.EpochInfo {
    for (members, 0..) |*m, i| {
        m.* = .{ .name = @splat(@intCast(i + 1)), .stake = 2500 };
    }
    return .{ .epoch = epoch, .protocol_version = 141, .chain_id = "0badc0de".*, .epoch_start_timestamp_ms = epoch * 1000, .committee = members, .own_index = 0 };
}

test "switch epoch stops the old components, opens the next store and starts again" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pb[0..try tmp.dir.realPath(std.testing.io, &pb)];
    var tc: TestComponents = .{};
    defer tc.started.deinit(std.testing.allocator);
    defer tc.stopped.deinit(std.testing.allocator);
    var m = EpochManager.init(std.testing.allocator, std.testing.io, dir, null, "0badc0de".*, .{ .ctx = &tc, .vtable = &TestComponents.vt });
    var ms: [4]reconfig.CommitteeMember = undefined;
    try m.start(testInfo(5, &ms), .{ .epoch_duration_ms = 1000, .safe_mode = false, .from_epoch = 4 });
    try m.switchEpoch(testInfo(6, &ms), .{ .epoch_duration_ms = 1000, .safe_mode = false, .from_epoch = 5 });
    try std.testing.expectEqualSlices(u64, &.{ 5, 6 }, tc.started.items);
    try std.testing.expectEqualSlices(u64, &.{5}, tc.stopped.items);
    // epochs may not skip or repeat
    try std.testing.expectError(error.EpochOrder, m.switchEpoch(testInfo(8, &ms), .{ .epoch_duration_ms = 1, .safe_mode = false, .from_epoch = 6 }));
    try std.testing.expectEqual(@as(u64, 1), m.switches);
    m.deinit();
    try std.testing.expectEqualSlices(u64, &.{ 5, 6 }, tc.stopped.items);
}

test "a component start failure leaves nothing running" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pb[0..try tmp.dir.realPath(std.testing.io, &pb)];
    var tc: TestComponents = .{};
    defer tc.started.deinit(std.testing.allocator);
    defer tc.stopped.deinit(std.testing.allocator);
    var m = EpochManager.init(std.testing.allocator, std.testing.io, dir, null, "0badc0de".*, .{ .ctx = &tc, .vtable = &TestComponents.vt });
    var ms: [4]reconfig.CommitteeMember = undefined;
    try m.start(testInfo(1, &ms), .{ .epoch_duration_ms = 1, .safe_mode = false, .from_epoch = 0 });
    tc.fail_start = true;
    try std.testing.expectError(error.ComponentFailed, m.switchEpoch(testInfo(2, &ms), .{ .epoch_duration_ms = 1, .safe_mode = false, .from_epoch = 1 }));
    try std.testing.expect(m.current == null);
    m.deinit();
}

test "the epoch reached is persisted and a restart resumes from it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pb[0..try tmp.dir.realPath(std.testing.io, &pb)];
    var tc: TestComponents = .{};
    defer tc.started.deinit(std.testing.allocator);
    defer tc.stopped.deinit(std.testing.allocator);
    var m = EpochManager.init(std.testing.allocator, std.testing.io, dir, null, "0badc0de".*, .{ .ctx = &tc, .vtable = &TestComponents.vt });
    var ms: [4]reconfig.CommitteeMember = undefined;
    try m.start(testInfo(5, &ms), .{ .epoch_duration_ms = 1000, .safe_mode = false, .from_epoch = 4 });
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const first = loadPersisted(arena, std.testing.io, dir, null, "0badc0de".*).?;
    try std.testing.expectEqual(@as(u64, 5), first.info.epoch);
    try m.switchEpoch(testInfo(6, &ms), .{ .epoch_duration_ms = 2500, .safe_mode = true, .from_epoch = 5 });
    m.deinit();
    const back = loadPersisted(arena, std.testing.io, dir, ms[2].name, "0badc0de".*).?;
    try std.testing.expectEqual(@as(u64, 6), back.info.epoch);
    try std.testing.expectEqual(@as(usize, 4), back.info.committee.len);
    try std.testing.expectEqual(@as(?u32, 2), back.info.own_index);
    try std.testing.expectEqual(@as(u64, 2500), back.transition.epoch_duration_ms);
    try std.testing.expect(back.transition.safe_mode);
    // another chain's file is not ours
    try std.testing.expect(loadPersisted(arena, std.testing.io, dir, null, "deadbeef".*) == null);
}
