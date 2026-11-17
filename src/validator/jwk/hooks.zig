//! `iface.JwkHooks` over the `Aggregator`: what the consensus handler (val-authority) calls for
//! each sequenced NewJWKFetched. The handler has already checked that the transaction's authority
//! equals the block author and `check_total_jwk_size` (`SequencedConsensusTransaction` checks); `vote`
//! applies `record_jwk_vote` and tells the handler whether the JWK just became active (it then
//! schedules the AuthenticatorStateUpdate one commit later via `state_update.forCommit`).
//! The adapter holds the commit's `Batch`; `takeBatch` hands it to the epoch store.
const std = @import("std");
const types = @import("types");
const iface = @import("../iface.zig");
const aggregator = @import("aggregator.zig");
const log = std.log.scoped(.jwk);

pub const Adapter = struct {
    gpa: std.mem.Allocator,
    agg: *aggregator.Aggregator,
    batch: aggregator.Batch,
    /// `jwk_aggregator`'s Mutex: the handler thread votes, the updater asks `isActive`.
    lock: @import("../authority/sync.zig").Spin = .{},

    pub fn init(gpa: std.mem.Allocator, agg: *aggregator.Aggregator) Adapter {
        return .{ .gpa = gpa, .agg = agg, .batch = aggregator.Batch.init(gpa) };
    }

    pub fn deinit(a: *Adapter) void {
        a.batch.deinit();
    }

    pub fn hooks(a: *Adapter) iface.JwkHooks {
        return .{ .ctx = a, .vtable = &vtable };
    }

    pub fn takeBatch(a: *Adapter) aggregator.Batch {
        const b = a.batch;
        a.batch = aggregator.Batch.init(a.gpa);
        return b;
    }

    fn vote(ctx: *anyopaque, from: *const iface.AuthorityName, id: *const types.JwkId, jwk: *const types.JWK, round: u64) bool {
        const a: *Adapter = @ptrCast(@alignCast(ctx));
        if (!aggregator.checkTotalJwkSize(id.*, jwk.*)) return false;
        a.lock.lock();
        defer a.lock.unlock();
        const out = a.agg.recordVote(&a.batch, round, &from.@"0", id.*, jwk.*) catch |e| {
            log.err("jwk vote failed: {s}", .{@errorName(e)});
            return false;
        };
        return out == .became_active;
    }

    fn takeRecords(ctx: *anyopaque, arena: std.mem.Allocator) error{OutOfMemory}!?[]const u8 {
        const a: *Adapter = @ptrCast(@alignCast(ctx));
        var b = blk: {
            a.lock.lock();
            defer a.lock.unlock();
            break :blk a.takeBatch();
        };
        defer b.deinit();
        return encodeBatch(arena, &b);
    }

    const vtable: iface.JwkHooks.VTable = .{ .vote = vote, .take_records = takeRecords };

    /// `jwk_active_in_current_epoch` for the updater (any thread).
    pub fn active(a: *Adapter) @import("updater.zig").Active {
        return .{ .ctx = a, .f = isActiveLocked };
    }
    fn isActiveLocked(ctx: *anyopaque, id: types.JwkId, jwk: types.JWK) bool {
        const a: *Adapter = @ptrCast(@alignCast(ctx));
        a.lock.lock();
        defer a.lock.unlock();
        return a.agg.isActive(id, jwk);
    }

    /// `get_new_jwks(round)` for the consensus handler (authority/handler.zig `JwkSource`): the
    /// JWKs that became active at `round`, scheduled as an AuthenticatorStateUpdate one commit later.
    pub fn source(a: *Adapter) JwkSource {
        return .{ .ctx = a, .get = getNew };
    }
    fn getNew(ctx: *anyopaque, arena: std.mem.Allocator, round: u64) []const types.ActiveJwk {
        const a: *Adapter = @ptrCast(@alignCast(ctx));
        a.lock.lock();
        defer a.lock.unlock();
        return a.agg.newJwks(arena, round) catch |e| {
            log.err("get_new_jwks({d}) failed: {s}", .{ round, @errorName(e) });
            return &.{};
        };
    }
};

/// Same shape as `authority/handler.zig` `JwkSource` (kept structural so this lane does not
/// import the authority lane).
pub const JwkSource = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, round: u64) []const types.ActiveJwk,
};

// ------------------------------------------------------------------ durable records

const rec_pending: u8 = 1;
const rec_active: u8 = 2;

/// One commit's aggregator rows (null when none): tag, then u32 LE length and bytes; an active row
/// carries its round (u64 LE) first.
pub fn encodeBatch(arena: std.mem.Allocator, b: *const aggregator.Batch) error{OutOfMemory}!?[]const u8 {
    if (b.pending.items.len == 0 and b.active.items.len == 0) return null;
    var out: std.ArrayList(u8) = .empty;
    var n: [8]u8 = undefined;
    for (b.pending.items) |p| {
        try out.append(arena, rec_pending);
        std.mem.writeInt(u32, n[0..4], @intCast(p.len), .little);
        try out.appendSlice(arena, n[0..4]);
        try out.appendSlice(arena, p);
    }
    for (b.active.items) |x| {
        try out.append(arena, rec_active);
        std.mem.writeInt(u64, &n, x.round, .little);
        try out.appendSlice(arena, &n);
        std.mem.writeInt(u32, n[0..4], @intCast(x.key.len), .little);
        try out.appendSlice(arena, n[0..4]);
        try out.appendSlice(arena, x.key);
    }
    return out.items;
}

/// Replays records written by `encodeBatch` into a fresh aggregator of the same epoch, in order.
pub fn restore(agg: *aggregator.Aggregator, bytes: []const u8) !void {
    var i: usize = 0;
    while (i < bytes.len) {
        const tag = bytes[i];
        i += 1;
        var round: u64 = 0;
        if (tag == rec_active) {
            if (bytes.len - i < 8) return error.Corrupt;
            round = std.mem.readInt(u64, bytes[i..][0..8], .little);
            i += 8;
        } else if (tag != rec_pending) return error.Corrupt;
        if (bytes.len - i < 4) return error.Corrupt;
        const len = std.mem.readInt(u32, bytes[i..][0..4], .little);
        i += 4;
        if (bytes.len - i < len) return error.Corrupt;
        const body = bytes[i..][0..len];
        i += len;
        if (tag == rec_pending) try agg.loadPending(body) else try agg.loadActive(round, body);
    }
}

test "records written per commit restore the aggregator after a restart; source gives the round's new jwks" {
    const gpa = std.testing.allocator;
    var members: [4]aggregator.Member = undefined;
    for (&members, 0..) |*m, i| m.* = .{ .name = @splat(@intCast(i + 1)), .stake = 2500 };
    var agg = try aggregator.Aggregator.init(gpa, .{ .epoch = 2, .members = &members });
    defer agg.deinit();
    var ad = Adapter.init(gpa, &agg);
    defer ad.deinit();
    const id: types.JwkId = .{ .iss = .{ .@"0" = "https://accounts.google.com" }, .kid = .{ .@"0" = "k" } };
    const jwk: types.JWK = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = "n" }, .alg = .{ .@"0" = "RS256" } };
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var log_: std.ArrayList([]const u8) = .empty;
    defer log_.deinit(gpa);
    const hk = ad.hooks();
    // three commits, one vote each; the third activates at round 9
    for (0..3) |i| {
        const from: iface.AuthorityName = .{ .@"0" = members[i].name };
        const active = hk.vtable.vote(hk.ctx, &from, &id, &jwk, 7 + i);
        try std.testing.expectEqual(i == 2, active);
        try log_.append(gpa, (try hk.vtable.take_records.?(hk.ctx, arena.allocator())).?);
    }
    try std.testing.expect((try hk.vtable.take_records.?(hk.ctx, arena.allocator())) == null);
    var fresh = try aggregator.Aggregator.init(gpa, .{ .epoch = 2, .members = &members });
    defer fresh.deinit();
    for (log_.items) |b| try restore(&fresh, b);
    try std.testing.expect(fresh.isActive(id, jwk));
    var ad2 = Adapter.init(gpa, &fresh);
    defer ad2.deinit();
    const src = ad2.source();
    try std.testing.expectEqual(@as(usize, 1), src.get(src.ctx, arena.allocator(), 9).len);
    try std.testing.expectEqual(@as(usize, 0), src.get(src.ctx, arena.allocator(), 8).len);
    try std.testing.expectError(error.Corrupt, restore(&fresh, log_.items[0][0 .. log_.items[0].len - 1]));
}
