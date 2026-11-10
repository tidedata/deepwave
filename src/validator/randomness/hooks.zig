//! `iface.RandomnessHooks` over the `Manager`: what the consensus handler (val-authority) calls
//! for RandomnessDkgMessage, RandomnessDkgConfirmation and the per-commit round reservation.
//! The adapter holds the `Batch` of the commit being handled; the handler brackets each commit:
//!
//!   adapter.beginCommit(round, timestamp_ms)
//!   ... hooks.dkg_message / dkg_confirmation for each sequenced transaction ...
//!   try adapter.advanceIfNeeded()           // merge / complete / timeout, submits the confirmation
//!   const round = hooks.reserve_next_round(ts)
//!   var batch = adapter.takeBatch()         // write it atomically with the rest of the commit
//!
//! Through the vtable the handler calls `begin_commit` before `dkg_failed` / `reserve_next_round`
//! (Rust's init_randomness runs before the commit's DKG transactions) and `advance_dkg` after the
//! commit's DKG transactions; the adapter applies Rust's condition for running advance_dkg.
const std = @import("std");
const iface = @import("../iface.zig");
const manager = @import("manager.zig");
const dkg = @import("dkg.zig");
const txs = @import("txs.zig");
const log = std.log.scoped(.randomness);

pub const Adapter = struct {
    gpa: std.mem.Allocator,
    mgr: *manager.Manager,
    batch: manager.Batch,
    commit_round: u32 = 0,
    commit_timestamp_ms: u64 = 0,
    /// A DKG message or confirmation of this commit decoded (Rust's `randomness_state_updated`).
    dkg_updates: bool = false,
    submit: ?iface.ConsensusSubmit,
    own_name: [96]u8,

    pub fn init(gpa: std.mem.Allocator, mgr: *manager.Manager, submit: ?iface.ConsensusSubmit, own_name: [96]u8) Adapter {
        return .{ .gpa = gpa, .mgr = mgr, .batch = manager.Batch.init(gpa), .submit = submit, .own_name = own_name };
    }

    pub fn deinit(a: *Adapter) void {
        a.batch.deinit();
    }

    pub fn hooks(a: *Adapter) iface.RandomnessHooks {
        return .{ .ctx = a, .vtable = &vtable };
    }

    pub fn beginCommit(a: *Adapter, consensus_round: u32, timestamp_ms: u64) void {
        a.commit_round = consensus_round;
        a.commit_timestamp_ms = timestamp_ms;
        a.dkg_updates = false;
    }

    /// `process_dkg_updates`' tail: `advance_dkg` only when this commit had DKG updates or Rust's
    /// always-advance rule holds (`Manager.shouldAdvance`).
    pub fn advanceIfNeeded(a: *Adapter) !void {
        if (!a.mgr.shouldAdvance(a.dkg_updates)) return;
        try a.advance();
    }

    /// `advance_dkg`: after all transactions of the commit were fed in. Submits this party's
    /// confirmation through consensus when the merge just produced one.
    pub fn advance(a: *Adapter) !void {
        var adv = try a.mgr.advanceDkg(&a.batch, a.commit_round);
        defer adv.deinit(a.gpa);
        if (adv.confirmation_to_submit) |conf| try a.submitBytes(conf, .confirmation);
    }

    /// `start_dkg` at epoch start: submits the DKG message (or the persisted confirmation).
    pub fn start(a: *Adapter) !void {
        const bytes = (try a.mgr.startDkg()) orelse return;
        defer a.gpa.free(bytes);
        const kind: enum { message, confirmation } = if (a.mgr.used != null) .confirmation else .message;
        try a.submitBytes(bytes, if (kind == .message) .message else .confirmation);
    }

    const Kind = enum { message, confirmation };

    fn submitBytes(a: *Adapter, versioned: []const u8, kind: Kind) !void {
        const submit = a.submit orelse return;
        const tx = switch (kind) {
            .message => try txs.dkgMessageTx(a.gpa, &a.own_name, versioned),
            .confirmation => try txs.dkgConfirmationTx(a.gpa, &a.own_name, versioned),
        };
        defer a.gpa.free(tx);
        try submit.submit(&.{tx}, .system);
    }

    /// The commit's records, to be written with the commit; the adapter starts a fresh batch.
    pub fn takeBatch(a: *Adapter) manager.Batch {
        const b = a.batch;
        a.batch = manager.Batch.init(a.gpa);
        return b;
    }

    fn fromCtx(ctx: *anyopaque) *Adapter {
        return @ptrCast(@alignCast(ctx));
    }

    fn dkgMessage(ctx: *anyopaque, from: *const iface.AuthorityName, versioned: []const u8) void {
        const a = fromCtx(ctx);
        a.mgr.addMessage(&from.@"0", versioned) catch |e| {
            log.debug("ignoring DKG message: {s}", .{@errorName(e)});
            if (e == error.Malformed or e == error.OutOfMemory) return;
        };
        a.dkg_updates = true;
    }

    fn dkgConfirmation(ctx: *anyopaque, from: *const iface.AuthorityName, versioned: []const u8) void {
        const a = fromCtx(ctx);
        a.mgr.addConfirmation(&a.batch, &from.@"0", versioned) catch |e| {
            log.debug("ignoring DKG confirmation: {s}", .{@errorName(e)});
            if (e == error.Malformed or e == error.OutOfMemory) return;
        };
        a.dkg_updates = true;
    }

    fn reserveNextRound(ctx: *anyopaque, commit_timestamp_ms: u64) ?u64 {
        const a = fromCtx(ctx);
        return a.mgr.reserveNextRandomness(&a.batch, commit_timestamp_ms);
    }

    fn dkgFailed(ctx: *anyopaque) bool {
        const a = fromCtx(ctx);
        return a.mgr.dkgStatusForCommitRound(a.commit_round) == .timed_out;
    }

    fn beginCommitHook(ctx: *anyopaque, round: u64, timestamp_ms: u64) void {
        fromCtx(ctx).beginCommit(@intCast(@min(round, std.math.maxInt(u32))), timestamp_ms);
    }

    fn advanceHook(ctx: *anyopaque) void {
        // Rust panics when advance_dkg fails ("failed to advance randomness DKG")
        fromCtx(ctx).advanceIfNeeded() catch |e| std.debug.panic("failed to advance randomness DKG: {s}", .{@errorName(e)});
    }

    const vtable: iface.RandomnessHooks.VTable = .{
        .dkg_message = dkgMessage,
        .dkg_confirmation = dkgConfirmation,
        .reserve_next_round = reserveNextRound,
        .dkg_failed = dkgFailed,
        .begin_commit = beginCommitHook,
        .advance_dkg = advanceHook,
    };
};

const group = @import("group.zig");

fn testMembers(rng: std.Random, secrets: *[4][32]u8, members: *[4]manager.Member) void {
    for (0..4) |i| {
        const s = group.scalarRand(rng);
        secrets[i] = group.scalarToBytes(s);
        members[i] = .{ .name = group.g2ToBytes(group.mulPublic(group.G2, group.g2Generator(), s)), .stake = 2500 };
    }
}

test "hooks: dkg status is read before the commit's advance, and advance follows Rust's condition" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(11);
    const rng = prng.random();
    var secrets: [4][32]u8 = undefined;
    var members: [4]manager.Member = undefined;
    testMembers(rng, &secrets, &members);

    // mainnet 141: no late completion, always advance while pending
    {
        const params: manager.Params = .{ .epoch = 1, .chain_id = @splat(1), .members = &members, .protocol = .{ .random_beacon_reduction_lower_bound = 8 } };
        const m = try manager.Manager.createForTesting(gpa, params, &secrets[0], rng);
        defer m.destroy();
        var ad = Adapter.init(gpa, m, null, members[0].name);
        defer ad.deinit();
        const h = ad.hooks();
        // commit 3001: init_randomness sees Pending, then advance_dkg fails the DKG
        h.vtable.begin_commit.?(h.ctx, 3001, 0);
        try std.testing.expect(!h.vtable.dkg_failed(h.ctx));
        h.vtable.advance_dkg.?(h.ctx);
        try std.testing.expectEqual(manager.DkgStatus.timed_out, m.dkgStatus());
        var b = ad.takeBatch();
        defer b.deinit();
        try std.testing.expect(b.dkg_output != null and b.dkg_output.? == .failed);
        // commit 3002: randomness transactions are cancelled
        h.vtable.begin_commit.?(h.ctx, 3002, 0);
        try std.testing.expect(h.vtable.dkg_failed(h.ctx));
    }
    // testnet 141: late completion allowed; no advance without DKG updates, status reads TimedOut
    // past the timeout round while the DKG stays open
    {
        const params: manager.Params = .{ .epoch = 1, .chain_id = @splat(1), .members = &members, .protocol = .{ .random_beacon_reduction_lower_bound = 8, .allow_dkg_completion_after_timeout = true } };
        const m = try manager.Manager.createForTesting(gpa, params, &secrets[0], rng);
        defer m.destroy();
        var ad = Adapter.init(gpa, m, null, members[0].name);
        defer ad.deinit();
        const h = ad.hooks();
        h.vtable.begin_commit.?(h.ctx, 5, 0);
        try std.testing.expect(!m.shouldAdvance(ad.dkg_updates));
        // undecodable bytes are not an update; a decodable (V0) message is
        const from: iface.AuthorityName = .{ .@"0" = members[1].name };
        h.vtable.dkg_message(h.ctx, &from, &.{ 7, 7 });
        try std.testing.expect(!ad.dkg_updates);
        h.vtable.dkg_message(h.ctx, &from, &.{0});
        try std.testing.expect(ad.dkg_updates);
        h.vtable.advance_dkg.?(h.ctx);
        h.vtable.begin_commit.?(h.ctx, 3001, 0);
        try std.testing.expect(!ad.dkg_updates);
        try std.testing.expect(h.vtable.dkg_failed(h.ctx));
        try std.testing.expectEqual(manager.DkgStatus.pending, m.dkgStatus());
    }
}
