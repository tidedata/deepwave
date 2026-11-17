//! Signing-time inputs and signatures as sui-core 1.83.1 reads them (PARITY G11, G12, G13):
//! shared inputs whose consensus stream ended this epoch, receiving objects already received at
//! that version, address aliases from the live AddressAliases object, and the vote's
//! executed-transaction hooks.
const std = @import("std");
const types = @import("types");
const rpc_exec = @import("rpc_exec");
const consensus = @import("consensus");
const env_mod = @import("env.zig");
const checker = @import("checker.zig");
const tx_mod = @import("tx.zig");
const tx_validator = @import("tx_validator.zig");
const fixture = @import("preverify_fixture.zig");

const Fixture = fixture.Fixture;
const Signer = fixture.Signer;
const Id = [32]u8;
const usersig = rpc_exec.live.usersig;

fn userTx(a: std.mem.Allocator, m: fixture.Made) !tx_mod.UserTx {
    // ConsensusTransaction: tracking id (8), kind tag (1), PlainTransactionWithClaims
    return tx_mod.parse(a, m.block_tx[9..]);
}

const MarkerSet = struct {
    epoch: u64 = 1,
    received: ?struct { Id, u64 } = null,
    ended: ?struct { Id, u64 } = null,

    fn markers(s: *MarkerSet) checker.Markers {
        return .{ .ctx = s, .received = rec, .stream_ended = end };
    }
    fn rec(ctx: *anyopaque, epoch: u64, id: *const Id, version: u64) bool {
        const s: *MarkerSet = @ptrCast(@alignCast(ctx));
        const r = s.received orelse return false;
        return epoch == s.epoch and std.mem.eql(u8, id, &r[0]) and version == r[1];
    }
    fn end(ctx: *anyopaque, epoch: u64, id: *const Id, start: u64) bool {
        const s: *MarkerSet = @ptrCast(@alignCast(ctx));
        const r = s.ended orelse return false;
        return epoch == s.epoch and std.mem.eql(u8, id, &r[0]) and start == r[1];
    }
};

fn expectFail(f: ?@import("rpc_exec").checks.Fail, needle: []const u8) !void {
    const x = f orelse return error.TestExpectedFailure;
    if (std.mem.indexOf(u8, x.message, needle) == null) {
        std.debug.print("message: {s}\n", .{x.message});
        return error.TestUnexpectedMessage;
    }
}

fn idOf(b: u8) Id {
    return @splat(b);
}

test "G12: a shared input whose consensus stream ended this epoch is accepted at signing" {
    const gpa = std.testing.allocator;
    const f = try Fixture.create(gpa);
    defer f.destroy();
    const a = f.arena();
    const sid = idOf(0x5a);
    const shared: types.CallArg = .{ .Object = .{ .SharedObject = .{ .id = .{ .@"0" = .{ .@"0" = sid } }, .initial_shared_version = .{ .@"0" = 3 }, .mutability = .Mutable } } };
    const m = try f.makeTx(.{ .signer = Signer.edSeed(1), .coin = 1, .extra_inputs = &.{shared} });
    const u = try userTx(a, m);

    // no object, no marker: the object is not found
    try expectFail(try checker.checkInputs(a, &f.env, &u, .{}), "Could not find the referenced object");
    // a marker for another start version or another epoch does not count
    var ms: MarkerSet = .{ .ended = .{ sid, 4 } };
    f.env.markers = ms.markers();
    try expectFail(try checker.checkInputs(a, &f.env, &u, .{}), "Could not find the referenced object");
    ms = .{ .ended = .{ sid, 3 }, .epoch = 0 };
    try expectFail(try checker.checkInputs(a, &f.env, &u, .{}), "Could not find the referenced object");
    // ObjectConsensusStreamEnded at (id, 3) this epoch: check_objects skips it
    ms = .{ .ended = .{ sid, 3 } };
    try std.testing.expect(try checker.checkInputs(a, &f.env, &u, .{}) == null);

    // the stream was re-started (now shared at a later version): the live object does not
    // match the claimed start, the marker still does
    var contents: [40]u8 = undefined;
    contents[0..32].* = sid;
    @memset(contents[32..], 0);
    try f.map.put(gpa, sid, 9, try fixture.moveObject(a, &contents, 9, .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 8 } } }));
    try std.testing.expect(try checker.checkInputs(a, &f.env, &u, .{}) == null);
    f.env.markers = null;
    try expectFail(try checker.checkInputs(a, &f.env, &u, .{}), "Could not find the referenced object");
}

test "G12: a receiving object already received at that version is skipped at signing" {
    const gpa = std.testing.allocator;
    const f = try Fixture.create(gpa);
    defer f.destroy();
    const a = f.arena();
    const rid = idOf(0x6b);
    const recv: types.CallArg = .{ .Object = .{ .Receiving = .{ .{ .@"0" = .{ .@"0" = rid } }, .{ .@"0" = 4 }, .{ .@"0" = .{ .@"0" = @splat(1) } } } } };
    const m = try f.makeTx(.{ .signer = Signer.edSeed(2), .coin = 2, .extra_inputs = &.{recv} });
    const u = try userTx(a, m);

    try expectFail(try checker.checkInputs(a, &f.env, &u, .{}), "Some(SequenceNumber(4))");
    var ms: MarkerSet = .{ .received = .{ rid, 5 } };
    f.env.markers = ms.markers();
    try expectFail(try checker.checkInputs(a, &f.env, &u, .{}), "Some(SequenceNumber(4))");
    // PreviouslyReceivedObject at (id, 4) this epoch
    ms = .{ .received = .{ rid, 4 } };
    try std.testing.expect(try checker.checkInputs(a, &f.env, &u, .{}) == null);
}

/// AddressAliases `{ id: UID, aliases: VecSet<address> }` of `owner` at `version`.
fn putAliases(f: *Fixture, owner: Id, version: u64, aliases: []const Id) !void {
    const a = f.arena();
    const oid = usersig.aliasesObjectId(&owner);
    const contents = try a.alloc(u8, 33 + 32 * aliases.len);
    contents[0..32].* = oid;
    contents[32] = @intCast(aliases.len);
    for (aliases, 0..) |al, i| contents[33 + 32 * i ..][0..32].* = al;
    try f.map.put(f.gpa, oid, version, try fixture.moveObject(a, contents, version, .{ .ObjectOwner = .{ .@"0" = @splat(0xa) } }));
}

test "G11: signatures verify under the signer's current AddressAliases, its version in the claim" {
    const gpa = std.testing.allocator;
    const f = try Fixture.create(gpa);
    defer f.destroy();
    try std.testing.expect(f.cfg.feature_flags.address_aliases);
    const a = f.arena();
    const s1 = Signer.edSeed(11);
    const s2 = Signer.edSeed(12);

    // no AddressAliases object: the signer is its own alias, version None
    {
        const m = try f.makeTx(.{ .signer = s1, .coin = 11 });
        const u = try userTx(a, m);
        const r = try checker.verifySignatures(a, &f.env, &u, &.{});
        try std.testing.expect(r == .ok);
        try std.testing.expectEqual(@as(?u64, null), r.ok[0].alias_version);
        try std.testing.expect(checker.aliasClaimMatches(&u, r.ok));
    }
    // s2's key may sign for s1 once s1's aliases name it; the claim carries version 7
    try putAliases(f, s1.address(), 7, &.{ s1.address(), s2.address() });
    {
        const m = try f.makeTx(.{ .signer = s1, .sign_with = s2, .coin = 12, .alias_version = 7 });
        const u = try userTx(a, m);
        const r = try checker.verifySignatures(a, &f.env, &u, &.{});
        try std.testing.expect(r == .ok);
        try std.testing.expectEqual(@as(?u64, 7), r.ok[0].alias_version);
        try std.testing.expect(checker.aliasClaimMatches(&u, r.ok));
        // a claim of version None no longer matches ("Address aliases have changed")
        const stale = try f.makeTx(.{ .signer = s1, .sign_with = s2, .coin = 13 });
        const us = try userTx(a, stale);
        const rs = try checker.verifySignatures(a, &f.env, &us, &.{});
        try std.testing.expect(rs == .ok);
        try std.testing.expect(!checker.aliasClaimMatches(&us, rs.ok));
    }
    // aliases without the signer itself: the signer's own key no longer verifies
    try putAliases(f, s1.address(), 8, &.{s2.address()});
    {
        const m = try f.makeTx(.{ .signer = s1, .coin = 14, .alias_version = 8 });
        const u = try userTx(a, m);
        const r = try checker.verifySignatures(a, &f.env, &u, &.{});
        try std.testing.expect(r == .fail);
    }
    // an empty alias set falls back to the signer
    try putAliases(f, s1.address(), 9, &.{});
    {
        const m = try f.makeTx(.{ .signer = s1, .coin = 15, .alias_version = 9 });
        const u = try userTx(a, m);
        const r = try checker.verifySignatures(a, &f.env, &u, &.{});
        try std.testing.expect(r == .ok);
        try std.testing.expectEqual(@as(?u64, 9), r.ok[0].alias_version);
    }
}

const VoteHooks = struct {
    recent: bool = false,
    last_epoch: bool = false,

    fn hooks(h: *VoteHooks) tx_validator.Hooks {
        return .{ .ctx = h, .recently_executed = recentFn, .executed_last_epoch = lastFn };
    }
    fn recentFn(ctx: *anyopaque, _: *const Id) bool {
        return @as(*VoteHooks, @ptrCast(@alignCast(ctx))).recent;
    }
    fn lastFn(ctx: *anyopaque, _: *const Id) bool {
        return @as(*VoteHooks, @ptrCast(@alignCast(ctx))).last_epoch;
    }
};

test "G13: the vote accepts recently executed transactions and rejects last epoch's" {
    const gpa = std.testing.allocator;
    const f = try Fixture.create(gpa);
    defer f.destroy();
    const a = f.arena();
    // the gas coin is gone (consumed by the execution): input checks alone would reject
    const m = try f.makeTx(.{ .signer = Signer.edSeed(21), .coin = 21, .put_coin = false });
    const u = try userTx(a, m);
    var ctl = try env_mod.LocalEpochControl.init(gpa, &f.stakes);
    defer ctl.deinit();
    var reasons: tx_validator.ReasonCache = .{ .gpa = gpa };
    defer reasons.deinit();
    var v = tx_validator.TxValidator.init(gpa, f.params, f.cfg, &f.env, ctl.control(), &reasons);
    defer v.deinit();
    var h: VoteHooks = .{};
    v.hooks = h.hooks();
    var out: [4]consensus.types.TransactionIndex = undefined;
    const ref: consensus.types.BlockRef = .{ .round = 1, .author = 0, .digest = @splat(0) };
    const blk = try f.block(&.{m.block_tx});

    try std.testing.expectEqual(@as(usize, 1), try v.verifyAndVote(ref, blk, &out));
    // executed in this epoch or recently finalized: accepted without the input checks
    h.recent = true;
    try std.testing.expectEqual(@as(usize, 0), try v.verifyAndVote(ref, blk, &out));
    // the recent check wins over the last-epoch check, as in handle_vote_transaction
    h.last_epoch = true;
    try std.testing.expectEqual(@as(usize, 0), try v.verifyAndVote(ref, blk, &out));
    // executed in the previous epoch: TransactionAlreadyExecuted
    h.recent = false;
    const ref2: consensus.types.BlockRef = .{ .round = 2, .author = 0, .digest = @splat(0) };
    try std.testing.expectEqual(@as(usize, 1), try v.verifyAndVote(ref2, blk, &out));
    const why = reasons.get(a, .{ .round = 2, .author = 0, .digest = @splat(0), .index = 0 }) orelse return error.NoReason;
    const want = try std.fmt.allocPrint(a, "Attempt to move to `Executed` state an transaction that has already been executed: TransactionDigest({s}).", .{try rpc_exec.checks.b58(a, &u.digest)});
    try std.testing.expectEqualStrings(want, why);
}

test "G11: checkpoint user signatures follow the alias claim (fix_checkpoint_signature_mapping)" {
    const handler = @import("handler.zig");
    const gpa = std.testing.allocator;
    const f = try Fixture.create(gpa);
    defer f.destroy();
    const a = f.arena();
    try std.testing.expect(f.params.fix_checkpoint_signature_mapping);
    // two signatures, one required signer: the claim names signature 0 at alias version 7
    const m = try f.makeTx(.{ .signer = Signer.edSeed(31), .coin = 31, .alias_version = 7, .extra_sig = true });
    const u = try userTx(a, m);
    try std.testing.expectEqual(@as(usize, 2), u.signatures().len);
    const s = try handler.checkpointSigs(a, true, &u);
    try std.testing.expectEqual(@as(usize, 1), s.sigs.len);
    try std.testing.expectEqualSlices(u8, u.signatures()[0].@"0", s.sigs[0]);
    try std.testing.expectEqual(@as(?u64, 7), s.alias_versions[0]);
    // without the flag: every signature, versions zipped in order
    const old = try handler.checkpointSigs(a, false, &u);
    try std.testing.expectEqual(@as(usize, 2), old.sigs.len);
    try std.testing.expectEqual(@as(usize, 1), old.alias_versions.len);
}
