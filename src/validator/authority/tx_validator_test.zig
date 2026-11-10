//! Block-level checks of the transaction validator (`verify_batch`): no state, no signatures.
const std = @import("std");
const bcs = @import("bcs");
const protocol = @import("protocol");
const consensus = @import("consensus");
const messages = @import("../messages.zig");
const env_mod = @import("env.zig");
const checker = @import("checker.zig");
const tx_validator = @import("tx_validator.zig");

fn ct(arena: std.mem.Allocator, kind: messages.ConsensusTransactionKind) ![]const u8 {
    const t: messages.ConsensusTransaction = .{ .tracking_id = @splat(0), .kind = kind };
    return bcs.encodeAlloc(messages.ConsensusTransaction, arena, &t);
}

fn name(b: u8) messages.AuthorityName {
    return .{ .@"0" = @splat(b) };
}

const Fixture = struct {
    ctl: env_mod.LocalEpochControl,
    reasons: tx_validator.ReasonCache,
    v: tx_validator.TxValidator,
    stakes: [4]u64 = .{ 2500, 2500, 2500, 2500 },

    fn init(f: *Fixture, gpa: std.mem.Allocator) !void {
        const cfg = try protocol.get(141, .mainnet);
        f.ctl = try env_mod.LocalEpochControl.init(gpa, &f.stakes);
        f.reasons = .{ .gpa = gpa };
        f.v = tx_validator.TxValidator.init(gpa, env_mod.Params.fromProtocol(cfg, 1, 0, 1000), cfg, undefined, f.ctl.control(), &f.reasons);
    }
    fn deinit(f: *Fixture) void {
        f.v.deinit();
        f.reasons.deinit();
        f.ctl.deinit();
    }
    fn batch(arena: std.mem.Allocator, items: []const []const u8) ![]consensus.types.Transaction {
        const out = try arena.alloc(consensus.types.Transaction, items.len);
        for (items, out) |i, *o| o.* = .{ .data = i };
        return out;
    }
};

test "accepts system messages, rejects deprecated kinds and oversized dkg messages" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.init(gpa);
    defer f.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();

    const eop = try ct(a, .{ .EndOfPublish = name(1) });
    try f.v.verifyBatch(try Fixture.batch(a, &.{eop}), null);

    const dkg_ok = try ct(a, .{ .RandomnessDkgMessage = .{ name(1), "small" } });
    try f.v.verifyBatch(try Fixture.batch(a, &.{dkg_ok}), null);

    const big = try a.alloc(u8, tx_validator.dkg_messages_max_size + 1);
    @memset(big, 0);
    const dkg_big = try ct(a, .{ .RandomnessDkgMessage = .{ name(1), big } });
    try std.testing.expectError(error.InvalidTransaction, f.v.verifyBatch(try Fixture.batch(a, &.{dkg_big}), null));
    const conf_big = try ct(a, .{ .RandomnessDkgConfirmation = .{ name(1), big } });
    try std.testing.expectError(error.InvalidTransaction, f.v.verifyBatch(try Fixture.batch(a, &.{conf_big}), null));

    // deprecated: RandomnessStateUpdate
    const rsu = try ct(a, .{ .RandomnessStateUpdate = .{ 1, "x" } });
    try std.testing.expectError(error.InvalidTransaction, f.v.verifyBatch(try Fixture.batch(a, &.{rsu}), null));

    // undecodable bytes reject the block
    try std.testing.expectError(error.InvalidTransaction, f.v.verifyBatch(try Fixture.batch(a, &.{"not bcs"}), null));

    // one bad transaction poisons the whole batch
    try std.testing.expectError(error.InvalidTransaction, f.v.verifyBatch(try Fixture.batch(a, &.{ eop, rsu }), null));
}

test "execution time observations are bounded by the command limit" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.init(gpa);
    defer f.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    const n = f.v.params.max_programmable_tx_commands + 1;
    const est = try a.alloc(@typeInfo(@TypeOf(@as(messages.ExecutionTimeObservation, undefined).estimates)).pointer.child, n);
    for (est) |*e| e.* = .{ .TransferObjects, .{ .secs = 0, .nanos = 1 } };
    const obs = try ct(a, .{ .ExecutionTimeObservation = .{ .authority = name(1), .generation = 1, .estimates = est } });
    try std.testing.expectError(error.InvalidTransaction, f.v.verifyBatch(try Fixture.batch(a, &.{obs}), null));
    try f.v.verifyBatch(try Fixture.batch(a, &.{try ct(a, .{ .ExecutionTimeObservation = .{ .authority = name(1), .generation = 1, .estimates = est[0..3] } })}), null);
}

test "deny config share limits" {
    const gpa = std.testing.allocator;
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    const ids = try a.alloc(@typeInfo(@TypeOf(@as(messages.TransactionDenyRules, undefined).object_deny_list)).pointer.child, tx_validator.deny_max_share_entries + 1);
    for (ids, 0..) |*id, i| {
        var b: [32]u8 = @splat(0);
        std.mem.writeInt(u64, b[0..8], i, .big);
        id.* = .{ .@"0" = .{ .@"0" = b } };
    }
    const rules: messages.TransactionDenyRules = .{
        .object_deny_list = ids,
        .package_deny_list = &.{},
        .address_deny_list = &.{},
        .package_publish_disabled = false,
        .package_upgrade_disabled = false,
        .shared_object_disabled = false,
        .user_transaction_disabled = false,
        .gasless_disabled = false,
        .receiving_objects_disabled = false,
        .zklogin_sig_disabled = false,
        .zklogin_disabled_providers = &.{},
    };
    try std.testing.expect(!tx_validator.denyShareLimitsOk(a, &rules));
    var small = rules;
    small.object_deny_list = ids[0..10];
    try std.testing.expect(tx_validator.denyShareLimitsOk(a, &small));
}

/// The Rust `user_v2` vector (sui-types 1.83.1): one signature, claims [AddressAliasesV2 [(0, None)]].
fn rustUserV2(a: std.mem.Allocator) !messages.ConsensusTransaction {
    const vectors = @embedFile("testdata/consensus_tx_vectors.txt");
    const at = std.mem.indexOf(u8, vectors, "ZUIVEC user_v2 1 ").? + "ZUIVEC user_v2 1 ".len;
    const hex = vectors[at..][0..std.mem.indexOfScalar(u8, vectors[at..], ' ').?];
    const raw = try a.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(raw, hex);
    return bcs.decode(messages.ConsensusTransaction, a, raw);
}

fn withClaims(a: std.mem.Allocator, base: messages.ConsensusTransaction, claims: []const messages.TransactionClaim) ![]const u8 {
    var t = base;
    t.kind.UserTransactionV2.claims = claims;
    return bcs.encodeAlloc(messages.ConsensusTransaction, a, &t);
}

test "only the first AddressAliasesV2 claim is checked, as Rust tx.aliases() (find_map)" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.init(gpa);
    defer f.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    const base = try rustUserV2(a);
    try std.testing.expectEqual(@as(usize, 1), base.kind.UserTransactionV2.tx.data.@"0".element().tx_signatures.len);

    try f.v.verifyBatch(try Fixture.batch(a, &.{try ct(a, base.kind)}), 0);
    // a second, out-of-range V2 claim is ignored by Rust: the block is accepted
    const two = try withClaims(a, base, &.{ .{ .AddressAliasesV2 = &.{.{ 0, null }} }, .{ .AddressAliasesV2 = &.{.{ 7, null }} } });
    try f.v.verifyBatch(try Fixture.batch(a, &.{two}), 0);
    // the first claim out of range rejects the block
    const bad = try withClaims(a, base, &.{ .{ .AddressAliasesV2 = &.{.{ 1, null }} }, .{ .AddressAliasesV2 = &.{.{ 0, null }} } });
    try std.testing.expectError(error.InvalidTransaction, f.v.verifyBatch(try Fixture.batch(a, &.{bad}), 0));
    // no V2 claim at 141 (address_aliases, fix_checkpoint_signature_mapping): rejected
    const none = try withClaims(a, base, &.{.{ .ImmutableInputObjects = &.{} }});
    try std.testing.expectError(error.InvalidTransaction, f.v.verifyBatch(try Fixture.batch(a, &.{none}), 0));
    // a V1 alias claim alone does not count once the mapping fix is on
    const v1 = try withClaims(a, base, &.{.{ .AddressAliases = &.{.{ .{ .@"0" = @splat(1) }, null }} }});
    try std.testing.expectError(error.InvalidTransaction, f.v.verifyBatch(try Fixture.batch(a, &.{v1}), 0));
}

test "allowed proposers are enforced on the verify_batch path through the consensus interface" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.init(gpa);
    defer f.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    var t = try rustUserV2(a);
    // rebuild the transaction with Validity { allowed_proposers: epoch 1, [2] }
    const items = try a.dupe(@TypeOf(t.kind.UserTransactionV2.tx.data.@"0".items[0]), t.kind.UserTransactionV2.tx.data.@"0".items);
    items[0].intent_message.value.V1.expiration = .{ .Validity = .{ .min_epoch = 1, .max_epoch = 1, .min_timestamp = null, .max_timestamp = null, .chain = .{ .@"0" = .{ .@"0" = .{ .@"0" = @splat(0) } } }, .nonce = 0, .allowed_proposers = .{ .epoch = 1, .proposers = &.{2} } } };
    t.kind.UserTransactionV2.tx.data.@"0".items = items;
    const txs = try Fixture.batch(a, &.{try bcs.encodeAlloc(messages.ConsensusTransaction, a, &t)});
    const verifier = f.v.verifier();
    const ref = struct {
        fn of(author: u32) consensus.types.BlockRef {
            return .{ .round = 5, .author = author, .digest = @splat(9) };
        }
    }.of;
    try std.testing.expectError(error.InvalidTransaction, verifier.verifyBatch(ref(0), txs));
    try std.testing.expectError(error.InvalidTransaction, verifier.verifyBatch(ref(3), txs));
    try verifier.verifyBatch(ref(2), txs);
    // another epoch's restriction does not apply
    items[0].intent_message.value.V1.expiration.Validity.allowed_proposers.?.epoch = 2;
    try verifier.verifyBatch(ref(0), try Fixture.batch(a, &.{try bcs.encodeAlloc(messages.ConsensusTransaction, a, &t)}));
}

test "checkpoint signatures without a verifier hook reject the block (fail closed)" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.init(gpa);
    defer f.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    const vectors = @embedFile("testdata/consensus_tx_vectors.txt");
    const at = std.mem.indexOf(u8, vectors, "ZUIVEC ckpt_v2 1 ").? + "ZUIVEC ckpt_v2 1 ".len;
    const hex = vectors[at..][0..std.mem.indexOfScalar(u8, vectors[at..], ' ').?];
    const raw = try a.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(raw, hex);
    const txs = try Fixture.batch(a, &.{raw});
    try std.testing.expectError(error.InvalidTransaction, f.v.verifyBatch(txs, 0));
    const Hook = struct {
        var calls: usize = 0;
        fn ok(_: *anyopaque, msgs: []const *const messages.CheckpointSignatureMessage) bool {
            calls += msgs.len;
            return true;
        }
    };
    var dummy: u8 = 0;
    f.v.hooks = .{ .ctx = &dummy, .checkpoint_signatures = Hook.ok };
    try f.v.verifyBatch(txs, 0);
    try std.testing.expectEqual(@as(usize, 1), Hook.calls);
}

test "deny-config limits use the deduplicated sets" {
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const Oid = @typeInfo(@TypeOf(@as(messages.TransactionDenyRules, undefined).object_deny_list)).pointer.child;
    const ids = try a.alloc(Oid, tx_validator.deny_max_share_entries + 1);
    for (ids, 0..) |*id, i| {
        var b: [32]u8 = @splat(0);
        // index 5000 repeats index 0
        std.mem.writeInt(u64, b[0..8], if (i == tx_validator.deny_max_share_entries) 0 else i, .big);
        id.* = .{ .@"0" = .{ .@"0" = b } };
    }
    const rules: messages.TransactionDenyRules = .{
        .object_deny_list = ids,
        .package_deny_list = &.{},
        .address_deny_list = &.{},
        .package_publish_disabled = false,
        .package_upgrade_disabled = false,
        .shared_object_disabled = false,
        .user_transaction_disabled = false,
        .gasless_disabled = false,
        .receiving_objects_disabled = false,
        .zklogin_sig_disabled = false,
        .zklogin_disabled_providers = &.{ .{ .@"0" = "b" }, .{ .@"0" = "a" }, .{ .@"0" = "b" } },
    };
    // 5001 listed object ids, 5000 distinct, plus 2 distinct providers: 5002 > 5000, rejected
    try std.testing.expect(!tx_validator.denyShareLimitsOk(a, &rules));
    var r2 = rules;
    r2.zklogin_disabled_providers = &.{};
    // 5000 distinct object ids: accepted although 5001 are listed
    try std.testing.expect(tx_validator.denyShareLimitsOk(a, &r2));
    const n = try tx_validator.normalizedDenyRules(a, &rules);
    try std.testing.expectEqual(@as(usize, 5000), n.object_deny_list.len);
    try std.testing.expectEqual(@as(usize, 2), n.zklogin_disabled_providers.len);
    try std.testing.expectEqualStrings("a", n.zklogin_disabled_providers[0].@"0");
}
