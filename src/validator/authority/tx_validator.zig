//! `SuiTxValidator` (consensus_validator.rs, mainnet-v1.83.1): what a validator checks in a
//! peer's block before accepting it, and how it votes on the block's user transactions for the
//! Mysticeti fast path. Implements `consensus.iface.TransactionVerifier`.
//!
//! `verify_batch` rejects the whole block (a Byzantine proposer) for: deprecated kinds
//! (CertifiedTransaction, CheckpointSignature V1, CapabilityNotification V1, RandomnessStateUpdate,
//! UserTransaction V1), oversized DKG messages, a UserTransactionV2 without an aliases claim when
//! address aliases are on, alias signature indexes out of range, a proposer outside a
//! transaction's allowed proposers, too many ExecutionTimeObservation estimates, deny-config
//! updates when the protocol does not share them or beyond the share limits, and checkpoint
//! signatures that fail batch verification.
//!
//! `verify_and_vote_batch` additionally votes on each UserTransactionV2: the transaction is
//! checked as for signing (checker.zig: validity, signatures and the alias claim, deny config,
//! inputs live at the claimed versions, immutable claims). A failing transaction is a reject
//! vote and its reason is cached by consensus position. It must vote exactly as Rust does or the
//! fast path diverges.
//!
//! Both entry points get the block ref, so the allowed-proposer check runs on every path, as in
//! Rust. Without a `checkpoint_signatures` hook a block carrying CheckpointSignatureV2 is
//! rejected (fail closed): Rust always batch-verifies them.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const consensus = @import("consensus");
const messages = @import("../messages.zig");
const tx_mod = @import("tx.zig");
const checker = @import("checker.zig");
const env_mod = @import("env.zig");
const preverify = @import("preverify.zig");

const Allocator = std.mem.Allocator;
const cti = consensus.iface;

/// `dkg_v1::DKG_MESSAGES_MAX_SIZE` (fastcrypto-tbls).
pub const dkg_messages_max_size: usize = 400_000;

/// `TransactionDenyRules::MAX_SHARE_*`.
pub const deny_max_share_entries: usize = 5_000;
pub const deny_max_provider_len: usize = 256;
pub const deny_max_serialized_bytes: usize = 200 * 1024;

/// Optional hooks into the rest of the validator; every one defaults to "not configured".
pub const Hooks = struct {
    ctx: ?*anyopaque = null,
    /// Executed in the current epoch or recently finalized: the vote accepts it.
    recently_executed: ?*const fn (ctx: *anyopaque, digest: *const tx_mod.Id) bool = null,
    /// `transaction_executed_in_last_epoch`: reject (TransactionAlreadyExecuted).
    executed_last_epoch: ?*const fn (ctx: *anyopaque, digest: *const tx_mod.Id) bool = null,
    /// `check_system_overload` at signing: true = overloaded, reject.
    overloaded: ?*const fn (ctx: *anyopaque) bool = null,
    /// `batch_verify_checkpoints` (BLS aggregate over the committee) then forwarded to the
    /// checkpoint service (`notify_checkpoint_signature`): false rejects the block.
    checkpoint_signatures: ?*const fn (ctx: *anyopaque, msgs: []const *const messages.CheckpointSignatureMessage) bool = null,
    /// A fully validated block's UpdateTransactionDenyConfig messages, applied early.
    apply_deny_updates: ?*const fn (ctx: *anyopaque, author_index: u32, updates: []const messages.SharedTransactionDenyConfig) void = null,
};

pub const ReasonKey = struct { round: u32, author: u32, digest: [32]u8, index: u16 };

/// `tx_reject_reason_cache`: bounded FIFO of (position -> reason text).
pub const ReasonCache = struct {
    gpa: Allocator,
    /// Written by the handler and consensus verify threads, read by API threads.
    lock: @import("sync.zig").Spin = .{},
    cap: usize = 65536,
    map: std.AutoHashMapUnmanaged(ReasonKey, []u8) = .empty,
    order: std.ArrayList(ReasonKey) = .empty,

    pub fn deinit(c: *ReasonCache) void {
        var it = c.map.valueIterator();
        while (it.next()) |v| c.gpa.free(v.*);
        c.map.deinit(c.gpa);
        c.order.deinit(c.gpa);
    }

    pub fn set(c: *ReasonCache, k: ReasonKey, reason: []const u8) Allocator.Error!void {
        c.lock.lock();
        defer c.lock.unlock();
        if (c.map.count() >= c.cap and c.order.items.len > 0) {
            const old = c.order.orderedRemove(0);
            if (c.map.fetchRemove(old)) |kv| c.gpa.free(kv.value);
        }
        const copy = try c.gpa.dupe(u8, reason);
        errdefer c.gpa.free(copy);
        const gop = try c.map.getOrPut(c.gpa, k);
        if (gop.found_existing) c.gpa.free(gop.value_ptr.*) else try c.order.append(c.gpa, k);
        gop.value_ptr.* = copy;
    }

    /// A copy owned by the caller (the cache may evict the entry at any time).
    pub fn get(c: *ReasonCache, arena: Allocator, k: ReasonKey) ?[]const u8 {
        c.lock.lock();
        defer c.lock.unlock();
        const v = c.map.get(k) orelse return null;
        return arena.dupe(u8, v) catch null;
    }
};

pub const TxValidator = struct {
    gpa: Allocator,
    params: env_mod.Params,
    cfg: *const protocol.ProtocolConfig,
    check_env: *const checker.Env,
    epoch_ctl: env_mod.EpochControl,
    hooks: Hooks = .{},
    /// Shared with the handler and WaitForEffects (the Authority owns it).
    reasons: *ReasonCache,
    /// Votes cast / rejected, for the metrics tile.
    votes_accept: u64 = 0,
    votes_reject: u64 = 0,
    /// Signature pre-verification of a block's user transactions (preverify.zig; zui-only, the
    /// votes do not change).
    preverify: preverify.Config = .{},
    preverify_stats: preverify.Stats = .{},

    pub fn init(gpa: Allocator, params: env_mod.Params, cfg: *const protocol.ProtocolConfig, check_env: *const checker.Env, epoch_ctl: env_mod.EpochControl, reasons: *ReasonCache) TxValidator {
        return .{ .gpa = gpa, .params = params, .cfg = cfg, .check_env = check_env, .epoch_ctl = epoch_ctl, .reasons = reasons };
    }

    pub fn deinit(v: *TxValidator) void {
        _ = v;
    }

    pub const BlockError = error{ InvalidTransaction, OutOfMemory };

    fn decode(arena: Allocator, data: []const u8) BlockError!messages.ConsensusTransaction {
        return bcs.decode(messages.ConsensusTransaction, arena, data) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidTransaction,
        };
    }

    /// `validate_transactions` for one decoded block. `proposer` is the block author index
    /// when known.
    fn validateKinds(v: *TxValidator, kinds: []const messages.ConsensusTransactionKind, proposer: ?u32, ckpt: *std.ArrayList(*const messages.CheckpointSignatureMessage), arena: Allocator) BlockError!void {
        const ff = &v.cfg.feature_flags;
        for (kinds) |*k| switch (k.*) {
            .CertifiedTransaction, .CheckpointSignature, .CapabilityNotification, .RandomnessStateUpdate, .UserTransaction => return error.InvalidTransaction,
            .CheckpointSignatureV2 => |*m| try ckpt.append(arena, m),
            .RandomnessDkgMessage => |m| if (m.@"1".len > dkg_messages_max_size) return error.InvalidTransaction,
            .RandomnessDkgConfirmation => |m| if (m.@"1".len > dkg_messages_max_size) return error.InvalidTransaction,
            .EndOfPublish, .NewJWKFetched, .CapabilityNotificationV2 => {},
            .UserTransactionV2 => |*t| {
                const aliases = firstAliasesV2(t.claims);
                if (ff.address_aliases) {
                    // `tx.aliases()` (first AddressAliasesV2) or, before the mapping fix,
                    // `tx.aliases_v1()` (first AddressAliases)
                    const has = if (ff.fix_checkpoint_signature_mapping) aliases != null else hasAliasesV1(t.claims);
                    if (!has) return error.InvalidTransaction;
                }
                // only the first AddressAliasesV2 claim is bounds-checked (Rust find_map)
                const nsigs = t.tx.data.@"0".element().tx_signatures.len;
                if (aliases) |al| for (al) |e| if (@as(usize, e.@"0") >= nsigs) return error.InvalidTransaction;
                if (proposer) |p| if (ff.allowed_proposers) {
                    // Rust only runs check_allowed_proposer on the expiration; input problems stay on the vote path
                    if (!tx_mod.allowedProposer(&t.tx.data.@"0".element().intent_message.value.V1, p, v.params.epoch)) return error.InvalidTransaction;
                };
            },
            .ExecutionTimeObservation => |o| if (o.estimates.len > v.params.max_programmable_tx_commands) return error.InvalidTransaction,
            .UpdateTransactionDenyConfig => |*m| {
                if (!ff.share_transaction_deny_config_in_consensus) return error.InvalidTransaction;
                switch (m.*) {
                    .V1 => |c| if (c.rules) |r| if (!denyShareLimitsOk(arena, &r)) return error.InvalidTransaction,
                }
            },
        };
        if (ckpt.items.len != 0) {
            // unverifiable signatures are never accepted: no hook means reject the block
            const f = v.hooks.checkpoint_signatures orelse return error.InvalidTransaction;
            if (!f(v.hooks.ctx.?, ckpt.items)) return error.InvalidTransaction;
        }
    }

    /// `verify_batch`.
    pub fn verifyBatch(v: *TxValidator, txs: []const consensus.types.Transaction, proposer: ?u32) BlockError!void {
        var arena_state: std.heap.ArenaAllocator = .init(v.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const kinds = try arena.alloc(messages.ConsensusTransactionKind, txs.len);
        for (txs, kinds) |t, *k| k.* = (try decode(arena, t.data)).kind;
        var ckpt: std.ArrayList(*const messages.CheckpointSignatureMessage) = .empty;
        try v.validateKinds(kinds, proposer, &ckpt, arena);
    }

    /// `verify_and_vote_batch`: validates, then votes. Writes reject indices to `out`; returns
    /// how many (always at most out.len; a block never has more than out.len transactions).
    pub fn verifyAndVote(v: *TxValidator, block: consensus.types.BlockRef, txs: []const consensus.types.Transaction, out: []consensus.types.TransactionIndex) BlockError!usize {
        var arena_state: std.heap.ArenaAllocator = .init(v.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const kinds = try arena.alloc(messages.ConsensusTransactionKind, txs.len);
        for (txs, kinds) |t, *k| k.* = (try decode(arena, t.data)).kind;
        var ckpt: std.ArrayList(*const messages.CheckpointSignatureMessage) = .empty;
        try v.validateKinds(kinds, block.author, &ckpt, arena);

        // deny config updates of a validated block take effect early
        if (v.hooks.apply_deny_updates) |f| {
            var ups: std.ArrayList(messages.SharedTransactionDenyConfig) = .empty;
            for (kinds) |k| switch (k) {
                .UpdateTransactionDenyConfig => |m| try ups.append(arena, m),
                else => {},
            };
            if (ups.items.len != 0) f(v.hooks.ctx.?, block.author, ups.items);
        }

        // signature pre-verification: every user transaction's decode, validity check and
        // signatures across the pool's lanes; the loop below uses the results in place
        var pre: ?preverify.Batch = null;
        defer if (pre) |*b| b.deinit();
        {
            var n_user: usize = 0;
            for (kinds) |k| n_user += @intFromBool(k == .UserTransactionV2);
            if (v.preverify.active(n_user)) {
                const plains = try arena.alloc(?*const messages.PlainTransactionWithClaims, kinds.len);
                for (kinds, plains) |*k, *o| o.* = switch (k.*) {
                    .UserTransactionV2 => |*t| t,
                    else => null,
                };
                pre = try preverify.Batch.initPlain(v.gpa, arena, &v.preverify, v.check_env, plains);
                pre.?.stats = &v.preverify_stats;
                pre.?.decode();
                if (pre.?.needVerify()) {
                    for (pre.?.slots) |*sl| sl.need_sig = sl.validityOk();
                    try pre.?.verify(arena);
                }
            }
        }

        var n: usize = 0;
        for (kinds, 0..) |*k, i| {
            const t = switch (k.*) {
                .UserTransactionV2 => |*t| t,
                else => continue,
            };
            // per-transaction scratch: freed with the call's arena
            if (try v.voteTransactionPre(arena, t, if (pre) |*b| &b.slots[i] else null)) |reason| {
                v.votes_reject += 1;
                if (n < out.len) {
                    out[n] = @intCast(i);
                    n += 1;
                }
                v.reasons.set(.{ .round = block.round, .author = block.author, .digest = block.digest, .index = @intCast(i) }, reason) catch {};
            } else v.votes_accept += 1;
        }
        return n;
    }

    /// `vote_transaction`: null = accept, otherwise the reject reason.
    pub fn voteTransaction(v: *TxValidator, arena: Allocator, t: *const messages.PlainTransactionWithClaims) BlockError!?[]const u8 {
        return v.voteTransactionPre(arena, t, null);
    }

    /// `voteTransaction` taking the decode, validity and signature results the pre-verification
    /// stage stored in `pre` (each one computed here when absent). The returned reason may live
    /// in `pre`'s arena.
    fn voteTransactionPre(v: *TxValidator, arena: Allocator, t: *const messages.PlainTransactionWithClaims, pre: ?*const preverify.Slot) BlockError!?[]const u8 {
        var u_local: tx_mod.UserTx = undefined;
        const u: *const tx_mod.UserTx = if (pre != null and pre.?.u != null) &pre.?.u.? else blk: {
            u_local = tx_mod.fromDecoded(arena, &.{}, t.*) catch return "malformed transaction";
            break :blk &u_local;
        };
        const env = v.check_env;

        const validity = if (pre != null and pre.?.validity != null) pre.?.validity.? else checker.checkValidity(arena, env, u);
        if (validity catch return error.OutOfMemory) |f| return f.message;

        if (v.hooks.overloaded) |f| if (f(v.hooks.ctx.?)) return "Validator is overloaded";

        // signatures, and the alias claim against what verification derives
        const sr_pre = if (pre != null and pre.?.sig != null) pre.?.sig.? else checker.verifySignatures(arena, env, u, &.{});
        const sr = sr_pre catch return error.OutOfMemory;
        const derived = switch (sr) {
            .fail => |f| return f.message,
            .ok => |d| d,
        };
        if (v.cfg.feature_flags.address_aliases) {
            if (!checker.hasAliasClaim(u)) return "missing address alias claim";
            if (!checker.aliasClaimMatches(u, derived)) return "Address aliases have changed";
        }

        // handle_vote_transaction
        if (!v.epoch_ctl.reconfigState().shouldAcceptUserCerts()) return "Validator halted at epoch end";
        var accepted_early = false;
        if (v.hooks.recently_executed) |f| if (f(v.hooks.ctx.?, &u.digest)) {
            accepted_early = true;
        };
        if (!accepted_early) {
            if (v.hooks.executed_last_epoch) |f| if (f(v.hooks.ctx.?, &u.digest)) return "Transaction already executed";
            if (checker.checkInputs(arena, env, u, .{ .validity = false }) catch return error.OutOfMemory) |f| return f.message;
        }
        if (u.immutableClaims().len != 0) {
            if (checker.immutableClaimsError(arena, env, u) catch return error.OutOfMemory) |f| return f.message;
        }
        return null;
    }

    // ---- consensus.iface.TransactionVerifier adapter

    fn castCtx(ctx: *anyopaque) *TxValidator {
        return @ptrCast(@alignCast(ctx));
    }
    fn vtVerifyBatch(ctx: *anyopaque, block: consensus.types.BlockRef, txs: []const consensus.types.Transaction) cti.TransactionVerifier.VerifyError!void {
        castCtx(ctx).verifyBatch(txs, block.author) catch return error.InvalidTransaction;
    }
    fn vtVerifyAndVote(ctx: *anyopaque, block: consensus.types.BlockRef, txs: []const consensus.types.Transaction, out: []consensus.types.TransactionIndex) cti.TransactionVerifier.VerifyError!usize {
        return castCtx(ctx).verifyAndVote(block, txs, out) catch return error.InvalidTransaction;
    }
    const vt: cti.TransactionVerifier.VTable = .{ .verify_batch = vtVerifyBatch, .verify_and_vote_batch = vtVerifyAndVote };

    pub fn verifier(v: *TxValidator) cti.TransactionVerifier {
        return .{ .ctx = v, .vtable = &vt };
    }
};

fn firstAliasesV2(claims: []const messages.TransactionClaim) ?@FieldType(messages.TransactionClaim, "AddressAliasesV2") {
    for (claims) |c| switch (c) {
        .AddressAliasesV2 => |al| return al,
        else => {},
    };
    return null;
}

fn hasAliasesV1(claims: []const messages.TransactionClaim) bool {
    for (claims) |c| switch (c) {
        .AddressAliases => return true,
        else => {},
    };
    return false;
}

/// `TransactionDenyRules::check_share_limits` on the deserialized value. The four lists are
/// `BTreeSet`s in Rust: decoding accepts duplicates and any order and normalizes, so the entry
/// count and the serialized size are those of the sorted, deduplicated sets.
pub fn denyShareLimitsOk(arena: Allocator, r: *const messages.TransactionDenyRules) bool {
    const n = normalizedDenyRules(arena, r) catch return false;
    const entries = n.object_deny_list.len + n.package_deny_list.len + n.address_deny_list.len + n.zklogin_disabled_providers.len;
    if (entries > deny_max_share_entries) return false;
    for (n.zklogin_disabled_providers) |p| if (p.@"0".len > deny_max_provider_len) return false;
    const enc = bcs.encodeAlloc(messages.TransactionDenyRules, arena, &n) catch return false;
    return enc.len <= deny_max_serialized_bytes;
}

/// The rules as Rust holds them after deserialization (each list a sorted, deduplicated set).
pub fn normalizedDenyRules(arena: Allocator, r: *const messages.TransactionDenyRules) Allocator.Error!messages.TransactionDenyRules {
    return .{
        .object_deny_list = try sortedSet(arena, types.ObjectID, r.object_deny_list),
        .package_deny_list = try sortedSet(arena, types.ObjectID, r.package_deny_list),
        .address_deny_list = try sortedSet(arena, types.SuiAddress, r.address_deny_list),
        .zklogin_disabled_providers = try sortedSet(arena, bcs.String, r.zklogin_disabled_providers),
        .package_publish_disabled = r.package_publish_disabled,
        .package_upgrade_disabled = r.package_upgrade_disabled,
        .shared_object_disabled = r.shared_object_disabled,
        .user_transaction_disabled = r.user_transaction_disabled,
        .gasless_disabled = r.gasless_disabled,
        .receiving_objects_disabled = r.receiving_objects_disabled,
        .zklogin_sig_disabled = r.zklogin_sig_disabled,
    };
}

/// Byte key of a set element: Rust `Ord` on ObjectID / SuiAddress / String is lexicographic on
/// these bytes.
fn setKey(comptime T: type, x: *const T) []const u8 {
    return if (T == bcs.String) x.@"0" else std.mem.asBytes(x);
}

fn setLess(comptime T: type) fn (void, T, T) bool {
    return struct {
        fn f(_: void, a: T, b: T) bool {
            return std.mem.lessThan(u8, setKey(T, &a), setKey(T, &b));
        }
    }.f;
}

/// The elements as a Rust `BTreeSet` holds them after deserialization: sorted, no duplicates.
fn sortedSet(arena: Allocator, comptime T: type, xs: []const T) Allocator.Error![]const T {
    const out = try arena.dupe(T, xs);
    std.mem.sort(T, out, {}, setLess(T));
    var n: usize = 0;
    for (out) |x| {
        if (n > 0 and std.mem.eql(u8, setKey(T, &out[n - 1]), setKey(T, &x))) continue;
        out[n] = x;
        n += 1;
    }
    return out[0..n];
}

test "reason cache bounded" {
    var c: ReasonCache = .{ .gpa = std.testing.allocator, .cap = 2 };
    defer c.deinit();
    try c.set(.{ .round = 1, .author = 0, .digest = @splat(0), .index = 0 }, "a");
    try c.set(.{ .round = 2, .author = 0, .digest = @splat(0), .index = 0 }, "b");
    try c.set(.{ .round = 3, .author = 0, .digest = @splat(0), .index = 0 }, "c");
    try std.testing.expect(c.get(std.testing.allocator, .{ .round = 1, .author = 0, .digest = @splat(0), .index = 0 }) == null);
    const got = c.get(std.testing.allocator, .{ .round = 3, .author = 0, .digest = @splat(0), .index = 0 }).?;
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("c", got);
}

test "dkg size limit constant" {
    try std.testing.expectEqual(@as(usize, 400_000), dkg_messages_max_size);
}
