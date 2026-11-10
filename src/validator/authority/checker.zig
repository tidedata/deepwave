//! Transaction checks the validator runs before it signs, votes or submits (sui-core
//! `handle_vote_transaction`, `check_transaction_validity`, `SuiTxValidator::vote_transaction`):
//!
//!   1. `TransactionData::validity_check` (rpc_exec.checks.validity),
//!   2. transaction deny config (rpc_exec.txdeny),
//!   3. input loading at the claimed versions and `check_transaction_input` (gas status, gas
//!      objects and balance, object ownership, replay protection, receiving objects),
//!   4. owned objects must be live: exactly the claimed version and digest
//!      (`ObjectLocks::validate_owned_object_versions`; locking itself happens after consensus),
//!   5. user signatures over the intent message for every required signer (sig.user), with the
//!      address-alias claim compared to what verification derives.
//!
//! A failure is a `Fail` (the SuiError text and a gRPC-ish code) so the same function serves the
//! submit path (reply to the client) and the vote path (reject vote + cached reason).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const exec = @import("exec");
const sig = @import("sig");
const rpc_exec = @import("rpc_exec");
const tx_mod = @import("tx.zig");

const checks = rpc_exec.checks;
const txdeny = rpc_exec.txdeny;
const Allocator = std.mem.Allocator;
const ObjectView = exec.objects.ObjectView;
pub const Fail = checks.Fail;
pub const Id = tx_mod.Id;

pub const Error = Allocator.Error || error{ProtocolConfigMissing};

/// What the checks read about the epoch and the object store.
pub const Env = struct {
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    chain_id: Id,
    rgp: u64,
    committee_size: u32,
    state: rpc_exec.State,
    sig_env: *const sig.user.UserSigEnv,
    /// Maximum number of user signatures (`max_tx_gas`-independent: Rust checks
    /// `tx_signatures().len() <= max_num_user_signatures` in `validity_check`); 0 = unchecked.
    max_signatures: usize = 0,
};

fn lessId(_: void, a: Id, b: Id) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

pub const Opts = struct {
    /// Run `validity_check` (step 1). The vote path runs it first and again here only once.
    validity: bool = true,
};

/// Step 1 alone: validity check and the signature count limit.
pub fn checkValidity(arena: Allocator, env: *const Env, u: *const tx_mod.UserTx) Error!?Fail {
    const td = u.data();
    if (checks.isSystemKind(&td.kind)) return try checks.userInput(arena, "system transactions cannot be submitted by users", .{});
    var kinds: std.ArrayList(checks.InputKind) = .empty;
    var recv: std.ArrayList(checks.Receiving) = .empty;
    if (try checks.inputKinds(arena, td, &kinds, &recv)) |f| return f;
    const vctx: checks.ValidityCtx = .{ .cfg = env.cfg, .epoch = env.epoch, .chain_id = env.chain_id, .rgp = env.rgp, .committee_size = env.committee_size };
    if (try checks.validity(arena, &vctx, td)) |f| return f;
    if (env.max_signatures != 0 and u.signatures().len > env.max_signatures)
        return try checks.userInput(arena, "Too many signatures: {d} (max {d})", .{ u.signatures().len, env.max_signatures });
    return null;
}

/// Steps 1 to 4.
pub fn checkInputs(arena: Allocator, env: *const Env, u: *const tx_mod.UserTx, opts: Opts) Error!?Fail {
    const cfg = env.cfg;
    const td = u.data();
    if (checks.isSystemKind(&td.kind)) return try checks.userInput(arena, "system transactions cannot be submitted by users", .{});
    if (checks.unsupportedWithdrawal(td)) |why| return try checks.unsupportedFeature(arena, "{s}", .{why});

    var kinds: std.ArrayList(checks.InputKind) = .empty;
    var recv: std.ArrayList(checks.Receiving) = .empty;
    if (try checks.inputKinds(arena, td, &kinds, &recv)) |f| return f;

    if (opts.validity) if (try checkValidity(arena, env, u)) |f| return f;

    // deny config
    {
        const deny_cfg = txdeny.current();
        if (deny_cfg.active()) {
            const raw_sigs = try arena.alloc([]const u8, u.signatures().len);
            for (u.signatures(), raw_sigs) |s, *o| o.* = s.@"0";
            if (try txdeny.check(arena, &deny_cfg.rules, td, raw_sigs, kinds.items, recv.items, null)) |f| return f;
        }
    }

    // read_objects_for_signing
    const state = env.state;
    const loaded = try arena.alloc(checks.Loaded, kinds.items.len);
    for (kinds.items, 0..) |k, i| switch (k) {
        .package => |pid| {
            const raw = state.latest(&pid) orelse return try checks.userInput(arena, "Dependent package not found on-chain: {s}", .{checks.hex(&pid).s()});
            const v = ObjectView.parse(raw) catch return try checks.userInput(arena, "Dependent package not found on-chain: {s}", .{checks.hex(&pid).s()});
            if (!v.is_package) return try checks.userInput(arena, "Dependent package not found on-chain: {s}", .{checks.hex(&pid).s()});
            loaded[i] = try loadedOf(arena, k, raw);
        },
        .shared => |s| {
            const raw = state.latest(&s.id) orelse return try checks.userInput(arena, "Could not find the referenced object {s} at version None", .{checks.hex(&s.id).s()});
            const l = try loadedOf(arena, k, raw);
            const start: ?u64 = switch (l.owner) {
                .Shared => |x| x.initial_shared_version.@"0",
                .ConsensusAddressOwner => |x| x.start_version.@"0",
                .Party => |x| x.start_version.@"0",
                else => null,
            };
            if (start == null or start.? != s.isv) return try checks.userInput(arena, "Could not find the referenced object {s} at version None", .{checks.hex(&s.id).s()});
            loaded[i] = l;
        },
        .owned => |o| {
            const raw = state.at(&o.id, o.version) orelse {
                const live = state.latest(&o.id) orelse return try checks.userInput(arena, "Could not find the referenced object {s} at version None", .{checks.hex(&o.id).s()});
                const lv = ObjectView.parse(live) catch return try checks.userInput(arena, "Could not find the referenced object {s} at version None", .{checks.hex(&o.id).s()});
                if (lv.version >= o.version)
                    return try checks.userInput(arena, "Transaction needs to be rebuilt because object {s} version {d} ({s}) is unavailable for consumption, current version: {d}", .{ checks.hex(&o.id).s(), o.version, try checks.b58(arena, &o.digest), lv.version });
                return try checks.userInput(arena, "Could not find the referenced object {s} at version Some(SequenceNumber({d}))", .{ checks.hex(&o.id).s(), o.version });
            };
            loaded[i] = try loadedOf(arena, k, raw);
        },
    };
    const recv_objs = try arena.alloc(?[]const u8, recv.items.len);
    for (recv.items, recv_objs) |r, *o| {
        o.* = state.latest(&r.id) orelse return try checks.userInput(arena, "Could not find the referenced object {s} at version Some(SequenceNumber({d}))", .{ checks.hex(&r.id).s(), r.version });
    }

    if (try checks.transactionInput(arena, cfg, env.rgp, td, loaded, recv.items, recv_objs)) |f| return f;

    // validate_owned_object_versions: owned (non-immutable) inputs are live at the claimed ref
    for (loaded) |l| switch (l.kind) {
        .owned => |o| {
            if (l.owner == .Immutable) continue;
            const live = state.latest(&o.id) orelse return try checks.userInput(arena, "Could not find the referenced object {s} at version None", .{checks.hex(&o.id).s()});
            const lv = ObjectView.parse(live) catch return try checks.internal(arena, "unparsable live object {s}", .{checks.hex(&o.id).s()});
            if (lv.version != o.version)
                return try checks.userInput(arena, "Transaction needs to be rebuilt because object {s} version {d} ({s}) is unavailable for consumption, current version: {d}", .{ checks.hex(&o.id).s(), o.version, try checks.b58(arena, &o.digest), lv.version });
            const live_digest = lv.digest();
            if (!std.mem.eql(u8, &live_digest, &o.digest))
                return try checks.userInput(arena, "Object digest {s} is not valid for object {s}: expected {s}", .{ try checks.b58(arena, &o.digest), checks.hex(&o.id).s(), try checks.b58(arena, &live_digest) });
        },
        else => {},
    };
    return null;
}

fn loadedOf(arena: Allocator, kind: checks.InputKind, raw: []const u8) Error!checks.Loaded {
    const v = ObjectView.parse(raw) catch return error.ProtocolConfigMissing;
    const owner = bcs.decode(types.Owner, arena, raw[v.owner_at..v.prev_tx_at]) catch return error.ProtocolConfigMissing;
    return .{ .kind = kind, .raw = raw, .view = v, .owner = owner };
}

pub const SigResult = union(enum) {
    ok: []const AliasEntry,
    fail: Fail,
};

/// One required signer's (signature index, alias version) as `verify_transaction_with_current_aliases`.
pub const AliasEntry = struct { sig_index: u8, alias_version: ?u64 };

/// Step 5. Aliases: no alias objects are consulted here (each signer is its own alias), which is
/// what a network without AddressAliases state produces; the alias resolver hook of the epoch
/// lane replaces `aliases` when mainnet alias state must be honoured.
pub fn verifySignatures(arena: Allocator, env: *const Env, u: *const tx_mod.UserTx, aliases: []const sig.user.AliasSet) Error!SigResult {
    return verifySignaturesIntent(arena, env, u, try intentMessage(arena, u), aliases);
}

/// The bytes every user signature of `u` signs over (through their Blake2b-256 digest):
/// `IntentMessage { Intent::sui_transaction(), TransactionData }` in BCS.
pub fn intentMessage(arena: Allocator, u: *const tx_mod.UserTx) Allocator.Error![]const u8 {
    const td_all: types.TransactionData = .{ .V1 = u.data().* };
    const td_bcs = try bcs.encodeAlloc(types.TransactionData, arena, &td_all);
    const intent = try arena.alloc(u8, 3 + td_bcs.len);
    intent[0] = 0;
    intent[1] = 0;
    intent[2] = 0;
    @memcpy(intent[3..], td_bcs);
    return intent;
}

/// `verifySignatures` with the intent message already built (`intentMessage(u)`).
pub fn verifySignaturesIntent(arena: Allocator, env: *const Env, u: *const tx_mod.UserTx, intent: []const u8, aliases: []const sig.user.AliasSet) Error!SigResult {
    const sigs = try arena.alloc([]const u8, u.signatures().len);
    for (u.signatures(), sigs) |s, *o| o.* = s.@"0";
    const scratch = try arena.alloc(u8, sig.user.txScratchLen(sigs));
    const res = sig.user.verifyTransaction(env.sig_env, intent, sigs, aliases, scratch) catch |e| switch (e) {
        error.Bcs => return .{ .fail = try checks.userInput(arena, "Invalid transaction data", .{}) },
        else => return .{ .fail = try checks.internal(arena, "Signature verification failed: {s}", .{@errorName(e)}) },
    };
    switch (res.verdict) {
        .valid => {},
        .invalid => |r| return .{ .fail = try checks.internal(arena, "Signature is not valid: {s}", .{r.truthName()}) },
    }
    const out = try arena.alloc(AliasEntry, res.n);
    for (out, 0..) |*o, i| o.* = .{ .sig_index = res.indices[i], .alias_version = null };
    return .{ .ok = out };
}

/// The address-alias claim a `UserTransactionV2` carries must equal what verification derives
/// (`AliasesChanged` otherwise). With `address_aliases` on, the claim must be present.
pub fn aliasClaimMatches(u: *const tx_mod.UserTx, derived: []const AliasEntry) bool {
    for (u.tx.claims) |c| switch (c) {
        .AddressAliasesV2 => |claimed| {
            if (claimed.len != derived.len) return false;
            for (claimed, derived) |a, b| {
                if (a.@"0" != b.sig_index) return false;
                const av: ?u64 = if (a.@"1") |v| v.@"0" else null;
                if (av != b.alias_version) return false;
            }
            return true;
        },
        else => {},
    };
    return false;
}

pub fn hasAliasClaim(u: *const tx_mod.UserTx) bool {
    for (u.tx.claims) |c| switch (c) {
        .AddressAliasesV2 => return true,
        else => {},
    };
    return false;
}

/// `verify_immutable_object_claims`: the claimed ids must be exactly the owned inputs that are
/// immutable in the store. Returns an error text or null.
pub fn immutableClaimsError(arena: Allocator, env: *const Env, u: *const tx_mod.UserTx) Allocator.Error!?Fail {
    const claimed = u.immutableClaims();
    if (claimed.len == 0) return null;
    // every claimed id must be among the owned inputs
    for (claimed) |c| {
        var found = false;
        for (u.owned) |o| if (std.mem.eql(u8, &o.id, &c.@"0".@"0")) {
            found = true;
        };
        if (!found) return try checks.internal(arena, "Immutable object claim not found in transaction input: {s}", .{checks.hex(&c.@"0".@"0").s()});
    }
    // the set of actually immutable owned inputs must equal the claim
    for (u.owned) |o| {
        const live = env.state.latest(&o.id) orelse return try checks.userInput(arena, "Could not find the referenced object {s} at version Some(SequenceNumber({d}))", .{ checks.hex(&o.id).s(), o.version });
        const v = ObjectView.parse(live) catch return try checks.internal(arena, "unparsable live object", .{});
        if (v.version != o.version) return try checks.userInput(arena, "Transaction needs to be rebuilt because object {s} version {d} is unavailable for consumption, current version: {d}", .{ checks.hex(&o.id).s(), o.version, v.version });
        const owner = bcs.decode(types.Owner, arena, live[v.owner_at..v.prev_tx_at]) catch return try checks.internal(arena, "unparsable owner", .{});
        const immutable = owner == .Immutable;
        const is_claimed = u.hasImmutableClaim(&o.id);
        if (is_claimed and !immutable) return try checks.internal(arena, "Invalid immutable object claim: object {s} is not immutable", .{checks.hex(&o.id).s()});
        if (immutable and !is_claimed) return try checks.internal(arena, "Immutable object not claimed: {s}", .{checks.hex(&o.id).s()});
    }
    return null;
}
