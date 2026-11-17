//! The transaction-deny config shared through consensus (protocol flag
//! `share_transaction_deny_config_in_consensus`, on from 131): sui-core 1.83.1
//! `transaction_deny_config_manager.rs` (TransactionDenyConfigManager, `evaluate_deny_configs`),
//! sui-config `PeerDenySyncConfig` and sui-node's startup / epoch-change broadcast
//! (`deny_config_broadcast_payload`).
//!
//! Each validator may share its local `transaction-deny-config` rules as an
//! `UpdateTransactionDenyConfig` consensus message (or withdraw them: `rules: None`). Every node
//! keeps the latest accepted message per committee member and derives its effective config: the
//! local rules, plus each operator pre-listed ruleset (`peer-deny-sync-config.rulesets`) that
//! enough eligible stake proposed a superset of, plus each element of a kind claimed by a default
//! bucket that enough eligible stake proposed. Signing, voting and simulation read the effective
//! config (`txdeny.effective()`); it is local policy only: nothing on the wire depends on it.
//!
//! Updates arrive from two places, as in Rust: a fully validated block's messages, applied when
//! this validator votes on the block (consensus_validator `apply_deny_config_updates`, author =
//! the block author), and the commit handler's backstop (`process_transaction_deny_config_updates`,
//! author = the sequenced transaction's author), one message at a time. A message is dropped when
//! its claimed authority is not the author, the author is not in the committee, its generation is
//! more than 60 s ahead of the local wall clock, or it is not newer than the stored one.
//!
//! The accepted messages and the last broadcast generation persist across restarts and epochs
//! (Rust: perpetual tables `shared_transaction_deny_configs`, `last_broadcast_deny_generation`) in
//! `<db>/validator/deny-sync`. At load this validator's own row and rows of non-members are not
//! voted (they stay in the file, as the rows stay in Rust's table).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const txdeny = @import("rpc_exec").txdeny;
const iface = @import("../iface.zig");
const messages = @import("../messages.zig");
const tx_validator = @import("tx_validator.zig");
const Spin = @import("sync.zig").Spin;

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const log = std.log.scoped(.deny_sync);

pub const Name = [96]u8;
pub const Rules = txdeny.Rules;

/// sui_types::committee::TOTAL_VOTING_POWER.
pub const total_voting_power: u64 = 10_000;
/// SharedTransactionDenyConfig::MAX_GENERATION_FUTURE_DRIFT_MS.
pub const max_generation_future_drift_ms: u64 = 60_000;

pub const Member = struct { name: Name, stake: u64 };

/// sui_types `DenyElementKind`, in its `Ord` order.
pub const Kind = enum(u4) {
    object,
    package,
    address,
    zklogin_provider,
    package_publish_disabled,
    package_upgrade_disabled,
    shared_object_disabled,
    user_transaction_disabled,
    gasless_disabled,
    receiving_objects_disabled,
    zklogin_sig_disabled,

    /// serde kebab-case (the YAML names).
    pub fn kebab(k: Kind) []const u8 {
        return switch (k) {
            .object => "object",
            .package => "package",
            .address => "address",
            .zklogin_provider => "zk-login-provider",
            .package_publish_disabled => "package-publish-disabled",
            .package_upgrade_disabled => "package-upgrade-disabled",
            .shared_object_disabled => "shared-object-disabled",
            .user_transaction_disabled => "user-transaction-disabled",
            .gasless_disabled => "gasless-disabled",
            .receiving_objects_disabled => "receiving-objects-disabled",
            .zklogin_sig_disabled => "zk-login-sig-disabled",
        };
    }

    /// `{:?}` (the variant name).
    pub fn debugName(k: Kind) []const u8 {
        return switch (k) {
            .object => "Object",
            .package => "Package",
            .address => "Address",
            .zklogin_provider => "ZkLoginProvider",
            .package_publish_disabled => "PackagePublishDisabled",
            .package_upgrade_disabled => "PackageUpgradeDisabled",
            .shared_object_disabled => "SharedObjectDisabled",
            .user_transaction_disabled => "UserTransactionDisabled",
            .gasless_disabled => "GaslessDisabled",
            .receiving_objects_disabled => "ReceivingObjectsDisabled",
            .zklogin_sig_disabled => "ZkLoginSigDisabled",
        };
    }

    pub fn parse(s: []const u8) ?Kind {
        for (std.enums.values(Kind)) |k| if (std.mem.eql(u8, s, k.kebab())) return k;
        return null;
    }
};

pub const KindSet = std.EnumSet(Kind);

/// sui-config `ValidatorEligibility` (names sorted, unique: a BTreeSet).
pub const Eligibility = union(enum) {
    allowlist: []const Name,
    denylist: []const Name,

    pub fn isEligible(e: Eligibility, n: *const Name) bool {
        return switch (e) {
            .allowlist => |l| has(l, n),
            .denylist => |l| !has(l, n),
        };
    }

    fn has(l: []const Name, n: *const Name) bool {
        for (l) |x| if (std.mem.eql(u8, &x, n)) return true;
        return false;
    }
};

pub const Threshold = struct {
    eligibility: Eligibility = .{ .denylist = &.{} },
    /// Whole percent, 1..=100.
    stake_threshold_percent: u16,
};

pub const Ruleset = struct { name: []const u8, rules: Rules, threshold: Threshold };
pub const Bucket = struct { name: []const u8, element_kinds: KindSet, threshold: Threshold };

/// sui-config `PeerDenySyncConfig` (`peer-deny-sync-config` in validator.yaml).
pub const SyncConfig = struct {
    rulesets: []const Ruleset = &.{},
    default_buckets: []const Bucket = &.{},
    broadcast_on_startup: bool = false,
    broadcast_on_epoch_change: bool = false,

    /// `PeerDenySyncConfig::validate`: null, or Rust's error text.
    pub fn validate(c: *const SyncConfig, arena: Allocator) Allocator.Error!?[]const u8 {
        var names: std.StringHashMapUnmanaged(void) = .empty;
        for (c.rulesets) |r| {
            if (r.name.len == 0) return "rulesets entry has an empty name";
            if ((try names.getOrPut(arena, r.name)).found_existing) return try std.fmt.allocPrint(arena, "duplicate rulesets name: {s}", .{r.name});
            if (r.rules.isEmpty()) return try std.fmt.allocPrint(arena, "rulesets entry {s} has empty rules", .{r.name});
            if (try thresholdError(arena, &r.threshold, r.name)) |e| return e;
        }
        var seen: KindSet = .empty;
        for (c.default_buckets) |b| {
            if (b.name.len == 0) return "default_buckets entry has an empty name";
            if ((try names.getOrPut(arena, b.name)).found_existing) return try std.fmt.allocPrint(arena, "default_buckets name collides with another ruleset or bucket: {s}", .{b.name});
            if (b.element_kinds.count() == 0) return try std.fmt.allocPrint(arena, "default_buckets entry {s} has empty element_kinds", .{b.name});
            var it = b.element_kinds.iterator();
            while (it.next()) |k| {
                if (seen.contains(k)) return try std.fmt.allocPrint(arena, "default_buckets entry {s} claims element kind {s} already claimed by another bucket", .{ b.name, k.debugName() });
                seen.insert(k);
            }
            if (try thresholdError(arena, &b.threshold, b.name)) |e| return e;
        }
        return null;
    }

    fn thresholdError(arena: Allocator, t: *const Threshold, label: []const u8) Allocator.Error!?[]const u8 {
        if (t.stake_threshold_percent == 0 or t.stake_threshold_percent > 100)
            return try std.fmt.allocPrint(arena, "{s}: stake_threshold_percent must be 1..=100, got {d}", .{ label, t.stake_threshold_percent });
        return null;
    }
};

// ---- evaluation (evaluate_deny_configs) --------------------------------------------------------

pub const Vote = struct { name: Name, rules: *const Rules };

pub const RulesetStatus = struct { eligible_stake: u64, voted_stake: u64, voters: usize, active: bool };
pub const BucketStatus = struct { eligible_stake: u64, applied: usize };

pub const Evaluation = struct {
    /// Local rules with the activated rulesets and elements merged in: what is enforced.
    effective: Rules,
    prelisted: []RulesetStatus,
    defaults: []BucketStatus,
};

fn stakeOf(stakes: []const Member, n: *const Name) ?u64 {
    for (stakes) |m| if (std.mem.eql(u8, &m.name, n)) return m.stake;
    return null;
}

/// `meets_threshold`: voted / eligible >= percent / 100; zero eligible stake never meets one.
pub fn meetsThreshold(voted: u64, eligible: u64, percent: u16) bool {
    if (eligible == 0) return false;
    return voted *% 100 >= @as(u64, percent) *% eligible;
}

/// `eligible_stake`: the threshold's denominator. A denylist counts against the whole
/// TOTAL_VOTING_POWER (not the committee's sum).
pub fn eligibleStake(e: Eligibility, stakes: []const Member) u64 {
    var sum: u64 = 0;
    switch (e) {
        .allowlist => |l| {
            for (l) |*n| sum +%= stakeOf(stakes, n) orelse 0;
            return sum;
        },
        .denylist => |l| {
            for (l) |*n| sum +%= stakeOf(stakes, n) orelse 0;
            return total_voting_power -% sum;
        },
    }
}

fn subsetIds(small: []const Id, big: []const Id) bool {
    var j: usize = 0;
    for (small) |x| {
        while (j < big.len and std.mem.order(u8, &big[j], &x) == .lt) j += 1;
        if (j == big.len or !std.mem.eql(u8, &big[j], &x)) return false;
        j += 1;
    }
    return true;
}

fn subsetStrs(small: []const []const u8, big: []const []const u8) bool {
    var j: usize = 0;
    for (small) |x| {
        while (j < big.len and std.mem.order(u8, big[j], x) == .lt) j += 1;
        if (j == big.len or !std.mem.eql(u8, big[j], x)) return false;
        j += 1;
    }
    return true;
}

/// `TransactionDenyRules::is_superset_of` (both sides sorted sets).
pub fn isSupersetOf(a: *const Rules, b: *const Rules) bool {
    return subsetIds(b.object_deny_list, a.object_deny_list) and
        subsetIds(b.package_deny_list, a.package_deny_list) and
        subsetIds(b.address_deny_list, a.address_deny_list) and
        subsetStrs(b.zklogin_disabled_providers, a.zklogin_disabled_providers) and
        (a.package_publish_disabled or !b.package_publish_disabled) and
        (a.package_upgrade_disabled or !b.package_upgrade_disabled) and
        (a.shared_object_disabled or !b.shared_object_disabled) and
        (a.user_transaction_disabled or !b.user_transaction_disabled) and
        (a.gasless_disabled or !b.gasless_disabled) and
        (a.receiving_objects_disabled or !b.receiving_objects_disabled) and
        (a.zklogin_sig_disabled or !b.zklogin_sig_disabled);
}

pub fn rulesEql(a: *const Rules, b: *const Rules) bool {
    return isSupersetOf(a, b) and isSupersetOf(b, a);
}

const bool_kinds = [_]struct { Kind, []const u8 }{
    .{ .package_publish_disabled, "package_publish_disabled" },
    .{ .package_upgrade_disabled, "package_upgrade_disabled" },
    .{ .shared_object_disabled, "shared_object_disabled" },
    .{ .user_transaction_disabled, "user_transaction_disabled" },
    .{ .gasless_disabled, "gasless_disabled" },
    .{ .receiving_objects_disabled, "receiving_objects_disabled" },
    .{ .zklogin_sig_disabled, "zklogin_sig_disabled" },
};

/// Rules under construction: `merge` and `apply_element` append, `finish` sorts and dedups.
const Builder = struct {
    objs: std.ArrayList(Id) = .empty,
    pkgs: std.ArrayList(Id) = .empty,
    addrs: std.ArrayList(Id) = .empty,
    provs: std.ArrayList([]const u8) = .empty,
    r: Rules = .{},

    fn merge(b: *Builder, a: Allocator, o: *const Rules) Allocator.Error!void {
        try b.objs.appendSlice(a, o.object_deny_list);
        try b.pkgs.appendSlice(a, o.package_deny_list);
        try b.addrs.appendSlice(a, o.address_deny_list);
        try b.provs.appendSlice(a, o.zklogin_disabled_providers);
        inline for (bool_kinds) |bk| @field(b.r, bk[1]) = @field(b.r, bk[1]) or @field(o, bk[1]);
    }

    /// `apply_element` of an element key (see `elementKey`).
    fn apply(b: *Builder, a: Allocator, key: []const u8) Allocator.Error!void {
        const k: Kind = @enumFromInt(key[0]);
        const p = key[1..];
        switch (k) {
            .object => try b.objs.append(a, p[0..32].*),
            .package => try b.pkgs.append(a, p[0..32].*),
            .address => try b.addrs.append(a, p[0..32].*),
            .zklogin_provider => try b.provs.append(a, p),
            inline else => |bk| inline for (bool_kinds) |e| {
                if (e[0] == bk) @field(b.r, e[1]) = true;
            },
        }
    }

    fn finish(b: *Builder) Rules {
        var r = b.r;
        r.object_deny_list = sortIds(b.objs.items);
        r.package_deny_list = sortIds(b.pkgs.items);
        r.address_deny_list = sortIds(b.addrs.items);
        r.zklogin_disabled_providers = sortStrs(b.provs.items);
        return r;
    }
};

fn sortIds(l: []Id) []const Id {
    std.mem.sort(Id, l, {}, struct {
        fn lt(_: void, x: Id, y: Id) bool {
            return std.mem.order(u8, &x, &y) == .lt;
        }
    }.lt);
    var n: usize = 0;
    for (l) |x| {
        if (n > 0 and std.mem.eql(u8, &l[n - 1], &x)) continue;
        l[n] = x;
        n += 1;
    }
    return l[0..n];
}

fn sortStrs(l: [][]const u8) []const []const u8 {
    std.mem.sort([]const u8, l, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    var n: usize = 0;
    for (l) |x| {
        if (n > 0 and std.mem.eql(u8, l[n - 1], x)) continue;
        l[n] = x;
        n += 1;
    }
    return l[0..n];
}

/// A `DenyElement` as bytes: the kind, then the id or provider name.
fn elementKey(a: Allocator, k: Kind, payload: []const u8) Allocator.Error![]const u8 {
    const out = try a.alloc(u8, 1 + payload.len);
    out[0] = @intFromEnum(k);
    @memcpy(out[1..], payload);
    return out;
}

/// `evaluate_deny_configs`. `votes` are the members' proposals (one per name); a vote whose name
/// has no stake counts for nothing.
pub fn evaluate(a: Allocator, local: *const Rules, sync: *const SyncConfig, votes: []const Vote, stakes: []const Member) Allocator.Error!Evaluation {
    const pre = try a.alloc(RulesetStatus, sync.rulesets.len);
    for (sync.rulesets, pre) |*rs, *st| {
        const eligible = eligibleStake(rs.threshold.eligibility, stakes);
        var voted: u64 = 0;
        var voters: usize = 0;
        for (votes) |*v| {
            const stake = stakeOf(stakes, &v.name) orelse continue;
            if (rs.threshold.eligibility.isEligible(&v.name) and isSupersetOf(v.rules, &rs.rules)) {
                voted +%= stake;
                voters += 1;
            }
        }
        st.* = .{ .eligible_stake = eligible, .voted_stake = voted, .voters = voters, .active = meetsThreshold(voted, eligible, rs.threshold.stake_threshold_percent) };
    }

    // per bucket: element -> stake of the eligible voters proposing it
    const per = try a.alloc(std.StringArrayHashMapUnmanaged(u64), sync.default_buckets.len);
    for (per) |*m| m.* = .empty;
    for (votes) |*v| {
        const stake = stakeOf(stakes, &v.name) orelse continue;
        const r = v.rules;
        var keys: std.ArrayList([]const u8) = .empty;
        for (r.object_deny_list) |*id| try keys.append(a, try elementKey(a, .object, id));
        for (r.package_deny_list) |*id| try keys.append(a, try elementKey(a, .package, id));
        for (r.address_deny_list) |*id| try keys.append(a, try elementKey(a, .address, id));
        for (r.zklogin_disabled_providers) |p| try keys.append(a, try elementKey(a, .zklogin_provider, p));
        inline for (bool_kinds) |bk| if (@field(r, bk[1])) try keys.append(a, try elementKey(a, bk[0], ""));
        for (keys.items) |key| {
            const kind: Kind = @enumFromInt(key[0]);
            const bi = for (sync.default_buckets, 0..) |*b, i| {
                if (b.element_kinds.contains(kind)) break i;
            } else continue;
            if (!sync.default_buckets[bi].threshold.eligibility.isEligible(&v.name)) continue;
            const gop = try per[bi].getOrPut(a, key);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* +%= stake;
        }
    }

    var b: Builder = .{};
    try b.merge(a, local);
    for (sync.rulesets, pre) |*rs, st| if (st.active) try b.merge(a, &rs.rules);
    const defs = try a.alloc(BucketStatus, sync.default_buckets.len);
    for (sync.default_buckets, per, defs) |*bk, m, *st| {
        const eligible = eligibleStake(bk.threshold.eligibility, stakes);
        var applied: usize = 0;
        var it = m.iterator();
        while (it.next()) |e| if (meetsThreshold(e.value_ptr.*, eligible, bk.threshold.stake_threshold_percent)) {
            try b.apply(a, e.key_ptr.*);
            applied += 1;
        };
        st.* = .{ .eligible_stake = eligible, .applied = applied };
    }
    return .{ .effective = b.finish(), .prelisted = pre, .defaults = defs };
}

// ---- wire rules <-> local rules ----------------------------------------------------------------

/// The rules of a shared message as Rust holds them after deserialization (sets sorted, unique).
pub fn fromWire(a: Allocator, w: *const messages.TransactionDenyRules) Allocator.Error!Rules {
    const n = try tx_validator.normalizedDenyRules(a, w);
    var r: Rules = .{};
    const objs = try a.alloc(Id, n.object_deny_list.len);
    for (n.object_deny_list, objs) |x, *o| o.* = std.mem.asBytes(&x)[0..32].*;
    const pkgs = try a.alloc(Id, n.package_deny_list.len);
    for (n.package_deny_list, pkgs) |x, *o| o.* = std.mem.asBytes(&x)[0..32].*;
    const addrs = try a.alloc(Id, n.address_deny_list.len);
    for (n.address_deny_list, addrs) |x, *o| o.* = x.@"0";
    const provs = try a.alloc([]const u8, n.zklogin_disabled_providers.len);
    for (n.zklogin_disabled_providers, provs) |x, *o| o.* = x.@"0";
    r.object_deny_list = objs;
    r.package_deny_list = pkgs;
    r.address_deny_list = addrs;
    r.zklogin_disabled_providers = provs;
    inline for (bool_kinds) |bk| @field(r, bk[1]) = @field(n, bk[1]);
    return r;
}

pub fn toWire(a: Allocator, r: *const Rules) Allocator.Error!messages.TransactionDenyRules {
    const objs = try a.alloc(types.ObjectID, r.object_deny_list.len);
    for (r.object_deny_list, objs) |x, *o| o.* = std.mem.bytesToValue(types.ObjectID, &x);
    const pkgs = try a.alloc(types.ObjectID, r.package_deny_list.len);
    for (r.package_deny_list, pkgs) |x, *o| o.* = std.mem.bytesToValue(types.ObjectID, &x);
    const addrs = try a.alloc(types.SuiAddress, r.address_deny_list.len);
    for (r.address_deny_list, addrs) |x, *o| o.* = .{ .@"0" = x };
    const provs = try a.alloc(bcs.String, r.zklogin_disabled_providers.len);
    for (r.zklogin_disabled_providers, provs) |x, *o| o.* = .{ .@"0" = x };
    var w: messages.TransactionDenyRules = .{
        .object_deny_list = objs,
        .package_deny_list = pkgs,
        .address_deny_list = addrs,
        .zklogin_disabled_providers = provs,
        .package_publish_disabled = false,
        .package_upgrade_disabled = false,
        .shared_object_disabled = false,
        .user_transaction_disabled = false,
        .gasless_disabled = false,
        .receiving_objects_disabled = false,
        .zklogin_sig_disabled = false,
    };
    inline for (bool_kinds) |bk| @field(w, bk[1]) = @field(r, bk[1]);
    return w;
}

/// `TransactionDenyRules::check_share_limits().is_ok()`.
pub fn shareLimitsOk(a: Allocator, r: *const Rules) Allocator.Error!bool {
    const w = try toWire(a, r);
    return tx_validator.denyShareLimitsOk(a, &w);
}

// ---- startup / epoch-change broadcast (sui-node monitor_reconfiguration) -----------------------

pub const BroadcastAction = enum { broadcast, withdraw, skip };

/// `deny_config_broadcast_payload`: broadcast the local rules (an empty config withdraws) when
/// configured to and they fit the share limits; at startup, withdraw a possibly stale earlier
/// broadcast otherwise.
pub fn broadcastPayload(a: Allocator, local: *const Rules, broadcast: bool, is_startup: bool, may_have_prior: bool) Allocator.Error!BroadcastAction {
    const shareable = local.isEmpty() or try shareLimitsOk(a, local);
    if (broadcast and shareable) return if (local.isEmpty()) .withdraw else .broadcast;
    if (is_startup and may_have_prior) return .withdraw;
    return .skip;
}

// ---- the manager -------------------------------------------------------------------------------

pub const Options = struct {
    self_name: Name,
    /// The operator's transaction-deny-config: always applied. Must outlive the manager.
    local: *const txdeny.Config,
    sync: SyncConfig = .{},
    /// The committee at startup (`update_for_committee` replaces it each epoch).
    committee: []const Member,
    /// Where the effective config is published (`txdeny.effective_slot` in the validator).
    slot: *txdeny.Slot,
    /// The persistence file; null keeps everything in memory.
    path: ?[]const u8 = null,
    io: ?std.Io = null,
    /// Wall clock, ms since the Unix epoch (`AuthorityState::unixtime_now_ms`).
    now_ms: *const fn () u64,
};

const Row = struct { generation: u64, has_rules: bool, bytes: []u8 };

pub const Manager = struct {
    gpa: Allocator,
    opts: Options,
    /// peers, dormant, committee, effective, last_broadcast.
    lock: Spin = .{},
    /// Serializes the writers (and the file writes).
    write_lock: Spin = .{},
    /// Latest accepted proposal per member (BCS SharedTransactionDenyConfig, gpa-owned).
    peers: std.AutoArrayHashMapUnmanaged(Name, Row) = .empty,
    /// Stored rows that do not vote: this validator's own row and non-members at load.
    dormant: std.AutoArrayHashMapUnmanaged(Name, []u8) = .empty,
    committee: []Member = &.{},
    effective_arena: std.heap.ArenaAllocator,
    effective: Rules = .{},
    last_broadcast: ?u64 = null,

    pub const Error = error{ OutOfMemory, BadSyncConfig, Corrupt, Io, ShareLimits, Overloaded, EpochEnding, Unimplemented };

    /// `TransactionDenyConfigManager::new`.
    pub fn create(gpa: Allocator, opts: Options) Error!*Manager {
        {
            var ar = std.heap.ArenaAllocator.init(gpa);
            defer ar.deinit();
            if (try opts.sync.validate(ar.allocator())) |why| {
                log.err("peer-deny-sync-config: {s}", .{why});
                return error.BadSyncConfig;
            }
        }
        const m = try gpa.create(Manager);
        errdefer gpa.destroy(m);
        m.* = .{ .gpa = gpa, .opts = opts, .effective_arena = .init(gpa) };
        errdefer m.destroyInner();
        m.committee = try gpa.dupe(Member, opts.committee);
        try m.load();
        var ar = std.heap.ArenaAllocator.init(gpa);
        defer ar.deinit();
        try m.reevaluate(ar.allocator(), true);
        return m;
    }

    fn destroyInner(m: *Manager) void {
        for (m.peers.values()) |r| m.gpa.free(r.bytes);
        m.peers.deinit(m.gpa);
        for (m.dormant.values()) |b| m.gpa.free(b);
        m.dormant.deinit(m.gpa);
        m.gpa.free(m.committee);
        m.effective_arena.deinit();
    }

    pub fn destroy(m: *Manager) void {
        m.destroyInner();
        m.gpa.destroy(m);
    }

    fn inCommittee(m: *const Manager, n: *const Name) bool {
        for (m.committee) |c| if (std.mem.eql(u8, &c.name, n)) return true;
        return false;
    }

    fn rowOf(gpa: Allocator, msg: *const messages.SharedTransactionDenyConfig) Allocator.Error!struct { Name, Row } {
        const v = switch (msg.*) {
            .V1 => |x| x,
        };
        return .{ v.authority.@"0", .{ .generation = v.generation, .has_rules = v.rules != null, .bytes = try bcs.encodeAlloc(messages.SharedTransactionDenyConfig, gpa, msg) } };
    }

    /// `apply_updates`: `from` is the authority that sequenced the messages (block author).
    pub fn applyUpdates(m: *Manager, from: *const Name, msgs: []const messages.SharedTransactionDenyConfig) void {
        if (msgs.len == 0) return;
        const max_generation = m.opts.now_ms() +| max_generation_future_drift_ms;
        m.write_lock.lock();
        defer m.write_lock.unlock();
        var ar = std.heap.ArenaAllocator.init(m.gpa);
        defer ar.deinit();
        m.lock.lock();
        var accepted = false;
        for (msgs) |*msg| {
            const v = switch (msg.*) {
                .V1 => |x| x,
            };
            const name = &v.authority.@"0";
            if (!std.mem.eql(u8, name, from)) {
                log.warn("dropping UpdateTransactionDenyConfig: claimed authority does not match sender", .{});
                continue;
            }
            if (!m.inCommittee(name)) {
                log.info("dropping UpdateTransactionDenyConfig: sender not in committee", .{});
                continue;
            }
            if (v.generation > max_generation) {
                log.warn("dropping UpdateTransactionDenyConfig: generation {d} too far in the future", .{v.generation});
                continue;
            }
            if (m.peers.get(name.*)) |ex| if (ex.generation >= v.generation) continue;
            const row = rowOf(m.gpa, msg) catch {
                log.err("deny sync: out of memory", .{});
                continue;
            };
            const gop = m.peers.getOrPut(m.gpa, row[0]) catch {
                m.gpa.free(row[1].bytes);
                log.err("deny sync: out of memory", .{});
                continue;
            };
            if (gop.found_existing) m.gpa.free(gop.value_ptr.bytes);
            gop.value_ptr.* = row[1];
            if (m.dormant.fetchSwapRemove(row[0])) |d| m.gpa.free(d.value);
            accepted = true;
        }
        if (!accepted) {
            m.lock.unlock();
            return;
        }
        m.reevaluate(ar.allocator(), false) catch log.err("deny sync: evaluation out of memory", .{});
        const file = m.encodeFile(ar.allocator()) catch null;
        m.lock.unlock();
        if (file) |f| m.persist(f);
    }

    /// `update_for_committee`: a new epoch's committee; members that left are dropped (and
    /// their rows removed), the effective config is re-evaluated with the new stakes.
    pub fn updateForCommittee(m: *Manager, committee: []const Member) Error!void {
        m.write_lock.lock();
        defer m.write_lock.unlock();
        var ar = std.heap.ArenaAllocator.init(m.gpa);
        defer ar.deinit();
        const copy = try m.gpa.dupe(Member, committee);
        m.lock.lock();
        m.gpa.free(m.committee);
        m.committee = copy;
        var i: usize = 0;
        while (i < m.peers.count()) {
            if (m.inCommittee(&m.peers.keys()[i])) {
                i += 1;
                continue;
            }
            m.gpa.free(m.peers.values()[i].bytes);
            m.peers.swapRemoveAt(i);
        }
        const r = m.reevaluate(ar.allocator(), false);
        const file = m.encodeFile(ar.allocator()) catch null;
        m.lock.unlock();
        try r;
        if (file) |f| m.persist(f);
    }

    /// `may_have_outstanding_broadcast`.
    pub fn mayHaveOutstandingBroadcast(m: *Manager) bool {
        m.lock.lock();
        defer m.lock.unlock();
        return m.last_broadcast != null;
    }

    /// `allocate_next_broadcast_generation`: strictly increasing across restarts, reset to the
    /// clock when the stored one is too far ahead; persisted before it is used.
    pub fn allocateNextBroadcastGeneration(m: *Manager) Error!u64 {
        m.write_lock.lock();
        defer m.write_lock.unlock();
        var ar = std.heap.ArenaAllocator.init(m.gpa);
        defer ar.deinit();
        const now = m.opts.now_ms();
        m.lock.lock();
        const last = m.last_broadcast orelse 0;
        var generation = @max(now, last +| 1);
        if (generation > now +| max_generation_future_drift_ms) {
            log.warn("stored deny broadcast generation {d} is too far ahead; resetting to {d}", .{ last, now });
            generation = now;
        }
        m.last_broadcast = generation;
        const file = m.encodeFile(ar.allocator()) catch null;
        m.lock.unlock();
        if (file) |f| {
            if (m.opts.path != null and !m.writeFile(f)) return error.Io;
        }
        return generation;
    }

    /// `submit_broadcast`: shares `rules` (null withdraws) through consensus, then applies the
    /// message locally (a validator does not verify its own blocks).
    pub fn submitBroadcast(m: *Manager, rules: ?*const Rules, submit: iface.ConsensusSubmit, tracking_id: [8]u8) Error!u64 {
        var ar = std.heap.ArenaAllocator.init(m.gpa);
        defer ar.deinit();
        const a = ar.allocator();
        var wire: ?messages.TransactionDenyRules = null;
        if (rules) |r| {
            if (!try shareLimitsOk(a, r)) return error.ShareLimits;
            wire = try toWire(a, r);
        }
        const generation = try m.allocateNextBroadcastGeneration();
        const msg: messages.SharedTransactionDenyConfig = .{ .V1 = .{ .authority = .{ .@"0" = m.opts.self_name }, .generation = generation, .rules = wire } };
        const tx: messages.ConsensusTransaction = .{ .tracking_id = tracking_id, .kind = .{ .UpdateTransactionDenyConfig = msg } };
        const body = try bcs.encodeAlloc(messages.ConsensusTransaction, a, &tx);
        submit.submit(&.{body}, .system) catch |e| return switch (e) {
            error.Overloaded => error.Overloaded,
            error.EpochEnding => error.EpochEnding,
            error.Unimplemented => error.Unimplemented,
        };
        m.applyUpdates(&m.opts.self_name, &.{msg});
        return generation;
    }

    /// sui-node's reconciliation after the epoch's capability notification: `is_startup` for
    /// the first epoch this process runs as a validator with the flag on.
    pub fn reconcile(m: *Manager, submit: iface.ConsensusSubmit, tracking_id: [8]u8, is_startup: bool) void {
        var ar = std.heap.ArenaAllocator.init(m.gpa);
        defer ar.deinit();
        const broadcast = if (is_startup) m.opts.sync.broadcast_on_startup else m.opts.sync.broadcast_on_epoch_change;
        const local = &m.opts.local.rules;
        const action = broadcastPayload(ar.allocator(), local, broadcast, is_startup, m.mayHaveOutstandingBroadcast()) catch return;
        const r = switch (action) {
            .skip => return,
            .broadcast => m.submitBroadcast(local, submit, tracking_id),
            .withdraw => m.submitBroadcast(null, submit, tracking_id),
        };
        if (r) |_| {} else |e| log.warn("failed to broadcast transaction deny config: {s}", .{@errorName(e)});
    }

    /// The effective rules now (copied into `a`).
    pub fn effectiveRules(m: *Manager, a: Allocator) Allocator.Error!Rules {
        m.lock.lock();
        defer m.lock.unlock();
        return txdeny.cloneRules(a, &m.effective);
    }

    pub const PeerView = struct { name: Name, generation: u64, rules: ?Rules };

    /// The voting rows, sorted by name (`peer_configs_snapshot`).
    pub fn peerSnapshot(m: *Manager, a: Allocator) Error![]PeerView {
        m.lock.lock();
        defer m.lock.unlock();
        const out = try a.alloc(PeerView, m.peers.count());
        for (m.peers.keys(), m.peers.values(), out) |k, r, *o| {
            const msg = bcs.decode(messages.SharedTransactionDenyConfig, a, r.bytes) catch return error.Corrupt;
            const v = switch (msg) {
                .V1 => |x| x,
            };
            o.* = .{ .name = k, .generation = r.generation, .rules = if (v.rules) |*w| try fromWire(a, w) else null };
        }
        std.mem.sort(PeerView, out, {}, struct {
            fn lt(_: void, x: PeerView, y: PeerView) bool {
                return std.mem.order(u8, &x.name, &y.name) == .lt;
            }
        }.lt);
        return out;
    }

    /// `evaluate` + `apply_evaluation` (under `lock`): publishes when the rules changed.
    fn reevaluate(m: *Manager, a: Allocator, force: bool) Error!void {
        var votes: std.ArrayList(Vote) = .empty;
        for (m.peers.keys(), m.peers.values()) |k, r| {
            if (!r.has_rules or !m.inCommittee(&k)) continue;
            const msg = bcs.decode(messages.SharedTransactionDenyConfig, a, r.bytes) catch return error.Corrupt;
            const w = switch (msg) {
                .V1 => |x| x.rules.?,
            };
            const rules = try a.create(Rules);
            rules.* = try fromWire(a, &w);
            try votes.append(a, .{ .name = k, .rules = rules });
        }
        const ev = try evaluate(a, &m.opts.local.rules, &m.opts.sync, votes.items, m.committee);
        if (!force and rulesEql(&ev.effective, &m.effective)) return;
        const snap = try txdeny.newSnapshot(m.gpa, m.opts.local, &ev.effective);
        var fresh = std.heap.ArenaAllocator.init(m.gpa);
        const copy = txdeny.cloneRules(fresh.allocator(), &ev.effective) catch |e| {
            fresh.deinit();
            snap.arena.deinit();
            m.gpa.destroy(snap);
            return e;
        };
        m.effective_arena.deinit();
        m.effective_arena = fresh;
        m.effective = copy;
        m.opts.slot.publish(snap);
    }

    // ---- persistence: "ZDS1", u8 has_last, u64 last, u32 n, n x (u32 len, BCS message)

    const magic = "ZDS1";

    fn load(m: *Manager) Error!void {
        const path = m.opts.path orelse return;
        const io = m.opts.io orelse return;
        const raw = (@import("../keys/fsutil.zig").readAll(m.gpa, io, path, 1 << 30) catch return error.Io) orelse return;
        defer m.gpa.free(raw);
        if (raw.len < 17 or !std.mem.eql(u8, raw[0..4], magic)) return error.Corrupt;
        if (raw[4] == 1) m.last_broadcast = std.mem.readInt(u64, raw[5..13], .little);
        const n = std.mem.readInt(u32, raw[13..17], .little);
        var off: usize = 17;
        var ar = std.heap.ArenaAllocator.init(m.gpa);
        defer ar.deinit();
        for (0..n) |_| {
            if (off + 4 > raw.len) return error.Corrupt;
            const len = std.mem.readInt(u32, raw[off..][0..4], .little);
            off += 4;
            if (off + len > raw.len) return error.Corrupt;
            const bytes = raw[off .. off + len];
            off += len;
            const msg = bcs.decode(messages.SharedTransactionDenyConfig, ar.allocator(), bytes) catch return error.Corrupt;
            const v = switch (msg) {
                .V1 => |x| x,
            };
            const name = v.authority.@"0";
            const owned = try m.gpa.dupe(u8, bytes);
            if (std.mem.eql(u8, &name, &m.opts.self_name) or !m.inCommittee(&name)) {
                const gop = try m.dormant.getOrPut(m.gpa, name);
                if (gop.found_existing) m.gpa.free(gop.value_ptr.*);
                gop.value_ptr.* = owned;
            } else {
                const gop = try m.peers.getOrPut(m.gpa, name);
                if (gop.found_existing) m.gpa.free(gop.value_ptr.bytes);
                gop.value_ptr.* = .{ .generation = v.generation, .has_rules = v.rules != null, .bytes = owned };
            }
        }
    }

    fn encodeFile(m: *const Manager, a: Allocator) Allocator.Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(a, magic);
        try out.append(a, @intFromBool(m.last_broadcast != null));
        var b8: [8]u8 = undefined;
        std.mem.writeInt(u64, &b8, m.last_broadcast orelse 0, .little);
        try out.appendSlice(a, &b8);
        var b4: [4]u8 = undefined;
        std.mem.writeInt(u32, &b4, @intCast(m.peers.count() + m.dormant.count()), .little);
        try out.appendSlice(a, &b4);
        for (m.peers.values()) |r| {
            std.mem.writeInt(u32, &b4, @intCast(r.bytes.len), .little);
            try out.appendSlice(a, &b4);
            try out.appendSlice(a, r.bytes);
        }
        for (m.dormant.values()) |b| {
            std.mem.writeInt(u32, &b4, @intCast(b.len), .little);
            try out.appendSlice(a, &b4);
            try out.appendSlice(a, b);
        }
        return out.items;
    }

    fn writeFile(m: *Manager, bytes: []const u8) bool {
        const path = m.opts.path orelse return true;
        const io = m.opts.io orelse return true;
        @import("../keys/fsutil.zig").writeAtomic(io, path, bytes) catch {
            log.err("deny sync: writing {s} failed", .{path});
            return false;
        };
        return true;
    }

    fn persist(m: *Manager, bytes: []const u8) void {
        _ = m.writeFile(bytes);
    }
};

// ---- tests ---------------------------------------------------------------------------------------

const testing = std.testing;

fn nm(b: u8) Name {
    return @splat(b);
}

fn oid(b: u8) Id {
    var x: Id = @splat(0);
    x[31] = b;
    return x;
}

var test_clock: u64 = 1_000_000;
fn testNow() u64 {
    return test_clock;
}

fn wireMsg(a: Allocator, who: u8, generation: u64, rules: ?Rules) !messages.SharedTransactionDenyConfig {
    return .{ .V1 = .{ .authority = .{ .@"0" = nm(who) }, .generation = generation, .rules = if (rules) |r| try toWire(a, &r) else null } };
}

test "deny manager: thresholds, stale and future generations, withdrawal, committee change" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const committee = [_]Member{ .{ .name = nm(1), .stake = 2500 }, .{ .name = nm(2), .stake = 2500 }, .{ .name = nm(3), .stake = 2500 }, .{ .name = nm(4), .stake = 2500 } };
    const rs_rules: Rules = .{ .object_deny_list = &.{oid(7)} };
    const sync: SyncConfig = .{ .rulesets = &.{.{ .name = "r", .rules = rs_rules, .threshold = .{ .stake_threshold_percent = 50 } }} };
    const local: txdeny.Config = .{ .rules = .{ .package_publish_disabled = true } };
    var slot: txdeny.Slot = .{};
    defer slot.publish(null);
    const m = try Manager.create(testing.allocator, .{ .self_name = nm(1), .local = &local, .sync = sync, .committee = &committee, .slot = &slot, .now_ms = testNow });
    defer m.destroy();

    var g = slot.acquire();
    try testing.expect(g.config().rules.package_publish_disabled);
    try testing.expectEqual(@as(usize, 0), g.config().rules.object_deny_list.len);
    g.release();

    const vote: Rules = .{ .object_deny_list = &.{ oid(7), oid(8) } };
    m.applyUpdates(&nm(2), &.{try wireMsg(a, 2, 10, vote)});
    try testing.expectEqual(@as(usize, 0), (try m.effectiveRules(a)).object_deny_list.len); // 25% < 50%
    // claimed authority 3, sequenced by 2: dropped
    m.applyUpdates(&nm(2), &.{try wireMsg(a, 3, 10, vote)});
    try testing.expectEqual(@as(usize, 0), (try m.effectiveRules(a)).object_deny_list.len);
    // generation beyond now + 60 s: dropped
    m.applyUpdates(&nm(3), &.{try wireMsg(a, 3, test_clock + max_generation_future_drift_ms + 1, vote)});
    try testing.expectEqual(@as(usize, 0), (try m.effectiveRules(a)).object_deny_list.len);
    m.applyUpdates(&nm(3), &.{try wireMsg(a, 3, test_clock + max_generation_future_drift_ms, vote)});
    g = slot.acquire();
    try testing.expectEqual(@as(usize, 1), g.config().rules.object_deny_list.len); // 50%: the ruleset only
    try testing.expect(g.config().rules.package_publish_disabled);
    g.release();
    // stale generation from 2 (withdrawal at the same generation): ignored
    m.applyUpdates(&nm(2), &.{try wireMsg(a, 2, 10, null)});
    try testing.expectEqual(@as(usize, 1), (try m.effectiveRules(a)).object_deny_list.len);
    // newer withdrawal: below threshold again
    m.applyUpdates(&nm(2), &.{try wireMsg(a, 2, 11, null)});
    try testing.expectEqual(@as(usize, 0), (try m.effectiveRules(a)).object_deny_list.len);
    // 3 leaves the committee: its row goes
    try m.updateForCommittee(committee[0..2]);
    try testing.expectEqual(@as(usize, 1), (try m.peerSnapshot(a)).len);
}

test "deny manager: default buckets per element, eligibility, broadcast payload" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const stakes = [_]Member{ .{ .name = nm(1), .stake = 4000 }, .{ .name = nm(2), .stake = 3000 }, .{ .name = nm(3), .stake = 3000 } };
    var kinds: KindSet = .empty;
    kinds.insert(.object);
    kinds.insert(.user_transaction_disabled);
    const sync: SyncConfig = .{ .default_buckets = &.{.{ .name = "d", .element_kinds = kinds, .threshold = .{ .eligibility = .{ .denylist = &.{nm(1)} }, .stake_threshold_percent = 100 } }} };
    const v2: Rules = .{ .object_deny_list = &.{ oid(1), oid(2) }, .package_deny_list = &.{oid(9)}, .user_transaction_disabled = true };
    const v3: Rules = .{ .object_deny_list = &.{oid(2)}, .user_transaction_disabled = true };
    const v1: Rules = .{ .object_deny_list = &.{oid(1)} };
    const ev = try evaluate(a, &.{}, &sync, &.{ .{ .name = nm(1), .rules = &v1 }, .{ .name = nm(2), .rules = &v2 }, .{ .name = nm(3), .rules = &v3 } }, &stakes);
    // eligible = 10000 - 4000; oid(2) and user_transaction_disabled have 6000, oid(1) only 3000
    try testing.expectEqual(@as(u64, 6000), ev.defaults[0].eligible_stake);
    try testing.expectEqual(@as(usize, 1), ev.effective.object_deny_list.len);
    try testing.expectEqualSlices(u8, &oid(2), &ev.effective.object_deny_list[0]);
    try testing.expect(ev.effective.user_transaction_disabled);
    try testing.expectEqual(@as(usize, 0), ev.effective.package_deny_list.len);

    try testing.expectEqual(BroadcastAction.withdraw, try broadcastPayload(a, &.{}, true, true, false));
    try testing.expectEqual(BroadcastAction.broadcast, try broadcastPayload(a, &.{ .package_publish_disabled = true }, true, false, false));
    try testing.expectEqual(BroadcastAction.withdraw, try broadcastPayload(a, &.{ .package_publish_disabled = true }, false, true, true));
    try testing.expectEqual(BroadcastAction.skip, try broadcastPayload(a, &.{ .package_publish_disabled = true }, false, false, true));
    const long = try a.alloc(u8, 257);
    @memset(long, 'x');
    const providers = [_][]const u8{long};
    try testing.expectEqual(BroadcastAction.skip, try broadcastPayload(a, &.{ .zklogin_disabled_providers = &providers }, true, false, false));
}

const Capture = struct {
    got: std.ArrayList([]u8) = .empty,
    fn submit(ctx: *anyopaque, txs: []const []const u8, _: iface.ConsensusSubmit.Priority) iface.ConsensusSubmit.Error!void {
        const c: *Capture = @ptrCast(@alignCast(ctx));
        for (txs) |t| c.got.append(testing.allocator, testing.allocator.dupe(u8, t) catch return error.Overloaded) catch return error.Overloaded;
    }
    const vt: iface.ConsensusSubmit.VTable = .{ .submit = submit };
};

test "deny manager: own broadcast is submitted, applied locally and its generation persists" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pbuf[0..try tmp.dir.realPath(testing.io, &pbuf)];
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/deny-sync", .{dir});
    defer testing.allocator.free(path);

    const committee = [_]Member{ .{ .name = nm(1), .stake = 5000 }, .{ .name = nm(2), .stake = 5000 } };
    const local: txdeny.Config = .{ .rules = .{ .shared_object_disabled = true } };
    var kinds: KindSet = .empty;
    kinds.insert(.shared_object_disabled);
    const sync: SyncConfig = .{ .default_buckets = &.{.{ .name = "d", .element_kinds = kinds, .threshold = .{ .stake_threshold_percent = 100 } }}, .broadcast_on_startup = true };
    var slot: txdeny.Slot = .{};
    defer slot.publish(null);
    var cap: Capture = .{};
    defer {
        for (cap.got.items) |t| testing.allocator.free(t);
        cap.got.deinit(testing.allocator);
    }
    {
        const m = try Manager.create(testing.allocator, .{ .self_name = nm(1), .local = &local, .sync = sync, .committee = &committee, .slot = &slot, .path = path, .io = testing.io, .now_ms = testNow });
        defer m.destroy();
        try testing.expect(!m.mayHaveOutstandingBroadcast());
        m.reconcile(.{ .ctx = &cap, .vtable = &Capture.vt }, @splat(0), true);
        try testing.expectEqual(@as(usize, 1), cap.got.items.len);
        try testing.expect(m.mayHaveOutstandingBroadcast());
        var par = std.heap.ArenaAllocator.init(testing.allocator);
        defer par.deinit();
        const peers = try m.peerSnapshot(par.allocator());
        try testing.expectEqual(@as(usize, 1), peers.len);
        try testing.expectEqual(test_clock, peers[0].generation);
    }
    {
        // restart: the own row is not voted, the generation counter carries on
        const m = try Manager.create(testing.allocator, .{ .self_name = nm(1), .local = &local, .sync = sync, .committee = &committee, .slot = &slot, .path = path, .io = testing.io, .now_ms = testNow });
        defer m.destroy();
        try testing.expect(m.mayHaveOutstandingBroadcast());
        var par = std.heap.ArenaAllocator.init(testing.allocator);
        defer par.deinit();
        try testing.expectEqual(@as(usize, 0), (try m.peerSnapshot(par.allocator())).len);
        try testing.expectEqual(test_clock + 1, try m.allocateNextBroadcastGeneration());
    }
}
