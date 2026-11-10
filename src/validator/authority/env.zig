//! What the handler, validator and adapter read about the running epoch: protocol parameters
//! extracted from the protocol config (so the logic is testable without a full ProtocolConfig),
//! and the reconfiguration control the epoch lane implements (`EpochControl`), with a small
//! in-memory implementation (`LocalEpochControl`) for tests and the local committee harness.
const std = @import("std");
const protocol = @import("protocol");
const versions = @import("versions.zig");

pub const Id = [32]u8;

pub const Params = struct {
    epoch: u64,
    epoch_start_ms: u64,
    rgp: u64,
    ordering_by_gas_price: bool = false,
    defer_unpaid_amplification: bool = false,
    defer_owned_object_double_spend: bool = false,
    merge_colliding_deferrals: bool = false,
    max_deferral_rounds: u64 = 0,
    congestion: protocol.ExecutionTimeEstimateParams = .{},
    /// max_accumulated_txn_cost_per_object_in_mysticeti_commit (None = 0)
    per_commit_budget: u64 = 0,
    /// randomness variant, defaulting to `per_commit_budget`
    per_commit_budget_randomness: u64 = 0,
    max_tx_per_checkpoint: u64 = 10_000,
    min_checkpoint_interval_ms: u64 = 0,
    record_additional_state_digest: bool = false,
    commit_rate_window: u32 = 0,
    randomness_state_enabled: bool = false,
    allowed_proposers: bool = false,
    epoch_close_deadline_ms: ?u64 = null,
    /// Epoch start configuration: initial shared versions of the system objects.
    authenticator_isv: ?u64 = null,
    randomness_isv: ?u64 = null,
    implicit: versions.Implicit = .{},
    accumulators_enabled: bool = false,
    max_programmable_tx_commands: u64 = 1024,
    consensus_max_transaction_size_bytes: u64 = 262144,
    mode_is_execution_time_estimate: bool = true,

    /// Mirrors the reads `ConsensusHandler` and `AuthorityPerEpochStore` make of the config.
    pub fn fromProtocol(cfg: *const protocol.ProtocolConfig, epoch: u64, epoch_start_ms: u64, rgp: u64) Params {
        var p: Params = .{ .epoch = epoch, .epoch_start_ms = epoch_start_ms, .rgp = rgp };
        const ff = &cfg.feature_flags;
        p.ordering_by_gas_price = ff.consensus_transaction_ordering == .ByGasPrice;
        p.defer_unpaid_amplification = ff.defer_unpaid_amplification;
        p.defer_owned_object_double_spend = ff.defer_owned_object_double_spend;
        p.merge_colliding_deferrals = ff.merge_colliding_deferrals;
        p.max_deferral_rounds = cfg.max_deferral_rounds_for_congestion_control orelse 0;
        switch (ff.per_object_congestion_control_mode) {
            .ExecutionTimeEstimate => |e| p.congestion = e,
            else => p.mode_is_execution_time_estimate = false,
        }
        p.per_commit_budget = cfg.max_accumulated_txn_cost_per_object_in_mysticeti_commit orelse 0;
        p.per_commit_budget_randomness = cfg.max_accumulated_randomness_txn_cost_per_object_in_mysticeti_commit orelse p.per_commit_budget;
        p.max_tx_per_checkpoint = cfg.max_transactions_per_checkpoint orelse 10_000;
        p.min_checkpoint_interval_ms = cfg.min_checkpoint_interval_ms orelse 0;
        p.record_additional_state_digest = ff.record_additional_state_digest_in_prologue;
        p.commit_rate_window = cfg.consensus_commit_rate_estimation_window_size orelse 0;
        p.randomness_state_enabled = ff.random_beacon;
        p.allowed_proposers = ff.allowed_proposers;
        p.epoch_close_deadline_ms = cfg.epoch_close_deadline_ms;
        p.accumulators_enabled = ff.enable_accumulators;
        p.max_programmable_tx_commands = cfg.max_programmable_tx_commands orelse 1024;
        p.consensus_max_transaction_size_bytes = cfg.consensus_max_transaction_size_bytes orelse 262144;
        return p;
    }
};

/// `ReconfigState` (epoch/reconfiguration.rs): the states of closing an epoch.
pub const ReconfigStatus = enum { accept_all_certs, reject_user_certs, reject_all_certs, reject_all_tx };

pub const ReconfigState = struct {
    status: ReconfigStatus = .accept_all_certs,

    pub fn shouldAcceptUserCerts(r: ReconfigState) bool {
        return r.status == .accept_all_certs;
    }
    pub fn shouldAcceptConsensusCerts(r: ReconfigState) bool {
        return r.status == .accept_all_certs or r.status == .reject_user_certs;
    }
    pub fn shouldAcceptTx(r: ReconfigState) bool {
        return r.status != .reject_all_tx;
    }
    pub fn isRejectAllTx(r: ReconfigState) bool {
        return r.status == .reject_all_tx;
    }
    pub fn closeAllCerts(r: *ReconfigState) void {
        if (r.status != .reject_all_tx) r.status = .reject_all_certs;
    }
    pub fn closeAllTx(r: *ReconfigState) void {
        r.status = .reject_all_tx;
    }
    pub fn closeUserCerts(r: *ReconfigState) void {
        if (r.status == .accept_all_certs) r.status = .reject_user_certs;
    }
};

/// The epoch lane's side (val-epoch-api-keys implements it over the real epoch store). The
/// consensus handler calls it on the handler thread only.
pub const EpochControl = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        reconfig_state: *const fn (ctx: *anyopaque) ReconfigState,
        /// Persisted with the commit by the epoch lane (the handler passes the new value).
        store_reconfig_state: *const fn (ctx: *anyopaque, state: ReconfigState) void,
        has_received_end_of_publish_from: *const fn (ctx: *anyopaque, authority_index: u32) bool,
        /// Records an EndOfPublish; true when stake quorum is reached (now or already).
        record_end_of_publish: *const fn (ctx: *anyopaque, authority_index: u32) bool,
        has_end_of_publish_quorum: *const fn (ctx: *anyopaque) bool,
        next_reconfiguration_timestamp_ms: *const fn (ctx: *anyopaque) u64,
    };

    pub fn reconfigState(c: EpochControl) ReconfigState {
        return c.vtable.reconfig_state(c.ctx);
    }
    pub fn storeReconfigState(c: EpochControl, s: ReconfigState) void {
        c.vtable.store_reconfig_state(c.ctx, s);
    }
    pub fn hasReceivedEndOfPublishFrom(c: EpochControl, i: u32) bool {
        return c.vtable.has_received_end_of_publish_from(c.ctx, i);
    }
    pub fn recordEndOfPublish(c: EpochControl, i: u32) bool {
        return c.vtable.record_end_of_publish(c.ctx, i);
    }
    pub fn hasEndOfPublishQuorum(c: EpochControl) bool {
        return c.vtable.has_end_of_publish_quorum(c.ctx);
    }
    pub fn nextReconfigurationTimestampMs(c: EpochControl) u64 {
        return c.vtable.next_reconfiguration_timestamp_ms(c.ctx);
    }
};

/// In-memory EpochControl: stake-weighted EndOfPublish quorum (2f+1 of total stake, as
/// `Committee::quorum_threshold`), a fixed epoch end time.
pub const LocalEpochControl = struct {
    state: ReconfigState = .{},
    stakes: []const u64,
    eop: []bool,
    next_reconfig_ms: u64 = std.math.maxInt(u64),
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator, stakes: []const u64) !LocalEpochControl {
        const eop = try gpa.alloc(bool, stakes.len);
        @memset(eop, false);
        return .{ .stakes = stakes, .eop = eop, .gpa = gpa };
    }
    pub fn deinit(l: *LocalEpochControl) void {
        l.gpa.free(l.eop);
    }

    fn total(l: *const LocalEpochControl) u64 {
        var t: u64 = 0;
        for (l.stakes) |s| t += s;
        return t;
    }
    /// `Committee::quorum_threshold`: total - validity_threshold... for total 10000: 6667.
    fn quorum(l: *const LocalEpochControl) u64 {
        const t = l.total();
        // 2f+1 where f = (t-1)/3: threshold = t - (t-1)/3 (Sui: TOTAL_VOTING_POWER - (TOTAL-1)/3)
        return t - (t - 1) / 3;
    }
    fn eopStake(l: *const LocalEpochControl) u64 {
        var s: u64 = 0;
        for (l.eop, l.stakes) |e, st| if (e) {
            s += st;
        };
        return s;
    }

    fn cast(ctx: *anyopaque) *LocalEpochControl {
        return @ptrCast(@alignCast(ctx));
    }
    fn rs(ctx: *anyopaque) ReconfigState {
        return cast(ctx).state;
    }
    fn srs(ctx: *anyopaque, s: ReconfigState) void {
        cast(ctx).state = s;
    }
    fn has(ctx: *anyopaque, i: u32) bool {
        const l = cast(ctx);
        return i < l.eop.len and l.eop[i];
    }
    fn rec(ctx: *anyopaque, i: u32) bool {
        const l = cast(ctx);
        if (i < l.eop.len) l.eop[i] = true;
        return l.eopStake() >= l.quorum();
    }
    fn hasq(ctx: *anyopaque) bool {
        const l = cast(ctx);
        return l.eopStake() >= l.quorum();
    }
    fn nxt(ctx: *anyopaque) u64 {
        return cast(ctx).next_reconfig_ms;
    }
    const vt: EpochControl.VTable = .{
        .reconfig_state = rs,
        .store_reconfig_state = srs,
        .has_received_end_of_publish_from = has,
        .record_end_of_publish = rec,
        .has_end_of_publish_quorum = hasq,
        .next_reconfiguration_timestamp_ms = nxt,
    };

    pub fn control(l: *LocalEpochControl) EpochControl {
        return .{ .ctx = l, .vtable = &vt };
    }
};

test "reconfig transitions" {
    var r: ReconfigState = .{};
    try std.testing.expect(r.shouldAcceptUserCerts() and r.shouldAcceptTx());
    r.closeAllCerts();
    try std.testing.expect(!r.shouldAcceptConsensusCerts() and r.shouldAcceptTx());
    r.closeAllTx();
    try std.testing.expect(!r.shouldAcceptTx() and r.isRejectAllTx());
    r.closeAllCerts();
    try std.testing.expect(r.isRejectAllTx());
}

test "local epoch control quorum" {
    var l = try LocalEpochControl.init(std.testing.allocator, &.{ 2500, 2500, 2500, 2500 });
    defer l.deinit();
    const c = l.control();
    try std.testing.expect(!c.recordEndOfPublish(0));
    try std.testing.expect(!c.recordEndOfPublish(1));
    try std.testing.expect(c.recordEndOfPublish(2));
    try std.testing.expect(c.hasEndOfPublishQuorum());
}
