//! Reconfiguration state of one epoch at mainnet-v1.83.1: `ReconfigState` (epoch/reconfiguration.rs),
//! the EndOfPublish aggregator, authority capabilities (`record_capabilities_v2`), the end-of-epoch
//! state machine of the consensus handler (`handle_close_epoch`, `advance_end_of_epoch_state_machine`,
//! `process_end_of_publish_transactions`) and the protocol-version vote
//! (`AuthorityState::choose_protocol_version_and_system_packages_v2`).
//!
//! All state sits on top of the epoch store (store.zig): every change is staged in the commit's
//! `Batch`, and the in-memory view is rebuilt from the tables at open, so a crash between commits
//! never leaves the reconfig state ahead of the rest of the commit.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const messages = @import("../messages.zig");
const iface = @import("../iface.zig");
const store_mod = @import("store.zig");
const Store = store_mod.Store;
const Batch = store_mod.Batch;

pub const Error = error{ Io, OutOfMemory, BatchTooLarge, BadCommittee, BadCapabilities };

/// epoch/reconfiguration.rs ReconfigCertStatus (the BCS of `ReconfigState` is the variant index).
pub const ReconfigState = enum(u8) {
    accept_all_certs = 0,
    /// Manual epoch close only: user transactions closed, consensus ones still accepted.
    reject_user_certs = 1,
    /// All user transactions rejected; DKG, JWK, checkpoint signatures and deferred ones still run.
    reject_all_certs = 2,
    /// Everything rejected, including system transactions.
    reject_all_tx = 3,

    pub fn closeUserCerts(s: *ReconfigState) void {
        if (s.* == .accept_all_certs) s.* = .reject_user_certs;
    }
    pub fn isRejectUserCerts(s: ReconfigState) bool {
        return s == .reject_user_certs;
    }
    pub fn closeAllCerts(s: *ReconfigState) void {
        if (s.* != .reject_all_tx) s.* = .reject_all_certs;
    }
    pub fn shouldAcceptUserCerts(s: ReconfigState) bool {
        return s == .accept_all_certs;
    }
    pub fn shouldAcceptConsensusCerts(s: ReconfigState) bool {
        return s == .accept_all_certs or s == .reject_user_certs;
    }
    pub fn isRejectAllCerts(s: ReconfigState) bool {
        return s == .reject_all_certs;
    }
    pub fn closeAllTx(s: *ReconfigState) void {
        s.* = .reject_all_tx;
    }
    pub fn isRejectAllTx(s: ReconfigState) bool {
        return s == .reject_all_tx;
    }
    pub fn shouldAcceptTx(s: ReconfigState) bool {
        return s != .reject_all_tx;
    }
};

pub const CommitteeMember = struct { name: [96]u8, stake: u64 };

/// Everything fixed at the start of an epoch.
pub const EpochInfo = struct {
    epoch: u64,
    protocol_version: u64,
    chain_id: [8]u8,
    epoch_start_timestamp_ms: u64,
    /// Sui committee in consensus AuthorityIndex order (sorted by key bytes, `Committee::new`).
    committee: []const CommitteeMember,
    own_index: ?u32,
};

pub const total_voting_power: u64 = 10_000;

/// `Committee::quorum_threshold` / `validity_threshold` as consensus computes them
/// (f = (total - 1) / 3).
pub const Thresholds = struct {
    total: u64,
    quorum: u64,
    validity: u64,

    pub fn of(total: u64) Thresholds {
        const f = (total -| 1) / 3;
        return .{ .total = total, .quorum = total - f, .validity = f + 1 };
    }
};

pub const meta_reconfig_key = "reconfig_state";
pub const meta_info_key = "epoch_info";

/// capabilities as stored: generation first so the compare-and-write needs no decode.
fn capsGeneration(b: []const u8) ?u64 {
    // BCS(AuthorityCapabilitiesV2) = authority (uleb 96 + 96 bytes) ++ generation u64 ++ ...
    if (b.len < 1 + 96 + 8 or b[0] != 96) return null;
    return std.mem.readInt(u64, b[97..105], .little);
}

pub const CloseInput = struct {
    commit_timestamp_ms: u64,
    /// Authorities whose EndOfPublish was sequenced in this commit, in commit order.
    end_of_publish_from: []const [96]u8 = &.{},
    /// Any deferred transactions left (this commit's or earlier commits').
    has_deferred: bool = false,
    /// `epoch_close_deadline_ms` of the protocol config, if set.
    close_deadline_ms: ?u64 = null,
    /// epoch_duration_ms from the system state parameters at epoch start.
    epoch_duration_ms: u64,
};

pub const CloseOutcome = struct {
    /// The commit's transactions are still accepted (reconfig state is not RejectAllTx afterwards).
    accept_tx: bool,
    /// This commit is the last of the epoch: its pending checkpoint is `last_of_epoch`.
    final_round: bool,
    /// The deadline forced the close with deferred transactions left: the handler drops them.
    abandon_deferred: bool,
    /// The state machine ran in this commit (timestamp or EndOfPublish quorum).
    advanced: bool,
};

pub const EpochState = struct {
    gpa: std.mem.Allocator,
    store: *Store,
    info: EpochInfo,
    thresholds: Thresholds,
    index_of: std.AutoHashMapUnmanaged([96]u8, u32) = .empty,
    reconfig: ReconfigState = .accept_all_certs,
    eop_voted: []bool,
    eop_stake: u64 = 0,
    /// Highest capability generation seen per authority index, including what the commit in
    /// progress staged (Rust writes the table directly, so a later message of the same commit is
    /// compared against an earlier one).
    caps_gen: []?u64,
    /// Committee in iface shape (borrowed by `view`).
    view_committee: []struct { iface.AuthorityName, u64 },
    /// Batch of the commit being processed, set by `beginCommit`; hook calls outside a commit
    /// commit their own batch.
    current: ?*Batch = null,

    pub fn open(gpa: std.mem.Allocator, io: std.Io, db_dir: []const u8, info: EpochInfo) Error!*EpochState {
        if (info.committee.len == 0) return error.BadCommittee;
        var total: u64 = 0;
        for (info.committee) |m| total = std.math.add(u64, total, m.stake) catch return error.BadCommittee;
        if (total == 0) return error.BadCommittee;
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrint(&pb, "{s}/validator/epoch-{d}/epoch.log", .{ db_dir, info.epoch }) catch return error.Io;
        const st = try Store.open(gpa, io, path);
        errdefer st.close();
        const self = try gpa.create(EpochState);
        errdefer gpa.destroy(self);
        const members = try gpa.dupe(CommitteeMember, info.committee);
        errdefer gpa.free(members);
        const voted = try gpa.alloc(bool, members.len);
        errdefer gpa.free(voted);
        @memset(voted, false);
        const caps_gen = try gpa.alloc(?u64, members.len);
        errdefer gpa.free(caps_gen);
        @memset(caps_gen, null);
        const vc = try gpa.alloc(struct { iface.AuthorityName, u64 }, members.len);
        errdefer gpa.free(vc);
        for (members, vc) |m, *o| o.* = .{ .{ .@"0" = m.name }, m.stake };
        self.* = .{ .gpa = gpa, .store = st, .info = info, .thresholds = Thresholds.of(total), .eop_voted = voted, .caps_gen = caps_gen, .view_committee = vc };
        self.info.committee = members;
        errdefer self.index_of.deinit(gpa);
        try self.index_of.ensureTotalCapacity(gpa, @intCast(members.len));
        for (members, 0..) |m, i| self.index_of.putAssumeCapacity(m.name, @intCast(i));
        // the store belongs to one epoch: record the identity on first open and check on reopen
        var enc: [1 << 16]u8 = undefined;
        const ident = encodeIdentity(&enc, &self.info) catch return error.BadCommittee;
        if (st.get(.meta, meta_info_key)) |have| {
            if (!std.mem.eql(u8, have, ident)) return error.BadCommittee;
        } else {
            var b = st.batch();
            defer b.deinit();
            try b.put(.meta, meta_info_key, ident);
            try st.commit(&b);
        }
        if (st.get(.meta, meta_reconfig_key)) |v| {
            if (v.len == 1 and v[0] <= 3) self.reconfig = @enumFromInt(v[0]);
        }
        var it = st.iterator(.end_of_publish);
        while (it.next()) |e| {
            if (e.key_ptr.len != 4) continue;
            const idx = std.mem.readInt(u32, e.key_ptr.*[0..4], .little);
            if (idx < voted.len and !voted[idx]) {
                voted[idx] = true;
                self.eop_stake += members[idx].stake;
            }
        }
        var cit = st.iterator(.capabilities_v2);
        while (cit.next()) |e| {
            if (e.key_ptr.len != 4) continue;
            const idx = std.mem.readInt(u32, e.key_ptr.*[0..4], .little);
            if (idx < caps_gen.len) caps_gen[idx] = capsGeneration(e.value_ptr.*);
        }
        return self;
    }

    pub fn close(self: *EpochState) void {
        self.store.close();
        self.index_of.deinit(self.gpa);
        self.gpa.free(self.eop_voted);
        self.gpa.free(self.caps_gen);
        self.gpa.free(self.view_committee);
        self.gpa.free(self.info.committee);
        self.gpa.destroy(self);
    }

    fn encodeIdentity(out: []u8, info: *const EpochInfo) error{NoSpaceLeft}![]const u8 {
        var w = std.Io.Writer.fixed(out);
        w.writeInt(u64, info.epoch, .little) catch return error.NoSpaceLeft;
        w.writeInt(u64, info.protocol_version, .little) catch return error.NoSpaceLeft;
        w.writeAll(&info.chain_id) catch return error.NoSpaceLeft;
        w.writeInt(u64, info.epoch_start_timestamp_ms, .little) catch return error.NoSpaceLeft;
        for (info.committee) |m| {
            w.writeAll(&m.name) catch return error.NoSpaceLeft;
            w.writeInt(u64, m.stake, .little) catch return error.NoSpaceLeft;
        }
        return w.buffered();
    }

    pub fn view(self: *const EpochState) iface.EpochView {
        return .{
            .epoch = self.info.epoch,
            .protocol_version = self.info.protocol_version,
            .chain_id = self.info.chain_id,
            .epoch_start_timestamp_ms = self.info.epoch_start_timestamp_ms,
            .committee = self.view_committee,
            .own_index = self.info.own_index,
        };
    }

    pub fn indexOf(self: *const EpochState, name: *const [96]u8) ?u32 {
        return self.index_of.get(name.*);
    }

    /// Stake of `name`, 0 when not in the committee.
    pub fn stakeOf(self: *const EpochState, name: *const [96]u8) u64 {
        const i = self.indexOf(name) orelse return 0;
        return self.info.committee[i].stake;
    }

    /// `next_reconfiguration_timestamp_ms`: epoch start plus the epoch duration.
    pub fn nextReconfigurationTimestampMs(self: *const EpochState, epoch_duration_ms: u64) u64 {
        return self.info.epoch_start_timestamp_ms +| epoch_duration_ms;
    }

    // -------------------------------------------------------------- commit scope

    /// Starts a commit scope: later hook calls stage into `b`. The consensus handler commits `b`
    /// once per consensus commit (after every lane's staging).
    pub fn beginCommit(self: *EpochState, b: *Batch) void {
        self.current = b;
    }
    pub fn endCommit(self: *EpochState) void {
        self.current = null;
    }

    fn stage(self: *EpochState, table: store_mod.Table, key: []const u8, value: []const u8) Error!void {
        if (self.current) |b| {
            try b.put(table, key, value);
        } else {
            var b = self.store.batch();
            defer b.deinit();
            try b.put(table, key, value);
            try self.store.commit(&b);
        }
    }

    // -------------------------------------------------------------- end of publish

    pub fn hasEndOfPublishQuorum(self: *const EpochState) bool {
        return self.eop_stake >= self.thresholds.quorum;
    }

    /// `process_end_of_publish_transactions` for one message: records it (once per authority) and
    /// returns true once a quorum of stake has sent EndOfPublish (this call or earlier ones).
    /// Messages after the quorum are ignored, as Rust returns early.
    pub fn recordEndOfPublish(self: *EpochState, from: *const [96]u8) Error!bool {
        if (self.hasEndOfPublishQuorum()) return true;
        const idx = self.indexOf(from) orelse return false;
        if (self.eop_voted[idx]) return false;
        var key: [4]u8 = undefined;
        std.mem.writeInt(u32, &key, idx, .little);
        try self.stage(.end_of_publish, &key, "");
        self.eop_voted[idx] = true;
        self.eop_stake += self.info.committee[idx].stake;
        return self.hasEndOfPublishQuorum();
    }

    // -------------------------------------------------------------- capabilities

    /// `record_capabilities_v2`: keeps the highest generation per authority; unknown authorities
    /// and stale generations are ignored. Returns whether it was stored.
    pub fn recordCapabilities(self: *EpochState, caps: *const messages.AuthorityCapabilitiesV2) Error!bool {
        const idx = self.indexOf(&caps.authority.@"0") orelse return false;
        var key: [4]u8 = undefined;
        std.mem.writeInt(u32, &key, idx, .little);
        if (self.caps_gen[idx]) |g| {
            if (g >= caps.generation) return false;
        }
        const enc = bcs.encodeAlloc(messages.AuthorityCapabilitiesV2, self.gpa, caps) catch return error.OutOfMemory;
        defer self.gpa.free(enc);
        try self.stage(.capabilities_v2, &key, enc);
        self.caps_gen[idx] = caps.generation;
        return true;
    }

    /// Every stored capability, decoded into `arena`.
    pub fn capabilities(self: *const EpochState, arena: std.mem.Allocator) Error![]messages.AuthorityCapabilitiesV2 {
        var out: std.ArrayList(messages.AuthorityCapabilitiesV2) = .empty;
        var it = self.store.iterator(.capabilities_v2);
        while (it.next()) |e| {
            const c = bcs.decode(messages.AuthorityCapabilitiesV2, arena, e.value_ptr.*) catch return error.BadCapabilities;
            try out.append(arena, c);
        }
        return out.items;
    }

    pub fn recordDenyConfig(self: *EpochState, cfg: *const messages.SharedTransactionDenyConfig) Error!void {
        const authority = switch (cfg.*) {
            .V1 => |v| v.authority.@"0",
        };
        const enc = bcs.encodeAlloc(messages.SharedTransactionDenyConfig, self.gpa, cfg) catch return error.OutOfMemory;
        defer self.gpa.free(enc);
        try self.stage(.deny_config, &authority, enc);
    }

    // -------------------------------------------------------------- state machine

    pub fn setReconfig(self: *EpochState, state: ReconfigState) Error!void {
        self.reconfig = state;
        try self.stage(.meta, meta_reconfig_key, &.{@intFromEnum(state)});
    }

    /// Manual epoch close (`close_user_certs_for_manual_epoch_close`): moves AcceptAllCerts to
    /// RejectUserCerts; the caller then submits this validator's EndOfPublish.
    pub fn closeUserCerts(self: *EpochState) Error!void {
        var s = self.reconfig;
        s.closeUserCerts();
        if (s != self.reconfig) try self.setReconfig(s);
    }

    /// True when this validator should send EndOfPublish (reconfig state RejectUserCerts).
    pub fn shouldSendEndOfPublish(self: *const EpochState) bool {
        return self.reconfig.isRejectUserCerts();
    }

    /// `handle_close_epoch` + `advance_end_of_epoch_state_machine`, run once per commit.
    pub fn handleCloseEpoch(self: *EpochState, in: CloseInput) Error!CloseOutcome {
        const deadline_reached = if (in.close_deadline_ms) |d|
            in.commit_timestamp_ms >= self.nextReconfigurationTimestampMs(in.epoch_duration_ms) +| d
        else
            false;
        const timestamp_triggered = in.commit_timestamp_ms >= self.nextReconfigurationTimestampMs(in.epoch_duration_ms);
        var quorum = self.hasEndOfPublishQuorum();
        if (!quorum) {
            for (in.end_of_publish_from) |*from| {
                if (try self.recordEndOfPublish(from)) {
                    quorum = true;
                    break;
                }
            }
        }
        if (!(timestamp_triggered or quorum)) return .{ .accept_tx = self.reconfig.shouldAcceptTx(), .final_round = false, .abandon_deferred = false, .advanced = false };
        const start_reject_all_tx = self.reconfig.isRejectAllTx();
        var next = self.reconfig;
        next.closeAllCerts();
        const should_close = !in.has_deferred or deadline_reached;
        const final_round = should_close and !start_reject_all_tx;
        var abandon = false;
        if (final_round) {
            abandon = in.has_deferred;
            next.closeAllTx();
        }
        if (next != self.reconfig or final_round) try self.setReconfig(next);
        return .{ .accept_tx = next.shouldAcceptTx(), .final_round = final_round, .abandon_deferred = abandon, .advanced = true };
    }
};

// ------------------------------------------------------------------ protocol version vote

pub const ObjectRef = messages.ObjectRef;

pub const Chosen = struct {
    protocol_version: u64,
    /// System packages of the winning vote (sorted), empty when no upgrade won.
    packages: []const ObjectRef,
};

fn refOrder(a: ObjectRef, b: ObjectRef) std.math.Order {
    switch (std.mem.order(u8, &a[0].@"0".@"0", &b[0].@"0".@"0")) {
        .eq => {},
        else => |o| return o,
    }
    if (a[1].@"0" != b[1].@"0") return std.math.order(a[1].@"0", b[1].@"0");
    return std.mem.order(u8, &a[2].@"0".@"0", &b[2].@"0".@"0");
}

fn refsOrder(a: []const ObjectRef, b: []const ObjectRef) std.math.Order {
    const n = @min(a.len, b.len);
    for (0..n) |i| {
        const o = refOrder(a[i], b[i]);
        if (o != .eq) return o;
    }
    return std.math.order(a.len, b.len);
}

const Vote = struct {
    digest: [32]u8,
    packages: []const ObjectRef,
    authority: [96]u8,
};

fn voteLess(_: void, a: Vote, b: Vote) bool {
    switch (std.mem.order(u8, &a.digest, &b.digest)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    switch (refsOrder(a.packages, b.packages)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    return std.mem.order(u8, &a.authority, &b.authority) == .lt;
}

/// `is_protocol_version_supported_v2`: the packages of the vote group that has at least
/// `quorum + ceil(f * buffer_bps / 10000)` stake for `proposed`, or null.
pub fn isProtocolVersionSupported(
    arena: std.mem.Allocator,
    current: u64,
    proposed: u64,
    advance_to_highest: bool,
    thresholds: Thresholds,
    stake_of: *const fn (ctx: *const anyopaque, name: *const [96]u8) u64,
    ctx: *const anyopaque,
    caps: []const messages.AuthorityCapabilitiesV2,
    buffer_stake_bps_in: u64,
) Error!?Chosen {
    if (proposed > current + 1 and !advance_to_highest) return null;
    const buffer_bps = @min(buffer_stake_bps_in, 10_000);
    var votes: std.ArrayList(Vote) = .empty;
    for (caps) |c| {
        // a validator that lists no packages votes against any change
        if (c.available_system_packages.len == 0) continue;
        const sorted = try arena.dupe(ObjectRef, c.available_system_packages);
        std.mem.sort(ObjectRef, sorted, {}, struct {
            fn lt(_: void, a: ObjectRef, b: ObjectRef) bool {
                return refOrder(a, b) == .lt;
            }
        }.lt);
        // a validator that does not support `proposed` votes against it
        var digest: ?[32]u8 = null;
        for (c.supported_protocol_versions.versions) |v| {
            if (v[0].@"0" == proposed) {
                digest = v[1].@"0";
                break;
            }
        }
        const d = digest orelse continue;
        try votes.append(arena, .{ .digest = d, .packages = sorted, .authority = c.authority.@"0" });
    }
    std.mem.sort(Vote, votes.items, {}, voteLess);
    const f = thresholds.total - thresholds.quorum;
    const buffer_stake = (f * buffer_bps + 9999) / 10_000;
    const effective = thresholds.quorum + buffer_stake;
    var i: usize = 0;
    while (i < votes.items.len) {
        var j = i;
        var stake: u64 = 0;
        var seen: std.AutoHashMapUnmanaged([96]u8, void) = .empty;
        while (j < votes.items.len and std.mem.eql(u8, &votes.items[j].digest, &votes.items[i].digest) and refsOrder(votes.items[j].packages, votes.items[i].packages) == .eq) : (j += 1) {
            const gop = try seen.getOrPut(arena, votes.items[j].authority);
            if (!gop.found_existing) stake += stake_of(ctx, &votes.items[j].authority);
        }
        if (stake >= effective) return .{ .protocol_version = proposed, .packages = votes.items[i].packages };
        i = j;
    }
    return null;
}

/// `choose_protocol_version_and_system_packages_v2`: raises the version one step at a time while a
/// vote group with enough stake exists for the next one.
pub fn chooseProtocolVersion(
    arena: std.mem.Allocator,
    state: *const EpochState,
    advance_to_highest: bool,
    buffer_stake_bps: u64,
    caps: []const messages.AuthorityCapabilitiesV2,
) Error!Chosen {
    var next = state.info.protocol_version;
    var packages: []const ObjectRef = &.{};
    const S = struct {
        fn stake(ctx: *const anyopaque, name: *const [96]u8) u64 {
            const st: *const EpochState = @ptrCast(@alignCast(ctx));
            return st.stakeOf(name);
        }
    };
    while (try isProtocolVersionSupported(arena, state.info.protocol_version, next + 1, advance_to_highest, state.thresholds, S.stake, state, caps, buffer_stake_bps)) |c| {
        next = c.protocol_version;
        packages = c.packages;
    }
    return .{ .protocol_version = next, .packages = packages };
}

// ------------------------------------------------------------------ tests

fn testName(i: u8) [96]u8 {
    var n: [96]u8 = @splat(0);
    n[0] = i;
    return n;
}

fn testInfo(members: []CommitteeMember, n: u8) EpochInfo {
    for (members[0..n], 0..) |*m, i| m.* = .{ .name = testName(@intCast(i + 1)), .stake = 2500 };
    return .{ .epoch = 3, .protocol_version = 141, .chain_id = "0badc0de".*, .epoch_start_timestamp_ms = 1_000, .committee = members[0..n], .own_index = 0 };
}

fn tmpDir(tmp: *std.testing.TmpDir, buf: []u8) ![]const u8 {
    const n = try tmp.dir.realPath(std.testing.io, buf);
    return buf[0..n];
}

test "reconfig state transitions follow reconfiguration.rs" {
    var s: ReconfigState = .accept_all_certs;
    try std.testing.expect(s.shouldAcceptUserCerts() and s.shouldAcceptTx());
    s.closeUserCerts();
    try std.testing.expect(s.isRejectUserCerts() and s.shouldAcceptConsensusCerts() and !s.shouldAcceptUserCerts());
    s.closeAllCerts();
    try std.testing.expect(s.isRejectAllCerts() and !s.shouldAcceptConsensusCerts() and s.shouldAcceptTx());
    s.closeAllTx();
    try std.testing.expect(!s.shouldAcceptTx());
    s.closeAllCerts(); // does not leave RejectAllTx
    try std.testing.expect(s.isRejectAllTx());
    s.closeUserCerts(); // only from AcceptAllCerts
    try std.testing.expect(s.isRejectAllTx());
}

test "end of publish quorum, persisted across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDir(&tmp, &pb);
    var ms: [4]CommitteeMember = undefined;
    const info = testInfo(&ms, 4);
    const st = try EpochState.open(std.testing.allocator, std.testing.io, dir, info);
    // quorum of 10000 total is 6667: three of four equal validators
    try std.testing.expect(!(try st.recordEndOfPublish(&testName(1))));
    try std.testing.expect(!(try st.recordEndOfPublish(&testName(1)))); // duplicate counts once
    try std.testing.expect(!(try st.recordEndOfPublish(&testName(9)))); // not in the committee
    try std.testing.expect(!(try st.recordEndOfPublish(&testName(2))));
    try std.testing.expect(try st.recordEndOfPublish(&testName(3)));
    try std.testing.expect(st.hasEndOfPublishQuorum());
    st.close();
    const st2 = try EpochState.open(std.testing.allocator, std.testing.io, dir, info);
    defer st2.close();
    try std.testing.expect(st2.hasEndOfPublishQuorum());
}

test "epoch store identity mismatch is refused" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDir(&tmp, &pb);
    var ms: [4]CommitteeMember = undefined;
    var info = testInfo(&ms, 4);
    const st = try EpochState.open(std.testing.allocator, std.testing.io, dir, info);
    st.close();
    info.epoch_start_timestamp_ms += 1;
    try std.testing.expectError(error.BadCommittee, EpochState.open(std.testing.allocator, std.testing.io, dir, info));
}

test "close epoch state machine: timestamp, deferred transactions, deadline" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDir(&tmp, &pb);
    var ms: [4]CommitteeMember = undefined;
    const info = testInfo(&ms, 4);
    const st = try EpochState.open(std.testing.allocator, std.testing.io, dir, info);
    defer st.close();
    // before the deadline timestamp: nothing happens
    var o = try st.handleCloseEpoch(.{ .commit_timestamp_ms = 5_000, .epoch_duration_ms = 100_000 });
    try std.testing.expect(!o.advanced and o.accept_tx and !o.final_round);
    // timestamp reached with deferred transactions left: certs close, epoch stays open
    o = try st.handleCloseEpoch(.{ .commit_timestamp_ms = 101_000, .epoch_duration_ms = 100_000, .has_deferred = true });
    try std.testing.expect(o.advanced and o.accept_tx and !o.final_round);
    try std.testing.expect(st.reconfig.isRejectAllCerts());
    // deferred drained: final round
    o = try st.handleCloseEpoch(.{ .commit_timestamp_ms = 102_000, .epoch_duration_ms = 100_000 });
    try std.testing.expect(o.final_round and !o.accept_tx and !o.abandon_deferred);
    try std.testing.expect(st.reconfig.isRejectAllTx());
    // later commits are not final again
    o = try st.handleCloseEpoch(.{ .commit_timestamp_ms = 103_000, .epoch_duration_ms = 100_000 });
    try std.testing.expect(!o.final_round and !o.accept_tx);
}

test "close epoch deadline abandons deferred transactions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDir(&tmp, &pb);
    var ms: [4]CommitteeMember = undefined;
    const info = testInfo(&ms, 4);
    const st = try EpochState.open(std.testing.allocator, std.testing.io, dir, info);
    defer st.close();
    var o = try st.handleCloseEpoch(.{ .commit_timestamp_ms = 100_500, .epoch_duration_ms = 100_000, .has_deferred = true, .close_deadline_ms = 1_000 });
    try std.testing.expect(!o.final_round);
    o = try st.handleCloseEpoch(.{ .commit_timestamp_ms = 102_000, .epoch_duration_ms = 100_000, .has_deferred = true, .close_deadline_ms = 1_000 });
    try std.testing.expect(o.final_round and o.abandon_deferred);
}

test "EndOfPublish quorum closes the epoch before the timestamp" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDir(&tmp, &pb);
    var ms: [4]CommitteeMember = undefined;
    const info = testInfo(&ms, 4);
    const st = try EpochState.open(std.testing.allocator, std.testing.io, dir, info);
    defer st.close();
    const from = [_][96]u8{ testName(1), testName(2), testName(3) };
    const o = try st.handleCloseEpoch(.{ .commit_timestamp_ms = 2_000, .epoch_duration_ms = 100_000, .end_of_publish_from = &from });
    try std.testing.expect(o.advanced and o.final_round);
}

fn testCaps(i: u8, gen: u64, version: u64, digest_byte: u8, pkg_version: u64) messages.AuthorityCapabilitiesV2 {
    const S = struct {
        var vers: [8][1]struct { types.ProtocolVersion, types.Digest } = undefined;
        var pkgs: [8][1]ObjectRef = undefined;
    };
    S.vers[i] = .{.{ .{ .@"0" = version }, .{ .@"0" = @splat(digest_byte) } }};
    S.pkgs[i] = .{.{ .{ .@"0" = .{ .@"0" = @splat(2) } }, .{ .@"0" = pkg_version }, .{ .@"0" = .{ .@"0" = @splat(7) } } }};
    return .{ .authority = .{ .@"0" = testName(i) }, .generation = gen, .supported_protocol_versions = .{ .versions = &S.vers[i] }, .available_system_packages = &S.pkgs[i] };
}

test "capabilities keep the highest generation and the vote picks a supported version" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDir(&tmp, &pb);
    var ms: [4]CommitteeMember = undefined;
    const info = testInfo(&ms, 4);
    const st = try EpochState.open(std.testing.allocator, std.testing.io, dir, info);
    defer st.close();
    // validators 1..3 vote for 142 with the same packages; validator 4 votes for 142 with another digest
    for ([_]u8{ 1, 2, 3 }) |i| {
        const c = testCaps(i, 1, 142, 0xaa, 5);
        try std.testing.expect(try st.recordCapabilities(&c));
    }
    const c4 = testCaps(4, 1, 142, 0xbb, 5);
    try std.testing.expect(try st.recordCapabilities(&c4));
    // an older generation of validator 1 is ignored; unknown authority too
    const old = testCaps(1, 1, 150, 0xcc, 9);
    try std.testing.expect(!(try st.recordCapabilities(&old)));
    const stranger = testCaps(7, 1, 142, 0xaa, 5);
    try std.testing.expect(!(try st.recordCapabilities(&stranger)));
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const caps = try st.capabilities(arena.allocator());
    try std.testing.expectEqual(@as(usize, 4), caps.len);
    const chosen = try chooseProtocolVersion(arena.allocator(), st, false, 0, caps);
    try std.testing.expectEqual(@as(u64, 142), chosen.protocol_version);
    try std.testing.expectEqual(@as(usize, 1), chosen.packages.len);
    // with a buffer of 100% the group (7500 stake) needs 6667 + 3333, so no upgrade
    const none = try chooseProtocolVersion(arena.allocator(), st, false, 10_000, caps);
    try std.testing.expectEqual(@as(u64, 141), none.protocol_version);
    try std.testing.expectEqual(@as(usize, 0), none.packages.len);
    // votes only for 143: the loop starts at 142, finds no support and stops (as Rust)
    const c1 = testCaps(1, 2, 143, 0xaa, 5);
    try std.testing.expect(try st.recordCapabilities(&c1));
    const c2 = testCaps(2, 2, 143, 0xaa, 5);
    try std.testing.expect(try st.recordCapabilities(&c2));
    const c3 = testCaps(3, 2, 143, 0xaa, 5);
    try std.testing.expect(try st.recordCapabilities(&c3));
    const caps2 = try st.capabilities(arena.allocator());
    const stay = try chooseProtocolVersion(arena.allocator(), st, true, 0, caps2);
    try std.testing.expectEqual(@as(u64, 141), stay.protocol_version);
}

test "capabilities of one commit: a later lower generation is ignored (and survives reopen)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDir(&tmp, &pb);
    var ms: [4]CommitteeMember = undefined;
    const info = testInfo(&ms, 4);
    {
        const st = try EpochState.open(std.testing.allocator, std.testing.io, dir, info);
        defer st.close();
        var b = st.store.batch();
        defer b.deinit();
        st.beginCommit(&b);
        const hi = testCaps(1, 5, 142, 0xaa, 5);
        const lo = testCaps(1, 3, 143, 0xbb, 5);
        try std.testing.expect(try st.recordCapabilities(&hi));
        try std.testing.expect(!(try st.recordCapabilities(&lo)));
        st.endCommit();
        try st.store.commit(&b);
    }
    const st = try EpochState.open(std.testing.allocator, std.testing.io, dir, info);
    defer st.close();
    const lower = testCaps(1, 4, 150, 0xcc, 5);
    try std.testing.expect(!(try st.recordCapabilities(&lower)));
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const caps = try st.capabilities(arena.allocator());
    try std.testing.expectEqual(@as(u64, 5), caps[0].generation);
}
