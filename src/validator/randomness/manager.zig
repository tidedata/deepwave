//! RandomnessManager (sui-core `epoch/randomness.rs`, mainnet-v1.83.1) as a sans-I/O state
//! machine. The consensus handler calls it in commit order:
//!
//!   startDkg()                 once per epoch start: the DKG Message to submit through consensus
//!   addMessage / addConfirmation   for each sequenced RandomnessDkgMessage / Confirmation
//!   advanceDkg(commit_round)   once per commit: process messages, merge (emits this party's
//!                              Confirmation), complete (DKG output) or time out
//!   reserveNextRandomness(ts)  once per commit: the next randomness round when the interval passed
//!   dkgStatusForCommitRound    whether randomness-using transactions run or are cancelled
//!
//! Every mutation that Rust writes into the commit's `ConsensusCommitOutput` is appended to the
//! `Batch` the caller passes, and the caller writes the batch atomically with the rest of the
//! commit. `load*` rebuild the in-memory state from those records at epoch store open.
//!
//! Message processing (decrypting and verifying shares) is the expensive part; Rust spawns it on
//! blocking threads when the message is received and joins in `advanceDkg`. Here `advanceDkg`
//! processes the enqueued messages itself (ascending party id, the order the BTreeMap gives), and
//! `processPending` is separable so the validator can run it on a worker pool.
const std = @import("std");
const protocol = @import("protocol");
const group = @import("group.zig");
const wire = @import("wire.zig");
const oracle = @import("oracle.zig");
const dkg = @import("dkg.zig");
const nodes_mod = @import("nodes.zig");
const poly = @import("poly.zig");
const tbls = @import("tbls.zig");
const Scalar = group.Scalar;
const G2 = group.G2;

pub const Error = error{
    InvalidCommittee,
    InvalidKey,
    UnknownAuthority,
    NotAParty,
    Equivocation,
    DuplicateMessage,
    UnsupportedVersion,
    Ignored,
    /// The bytes do not decode as the versioned enum (Rust: bcs::from_bytes fails, the handler
    /// logs and the commit does not count as a DKG update).
    Malformed,
    NoShares,
    OutOfMemory,
} || dkg.Error;

/// The protocol config values the beacon reads (mainnet 141 snapshot defaults).
pub const ProtocolParams = struct {
    random_beacon_reduction_allowed_delta: u16 = 800,
    random_beacon_reduction_lower_bound: u16 = 500,
    random_beacon_dkg_timeout_round: u32 = 3000,
    random_beacon_min_round_interval_ms: u64 = 500,
    random_beacon_dkg_version: u64 = 1,
    /// Mainnet 141: false (late completion is enabled from a later protocol version).
    allow_dkg_completion_after_timeout: bool = false,
    /// Mainnet and testnet 141: true. Rust also forces it on Mainnet from epoch 1143; a caller
    /// on mainnet sets it.
    always_advance_dkg_to_resolution: bool = true,
};

/// The beacon parameters of a protocol config (the epoch's version and chain). Rust reads them
/// from `epoch_store.protocol_config()`; the integration builds `Params.protocol` with this.
pub fn protocolParams(cfg: *const protocol.ProtocolConfig) ProtocolParams {
    const d: ProtocolParams = .{};
    return .{
        .random_beacon_reduction_allowed_delta = cfg.random_beacon_reduction_allowed_delta orelse d.random_beacon_reduction_allowed_delta,
        .random_beacon_reduction_lower_bound = if (cfg.random_beacon_reduction_lower_bound) |v| @intCast(@min(v, std.math.maxInt(u16))) else d.random_beacon_reduction_lower_bound,
        .random_beacon_dkg_timeout_round = cfg.random_beacon_dkg_timeout_round orelse d.random_beacon_dkg_timeout_round,
        .random_beacon_min_round_interval_ms = cfg.random_beacon_min_round_interval_ms orelse d.random_beacon_min_round_interval_ms,
        .random_beacon_dkg_version = cfg.random_beacon_dkg_version orelse d.random_beacon_dkg_version,
        .allow_dkg_completion_after_timeout = cfg.feature_flags.allow_dkg_completion_after_timeout,
        .always_advance_dkg_to_resolution = cfg.feature_flags.always_advance_dkg_to_resolution,
    };
}

test "beacon parameters from the 141 protocol configs" {
    const m = protocolParams(try protocol.get(141, .mainnet));
    try std.testing.expectEqual(ProtocolParams{}, m); // the defaults are mainnet 141
    try std.testing.expectEqual(@as(u16, 800), m.random_beacon_reduction_allowed_delta);
    try std.testing.expectEqual(@as(u16, 500), m.random_beacon_reduction_lower_bound);
    try std.testing.expectEqual(@as(u32, 3000), m.random_beacon_dkg_timeout_round);
    try std.testing.expectEqual(@as(u64, 500), m.random_beacon_min_round_interval_ms);
    try std.testing.expectEqual(@as(u64, 1), m.random_beacon_dkg_version);
    try std.testing.expect(!m.allow_dkg_completion_after_timeout and m.always_advance_dkg_to_resolution);
    const t = protocolParams(try protocol.get(141, .testnet));
    try std.testing.expect(t.allow_dkg_completion_after_timeout and t.always_advance_dkg_to_resolution);
}

pub const Member = struct { name: [96]u8, stake: u64 };

pub const Params = struct {
    epoch: u64,
    /// ChainIdentifier bytes (the genesis checkpoint digest): hex in the random oracle prefix.
    chain_id: [32]u8,
    /// Committee in authority index order (the sorted order of `Committee::voting_rights`).
    members: []const Member,
    /// `committee.validity_threshold()` (f+1 stake, 3334 of 10000).
    validity_threshold: u64 = 3334,
    protocol: ProtocolParams = .{},
};

pub const DkgStatus = enum { pending, timed_out, successful };

/// The records of one commit that Rust puts into `ConsensusCommitOutput`; owned bytes.
pub const Batch = struct {
    gpa: std.mem.Allocator,
    processed: std.ArrayList(Record) = .empty,
    confirmations: std.ArrayList(Record) = .empty,
    used_messages: ?[]u8 = null,
    own_confirmation: ?[]u8 = null,
    /// null = unchanged; `.failed` = Some(None) (timed out); `.success` = encoded Output.
    dkg_output: ?union(enum) { success: []u8, failed } = null,
    reserved_round: ?struct { next_round: u64, timestamp_ms: u64 } = null,

    pub const Record = struct { sender: u16, bytes: []u8 };

    pub fn init(gpa: std.mem.Allocator) Batch {
        return .{ .gpa = gpa };
    }

    pub fn deinit(b: *Batch) void {
        for (b.processed.items) |r| b.gpa.free(r.bytes);
        b.processed.deinit(b.gpa);
        for (b.confirmations.items) |r| b.gpa.free(r.bytes);
        b.confirmations.deinit(b.gpa);
        if (b.used_messages) |x| b.gpa.free(x);
        if (b.own_confirmation) |x| b.gpa.free(x);
        if (b.dkg_output) |o| switch (o) {
            .success => |x| b.gpa.free(x),
            .failed => {},
        };
        b.* = init(b.gpa);
    }
};

/// What a commit's DKG step asks the caller to do after the batch is written.
pub const Advance = struct {
    /// Versioned (V1) DKG Confirmation to submit through consensus (this party only).
    confirmation_to_submit: ?[]u8 = null,
    pub fn deinit(a: *Advance, gpa: std.mem.Allocator) void {
        if (a.confirmation_to_submit) |x| gpa.free(x);
        a.* = .{};
    }
};

const Role = union(enum) { party: dkg.Party, observer: dkg.Observer };

const OutputState = union(enum) {
    unset,
    failed,
    ready: dkg.Owned(dkg.Output),
};

pub const SecureRandom = @import("secure.zig").SecureRandom;

pub const Manager = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator, // nodes and the lookup tables
    params: Params,
    rng: std.Random,
    secure: SecureRandom = undefined, // backing state for `rng` in production
    nodes: *nodes_mod.Nodes,
    t: u16,
    ro: oracle.RandomOracle,
    role: Role,
    /// Authority index of this validator (a party), or null for an observer.
    own_index: ?u16,

    enqueued: []?dkg.Owned(dkg.Message),
    processed: []?dkg.Owned(dkg.ProcessedMessage),
    used: ?dkg.Owned(dkg.UsedProcessedMessages) = null,
    confirmations: []?dkg.Owned(dkg.Confirmation),
    own_confirmation_bytes: ?[]u8 = null, // persisted copy to re-send after a restart
    output: OutputState = .unset,
    dkg_timeout_reported: bool = false,
    /// Which processed messages already went into a batch (so a retried advance does not repeat).
    persisted: []bool,

    next_randomness_round: u64 = 0,
    last_round_timestamp_ms: ?u64 = null,
    highest_completed_round: ?u64 = null,

    /// `RandomnessManager::try_new`. `authority_secret` is the validator's BLS private key (32
    /// bytes big-endian) for a validator, null for an observer (full node).
    /// All secret material (VSS polynomial, ECIES ephemeral, NIZK nonces, batch-verification
    /// weights) is drawn from the OS CSPRNG through `io.randomSecure`.
    pub fn create(gpa: std.mem.Allocator, io: std.Io, params: Params, authority_secret: ?*const [32]u8) Error!*Manager {
        return createInner(gpa, params, authority_secret, null, io);
    }

    /// Test-only: a deterministic caller-supplied rng. Never use for a real validator.
    pub fn createForTesting(gpa: std.mem.Allocator, params: Params, authority_secret: ?*const [32]u8, rng: std.Random) Error!*Manager {
        return createInner(gpa, params, authority_secret, rng, undefined);
    }

    fn createInner(gpa: std.mem.Allocator, params: Params, authority_secret: ?*const [32]u8, test_rng: ?std.Random, io: std.Io) Error!*Manager {
        const self = try gpa.create(Manager);
        errdefer gpa.destroy(self);
        self.secure = .{ .io = io };
        const rng: std.Random = test_rng orelse self.secure.interface();
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();

        if (params.members.len == 0 or params.members.len > nodes_mod.max_nodes) return error.InvalidCommittee;
        const in = try a.alloc(nodes_mod.Node, params.members.len);
        for (params.members, in, 0..) |m, *n, i| {
            const pk = group.g2FromBytes(&m.name) orelse return error.InvalidCommittee;
            if (m.stake > std.math.maxInt(u16)) return error.InvalidCommittee;
            n.* = .{ .id = @intCast(i), .pk = pk, .weight = @intCast(m.stake) };
        }
        if (params.validity_threshold > std.math.maxInt(u16)) return error.InvalidCommittee;
        const reduced = try nodes_mod.Nodes.newReduced(
            a,
            in,
            @intCast(params.validity_threshold),
            params.protocol.random_beacon_reduction_allowed_delta,
            params.protocol.random_beacon_reduction_lower_bound,
        );
        const nodes = try a.create(nodes_mod.Nodes);
        nodes.* = reduced.nodes;

        var prefix_buf: [128]u8 = undefined;
        const prefix = std.fmt.bufPrint(&prefix_buf, "dkg {x} {d}", .{ &params.chain_id, params.epoch }) catch return error.InvalidInput;
        const ro = try oracle.RandomOracle.init(prefix);

        var own_index: ?u16 = null;
        var role: Role = if (authority_secret) |sk_bytes| blk: {
            const sk = group.scalarFromBytes(sk_bytes) orelse return error.InvalidKey;
            var party = try dkg.Party.init(gpa, sk, nodes, reduced.t, ro, rng);
            errdefer party.deinit();
            own_index = party.id;
            break :blk .{ .party = party };
        } else .{ .observer = try dkg.Observer.init(nodes, reduced.t, ro) };
        errdefer switch (role) {
            .party => |*p| p.deinit(),
            .observer => {},
        };

        const n = params.members.len;
        const enq = try a.alloc(?dkg.Owned(dkg.Message), n);
        const proc = try a.alloc(?dkg.Owned(dkg.ProcessedMessage), n);
        const confs = try a.alloc(?dkg.Owned(dkg.Confirmation), n);
        @memset(enq, null);
        @memset(proc, null);
        @memset(confs, null);
        const persisted = try a.alloc(bool, n);
        @memset(persisted, false);

        const secure = self.secure;
        self.* = .{
            .secure = secure,
            .gpa = gpa,
            .arena = arena,
            .params = params,
            .rng = rng,
            .nodes = nodes,
            .t = reduced.t,
            .ro = ro,
            .role = role,
            .own_index = own_index,
            .enqueued = enq,
            .processed = proc,
            .confirmations = confs,
            .persisted = persisted,
        };
        // params.members is borrowed: the caller keeps it alive for the epoch (it is the epoch
        // store's committee). Copy to be safe.
        self.params.members = try a.dupe(Member, params.members);
        return self;
    }

    pub fn destroy(self: *Manager) void {
        const gpa = self.gpa;
        for (self.enqueued) |*m| if (m.*) |*x| x.deinit();
        for (self.processed) |*m| if (m.*) |*x| x.deinit();
        for (self.confirmations) |*m| if (m.*) |*x| x.deinit();
        if (self.used) |*u| u.deinit();
        if (self.own_confirmation_bytes) |b| gpa.free(b);
        switch (self.output) {
            .ready => |*o| o.deinit(),
            else => {},
        }
        switch (self.role) {
            .party => |*p| p.deinit(),
            .observer => {},
        }
        var arena = self.arena;
        gpa.destroy(self);
        arena.deinit();
    }

    pub fn threshold(self: *const Manager) u16 {
        return self.t;
    }

    pub fn isParty(self: *const Manager) bool {
        return self.role == .party;
    }

    pub fn authorityIndex(self: *const Manager, name: *const [96]u8) ?u16 {
        for (self.params.members, 0..) |m, i| if (std.mem.eql(u8, &m.name, name)) return @intCast(i);
        return null;
    }

    // ------------------------------------------------------------------------- DKG

    /// `start_dkg`: the versioned DKG message to submit through consensus, or null (observer,
    /// DKG already completed, nothing to re-send, or zero weight). A merged-but-unconfirmed DKG
    /// returns the persisted own confirmation instead (only with late completion enabled).
    pub fn startDkg(self: *Manager) Error!?[]u8 {
        const party = switch (self.role) {
            .observer => return null,
            .party => |*p| p,
        };
        if (self.output == .ready or self.output == .failed) return null;
        if (self.used != null) {
            if (!self.params.protocol.allow_dkg_completion_after_timeout) return null;
            if (self.confirmations[party.id] != null) return null;
            if (self.own_confirmation_bytes) |b| return try self.gpa.dupe(u8, b);
            return null;
        }
        if (self.params.protocol.random_beacon_dkg_version != 1) return null;
        var msg = party.createMessage(self.gpa, self.rng) catch |e| switch (e) {
            error.IgnoredMessage => return null,
            else => return null, // Rust logs and returns Ok
        };
        defer msg.deinit();
        return try dkg.encodeVersionedMessage(self.gpa, &msg.value);
    }

    /// `add_message`: a sequenced RandomnessDkgMessage from `authority`.
    pub fn addMessage(self: *Manager, authority: *const [96]u8, versioned: []const u8) Error!void {
        var v = dkg.decodeVersionedMessage(self.gpa, versioned) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Malformed;
        switch (v) {
            .v0 => return error.UnsupportedVersion,
            .v1 => |*owned| {
                errdefer owned.deinit();
                if (self.params.protocol.random_beacon_dkg_version != 1) return error.UnsupportedVersion;
                if (self.used != null or self.output != .unset) return error.Ignored;
                const party_id = self.authorityIndex(authority) orelse return error.UnknownAuthority;
                if (party_id != owned.value.sender) return error.Equivocation;
                if (self.enqueued[party_id] != null or self.processed[party_id] != null) return error.DuplicateMessage;
                self.enqueued[party_id] = owned.*;
            },
        }
    }

    /// `add_confirmation`: a sequenced RandomnessDkgConfirmation. Recorded into `batch`.
    pub fn addConfirmation(self: *Manager, batch: *Batch, authority: *const [96]u8, versioned: []const u8) Error!void {
        var v = dkg.decodeVersionedConfirmation(self.gpa, versioned) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Malformed;
        switch (v) {
            .v0 => return error.UnsupportedVersion,
            .v1 => |*owned| {
                errdefer owned.deinit();
                if (self.params.protocol.random_beacon_dkg_version != 1) return error.UnsupportedVersion;
                if (self.output != .unset) return error.Ignored;
                const party_id = self.authorityIndex(authority) orelse return error.UnknownAuthority;
                if (party_id != owned.value.sender) return error.Equivocation;
                const bytes = try self.gpa.dupe(u8, versioned);
                errdefer self.gpa.free(bytes);
                try batch.confirmations.append(self.gpa, .{ .sender = party_id, .bytes = bytes });
                if (self.confirmations[party_id]) |*old| old.deinit();
                self.confirmations[party_id] = owned.*; // BTreeMap::insert replaces
            },
        }
    }

    /// Verify and decrypt every enqueued message (the expensive step; safe to call from a worker
    /// before `advanceDkg`). NOT thread-safe: it mutates the slots and uses the shared rng, so it
    /// must run on the consensus-handler thread. Invalid messages are dropped, as Rust does.
    pub fn processPending(self: *Manager) Error!void {
        if (self.output == .ready or self.used != null) return;
        for (self.enqueued, 0..) |*slot, i| {
            const m = &(slot.* orelse continue);
            defer {
                m.deinit();
                slot.* = null;
            }
            const processed: ?dkg.Owned(dkg.ProcessedMessage) = switch (self.role) {
                .party => |*p| p.processMessage(self.gpa, &m.value, self.rng) catch null,
                .observer => |*o| blk: {
                    o.processMessage(&m.value) catch break :blk null;
                    break :blk try observerProcessed(self.gpa, &m.value);
                },
            };
            if (processed) |pm| self.processed[i] = pm;
        }
    }

    /// Whether the consensus handler calls `advance_dkg` for this commit
    /// (consensus_handler.rs `process_dkg_updates`): when a DKG message or confirmation of the
    /// commit decoded, or, without late completion, on every commit while the DKG is pending so
    /// the timeout fails it at the same commit on every validator.
    pub fn shouldAdvance(self: *const Manager, dkg_updates: bool) bool {
        if (dkg_updates) return true;
        return !self.params.protocol.allow_dkg_completion_after_timeout and
            self.params.protocol.always_advance_dkg_to_resolution and
            self.dkgStatus() == .pending;
    }

    /// `advance_dkg` for the commit at consensus `round`.
    pub fn advanceDkg(self: *Manager, batch: *Batch, round: u32) Error!Advance {
        var adv: Advance = .{};
        errdefer adv.deinit(self.gpa);
        try self.tryMergeMessages(batch, &adv);
        try self.tryCompleteDkg(batch);
        if (!self.params.protocol.allow_dkg_completion_after_timeout and
            self.output == .unset and self.isPastTimeoutRound(round))
        {
            self.output = .failed;
            batch.dkg_output = .failed;
        }
        return adv;
    }

    fn tryMergeMessages(self: *Manager, batch: *Batch, adv: *Advance) Error!void {
        if (self.output == .ready or self.output == .failed or self.used != null) return;
        // the Rust OnceCell `dkg_output.initialized()` also covers the failed state
        try self.processPending();
        var list: std.ArrayList(*const dkg.ProcessedMessage) = .empty;
        defer list.deinit(self.gpa);
        // record newly processed messages into the batch (all of them are new when first merged,
        // but a retry after NotEnoughInputs must not duplicate: track by flag)
        for (self.processed, 0..) |*pm, i| if (pm.*) |*x| {
            try list.append(self.gpa, &x.value);
            if (!self.persisted[i]) {
                var w = wire.Writer.init(self.gpa);
                errdefer w.deinit();
                try x.value.encode(&w);
                try batch.processed.append(self.gpa, .{ .sender = @intCast(i), .bytes = try w.toOwnedSlice() });
                self.persisted[i] = true;
            }
        };
        switch (self.role) {
            .party => |*p| {
                var merged = p.merge(self.gpa, list.items) catch |e| switch (e) {
                    error.NotEnoughInputs => return,
                    else => return, // Rust logs "error while merging DKG Messages" and waits
                };
                var conf_owned = true;
                var used_owned = true;
                defer if (conf_owned) merged.confirmation.deinit();
                defer if (used_owned) merged.used.deinit();
                var uw = wire.Writer.init(self.gpa);
                errdefer uw.deinit();
                try merged.used.value.encode(&uw);
                const used_bytes = try uw.toOwnedSlice();
                errdefer self.gpa.free(used_bytes);
                const conf_bytes = try dkg.encodeVersionedConfirmation(self.gpa, &merged.confirmation.value);
                errdefer self.gpa.free(conf_bytes);
                // all fallible allocations first; the commit below has no `try`
                const batch_conf = try self.gpa.dupe(u8, conf_bytes);
                errdefer self.gpa.free(batch_conf);
                const own_conf = try self.gpa.dupe(u8, conf_bytes);
                merged.confirmation.deinit();
                conf_owned = false;
                self.used = merged.used;
                used_owned = false;
                batch.used_messages = used_bytes;
                batch.own_confirmation = batch_conf;
                if (self.own_confirmation_bytes) |old| self.gpa.free(old);
                self.own_confirmation_bytes = own_conf;
                adv.confirmation_to_submit = conf_bytes;
            },
            .observer => |*o| {
                const msgs = try self.gpa.alloc(*const dkg.Message, list.items.len);
                defer self.gpa.free(msgs);
                for (list.items, msgs) |pm, *d| d.* = &pm.message;
                o.merge(msgs) catch return;
                // used messages for an observer carry no shares
                var arena = std.heap.ArenaAllocator.init(self.gpa);
                errdefer arena.deinit();
                const items = try arena.allocator().alloc(dkg.ProcessedMessage, list.items.len);
                for (list.items, items) |pm, *d| d.* = try pm.clone(arena.allocator());
                var u: dkg.Owned(dkg.UsedProcessedMessages) = .{ .arena = arena, .value = .{ .items = items } };
                errdefer u.deinit();
                var uw = wire.Writer.init(self.gpa);
                errdefer uw.deinit();
                try u.value.encode(&uw);
                batch.used_messages = try uw.toOwnedSlice();
                self.used = u;
            },
        }
    }

    fn tryCompleteDkg(self: *Manager, batch: *Batch) Error!void {
        if (self.output != .unset or self.used == null) return;
        const used = &self.used.?;
        var confs: std.ArrayList(*const dkg.Confirmation) = .empty;
        defer confs.deinit(self.gpa);
        for (self.confirmations) |*c| if (c.*) |*x| try confs.append(self.gpa, &x.value);

        var out = switch (self.role) {
            .party => |*p| p.complete(self.gpa, &used.value, confs.items, self.rng) catch return,
            .observer => |*o| blk: {
                const msgs = try self.gpa.alloc(*const dkg.Message, used.value.items.len);
                defer self.gpa.free(msgs);
                for (used.value.items, msgs) |*m, *d| d.* = &m.message;
                break :blk o.complete(self.gpa, msgs, confs.items, self.rng) catch return;
            },
        };
        errdefer out.deinit();
        var w = wire.Writer.init(self.gpa);
        errdefer w.deinit();
        try out.value.encode(&w);
        batch.dkg_output = .{ .success = try w.toOwnedSlice() };
        self.output = .{ .ready = out };
    }

    fn isPastTimeoutRound(self: *const Manager, round: u32) bool {
        return round > self.params.protocol.random_beacon_dkg_timeout_round;
    }

    pub fn dkgStatus(self: *const Manager) DkgStatus {
        return switch (self.output) {
            .ready => .successful,
            .failed => .timed_out,
            .unset => .pending,
        };
    }

    /// `dkg_status_for_commit_round`: with late completion an incomplete DKG reads as timed out
    /// for commits past the timeout round while the protocol keeps running.
    pub fn dkgStatusForCommitRound(self: *Manager, round: u32) DkgStatus {
        const s = self.dkgStatus();
        if (s != .pending) return s;
        if (!self.params.protocol.allow_dkg_completion_after_timeout or !self.isPastTimeoutRound(round)) return s;
        self.dkg_timeout_reported = true;
        return .timed_out;
    }

    /// The beacon public key (c0 of the VSS polynomial) once the DKG succeeded.
    pub fn publicKey(self: *const Manager) ?group.G2P {
        return switch (self.output) {
            .ready => |*o| o.value.publicKey(),
            else => null,
        };
    }

    pub fn output_(self: *const Manager) ?*const dkg.Output {
        return switch (self.output) {
            .ready => |*o| &o.value,
            else => null,
        };
    }

    // ------------------------------------------------------------------------- rounds

    /// `reserve_next_randomness`: the round to schedule for this commit, if the minimum interval
    /// since the previous round passed (wrapping subtraction like the release build of Rust).
    pub fn reserveNextRandomness(self: *Manager, batch: *Batch, commit_timestamp_ms: u64) ?u64 {
        if (self.last_round_timestamp_ms) |last| {
            if (commit_timestamp_ms -% last < self.params.protocol.random_beacon_min_round_interval_ms) return null;
        }
        const round = self.next_randomness_round;
        self.next_randomness_round += 1;
        self.last_round_timestamp_ms = commit_timestamp_ms;
        batch.reserved_round = .{ .next_round = self.next_randomness_round, .timestamp_ms = commit_timestamp_ms };
        return round;
    }

    /// `notify_randomness_in_checkpoint`: true when the highest completed round advanced (the
    /// caller persists it and completes the round in the signature collector).
    pub fn notifyRandomnessInCheckpoint(self: *Manager, round: u64) bool {
        if (self.highest_completed_round == null or round > self.highest_completed_round.?) {
            self.highest_completed_round = round;
            return true;
        }
        return false;
    }

    /// `generate_randomness` for a validator: this party's partial signatures for `round`, one
    /// per share (ascending share index). NoShares for an observer, a failed DKG or a party whose
    /// shares were invalid.
    pub fn partialSignatures(self: *const Manager, arena: std.mem.Allocator, round: u64) Error![]tbls.PartialSignature {
        if (self.role != .party) return error.NoShares;
        const out = self.output_() orelse return error.NoShares;
        const shares = out.shares orelse return error.NoShares;
        const msg = tbls.roundMessage(round);
        return tbls.partialSignBatch(arena, shares, &msg);
    }

    // ------------------------------------------------------------------------- restore

    pub fn loadOutput(self: *Manager, bytes: []const u8) Error!void {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        errdefer arena.deinit();
        var r = wire.Reader.init(bytes);
        const o = try dkg.Output.decodeFrom(arena.allocator(), &r);
        try r.finish();
        if (self.output == .ready) self.output.ready.deinit();
        self.output = .{ .ready = .{ .arena = arena, .value = o } };
    }

    pub fn loadOutputFailed(self: *Manager) void {
        self.output = .failed;
    }

    pub fn loadProcessed(self: *Manager, sender: u16, bytes: []const u8) Error!void {
        if (sender >= self.processed.len) return error.InvalidInput;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        errdefer arena.deinit();
        var r = wire.Reader.init(bytes);
        const m = try dkg.ProcessedMessage.decodeFrom(arena.allocator(), &r);
        try r.finish();
        if (self.processed[sender]) |*old| old.deinit();
        self.processed[sender] = .{ .arena = arena, .value = m };
        self.persisted[sender] = true;
    }

    pub fn loadUsed(self: *Manager, bytes: []const u8) Error!void {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        errdefer arena.deinit();
        var r = wire.Reader.init(bytes);
        const m = try dkg.UsedProcessedMessages.decodeFrom(arena.allocator(), &r);
        try r.finish();
        for (m.items) |it| if (it.message.sender >= self.processed.len) return error.InvalidInput;
        if (self.used) |*old| old.deinit();
        self.used = .{ .arena = arena, .value = m };
    }

    pub fn loadConfirmation(self: *Manager, sender: u16, versioned: []const u8) Error!void {
        if (sender >= self.confirmations.len) return error.InvalidInput;
        var v = try dkg.decodeVersionedConfirmation(self.gpa, versioned);
        switch (v) {
            .v0 => return error.UnsupportedVersion,
            .v1 => |*o| {
                if (self.confirmations[sender]) |*old| old.deinit();
                self.confirmations[sender] = o.*;
            },
        }
    }

    pub fn loadOwnConfirmation(self: *Manager, versioned: []const u8) Error!void {
        if (self.own_confirmation_bytes) |old| self.gpa.free(old);
        self.own_confirmation_bytes = try self.gpa.dupe(u8, versioned);
    }

    pub fn loadRounds(self: *Manager, next_round: ?u64, last_timestamp_ms: ?u64, highest_completed: ?u64) void {
        if (next_round) |r| self.next_randomness_round = r;
        self.last_round_timestamp_ms = last_timestamp_ms;
        self.highest_completed_round = highest_completed;
    }

    /// Rounds whose partial signatures must be re-sent after a restart: highest completed + 1 up
    /// to (excluding) the next round.
    pub fn incompleteRounds(self: *const Manager) struct { first: u64, end: u64 } {
        const first = if (self.highest_completed_round) |h| h + 1 else 0;
        return .{ .first = first, .end = self.next_randomness_round };
    }
};

fn observerProcessed(gpa: std.mem.Allocator, m: *const dkg.Message) Error!dkg.Owned(dkg.ProcessedMessage) {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const pm: dkg.ProcessedMessage = .{ .message = try m.clone(arena.allocator()), .shares = &.{}, .complaint = null };
    return .{ .arena = arena, .value = pm };
}

// ---------------------------------------------------------------------------------------------
// tests

const TestCommittee = struct {
    secrets: [4][32]u8,
    members: [4]Member,

    fn init(rng: std.Random, stakes: [4]u64) TestCommittee {
        var c: TestCommittee = undefined;
        for (0..4) |i| {
            const s = group.scalarRand(rng);
            c.secrets[i] = group.scalarToBytes(s);
            c.members[i] = .{
                .name = group.g2ToBytes(group.mulPublic(G2, group.g2Generator(), s)),
                .stake = stakes[i],
            };
        }
        return c;
    }
};

test "four validators and an observer run the DKG through a mock consensus, then the beacon" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(2024);
    const rng = prng.random();
    // stakes sum to 10000 like a real committee; reduction brings the weights down
    const com = TestCommittee.init(rng, .{ 2500, 2500, 2500, 2500 });
    const params: Params = .{
        .epoch = 7,
        .chain_id = @splat(0xab),
        .members = &com.members,
        .protocol = .{ .random_beacon_reduction_lower_bound = 8, .random_beacon_reduction_allowed_delta = 800 },
    };
    var mgrs: [5]*Manager = undefined;
    for (0..4) |i| mgrs[i] = try Manager.createForTesting(gpa, params, &com.secrets[i], rng);
    mgrs[4] = try Manager.createForTesting(gpa, params, null, rng);
    defer for (mgrs) |m| m.destroy();
    try std.testing.expect(mgrs[0].threshold() >= 1);

    // epoch start: every validator deals
    var msgs: [4][]u8 = undefined;
    for (0..4) |i| msgs[i] = (try mgrs[i].startDkg()).?;
    defer for (msgs) |m| gpa.free(m);
    try std.testing.expect((try mgrs[4].startDkg()) == null);

    // consensus orders the messages; every node (incl. the observer) records them
    for (mgrs) |m| for (0..4) |j| try m.addMessage(&com.members[j].name, msgs[j]);
    // duplicates are ignored
    try std.testing.expectError(error.DuplicateMessage, mgrs[0].addMessage(&com.members[1].name, msgs[1]));
    // equivocation: a message claiming another party id
    try std.testing.expectError(error.Equivocation, mgrs[0].addMessage(&com.members[2].name, msgs[1]));

    // commit 1: advance, collecting the confirmations
    var confs: [4]?[]u8 = @splat(null);
    defer for (confs) |c| if (c) |x| gpa.free(x);
    for (mgrs, 0..) |m, i| {
        var batch = Batch.init(gpa);
        defer batch.deinit();
        var adv = try m.advanceDkg(&batch, 10);
        defer adv.deinit(gpa);
        try std.testing.expect(batch.processed.items.len > 0);
        try std.testing.expect(batch.used_messages != null);
        if (i < 4) {
            try std.testing.expect(adv.confirmation_to_submit != null);
            confs[i] = adv.confirmation_to_submit;
            adv.confirmation_to_submit = null;
            try std.testing.expect(batch.own_confirmation != null);
        } else try std.testing.expect(adv.confirmation_to_submit == null);
        try std.testing.expectEqual(DkgStatus.pending, m.dkgStatus());
    }

    // consensus orders the confirmations; commit 2 completes the DKG everywhere
    for (mgrs) |m| {
        var batch = Batch.init(gpa);
        defer batch.deinit();
        for (0..4) |j| try m.addConfirmation(&batch, &com.members[j].name, confs[j].?);
        try std.testing.expectEqual(@as(usize, 4), batch.confirmations.items.len);
        var adv = try m.advanceDkg(&batch, 11);
        defer adv.deinit(gpa);
        try std.testing.expect(batch.dkg_output != null);
        try std.testing.expectEqual(DkgStatus.successful, m.dkgStatus());
    }
    const pk = mgrs[0].publicKey().?;
    for (mgrs) |m| try std.testing.expect(m.publicKey().?.eql(pk));

    // the beacon: reserve a round, partial signatures from every validator, aggregate, verify
    var batch = Batch.init(gpa);
    defer batch.deinit();
    const r0 = mgrs[0].reserveNextRandomness(&batch, 1_000).?;
    try std.testing.expectEqual(@as(u64, 0), r0);
    try std.testing.expect(mgrs[0].reserveNextRandomness(&batch, 1_100) == null); // inside the interval
    try std.testing.expectEqual(@as(?u64, 1), mgrs[0].reserveNextRandomness(&batch, 1_500));

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var all: std.ArrayList(tbls.PartialSignature) = .empty;
    for (mgrs[0..4]) |m| {
        const ps = try m.partialSignatures(a, 0);
        for (ps) |p| try all.append(a, p);
    }
    const out = mgrs[0].output_().?;
    try tbls.partialVerifyBatch(a, out.vss_pk, &tbls.roundMessage(0), all.items, rng);
    const sig = try tbls.aggregate(a, mgrs[0].threshold(), all.items);
    try tbls.verify(pk, &tbls.roundMessage(0), sig);
    try std.testing.expectError(error.NoShares, mgrs[4].partialSignatures(a, 0));
    try std.testing.expect(mgrs[0].notifyRandomnessInCheckpoint(0));
    try std.testing.expect(!mgrs[0].notifyRandomnessInCheckpoint(0));
}

test "dkg that never gets messages times out after the timeout round" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5);
    const rng = prng.random();
    const com = TestCommittee.init(rng, .{ 2500, 2500, 2500, 2500 });
    const params: Params = .{ .epoch = 1, .chain_id = @splat(1), .members = &com.members, .protocol = .{ .random_beacon_reduction_lower_bound = 8 } };
    const m = try Manager.createForTesting(gpa, params, &com.secrets[0], rng);
    defer m.destroy();
    var b1 = Batch.init(gpa);
    defer b1.deinit();
    var a1 = try m.advanceDkg(&b1, 3000);
    defer a1.deinit(gpa);
    try std.testing.expectEqual(DkgStatus.pending, m.dkgStatus());
    var b2 = Batch.init(gpa);
    defer b2.deinit();
    var a2 = try m.advanceDkg(&b2, 3001);
    defer a2.deinit(gpa);
    try std.testing.expectEqual(DkgStatus.timed_out, m.dkgStatus());
    try std.testing.expect(b2.dkg_output != null and b2.dkg_output.? == .failed);
}

test "restart restores the dkg output and rounds" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(31);
    const rng = prng.random();
    const com = TestCommittee.init(rng, .{ 2500, 2500, 2500, 2500 });
    const params: Params = .{ .epoch = 2, .chain_id = @splat(2), .members = &com.members, .protocol = .{ .random_beacon_reduction_lower_bound = 8 } };
    var mgrs: [4]*Manager = undefined;
    for (0..4) |i| mgrs[i] = try Manager.createForTesting(gpa, params, &com.secrets[i], rng);
    defer for (mgrs) |m| m.destroy();
    var msgs: [4][]u8 = undefined;
    for (0..4) |i| msgs[i] = (try mgrs[i].startDkg()).?;
    defer for (msgs) |m| gpa.free(m);
    for (mgrs) |m| for (0..4) |j| try m.addMessage(&com.members[j].name, msgs[j]);
    var confs: [4][]u8 = undefined;
    for (mgrs, 0..) |m, i| {
        var batch = Batch.init(gpa);
        defer batch.deinit();
        var adv = try m.advanceDkg(&batch, 5);
        confs[i] = adv.confirmation_to_submit.?;
        adv.confirmation_to_submit = null;
    }
    defer for (confs) |c| gpa.free(c);
    var out_bytes: ?[]u8 = null;
    defer if (out_bytes) |b| gpa.free(b);
    for (mgrs, 0..) |m, i| {
        var batch = Batch.init(gpa);
        defer batch.deinit();
        for (0..4) |j| try m.addConfirmation(&batch, &com.members[j].name, confs[j]);
        var adv = try m.advanceDkg(&batch, 6);
        defer adv.deinit(gpa);
        if (i == 0) {
            out_bytes = batch.dkg_output.?.success;
            batch.dkg_output = null; // keep ownership of the bytes
        }
    }
    const fresh = try Manager.createForTesting(gpa, params, &com.secrets[0], rng);
    defer fresh.destroy();
    try fresh.loadOutput(out_bytes.?);
    fresh.loadRounds(5, 4_000, 2);
    try std.testing.expect(fresh.publicKey().?.eql(mgrs[0].publicKey().?));
    try std.testing.expectEqual(DkgStatus.successful, fresh.dkgStatus());
    const rr = fresh.incompleteRounds();
    try std.testing.expectEqual(@as(u64, 3), rr.first);
    try std.testing.expectEqual(@as(u64, 5), rr.end);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const ps = try fresh.partialSignatures(arena_state.allocator(), 3);
    try std.testing.expect(ps.len > 0);
}
