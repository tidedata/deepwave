//! The validator's SubmitTransaction and WaitForEffects logic (authority_server.rs
//! `handle_submit_transaction_inner`, `wait_for_effects_response`, mainnet-v1.83.1), typed: the
//! `sui.validator.Validator` gRPC server (val-epoch-api-keys, src/validator/api) decodes the
//! prost messages, calls `Submit.handle` / `WaitForEffects.poll`, and encodes the answers with
//! `rpc_exec.driver.wire`.
//!
//! SubmitTransaction, per transaction in request order:
//!   1. decode `Transaction`, `validity_check` (and the size it returns), the proposer allowed
//!      check for this validator, duplicate digests (an error for a soft bundle), soft bundle
//!      members share one gas price and one allowed-proposer set;
//!   2. overload checks: system and consensus (`Rejected`);
//!   3. signature verification (address aliases on: with the current alias state);
//!   4. already executed: `Executed{effects_digest}` (effects against what was signed);
//!      executed in the last epoch: rejected (TransactionAlreadyExecuted);
//!   5. consensus message already processed: owned-object lock conflict -> rejected, otherwise
//!      revalidate and answer TransactionProcessing;
//!   6. in-flight and recently submitted suppression (TransactionSubmitted);
//!   7. `handle_vote_transaction`: reconfig halt, deny checks, inputs live at the claimed ref;
//!   8. claims (immutable input ids, address aliases V2) and the ConsensusTransaction
//!      `UserTransactionV2`, handed to the adapter; a ticket stands for the consensus position.
//! A ping request carries no transaction and returns the position of the next block.
//!
//! WaitForEffects: effects first (executed -> `Executed`), then the consensus position's fate
//! (rejected or dropped -> `Rejected` with the cached vote reason, expired -> `Expired`), a
//! position too far ahead is an error, finalized keeps waiting for effects. A ping answers when
//! its position is finalized.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const sig = @import("sig");
const hash = @import("hash");
const consensus = @import("consensus");
const messages = @import("../messages.zig");
const iface = @import("../iface.zig");
const tx_mod = @import("tx.zig");
const checker = @import("checker.zig");
const env_mod = @import("env.zig");
const state_mod = @import("state.zig");
const status_mod = @import("status.zig");
const adapter_mod = @import("adapter.zig");
const exec_bridge = @import("exec_bridge.zig");
const tx_validator = @import("tx_validator.zig");
const handler_mod = @import("handler.zig");
const preverify = @import("preverify.zig");

const Allocator = std.mem.Allocator;
pub const Id = tx_mod.Id;

pub const SubmitType = enum(i32) { default = 0, ping = 1, soft_bundle = 2 };

pub const Request = struct {
    submit_type: SubmitType = .default,
    /// BCS(Transaction) each.
    transactions: []const []const u8,
};

pub const Result = union(enum) {
    /// Handed to consensus: the ticket resolves to a consensus position (`Adapter.positionOf`).
    submitted: u64,
    executed: struct { effects_digest: Id },
    rejected: []const u8,
};

pub const Response = struct {
    results: []const Result,
};

pub const RequestError = error{ InvalidRequest, TransactionDeserialization, ValidatorHalted, OutOfMemory };

/// Errors that fail the whole request (a gRPC error) are returned with their SuiError text here.
pub const Failure = struct { kind: RequestError, message: []const u8 };

pub const Hooks = struct {
    ctx: ?*anyopaque = null,
    /// `get_executed_effects(digest)`: the effects digest when executed.
    executed_effects: ?*const fn (ctx: *anyopaque, digest: *const Id) ?Id = null,
    executed_in_last_epoch: ?*const fn (ctx: *anyopaque, digest: *const Id) bool = null,
    /// `check_system_overload`: error text when overloaded.
    system_overload: ?*const fn (ctx: *anyopaque) ?[]const u8 = null,
    /// `check_consensus_overload` (the adapter's own limit is checked separately).
    consensus_overload: ?*const fn (ctx: *anyopaque) ?[]const u8 = null,
};

pub const Submit = struct {
    gpa: Allocator,
    params: env_mod.Params,
    cfg: *const protocol.ProtocolConfig,
    check_env: *const checker.Env,
    state: *state_mod.EpochState,
    epoch_ctl: env_mod.EpochControl,
    adapter: *adapter_mod.Adapter,
    own_index: ?u32,
    own_name: iface.AuthorityName,
    hooks: Hooks = .{},
    /// In-flight transactions (digest -> submission time ms) and the suppression window.
    inflight: std.AutoHashMapUnmanaged(Id, u64) = .empty,
    inflight_lock: adapter_mod.Spin = .{},
    recent_window_ms: u64 = 5_000,
    /// Wall clock in ms; required, there is no usable default.
    now_ms: *const fn () u64,
    stats: struct { submitted: u64 = 0, rejected: u64 = 0, executed: u64 = 0, suppressed: u64 = 0 } = .{},
    /// Signature pre-verification of a request's transactions (preverify.zig; zui-only, the
    /// results do not change).
    preverify: preverify.Config = .{},
    preverify_stats: preverify.Stats = .{},

    pub fn deinit(s: *Submit) void {
        s.inflight.deinit(s.gpa);
    }

    fn reject(arena: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!Result {
        return .{ .rejected = try std.fmt.allocPrint(arena, fmt, args) };
    }

    /// Handles one request. Whole-request failures come back as `error.Failed` with `failure`
    /// set; per-transaction outcomes are in the response.
    pub fn handle(s: *Submit, arena: Allocator, req: Request, failure: *Failure) error{ Failed, OutOfMemory }!Response {
        const p = s.params;
        const is_ping = req.submit_type == .ping;
        if (is_ping) {
            if (req.transactions.len != 0) return fail(failure, error.InvalidRequest, try std.fmt.allocPrint(arena, "Ping request cannot contain {d} transactions", .{req.transactions.len}));
            // A ping is an empty block slot in Rust (`PING_TRANSACTION_INDEX`); the core's
            // proposer for it is not built yet, and a made-up payload would invalidate our block
            // at every peer. Answered as a rejection until consensus exposes the empty slot.
            const r = try arena.alloc(Result, 1);
            r[0] = .{ .rejected = "Ping is not supported by this validator yet" };
            return .{ .results = r };
        }
        if (req.transactions.len == 0) return fail(failure, error.InvalidRequest, "At least one transaction needs to be submitted");
        const is_bundle = req.submit_type == .soft_bundle;
        const max_n: usize = if (is_bundle) 5 else 128;
        if (req.transactions.len > max_n) return fail(failure, error.InvalidRequest, try std.fmt.allocPrint(arena, "Too many transactions in request: {d} vs {d}", .{ req.transactions.len, max_n }));

        const results = try arena.alloc(?Result, req.transactions.len);
        @memset(results, null);
        var to_submit: std.ArrayList([]const u8) = .empty;
        var to_submit_idx: std.ArrayList(usize) = .empty;
        var seen: std.AutoHashMapUnmanaged(Id, void) = .empty;
        var bundle_price: ?u64 = null;
        var to_submit_digest: std.ArrayList(Id) = .empty;
        var to_submit_ckey: std.ArrayList([32]u8) = .empty;

        // signature pre-verification (decode, validity, then the signatures of the transactions
        // the loop below can reach the signature step for), across the pool's lanes
        var pre: ?preverify.Batch = null;
        defer if (pre) |*b| b.deinit();
        if (s.preverify.active(req.transactions.len)) {
            pre = try preverify.Batch.initRaw(s.gpa, arena, &s.preverify, s.check_env, req.transactions);
            pre.?.stats = &s.preverify_stats;
            pre.?.decode();
            try s.markNeeded(arena, pre.?.slots, is_bundle);
            try pre.?.verify(arena);
        }

        for (req.transactions, 0..) |raw, idx| {
            const slot: ?*const preverify.Slot = if (pre) |*b| &b.slots[idx] else null;
            const t = if (slot != null and slot.?.t != null) slot.?.t.? else bcs.decode(messages.Transaction, arena, raw) catch return fail(failure, error.TransactionDeserialization, try std.fmt.allocPrint(arena, "Failed to deserialize transaction at index {d}", .{idx}));
            // decoded as a UserTx with no claims (claims are added below)
            const pt: messages.PlainTransactionWithClaims = .{ .tx = t, .claims = &.{} };
            var u_local: tx_mod.UserTx = undefined;
            const u: *const tx_mod.UserTx = if (slot != null and slot.?.u != null) &slot.?.u.? else blk: {
                u_local = tx_mod.fromDecoded(arena, raw, pt) catch return fail(failure, error.TransactionDeserialization, "Invalid transaction");
                break :blk &u_local;
            };
            const validity = if (slot != null and slot.?.validity != null) slot.?.validity.? else checker.checkValidity(arena, s.check_env, u);
            if (validity catch return error.OutOfMemory) |f| return fail(failure, error.InvalidRequest, try arena.dupe(u8, f.message));
            // this validator must be allowed to propose it
            if (p.allowed_proposers and u.restrictsProposers(p.epoch)) {
                const own = s.own_index orelse return fail(failure, error.InvalidRequest, "this node is not a member of the current committee");
                if (!u.isAllowedProposer(own, p.epoch)) return fail(failure, error.InvalidRequest, try std.fmt.allocPrint(arena, "Proposer {d} is not allowed to propose this transaction", .{own}));
            }
            const gop = try seen.getOrPut(arena, u.digest);
            if (gop.found_existing) {
                const msg = try std.fmt.allocPrint(arena, "Repeated transaction {s}", .{checkerHex(&u.digest)});
                if (is_bundle) return fail(failure, error.InvalidRequest, msg);
                results[idx] = .{ .rejected = msg };
                continue;
            }
            if (is_bundle) {
                if (bundle_price) |exp| {
                    if (u.gas_price != exp) return fail(failure, error.InvalidRequest, try std.fmt.allocPrint(arena, "Gas price mismatch in soft bundle: expected {d}, got {d}", .{ exp, u.gas_price }));
                } else bundle_price = u.gas_price;
            }

            // overload
            if (s.hooks.system_overload) |f| if (f(s.hooks.ctx.?)) |why| {
                results[idx] = .{ .rejected = why };
                continue;
            };
            if (s.hooks.consensus_overload) |f| if (f(s.hooks.ctx.?)) |why| {
                results[idx] = .{ .rejected = why };
                continue;
            };
            if (s.adapter.pendingUser() >= s.adapter.limits.max_pending_user) {
                results[idx] = .{ .rejected = "Validator consensus queue is overloaded, retry later" };
                continue;
            }

            // signatures
            const sr_pre = if (slot != null and slot.?.sig != null) slot.?.sig.? else checker.verifySignatures(arena, s.check_env, u, &.{});
            const sr = sr_pre catch return error.OutOfMemory;
            const derived = switch (sr) {
                .fail => |f| return fail(failure, error.InvalidRequest, try arena.dupe(u8, f.message)),
                .ok => |d| d,
            };

            // already executed
            if (s.hooks.executed_effects) |f| if (f(s.hooks.ctx.?, &u.digest)) |ed| {
                results[idx] = .{ .executed = .{ .effects_digest = ed } };
                s.stats.executed += 1;
                continue;
            };
            if (s.hooks.executed_in_last_epoch) |f| if (f(s.hooks.ctx.?, &u.digest)) {
                results[idx] = try reject(arena, "Transaction {s} already executed", .{checkerHex(&u.digest)});
                continue;
            };

            // consensus message already processed
            var key_buf: [33]u8 = undefined;
            key_buf[0] = 0;
            key_buf[1..33].* = u.digest;
            const key = hash.blake2b256(&.{&key_buf});
            if (s.state.isProcessed(&key)) {
                const refs = try u.refsToLock(arena);
                var conflict = false;
                for (refs) |r| if (s.state.lockHolder(r)) |holder| if (!std.mem.eql(u8, &holder, &u.digest)) {
                    conflict = true;
                };
                if (conflict) {
                    results[idx] = .{ .rejected = "Object is locked by another transaction" };
                    s.stats.rejected += 1;
                    continue;
                }
                results[idx] = try reject(arena, "Transaction {s} is being processed: consensus message processed", .{checkerHex(&u.digest)});
                continue;
            }

            // in-flight suppression: only transactions that really reached the adapter are marked
            // (after submitTracked below), so a rejected one can be retried at once
            {
                s.inflight_lock.lock();
                defer s.inflight_lock.unlock();
                const now = s.now_ms();
                if (s.inflight.get(u.digest)) |at| if (now -| at < s.recent_window_ms) {
                    s.stats.suppressed += 1;
                    results[idx] = try reject(arena, "Transaction {s} was already submitted", .{checkerHex(&u.digest)});
                    continue;
                };
            }

            // handle_vote_transaction
            if (!s.epoch_ctl.reconfigState().shouldAcceptUserCerts()) return fail(failure, error.ValidatorHalted, "Validator halted at epoch end");
            if (checker.checkInputs(arena, s.check_env, u, .{ .validity = false }) catch return error.OutOfMemory) |f| {
                results[idx] = .{ .rejected = f.message };
                s.stats.rejected += 1;
                continue;
            }

            // claims
            var claims: std.ArrayList(messages.TransactionClaim) = .empty;
            const imm = try s.immutableInputIds(arena, u);
            if (imm.len != 0) try claims.append(arena, .{ .ImmutableInputObjects = imm });
            if (s.cfg.feature_flags.address_aliases) {
                const al = try arena.alloc(struct { u8, ?types.SequenceNumber }, derived.len);
                for (derived, al) |d, *o| o.* = .{ d.sig_index, if (d.alias_version) |v| handler_mod.seqn(v) else null };
                try claims.append(arena, .{ .AddressAliasesV2 = al });
            }
            const ct: messages.ConsensusTransaction = .{
                .tracking_id = trackingId(&u.digest, &s.own_name),
                .kind = .{ .UserTransactionV2 = .{ .tx = t, .claims = claims.items } },
            };
            const bytes = try bcs.encodeAlloc(messages.ConsensusTransaction, arena, &ct);
            try to_submit.append(arena, bytes);
            try to_submit_idx.append(arena, idx);
            try to_submit_digest.append(arena, u.digest);
            try to_submit_ckey.append(arena, key);
        }

        if (to_submit.items.len != 0) {
            const tickets = try arena.alloc(u64, to_submit.items.len);
            const prio: adapter_mod.Priority = if (is_bundle) .soft_bundle else .user;
            if (s.adapter.submitTracked(to_submit.items, prio, tickets, to_submit_ckey.items)) |_| {
                s.inflight_lock.lock();
                defer s.inflight_lock.unlock();
                const now = s.now_ms();
                s.pruneInflight(now);
                for (to_submit_idx.items, tickets, to_submit_digest.items) |i, tk, dg| {
                    results[i] = .{ .submitted = tk };
                    s.stats.submitted += 1;
                    s.inflight.put(s.gpa, dg, now) catch {};
                }
            } else |e| {
                const msg: []const u8 = switch (e) {
                    error.Overloaded => "Validator consensus queue is overloaded, retry later",
                    error.EpochEnding => "Validator halted at epoch end",
                    error.Unimplemented => "consensus unavailable",
                };
                for (to_submit_idx.items) |i| results[i] = .{ .rejected = msg };
            }
        }
        const out = try arena.alloc(Result, results.len);
        for (results, out) |r, *o| o.* = r orelse .{ .rejected = "no result" };
        return .{ .results = out };
    }

    /// Which transactions the serial loop of `handle` can reach the signature step for, from
    /// the stage's decode and validity results: none after the first request-level failure
    /// (decode, validity, proposer, soft-bundle gas price or duplicate), none for a repeated
    /// digest. Only saves work: a slot left unmarked is verified by the loop itself if reached.
    fn markNeeded(s: *Submit, arena: Allocator, slots: []preverify.Slot, is_bundle: bool) Allocator.Error!void {
        const p = s.params;
        var seen: std.AutoHashMapUnmanaged(Id, void) = .empty;
        var bundle_price: ?u64 = null;
        for (slots) |*sl| {
            if (!sl.validityOk()) return;
            const u = &sl.u.?;
            if (p.allowed_proposers and u.restrictsProposers(p.epoch)) {
                const own = s.own_index orelse return;
                if (!u.isAllowedProposer(own, p.epoch)) return;
            }
            if ((try seen.getOrPut(arena, u.digest)).found_existing) {
                if (is_bundle) return;
                continue;
            }
            if (is_bundle) {
                if (bundle_price) |exp| {
                    if (u.gas_price != exp) return;
                } else bundle_price = u.gas_price;
            }
            sl.need_sig = true;
        }
    }

    /// Drops marks older than the suppression window once the map is non-trivial (caller holds the lock).
    fn pruneInflight(s: *Submit, now: u64) void {
        if (s.inflight.count() < 1024) return;
        var dead: std.ArrayList(Id) = .empty;
        defer dead.deinit(s.gpa);
        var it = s.inflight.iterator();
        while (it.next()) |kv| if (now -| kv.value_ptr.* >= s.recent_window_ms) dead.append(s.gpa, kv.key_ptr.*) catch break;
        for (dead.items) |k| _ = s.inflight.remove(k);
    }

    fn fail(failure: *Failure, kind: RequestError, msg: []const u8) error{Failed} {
        failure.* = .{ .kind = kind, .message = msg };
        return error.Failed;
    }

    /// `collect_immutable_object_ids`: owned inputs that are immutable in the store.
    fn immutableInputIds(s: *Submit, arena: Allocator, u: *const tx_mod.UserTx) Allocator.Error![]const types.ObjectID {
        var out: std.ArrayList(types.ObjectID) = .empty;
        const exec = @import("exec");
        for (u.owned) |o| {
            const live = s.check_env.state.latest(&o.id) orelse continue;
            const v = exec.objects.ObjectView.parse(live) catch continue;
            const owner = bcs.decode(types.Owner, arena, live[v.owner_at..v.prev_tx_at]) catch continue;
            if (owner == .Immutable) try out.append(arena, handler_mod.oid(o.id));
        }
        return out.items;
    }
};

fn trackingId(digest: *const Id, name: *const iface.AuthorityName) [8]u8 {
    const h = hash.blake2b256(&.{ digest, &name.@"0" });
    return h[0..8].*;
}

fn checkerHex(id: *const Id) []const u8 {
    const S = struct {
        threadlocal var buf: [66]u8 = undefined;
    };
    S.buf[0] = '0';
    S.buf[1] = 'x';
    S.buf[2..66].* = std.fmt.bytesToHex(id.*, .lower);
    return &S.buf;
}

/// BCS of `ConsensusPosition { epoch, block: BlockRef { round, author, digest }, index }`.
pub fn encodePosition(buf: *[8 + 4 + 4 + 32 + 2]u8, epoch: u64, p: adapter_mod.Position) []const u8 {
    std.mem.writeInt(u64, buf[0..8], epoch, .little);
    std.mem.writeInt(u32, buf[8..12], p.block.round, .little);
    std.mem.writeInt(u32, buf[12..16], p.block.author, .little);
    buf[16..48].* = p.block.digest;
    std.mem.writeInt(u16, buf[48..50], p.index, .little);
    return buf[0..50];
}

pub fn decodePosition(b: []const u8) ?struct { epoch: u64, pos: status_mod.Position } {
    if (b.len != 50) return null;
    return .{
        .epoch = std.mem.readInt(u64, b[0..8], .little),
        .pos = .{
            .round = std.mem.readInt(u32, b[8..12], .little),
            .author = std.mem.readInt(u32, b[12..16], .little),
            .digest = b[16..48].*,
            .index = std.mem.readInt(u16, b[48..50], .little),
        },
    };
}

// ------------------------------------------------------------------------ WaitForEffects

pub const WaitRequest = struct {
    digest: ?Id = null,
    /// BCS ConsensusPosition.
    consensus_position: ?[]const u8 = null,
    include_details: bool = false,
    ping: bool = false,
};

pub const WaitResponse = union(enum) {
    executed: struct { effects_digest: Id, include_details: bool },
    /// The cached reject vote reason, when this validator cast a reject vote.
    rejected: ?[]const u8,
    expired: struct { epoch: u64, round: ?u32 },
};

pub const Poll = union(enum) {
    ready: WaitResponse,
    /// Neither executed nor decided yet: poll again when something changes.
    pending,
    /// Whole-request errors.
    invalid: []const u8,
    lagging: struct { round: u32, last_committed_round: u64 },
};

pub const WaitForEffects = struct {
    epoch: u64,
    statuses: *status_mod.StatusCache,
    exec: *exec_bridge.Bridge,
    reasons: ?*tx_validator.ReasonCache = null,
    hooks: Hooks = .{},

    /// One non-blocking evaluation of `wait_for_effects_response`. The server loops with a 20 s
    /// deadline (10 s for pings), re-polling when the handler commits or execution advances.
    pub fn poll(w: *const WaitForEffects, arena: Allocator, req: WaitRequest) Poll {
        if (req.ping) return w.pollPing(arena, req);
        const digest = req.digest orelse return .{ .invalid = "Transaction digest is required for wait for effects requests" };
        // effects first (notify_read_executed_effects wins the select when both are ready)
        if (w.exec.effectsDigest(&digest)) |ed| return .{ .ready = .{ .executed = .{ .effects_digest = ed, .include_details = req.include_details } } };
        if (w.hooks.executed_effects) |f| if (f(w.hooks.ctx.?, &digest)) |ed| return .{ .ready = .{ .executed = .{ .effects_digest = ed, .include_details = req.include_details } } };
        const pos_bytes = req.consensus_position orelse return .pending;
        const dp = decodePosition(pos_bytes) orelse return .{ .invalid = "invalid consensus position" };
        if (w.statuses.tooAhead(dp.pos)) return .{ .lagging = .{ .round = dp.pos.round, .last_committed_round = w.statuses.lastCommitted() } };
        return switch (w.statuses.poll(dp.pos)) {
            .status => |st| switch (st) {
                .rejected, .dropped => .{ .ready = .{ .rejected = w.reasonFor(arena, dp.pos) } },
                .finalized => .pending,
            },
            .expired => |r| .{ .ready = .{ .expired = .{ .epoch = w.epoch, .round = @intCast(@min(r, std.math.maxInt(u32))) } } },
            .pending => .pending,
        };
    }

    fn pollPing(w: *const WaitForEffects, arena: Allocator, req: WaitRequest) Poll {
        const pos_bytes = req.consensus_position orelse return .{ .invalid = "Consensus position is required for Ping requests" };
        const dp = decodePosition(pos_bytes) orelse return .{ .invalid = "invalid consensus position" };
        if (w.statuses.tooAhead(dp.pos)) return .{ .lagging = .{ .round = dp.pos.round, .last_committed_round = w.statuses.lastCommitted() } };
        return switch (w.statuses.poll(dp.pos)) {
            .status => |st| switch (st) {
                .rejected, .dropped => .{ .ready = .{ .rejected = w.reasonFor(arena, dp.pos) } },
                .finalized => .{ .ready = .{ .executed = .{ .effects_digest = @splat(0), .include_details = req.include_details } } },
            },
            .expired => |r| .{ .ready = .{ .expired = .{ .epoch = w.epoch, .round = @intCast(@min(r, std.math.maxInt(u32))) } } },
            .pending => .pending,
        };
    }

    fn reasonFor(w: *const WaitForEffects, arena: Allocator, p: status_mod.Position) ?[]const u8 {
        const rc = w.reasons orelse return null;
        return rc.get(arena, .{ .round = p.round, .author = p.author, .digest = p.digest, .index = p.index });
    }
};

// ------------------------------------------------------------------------ tests

test "position encoding round trip" {
    var buf: [50]u8 = undefined;
    const b: consensus.types.BlockRef = .{ .round = 12, .author = 3, .digest = @splat(7) };
    const enc = encodePosition(&buf, 9, .{ .block = b, .index = 4 });
    const dec = decodePosition(enc).?;
    try std.testing.expectEqual(@as(u64, 9), dec.epoch);
    try std.testing.expectEqual(@as(u16, 4), dec.pos.index);
    try std.testing.expectEqual(@as(u32, 12), dec.pos.round);
}

test "wait for effects: executed wins, rejected carries reason, ping finalized" {
    const gpa = std.testing.allocator;
    var statuses: status_mod.StatusCache = .{ .gpa = gpa };
    defer statuses.deinit();
    var reasons: tx_validator.ReasonCache = .{ .gpa = gpa };
    defer reasons.deinit();
    var mem: exec_bridge.MemRunner = .{ .gpa = gpa };
    defer mem.deinit();
    var bridge = exec_bridge.Bridge.init(gpa, mem.runner());
    defer bridge.deinit();
    const w: WaitForEffects = .{ .epoch = 5, .statuses = &statuses, .exec = &bridge, .reasons = &reasons };

    const pos: status_mod.Position = .{ .round = 10, .author = 1, .digest = @splat(2), .index = 3 };
    var pb: [50]u8 = undefined;
    const pos_bytes = encodePosition(&pb, 5, .{ .block = .{ .round = 10, .author = 1, .digest = @splat(2) }, .index = 3 });
    const digest: Id = @splat(9);

    // nothing yet
    try std.testing.expect(w.poll(gpa, .{ .digest = digest, .consensus_position = pos_bytes }) == .pending);
    // missing digest
    try std.testing.expect(w.poll(gpa, .{}) == .invalid);
    // rejected with a reason
    try statuses.set(pos, .rejected);
    try reasons.set(.{ .round = 10, .author = 1, .digest = @splat(2), .index = 3 }, "bad input");
    const r = w.poll(gpa, .{ .digest = digest, .consensus_position = pos_bytes });
    defer gpa.free(r.ready.rejected.?);
    try std.testing.expectEqualStrings("bad input", r.ready.rejected.?);
    // finalized keeps waiting for effects, ping answers
    try statuses.set(.{ .round = 10, .author = 1, .digest = @splat(2), .index = 4 }, .finalized);
    var pb2: [50]u8 = undefined;
    const pos2 = encodePosition(&pb2, 5, .{ .block = .{ .round = 10, .author = 1, .digest = @splat(2) }, .index = 4 });
    try std.testing.expect(w.poll(gpa, .{ .digest = digest, .consensus_position = pos2 }) == .pending);
    const pg = w.poll(gpa, .{ .ping = true, .consensus_position = pos2 });
    try std.testing.expect(pg.ready == .executed);
    // executed effects win
    try bridge.markDone(digest, @splat(1));
    const ex = w.poll(gpa, .{ .digest = digest, .consensus_position = pos_bytes });
    try std.testing.expect(ex.ready == .executed);
}

test "status expiry follows the previous committed round" {
    const gpa = std.testing.allocator;
    var statuses: status_mod.StatusCache = .{ .gpa = gpa };
    defer statuses.deinit();
    const p: status_mod.Position = .{ .round = 1, .author = 0, .digest = @splat(0), .index = 0 };
    statuses.updateLastCommitted(1);
    try std.testing.expect(statuses.poll(p) == .pending);
    statuses.updateLastCommitted(500);
    // the horizon is the previous round (1): 1 + 400 > 1, still pending
    try std.testing.expect(statuses.poll(p) == .pending);
    statuses.updateLastCommitted(501);
    // horizon 500: 1 + 400 <= 500: expired
    try std.testing.expect(statuses.poll(p) == .expired);
}
