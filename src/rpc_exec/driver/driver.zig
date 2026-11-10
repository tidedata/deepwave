//! `TransactionDriver::drive_transaction` (crates/sui-core/src/transaction_driver/) as a sans-IO
//! state machine, with the orchestrator's finality timeout on top.
//!
//! One `Driver` drives one transaction. It never does IO itself: it asks the `Transport` to start
//! and cancel unary validator calls, reads time from the `Clock`, and is fed the answers through
//! `onResponse`. `poll` runs everything that is due and says what happens next:
//!
//! ```
//! var d = try Driver.init(arena, &committee, transport, clock, request, options);
//! while (true) switch (try d.poll()) {
//!     .done => |outcome| break outcome,
//!     .pending => |deadline| io.waitForResponseOrTime(deadline), // calls d.onResponse(...)
//! };
//! ```
//!
//! State machine (each attempt of the retry loop is one submission then one certification):
//!
//! ```
//! start --amplification 0--> done(ValidationFailed)
//!   |
//!   v
//! Submitting --first Ok--> Certifying --certified, full effects match--> done(ok)
//!   | non-retriable / exhausted       | ack or full-effects error
//!   v                                 v
//! (attempt error) --non-retriable--> done(TransactionFailed)
//!   | retriable
//!   v
//! Backoff(100ms..10s, +10s on ValidatorOverloaded) --> Submitting (attempts + 1)
//!
//! any state --finality timeout (90s)--> done(TimeoutBeforeFinality)
//! any state --drive timeout----------> done(TimeoutBeforeFinalityWithErrors)
//! ```
//!
//! Submitting = `TransactionSubmitter::submit_transaction`: `amplification` requests to the first
//! ranked validators, one more after each failure and after each second without an answer
//! (`SUBMIT_TRANSACTION_BACKUP_REQUEST_DELAY`), each bounded by 10s; the first success wins.
//! Certifying = `EffectsCertifier::get_certified_finalized_effects`: `WaitForEffects` without
//! details to every member (10s each, RPC errors retried with backoff) until 2f+1 stake agree on
//! one effects digest, joined with a full-effects request (details) to one validator with a fallback
//! to another acknowledging validator every 200ms.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const serve = @import("serve");
const se = @import("sui_error.zig");
const wire = @import("wire.zig");
const cm = @import("committee.zig");
const errors = @import("errors.zig");

const Committee = cm.Committee;
const RequestError = errors.RequestError;
const DriverError = errors.DriverError;
const SuiErrorKind = se.SuiErrorKind;
const ErrorCategory = se.ErrorCategory;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

pub const CallId = u32;

/// The two `sui.validator.Validator` methods the driver calls.
pub const Method = enum {
    submit_transaction,
    wait_for_effects,

    pub fn path(m: Method) []const u8 {
        return switch (m) {
            .submit_transaction => "/sui.validator.Validator/SubmitTransaction",
            .wait_for_effects => "/sui.validator.Validator/WaitForEffects",
        };
    }
};

/// A gRPC status a validator call ended with (tonic `Status`: code, message, details bytes).
pub const Status = struct { code: u8, message: []const u8 = "", details: []const u8 = "" };

/// What one unary call returned: the response message bytes, or a non-OK status.
pub const RpcResult = union(enum) { ok: []const u8, status: Status };

/// Unary validator calls. `start` must not block; it may deliver the answer at once (from inside
/// `start`) or later, always through `Driver.onResponse(call, ...)`. After `cancel`, answers for
/// that call are ignored. Bodies passed to `start` live as long as the driver's arena.
pub const Transport = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        start: *const fn (ctx: *anyopaque, call: CallId, validator: u32, method: Method, body: []const u8) void,
        cancel: *const fn (ctx: *anyopaque, call: CallId) void,
    };
};

/// Monotonic nanoseconds.
pub const Clock = struct {
    ctx: *anyopaque,
    nowFn: *const fn (ctx: *anyopaque) u64,

    pub fn now(c: Clock) u64 {
        return c.nowFn(c.ctx);
    }
};

/// Mysten's constants (transaction_driver/*.rs, transaction_orchestrator.rs).
pub const Timing = struct {
    submit_timeout: u64 = 10 * ns_per_s, // SUBMIT_TRANSACTION_TIMEOUT
    backup_delay: u64 = 1 * ns_per_s, // SUBMIT_TRANSACTION_BACKUP_REQUEST_DELAY
    wait_for_effects_timeout: u64 = 10 * ns_per_s, // WAIT_FOR_EFFECTS_TIMEOUT
    wait_retry_initial: u64 = 100 * ns_per_ms,
    wait_retry_max: u64 = 2 * ns_per_s, // MAX_WAIT_FOR_EFFECTS_RETRY_DELAY
    full_effects_fallback: u64 = 200 * ns_per_ms, // GET_FULL_EFFECTS_FALLBACK_DELAY
    drive_retry_initial: u64 = 100 * ns_per_ms,
    drive_retry_max: u64 = 10 * ns_per_s, // MAX_DRIVE_TRANSACTION_RETRY_DELAY
    overload_extra: u64 = 10 * ns_per_s, // OVERLOAD_ADDITIONAL_DELAY
};

pub const Options = struct {
    reference_gas_price: u64,
    /// `td_allowed_submission_list` / `td_blocked_submission_list`: display names.
    allowed_validators: []const []const u8 = &.{},
    blocked_validators: []const []const u8 = &.{},
    /// The orchestrator's `WAIT_FOR_FINALITY_TIMEOUT` (null: none).
    finality_timeout: ?u64 = 90 * ns_per_s,
    /// `drive_transaction`'s own timeout; the orchestrator passes its finality timeout. When both
    /// are equal the orchestrator's timer was armed first and wins.
    drive_timeout: ?u64 = 90 * ns_per_s,
    /// `ValidatorClientMonitor` cached latencies by committee index (ns); empty: none known.
    latencies: []const u64 = &.{},
    /// Seeds the validator shuffles and the backoff jitter.
    seed: u64 = 0,
    /// deepwave: submit a transaction to at least this many validators at once (sui-node submits to
    /// gas price / RGP of them, 1 at the reference price). More proposers put the transaction
    /// into consensus sooner and one slow or stuck proposer no longer stalls the drive. Pings
    /// keep their single target.
    min_amplification: u64 = 1,
    /// Submit to this committee member only (the latency check's pings; sui-node passes its
    /// display name in `allowed_validators`).
    only_validator: ?u32 = null,
    /// deepwave: acknowledgment calls to these members ask for the full effects as well
    /// (`include_details`), so the certified effects usually arrive with the quorum instead of
    /// one round trip later.
    detail_acks: []const u32 = &.{},
    /// `ValidatorClientMonitor::record_interaction_result`.
    feedback: ?Feedback = null,
    timing: Timing = .{},
};

/// The operations `ValidatorClientMonitor` keeps statistics for.
pub const Op = enum { submit, effects, finality };

/// `record_interaction_result`: `latency_ns` null records a failure.
pub const Feedback = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, validator: u32, op: Op, latency_ns: ?u64, ping: bool) void,
    /// One attempt failed with an error of `cat` (`drive_transaction_errors`); null: not counted.
    attempt_error: ?*const fn (ctx: *anyopaque, cat: ErrorCategory, ping: bool) void = null,
};

pub const Request = struct {
    /// BCS `Transaction` envelope (what a validator receives); null: a consensus ping.
    transaction: ?[]const u8,
    digest: ?[32]u8 = null,
    gas_price: u64 = 0,
    /// `is_gasless_transaction`: no gas payment, a programmable transaction, price 0.
    gasless: bool = false,
    /// `TransactionExpiration::Validity { allowed_proposers }` (any epoch; filtered here).
    allowed_proposers: ?types.AllowedProposers = null,

    /// From the envelope and its decoded `TransactionData`.
    pub fn fromData(envelope: []const u8, data_bcs: []const u8, data: *const types.TransactionData) Request {
        const v1 = switch (data.*) {
            .V1 => |*v| v,
        };
        const ptb = v1.kind == .ProgrammableTransaction;
        return .{
            .transaction = envelope,
            .digest = types.digest.transactionDataDigest(data_bcs),
            .gas_price = v1.gas_data.price,
            .gasless = v1.gas_data.payment.len == 0 and ptb and v1.gas_data.price == 0,
            .allowed_proposers = switch (v1.expiration) {
                .Validity => |v| v.allowed_proposers,
                else => null,
            },
        };
    }
};

/// `QuorumTransactionResponse` (raw BCS).
pub const QuorumResponse = struct {
    effects_digest: [32]u8,
    effects: []const u8,
    events: ?[]const u8,
    input_objects: ?[]const []const u8,
    output_objects: ?[]const []const u8,
    /// Committee index of the validator the full effects came from.
    source: u32,
};

pub const Outcome = union(enum) {
    ok: QuorumResponse,
    err: errors.SubmissionError,
};

pub const Poll = union(enum) {
    /// Waiting for answers; call `poll` again after an answer or at this time (null: no timer).
    pending: ?u64,
    done: Outcome,
};

/// mysten-common `ExponentialBackoff` (factor 1.2, jitter below the initial delay, added after
/// the cap).
pub const Backoff = struct {
    next: u64,
    max: u64,
    max_jitter: u64,

    pub fn init(initial: u64, max: u64) Backoff {
        return .{ .next = initial, .max = max, .max_jitter = initial };
    }

    pub fn step(b: *Backoff, rng: std.Random) u64 {
        const current = b.next;
        const jitter = if (b.max_jitter == 0) 0 else rng.uintLessThan(u64, b.max_jitter);
        const grown: u64 = @intFromFloat(@as(f64, @floatFromInt(current)) * 1.2);
        b.next = @min(grown, b.max) +| jitter;
        return current;
    }
};

const Inflight = struct { call: CallId, validator: u32, deadline: u64 };

const Agg = cm.StatusAggregator(RequestError);
const Votes = cm.StatusAggregator(void);

/// `RequestRetrier`.
const Retrier = struct {
    ranked: []const u32,
    head: usize = 0,
    non_retriable: Agg,
    retriable: Agg,

    const Filter = struct {
        allowed: []const []const u8 = &.{},
        blocked: []const []const u8 = &.{},
        proposers: ?[]const u32 = null,
        only: ?u32 = null,
    };

    fn init(d: *Driver, f: Filter) !Retrier {
        const c = d.committee;
        const order = try d.rank();
        var out: std.ArrayList(u32) = try .initCapacity(d.arena, order.len);
        for (order) |i| {
            if (f.proposers) |p| if (std.mem.indexOfScalar(u32, p, i) == null) continue;
            if (f.only) |o| if (o != i) continue;
            const name = c.displayName(i);
            if (f.allowed.len > 0 and !contains(f.allowed, name)) continue;
            if (f.blocked.len > 0 and contains(f.blocked, name)) continue;
            out.appendAssumeCapacity(i);
        }
        return .{
            .ranked = out.items,
            .non_retriable = try .init(d.arena, c),
            .retriable = try .init(d.arena, c),
        };
    }

    fn next(r: *Retrier) ?u32 {
        if (r.head >= r.ranked.len) return null;
        r.head += 1;
        return r.ranked[r.head - 1];
    }

    fn rejected(r: *const Retrier, d: *Driver) !DriverError {
        return .{ .RejectedByValidators = .{
            .non_retriable = try errors.aggregate(d.arena, d.committee, r.non_retriable.statuses),
            .retriable = try errors.aggregate(d.arena, d.committee, r.retriable.statuses),
        } };
    }

    fn aborted(r: *const Retrier, d: *Driver) !DriverError {
        return .{ .Aborted = .{
            .non_retriable = try errors.aggregate(d.arena, d.committee, r.non_retriable.statuses),
            .retriable = try errors.aggregate(d.arena, d.committee, r.retriable.statuses),
        } };
    }

    /// `next_target`'s error once the ranked list is empty.
    fn exhausted(r: *const Retrier, d: *Driver) !DriverError {
        return if (r.non_retriable.reachedValidityThreshold()) r.rejected(d) else r.aborted(d);
    }

    /// `add_error`: an error when f+1 stake rejected the transaction as invalid.
    fn addError(r: *Retrier, d: *Driver, i: u32, e: RequestError) !?DriverError {
        if (e.isSubmissionRetriable()) {
            _ = r.retriable.insert(i, e);
            return null;
        }
        _ = r.non_retriable.insert(i, e);
        if (r.non_retriable.reachedValidityThreshold()) return try r.rejected(d);
        return null;
    }
};

fn contains(list: []const []const u8, s: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, s)) return true;
    return false;
}

const Submit = struct {
    retrier: Retrier,
    amp: u64,
    initial: bool = true,
    inflight: std.ArrayList(Inflight) = .empty,
    backup_at: u64 = 0,
};

const FullResult = union(enum) {
    ok: struct { digest: [32]u8, data: wire.ExecutedData },
    err: RequestError,
};

const Ack = struct {
    state: enum { inflight, sleeping, done } = .inflight,
    call: CallId = 0,
    wake: u64 = 0,
    deadline: u64,
    backoff: Backoff,
};

const DigestVotes = struct { digest: [32]u8, votes: Votes };

const Cert = struct {
    target: u32,
    started: u64 = 0,
    /// The validator that accepted the submission.
    submitted_to: u32 = 0,
    /// Executed answers with details from `detail_acks` members (verified), by arrival.
    details: std.ArrayList(struct { validator: u32, digest: [32]u8, data: wire.ExecutedData }) = .empty,
    retrier: Retrier,
    wait_body: []const u8,
    full_body: []const u8,
    // acknowledgments
    acks: []Ack,
    digests: std.ArrayList(DigestVotes) = .empty,
    non_retriable: Agg,
    retriable: Agg,
    not_found: Votes,
    ack_result: ?union(enum) { ok: [32]u8, err: DriverError } = null,
    acked: std.ArrayList(u32) = .empty,
    acked_head: usize = 0,
    // full effects
    full: union(enum) {
        none,
        fallback: struct { initial: u32, pending: std.ArrayList(Inflight), next_tick: u64 },
        sequential: Inflight,
    } = .none,
    full_result: ?struct { validator: u32, result: FullResult } = null,

    fn ackBody(cert: *const Cert, d: *const Driver, member: u32) []const u8 {
        for (d.opts.detail_acks) |m| if (m == member) return cert.full_body;
        return cert.wait_body;
    }
};

const Role = enum { submit, ack, full };

const Due = struct { at: u64, which: Timer };
const SubmitOutcome = union(enum) { ok: wire.SubmitTxResult, err: RequestError };
const WaitOutcome = union(enum) { ok: wire.WaitForEffectsResponse, err: SuiErrorKind };

const Call = struct { validator: u32, role: Role, live: bool = true, member: u32 = 0 };

const Phase = union(enum) {
    start,
    submitting: *Submit,
    certifying: *Cert,
    backoff: u64,
    done,
};

const Timer = union(enum) {
    finality,
    drive,
    submit_call: usize,
    submit_backup,
    ack_deadline: u32,
    ack_wake: u32,
    fallback_tick,
    fallback_call: usize,
    sequential_call,
    backoff,
};

pub const Driver = struct {
    arena: Allocator,
    committee: *const Committee,
    transport: Transport,
    clock: Clock,
    request: Request,
    opts: Options,
    prng: std.Random.DefaultPrng,

    submit_body: []const u8 = "",
    amp: u64 = 1,
    start_ns: u64 = 0,
    /// `drive_transaction_once`'s start (finality latency for the monitor).
    attempt_start: u64 = 0,
    attempts: u32 = 0,
    latest_retriable: ?*const DriverError = null,
    backoff: Backoff,
    phase: Phase = .start,
    calls: std.ArrayList(Call) = .empty,
    inbox: std.ArrayList(struct { call: CallId, result: RpcResult }) = .empty,
    inbox_head: usize = 0,
    outcome: ?Outcome = null,
    /// The `TransactionDriverError` that ended the drive, if one did.
    driver_error: ?DriverError = null,

    pub fn init(arena: Allocator, committee: *const Committee, transport: Transport, clock: Clock, request: Request, opts: Options) Allocator.Error!Driver {
        var d: Driver = .{
            .arena = arena,
            .committee = committee,
            .transport = transport,
            .clock = clock,
            .request = request,
            .opts = opts,
            .prng = .init(opts.seed),
            .backoff = .init(opts.timing.drive_retry_initial, opts.timing.drive_retry_max),
        };
        d.submit_body = try wire.submitTxRequest(arena, request.transaction);
        return d;
    }

    /// Hands the driver the answer of `call`. Copies it; never calls the transport.
    pub fn onResponse(d: *Driver, call: CallId, result: RpcResult) Allocator.Error!void {
        const copy: RpcResult = switch (result) {
            .ok => |b| .{ .ok = try d.arena.dupe(u8, b) },
            .status => |s| .{ .status = .{ .code = s.code, .message = try d.arena.dupe(u8, s.message), .details = try d.arena.dupe(u8, s.details) } },
        };
        try d.inbox.append(d.arena, .{ .call = call, .result = copy });
    }

    /// Runs every answer and timer that is due.
    pub fn poll(d: *Driver) Allocator.Error!Poll {
        while (true) {
            if (d.outcome) |o| return .{ .done = o };
            const now = d.clock.now();
            if (d.phase == .start) {
                try d.begin(now);
                continue;
            }
            if (d.inbox_head < d.inbox.items.len) {
                const ev = d.inbox.items[d.inbox_head];
                d.inbox_head += 1;
                try d.handle(ev.call, ev.result, now);
                continue;
            }
            const t = d.earliest() orelse return .{ .pending = null };
            if (t.at > now) return .{ .pending = t.at };
            try d.fire(t.which, now);
        }
    }

    pub fn rng(d: *Driver) std.Random {
        return d.prng.random();
    }

    // ---------------------------------------------------------------------------------------
    // drive_transaction

    fn begin(d: *Driver, now: u64) !void {
        d.start_ns = now;
        if (d.request.transaction != null and !d.request.gasless) {
            const rgp = d.opts.reference_gas_price;
            d.amp = d.request.gas_price / @max(rgp, 1);
            if (d.amp == 0) {
                const u: se.UserInputError = .{ .GasPriceUnderRGP = .{ .gas_price = d.request.gas_price, .reference_gas_price = rgp } };
                return d.finishError(.{ .ValidationFailed = try se.allocPrint(d.arena, &u) });
            }
        }
        try d.startAttempt(now);
    }

    fn startAttempt(d: *Driver, now: u64) !void {
        d.attempt_start = now;
        const c = d.committee;
        const proposers: ?[]const u32 = if (d.request.allowed_proposers) |ap| (if (ap.epoch == c.epoch) ap.proposers else null) else null;
        const max_targets: u64 = if (proposers) |p| p.len else c.size();
        const s = try d.arena.create(Submit);
        s.* = .{
            .retrier = try .init(d, .{ .allowed = d.opts.allowed_validators, .blocked = d.opts.blocked_validators, .proposers = proposers, .only = d.opts.only_validator }),
            .amp = @min(@max(d.amp, if (d.request.transaction == null) 1 else d.opts.min_amplification, 1), max_targets),
        };
        d.phase = .{ .submitting = s };
        try d.submitIterate(s, now);
    }

    /// One attempt ended with `e`: stop, or back off and retry.
    fn attemptFailed(d: *Driver, e: DriverError, now: u64) !void {
        // deepwave: a submission that never certified counts against its target's finality
        if (d.phase == .certifying) d.feedback(d.phase.certifying.submitted_to, .finality, null);
        if (d.opts.feedback) |fb| if (fb.attempt_error) |f| f(fb.ctx, e.categorize(), d.request.transaction == null);
        d.cancelAll();
        if (!e.isSubmissionRetriable()) return d.finishError(e);
        const p = try d.arena.create(DriverError);
        p.* = e;
        d.latest_retriable = p;
        var delay = d.backoff.step(d.rng());
        if (e.categorize() == .ValidatorOverloaded) delay += d.opts.timing.overload_extra;
        d.phase = .{ .backoff = now + delay };
    }

    fn finishError(d: *Driver, e: DriverError) !void {
        d.cancelAll();
        d.driver_error = e;
        d.phase = .done;
        d.outcome = .{ .err = try e.toSubmissionError(d.arena) };
    }

    fn feedback(d: *Driver, validator: u32, op: Op, latency_ns: ?u64) void {
        const fb = d.opts.feedback orelse return;
        fb.f(fb.ctx, validator, op, latency_ns, d.request.transaction == null);
    }

    fn finishOk(d: *Driver, validator: u32, digest: [32]u8, data: wire.ExecutedData) void {
        if (d.phase == .certifying) {
            const cert = d.phase.certifying;
            const now = d.clock.now();
            // `drive_transaction_once`: finality through the submission target; the effects
            // source's latency (`get_full_effects`)
            d.feedback(cert.submitted_to, .finality, now -| d.attempt_start);
            d.feedback(validator, .effects, now -| cert.started);
        }
        d.cancelAll();
        d.phase = .done;
        d.outcome = .{ .ok = .{
            .effects_digest = digest,
            .effects = data.effects,
            .events = data.events,
            .input_objects = if (data.input_objects.len > 0) data.input_objects else null,
            .output_objects = if (data.output_objects.len > 0) data.output_objects else null,
            .source = validator,
        } };
    }

    fn cancelAll(d: *Driver) void {
        for (d.calls.items, 0..) |*c, i| if (c.live) {
            c.live = false;
            d.transport.vtable.cancel(d.transport.ctx, @intCast(i));
        };
    }

    fn startCall(d: *Driver, validator: u32, method: Method, body: []const u8, role: Role, member: u32) !CallId {
        const id: CallId = @intCast(d.calls.items.len);
        try d.calls.append(d.arena, .{ .validator = validator, .role = role, .member = member });
        d.transport.vtable.start(d.transport.ctx, id, validator, method, body);
        return id;
    }

    fn cancelCall(d: *Driver, id: CallId) void {
        const c = &d.calls.items[id];
        if (!c.live) return;
        c.live = false;
        d.transport.vtable.cancel(d.transport.ctx, id);
    }

    /// `ValidatorClientMonitor::select_shuffled_preferred_validators`.
    fn rank(d: *Driver) ![]u32 {
        const n = d.committee.size();
        const order = try d.arena.alloc(u32, n);
        for (order, 0..) |*o, i| o.* = @intCast(i);
        const r = d.rng();
        r.shuffleWithIndex(u32, order, u32);
        if (d.opts.latencies.len == 0) return order;
        const lat = struct {
            fn of(l: []const u64, i: u32) u64 {
                return if (i < l.len) l[i] else 0;
            }
        };
        const Ctx = struct { l: []const u64 };
        std.sort.insertion(u32, order, Ctx{ .l = d.opts.latencies }, struct {
            fn lt(ctx: Ctx, a: u32, b: u32) bool {
                return lat.of(ctx.l, a) < lat.of(ctx.l, b);
            }
        }.lt);
        const lowest = lat.of(d.opts.latencies, order[0]);
        const threshold: u64 = @intFromFloat(@as(f64, @floatFromInt(lowest)) * 1.02);
        var k: usize = order.len;
        for (order, 0..) |v, i| if (lat.of(d.opts.latencies, v) > threshold) {
            k = i;
            break;
        };
        r.shuffleWithIndex(u32, order[0..k], u32);
        return order;
    }

    // ---------------------------------------------------------------------------------------
    // TransactionSubmitter

    fn submitIterate(d: *Driver, s: *Submit, now: u64) !void {
        const n: u64 = if (s.initial) s.amp else 1;
        s.initial = false;
        var k: u64 = 0;
        while (k < n) : (k += 1) {
            const v = s.retrier.next() orelse {
                if (s.inflight.items.len > 0) break;
                return d.attemptFailed(try s.retrier.aborted(d), now);
            };
            const id = try d.startCall(v, .submit_transaction, d.submit_body, .submit, 0);
            try s.inflight.append(d.arena, .{ .call = id, .validator = v, .deadline = now + d.opts.timing.submit_timeout });
            if (d.phase != .submitting) return; // cannot happen: start only queues
        }
        s.backup_at = now + d.opts.timing.backup_delay;
    }

    fn submitDone(d: *Driver, s: *Submit, idx: usize, result: SubmitOutcome, now: u64) !void {
        const f = s.inflight.orderedRemove(idx);
        d.cancelCall(f.call);
        switch (result) {
            .ok => d.feedback(f.validator, .submit, now -| (f.deadline -| d.opts.timing.submit_timeout)),
            .err => |e| switch (e.categorize()) {
                .Aborted, .Internal, .ValidatorOverloaded, .Unavailable => d.feedback(f.validator, .submit, null),
                else => {},
            },
        }
        switch (result) {
            .ok => |r| {
                for (s.inflight.items) |o| d.cancelCall(o.call);
                s.inflight.clearRetainingCapacity();
                return d.startCertify(f.validator, r, now);
            },
            .err => |e| {
                if (try s.retrier.addError(d, f.validator, e)) |de| return d.attemptFailed(de, now);
                return d.submitIterate(s, now);
            },
        }
    }

    /// `submit_transaction_once` on an answer.
    fn submitAnswer(d: *Driver, r: RpcResult) !SubmitOutcome {
        switch (r) {
            .status => |st| return .{ .err = .{ .RejectedAtValidator = try se.fromStatus(d.arena, st.code, st.message, st.details) } },
            .ok => |body| switch (try wire.decodeSubmitTxResponse(d.arena, body)) {
                .err => |e| return .{ .err = .{ .RejectedAtValidator = e } },
                .ok => |res| switch (res) {
                    .Rejected => |e| return .{ .err = .{ .RejectedAtValidator = e } },
                    else => return .{ .ok = res },
                },
            },
        }
    }

    // ---------------------------------------------------------------------------------------
    // EffectsCertifier

    fn startCertify(d: *Driver, target: u32, result: wire.SubmitTxResult, now: u64) !void {
        const c = d.committee;
        const position: ?wire.ConsensusPosition = switch (result) {
            .Submitted => |s| s.position,
            else => null,
        };
        const t = d.opts.timing;
        const cert = try d.arena.create(Cert);
        cert.* = .{
            .target = target,
            .started = now,
            .submitted_to = target,
            .retrier = try .init(d, .{}),
            .wait_body = try wire.waitForEffectsRequest(d.arena, .{ .transaction_digest = d.request.digest, .consensus_position = position, .include_details = false, .ping = d.request.digest == null }),
            .full_body = try wire.waitForEffectsRequest(d.arena, .{ .transaction_digest = d.request.digest, .consensus_position = position, .include_details = true, .ping = d.request.digest == null }),
            .acks = try d.arena.alloc(Ack, c.size()),
            .non_retriable = try .init(d.arena, c),
            .retriable = try .init(d.arena, c),
            .not_found = try .init(d.arena, c),
        };
        d.phase = .{ .certifying = cert };
        // full effects: from the submission, or the first ranked validator with a fallback
        switch (result) {
            .Executed => |e| if (e.details) |det| {
                cert.full_result = .{ .validator = target, .result = .{ .ok = .{ .digest = e.effects_digest, .data = det } } };
            },
            else => {},
        }
        for (cert.acks, 0..) |*a, i| {
            a.* = .{ .deadline = now + t.wait_for_effects_timeout, .backoff = .init(t.wait_retry_initial, t.wait_retry_max) };
            a.call = try d.startCall(@intCast(i), .wait_for_effects, cert.ackBody(d, @intCast(i)), .ack, @intCast(i));
        }
        if (cert.full_result == null) {
            const first = cert.retrier.next() orelse unreachable; // a committee has members
            const id = try d.startCall(first, .wait_for_effects, cert.full_body, .full, 0);
            var pending: std.ArrayList(Inflight) = .empty;
            try pending.append(d.arena, .{ .call = id, .validator = first, .deadline = now + t.wait_for_effects_timeout });
            cert.full = .{ .fallback = .{ .initial = first, .pending = pending, .next_tick = now + t.full_effects_fallback } };
        }
        try d.certifyProgress(cert, now);
    }

    /// `wait_for_effects` through `SafeClient` (with `verify_executed_data`).
    fn waitAnswer(d: *Driver, validator: u32, r: RpcResult) !WaitOutcome {
        switch (r) {
            .status => |st| return .{ .err = try se.fromStatus(d.arena, st.code, st.message, st.details) },
            .ok => |body| switch (try wire.decodeWaitForEffectsResponse(d.arena, body)) {
                .err => |e| return .{ .err = e },
                .ok => |res| {
                    switch (res) {
                        .Executed => |e| if (e.details) |det| {
                            if (try verifyExecutedData(d.arena, &d.committee.members[validator].name, det)) |bad| return .{ .err = bad };
                        },
                        else => {},
                    }
                    return .{ .ok = res };
                },
            },
        }
    }

    /// `get_full_effects` on an answer.
    fn fullAnswer(d: *Driver, validator: u32, r: RpcResult) !FullResult {
        return switch (try d.waitAnswer(validator, r)) {
            .err => |e| .{ .err = .{ .Aborted = e } },
            .ok => |res| switch (res) {
                .Executed => |e| if (e.details) |det|
                    .{ .ok = .{ .digest = e.effects_digest, .data = det } }
                else
                    .{ .err = .{ .ValidatorInternal = "Execution data not found" } },
                .Rejected => |maybe| if (maybe) |e| .{ .err = .{ .RejectedAtValidator = e } } else .{ .err = .RejectedByConsensus },
                .Expired => |x| .{ .err = .{ .StatusExpired = .{ .epoch = x.epoch, .round = x.round orelse 0 } } },
            },
        };
    }

    /// One member's acknowledgment arrived (`Ok` response or final error).
    fn ackRecord(d: *Driver, cert: *Cert, i: u32, result: WaitOutcome) !void {
        cert.acks[i].state = .done;
        const c = d.committee;
        switch (result) {
            .ok => |res| switch (res) {
                .Executed => |e| {
                    try cert.acked.append(d.arena, i);
                    const votes = for (cert.digests.items) |*dv| {
                        if (std.mem.eql(u8, &dv.digest, &e.effects_digest)) break &dv.votes;
                    } else blk: {
                        try cert.digests.append(d.arena, .{ .digest = e.effects_digest, .votes = try .init(d.arena, c) });
                        break :blk &cert.digests.items[cert.digests.items.len - 1].votes;
                    };
                    _ = votes.insert(i, {});
                    if (votes.reachedQuorumThreshold()) {
                        cert.ack_result = .{ .ok = e.effects_digest };
                        return;
                    }
                },
                .Rejected => |maybe| if (maybe) |e| {
                    const re: RequestError = .{ .RejectedAtValidator = e };
                    if (re.isSubmissionRetriable()) _ = cert.retriable.insert(i, re) else _ = cert.non_retriable.insert(i, re);
                } else {
                    _ = cert.not_found.insert(i, {});
                },
                .Expired => |x| _ = cert.retriable.insert(i, .{ .StatusExpired = .{ .epoch = x.epoch, .round = x.round orelse 0 } }),
            },
            .err => |e| {
                const re: RequestError = .{ .Aborted = e };
                if (re.isSubmissionRetriable()) _ = cert.retriable.insert(i, re) else _ = cert.non_retriable.insert(i, re);
            },
        }
        var executed: u64 = 0;
        for (cert.digests.items) |dv| executed += dv.votes.total_votes;
        const total = executed + cert.not_found.total_votes + cert.non_retriable.total_votes + cert.retriable.total_votes;
        const remaining = cm.total_voting_power - total;
        if (total >= cm.quorum_threshold) {
            if (cert.non_retriable.total_votes >= cm.validity_threshold) {
                cert.ack_result = .{ .err = .{ .RejectedByValidators = .{
                    .non_retriable = try errors.aggregate(d.arena, c, cert.non_retriable.statuses),
                    .retriable = try errors.aggregate(d.arena, c, cert.retriable.statuses),
                } } };
                return;
            }
            if (cert.non_retriable.total_votes + remaining < cm.validity_threshold and
                cert.retriable.total_votes + cert.non_retriable.total_votes >= cm.validity_threshold)
            {
                cert.ack_result = .{ .err = .{ .Aborted = .{
                    .non_retriable = try errors.aggregate(d.arena, c, cert.non_retriable.statuses),
                    .retriable = try errors.aggregate(d.arena, c, cert.retriable.statuses),
                    .observed = try d.observed(cert),
                } } };
                return;
            }
        }
        for (cert.acks) |a| if (a.state != .done) return;
        // every member answered without a decision
        const retriable_weight = cert.retriable.total_votes + cert.not_found.total_votes;
        var submission_retriable = retriable_weight >= cm.quorum_threshold;
        for (cert.digests.items) |dv| if (dv.votes.total_votes + retriable_weight >= cm.quorum_threshold) {
            submission_retriable = true;
        };
        const nr = try errors.aggregate(d.arena, c, cert.non_retriable.statuses);
        const rr = try errors.aggregate(d.arena, c, cert.retriable.statuses);
        cert.ack_result = .{ .err = if (submission_retriable)
            .{ .Aborted = .{ .non_retriable = nr, .retriable = rr, .observed = try d.observed(cert) } }
        else
            .{ .ForkedExecution = .{ .observed = try d.observed(cert), .non_retriable = nr, .retriable = rr } } };
    }

    /// The per-digest votes as `AggregatedEffectsDigests` (digest order, names in name order).
    fn observed(d: *Driver, cert: *const Cert) !errors.AggregatedEffectsDigests {
        const out = try d.arena.alloc(errors.DigestGroup, cert.digests.items.len);
        for (cert.digests.items, out) |dv, *o| {
            var names: std.ArrayList(errors.Name) = .empty;
            for (dv.votes.statuses, 0..) |st, i| if (st != null) try names.append(d.arena, &d.committee.members[i].name);
            o.* = .{ .digest = dv.digest, .names = names.items, .stake = dv.votes.total_votes };
        }
        std.sort.insertion(errors.DigestGroup, out, {}, struct {
            fn lt(_: void, a: errors.DigestGroup, b: errors.DigestGroup) bool {
                return std.mem.order(u8, &a.digest, &b.digest) == .lt;
            }
        }.lt);
        return .{ .digests = out };
    }

    /// After any change: stop outstanding acks once decided, and resolve when both halves are in.
    fn certifyProgress(d: *Driver, cert: *Cert, now: u64) !void {
        if (cert.ack_result != null) for (cert.acks) |*a| if (a.state != .done) {
            if (a.state == .inflight) d.cancelCall(a.call);
            a.state = .done;
        };
        if (cert.full_result != null) switch (cert.full) {
            .fallback => |*fb| {
                for (fb.pending.items) |p| d.cancelCall(p.call);
                fb.pending.clearRetainingCapacity();
                cert.full = .none;
            },
            .sequential => |s| {
                d.cancelCall(s.call);
                cert.full = .none;
            },
            .none => {},
        };
        const ack = cert.ack_result orelse return;
        if (ack == .ok) for (cert.details.items) |x| if (std.mem.eql(u8, &x.digest, &ack.ok)) {
            // deepwave: certified effects that already came with an acknowledgment
            if (cert.full_result) |fr| if (fr.result == .ok and std.mem.eql(u8, &fr.result.ok.digest, &ack.ok)) break;
            return d.finishOk(x.validator, x.digest, x.data);
        };
        if (cert.full_result == null) return;
        const certified = switch (ack) {
            .err => |e| return d.attemptFailed(e, now),
            .ok => |digest| digest,
        };
        const fr = cert.full_result.?;
        switch (fr.result) {
            .ok => |o| if (std.mem.eql(u8, &o.digest, &certified)) return d.finishOk(fr.validator, o.digest, o.data),
            .err => |e| if (try cert.retrier.addError(d, fr.validator, e)) |de| return d.attemptFailed(de, now),
        }
        const next = cert.retrier.next() orelse return d.attemptFailed(try cert.retrier.exhausted(d), now);
        cert.target = next;
        cert.full_result = null;
        const id = try d.startCall(next, .wait_for_effects, cert.full_body, .full, 0);
        cert.full = .{ .sequential = .{ .call = id, .validator = next, .deadline = now + d.opts.timing.wait_for_effects_timeout } };
    }

    fn fallbackTick(d: *Driver, cert: *Cert, now: u64) !void {
        const fb = &cert.full.fallback;
        fb.next_tick += d.opts.timing.full_effects_fallback;
        while (cert.acked_head < cert.acked.items.len) {
            const v = cert.acked.items[cert.acked_head];
            cert.acked_head += 1;
            if (v == fb.initial) continue;
            const id = try d.startCall(v, .wait_for_effects, cert.full_body, .full, 0);
            try fb.pending.append(d.arena, .{ .call = id, .validator = v, .deadline = now + d.opts.timing.wait_for_effects_timeout });
            break;
        }
    }

    // ---------------------------------------------------------------------------------------
    // events

    fn handle(d: *Driver, id: CallId, r: RpcResult, now: u64) !void {
        if (id >= d.calls.items.len) return;
        const call = &d.calls.items[id];
        if (!call.live) return;
        call.live = false;
        switch (d.phase) {
            .submitting => |s| {
                if (call.role != .submit) return;
                for (s.inflight.items, 0..) |f, i| if (f.call == id) {
                    return d.submitDone(s, i, try d.submitAnswer(r), now);
                };
            },
            .certifying => |cert| switch (call.role) {
                .submit => {},
                .ack => {
                    const m = call.member;
                    const a = &cert.acks[m];
                    if (a.state != .inflight or a.call != id) return;
                    const res = try d.waitAnswer(m, r);
                    // `wait_for_acknowledgment_rpc`: every answer is an `Effects` interaction,
                    // a success with its latency (Executed, Rejected or Expired alike), any
                    // error a failure
                    switch (res) {
                        .ok => d.feedback(m, .effects, now -| cert.started),
                        .err => d.feedback(m, .effects, null),
                    }
                    switch (res) {
                        .err => |e| if (e == .RpcError) {
                            // RPC errors are retried after a backoff
                            a.state = .sleeping;
                            a.wake = now + a.backoff.step(d.rng());
                            return;
                        },
                        .ok => {},
                    }
                    switch (res) {
                        .ok => |w| switch (w) {
                            .Executed => |e| {
                                if (e.details) |det| try cert.details.append(d.arena, .{ .validator = m, .digest = e.effects_digest, .data = det });
                            },
                            else => {},
                        },
                        .err => {},
                    }
                    try d.ackRecord(cert, m, res);
                    try d.certifyProgress(cert, now);
                },
                .full => {
                    const v = call.validator;
                    switch (cert.full) {
                        .fallback => |*fb| for (fb.pending.items) |p| if (p.call == id) {
                            cert.full_result = .{ .validator = v, .result = try d.fullAnswer(v, r) };
                            break;
                        },
                        .sequential => |s| if (s.call == id) {
                            cert.full_result = .{ .validator = v, .result = try d.fullAnswer(v, r) };
                        },
                        .none => {},
                    }
                    try d.certifyProgress(cert, now);
                },
            },
            else => {},
        }
    }

    fn earliest(d: *Driver) ?Due {
        var best: ?Due = null;
        const S = struct {
            fn consider(b: *?Due, at: u64, which: Timer) void {
                if (b.* == null or at < b.*.?.at) b.* = .{ .at = at, .which = which };
            }
        };
        if (d.opts.finality_timeout) |t| S.consider(&best, d.start_ns +| t, .finality);
        if (d.opts.drive_timeout) |t| S.consider(&best, d.start_ns +| t, .drive);
        switch (d.phase) {
            .submitting => |s| {
                for (s.inflight.items, 0..) |f, i| S.consider(&best, f.deadline, .{ .submit_call = i });
                if (s.inflight.items.len > 0) S.consider(&best, s.backup_at, .submit_backup);
            },
            .certifying => |cert| {
                for (cert.acks, 0..) |a, i| switch (a.state) {
                    .inflight => S.consider(&best, a.deadline, .{ .ack_deadline = @intCast(i) }),
                    .sleeping => {
                        S.consider(&best, a.deadline, .{ .ack_deadline = @intCast(i) });
                        S.consider(&best, a.wake, .{ .ack_wake = @intCast(i) });
                    },
                    .done => {},
                };
                switch (cert.full) {
                    .fallback => |fb| {
                        for (fb.pending.items, 0..) |p, i| S.consider(&best, p.deadline, .{ .fallback_call = i });
                        S.consider(&best, fb.next_tick, .fallback_tick);
                    },
                    .sequential => |s| S.consider(&best, s.deadline, .sequential_call),
                    .none => {},
                }
            },
            .backoff => |at| S.consider(&best, at, .backoff),
            else => {},
        }
        return best;
    }

    fn fire(d: *Driver, which: Timer, now: u64) !void {
        switch (which) {
            .finality => {
                d.cancelAll();
                d.phase = .done;
                d.outcome = .{ .err = .TimeoutBeforeFinality };
            },
            .drive => return d.finishError(.{ .TimeoutWithLastRetriableError = .{
                .last_error = d.latest_retriable,
                .attempts = d.attempts,
                .timeout_ns = d.opts.drive_timeout.?,
            } }),
            .submit_call => |i| {
                const s = d.phase.submitting;
                return d.submitDone(s, i, .{ .err = .TimedOutSubmittingTransaction }, now);
            },
            .submit_backup => {
                const s = d.phase.submitting;
                return d.submitIterate(s, now);
            },
            .ack_deadline => |m| {
                const cert = d.phase.certifying;
                const a = &cert.acks[m];
                if (a.state == .inflight) d.cancelCall(a.call);
                d.feedback(m, .effects, null);
                try d.ackRecord(cert, m, .{ .err = .TimeoutError });
                return d.certifyProgress(cert, now);
            },
            .ack_wake => |m| {
                const cert = d.phase.certifying;
                const a = &cert.acks[m];
                a.state = .inflight;
                a.call = try d.startCall(m, .wait_for_effects, cert.ackBody(d, m), .ack, m);
            },
            .fallback_tick => return d.fallbackTick(d.phase.certifying, now),
            .fallback_call => |i| {
                const cert = d.phase.certifying;
                const p = cert.full.fallback.pending.items[i];
                cert.full_result = .{ .validator = p.validator, .result = .{ .err = .TimedOutGettingFullEffectsAtValidator } };
                return d.certifyProgress(cert, now);
            },
            .sequential_call => {
                const cert = d.phase.certifying;
                const s = cert.full.sequential;
                cert.full_result = .{ .validator = s.validator, .result = .{ .err = .TimedOutGettingFullEffectsAtValidator } };
                return d.certifyProgress(cert, now);
            },
            .backoff => {
                d.attempts += 1;
                return d.startAttempt(now);
            },
        }
    }
};

/// Blocks until something can be delivered: an answer (handed over with `d.onResponse`) or
/// `deadline` (monotonic ns, the clock's) passed. Errors end the drive.
pub const Waiter = struct {
    ctx: *anyopaque,
    waitFn: *const fn (ctx: *anyopaque, d: *Driver, deadline: ?u64) anyerror!void,
};

/// Drives `d` to its outcome, waiting through `waiter` between polls.
pub fn runBlocking(d: *Driver, waiter: Waiter) anyerror!Outcome {
    while (true) switch (try d.poll()) {
        .done => |o| return o,
        .pending => |deadline| try waiter.waitFn(waiter.ctx, d, deadline),
    };
}

/// The orchestrator's other select arm (`notify_read_executed_effects_may_fail`): effects this
/// node executed itself (checkpoint execution) while the drive is still pending answer at once,
/// as sui-node's `build_response_from_local_effects`. `get` is asked before every wait, at most
/// once per `every_ns` of the driver's clock; a drive that ends first answers as usual.
pub const LocalRace = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque) ?QuorumResponse,
    every_ns: u64,
};

pub const RaceResult = struct { outcome: Outcome, local: bool };

/// `runBlocking` racing the node's own execution of the transaction.
pub fn runRacing(d: *Driver, waiter: Waiter, race: LocalRace) anyerror!RaceResult {
    var next_check: u64 = 0;
    while (true) switch (try d.poll()) {
        .done => |o| return .{ .outcome = o, .local = false },
        .pending => |deadline| {
            const now = d.clock.now();
            if (now >= next_check) {
                if (race.get(race.ctx)) |q| return .{ .outcome = .{ .ok = q }, .local = true };
                next_check = now + race.every_ns;
            }
            try waiter.waitFn(waiter.ctx, d, if (deadline) |dl| @min(dl, next_check) else next_check);
        },
    };
}

/// `SafeClient::verify_executed_data`: events against the effects' events digest, input objects
/// against `old_object_metadata`, output objects against `all_changed_objects`. Returns the
/// `ByzantineAuthoritySuspicion` error, or null.
pub fn verifyExecutedData(arena: Allocator, authority: *const [96]u8, data: wire.ExecutedData) Allocator.Error!?SuiErrorKind {
    const eff = bcs.decode(types.TransactionEffects, arena, data.effects) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null, // the wire decoder already rejected malformed effects
    };
    const bad = struct {
        fn of(a: *const [96]u8, reason: []const u8) SuiErrorKind {
            return .{ .ByzantineAuthoritySuspicion = .{ .authority = .{ .@"0" = a.* }, .reason = .{ .@"0" = reason } } };
        }
    };
    const events_digest: ?[32]u8 = switch (eff) {
        .V1 => |v| if (v.events_digest) |x| x.@"0".@"0" else null,
        .V2 => |v| if (v.events_digest) |x| x.@"0".@"0" else null,
    };
    if (data.events) |ev| {
        if (events_digest) |want| {
            const got = types.digest.eventsDigest(ev);
            if (!std.mem.eql(u8, &got, &want)) return bad.of(authority, "Returned events don't match events digest in effects");
        } else if (ev.len > 0 and ev[0] != 0) {
            return bad.of(authority, "Returned events but no event digest present in effects");
        }
    }
    const Ref = struct { id: [32]u8, version: u64, digest: [32]u8 };
    var inputs: std.ArrayList(Ref) = .empty;
    var outputs: std.ArrayList(Ref) = .empty;
    switch (eff) {
        .V2 => |v| {
            const lamport = v.lamport_version.@"0";
            for (v.changed_objects) |e| {
                const id = e.@"0".@"0".@"0";
                const ch = e.@"1";
                switch (ch.input_state) {
                    .Exist => |x| try inputs.append(arena, .{ .id = id, .version = x.@"0".@"0".@"0", .digest = x.@"0".@"1".@"0".@"0" }),
                    .NotExist => {},
                }
                const out: ?Ref = switch (ch.output_state) {
                    .ObjectWrite => |w| switch (ch.input_state) {
                        .Exist => .{ .id = id, .version = lamport, .digest = w.@"0".@"0".@"0" },
                        .NotExist => if (ch.id_operation == .Created or ch.id_operation == .None) .{ .id = id, .version = lamport, .digest = w.@"0".@"0".@"0" } else null,
                    },
                    .PackageWrite => |p| switch (ch.input_state) {
                        .Exist => .{ .id = id, .version = p.@"0".@"0", .digest = p.@"1".@"0".@"0" },
                        .NotExist => if (ch.id_operation == .Created) .{ .id = id, .version = p.@"0".@"0", .digest = p.@"1".@"0".@"0" } else null,
                    },
                    else => null,
                };
                if (out) |o| try outputs.append(arena, o);
            }
        },
        .V1 => |v| {
            // `old_object_metadata` is unimplemented for V1 effects; only outputs are checked
            for ([_]@TypeOf(v.created){ v.mutated, v.created, v.unwrapped }) |list| for (list) |e| {
                try outputs.append(arena, .{ .id = e.@"0".@"0".@"0".@"0", .version = e.@"0".@"1".@"0", .digest = e.@"0".@"2".@"0".@"0" });
            };
        },
    }
    const checks = [_]struct { objs: []const []const u8, refs: []const Ref, skip: bool }{
        .{ .objs = data.input_objects, .refs = inputs.items, .skip = eff == .V1 },
        .{ .objs = data.output_objects, .refs = outputs.items, .skip = false },
    };
    for (checks) |ck| {
        if (ck.skip) continue;
        for (ck.objs) |raw| {
            const k = serve.objset.headKey(raw) catch return bad.of(authority, "Returned object that wasn't present in effects");
            const id = k[0..32];
            const version = std.mem.readInt(u64, k[32..40], .little);
            // a HashMap collected from the refs: the last ref of an id wins
            var want: ?Ref = null;
            for (ck.refs) |r| if (std.mem.eql(u8, &r.id, id)) {
                want = r;
            };
            const w = want orelse return bad.of(authority, "Returned object that wasn't present in effects");
            const digest = types.digest.objectDigest(raw);
            if (w.version != version or !std.mem.eql(u8, &w.digest, &digest)) return bad.of(authority, "Returned object that wasn't present in effects");
        }
    }
    return null;
}

test "backoff grows by 1.2 and caps" {
    var prng: std.Random.DefaultPrng = .init(1);
    var b: Backoff = .{ .next = 100 * ns_per_ms, .max = 150 * ns_per_ms, .max_jitter = 0 };
    try std.testing.expectEqual(@as(u64, 100 * ns_per_ms), b.step(prng.random()));
    try std.testing.expectEqual(@as(u64, 120 * ns_per_ms), b.step(prng.random()));
    try std.testing.expectEqual(@as(u64, 144 * ns_per_ms), b.step(prng.random()));
    try std.testing.expectEqual(@as(u64, 150 * ns_per_ms), b.step(prng.random()));
}
