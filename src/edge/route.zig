//! Edge request routing (docs/EDGE.md section 11): for one sui.rpc.v2 request, whether an edge
//! answers from its own store, waits a moment for its follower and then decides, or passes the
//! request to its core. Pure: the caller parses the request into `Facts`, reads the edge's
//! `State`, and acts on the `Decision`. No I/O, no clock, no allocation, so every rule is a table
//! row in the tests below and a second front end (opaque sui.rpc.v2 calls over zui/1) can use the
//! same rules.
//!
//! The one invariant: an answer the edge gives itself is the answer its core would give. Passing
//! a request on is always exact, so every doubt goes to `forward`.
//!
//! Three steps, each a pure function:
//!   `decide`      before anything is read: policy, lag guard, floor, tip, read mask needs;
//!   `afterWait`   for a request that named something ahead of the edge, once the wait is over;
//!   `afterLocal`  after the local handler ran: an answer that is not a plain success, or one
//!                 that met a gap in the edge's store, is dropped and the request is passed on.
const std = @import("std");

/// The sui.rpc.v2 methods an edge tells apart. `own`: paths that are the edge's own business and
/// are never passed on (grpc.health, reflection, GET /health, and any path outside the table,
/// which the local router answers 404 or UNIMPLEMENTED exactly as the core's would).
pub const Method = enum(u8) {
    get_service_info,
    get_object,
    batch_get_objects,
    get_transaction,
    batch_get_transactions,
    get_checkpoint,
    get_epoch,
    list_checkpoints,
    list_transactions,
    list_events,
    list_dynamic_fields,
    list_owned_objects,
    get_coin_info,
    get_balance,
    list_balances,
    get_package,
    get_datatype,
    get_function,
    list_package_versions,
    lookup_name,
    reverse_lookup_name,
    subscribe_checkpoints,
    subscribe_transactions,
    subscribe_events,
    execute_transaction,
    simulate_transaction,
    verify_signature,
    get_checkpoint_object_proof,
    own,

    pub const count = @typeInfo(Method).@"enum".field_names.len;

    /// Server-streaming methods: their forwarded form runs on a stream pump.
    pub fn streams(m: Method) bool {
        return switch (m) {
            .list_checkpoints, .list_transactions, .list_events, .subscribe_checkpoints, .subscribe_transactions, .subscribe_events => true,
            else => false,
        };
    }
};

const Entry = struct { path: []const u8, method: Method };
/// Path of every method in the table (the metric label of each is its path).
pub const paths = [_]Entry{
    .{ .path = "/sui.rpc.v2.LedgerService/GetServiceInfo", .method = .get_service_info },
    .{ .path = "/sui.rpc.v2.LedgerService/GetObject", .method = .get_object },
    .{ .path = "/sui.rpc.v2.LedgerService/BatchGetObjects", .method = .batch_get_objects },
    .{ .path = "/sui.rpc.v2.LedgerService/GetTransaction", .method = .get_transaction },
    .{ .path = "/sui.rpc.v2.LedgerService/BatchGetTransactions", .method = .batch_get_transactions },
    .{ .path = "/sui.rpc.v2.LedgerService/GetCheckpoint", .method = .get_checkpoint },
    .{ .path = "/sui.rpc.v2.LedgerService/GetEpoch", .method = .get_epoch },
    .{ .path = "/sui.rpc.v2.LedgerService/ListCheckpoints", .method = .list_checkpoints },
    .{ .path = "/sui.rpc.v2.LedgerService/ListTransactions", .method = .list_transactions },
    .{ .path = "/sui.rpc.v2.LedgerService/ListEvents", .method = .list_events },
    .{ .path = "/sui.rpc.v2.StateService/ListDynamicFields", .method = .list_dynamic_fields },
    .{ .path = "/sui.rpc.v2.StateService/ListOwnedObjects", .method = .list_owned_objects },
    .{ .path = "/sui.rpc.v2.StateService/GetCoinInfo", .method = .get_coin_info },
    .{ .path = "/sui.rpc.v2.StateService/GetBalance", .method = .get_balance },
    .{ .path = "/sui.rpc.v2.StateService/ListBalances", .method = .list_balances },
    .{ .path = "/sui.rpc.v2.MovePackageService/GetPackage", .method = .get_package },
    .{ .path = "/sui.rpc.v2.MovePackageService/GetDatatype", .method = .get_datatype },
    .{ .path = "/sui.rpc.v2.MovePackageService/GetFunction", .method = .get_function },
    .{ .path = "/sui.rpc.v2.MovePackageService/ListPackageVersions", .method = .list_package_versions },
    .{ .path = "/sui.rpc.v2.NameService/LookupName", .method = .lookup_name },
    .{ .path = "/sui.rpc.v2.NameService/ReverseLookupName", .method = .reverse_lookup_name },
    .{ .path = "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", .method = .subscribe_checkpoints },
    .{ .path = "/sui.rpc.v2.SubscriptionService/SubscribeTransactions", .method = .subscribe_transactions },
    .{ .path = "/sui.rpc.v2.SubscriptionService/SubscribeEvents", .method = .subscribe_events },
    .{ .path = "/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction", .method = .execute_transaction },
    .{ .path = "/sui.rpc.v2.TransactionExecutionService/SimulateTransaction", .method = .simulate_transaction },
    .{ .path = "/sui.rpc.v2.SignatureVerificationService/VerifySignature", .method = .verify_signature },
    .{ .path = "/sui.rpc.v2alpha.ProofService/GetCheckpointObjectProof", .method = .get_checkpoint_object_proof },
};

const sui_prefix = "/sui.rpc.v2";

pub fn methodOf(path: []const u8) Method {
    if (!std.mem.startsWith(u8, path, sui_prefix)) return .own;
    for (paths) |e| if (std.mem.eql(u8, e.path, path)) return e.method;
    return .own;
}

/// The metric label of a method (its path; `own` has none).
pub fn label(m: Method) []const u8 {
    for (paths) |e| if (e.method == m) return e.path;
    return "own";
}

/// Why a request was passed to the core. A small fixed set: it is a metric label.
pub const Reason = enum(u8) {
    /// The method is always passed on (a policy constant below).
    policy,
    /// Names history below what the edge keeps.
    below_floor,
    /// Names a checkpoint or an object version the edge has not applied, after the wait.
    ahead,
    /// The local attempt came up empty (NOT_FOUND, OUT_OF_RANGE, pruned): the core answers.
    negative,
    /// The answer needs input objects, loaded-object lists or a signature order, and the edge
    /// does not have them for it: a store built from a feed without read sets has none, one
    /// with read sets lacks them for the checkpoints that came without.
    needs_read_sets,
    /// The edge is too far behind its core, or cannot tell.
    lag_guard,
    /// A List* the edge cannot page exactly.
    list_paging,
    other,
    /// The answer carries the quorum certificate of a checkpoint the edge did not take from a
    /// core and has not yet replaced with the core's (certs.zig, docs/EDGE.md section 13).
    foreign_cert,
    /// A List* while the edge's ledger-history index does not hold every checkpoint the edge
    /// keeps (a backfill under way, or one that gave up): the index would answer from its own
    /// low end, the core has the rows.
    unindexed,

    pub const count = @typeInfo(Reason).@"enum".field_names.len;
};

// ---------------------------------------------------------------- policy constants
//
// Methods the edge could answer one day and passes on today. Each is one constant so the change
// is one line and one table row. `simulate` and `balance_lists` are defaults only: an edge may
// be started with another value (`State.simulate`, `State.balance_lists`).

pub const Where = enum { local, forward };

/// SuiNS lookups. `local` once an edge's name answers are proven equal to the core's.
pub const name_service: Where = .forward;

pub const Simulate = enum {
    /// Always to the core.
    forward,
    /// On the edge, when the request leaves nothing to this node's own choice (`Facts.gas_selection`
    /// is passed on). A local run that does not end in an answer is passed on too (`afterLocal`:
    /// an object the edge does not hold or holds at another version, a shape this node does not
    /// run, no epoch state), so every refusal a client sees is the core's.
    local_forward_on_miss,
    /// The same, and gas selection too: the coins come from the edge's own owner index and the
    /// budget from its own run, by the node's one algorithm. What the edge cannot add is the
    /// proposer restriction a node with a transaction driver puts on the resolved transaction
    /// (docs/EDGE.md 11.8): the transaction it returns has none.
    local_gas,

    /// `--edge-simulate forward | local | local-gas`.
    pub fn parse(text: []const u8) ?Simulate {
        if (std.mem.eql(u8, text, "forward")) return .forward;
        if (std.mem.eql(u8, text, "local")) return .local_forward_on_miss;
        if (std.mem.eql(u8, text, "local-gas")) return .local_gas;
        return null;
    }
};
/// The default of `State.simulate` (`--edge-simulate`).
pub const simulate: Simulate = .forward;

/// ListCheckpoints, ListTransactions, ListEvents: pages render transactions with their effects
/// and cross the edge's floor; an edge has no exact way to page them yet.
pub const ledger_lists: Where = .forward;
/// ListPackageVersions and GetPackage's `version` / `at_checkpoint` selectors read the
/// package-version index, whose rows before a restored snapshot are floors, not history.
pub const package_versions: Where = .forward;
/// SubscribeTransactions and SubscribeEvents render transactions with effects and object sets.
pub const tx_event_streams: Where = .forward;
/// sui.rpc.v2alpha ProofService.
pub const proofs: Where = .forward;
/// ListBalances: which coin types emptied to zero are still listed depends on each node's own
/// index history (docs/EDGE.md 11.2); GetBalance answers them alike and stays here.
/// The default of `State.balance_lists` (`--edge-balance-lists`).
pub const balance_lists: Where = .forward;

/// `forward | local`, as the edge's policy flags spell it.
pub fn parseWhere(text: []const u8) ?Where {
    if (std.mem.eql(u8, text, "forward")) return .forward;
    if (std.mem.eql(u8, text, "local")) return .local;
    return null;
}

// ---------------------------------------------------------------- input

/// Who asked. Carried through the decision for the access gate and the meter (`gate`, and
/// forward.zig's one metering point).
pub const Caller = struct {
    /// The request's `x-api-key` metadata ("" when absent).
    api_key: []const u8 = "",
    /// The peer's address as text ("" when the transport does not know it).
    peer: []const u8 = "",
    /// The access gate's verdict on this call, reached before routing by the front end that
    /// holds the gate's state (docs/GATE.md; forward.zig `GateHook`). Null: admitted, or no gate.
    deny: ?Deny = null,
    /// What the gate handed out for an admitted call; the meter gives it back. Opaque here.
    ticket: ?*anyopaque = null,
};

/// What a request's read mask needs beyond what a feed-built store holds.
pub const Needs = packed struct {
    /// Input objects or the loaded-object list of a transaction (its object set).
    object_set: bool = false,
    /// The submitted order of a transaction's signatures.
    signatures: bool = false,
    /// A checkpoint's quorum certificate (`Checkpoint.signature`). Every edge holds one for
    /// every checkpoint; it is the core's unless the checkpoint is marked (`Facts.foreign`).
    cert: bool = false,

    /// Needs something a feed-built store never has.
    pub fn any(n: Needs) bool {
        return n.object_set or n.signatures;
    }
};

/// The parsed request. Fields a method does not use stay at their defaults.
pub const Facts = struct {
    method: Method,
    caller: Caller = .{},
    /// The request bytes did not scan: the local handler answers the decode error, which is a
    /// function of the request alone.
    malformed: bool = false,
    /// A named checkpoint sequence number (GetCheckpoint, GetPackage `at_checkpoint`).
    seq: ?u64 = null,
    /// Names a transaction or checkpoint by digest. An unknown digest is neither old nor new,
    /// so nothing is decided from it here: a local miss passes the request on at once.
    by_digest: bool = false,
    /// GetObject: the version asked for, and the edge's latest version of that object (null:
    /// the edge holds no live object of that id).
    version: ?u64 = null,
    live_version: ?u64 = null,
    needs: Needs = .{},
    /// GetPackage with a `version` or `at_checkpoint` selector.
    selector: bool = false,
    /// GetEpoch: the epoch asked for (null: the current one) and the edge's current epoch.
    epoch: ?u64 = null,
    current_epoch: ?u64 = null,
    /// GetEpoch: the edge holds this epoch's whole record (its start, and its end unless it is
    /// the current epoch). An edge restored from a snapshot has none for earlier epochs.
    epoch_complete: bool = false,
    /// GetServiceInfo: the edge knows its core's lowest available checkpoint, which is the one
    /// it reports (with forwarding on, that is what a client can ask this edge for).
    info_ready: bool = true,
    /// SimulateTransaction under `local_forward_on_miss`: the local run read an object the edge
    /// does not hold.
    input_miss: bool = false,
    /// SimulateTransaction with `do_gas_selection` and checks on: the node picks gas coins from
    /// its own owner index, estimates the budget and may restrict the transaction to the
    /// proposers its own validator monitor prefers. It stays the core's under
    /// `local_forward_on_miss`; `local_gas` answers it here.
    gas_selection: bool = false,
    /// The checkpoint the request names (by number, by digest, or the latest when it names
    /// none) holds a certificate that is not a core's. For SubscribeCheckpoints: the edge is in
    /// such a period at its tip, so the stream's next checkpoints would be marked.
    foreign: bool = false,
};

pub const GuardState = enum(u8) { ok, tripped };

/// The edge as the request finds it.
pub const State = struct {
    /// False: no upstream is configured; every request is answered locally, as an edge without
    /// forwarding does.
    forwarding: bool = true,
    guard: GuardState = .ok,
    /// Highest checkpoint the edge serves (null: none yet).
    tip: ?u64 = null,
    /// Lowest checkpoint the edge keeps.
    floor: u64 = 0,
    /// The edge's ledger-history index begins above `floor` (or is empty): checkpoints the
    /// edge keeps have no index rows. Only read for the List* methods.
    history_gap: bool = false,
    /// The edge keeps read sets (docs/EDGE.md section 12): a read that needs a transaction's
    /// object set is tried locally, and stands only when the checkpoint it belongs to has its
    /// whole read set here (`Gap.read_set_missing` otherwise). False: such reads are passed on
    /// before anything is read, as on an edge built from a feed without read sets.
    read_sets: bool = false,
    /// `--edge-balance-lists`: where ListBalances is answered. `local`: from the edge's own
    /// index, which can differ from the core's only in rows of coin types emptied to zero.
    balance_lists: Where = balance_lists,
    /// `--edge-simulate`, as it stands for this request (forward.zig `simulateNow`).
    simulate: Simulate = simulate,
};

// ---------------------------------------------------------------- output

pub const Deny = struct {
    /// gRPC status: 8 RESOURCE_EXHAUSTED, 7 PERMISSION_DENIED or 16 UNAUTHENTICATED.
    code: u8,
    message: []const u8,
};

pub const Wait = union(enum) {
    /// Until the edge's tip reaches this checkpoint.
    checkpoint: u64,
    /// Until the edge's latest version of the object reaches this version.
    version: u64,
};

pub const Decision = union(enum) {
    /// Answer from the edge's store, then ask `afterLocal`.
    local,
    /// The request names something ahead of the edge: wait (bounded) for the follower, then
    /// ask `afterWait`.
    wait: Wait,
    forward: Reason,
    /// Refused before routing (the access gate).
    deny: Deny,
};

/// The access gate: API keys, rate limits, per-key quotas. Runs before any routing. The gate
/// itself keeps state (buckets, leases), so its verdict is a fact of the request like any other:
/// the front end asks the gate and puts the answer in `Caller.deny`, and the policy refuses the
/// call here, before it looks at anything else. Both the gRPC and the zui/1 front end get it.
pub fn gate(c: *const Caller, _: Method) ?Deny {
    return c.deny;
}

pub fn decide(f: *const Facts, s: *const State) Decision {
    if (f.method == .own) return .local;
    if (gate(&f.caller, f.method)) |d| return .{ .deny = d };
    if (!s.forwarding) return .local;
    if (s.guard == .tripped) return .{ .forward = .lag_guard };
    switch (f.method) {
        .own => unreachable,
        .execute_transaction => return .{ .forward = .policy },
        .simulate_transaction => return switch (s.simulate) {
            .forward => .{ .forward = .policy },
            .local_forward_on_miss => if (f.malformed) .local else if (f.gas_selection) .{ .forward = .policy } else if (f.input_miss) .{ .forward = .needs_read_sets } else .local,
            .local_gas => if (f.malformed) .local else if (f.input_miss) .{ .forward = .needs_read_sets } else .local,
        },
        .lookup_name, .reverse_lookup_name => return whereOf(name_service, .policy),
        // (ListCheckpoints with `signature` in its mask over a marked checkpoint is covered by
        // this constant; a local ListCheckpoints must ask the marks for its page first.)
        .list_checkpoints, .list_transactions, .list_events => return if (s.history_gap) .{ .forward = .unindexed } else whereOf(ledger_lists, .list_paging),
        .list_package_versions => return whereOf(package_versions, .list_paging),
        .subscribe_transactions, .subscribe_events => return whereOf(tx_event_streams, .needs_read_sets),
        .get_checkpoint_object_proof => return whereOf(proofs, .policy),
        .list_balances => return whereOf(s.balance_lists, .policy),
        else => {},
    }
    // A request that does not scan gets the local handler's decode error.
    if (f.malformed) return .local;
    switch (f.method) {
        .get_service_info => return if (f.info_ready) .local else .{ .forward = .other },
        .list_dynamic_fields, .list_owned_objects, .get_coin_info, .get_balance, .list_balances, .get_datatype, .get_function, .verify_signature, .batch_get_objects => return .local,
        .get_object => {
            const v = f.version orelse return .local;
            // No live object of that id here: deleted, wrapped, never seen, or created in a
            // checkpoint the edge has not applied. The edge cannot tell which.
            const live = f.live_version orelse return .{ .forward = .negative };
            if (v > live) return .{ .wait = .{ .version = v } };
            return .local;
        },
        .get_transaction, .batch_get_transactions => {
            // With read sets the checkpoint decides, and only the local attempt knows which
            // checkpoint a digest belongs to: it ends with a gap where the read set is missing.
            if (f.needs.object_set and !s.read_sets) return .{ .forward = .needs_read_sets };
            return .local;
        },
        .get_checkpoint => {
            if (f.needs.object_set and !s.read_sets) return .{ .forward = .needs_read_sets };
            // The certificate of a marked checkpoint is not the core's. (Known before any
            // read for a number, a digest the edge holds and the latest; a checkpoint that
            // becomes the latest between this and the read is caught by the handler, `Gap`.)
            if (f.needs.cert and f.foreign) return .{ .forward = .foreign_cert };
            if (f.by_digest) return .local;
            const seq = f.seq orelse return if (s.tip == null) .{ .forward = .other } else .local;
            if (seq < s.floor) return .{ .forward = .below_floor };
            if (s.tip == null or seq > s.tip.?) return .{ .wait = .{ .checkpoint = seq } };
            return .local;
        },
        .subscribe_checkpoints => {
            // A stream cannot be handed over once it has started: its mask must be exact for
            // every checkpoint to come.
            if (f.needs.any()) return .{ .forward = .needs_read_sets };
            // In a foreign period the next checkpoints would carry marked certificates. A
            // stream that is local when one begins is ended there (subscribe.zig), and its
            // client comes back to this rule.
            if (f.needs.cert and f.foreign) return .{ .forward = .foreign_cert };
            return .local;
        },
        .get_epoch => {
            const cur = f.current_epoch orelse return .{ .forward = .other };
            const e = f.epoch orelse cur;
            if (e > cur) return .{ .forward = .ahead };
            if (!f.epoch_complete) return .{ .forward = if (e < cur) .below_floor else .other };
            return .local;
        },
        .get_package => {
            if (f.selector) return whereOf(package_versions, .other);
            return .local;
        },
        else => unreachable,
    }
}

fn whereOf(w: Where, why: Reason) Decision {
    return switch (w) {
        .local => .local,
        .forward => .{ .forward = why },
    };
}

/// After the wait of a `wait` decision: `caught_up` says whether the edge now holds what the
/// request named.
pub fn afterWait(f: *const Facts, s: *const State, caught_up: bool) Decision {
    _ = f;
    if (s.guard == .tripped) return .{ .forward = .lag_guard };
    return if (caught_up) .local else .{ .forward = .ahead };
}

/// A gap the local handler met in the edge's store (serve/service.zig `LocalGap`).
pub const Gap = enum(u8) {
    none,
    /// A batch item the edge does not hold.
    item_missing,
    /// A transaction with two or more signatures under a mask that renders them.
    sig_order,
    /// An object of a transaction's object set the edge does not hold.
    object_missing,
    /// The certificate of a marked checkpoint, under a mask that renders it.
    foreign_cert,
    /// The checkpoint's read set is not here (it was applied without one, or its lists did not
    /// pass the edge's checks), under a mask that needs a transaction's object set.
    read_set_missing,
};

/// How the local attempt ended.
pub const Outcome = struct {
    /// gRPC status code of the local answer.
    code: u8,
    /// The answer carries `grpc-status-details-bin` (an RpcError; a tonic decode error has none).
    has_details: bool = false,
    gap: Gap = .none,
};

/// Null: the local answer stands. Otherwise the request is passed on for this reason and the
/// local answer is dropped. Answers that are a function of the request alone stand (success
/// without a gap, INVALID_ARGUMENT, a decode error, UNIMPLEMENTED for an unknown method); so do
/// the ones where passing on cannot help (the deadline passed, the client left).
pub fn afterLocal(f: *const Facts, s: *const State, o: Outcome) ?Reason {
    if (f.method == .own or !s.forwarding) return null;
    // A local simulation that did not end in an answer is the core's to answer: INVALID_ARGUMENT
    // there is mostly about the state (an input the edge does not hold, or holds at another
    // version), not the request alone. A request that did not scan keeps its decode error.
    if (f.method == .simulate_transaction and !f.malformed) return switch (o.code) {
        0, 1, 4 => null,
        else => .negative,
    };
    switch (o.gap) {
        .none => {},
        .item_missing => return .negative,
        .sig_order, .object_missing, .read_set_missing => return .needs_read_sets,
        .foreign_cert => return .foreign_cert,
    }
    return switch (o.code) {
        0 => null,
        1, 3, 4 => null, // CANCELLED, INVALID_ARGUMENT, DEADLINE_EXCEEDED
        5 => if (f.method == .get_object and f.version != null and f.live_version != null and f.version.? < f.live_version.?) .below_floor else .negative,
        11 => .negative, // OUT_OF_RANGE
        12, 13 => if (o.has_details) .other else null, // tonic's own UNIMPLEMENTED / decode INTERNAL have no details
        else => .other,
    };
}

// ---------------------------------------------------------------- read masks

pub const MaskOf = enum { transaction, checkpoint };

/// What the read mask `mask_paths` (the request's FieldMask paths; null: the request has none,
/// so the method's default applies, which needs nothing) asks of a store. A path selects its
/// whole subtree, as sui-rpc's FieldMaskTree does; a path this does not know costs a forward,
/// never a wrong local answer.
pub fn maskNeeds(kind: MaskOf, mask_paths: ?[]const []const u8) Needs {
    var n: Needs = .{};
    const ps = mask_paths orelse return n;
    for (ps) |raw| {
        var p = raw;
        if (std.mem.eql(u8, p, "*")) {
            n.object_set = true;
            n.signatures = true;
            if (kind == .checkpoint) n.cert = true;
            continue;
        }
        if (kind == .checkpoint) {
            // Checkpoint.signature is the quorum certificate (render_checkpoint.zig: the one
            // field rendered from it; `summary` is the CheckpointSummary alone)
            if (under(p, "signature")) n.cert = true;
            // Checkpoint.objects is the checkpoint's object set
            if (under(p, "objects")) n.object_set = true;
            if (std.mem.eql(u8, p, "transactions")) {
                n.object_set = true;
                n.signatures = true;
                continue;
            }
            if (!std.mem.startsWith(u8, p, "transactions.")) continue;
            p = p["transactions.".len..];
        }
        if (std.mem.eql(u8, p, "*")) {
            n.object_set = true;
            n.signatures = true;
            continue;
        }
        // object_set.rs `mask_requests_object_set`
        if (under(p, "effects") or under(p, "balance_changes") or under(p, "objects")) n.object_set = true;
        if (under(p, "signatures")) n.signatures = true;
    }
    return n;
}

fn under(path: []const u8, field: []const u8) bool {
    if (!std.mem.startsWith(u8, path, field)) return false;
    return path.len == field.len or path[field.len] == '.';
}

// ---------------------------------------------------------------- lag guard

/// The freshness guard (docs/EDGE.md 11.5): tripped while the edge is more than `max_lag`
/// checkpoints behind the newest checkpoint it knows of, cannot tell how far behind it is, or has
/// heard nothing from any source for `stale_ns`. Recovery needs the lag at or under
/// `recoverLag()` for `hold_ns` without a break, so an edge hovering at the boundary does not
/// flap. A new guard is tripped: an edge proves it is fresh before it serves.
pub const Guard = struct {
    max_lag: u64 = 5,
    hold_ns: u64 = 500 * std.time.ns_per_ms,
    stale_ns: u64 = 3 * std.time.ns_per_s,
    state: GuardState = .tripped,
    /// Since when (ns) every observation has been good enough to recover (0: not yet).
    good_since: u64 = 0,

    pub const Obs = struct {
        /// Checkpoints between the newest one known to exist and the edge's tip (null: the
        /// edge does not know where the tip of its source is, as in catch-up).
        lag: ?u64,
        /// Time since a source last answered (a checkpoint, or "not there yet").
        source_age_ns: u64,
    };

    pub const Change = enum { none, tripped, recovered };

    pub fn recoverLag(g: *const Guard) u64 {
        return g.max_lag / 2;
    }

    pub fn update(g: *Guard, now_ns: u64, o: Obs) Change {
        const heard = o.source_age_ns <= g.stale_ns;
        const lag = o.lag orelse std.math.maxInt(u64);
        switch (g.state) {
            .ok => {
                if (heard and lag <= g.max_lag) return .none;
                g.state = .tripped;
                g.good_since = 0;
                return .tripped;
            },
            .tripped => {
                if (!heard or lag > g.recoverLag()) {
                    g.good_since = 0;
                    return .none;
                }
                if (g.good_since == 0) g.good_since = @max(now_ns, 1);
                if (now_ns -| g.good_since < g.hold_ns) return .none;
                g.state = .ok;
                return .recovered;
            },
        }
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn expectDecision(want: Decision, got: Decision) !void {
    try testing.expectEqual(std.meta.activeTag(want), std.meta.activeTag(got));
    switch (want) {
        .local => {},
        .forward => |r| try testing.expectEqual(r, got.forward),
        .wait => |w| switch (w) {
            .checkpoint => |c| try testing.expectEqual(c, got.wait.checkpoint),
            .version => |v| try testing.expectEqual(v, got.wait.version),
        },
        .deny => |d| try testing.expectEqual(d.code, got.deny.code),
    }
}

test "methodOf: every path, and everything else is the edge's own" {
    for (paths) |e| try testing.expectEqual(e.method, methodOf(e.path));
    // every method but `own` has exactly one path
    var seen: [Method.count]u8 = @splat(0);
    for (paths) |e| seen[@intFromEnum(e.method)] += 1;
    for (seen, 0..) |n, i| try testing.expectEqual(@as(u8, if (i == @intFromEnum(Method.own)) 0 else 1), n);
    try testing.expectEqual(Method.own, methodOf("/grpc.health.v1.Health/Check"));
    try testing.expectEqual(Method.own, methodOf("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"));
    try testing.expectEqual(Method.own, methodOf("/sui.rpc.v2.LedgerService/Nope"));
    try testing.expectEqual(Method.own, methodOf("/health"));
    try testing.expectEqual(Method.own, methodOf(""));
    try testing.expectEqualStrings("/sui.rpc.v2.LedgerService/GetObject", label(.get_object));
    try testing.expect(Method.subscribe_checkpoints.streams() and Method.list_events.streams() and !Method.get_object.streams());
}

test "decide: the routing table" {
    const at: State = .{ .tip = 1000, .floor = 900 };
    const with_rs: State = .{ .tip = 1000, .floor = 900, .read_sets = true };
    const sim_local: State = .{ .tip = 1000, .floor = 900, .read_sets = true, .simulate = .local_forward_on_miss };
    const sim_gas: State = .{ .tip = 1000, .floor = 900, .read_sets = true, .simulate = .local_gas };
    const Row = struct { f: Facts, s: State = at, want: Decision };
    const rows = [_]Row{
        // always passed on
        .{ .f = .{ .method = .execute_transaction }, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .execute_transaction, .malformed = true }, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .simulate_transaction }, .want = .{ .forward = .policy } },
        // `--edge-simulate`: forward (the default, spelled out) and local
        .{ .f = .{ .method = .simulate_transaction }, .s = .{ .tip = 1000, .floor = 900, .simulate = .forward }, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .simulate_transaction, .gas_selection = true }, .s = .{ .tip = 1000, .floor = 900, .simulate = .forward }, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .simulate_transaction }, .s = sim_local, .want = .local },
        // gas selection is each node's own choice: the core's
        .{ .f = .{ .method = .simulate_transaction, .gas_selection = true }, .s = sim_local, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .simulate_transaction, .input_miss = true }, .s = sim_local, .want = .{ .forward = .needs_read_sets } },
        // a request that does not scan gets the local decode error, gas selection or not
        .{ .f = .{ .method = .simulate_transaction, .malformed = true }, .s = sim_local, .want = .local },
        // `local-gas`: gas selection is the edge's too
        .{ .f = .{ .method = .simulate_transaction }, .s = sim_gas, .want = .local },
        .{ .f = .{ .method = .simulate_transaction, .gas_selection = true }, .s = sim_gas, .want = .local },
        .{ .f = .{ .method = .simulate_transaction, .gas_selection = true, .malformed = true }, .s = sim_gas, .want = .local },
        .{ .f = .{ .method = .simulate_transaction, .gas_selection = true, .input_miss = true }, .s = sim_gas, .want = .{ .forward = .needs_read_sets } },
        .{ .f = .{ .method = .execute_transaction }, .s = sim_gas, .want = .{ .forward = .policy } },
        // the setting moves nothing else
        .{ .f = .{ .method = .execute_transaction }, .s = sim_local, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .list_balances }, .s = sim_local, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .lookup_name }, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .reverse_lookup_name }, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .get_checkpoint_object_proof }, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .list_checkpoints }, .want = .{ .forward = .list_paging } },
        .{ .f = .{ .method = .list_transactions }, .want = .{ .forward = .list_paging } },
        .{ .f = .{ .method = .list_events }, .want = .{ .forward = .list_paging } },
        .{ .f = .{ .method = .list_package_versions }, .want = .{ .forward = .list_paging } },
        // a ledger-history index with a gap never answers a list, whatever `ledger_lists` says
        .{ .f = .{ .method = .list_checkpoints }, .s = .{ .tip = 1000, .floor = 900, .history_gap = true }, .want = .{ .forward = .unindexed } },
        .{ .f = .{ .method = .list_transactions }, .s = .{ .tip = 1000, .floor = 900, .history_gap = true }, .want = .{ .forward = .unindexed } },
        .{ .f = .{ .method = .list_events }, .s = .{ .tip = 1000, .floor = 900, .history_gap = true }, .want = .{ .forward = .unindexed } },
        // the gap is the lists' business only
        .{ .f = .{ .method = .list_package_versions }, .s = .{ .tip = 1000, .floor = 900, .history_gap = true }, .want = .{ .forward = .list_paging } },
        .{ .f = .{ .method = .get_checkpoint, .seq = 950 }, .s = .{ .tip = 1000, .floor = 900, .history_gap = true }, .want = .local },
        .{ .f = .{ .method = .subscribe_transactions }, .want = .{ .forward = .needs_read_sets } },
        .{ .f = .{ .method = .subscribe_events }, .want = .{ .forward = .needs_read_sets } },
        // answered here
        .{ .f = .{ .method = .get_service_info }, .want = .local },
        .{ .f = .{ .method = .get_service_info, .info_ready = false }, .want = .{ .forward = .other } },
        .{ .f = .{ .method = .get_object }, .want = .local },
        .{ .f = .{ .method = .batch_get_objects }, .want = .local },
        .{ .f = .{ .method = .list_owned_objects }, .want = .local },
        .{ .f = .{ .method = .list_dynamic_fields }, .want = .local },
        .{ .f = .{ .method = .get_balance }, .want = .local },
        .{ .f = .{ .method = .list_balances }, .want = .{ .forward = .policy } },
        // `--edge-balance-lists`: forward (the default, spelled out) and local
        .{ .f = .{ .method = .list_balances }, .s = .{ .tip = 1000, .floor = 900, .balance_lists = .forward }, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .list_balances }, .s = .{ .tip = 1000, .floor = 900, .balance_lists = .local }, .want = .local },
        .{ .f = .{ .method = .list_balances, .malformed = true }, .s = .{ .tip = 1000, .floor = 900, .balance_lists = .local }, .want = .local },
        .{ .f = .{ .method = .get_balance }, .s = .{ .tip = 1000, .floor = 900, .balance_lists = .local }, .want = .local },
        .{ .f = .{ .method = .simulate_transaction }, .s = .{ .tip = 1000, .floor = 900, .balance_lists = .local }, .want = .{ .forward = .policy } },
        .{ .f = .{ .method = .get_coin_info }, .want = .local },
        .{ .f = .{ .method = .get_datatype }, .want = .local },
        .{ .f = .{ .method = .get_function }, .want = .local },
        .{ .f = .{ .method = .verify_signature }, .want = .local },
        .{ .f = .{ .method = .get_package }, .want = .local },
        .{ .f = .{ .method = .get_package, .selector = true }, .want = .{ .forward = .other } },
        .{ .f = .{ .method = .own }, .want = .local },
        // a request that does not scan: the local decode error
        .{ .f = .{ .method = .get_checkpoint, .malformed = true }, .want = .local },
        .{ .f = .{ .method = .get_object, .malformed = true }, .want = .local },
        // object at a version: at or under the edge's latest is local, above it waits, an id
        // the edge has no live object for is passed on
        .{ .f = .{ .method = .get_object, .version = 7, .live_version = 7 }, .want = .local },
        .{ .f = .{ .method = .get_object, .version = 3, .live_version = 7 }, .want = .local },
        .{ .f = .{ .method = .get_object, .version = 8, .live_version = 7 }, .want = .{ .wait = .{ .version = 8 } } },
        .{ .f = .{ .method = .get_object, .version = 8 }, .want = .{ .forward = .negative } },
        // transactions: the object set is never here
        .{ .f = .{ .method = .get_transaction, .by_digest = true }, .want = .local },
        .{ .f = .{ .method = .get_transaction, .by_digest = true, .needs = .{ .signatures = true } }, .want = .local },
        .{ .f = .{ .method = .get_transaction, .by_digest = true, .needs = .{ .object_set = true } }, .want = .{ .forward = .needs_read_sets } },
        .{ .f = .{ .method = .batch_get_transactions }, .want = .local },
        .{ .f = .{ .method = .batch_get_transactions, .needs = .{ .object_set = true } }, .want = .{ .forward = .needs_read_sets } },
        // ... unless the edge keeps read sets: then the local attempt decides per checkpoint
        .{ .f = .{ .method = .get_transaction, .by_digest = true, .needs = .{ .object_set = true } }, .s = with_rs, .want = .local },
        .{ .f = .{ .method = .batch_get_transactions, .needs = .{ .object_set = true } }, .s = with_rs, .want = .local },
        .{ .f = .{ .method = .get_transaction, .by_digest = true, .needs = .{ .object_set = true, .signatures = true } }, .s = with_rs, .want = .local },
        .{ .f = .{ .method = .get_checkpoint, .seq = 950, .needs = .{ .object_set = true } }, .s = with_rs, .want = .local },
        .{ .f = .{ .method = .get_checkpoint, .needs = .{ .object_set = true } }, .s = with_rs, .want = .local },
        .{ .f = .{ .method = .get_checkpoint, .by_digest = true, .needs = .{ .object_set = true } }, .s = with_rs, .want = .local },
        // the window still applies to them
        .{ .f = .{ .method = .get_checkpoint, .seq = 899, .needs = .{ .object_set = true } }, .s = with_rs, .want = .{ .forward = .below_floor } },
        .{ .f = .{ .method = .get_checkpoint, .seq = 1001, .needs = .{ .object_set = true } }, .s = with_rs, .want = .{ .wait = .{ .checkpoint = 1001 } } },
        // a checkpoint stream is still exact for its whole life or not local at all: a later
        // checkpoint may arrive without its read set
        .{ .f = .{ .method = .subscribe_checkpoints, .needs = .{ .object_set = true } }, .s = with_rs, .want = .{ .forward = .needs_read_sets } },
        .{ .f = .{ .method = .subscribe_transactions }, .s = with_rs, .want = .{ .forward = .needs_read_sets } },
        // checkpoints: window, floor, tip
        .{ .f = .{ .method = .get_checkpoint }, .want = .local },
        .{ .f = .{ .method = .get_checkpoint, .seq = 1000 }, .want = .local },
        .{ .f = .{ .method = .get_checkpoint, .seq = 900 }, .want = .local },
        .{ .f = .{ .method = .get_checkpoint, .seq = 899 }, .want = .{ .forward = .below_floor } },
        .{ .f = .{ .method = .get_checkpoint, .seq = 0 }, .want = .{ .forward = .below_floor } },
        .{ .f = .{ .method = .get_checkpoint, .seq = 1001 }, .want = .{ .wait = .{ .checkpoint = 1001 } } },
        .{ .f = .{ .method = .get_checkpoint, .seq = std.math.maxInt(u64) }, .want = .{ .wait = .{ .checkpoint = std.math.maxInt(u64) } } },
        .{ .f = .{ .method = .get_checkpoint, .by_digest = true }, .want = .local },
        .{ .f = .{ .method = .get_checkpoint, .seq = 950, .needs = .{ .object_set = true } }, .want = .{ .forward = .needs_read_sets } },
        .{ .f = .{ .method = .get_checkpoint, .seq = 950, .needs = .{ .signatures = true } }, .want = .local },
        .{ .f = .{ .method = .get_checkpoint }, .s = .{ .tip = null }, .want = .{ .forward = .other } },
        .{ .f = .{ .method = .get_checkpoint, .seq = 5 }, .s = .{ .tip = null }, .want = .{ .wait = .{ .checkpoint = 5 } } },
        // the certificate of a checkpoint that did not come from a core: to the core, and only
        // when the mask renders it
        .{ .f = .{ .method = .get_checkpoint, .seq = 950, .needs = .{ .cert = true } }, .want = .local },
        .{ .f = .{ .method = .get_checkpoint, .seq = 950, .needs = .{ .cert = true }, .foreign = true }, .want = .{ .forward = .foreign_cert } },
        .{ .f = .{ .method = .get_checkpoint, .seq = 950, .foreign = true }, .want = .local },
        .{ .f = .{ .method = .get_checkpoint, .seq = 950, .needs = .{ .signatures = true }, .foreign = true }, .want = .local },
        .{ .f = .{ .method = .get_checkpoint, .by_digest = true, .needs = .{ .cert = true }, .foreign = true }, .want = .{ .forward = .foreign_cert } },
        .{ .f = .{ .method = .get_checkpoint, .by_digest = true, .needs = .{ .cert = true } }, .want = .local },
        .{ .f = .{ .method = .get_checkpoint, .needs = .{ .cert = true }, .foreign = true }, .want = .{ .forward = .foreign_cert } },
        .{ .f = .{ .method = .get_checkpoint, .needs = .{ .cert = true } }, .want = .local },
        // the object set wins (it is never here), below the floor and ahead of the tip too
        .{ .f = .{ .method = .get_checkpoint, .seq = 950, .needs = .{ .cert = true, .object_set = true }, .foreign = true }, .want = .{ .forward = .needs_read_sets } },
        .{ .f = .{ .method = .get_checkpoint, .seq = 899, .needs = .{ .cert = true } }, .want = .{ .forward = .below_floor } },
        .{ .f = .{ .method = .get_checkpoint, .seq = 1001, .needs = .{ .cert = true } }, .want = .{ .wait = .{ .checkpoint = 1001 } } },
        // a malformed request is the local decode error whatever is marked
        .{ .f = .{ .method = .get_checkpoint, .malformed = true, .needs = .{ .cert = true }, .foreign = true }, .want = .local },
        // ListCheckpoints: to the core whatever its mask and whatever is marked
        .{ .f = .{ .method = .list_checkpoints, .needs = .{ .cert = true }, .foreign = true }, .want = .{ .forward = .list_paging } },
        // other methods never render a checkpoint's certificate
        .{ .f = .{ .method = .get_transaction, .by_digest = true, .foreign = true }, .want = .local },
        .{ .f = .{ .method = .get_object, .foreign = true }, .want = .local },
        // a checkpoint stream is exact for its whole life or not local at all
        .{ .f = .{ .method = .subscribe_checkpoints }, .want = .local },
        .{ .f = .{ .method = .subscribe_checkpoints, .needs = .{ .object_set = true } }, .want = .{ .forward = .needs_read_sets } },
        .{ .f = .{ .method = .subscribe_checkpoints, .needs = .{ .signatures = true } }, .want = .{ .forward = .needs_read_sets } },
        // a stream that renders certificates starts locally only outside a foreign period
        .{ .f = .{ .method = .subscribe_checkpoints, .needs = .{ .cert = true } }, .want = .local },
        .{ .f = .{ .method = .subscribe_checkpoints, .needs = .{ .cert = true }, .foreign = true }, .want = .{ .forward = .foreign_cert } },
        .{ .f = .{ .method = .subscribe_checkpoints, .foreign = true }, .want = .local },
        // epochs
        .{ .f = .{ .method = .get_epoch, .current_epoch = 12, .epoch_complete = true }, .want = .local },
        .{ .f = .{ .method = .get_epoch, .epoch = 12, .current_epoch = 12, .epoch_complete = true }, .want = .local },
        .{ .f = .{ .method = .get_epoch, .epoch = 11, .current_epoch = 12, .epoch_complete = true }, .want = .local },
        .{ .f = .{ .method = .get_epoch, .epoch = 3, .current_epoch = 12 }, .want = .{ .forward = .below_floor } },
        .{ .f = .{ .method = .get_epoch, .epoch = 13, .current_epoch = 12 }, .want = .{ .forward = .ahead } },
        .{ .f = .{ .method = .get_epoch, .current_epoch = 12 }, .want = .{ .forward = .other } },
        .{ .f = .{ .method = .get_epoch }, .want = .{ .forward = .other } },
    };
    for (rows, 0..) |r, i| expectDecision(r.want, decide(&r.f, &r.s)) catch |e| {
        std.debug.print("row {d}: {s}\n", .{ i, @tagName(r.f.method) });
        return e;
    };
}

test "decide: the guard passes everything on, an edge without an upstream nothing" {
    const tripped: State = .{ .guard = .tripped, .tip = 1000, .floor = 900 };
    const off: State = .{ .forwarding = false, .guard = .tripped, .tip = 1000, .floor = 900 };
    inline for (comptime std.meta.fieldNames(Method)) |name| {
        const m = @field(Method, name);
        const f: Facts = .{ .method = m, .seq = 5, .needs = .{ .object_set = true, .cert = true }, .foreign = true };
        if (m == .own) {
            try expectDecision(.local, decide(&f, &tripped));
        } else {
            try expectDecision(.{ .forward = .lag_guard }, decide(&f, &tripped));
        }
        try expectDecision(.local, decide(&f, &off));
        // read sets change neither: a tripped guard still passes everything on
        const tripped_rs: State = .{ .guard = .tripped, .tip = 1000, .floor = 900, .read_sets = true };
        if (m != .own) try expectDecision(.{ .forward = .lag_guard }, decide(&f, &tripped_rs));
        // nor do the policy settings
        const tripped_pol: State = .{ .guard = .tripped, .tip = 1000, .floor = 900, .read_sets = true, .balance_lists = .local, .simulate = .local_gas };
        if (m != .own) try expectDecision(.{ .forward = .lag_guard }, decide(&f, &tripped_pol));
        // and its local answer stands whatever it is
        try testing.expectEqual(@as(?Reason, null), afterLocal(&f, &off, .{ .code = 5, .has_details = true }));
        try testing.expectEqual(@as(?Reason, null), afterLocal(&f, &off, .{ .code = 13, .gap = .foreign_cert }));
    }
}

test "afterWait: local once caught up, else ahead; the guard wins" {
    const f: Facts = .{ .method = .get_checkpoint, .seq = 1001 };
    const s: State = .{ .tip = 1001, .floor = 900 };
    try expectDecision(.local, afterWait(&f, &s, true));
    try expectDecision(.{ .forward = .ahead }, afterWait(&f, &s, false));
    const t: State = .{ .guard = .tripped, .tip = 1001 };
    try expectDecision(.{ .forward = .lag_guard }, afterWait(&f, &t, true));
}

test "afterLocal: only request-determined answers stand" {
    const s: State = .{ .tip = 1000, .floor = 900 };
    const Row = struct { f: Facts = .{ .method = .get_object }, o: Outcome, want: ?Reason };
    const rows = [_]Row{
        .{ .o = .{ .code = 0 }, .want = null },
        .{ .o = .{ .code = 3, .has_details = true }, .want = null }, // INVALID_ARGUMENT
        .{ .o = .{ .code = 13 }, .want = null }, // tonic decode error
        .{ .o = .{ .code = 12 }, .want = null }, // unknown method
        .{ .o = .{ .code = 4 }, .want = null }, // the deadline passed
        .{ .o = .{ .code = 1 }, .want = null }, // the client left
        .{ .o = .{ .code = 5, .has_details = true }, .want = .negative },
        .{ .o = .{ .code = 5 }, .want = .negative },
        .{ .o = .{ .code = 11, .has_details = true }, .want = .negative },
        .{ .o = .{ .code = 13, .has_details = true }, .want = .other }, // an RpcError internal
        .{ .o = .{ .code = 12, .has_details = true }, .want = .other },
        .{ .o = .{ .code = 14, .has_details = true }, .want = .other }, // index not ready
        .{ .o = .{ .code = 8 }, .want = .other },
        .{ .o = .{ .code = 2 }, .want = .other },
        // gaps, whatever the status
        .{ .o = .{ .code = 0, .gap = .item_missing }, .want = .negative },
        .{ .o = .{ .code = 13, .gap = .item_missing }, .want = .negative },
        .{ .o = .{ .code = 13, .gap = .sig_order }, .want = .needs_read_sets },
        .{ .o = .{ .code = 13, .gap = .object_missing }, .want = .needs_read_sets },
        .{ .o = .{ .code = 13, .gap = .foreign_cert }, .want = .foreign_cert },
        .{ .o = .{ .code = 0, .gap = .foreign_cert }, .want = .foreign_cert },
        .{ .o = .{ .code = 13, .gap = .read_set_missing }, .want = .needs_read_sets },
        .{ .o = .{ .code = 0, .gap = .read_set_missing }, .want = .needs_read_sets },
        // an old version of an object the edge holds newer: below its floor
        .{ .f = .{ .method = .get_object, .version = 3, .live_version = 7 }, .o = .{ .code = 5, .has_details = true }, .want = .below_floor },
        .{ .f = .{ .method = .get_object, .version = 7, .live_version = 7 }, .o = .{ .code = 5, .has_details = true }, .want = .negative },
        .{ .f = .{ .method = .get_transaction, .by_digest = true }, .o = .{ .code = 5, .has_details = true }, .want = .negative },
    };
    for (rows, 0..) |r, i| testing.expectEqual(r.want, afterLocal(&r.f, &s, r.o)) catch |e| {
        std.debug.print("row {d}\n", .{i});
        return e;
    };
    // the edge's own paths are never passed on
    try testing.expectEqual(@as(?Reason, null), afterLocal(&.{ .method = .own }, &s, .{ .code = 5 }));
    // a local simulation (`--edge-simulate local`) stands only as an answer: every refusal is the
    // core's, INVALID_ARGUMENT included (an input the edge lacks or holds at another version)
    const sim: Facts = .{ .method = .simulate_transaction };
    const sl: State = .{ .tip = 1000, .floor = 900, .read_sets = true, .simulate = .local_forward_on_miss };
    try testing.expectEqual(@as(?Reason, null), afterLocal(&sim, &sl, .{ .code = 0 }));
    try testing.expectEqual(@as(?Reason, null), afterLocal(&sim, &sl, .{ .code = 1 }));
    try testing.expectEqual(@as(?Reason, null), afterLocal(&sim, &sl, .{ .code = 4 }));
    inline for (.{ 2, 3, 5, 8, 12, 13, 14 }) |code| {
        try testing.expectEqual(@as(?Reason, .negative), afterLocal(&sim, &sl, .{ .code = code }));
        try testing.expectEqual(@as(?Reason, .negative), afterLocal(&sim, &sl, .{ .code = code, .has_details = true }));
    }
    // the same under `local-gas`, for a gas selection too
    const sg: State = .{ .tip = 1000, .floor = 900, .read_sets = true, .simulate = .local_gas };
    const gas: Facts = .{ .method = .simulate_transaction, .gas_selection = true };
    try testing.expectEqual(@as(?Reason, null), afterLocal(&gas, &sg, .{ .code = 0 }));
    inline for (.{ 3, 5, 13, 14 }) |code| try testing.expectEqual(@as(?Reason, .negative), afterLocal(&gas, &sg, .{ .code = code, .has_details = true }));
    // its decode error is the request's own
    try testing.expectEqual(@as(?Reason, null), afterLocal(&.{ .method = .simulate_transaction, .malformed = true }, &sl, .{ .code = 13 }));
    // the flag spellings
    try testing.expectEqual(@as(?Simulate, .forward), Simulate.parse("forward"));
    try testing.expectEqual(@as(?Simulate, .local_forward_on_miss), Simulate.parse("local"));
    try testing.expectEqual(@as(?Simulate, .local_gas), Simulate.parse("local-gas"));
    try testing.expectEqual(@as(?Simulate, null), Simulate.parse("on"));
    try testing.expectEqual(@as(?Where, .forward), parseWhere("forward"));
    try testing.expectEqual(@as(?Where, .local), parseWhere("local"));
    try testing.expectEqual(@as(?Where, null), parseWhere(""));
}

test "maskNeeds: object sets and signature order" {
    const T = struct {
        fn n(kind: MaskOf, comptime ps: []const []const u8) Needs {
            return maskNeeds(kind, ps);
        }
    };
    const none: Needs = .{};
    const objs: Needs = .{ .object_set = true };
    const sigs: Needs = .{ .signatures = true };
    const both: Needs = .{ .object_set = true, .signatures = true };
    const cert: Needs = .{ .cert = true };
    const all: Needs = .{ .object_set = true, .signatures = true, .cert = true };
    try testing.expectEqual(none, maskNeeds(.transaction, null));
    try testing.expectEqual(none, T.n(.transaction, &.{}));
    try testing.expectEqual(none, T.n(.transaction, &.{ "digest", "transaction", "events", "checkpoint", "timestamp" }));
    try testing.expectEqual(objs, T.n(.transaction, &.{"effects"}));
    try testing.expectEqual(objs, T.n(.transaction, &.{"effects.status"}));
    try testing.expectEqual(objs, T.n(.transaction, &.{"effects.unchanged_loaded_runtime_objects"}));
    try testing.expectEqual(objs, T.n(.transaction, &.{"balance_changes"}));
    try testing.expectEqual(objs, T.n(.transaction, &.{"objects.objects.bcs"}));
    try testing.expectEqual(sigs, T.n(.transaction, &.{ "digest", "signatures" }));
    try testing.expectEqual(sigs, T.n(.transaction, &.{"signatures.bcs"}));
    try testing.expectEqual(both, T.n(.transaction, &.{ "signatures", "effects" }));
    try testing.expectEqual(both, T.n(.transaction, &.{"*"}));
    // a field that only starts like one is not it
    try testing.expectEqual(none, T.n(.transaction, &.{ "effects_digest", "objectsx", "signatures_count" }));
    // checkpoints
    try testing.expectEqual(none, maskNeeds(.checkpoint, null));
    try testing.expectEqual(none, T.n(.checkpoint, &.{ "sequence_number", "digest", "summary", "summary.bcs", "contents" }));
    try testing.expectEqual(none, T.n(.checkpoint, &.{ "transactions.digest", "transactions.transaction.bcs", "transactions.events" }));
    try testing.expectEqual(objs, T.n(.checkpoint, &.{"objects"}));
    try testing.expectEqual(objs, T.n(.checkpoint, &.{"objects.objects.object_id"}));
    try testing.expectEqual(objs, T.n(.checkpoint, &.{"transactions.effects.gas_used"}));
    try testing.expectEqual(objs, T.n(.checkpoint, &.{"transactions.balance_changes"}));
    try testing.expectEqual(objs, T.n(.checkpoint, &.{"transactions.objects"}));
    try testing.expectEqual(sigs, T.n(.checkpoint, &.{"transactions.signatures.scheme"}));
    try testing.expectEqual(both, T.n(.checkpoint, &.{"transactions"}));
    try testing.expectEqual(both, T.n(.checkpoint, &.{"transactions.*"}));
    try testing.expectEqual(all, T.n(.checkpoint, &.{"*"}));
    // the checkpoint's own `signature` is its quorum certificate, not a transaction's
    // signatures: its own need, and the only path that renders it besides `*`
    try testing.expectEqual(cert, T.n(.checkpoint, &.{"signature"}));
    try testing.expectEqual(cert, T.n(.checkpoint, &.{ "sequence_number", "signature.signature" }));
    try testing.expectEqual(cert, T.n(.checkpoint, &.{"signature.bitmap"}));
    try testing.expectEqual(none, T.n(.checkpoint, &.{ "signatures", "signature_scheme" }));
    try testing.expectEqual(Needs{ .cert = true, .signatures = true }, T.n(.checkpoint, &.{ "signature", "transactions.signatures" }));
    // a path after one that selects everything else still counts
    try testing.expectEqual(all, T.n(.checkpoint, &.{ "transactions", "signature" }));
    try testing.expectEqual(all, T.n(.checkpoint, &.{ "signature", "transactions.*" }));
    // a transaction has no certificate: `*` on one asks for none
    try testing.expectEqual(both, T.n(.transaction, &.{"*"}));
    try testing.expectEqual(sigs, T.n(.transaction, &.{"signatures"}));
    try testing.expectEqual(none, T.n(.transaction, &.{"signature"}));
    // `any` is about what a feed-built store lacks; the certificate is not that
    try testing.expect(!cert.any() and both.any());
}

test "guard: trips over the limit, recovers under half of it after the hold" {
    const ms = std.time.ns_per_ms;
    var g: Guard = .{};
    try testing.expectEqual(GuardState.tripped, g.state); // starts tripped
    // good, but not for long enough
    try testing.expectEqual(Guard.Change.none, g.update(1000 * ms, .{ .lag = 0, .source_age_ns = 0 }));
    try testing.expectEqual(Guard.Change.none, g.update(1400 * ms, .{ .lag = 1, .source_age_ns = 0 }));
    try testing.expectEqual(Guard.Change.recovered, g.update(1500 * ms, .{ .lag = 2, .source_age_ns = 0 }));
    try testing.expectEqual(GuardState.ok, g.state);
    // up to the limit it holds
    try testing.expectEqual(Guard.Change.none, g.update(1600 * ms, .{ .lag = 5, .source_age_ns = 0 }));
    try testing.expectEqual(Guard.Change.tripped, g.update(1700 * ms, .{ .lag = 6, .source_age_ns = 0 }));
    // back at the boundary: not recovered (3..5 neither trips nor recovers)
    for (0..50) |i| try testing.expectEqual(Guard.Change.none, g.update((1800 + 100 * i) * ms, .{ .lag = 5, .source_age_ns = 0 }));
    for (0..50) |i| try testing.expectEqual(Guard.Change.none, g.update((6800 + 100 * i) * ms, .{ .lag = 3, .source_age_ns = 0 }));
    // under half, with one bad sample restarting the hold
    try testing.expectEqual(Guard.Change.none, g.update(12_000 * ms, .{ .lag = 2, .source_age_ns = 0 }));
    try testing.expectEqual(Guard.Change.none, g.update(12_400 * ms, .{ .lag = 3, .source_age_ns = 0 }));
    try testing.expectEqual(Guard.Change.none, g.update(12_600 * ms, .{ .lag = 2, .source_age_ns = 0 }));
    try testing.expectEqual(Guard.Change.none, g.update(13_000 * ms, .{ .lag = 0, .source_age_ns = 0 }));
    try testing.expectEqual(Guard.Change.recovered, g.update(13_100 * ms, .{ .lag = 0, .source_age_ns = 0 }));
    // flapping input at the limit never flaps the state
    var changes: u32 = 0;
    for (0..1000) |i| {
        if (g.update((14_000 + 10 * i) * ms, .{ .lag = if (i % 2 == 0) 5 else 6, .source_age_ns = 0 }) != .none) changes += 1;
    }
    try testing.expectEqual(@as(u32, 1), changes);
    try testing.expectEqual(GuardState.tripped, g.state);
}

test "guard: an unknown tip or a silent source trips it" {
    const ms = std.time.ns_per_ms;
    var g: Guard = .{ .state = .ok };
    try testing.expectEqual(Guard.Change.none, g.update(1 * ms, .{ .lag = 0, .source_age_ns = 3000 * ms }));
    try testing.expectEqual(Guard.Change.tripped, g.update(2 * ms, .{ .lag = 0, .source_age_ns = 3001 * ms }));
    // silent sources never recover it, however small the lag looks
    for (0..20) |i| try testing.expectEqual(Guard.Change.none, g.update((100 + 100 * i) * ms, .{ .lag = 0, .source_age_ns = 4000 * ms }));
    try testing.expectEqual(Guard.Change.none, g.update(3000 * ms, .{ .lag = 0, .source_age_ns = 10 * ms }));
    try testing.expectEqual(Guard.Change.recovered, g.update(3500 * ms, .{ .lag = 0, .source_age_ns = 10 * ms }));
    try testing.expectEqual(Guard.Change.tripped, g.update(3600 * ms, .{ .lag = null, .source_age_ns = 0 }));
    try testing.expectEqual(Guard.Change.none, g.update(9000 * ms, .{ .lag = null, .source_age_ns = 0 }));
    // max_lag 0: any lag trips, recovery at 0
    var z: Guard = .{ .max_lag = 0, .state = .ok };
    try testing.expectEqual(Guard.Change.tripped, z.update(1 * ms, .{ .lag = 1, .source_age_ns = 0 }));
    try testing.expectEqual(Guard.Change.none, z.update(2 * ms, .{ .lag = 0, .source_age_ns = 0 }));
    try testing.expectEqual(Guard.Change.recovered, z.update(600 * ms, .{ .lag = 0, .source_age_ns = 0 }));
}

test "gate: a call the gate refused is denied before any routing, whatever the edge's state" {
    const refused: Caller = .{ .api_key = "k", .peer = "198.51.100.7:1", .deny = .{ .code = 8, .message = "rate limit exceeded" } };
    const states = [_]State{
        .{},
        .{ .forwarding = false },
        .{ .guard = .tripped },
        .{ .tip = 100, .floor = 50 },
    };
    for (states) |st| {
        for ([_]Method{ .get_object, .execute_transaction, .subscribe_checkpoints, .list_events, .get_service_info }) |m| {
            const d = decide(&.{ .method = m, .caller = refused, .seq = 999 }, &st);
            try std.testing.expect(d == .deny);
            try std.testing.expectEqual(@as(u8, 8), d.deny.code);
            try std.testing.expectEqualStrings("rate limit exceeded", d.deny.message);
        }
    }
    // an admitted caller (a ticket, no verdict) is routed as before
    var ticket: u8 = 0;
    const admitted: Caller = .{ .api_key = "k", .ticket = &ticket };
    try std.testing.expect(decide(&.{ .method = .get_object, .caller = admitted }, &.{ .forwarding = false }) == .local);
    try std.testing.expect(decide(&.{ .method = .get_object, .caller = admitted }, &.{ .guard = .tripped }) == .forward);
}
