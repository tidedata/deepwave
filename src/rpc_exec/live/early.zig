//! The orchestrator's early validation (sui-core 1.83.1 `check_transaction_validity`, on by
//! default: `TransactionDriverConfig::enable_early_validation`), the part that decides most
//! client-visible rejections: owned input objects (and gas coins) must be at their live version
//! with the live digest. A stale version answers `TransactionFailed { InvalidTransaction,
//! "Transaction needs to be rebuilt because object ... is unavailable for consumption, current
//! version: ..." }` (INVALID_ARGUMENT) without a submission, exactly as sui-node does; a retriable
//! category is ignored, as in sui-node.
//!
//! Also the gas coins' total balance against the budget (`GasBalanceTooLow`, checked first, as the
//! deny checks run before the version checks).
//!
//! With the epoch environment and latest-object reads (`LiveObjects.env`/`latest`), the rest of
//! `check_transaction_validity` in sui-node's order: `validity_check` (transaction limits, gas
//! price, expiration), then the input loader and `check_transaction_input` (gas budget and
//! balance, ownership, receiving objects) through the simulate lane's `checks.zig`, with sui-node's
//! texts. A retriable outcome (an object or package this node does not have) rejects nothing, as
//! in sui-node; transactions paying gas from an address balance skip the input checks (their
//! withdrawal checks are not ported here), so deepwave never refuses a transaction sui-node accepts.
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types");
const se = @import("../driver/sui_error.zig");
const errors = @import("../driver/errors.zig");
const handler = @import("../driver/handler.zig");
const checks = @import("../checks.zig");
const txdeny = @import("../txdeny.zig");
const drv = @import("../driver/driver.zig");
const LocalEffects = @import("local.zig").LocalEffects;
const exec = @import("exec");
const EpochEnv = @import("../root.zig").EpochEnv;

/// sui-node `TransactionDriverConfig::enable_early_validation` (fullnode.yaml
/// `transaction-driver-config.enable-early-validation`, deepwave `--early-validation`). Off skips
/// `check_transaction_validity` and with it the transaction-deny-config checks: the transaction goes
/// to the validators, which do not apply this node's deny config. Set at startup.
pub var enabled: std.atomic.Value(bool) = .init(true);

/// What answers an Execute after the user-signature check and before any submission (sui-node
/// `execute_transaction_impl`, then `execute_transaction_with_effects_waiting`).
pub const Head = union(enum) {
    /// early validation rejected a transaction this node has not executed
    reject: errors.SubmissionError,
    /// executed here: its local effects, filtered to the request's read mask
    local: drv.QuorumResponse,
    /// neither: submit it
    submit,
};

/// Early validation, then the local effects. An early rejection is skipped for a transaction
/// already executed here (sui-node: `is_tx_already_executed` after a non-retriable
/// `check_transaction_validity` error), so a retry of a landed transaction answers its effects even
/// when the deny config or a stale input would reject it now. A retriable early error rejects
/// nothing either way.
pub fn head(arena: Allocator, live: ?LiveObjects, local: ?LocalEffects, req: *const handler.ExecuteRequest, enforce_live: bool) Allocator.Error!Head {
    const rejected: ?errors.SubmissionError = if (!enabled.load(.monotonic)) null else if (live) |lo| try check(arena, lo, req, enforce_live) else null;
    if (local) |l| if (l.get(l.ctx, arena, req)) |q| return .{ .local = handler.filtered(.{ .ok = q }, req).ok };
    if (rejected) |e| return .{ .reject = e };
    return .submit;
}

/// The node's live version of an object (null: not known locally, nothing is checked).
pub const Live = struct { version: u64, digest: [32]u8, immutable: bool };

pub const LiveObjects = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?Live,
    /// BCS `Object` at an exact version (the input loader reads gas coins at the given version).
    at: *const fn (ctx: *anyopaque, arena: Allocator, id: *const [32]u8, version: u64) ?[]const u8,
    /// BCS `Object` at its live version (shared inputs, packages, receiving objects).
    latest: ?*const fn (ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?[]const u8 = null,
    /// The current epoch's protocol config, reference gas price and chain (null: the
    /// `validity_check` and input checks are skipped).
    env: ?EnvFn = null,
};

pub const EnvFn = struct {
    ctx: *const anyopaque,
    get: *const fn (ctx: *const anyopaque) ?EpochEnv,
};

/// A `checks.Fail` as the orchestrator's `TransactionFailed` (null: a category sui-node does not
/// reject early, or a text whose category is not known here).
fn failOf(f: checks.Fail) ?errors.SubmissionError {
    const user = "Error checking transaction input objects: ";
    const feature = "Use of disabled feature: ";
    if (f.code == 3 and std.mem.startsWith(u8, f.message, user)) {
        const inner = f.message[user.len..];
        // ObjectNotFound / DependentPackageNotFound: Aborted, retriable
        if (std.mem.startsWith(u8, inner, "Could not find the referenced object") or std.mem.startsWith(u8, inner, "Dependent package not found")) return null;
        return .{ .TransactionFailed = .{ .category = .InvalidTransaction, .details = f.message } };
    }
    if (f.code == 3 and std.mem.startsWith(u8, f.message, feature))
        return .{ .TransactionFailed = .{ .category = .Internal, .details = f.message } };
    return null;
}

const Outcome = union(enum) { pass, reject: errors.SubmissionError, stop };

/// `validity_check`, the input loader and `check_transaction_input`.
fn denyChecks(arena: Allocator, live: LiveObjects, env: *const EpochEnv, td: *const types.TransactionDataV1, sigs: []const []const u8) Allocator.Error!Outcome {
    if (checks.isSystemKind(&td.kind)) return .pass;
    const vctx: checks.ValidityCtx = .{ .cfg = env.cfg, .epoch = env.epoch, .chain_id = env.chain_id, .rgp = env.rgp, .committee_size = env.committee_size };
    if (checks.validity(arena, &vctx, td) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .stop,
    }) |f| return if (failOf(f)) |x| .{ .reject = x } else .stop;
    switch (try txDeny(arena, live, td, sigs)) {
        .pass => {},
        else => |o| return o,
    }
    const latest = live.latest orelse return .pass;
    if (td.gas_data.payment.len == 0 or checks.hasFundsWithdrawals(td) or checks.isGasless(env.cfg, td)) return .pass;
    var kinds: std.ArrayList(checks.InputKind) = .empty;
    var recv: std.ArrayList(checks.Receiving) = .empty;
    if (try checks.inputKinds(arena, td, &kinds, &recv)) |f| return if (failOf(f)) |x| .{ .reject = x } else .stop;
    const loaded = try arena.alloc(checks.Loaded, kinds.items.len);
    for (kinds.items, loaded) |k, *l| {
        const raw: []const u8 = switch (k) {
            .package => |pid| latest(live.ctx, arena, &pid) orelse return .stop,
            .shared => |sh| latest(live.ctx, arena, &sh.id) orelse return .stop,
            .owned => |o| live.at(live.ctx, arena, &o.id, o.version) orelse {
                const lv = live.get(live.ctx, arena, &o.id) orelse return .stop;
                if (lv.version >= o.version) {
                    if (try failed(arena, .{ .ObjectVersionUnavailableForConsumption = .{
                        .provided_obj_ref = .{ .{ .@"0" = .{ .@"0" = o.id } }, .{ .@"0" = o.version }, .{ .@"0" = .{ .@"0" = o.digest } } },
                        .current_version = .{ .@"0" = lv.version },
                    } })) |x| return .{ .reject = x };
                }
                return .stop;
            },
        };
        const v = exec.objects.ObjectView.parse(raw) catch return .stop;
        if (k == .package and !v.is_package) return .stop;
        const owner = @import("bcs").decode(types.Owner, arena, raw[v.owner_at..v.prev_tx_at]) catch return .stop;
        if (k == .shared) {
            const start: ?u64 = switch (owner) {
                .Shared => |x| x.initial_shared_version.@"0",
                .ConsensusAddressOwner => |x| x.start_version.@"0",
                .Party => |x| x.start_version.@"0",
                else => null,
            };
            if (start == null or start.? != k.shared.isv) return .stop;
        }
        l.* = .{ .kind = k, .raw = raw, .view = v, .owner = owner };
    }
    const recv_objs = try arena.alloc(?[]const u8, recv.items.len);
    for (recv.items, recv_objs) |r, *o| o.* = latest(live.ctx, arena, &r.id) orelse return .stop;
    if (checks.transactionInput(arena, env.cfg, env.rgp, td, loaded, recv.items, recv_objs) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .stop,
    }) |f| return if (failOf(f)) |x| .{ .reject = x } else .stop;
    return .pass;
}

/// `pre_object_load_checks`' deny checks (transaction-deny-config), right after `validity_check`.
fn txDeny(arena: Allocator, live: LiveObjects, td: *const types.TransactionDataV1, sigs: []const []const u8) Allocator.Error!Outcome {
    const cfg = txdeny.current();
    if (!cfg.active()) return .pass;
    const rules = &cfg.rules;
    var kinds: std.ArrayList(checks.InputKind) = .empty;
    var recv: std.ArrayList(checks.Receiving) = .empty;
    // a duplicate input fails in TransactionData::input_objects, before the deny checks
    if (try checks.inputKinds(arena, td, &kinds, &recv)) |f| return if (failOf(f)) |x| .{ .reject = x } else .stop;
    var pl: LivePkgs = .{ .live = live };
    const f = (try txdeny.check(arena, rules, td, sigs, kinds.items, recv.items, pl.lookup())) orelse return .pass;
    return if (failOf(f)) |x| .{ .reject = x } else .stop;
}

const LivePkgs = struct {
    live: LiveObjects,
    fn lookup(p: *LivePkgs) txdeny.PackageLookup {
        return .{ .ctx = p, .get = get };
    }
    fn get(ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?[]const u8 {
        const p: *LivePkgs = @ptrCast(@alignCast(ctx));
        const latest = p.live.latest orelse return null;
        return latest(p.live.ctx, arena, id);
    }
};

/// `GasStatus::check_gas_balance` step 3: the gas coins' total balance at their given versions
/// must cover the budget. Null when a coin is not readable here (sui-node: ObjectNotFound, a
/// retriable category, so early validation does not reject either).
fn gasBalanceError(arena: Allocator, live: LiveObjects, td: anytype) ?se.UserInputError {
    if (td.gas_data.payment.len == 0) return null; // address-balance gas: not checked here
    var total: u128 = 0;
    for (td.gas_data.payment) |g| {
        const raw = live.at(live.ctx, arena, &g.@"0".@"0".@"0", g.@"1".@"0") orelse return null;
        const bcs = @import("bcs");
        const obj = bcs.decode(types.Object, arena, raw) catch return null;
        const c = switch (obj.data) {
            .Move => |m| m.contents,
            else => return null,
        };
        if (c.len < 40) return null;
        total += std.mem.readInt(u64, c[32..40], .little);
    }
    if (total >= td.gas_data.budget) return null;
    return .{ .GasBalanceTooLow = .{ .gas_balance = total, .needed_gas_amount = td.gas_data.budget } };
}

fn failed(arena: Allocator, u: se.UserInputError) Allocator.Error!?errors.SubmissionError {
    const e: se.SuiErrorKind = .{ .UserInputError = .{ .@"error" = u } };
    const cat = e.categorize();
    if (cat.isSubmissionRetriable()) return null;
    var a: std.Io.Writer.Allocating = .init(arena);
    e.format(&a.writer) catch return error.OutOfMemory;
    return .{ .TransactionFailed = .{ .category = cat, .details = a.written() } };
}

/// Live from a BCS `Object` (owner and version from the bytes, digest from the caller).
pub fn liveOf(raw: []const u8, digest: [32]u8, arena: Allocator) ?Live {
    const bcs = @import("bcs");
    const obj = bcs.decode(types.Object, arena, raw) catch return null;
    const version: u64 = switch (obj.data) {
        .Move => |m| m.version.@"0",
        .Package => |p| p.version.@"0",
    };
    return .{ .version = version, .digest = digest, .immutable = obj.owner == .Immutable or obj.data == .Package };
}

const ObjRef = struct { id: [32]u8, version: u64, digest: [32]u8 };

/// Null: nothing to reject here.
pub fn check(arena: Allocator, live: LiveObjects, req: *const handler.ExecuteRequest, enforce_live: bool) Allocator.Error!?errors.SubmissionError {
    const td = switch (req.data.*) {
        .V1 => |*v| v,
    };
    var refs: std.ArrayList(ObjRef) = .empty;
    switch (td.kind) {
        .ProgrammableTransaction => |pt| for (pt.inputs) |in| switch (in) {
            .Object => |o| switch (o) {
                .ImmOrOwnedObject => |r| try refs.append(arena, .{ .id = r.@"0".@"0".@"0", .version = r.@"1".@"0", .digest = r.@"2".@"0".@"0" }),
                else => {},
            },
            else => {},
        },
        else => return null,
    }
    for (td.gas_data.payment) |g| try refs.append(arena, .{ .id = g.@"0".@"0".@"0", .version = g.@"1".@"0", .digest = g.@"2".@"0".@"0" });

    // validity_check and handle_transaction_deny_checks run before the version checks; an error
    // sui-node treats as retriable ends early validation without a rejection
    const env: ?EpochEnv = if (live.env) |e| e.get(e.ctx) else null;
    if (env) |*e| switch (try denyChecks(arena, live, e, td, req.signatures)) {
        .pass => {},
        .reject => |x| return x,
        .stop => return null,
    } else {
        // without the epoch environment validity_check is skipped; the deny config still applies
        switch (try txDeny(arena, live, td, req.signatures)) {
            .pass => {},
            .reject => |x| return x,
            .stop => return null,
        }
        if (gasBalanceError(arena, live, td)) |u| return failed(arena, u);
    }

    for (refs.items) |r| {
        const l = live.get(live.ctx, arena, &r.id) orelse continue;
        if (l.immutable) continue; // filter_owned_objects: address- and object-owned only
        const kind: ?se.UserInputError = if (r.version < l.version or (enforce_live and l.version < r.version))
            .{ .ObjectVersionUnavailableForConsumption = .{
                .provided_obj_ref = .{ .{ .@"0" = .{ .@"0" = r.id } }, .{ .@"0" = r.version }, .{ .@"0" = .{ .@"0" = r.digest } } },
                .current_version = .{ .@"0" = l.version },
            } }
        else if (r.version == l.version and !std.mem.eql(u8, &r.digest, &l.digest))
            .{ .InvalidObjectDigest = .{ .object_id = .{ .@"0" = .{ .@"0" = r.id } }, .expected_digest = .{ .@"0" = .{ .@"0" = l.digest } } } }
        else
            null;
        const u = kind orelse continue;
        return failed(arena, u);
    }
    return null;
}
