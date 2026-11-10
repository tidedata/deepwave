//! The driver's error values and their texts, as in `crates/sui-core/src/transaction_driver/error.rs`
//! (`TransactionRequestError`, `TransactionDriverError`, `aggregate_request_errors`) and
//! `crates/sui-types/src/transaction_driver_types.rs` (`TransactionSubmissionError`), with the
//! full node's mapping to a gRPC status (`sui-rpc-api` `From<TransactionSubmissionError> for
//! RpcError`, then tonic: details = `google.rpc.Status { code, message }`).
const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const serve = @import("serve");
const se = @import("sui_error.zig");
const committee_mod = @import("committee.zig");
const reply = @import("../reply.zig");

pub const SuiErrorKind = se.SuiErrorKind;
pub const ErrorCategory = se.ErrorCategory;
pub const Committee = committee_mod.Committee;
pub const RpcError = reply.RpcError;
/// An authority's 96-byte protocol key.
pub const Name = *const [96]u8;

/// `TransactionRequestError`: what one validator answered one request.
pub const RequestError = union(enum) {
    TimedOutSubmittingTransaction,
    TimedOutGettingFullEffectsAtValidator,
    ValidatorInternal: []const u8,
    RejectedAtValidator: SuiErrorKind,
    RejectedByConsensus,
    StatusExpired: struct { epoch: u64, round: u32 },
    Aborted: SuiErrorKind,

    pub fn categorize(e: *const RequestError) ErrorCategory {
        return switch (e.*) {
            .TimedOutSubmittingTransaction, .TimedOutGettingFullEffectsAtValidator => .Unavailable,
            .ValidatorInternal => .Internal,
            .RejectedAtValidator, .Aborted => |*s| s.categorize(),
            .RejectedByConsensus, .StatusExpired => .Aborted,
        };
    }

    pub fn isSubmissionRetriable(e: *const RequestError) bool {
        return e.categorize().isSubmissionRetriable();
    }

    pub fn format(e: *const RequestError, w: *Writer) Writer.Error!void {
        switch (e.*) {
            .TimedOutSubmittingTransaction => try w.writeAll("Request timed out submitting transaction"),
            .TimedOutGettingFullEffectsAtValidator => try w.writeAll("Request timed out getting full effects"),
            .ValidatorInternal => |s| try w.writeAll(s),
            .RejectedAtValidator, .Aborted => |*s| try s.format(w),
            .RejectedByConsensus => try w.writeAll("Transaction rejected by consensus"),
            .StatusExpired => try w.writeAll("Transaction status expired"),
        }
    }

    /// `format_transaction_request_error`: the aggregation key.
    pub fn aggregationText(e: *const RequestError, arena: Allocator) Allocator.Error![]const u8 {
        return switch (e.*) {
            .RejectedAtValidator => |*s| s.requestErrorText(arena),
            else => se.allocPrint(arena, e),
        };
    }
};

/// One `(error, names, stake, category)` row of `AggregatedRequestErrors`.
pub const ErrorGroup = struct {
    text: []const u8,
    names: []const Name,
    stake: u64,
    category: ErrorCategory,
};

pub const AggregatedRequestErrors = struct {
    errors: []const ErrorGroup = &.{},
    total_stake: u64 = 0,

    pub fn format(a: *const AggregatedRequestErrors, w: *Writer) Writer.Error!void {
        for (a.errors, 0..) |g, i| {
            if (i > 0) try w.writeAll("; ");
            try w.writeAll(g.text);
            try writeNames(w, g.names);
            try w.print(" with {d} stake", .{g.stake});
        }
    }
};

/// One `(digest, names, stake)` row of `AggregatedEffectsDigests`.
pub const DigestGroup = struct {
    digest: [32]u8,
    names: []const Name,
    stake: u64,
};

pub const AggregatedEffectsDigests = struct {
    digests: []const DigestGroup = &.{},

    pub fn format(a: *const AggregatedEffectsDigests, w: *Writer) Writer.Error!void {
        for (a.digests, 0..) |g, i| {
            if (i > 0) try w.writeAll("; ");
            var buf: [serve.b58.max_len_32]u8 = undefined;
            try w.writeAll(serve.b58.encode32(&buf, &g.digest));
            try writeNames(w, g.names);
            try w.print(" with {d} stake", .{g.stake});
        }
    }
};

fn writeNames(w: *Writer, names: []const Name) Writer.Error!void {
    try w.writeAll(" { ");
    for (names, 0..) |n, i| {
        if (i > 0) try w.writeAll(", ");
        try writeConcise(w, n);
    }
    try w.writeAll(" }");
}

/// `ConciseAuthorityPublicKeyBytes` Display: `k#` + hex of the first 4 bytes + `..`.
pub fn writeConcise(w: *Writer, n: Name) Writer.Error!void {
    try w.writeAll("k#");
    for (n[0..4]) |b| try w.print("{x:0>2}", .{b});
    try w.writeAll("..");
}

/// A request error as recorded by a `StatusAggregator`: the committee index and the error.
pub const Entry = struct { index: u32, err: RequestError };

/// `aggregate_request_errors(aggregator.status_by_authority())`: `entries` in name order (one
/// per authority). Groups by the aggregation text (BTreeMap order), then a stable sort by stake,
/// largest first.
pub fn aggregate(arena: Allocator, c: *const Committee, entries: []const ?RequestError) Allocator.Error!AggregatedRequestErrors {
    var groups: std.ArrayList(struct { text: []const u8, names: std.ArrayList(Name), stake: u64, category: ErrorCategory }) = .empty;
    var total: u64 = 0;
    for (entries, 0..) |maybe, i| {
        const e = maybe orelse continue;
        const stake = c.stake(@intCast(i));
        total += stake;
        const text = try e.aggregationText(arena);
        const g = for (groups.items) |*g| {
            if (std.mem.eql(u8, g.text, text)) break g;
        } else blk: {
            try groups.append(arena, .{ .text = text, .names = .empty, .stake = 0, .category = e.categorize() });
            break :blk &groups.items[groups.items.len - 1];
        };
        try g.names.append(arena, &c.members[i].name);
        g.stake += stake;
    }
    const out = try arena.alloc(ErrorGroup, groups.items.len);
    for (groups.items, out) |g, *o| o.* = .{ .text = g.text, .names = g.names.items, .stake = g.stake, .category = g.category };
    std.sort.insertion(ErrorGroup, out, {}, struct {
        fn lt(_: void, a: ErrorGroup, b: ErrorGroup) bool {
            return std.mem.order(u8, a.text, b.text) == .lt;
        }
    }.lt);
    std.sort.insertion(ErrorGroup, out, {}, struct {
        fn lt(_: void, a: ErrorGroup, b: ErrorGroup) bool {
            return a.stake > b.stake;
        }
    }.lt);
    return .{ .errors = out, .total_stake = total };
}

/// `TransactionDriverError`.
pub const DriverError = union(enum) {
    ClientInternal: []const u8,
    ValidationFailed: []const u8,
    Aborted: struct {
        non_retriable: AggregatedRequestErrors,
        retriable: AggregatedRequestErrors,
        observed: AggregatedEffectsDigests = .{},
    },
    RejectedByValidators: struct {
        non_retriable: AggregatedRequestErrors,
        retriable: AggregatedRequestErrors,
    },
    ForkedExecution: struct {
        observed: AggregatedEffectsDigests,
        non_retriable: AggregatedRequestErrors,
        retriable: AggregatedRequestErrors,
    },
    TimeoutWithLastRetriableError: struct {
        last_error: ?*const DriverError,
        attempts: u32,
        timeout_ns: u64,
    },

    pub fn categorize(e: *const DriverError) ErrorCategory {
        return switch (e.*) {
            .ClientInternal => .Internal,
            .ValidationFailed => .InvalidTransaction,
            .Aborted => |a| if (a.retriable.errors.len > 0)
                a.retriable.errors[0].category
            else if (a.non_retriable.errors.len > 0)
                a.non_retriable.errors[0].category
            else
                .Aborted,
            .RejectedByValidators => |r| if (r.non_retriable.errors.len > 0)
                r.non_retriable.errors[0].category
            else if (r.retriable.errors.len > 0)
                r.retriable.errors[0].category
            else
                .Internal,
            .ForkedExecution => .Internal,
            .TimeoutWithLastRetriableError => .Unavailable,
        };
    }

    pub fn isSubmissionRetriable(e: *const DriverError) bool {
        return e.categorize().isSubmissionRetriable();
    }

    pub fn format(e: *const DriverError, w: *Writer) Writer.Error!void {
        switch (e.*) {
            .ClientInternal => |s| try w.print("TransactionDriver internal error: {s}", .{s}),
            .ValidationFailed => |s| try w.print("Transaction failed validation: {s}", .{s}),
            .Aborted => |a| {
                try w.writeAll("Transaction processing aborted (retriable with another submission).");
                try part(w, "Retriable errors", a.retriable);
                try part(w, "Non-retriable errors", a.non_retriable);
                if (a.observed.digests.len > 0) try digestsPart(w, &a.observed);
            },
            .RejectedByValidators => |r| {
                try w.writeAll("Transaction is rejected as invalid by more than 1/3 of validators by stake (non-retriable).");
                try part(w, "Non-retriable errors", r.non_retriable);
                try part(w, "Retriable errors", r.retriable);
            },
            .ForkedExecution => |f| {
                try w.writeAll("Transaction execution observed forked outputs (non-retriable).");
                try digestsPart(w, &f.observed);
                try part(w, "Non-retriable errors", f.non_retriable);
                try part(w, "Retriable errors", f.retriable);
            },
            .TimeoutWithLastRetriableError => |t| {
                try w.print("Transaction timed out after {d} attempts. Timeout: ", .{t.attempts});
                try writeDuration(w, t.timeout_ns);
                try w.writeAll(". Last error: ");
                if (t.last_error) |l| try l.format(w);
            },
        }
    }

    fn part(w: *Writer, label: []const u8, a: AggregatedRequestErrors) Writer.Error!void {
        if (a.total_stake == 0) return;
        try w.print(" {s}: [", .{label});
        try a.format(w);
        try w.writeAll("].");
    }

    fn digestsPart(w: *Writer, d: *const AggregatedEffectsDigests) Writer.Error!void {
        try w.writeAll(" Observed effects digests: [");
        try d.format(w);
        try w.writeAll("].");
    }

    pub fn text(e: *const DriverError, arena: Allocator) Allocator.Error![]const u8 {
        return se.allocPrint(arena, e);
    }

    /// `submit_with_transaction_driver`'s mapping onto the client-facing error.
    pub fn toSubmissionError(e: *const DriverError, arena: Allocator) Allocator.Error!SubmissionError {
        return switch (e.*) {
            .TimeoutWithLastRetriableError => |t| .{ .TimeoutBeforeFinalityWithErrors = .{
                .last_error = if (t.last_error) |l| try l.text(arena) else "",
                .attempts = t.attempts,
                .timeout_ns = t.timeout_ns,
            } },
            else => .{ .TransactionFailed = .{ .category = e.categorize(), .details = try e.text(arena) } },
        };
    }
};

/// Rust `<Duration as Debug>::fmt` without a precision: `90s`, `1.5s`, `100ms`, `2.5µs`, `7ns`.
pub fn writeDuration(w: *Writer, ns: u64) Writer.Error!void {
    const secs = ns / std.time.ns_per_s;
    const nanos = ns % std.time.ns_per_s;
    if (secs > 0) {
        try fmtDecimal(w, secs, nanos, std.time.ns_per_s / 10, "s");
    } else if (nanos >= std.time.ns_per_ms) {
        try fmtDecimal(w, nanos / std.time.ns_per_ms, nanos % std.time.ns_per_ms, std.time.ns_per_ms / 10, "ms");
    } else if (nanos >= std.time.ns_per_us) {
        try fmtDecimal(w, nanos / std.time.ns_per_us, nanos % std.time.ns_per_us, 100, "µs");
    } else {
        try fmtDecimal(w, nanos, 0, 1, "ns");
    }
}

fn fmtDecimal(w: *Writer, integer: u64, fractional: u64, divisor: u64, suffix: []const u8) Writer.Error!void {
    try w.print("{d}", .{integer});
    var f = fractional;
    var d = divisor;
    if (f > 0) {
        try w.writeByte('.');
        while (f > 0 and d > 0) {
            try w.writeByte(@intCast('0' + f / d));
            f %= d;
            d /= 10;
        }
    }
    try w.writeAll(suffix);
}

/// `GroupedErrors` row: `(SuiError, stake, concise names)`.
pub const GroupedError = struct { err: SuiErrorKind, stake: u64, names: []const Name };

/// One conflicting transaction of `ObjectsDoubleUsed`: `(authority, object ref)` pairs and stake.
pub const Conflict = struct {
    digest: [32]u8,
    pairs: []const struct { name: Name, obj_ref: se.ObjectRef },
    stake: u64,
};

/// `TransactionSubmissionError`: what the orchestrator hands the RPC layer.
pub const SubmissionError = union(enum) {
    TransactionDriverInternalError: SuiErrorKind,
    InvalidUserSignature: SuiErrorKind,
    /// Sorted by transaction digest (a BTreeMap).
    ObjectsDoubleUsed: []const Conflict,
    TimeoutBeforeFinality,
    TimeoutBeforeFinalityWithErrors: struct { last_error: []const u8, attempts: u32, timeout_ns: u64 },
    FailedWithTransientErrorAfterMaximumAttempts: u32,
    NonRecoverableTransactionError: []const GroupedError,
    SystemOverload: struct { overloaded_stake: u64, errors: []const GroupedError },
    SystemOverloadRetryAfter: struct { overload_stake: u64, errors: []const GroupedError, retry_after_secs: u64 },
    TxAlreadyFinalizedWithDifferentUserSignatures,
    TransactionFailed: struct { category: ErrorCategory, details: []const u8 },

    /// `From<TransactionSubmissionError> for RpcError`, then tonic's `Status` (details =
    /// `google.rpc.Status { code, message }`).
    pub fn toRpcError(e: *const SubmissionError, arena: Allocator) Allocator.Error!RpcError {
        var a: Writer.Allocating = .init(arena);
        const w = &a.writer;
        const code: u8 = blk: switch (e.*) {
            .InvalidUserSignature => |*s| {
                w.writeAll("Invalid user signature: ") catch return error.OutOfMemory;
                switch (s.*) {
                    .UserInputError => |*u| u.@"error".format(w) catch return error.OutOfMemory,
                    else => s.format(w) catch return error.OutOfMemory,
                }
                break :blk 3;
            },
            .TransactionDriverInternalError => |*s| {
                s.format(w) catch return error.OutOfMemory;
                break :blk 13;
            },
            .ObjectsDoubleUsed => |c| {
                writeDoubleUsed(w, c) catch return error.OutOfMemory;
                break :blk 9;
            },
            .TimeoutBeforeFinality, .FailedWithTransientErrorAfterMaximumAttempts => {
                w.writeAll("timed-out before finality could be reached") catch return error.OutOfMemory;
                break :blk 14;
            },
            .TimeoutBeforeFinalityWithErrors => |t| {
                w.print("Transaction timed out before finality could be reached. Attempts: {d} & timeout: ", .{t.attempts}) catch return error.OutOfMemory;
                writeDuration(w, t.timeout_ns) catch return error.OutOfMemory;
                w.print(". Last error: {s}", .{t.last_error}) catch return error.OutOfMemory;
                break :blk 14;
            },
            .NonRecoverableTransactionError => |errs| {
                writeNonRecoverable(arena, w, errs) catch return error.OutOfMemory;
                break :blk 3;
            },
            .TxAlreadyFinalizedWithDifferentUserSignatures => {
                w.writeAll("The transaction is already finalized but with different user signatures") catch return error.OutOfMemory;
                break :blk 10;
            },
            .SystemOverload, .SystemOverloadRetryAfter => {
                w.writeAll("system is overloaded") catch return error.OutOfMemory;
                break :blk 14;
            },
            .TransactionFailed => |f| {
                w.writeAll(f.details) catch return error.OutOfMemory;
                break :blk categoryCode(f.category);
            },
        };
        const message = a.written();
        return .{ .code = code, .message = message, .details = try statusDetails(arena, code, message) };
    }
};

/// The gRPC code `TransactionFailed { category }` maps to.
pub fn categoryCode(c: ErrorCategory) u8 {
    return switch (c) {
        .Internal => 13,
        .Aborted => 10,
        .InvalidTransaction => 3,
        .LockConflict => 9,
        .ValidatorOverloaded => 8,
        .Unavailable => 14,
    };
}

/// tonic's `grpc-status-details-bin` for an `RpcError` without details: `Status { code, message }`.
pub fn statusDetails(arena: Allocator, code: u8, message: []const u8) Allocator.Error![]const u8 {
    return serve.status.plain(arena, code, message) catch return error.OutOfMemory;
}

fn writeNonRecoverable(arena: Allocator, w: *Writer, errs: []const GroupedError) !void {
    const sorted = try arena.dupe(GroupedError, errs);
    // itertools sorted_by is a stable sort; by stake, descending
    std.sort.insertion(GroupedError, sorted, {}, struct {
        fn lt(_: void, a: GroupedError, b: GroupedError) bool {
            return a.stake > b.stake;
        }
    }.lt);
    try w.writeAll("Transaction execution failed due to issues with transaction inputs, please review the errors and try again: ");
    var first = true;
    for (sorted) |*g| {
        switch (g.err) {
            .UserInputError => |*u| {
                if (!first) try w.writeAll(", ");
                first = false;
                try u.@"error".format(w);
            },
            else => {
                if (g.err.isRetryable().retryable) continue;
                if (!first) try w.writeAll(", ");
                first = false;
                try g.err.format(w);
            },
        }
    }
    try w.writeAll(".");
}

/// `format!("...Conflicting Transactions:\n{new_map:#?}")` with `new_map: BTreeMap<TransactionDigest,
/// Vec<ObjectRef>>`: Rust's pretty Debug (4-space indents, trailing commas).
fn writeDoubleUsed(w: *Writer, conflicts: []const Conflict) Writer.Error!void {
    try w.writeAll("Failed to sign transaction by a quorum of validators because of locked objects. Conflicting Transactions:\n");
    if (conflicts.len == 0) return w.writeAll("{}");
    try w.writeAll("{\n");
    for (conflicts) |c| {
        var buf: [serve.b58.max_len_32]u8 = undefined;
        try w.print("    TransactionDigest(\n        {s},\n    ): [", .{serve.b58.encode32(&buf, &c.digest)});
        if (c.pairs.len == 0) {
            try w.writeAll("],\n");
            continue;
        }
        try w.writeAll("\n");
        for (c.pairs) |p| {
            try w.writeAll("        (\n            0x");
            for (p.obj_ref.@"0".@"0".@"0") |b| try w.print("{x:0>2}", .{b});
            try w.print(",\n            SequenceNumber(\n                {d},\n            ),\n            o#", .{p.obj_ref.@"1".@"0"});
            try w.writeAll(serve.b58.encode32(&buf, &p.obj_ref.@"2".@"0".@"0"));
            try w.writeAll(",\n        ),\n");
        }
        try w.writeAll("    ],\n");
    }
    try w.writeAll("}");
}

const testing = std.testing;

test "duration debug" {
    var buf: [64]u8 = undefined;
    const cases = [_]struct { u64, []const u8 }{
        .{ 90 * std.time.ns_per_s, "90s" },
        .{ 1_500_000_000, "1.5s" },
        .{ 100 * std.time.ns_per_ms, "100ms" },
        .{ 2_500, "2.5µs" },
        .{ 7, "7ns" },
        .{ 0, "0ns" },
        .{ 1_000_000_001, "1.000000001s" },
    };
    for (cases) |c| {
        var w: Writer = .fixed(&buf);
        try writeDuration(&w, c[0]);
        try testing.expectEqualStrings(c[1], w.buffered());
    }
}

test "aggregate groups by text then stake" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const c = try Committee.init(arena, 1, &.{
        .{ .name = @splat(1), .stake = 2500 },
        .{ .name = @splat(2), .stake = 2500 },
        .{ .name = @splat(3), .stake = 2500 },
        .{ .name = @splat(4), .stake = 2500 },
    });
    const entries = [_]?RequestError{ .TimedOutSubmittingTransaction, .RejectedByConsensus, null, .RejectedByConsensus };
    const agg = try aggregate(arena, &c, &entries);
    try testing.expectEqual(@as(u64, 7500), agg.total_stake);
    const t = try se.allocPrint(arena, &agg);
    try testing.expectEqualStrings("Transaction rejected by consensus { k#02020202.., k#04040404.. } with 5000 stake; Request timed out submitting transaction { k#01010101.. } with 2500 stake", t);
    const de: DriverError = .{ .Aborted = .{ .non_retriable = .{}, .retriable = agg } };
    try testing.expectEqual(ErrorCategory.Aborted, de.categorize());
    const sub = try de.toSubmissionError(arena);
    const rpc = try sub.toRpcError(arena);
    try testing.expectEqual(@as(u8, 10), rpc.code);
    try testing.expect(std.mem.startsWith(u8, rpc.message, "Transaction processing aborted (retriable with another submission). Retriable errors: [Transaction rejected"));
}
