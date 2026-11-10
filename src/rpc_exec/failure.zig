//! sui-rpc-api's two gas-selection error replies with ErrorInfo details (simulate/mod.rs, error.rs):
//! - `simulation_failure_error`: "Transaction fails in simulation: {ExecutionErrorKind Display}[ in
//!   command N]", details `[Any(ErrorInfo { TRANSACTION_EXECUTION_FAILED, sui.io, {command, kind} }),
//!   Any(ExecutionError)]` where the ExecutionError is the one simulate's effects render (clever
//!   errors included);
//! - `InsufficientGasBalanceError`: the gas selection shortfall, details `[Any(ErrorInfo {
//!   INSUFFICIENT_GAS_BALANCE, sui.io, {addressBalance, coinBalance, owner, requiredBudget} })]`.
//! Also `ExecutionErrorKind`'s thiserror Display (sui-types execution_status.rs), every variant.
const std = @import("std");
const types = @import("types");
const serve = @import("serve");

const Allocator = std.mem.Allocator;
const proto = serve.proto;

pub const code_invalid_argument = 3;
/// `ErrorReason::DOMAIN`.
pub const domain = "sui.io";
const type_url_error_info = "/google.rpc.ErrorInfo";
const type_url_execution_error = "/sui.rpc.v2.ExecutionError";

fn hex0x(arena: Allocator, a: *const [32]u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, "0x{x}", .{a});
}

/// `MoveLocation`'s Display: `{module}::{fname} (function index F) at offset I`, or without a
/// function name `{module} in function definition F at offset I` (ModuleId: 64 hex digits, no 0x).
fn location(arena: Allocator, l: types.MoveLocation) Allocator.Error![]const u8 {
    if (l.function_name) |f|
        return std.fmt.allocPrint(arena, "{x}::{s}::{s} (function index {d}) at offset {d}", .{ &l.module.address.@"0", l.module.name.@"0", f.@"0", l.function, l.instruction });
    return std.fmt.allocPrint(arena, "{x}::{s} in function definition {d} at offset {d}", .{ &l.module.address.@"0", l.module.name.@"0", l.function, l.instruction });
}

fn commandArgDisplay(arena: Allocator, k: types.CommandArgumentError) Allocator.Error![]const u8 {
    return switch (k) {
        .TypeMismatch => "The type of the value does not match the expected type",
        .InvalidBCSBytes => "The argument cannot be deserialized into a value of the specified type",
        .InvalidUsageOfPureArg => "The argument cannot be instantiated from raw bytes",
        .InvalidArgumentToPrivateEntryFunction => "Invalid argument to private entry function. These functions cannot take arguments from other Move functions",
        .IndexOutOfBounds => |v| std.fmt.allocPrint(arena, "Out of bounds access to input or result vector {d}", .{v.idx}),
        .SecondaryIndexOutOfBounds => |v| std.fmt.allocPrint(arena, "Out of bounds secondary access to result vector {d} at secondary index {d}", .{ v.result_idx, v.secondary_idx }),
        .InvalidResultArity => |v| std.fmt.allocPrint(arena, "Invalid usage of result {d}, expected a single result but found either no return values or multiple.", .{v.result_idx}),
        .InvalidGasCoinUsage => "Invalid taking of the Gas coin. It can only be used by-value with TransferObjects",
        .InvalidValueUsage => "Invalid usage of value. Mutably borrowed values require unique usage. Immutably borrowed values cannot be taken or borrowed mutably. Taken values cannot be used again.",
        .InvalidObjectByValue => "Immutable objects cannot be passed by-value.",
        .InvalidObjectByMutRef => "Immutable objects cannot be passed by mutable reference, &mut.",
        .SharedObjectOperationNotAllowed => "Shared object operations such a wrapping, freezing, or converting to owned are not allowed.",
        .InvalidArgumentArity => "Invalid argument arity. Expected a single argument but found a result that expanded to multiple arguments.",
        .InvalidTransferObject => "Object passed to TransferObject does not have public transfer, i.e. the `store` ability",
        .InvalidMakeMoveVecNonObjectArgument => "First argument to MakeMoveVec is not an object. If no type is specified for MakeMoveVec, all arguments must be the same object type.",
        .ArgumentWithoutValue => "Specified argument location does not have a value and cannot be used",
        .CannotMoveBorrowedValue => "Cannot move a borrowed value. The value's type does resulted in this argument usage being inferred as a move. This is likely due to the type not having the `copy` ability; although in rare cases, it could also be this is the last usage of a value without the `drop` ability.",
        .CannotWriteToExtendedReference => "Cannot write to an argument location that is still borrowed, and where that borrow is an extension of that reference. This is likely due to this argument being used in a Move call that returns a reference, and that reference is used in a later command.",
        .InvalidReferenceArgument => "The argument specified cannot be used as a reference argument in the Move call. Either the argument is a mutable reference and it conflicts with another argument to the call, or the argument is mutable and another reference extends it and will be used in a later command.",
        .InvalidTxContext => "Invalid usage of TxContext in the function signature. TxContext can only be used by reference, `&TxContext` or `&mut TxContext`. If used mutably, it must be the only TxContext parameter, and TxContext can never be returned from a Move call.",
    };
}

fn upgradeDisplay(arena: Allocator, e: types.PackageUpgradeError) Allocator.Error![]const u8 {
    return switch (e) {
        .UnableToFetchPackage => |v| std.fmt.allocPrint(arena, "Unable to fetch package at {s}", .{try hex0x(arena, &v.package_id.@"0".@"0")}),
        .NotAPackage => |v| std.fmt.allocPrint(arena, "Object {s} is not a package", .{try hex0x(arena, &v.object_id.@"0".@"0")}),
        .IncompatibleUpgrade => "New package is incompatible with previous version",
        .DigestDoesNotMatch => "Digest in upgrade ticket and computed digest disagree",
        .UnknownUpgradePolicy => |v| std.fmt.allocPrint(arena, "Upgrade policy {d} is not a valid upgrade policy", .{v.policy}),
        .PackageIDDoesNotMatch => |v| std.fmt.allocPrint(arena, "Package ID {s} does not match package ID in upgrade ticket {s}", .{ try hex0x(arena, &v.package_id.@"0".@"0"), try hex0x(arena, &v.ticket_id.@"0".@"0") }),
    };
}

/// `ExecutionErrorKind`'s Display (thiserror attributes of sui-types 1.83.1 execution_status.rs).
pub fn kindDisplay(arena: Allocator, k: types.ExecutionErrorKind) Allocator.Error![]const u8 {
    return switch (k) {
        .InsufficientGas => "Insufficient Gas.",
        .InvalidGasObject => "Invalid Gas Object. Possibly not address-owned or possibly not a SUI coin.",
        .InvariantViolation => "INVARIANT VIOLATION.",
        .FeatureNotYetSupported => "Attempted to used feature that is not supported yet",
        .MoveObjectTooBig => |v| std.fmt.allocPrint(arena, "Move object with size {d} is larger than the maximum object size {d}", .{ v.object_size, v.max_object_size }),
        .MovePackageTooBig => |v| std.fmt.allocPrint(arena, "Move package with size {d} is larger than the maximum object size {d}", .{ v.object_size, v.max_object_size }),
        .CircularObjectOwnership => |v| std.fmt.allocPrint(arena, "Circular Object Ownership, including object {s}.", .{try hex0x(arena, &v.object.@"0".@"0")}),
        .InsufficientCoinBalance => "Insufficient coin balance for operation.",
        .CoinBalanceOverflow => "The coin balance overflows u64",
        .PublishErrorNonZeroAddress => "Publish Error, Non-zero Address. The modules in the package must have their self-addresses set to zero.",
        .SuiMoveVerificationError => "Sui Move Bytecode Verification Error. Please run the Sui Move Verifier for more information.",
        .MovePrimitiveRuntimeError => |v| std.fmt.allocPrint(arena, "Move Primitive Runtime Error. Location: {s}. Arithmetic error, stack overflow, max value depth, etc.", .{if (v.@"0") |l| try location(arena, l) else "UNKNOWN"}),
        .MoveAbort => |v| std.fmt.allocPrint(arena, "Move Runtime Abort. Location: {s}, Abort Code: {d}", .{ try location(arena, v[0]), v[1] }),
        .VMVerificationOrDeserializationError => "Move Bytecode Verification Error. Please run the Bytecode Verifier for more information.",
        .VMInvariantViolation => "MOVE VM INVARIANT VIOLATION.",
        .FunctionNotFound => "Function Not Found.",
        .ArityMismatch => "Arity mismatch for Move function. The number of arguments does not match the number of parameters",
        .TypeArityMismatch => "Type arity mismatch for Move function. Mismatch between the number of actual versus expected type arguments.",
        .NonEntryFunctionInvoked => "Non Entry Function Invoked. Move Call must start with an entry function",
        .CommandArgumentError => |v| std.fmt.allocPrint(arena, "Invalid command argument at {d}. {s}", .{ v.arg_idx, try commandArgDisplay(arena, v.kind) }),
        .TypeArgumentError => |v| std.fmt.allocPrint(arena, "Error for type argument at index {d}: {s}", .{ v.argument_idx, switch (v.kind) {
            .TypeNotFound => "A type was not found in the module specified.",
            .ConstraintNotSatisfied => "A type provided did not match the specified constraints.",
        } }),
        .UnusedValueWithoutDrop => |v| std.fmt.allocPrint(arena, "Unused result without the drop ability. Command result {d}, return value {d}", .{ v.result_idx, v.secondary_idx }),
        .InvalidPublicFunctionReturnType => |v| std.fmt.allocPrint(arena, "Invalid public Move function signature. Unsupported return type for return value {d}", .{v.idx}),
        .InvalidTransferObject => "Invalid Transfer Object, object does not have public transfer.",
        .EffectsTooLarge => |v| std.fmt.allocPrint(arena, "Effects of size {d} bytes too large. Limit is {d} bytes", .{ v.current_size, v.max_size }),
        .PublishUpgradeMissingDependency => "Publish/Upgrade Error, Missing dependency. A dependency of a published or upgraded package has not been assigned an on-chain address.",
        .PublishUpgradeDependencyDowngrade => "Publish/Upgrade Error, Dependency downgrade. Indirect (transitive) dependency of published or upgraded package has been assigned an on-chain version that is less than the version required by one of the package's transitive dependencies.",
        .PackageUpgradeError => |v| std.fmt.allocPrint(arena, "Invalid package upgrade. {s}", .{try upgradeDisplay(arena, v.upgrade_error)}),
        .WrittenObjectsTooLarge => |v| std.fmt.allocPrint(arena, "Written objects of {d} bytes too large. Limit is {d} bytes", .{ v.current_size, v.max_size }),
        .CertificateDenied => "Certificate is on the deny list",
        .SuiMoveVerificationTimedout => "Sui Move Bytecode Verification Timeout. Please run the Sui Move Verifier for more information.",
        .SharedObjectOperationNotAllowed => "The shared object operation is not allowed.",
        .InputObjectDeleted => "Certificate cannot be executed due to a dependency on a deleted shared object or an object that was transferred out of consensus",
        .ExecutionCancelledDueToSharedObjectCongestion => |v| blk: {
            // CongestedObjects Display: "{id}, " per object
            var out: std.ArrayList(u8) = .empty;
            try out.appendSlice(arena, "Certificate is cancelled due to congestion on shared objects: ");
            for (v.congested_objects.@"0") |o| try out.print(arena, "0x{x}, ", .{&o.@"0".@"0"});
            break :blk out.items;
        },
        .AddressDeniedForCoin => |v| std.fmt.allocPrint(arena, "Address {s} is denied for coin {s}", .{ try hex0x(arena, &v.address.@"0"), v.coin_type.@"0" }),
        .CoinTypeGlobalPause => |v| std.fmt.allocPrint(arena, "Coin type is globally paused for use: {s}", .{v.coin_type.@"0"}),
        .ExecutionCancelledDueToRandomnessUnavailable => "Certificate is cancelled because randomness could not be generated this epoch",
        .MoveVectorElemTooBig => |v| std.fmt.allocPrint(arena, "Move vector element (passed to MakeMoveVec) with size {d} is larger than the maximum size {d}. Note that this maximum is scaled based on the type of the vector element.", .{ v.value_size, v.max_scaled_size }),
        .MoveRawValueTooBig => |v| std.fmt.allocPrint(arena, "Move value (possibly an upgrade ticket or a dev-inspect value) with size {d} is larger than the maximum size  {d}. Note that this maximum is scaled based on the type of the value.", .{ v.value_size, v.max_scaled_size }),
        .InvalidLinkage => "A valid linkage was unable to be determined for the transaction",
        .InsufficientFundsForWithdraw => "Insufficient funds for funds accumulator withdrawal",
        .NonExclusiveWriteInputObjectModified => |v| std.fmt.allocPrint(arena, "Non-exclusive write input object {s} has been modified", .{try hex0x(arena, &v.id.@"0".@"0")}),
    };
}

/// The proto `ExecutionErrorKind::as_str_name` of a kind (sui.rpc.v2 numbering, in Rust order).
pub fn kindName(k: types.ExecutionErrorKind) []const u8 {
    return switch (k) {
        .InsufficientGas => "INSUFFICIENT_GAS",
        .InvalidGasObject => "INVALID_GAS_OBJECT",
        .InvariantViolation => "INVARIANT_VIOLATION",
        .FeatureNotYetSupported => "FEATURE_NOT_YET_SUPPORTED",
        .MoveObjectTooBig => "OBJECT_TOO_BIG",
        .MovePackageTooBig => "PACKAGE_TOO_BIG",
        .CircularObjectOwnership => "CIRCULAR_OBJECT_OWNERSHIP",
        .InsufficientCoinBalance => "INSUFFICIENT_COIN_BALANCE",
        .CoinBalanceOverflow => "COIN_BALANCE_OVERFLOW",
        .PublishErrorNonZeroAddress => "PUBLISH_ERROR_NON_ZERO_ADDRESS",
        .SuiMoveVerificationError => "SUI_MOVE_VERIFICATION_ERROR",
        .MovePrimitiveRuntimeError => "MOVE_PRIMITIVE_RUNTIME_ERROR",
        .MoveAbort => "MOVE_ABORT",
        .VMVerificationOrDeserializationError => "VM_VERIFICATION_OR_DESERIALIZATION_ERROR",
        .VMInvariantViolation => "VM_INVARIANT_VIOLATION",
        .FunctionNotFound => "FUNCTION_NOT_FOUND",
        .ArityMismatch => "ARITY_MISMATCH",
        .TypeArityMismatch => "TYPE_ARITY_MISMATCH",
        .NonEntryFunctionInvoked => "NON_ENTRY_FUNCTION_INVOKED",
        .CommandArgumentError => "COMMAND_ARGUMENT_ERROR",
        .TypeArgumentError => "TYPE_ARGUMENT_ERROR",
        .UnusedValueWithoutDrop => "UNUSED_VALUE_WITHOUT_DROP",
        .InvalidPublicFunctionReturnType => "INVALID_PUBLIC_FUNCTION_RETURN_TYPE",
        .InvalidTransferObject => "INVALID_TRANSFER_OBJECT",
        .EffectsTooLarge => "EFFECTS_TOO_LARGE",
        .PublishUpgradeMissingDependency => "PUBLISH_UPGRADE_MISSING_DEPENDENCY",
        .PublishUpgradeDependencyDowngrade => "PUBLISH_UPGRADE_DEPENDENCY_DOWNGRADE",
        .PackageUpgradeError => "PACKAGE_UPGRADE_ERROR",
        .WrittenObjectsTooLarge => "WRITTEN_OBJECTS_TOO_LARGE",
        .CertificateDenied => "CERTIFICATE_DENIED",
        .SuiMoveVerificationTimedout => "SUI_MOVE_VERIFICATION_TIMEDOUT",
        .SharedObjectOperationNotAllowed => "CONSENSUS_OBJECT_OPERATION_NOT_ALLOWED",
        .InputObjectDeleted => "INPUT_OBJECT_DELETED",
        .ExecutionCancelledDueToSharedObjectCongestion => "EXECUTION_CANCELED_DUE_TO_CONSENSUS_OBJECT_CONGESTION",
        .AddressDeniedForCoin => "ADDRESS_DENIED_FOR_COIN",
        .CoinTypeGlobalPause => "COIN_TYPE_GLOBAL_PAUSE",
        .ExecutionCancelledDueToRandomnessUnavailable => "EXECUTION_CANCELED_DUE_TO_RANDOMNESS_UNAVAILABLE",
        .MoveVectorElemTooBig => "MOVE_VECTOR_ELEM_TOO_BIG",
        .MoveRawValueTooBig => "MOVE_RAW_VALUE_TOO_BIG",
        .InvalidLinkage => "INVALID_LINKAGE",
        .InsufficientFundsForWithdraw => "INSUFFICIENT_FUNDS_FOR_WITHDRAW",
        .NonExclusiveWriteInputObjectModified => "NON_EXCLUSIVE_WRITE_INPUT_OBJECT_MODIFIED",
    };
}

/// "Transaction fails in simulation: {kind}[ in command N]".
pub fn simulationFailureMessage(arena: Allocator, f: types.ExecutionFailure) Allocator.Error![]const u8 {
    const kind = try kindDisplay(arena, f.@"error");
    if (f.command) |c| return std.fmt.allocPrint(arena, "Transaction fails in simulation: {s} in command {d}", .{ kind, c });
    return std.fmt.allocPrint(arena, "Transaction fails in simulation: {s}", .{kind});
}

// ---- protobuf assembly (prost encoding: default values skipped, maps in BTreeMap key order) ----

fn appendVarint(arena: Allocator, out: *std.ArrayList(u8), v0: u64) Allocator.Error!void {
    var v = v0;
    while (v >= 0x80) : (v >>= 7) try out.append(arena, @as(u8, @truncate(v)) | 0x80);
    try out.append(arena, @truncate(v));
}
fn appendLen(arena: Allocator, out: *std.ArrayList(u8), field: u32, b: []const u8) Allocator.Error!void {
    try appendVarint(arena, out, (@as(u64, field) << 3) | 2);
    try appendVarint(arena, out, b.len);
    try out.appendSlice(arena, b);
}
fn appendStr(arena: Allocator, out: *std.ArrayList(u8), field: u32, s: []const u8) Allocator.Error!void {
    if (s.len > 0) try appendLen(arena, out, field, s);
}

/// `ErrorInfo { reason 1, domain 2, metadata 3 }`; `metadata` must be sorted by key.
pub fn errorInfo(arena: Allocator, reason: []const u8, metadata: []const [2][]const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try appendStr(arena, &out, 1, reason);
    try appendStr(arena, &out, 2, domain);
    for (metadata, 0..) |kv, i| {
        if (i > 0) std.debug.assert(std.mem.order(u8, metadata[i - 1][0], kv[0]) == .lt);
        var e: std.ArrayList(u8) = .empty;
        try appendStr(arena, &e, 1, kv[0]);
        try appendStr(arena, &e, 2, kv[1]);
        try appendLen(arena, &out, 3, e.items);
    }
    return out.items;
}

pub const Any = struct { type_url: []const u8, value: []const u8 };

/// `google.rpc.Status { code 1, message 2, details 3 }` (the grpc-status-details-bin payload).
pub fn status(arena: Allocator, code: u32, message: []const u8, details: []const Any) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    if (code != 0) {
        try appendVarint(arena, &out, 1 << 3);
        try appendVarint(arena, &out, code);
    }
    try appendStr(arena, &out, 2, message);
    for (details) |d| {
        var a: std.ArrayList(u8) = .empty;
        try appendStr(arena, &a, 1, d.type_url);
        try appendStr(arena, &a, 2, d.value);
        try appendLen(arena, &out, 3, a.items);
    }
    return out.items;
}

/// The `ExecutionError` message of a failure as simulate's effects render it (before clever
/// errors): `ExecutionStatus { success 1, error 2 }`'s field 2.
pub fn executionError(arena: Allocator, f: types.ExecutionFailure) Allocator.Error![]const u8 {
    var size: usize = 4096;
    while (true) : (size *= 4) {
        const buf = try arena.alloc(u8, size);
        var w = proto.Writer.init(buf);
        serve.exec_error.writeStatus(arena, &w, 1, .{ .Failure = f }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => if (size < 1 << 26) continue else return error.OutOfMemory,
        };
        var r = proto.Reader.init(w.bytesWritten());
        const st = ((r.next() catch return &.{}) orelse return &.{}).data;
        var sr = proto.Reader.init(st);
        while (sr.next() catch return &.{}) |g| if (g.number == 2) return g.data;
        return &.{};
    }
}

/// `simulation_failure_error`'s details, given the rendered ExecutionError (`execution_error`).
pub fn simulationFailureDetails(arena: Allocator, message: []const u8, f: types.ExecutionFailure, execution_error: []const u8) Allocator.Error![]const u8 {
    const command = if (f.command) |c| try std.fmt.allocPrint(arena, "{d}", .{c}) else "";
    const info = try errorInfo(arena, "TRANSACTION_EXECUTION_FAILED", &.{ .{ "command", command }, .{ "kind", kindName(f.@"error") } });
    return status(arena, code_invalid_argument, message, &.{ .{ .type_url = type_url_error_info, .value = info }, .{ .type_url = type_url_execution_error, .value = execution_error } });
}

pub const InsufficientGas = struct { owner: [32]u8, required_budget: u64, coin_balance: u64, address_balance: u64 };

/// `InsufficientGasBalanceError` as an RpcError: message and details.
pub fn insufficientGas(arena: Allocator, g: InsufficientGas) Allocator.Error!struct { message: []const u8, details: []const u8 } {
    const owner = try hex0x(arena, &g.owner);
    const message = try std.fmt.allocPrint(arena, "Unable to perform gas selection due to insufficient SUI balance (in address balance or coins) for account {s} to satisfy required budget {d}.", .{ owner, g.required_budget });
    const info = try errorInfo(arena, "INSUFFICIENT_GAS_BALANCE", &.{
        .{ "addressBalance", try std.fmt.allocPrint(arena, "{d}", .{g.address_balance}) },
        .{ "coinBalance", try std.fmt.allocPrint(arena, "{d}", .{g.coin_balance}) },
        .{ "owner", owner },
        .{ "requiredBudget", try std.fmt.allocPrint(arena, "{d}", .{g.required_budget}) },
    });
    return .{ .message = message, .details = try status(arena, code_invalid_argument, message, &.{.{ .type_url = type_url_error_info, .value = info }}) };
}

test "ExecutionErrorKind Display matches sui-types for location forms and argument errors" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    var addr: [32]u8 = @splat(0);
    addr[31] = 2;
    const loc: types.MoveLocation = .{ .module = .{ .address = .{ .@"0" = addr }, .name = .{ .@"0" = "coin" } }, .function = 7, .instruction = 3, .function_name = null };
    try std.testing.expectEqualStrings(
        "Transaction fails in simulation: Move Runtime Abort. Location: 0000000000000000000000000000000000000000000000000000000000000002::coin in function definition 7 at offset 3, Abort Code: 1 in command 0",
        try simulationFailureMessage(al, .{ .@"error" = .{ .MoveAbort = .{ loc, 1 } }, .command = 0 }),
    );
    try std.testing.expectEqualStrings("Transaction fails in simulation: Insufficient coin balance for operation. in command 2", try simulationFailureMessage(al, .{ .@"error" = .InsufficientCoinBalance, .command = 2 }));
    try std.testing.expectEqualStrings("Transaction fails in simulation: Invalid command argument at 1. Out of bounds access to input or result vector 4 in command 0", try simulationFailureMessage(al, .{ .@"error" = .{ .CommandArgumentError = .{ .arg_idx = 1, .kind = .{ .IndexOutOfBounds = .{ .idx = 4 } } } }, .command = 0 }));
    try std.testing.expectEqualStrings("Move Primitive Runtime Error. Location: UNKNOWN. Arithmetic error, stack overflow, max value depth, etc.", try kindDisplay(al, .{ .MovePrimitiveRuntimeError = .{ .@"0" = null } }));
    try std.testing.expectEqualStrings("Transaction fails in simulation: Insufficient funds for funds accumulator withdrawal", try simulationFailureMessage(al, .{ .@"error" = .InsufficientFundsForWithdraw, .command = null }));
}

test "ErrorInfo details: TRANSACTION_EXECUTION_FAILED and INSUFFICIENT_GAS_BALANCE" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    const f: types.ExecutionFailure = .{ .@"error" = .InsufficientCoinBalance, .command = null };
    const ee = try executionError(al, f);
    // ExecutionError { description 1, kind 3 = INSUFFICIENT_COIN_BALANCE (8) }: no command field
    const want_ee = [_]u8{ 0x0a, 23 } ++ "InsufficientCoinBalance".* ++ [_]u8{ 0x18, 8 };
    try std.testing.expectEqualSlices(u8, &want_ee, ee);
    const st = try simulationFailureDetails(al, "m", f, ee);
    // Status { code 3, message "m", details [ErrorInfo { reason, domain, {command: "", kind} }, ExecutionError] }
    var r = proto.Reader.init(st);
    var n_details: usize = 0;
    while (try r.next()) |x| if (x.number == 3) {
        n_details += 1;
        var ar = proto.Reader.init(x.data);
        const url = (try ar.next()).?.data;
        const val = (try ar.next()).?.data;
        if (n_details == 1) {
            try std.testing.expectEqualStrings("/google.rpc.ErrorInfo", url);
            const want = "\x0a\x1cTRANSACTION_EXECUTION_FAILED\x12\x06sui.io\x1a\x09\x0a\x07command\x1a\x21\x0a\x04kind\x12\x19INSUFFICIENT_COIN_BALANCE";
            try std.testing.expectEqualSlices(u8, want, val);
        } else {
            try std.testing.expectEqualStrings("/sui.rpc.v2.ExecutionError", url);
            try std.testing.expectEqualSlices(u8, ee, val);
        }
    };
    try std.testing.expectEqual(@as(usize, 2), n_details);
    var owner: [32]u8 = @splat(0);
    owner[31] = 0xab;
    const ig = try insufficientGas(al, .{ .owner = owner, .required_budget = 5, .coin_balance = 3, .address_balance = 1 });
    try std.testing.expectEqualStrings("Unable to perform gas selection due to insufficient SUI balance (in address balance or coins) for account 0x00000000000000000000000000000000000000000000000000000000000000ab to satisfy required budget 5.", ig.message);
    try std.testing.expect(std.mem.indexOf(u8, ig.details, "\x0a\x0eaddressBalance\x12\x011") != null);
    try std.testing.expect(std.mem.indexOf(u8, ig.details, "INSUFFICIENT_GAS_BALANCE") != null);
}
