//! `ExecutionStatus` / `ExecutionError` messages (rpc_proto_conversions.rs 1184-1570), including
//! the Rust derived-Debug text used for `description`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types");
const base58 = @import("b58.zig");
const proto = @import("proto.zig");
const ro = @import("render_object.zig");
const typestr = @import("typestr.zig");
const mf = @import("move_format");

const Writer = proto.Writer;
pub const Error = ro.Error;

/// `clever_error` on a MoveAbort (clever.zig): the service installs a resolver for the duration
/// of a request (it needs the store); null renders MoveAbort without it.
pub const CleverHook = struct {
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, w: *Writer, field: u32, package: *const [32]u8, module: []const u8, abort_code: u64) proto.Error!void,
};
pub threadlocal var clever_hook: ?CleverHook = null;
/// Package lookup for `clever_error` (sui-rpc-api render.rs `render_clever_error`): the module
/// `module` of the object stored at `pkg` (`reader.get_object(package_id)`, the live version,
/// read as a package with `Package::read_from_object`); null when the object is missing, is not
/// a package, cannot be read or has no such module. The service installs one; without it no
/// `clever_error` is written (as a node whose store lacks the package).
pub const CleverResolver = struct {
    ctx: *anyopaque,
    module: *const fn (ctx: *anyopaque, arena: Allocator, pkg: *const [32]u8, module: []const u8) ?*const mf.file_format.CompiledModule,
};

/// `ErrorBitset` (move-command-line-common error_bitset.rs): msb0 packing of version (4 bits),
/// reserved (4), error_code (u8), line_number (u16), identifier_index (u16), constant_index (u16).
pub const ErrorBitset = struct {
    version: u4,
    error_code: u8,
    line_number: u16,
    identifier_index: u16,
    constant_index: u16,

    const version_0: u4 = 0b1000;
    const version_1: u4 = 0b1100;

    pub fn fromU64(bits: u64) ?ErrorBitset {
        const b: ErrorBitset = .{
            .version = @truncate(bits >> 60),
            .error_code = @truncate(bits >> 48),
            .line_number = @truncate(bits >> 32),
            .identifier_index = @truncate(bits >> 16),
            .constant_index = @truncate(bits),
        };
        return if (b.version == version_0 or b.version == version_1) b else null;
    }
    pub fn errorCode(b: ErrorBitset) ?u8 {
        if (b.version == version_0) return null;
        return if (b.error_code == std.math.maxInt(u8)) null else b.error_code;
    }
    fn u16Sentinel(v: u16) ?u16 {
        return if (v == std.math.maxInt(u16)) null else v;
    }
    pub fn lineNumber(b: ErrorBitset) ?u16 {
        return u16Sentinel(b.line_number);
    }
    pub fn identifierIndex(b: ErrorBitset) ?u16 {
        return u16Sentinel(b.identifier_index);
    }
    pub fn constantIndex(b: ErrorBitset) ?u16 {
        return u16Sentinel(b.constant_index);
    }
};

pub const Clever = struct {
    error_code: ?u8,
    line_number: u16,
    constant_name: ?[]const u8 = null,
    value: union(enum) { none, rendered: []const u8, raw: []const u8 } = .none,
};

/// BCS `Vec<u8>` that consumes all of `data` (bcs::from_bytes is strict).
fn bcsVecU8(data: []const u8) ?[]const u8 {
    var len: u64 = 0;
    var shift: u6 = 0;
    var i: usize = 0;
    while (true) {
        if (i >= data.len or i >= 10) return null;
        const b = data[i];
        i += 1;
        len |= @as(u64, b & 0x7f) << shift;
        if (b < 0x80) {
            // ULEB128 must be canonical and fit in u32.
            if (b == 0 and i > 1) return null;
            break;
        }
        shift += 7;
        if (shift > 28) return null;
    }
    if (len > std.math.maxInt(u32)) return null;
    if (data.len - i != len) return null;
    return data[i..];
}

fn bcsUint(comptime T: type, data: []const u8) ?T {
    if (data.len != @sizeOf(T)) return null;
    return std.mem.readInt(T, data[0..@sizeOf(T)], .little);
}

/// `try_render_constant` (move-command-line-common display.rs): null = NotRendered.
pub fn renderConstant(arena: Allocator, c: mf.file_format.Constant) Allocator.Error!?[]const u8 {
    if (c.type_.len == 0) return null;
    const d = c.data;
    return switch (c.type_[0].tag) {
        .Vector => blk: {
            if (c.type_.len != 2 or c.type_[1].tag != .U8) break :blk null;
            const v = bcsVecU8(d) orelse break :blk null;
            if (!std.unicode.utf8ValidateSlice(v)) break :blk null;
            break :blk v;
        },
        .U8 => if (bcsUint(u8, d)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .U16 => if (bcsUint(u16, d)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .U32 => if (bcsUint(u32, d)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .U64 => if (bcsUint(u64, d)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .U128 => if (bcsUint(u128, d)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .U256 => if (bcsUint(u256, d)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .Address => if (d.len == 32) try addr0x(arena, d[0..32]) else null,
        .Bool => if (d.len == 1 and d[0] <= 1) (if (d[0] == 1) "true" else "false") else null,
        else => null,
    };
}

/// `Package::resolve_clever_error` on one module.
pub fn resolveClever(arena: Allocator, cm: *const mf.file_format.CompiledModule, abort_code: u64) Allocator.Error!?Clever {
    const b = ErrorBitset.fromU64(abort_code) orelse return null;
    const line = b.lineNumber() orelse return null;
    var out: Clever = .{ .error_code = b.errorCode(), .line_number = line };
    const ii = b.identifierIndex();
    const ci = b.constantIndex();
    if (ii == null and ci == null) return out;
    if (ii == null or ci == null) return null;
    const pool = cm.constant_pool;
    if (ii.? >= pool.len or ci.? >= pool.len) return null;
    const ident_c = pool[ii.?];
    if (!(ident_c.type_.len == 2 and ident_c.type_[0].tag == .Vector and ident_c.type_[1].tag == .U8)) return null;
    const ident = bcsVecU8(ident_c.data) orelse return null;
    if (!std.unicode.utf8ValidateSlice(ident)) return null;
    out.constant_name = ident;
    const val = pool[ci.?];
    out.value = if (try renderConstant(arena, val)) |r| .{ .rendered = r } else .{ .raw = val.data };
    return out;
}

/// The `CleverError` message at `field`.
pub fn writeClever(w: *Writer, field: u32, c: Clever) Error!void {
    const m = try w.begin(field, 64);
    if (c.error_code) |e| try w.uint(1, e);
    try w.uint(2, c.line_number);
    if (c.constant_name) |n| try w.string(3, n);
    switch (c.value) {
        .none => {},
        .rendered => |r| try w.string(5, r),
        .raw => |r| try w.bytes(6, r),
    }
    try w.end(m);
}

fn hex32(arena: Allocator, a: *const [32]u8) ![]const u8 {
    const hex = "0123456789abcdef";
    const out = try arena.alloc(u8, 64);
    for (a, 0..) |b, i| {
        out[2 * i] = hex[b >> 4];
        out[2 * i + 1] = hex[b & 15];
    }
    return out;
}

/// "0x" + 64 hex (`to_canonical_string(true)`, and the `Debug` of ObjectID / SuiAddress).
fn addr0x(arena: Allocator, a: *const [32]u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "0x{s}", .{try hex32(arena, a)});
}

/// Rust `{:?}` of a str.
fn dbgStr(arena: Allocator, s: []const u8) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    try out.append(arena, '"');
    var view = std.unicode.Utf8View.initUnchecked(s);
    var it = view.iterator();
    while (it.nextCodepoint()) |c| switch (c) {
        '"' => try out.appendSlice(arena, "\\\""),
        '\\' => try out.appendSlice(arena, "\\\\"),
        '\n' => try out.appendSlice(arena, "\\n"),
        '\r' => try out.appendSlice(arena, "\\r"),
        '\t' => try out.appendSlice(arena, "\\t"),
        0 => try out.appendSlice(arena, "\\0"),
        else => if (c < 0x20 or c == 0x7f) {
            try out.print(arena, "\\u{{{x}}}", .{c});
        } else {
            var b: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(c, &b) catch unreachable;
            try out.appendSlice(arena, b[0..n]);
        },
    };
    try out.append(arena, '"');
    return out.items;
}

fn dbgLocation(arena: Allocator, l: types.MoveLocation) ![]const u8 {
    const fname = if (l.function_name) |f| try std.fmt.allocPrint(arena, "Some({s})", .{try dbgStr(arena, f.@"0")}) else "None";
    return std.fmt.allocPrint(arena, "MoveLocation {{ module: ModuleId {{ address: {s}, name: Identifier({s}) }}, function: {d}, instruction: {d}, function_name: {s} }}", .{
        try hex32(arena, &l.module.address.@"0"), try dbgStr(arena, l.module.name.@"0"), l.function, l.instruction, fname,
    });
}

fn dbgCommandArg(arena: Allocator, k: types.CommandArgumentError) ![]const u8 {
    return switch (k) {
        .IndexOutOfBounds => |v| std.fmt.allocPrint(arena, "IndexOutOfBounds {{ idx: {d} }}", .{v.idx}),
        .SecondaryIndexOutOfBounds => |v| std.fmt.allocPrint(arena, "SecondaryIndexOutOfBounds {{ result_idx: {d}, secondary_idx: {d} }}", .{ v.result_idx, v.secondary_idx }),
        .InvalidResultArity => |v| std.fmt.allocPrint(arena, "InvalidResultArity {{ result_idx: {d} }}", .{v.result_idx}),
        else => @tagName(k),
    };
}

fn dbgUpgrade(arena: Allocator, e: types.PackageUpgradeError) ![]const u8 {
    return switch (e) {
        .UnableToFetchPackage => |v| std.fmt.allocPrint(arena, "UnableToFetchPackage {{ package_id: {s} }}", .{try addr0x(arena, &v.package_id.@"0".@"0")}),
        .NotAPackage => |v| std.fmt.allocPrint(arena, "NotAPackage {{ object_id: {s} }}", .{try addr0x(arena, &v.object_id.@"0".@"0")}),
        .IncompatibleUpgrade => "IncompatibleUpgrade",
        .DigestDoesNotMatch => |v| blk: {
            var out = std.ArrayList(u8).empty;
            try out.appendSlice(arena, "DigestDoesNotMatch { digest: [");
            for (v.digest, 0..) |b, i| {
                if (i > 0) try out.appendSlice(arena, ", ");
                try out.print(arena, "{d}", .{b});
            }
            try out.appendSlice(arena, "] }");
            break :blk out.items;
        },
        .UnknownUpgradePolicy => |v| std.fmt.allocPrint(arena, "UnknownUpgradePolicy {{ policy: {d} }}", .{v.policy}),
        .PackageIDDoesNotMatch => |v| std.fmt.allocPrint(arena, "PackageIDDoesNotMatch {{ package_id: {s}, ticket_id: {s} }}", .{ try addr0x(arena, &v.package_id.@"0".@"0"), try addr0x(arena, &v.ticket_id.@"0".@"0") }),
    };
}

/// Rust `{:?}` of `ExecutionErrorKind`.
pub fn debugKind(arena: Allocator, k: types.ExecutionErrorKind) ![]const u8 {
    return switch (k) {
        .MoveObjectTooBig => |v| std.fmt.allocPrint(arena, "MoveObjectTooBig {{ object_size: {d}, max_object_size: {d} }}", .{ v.object_size, v.max_object_size }),
        .MovePackageTooBig => |v| std.fmt.allocPrint(arena, "MovePackageTooBig {{ object_size: {d}, max_object_size: {d} }}", .{ v.object_size, v.max_object_size }),
        .CircularObjectOwnership => |v| std.fmt.allocPrint(arena, "CircularObjectOwnership {{ object: {s} }}", .{try addr0x(arena, &v.object.@"0".@"0")}),
        .MovePrimitiveRuntimeError => |v| if (v.@"0") |l|
            std.fmt.allocPrint(arena, "MovePrimitiveRuntimeError(MoveLocationOpt(Some({s})))", .{try dbgLocation(arena, l)})
        else
            "MovePrimitiveRuntimeError(MoveLocationOpt(None))",
        .MoveAbort => |v| std.fmt.allocPrint(arena, "MoveAbort({s}, {d})", .{ try dbgLocation(arena, v.@"0"), v.@"1" }),
        .CommandArgumentError => |v| std.fmt.allocPrint(arena, "CommandArgumentError {{ arg_idx: {d}, kind: {s} }}", .{ v.arg_idx, try dbgCommandArg(arena, v.kind) }),
        .TypeArgumentError => |v| std.fmt.allocPrint(arena, "TypeArgumentError {{ argument_idx: {d}, kind: {s} }}", .{ v.argument_idx, @tagName(v.kind) }),
        .UnusedValueWithoutDrop => |v| std.fmt.allocPrint(arena, "UnusedValueWithoutDrop {{ result_idx: {d}, secondary_idx: {d} }}", .{ v.result_idx, v.secondary_idx }),
        .InvalidPublicFunctionReturnType => |v| std.fmt.allocPrint(arena, "InvalidPublicFunctionReturnType {{ idx: {d} }}", .{v.idx}),
        .EffectsTooLarge => |v| std.fmt.allocPrint(arena, "EffectsTooLarge {{ current_size: {d}, max_size: {d} }}", .{ v.current_size, v.max_size }),
        .PackageUpgradeError => |v| std.fmt.allocPrint(arena, "PackageUpgradeError {{ upgrade_error: {s} }}", .{try dbgUpgrade(arena, v.upgrade_error)}),
        .WrittenObjectsTooLarge => |v| std.fmt.allocPrint(arena, "WrittenObjectsTooLarge {{ current_size: {d}, max_size: {d} }}", .{ v.current_size, v.max_size }),
        .ExecutionCancelledDueToSharedObjectCongestion => |v| blk: {
            var out = std.ArrayList(u8).empty;
            try out.appendSlice(arena, "ExecutionCancelledDueToSharedObjectCongestion { congested_objects: CongestedObjects([");
            for (v.congested_objects.@"0", 0..) |o, i| {
                if (i > 0) try out.appendSlice(arena, ", ");
                try out.appendSlice(arena, try addr0x(arena, &o.@"0".@"0"));
            }
            try out.appendSlice(arena, "]) }");
            break :blk out.items;
        },
        .AddressDeniedForCoin => |v| std.fmt.allocPrint(arena, "AddressDeniedForCoin {{ address: {s}, coin_type: {s} }}", .{ try addr0x(arena, &v.address.@"0"), try dbgStr(arena, v.coin_type.@"0") }),
        .CoinTypeGlobalPause => |v| std.fmt.allocPrint(arena, "CoinTypeGlobalPause {{ coin_type: {s} }}", .{try dbgStr(arena, v.coin_type.@"0")}),
        .MoveVectorElemTooBig => |v| std.fmt.allocPrint(arena, "MoveVectorElemTooBig {{ value_size: {d}, max_scaled_size: {d} }}", .{ v.value_size, v.max_scaled_size }),
        .MoveRawValueTooBig => |v| std.fmt.allocPrint(arena, "MoveRawValueTooBig {{ value_size: {d}, max_scaled_size: {d} }}", .{ v.value_size, v.max_scaled_size }),
        .NonExclusiveWriteInputObjectModified => |v| std.fmt.allocPrint(arena, "NonExclusiveWriteInputObjectModified {{ id: {s} }}", .{try addr0x(arena, &v.id.@"0".@"0")}),
        else => @tagName(k),
    };
}

fn kindNumber(k: types.ExecutionErrorKind) u64 {
    return switch (k) {
        .InsufficientGas => 1,
        .InvalidGasObject => 2,
        .InvariantViolation => 3,
        .FeatureNotYetSupported => 4,
        .MoveObjectTooBig => 5,
        .MovePackageTooBig => 6,
        .CircularObjectOwnership => 7,
        .InsufficientCoinBalance => 8,
        .CoinBalanceOverflow => 9,
        .PublishErrorNonZeroAddress => 10,
        .SuiMoveVerificationError => 11,
        .MovePrimitiveRuntimeError => 12,
        .MoveAbort => 13,
        .VMVerificationOrDeserializationError => 14,
        .VMInvariantViolation => 15,
        .FunctionNotFound => 16,
        .ArityMismatch => 17,
        .TypeArityMismatch => 18,
        .NonEntryFunctionInvoked => 19,
        .CommandArgumentError => 20,
        .TypeArgumentError => 21,
        .UnusedValueWithoutDrop => 22,
        .InvalidPublicFunctionReturnType => 23,
        .InvalidTransferObject => 24,
        .EffectsTooLarge => 25,
        .PublishUpgradeMissingDependency => 26,
        .PublishUpgradeDependencyDowngrade => 27,
        .PackageUpgradeError => 28,
        .WrittenObjectsTooLarge => 29,
        .CertificateDenied => 30,
        .SuiMoveVerificationTimedout => 31,
        .SharedObjectOperationNotAllowed => 32,
        .InputObjectDeleted => 33,
        .ExecutionCancelledDueToSharedObjectCongestion => 34,
        .AddressDeniedForCoin => 35,
        .CoinTypeGlobalPause => 36,
        .ExecutionCancelledDueToRandomnessUnavailable => 37,
        .MoveVectorElemTooBig => 38,
        .MoveRawValueTooBig => 39,
        .InvalidLinkage => 40,
        .InsufficientFundsForWithdraw => 41,
        .NonExclusiveWriteInputObjectModified => 42,
    };
}

fn sizeError(w: *Writer, field: u32, size: u64, max: u64) Error!void {
    const m = try w.begin(field, 20);
    try w.uint(1, size);
    try w.uint(2, max);
    try w.end(m);
}

fn indexError(w: *Writer, field: u32, index: u16, sub: ?u16) Error!void {
    const m = try w.begin(field, 12);
    try w.uint(1, index);
    if (sub) |s| try w.uint(2, s);
    try w.end(m);
}

fn moveLocation(w: *Writer, field: u32, l: types.MoveLocation) Error!void {
    const m = try w.begin(field, 160);
    try ro.addrStr(w, 1, &l.module.address.@"0");
    try w.string(2, l.module.name.@"0");
    try w.uint(3, l.function);
    try w.uint(4, l.instruction);
    if (l.function_name) |f| try w.string(5, f.@"0");
    try w.end(m);
}

fn commandArgError(w: *Writer, field: u32, arg: u16, k: types.CommandArgumentError) Error!void {
    const m = try w.begin(field, 40);
    try w.uint(1, arg);
    try w.uint(2, switch (k) {
        .TypeMismatch => 1,
        .InvalidBCSBytes => 2,
        .InvalidUsageOfPureArg => 3,
        .InvalidArgumentToPrivateEntryFunction => 4,
        .IndexOutOfBounds => 5,
        .SecondaryIndexOutOfBounds => 6,
        .InvalidResultArity => 7,
        .InvalidGasCoinUsage => 8,
        .InvalidValueUsage => 9,
        .InvalidObjectByValue => 10,
        .InvalidObjectByMutRef => 11,
        .SharedObjectOperationNotAllowed => 12,
        .InvalidArgumentArity => 13,
        .InvalidTransferObject => 14,
        .InvalidMakeMoveVecNonObjectArgument => 15,
        .ArgumentWithoutValue => 16,
        .CannotMoveBorrowedValue => 17,
        .CannotWriteToExtendedReference => 18,
        .InvalidReferenceArgument => 19,
        .InvalidTxContext => 20,
    });
    switch (k) {
        .IndexOutOfBounds => |v| try indexError(w, 3, v.idx, null),
        .SecondaryIndexOutOfBounds => |v| try indexError(w, 3, v.result_idx, v.secondary_idx),
        .InvalidResultArity => |v| try indexError(w, 3, v.result_idx, null),
        else => {},
    }
    try w.end(m);
}

fn upgradeError(w: *Writer, field: u32, e: types.PackageUpgradeError) Error!void {
    const m = try w.begin(field, 160);
    switch (e) {
        .UnableToFetchPackage => |v| {
            try w.uint(1, 1);
            try ro.addrStr(w, 2, &v.package_id.@"0".@"0");
        },
        .NotAPackage => |v| {
            try w.uint(1, 2);
            try ro.addrStr(w, 2, &v.object_id.@"0".@"0");
        },
        .IncompatibleUpgrade => try w.uint(1, 3),
        .DigestDoesNotMatch => |v| {
            try w.uint(1, 4);
            if (v.digest.len == 32) try ro.str32(w, 3, v.digest[0..32]);
        },
        .UnknownUpgradePolicy => |v| {
            try w.uint(1, 5);
            try w.uint(4, v.policy);
        },
        .PackageIDDoesNotMatch => |v| {
            try w.uint(1, 6);
            try ro.addrStr(w, 2, &v.package_id.@"0".@"0");
            try ro.addrStr(w, 5, &v.ticket_id.@"0".@"0");
        },
    }
    try w.end(m);
}

/// `ExecutionStatus` message at `field`.
pub fn writeStatus(arena: Allocator, w: *Writer, field: u32, s: types.ExecutionStatus) Error!void {
    return writeStatusClever(arena, w, field, s, null);
}

/// `ExecutionStatus` message at `field`, with `clever_error` on a MoveAbort when `clever` finds
/// the aborting module (`annotate_effects` -> `render_clever_error`).
pub fn writeStatusClever(arena: Allocator, w: *Writer, field: u32, s: types.ExecutionStatus, clever: ?CleverResolver) Error!void {
    const m = try w.begin(field, 256);
    switch (s) {
        .Success => try w.uint(1, 1),
        .Failure => |f| {
            try w.uint(1, 0);
            const em = try w.begin(2, 256);
            const dbg = try debugKind(arena, f.@"error");
            const desc = if (f.command) |c| try std.fmt.allocPrint(arena, "{s} in command {d}", .{ dbg, c }) else dbg;
            try w.string(1, desc);
            if (f.command) |c| try w.uint(2, c);
            try w.uint(3, kindNumber(f.@"error"));
            switch (f.@"error") {
                .MoveObjectTooBig => |v| try sizeError(w, 5, v.object_size, v.max_object_size),
                .MovePackageTooBig => |v| try sizeError(w, 5, v.object_size, v.max_object_size),
                .EffectsTooLarge => |v| try sizeError(w, 5, v.current_size, v.max_size),
                .WrittenObjectsTooLarge => |v| try sizeError(w, 5, v.current_size, v.max_size),
                .MoveVectorElemTooBig => |v| try sizeError(w, 5, v.value_size, v.max_scaled_size),
                .MoveRawValueTooBig => |v| try sizeError(w, 5, v.value_size, v.max_scaled_size),
                .CircularObjectOwnership => |v| try ro.addrStr(w, 10, &v.object.@"0".@"0"),
                .NonExclusiveWriteInputObjectModified => |v| try ro.addrStr(w, 10, &v.id.@"0".@"0"),
                .MovePrimitiveRuntimeError => |v| if (v.@"0") |l| {
                    const am = try w.begin(4, 180);
                    try moveLocation(w, 2, l);
                    try w.end(am);
                },
                .MoveAbort => |v| {
                    const am = try w.begin(4, 180);
                    try w.uint(1, v.@"1");
                    try moveLocation(w, 2, v.@"0");
                    if (clever) |cr| {
                        const loc = v.@"0";
                        if (cr.module(cr.ctx, arena, &loc.module.address.@"0", loc.module.name.@"0")) |cm| {
                            if (try resolveClever(arena, cm, v.@"1")) |c| try writeClever(w, 3, c);
                        }
                    } else if (clever_hook) |h| try h.write(h.ctx, w, 3, &v.@"0".module.address.@"0", v.@"0".module.name.@"0", v.@"1");
                    try w.end(am);
                },
                .CommandArgumentError => |v| try commandArgError(w, 6, v.arg_idx, v.kind),
                .TypeArgumentError => |v| {
                    const tm = try w.begin(7, 12);
                    try w.uint(1, v.argument_idx);
                    try w.uint(2, switch (v.kind) {
                        .TypeNotFound => 1,
                        .ConstraintNotSatisfied => 2,
                    });
                    try w.end(tm);
                },
                .PackageUpgradeError => |v| try upgradeError(w, 8, v.upgrade_error),
                .UnusedValueWithoutDrop => |v| try indexError(w, 9, v.result_idx, v.secondary_idx),
                .InvalidPublicFunctionReturnType => |v| try indexError(w, 9, v.idx, null),
                .AddressDeniedForCoin => |v| {
                    const cm = try w.begin(11, 160);
                    try ro.addrStr(w, 1, &v.address.@"0");
                    try w.string(2, v.coin_type.@"0");
                    try w.end(cm);
                },
                .CoinTypeGlobalPause => |v| {
                    const cm = try w.begin(11, 100);
                    try w.string(2, v.coin_type.@"0");
                    try w.end(cm);
                },
                .ExecutionCancelledDueToSharedObjectCongestion => |v| {
                    const cm = try w.begin(12, 100);
                    for (v.congested_objects.@"0") |o| try ro.addrStr(w, 1, &o.@"0".@"0");
                    try w.end(cm);
                },
                else => {},
            }
            try w.end(em);
        },
    }
    try w.end(m);
}

test "clever error: bitset and constant rendering (error_bitset.rs, display.rs)" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ff = mf.file_format;
    const vec_u8 = [_]ff.Node{ .{ .tag = .Vector }, .{ .tag = .U8 } };
    const u64_t = [_]ff.Node{.{ .tag = .U64 }};
    const addr_t = [_]ff.Node{.{ .tag = .Address }};
    const bool_t = [_]ff.Node{.{ .tag = .Bool }};
    const vec_u64 = [_]ff.Node{ .{ .tag = .Vector }, .{ .tag = .U64 } };
    var addr: [32]u8 = @splat(0);
    addr[31] = 2;
    const pool = [_]ff.Constant{
        .{ .type_ = &vec_u8, .data = "\x0aEBadAmount" }, // 0: identifier
        .{ .type_ = &u64_t, .data = &.{ 7, 0, 0, 0, 0, 0, 0, 0 } }, // 1
        .{ .type_ = &vec_u8, .data = "\x05hello" }, // 2: string
        .{ .type_ = &vec_u8, .data = "\x02\xff\xfe" }, // 3: not utf-8 -> raw
        .{ .type_ = &addr_t, .data = &addr }, // 4
        .{ .type_ = &bool_t, .data = &.{1} }, // 5
        .{ .type_ = &vec_u64, .data = &.{0} }, // 6: vector<u64> -> raw
        .{ .type_ = &u64_t, .data = &.{ 7, 0 } }, // 7: short -> raw
    };
    const cm: ff.CompiledModule = .{ .version = 6, .constant_pool = &pool };
    const code = struct {
        fn f(version: u64, ec: u64, line: u64, ii: u64, ci: u64) u64 {
            return version << 60 | ec << 48 | line << 32 | ii << 16 | ci;
        }
    }.f;
    // not a clever code
    try t.expect((try resolveClever(arena, &cm, 13906834363567390719 & 0x0fff_ffff_ffff_ffff)) == null);
    // line only (identifier and constant unavailable), version 1 with error code
    {
        const c = (try resolveClever(arena, &cm, code(0b1100, 4, 988, 0xffff, 0xffff))).?;
        try t.expectEqual(@as(?u8, 4), c.error_code);
        try t.expectEqual(@as(u16, 988), c.line_number);
        try t.expect(c.constant_name == null and c.value == .none);
    }
    // version 0 never has an error code
    try t.expectEqual(@as(?u8, null), (try resolveClever(arena, &cm, code(0b1000, 4, 1, 0xffff, 0xffff))).?.error_code);
    // only one of the indexes: None
    try t.expect((try resolveClever(arena, &cm, code(0b1100, 0xff, 1, 0, 0xffff))) == null);
    // unknown line: None
    try t.expect((try resolveClever(arena, &cm, code(0b1100, 0xff, 0xffff, 0xffff, 0xffff))) == null);
    const expect = struct {
        fn f(a: Allocator, m: *const ff.CompiledModule, bits: u64, kind: enum { rendered, raw }, want: []const u8) !void {
            const c = (try resolveClever(a, m, bits)).?;
            try std.testing.expectEqualStrings("EBadAmount", c.constant_name.?);
            switch (kind) {
                .rendered => try std.testing.expectEqualStrings(want, c.value.rendered),
                .raw => try std.testing.expectEqualSlices(u8, want, c.value.raw),
            }
        }
    }.f;
    try expect(arena, &cm, code(0b1100, 0xff, 10, 0, 1), .rendered, "7");
    try expect(arena, &cm, code(0b1100, 0xff, 10, 0, 2), .rendered, "hello");
    try expect(arena, &cm, code(0b1100, 0xff, 10, 0, 3), .raw, "\x02\xff\xfe");
    try expect(arena, &cm, code(0b1100, 0xff, 10, 0, 4), .rendered, "0x0000000000000000000000000000000000000000000000000000000000000002");
    try expect(arena, &cm, code(0b1100, 0xff, 10, 0, 5), .rendered, "true");
    try expect(arena, &cm, code(0b1100, 0xff, 10, 0, 6), .raw, &.{0});
    try expect(arena, &cm, code(0b1100, 0xff, 10, 0, 7), .raw, &.{ 7, 0 });
    // identifier constant that is not vector<u8>: None; index out of the pool: None
    try t.expect((try resolveClever(arena, &cm, code(0b1100, 0xff, 10, 1, 1))) == null);
    try t.expect((try resolveClever(arena, &cm, code(0b1100, 0xff, 10, 0, 99))) == null);
    // wire form
    var buf: [128]u8 = undefined;
    var w = Writer.init(&buf);
    try writeClever(&w, 3, .{ .error_code = null, .line_number = 988, .constant_name = "E", .value = .{ .rendered = "!8f" } });
    try t.expectEqualSlices(u8, &.{ 0x1a, 0x0b, 0x10, 0xdc, 0x07, 0x1a, 0x01, 'E', 0x2a, 0x03, '!', '8', 'f' }, w.bytesWritten());
}

test "clever error on mainnet packages, equal to sui-node 1.83.1 (vectors/clever)" {
    const t = std.testing;
    const movepkg = @import("movepkg.zig");
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Case = struct { raw: []const u8, module: []const u8, code: u64, ec: ?u8, line: u16, name: []const u8, rendered: []const u8 };
    // Checkpoint 342947620 tx H6RMMUja.. (pool::repay_flashloan) and 342947761 tx 13
    // (play_coin::debit_escrow_account): sui-node's clever_error for each.
    const cases = [_]Case{
        .{ .raw = @embedFile("vectors/clever/pkg-54f7d3ba.bcs"), .module = "pool", .code = 13836747978885234704, .ec = 6, .line = 250, .name = "EInsufficientRepayment", .rendered = "repayment is smaller than principal" },
        .{ .raw = @embedFile("vectors/clever/pkg-d3a9ec94.bcs"), .module = "play_coin", .code = 13906838417772314644, .ec = null, .line = 988, .name = "EInsufficientEscrowAccount", .rendered = "!8f" },
    };
    for (cases) |c| {
        var pkg: movepkg.Package = undefined;
        try movepkg.read(arena, c.raw, &pkg);
        var cm: ?*const mf.file_format.CompiledModule = null;
        for (pkg.mods) |*m| if (std.mem.eql(u8, m.name, c.module)) {
            cm = &m.cm;
        };
        const got = (try resolveClever(arena, cm.?, c.code)).?;
        try t.expectEqual(c.ec, got.error_code);
        try t.expectEqual(c.line, got.line_number);
        try t.expectEqualStrings(c.name, got.constant_name.?);
        try t.expectEqualStrings(c.rendered, got.value.rendered);
    }
}
