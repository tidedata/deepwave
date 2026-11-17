//! Signing-time package verification (sui-execution `Verifier::meter_module_bytes` and
//! sui-adapter `run_metered_move_bytecode_verifier`, 1.83.1): run the Move and Sui verifiers on
//! every module of a package with one `SuiVerifierMeter` that the caller shares across the
//! transaction's packages, and fail only on a timeout. A module that does not deserialize, or
//! fails verification for any other reason, passes.
//!
//! The answer is `SuiError`'s Display, the text `UserInputError::PackageVerificationTimeout`
//! carries (sui-transaction-checks `check_non_system_packages_to_be_published`).
const std = @import("std");
const ff = @import("../file_format.zig");
const deserializer = @import("../deserializer.zig");
const c = @import("common.zig");
const sui = @import("sui.zig");
const verify = @import("verify.zig");

const Allocator = std.mem.Allocator;

/// sui-config `VerifierSigningConfig::default()`: meter units per function, module and package.
pub const MeterLimits = struct {
    max_per_fun_meter_units: u128 = 2_200_000,
    max_per_mod_meter_units: u128 = 2_200_000,
    max_per_pkg_meter_units: u128 = 2_200_000,
};

/// `SuiVerifierMeter::new(meter_config_for_signing())`.
pub fn meter(l: MeterLimits) c.Meter {
    return .{ .kind = .sui, .max_fun = l.max_per_fun_meter_units, .max_mod = l.max_per_mod_meter_units, .max_pkg = l.max_per_pkg_meter_units };
}

/// `meter_module_bytes` for one package. `cfg` is `verifier_config(Some(limits_for_signing()))`,
/// `bcfg` is `binary_config(Some(true))`. Returns null (pass) or the `SuiError` Display.
pub fn meterModuleBytes(arena: Allocator, scratch: *std.heap.ArenaAllocator, cfg: *const c.Config, bcfg: *const deserializer.BinaryConfig, module_bytes: []const []const u8, m: *c.Meter) Allocator.Error!?[]const u8 {
    const mods = try arena.alloc(ff.CompiledModule, module_bytes.len);
    for (module_bytes, mods) |b, *out| switch (try deserializer.deserialize(arena, b, bcfg)) {
        .ok => |cm| out.* = cm,
        // not a timeout
        .err => return null,
    };
    for (mods) |*cm| for (cm.identifiers) |id| if (std.mem.eql(u8, id, "<SELF>"))
        return "Error checking transaction input objects: Invalid identifier found in the transaction: invalid identifier: <SELF>";
    for (mods) |*cm| if (try verifyModuleTimeoutOnly(arena, scratch, cfg, cm, m)) |e| return e;
    return null;
}

/// sui-adapter `verify_module_timeout_only`.
fn verifyModuleTimeoutOnly(arena: Allocator, scratch: *std.heap.ArenaAllocator, cfg: *const c.Config, cm: *const ff.CompiledModule, m: *c.Meter) Allocator.Error!?[]const u8 {
    const name = cm.identifiers[cm.module_handles[cm.self_module_handle_idx].name];
    m.enterScope(.Module);
    m.mod_name = name;
    const r = try verify.verifyModuleMetered(arena, scratch, cfg, cm, null, m);
    if (r.move) |e| {
        if (sui.isVerifierTimeout(e.err.major)) {
            const loc: c.ErrLoc = switch (e.loc) {
                .module => .{ .module = .{ .addr = &cm.address_identifiers[cm.module_handles[cm.self_module_handle_idx].address], .name = name } },
                else => .undefined,
            };
            const msg = if (e.err.major == .PROGRAM_TOO_COMPLEX) try m.tripMessage(arena) else null;
            return try std.fmt.allocPrint(arena, "Failed to verify the Move module, reason: Verification timed out: {s}.", .{try c.vmErrorDisplay(arena, e.err, loc, msg)});
        }
    } else if (r.sui) |e| if (e.kind == .SuiMoveVerificationTimedout) {
        // SuiError::from(ExecutionError): "Error executing {ExecutionError Display}"
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "Error executing ExecutionError: ExecutionError { inner: ExecutionErrorInner { kind: SuiMoveVerificationTimedout, source: Some(");
        try rustDebugStr(arena, &out, e.msg);
        try out.appendSlice(arena, "), command: None } }");
        return out.items;
    };
    var ctx: c.Ctx = .{};
    m.transfer(&ctx, .Module, .Package, 1.0) catch return "Failed to verify the Move module, reason: Verification timed out.";
    return null;
}

/// Rust `<str as Debug>` for the ASCII text verifier messages hold.
fn rustDebugStr(arena: Allocator, out: *std.ArrayList(u8), s: []const u8) Allocator.Error!void {
    try out.append(arena, '"');
    for (s) |ch| switch (ch) {
        '"' => try out.appendSlice(arena, "\\\""),
        '\\' => try out.appendSlice(arena, "\\\\"),
        '\n' => try out.appendSlice(arena, "\\n"),
        '\r' => try out.appendSlice(arena, "\\r"),
        '\t' => try out.appendSlice(arena, "\\t"),
        0 => try out.appendSlice(arena, "\\0"),
        else => try out.append(arena, ch),
    };
    try out.append(arena, '"');
}

test {
    std.testing.refAllDecls(@This());
}
