//! sui-transaction-checks `check_non_system_packages_to_be_published` (1.83.1, PARITY.md G19):
//! before signing, meter the Move and Sui verifiers over every module that the transaction's
//! Publish and Upgrade commands carry, with one `SuiVerifierMeter` and the signing limits of
//! `VerifierSigningConfig::default()`. Only a timeout rejects:
//! `UserInputError::PackageVerificationTimeout`.
const std = @import("std");
const types = @import("types");
const protocol = @import("protocol");
const mf = @import("move_format");
const checks = @import("checks.zig");

const signing = mf.verifier.signing;
const Allocator = std.mem.Allocator;

/// `VerifierSigningConfig::default().limits_for_signing()`.
pub const signing_limits: protocol.derived.SigningLimits = .{
    .max_back_edges_per_function = 10_000,
    .max_back_edges_per_module = 10_000,
    .sanity_check_with_regex_reference_safety = 2_200_000,
};

pub fn check(arena: Allocator, cfg: *const protocol.ProtocolConfig, td: *const types.TransactionDataV1) checks.Error!?checks.Fail {
    const pt = checks.ptbOf(td) orelse return null;
    var any = false;
    for (pt.commands) |*cmd| switch (cmd.*) {
        .Publish, .Upgrade => any = true,
        else => {},
    };
    if (!any) return null;

    const v = try protocol.derived.verifierConfig(cfg, signing_limits);
    var vcfg: mf.verifier.verify.Config = .{};
    inline for (@typeInfo(@TypeOf(v)).@"struct".field_names) |f| @field(vcfg, f) = @field(v, f);
    const b = try protocol.derived.binaryConfig(cfg, true);
    var bcfg: mf.BinaryConfig = .{
        .max_binary_format_version = b.max_binary_format_version,
        .min_binary_format_version = b.min_binary_format_version,
        .check_no_extraneous_bytes = b.check_no_extraneous_bytes,
        .deprecate_global_storage_ops = b.deprecate_global_storage_ops,
        .type_parameter_index_max = b.type_parameter_index_max,
        .table_config = undefined,
    };
    inline for (@typeInfo(@TypeOf(b.table_config)).@"struct".field_names) |f| @field(bcfg.table_config, f) = @field(b.table_config, f);

    var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();
    var meter = signing.meter(.{});
    for (pt.commands) |*cmd| {
        const mods = switch (cmd.*) {
            .Publish => |p| p[0],
            .Upgrade => |u| u[0],
            else => continue,
        };
        if (try signing.meterModuleBytes(arena, &scratch, &vcfg, &bcfg, mods, &meter)) |err|
            return try checks.userInput(arena, "Package verification failed: {s}", .{err});
    }
    return null;
}

test {
    std.testing.refAllDecls(@This());
}
