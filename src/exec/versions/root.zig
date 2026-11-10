//! exec-history (CONTRACTS 6.6b): Move-call PTBs on the execution versions before the latest.
//!
//! Mysten keeps one cut per execution version (`sui-execution/historical-versions/v0..v3`, each
//! with its own adapter, Move VM and natives). deepwave keeps one executor and one VM and expresses
//! each older cut as the deltas from `latest`: this file says which executor and which deltas a
//! protocol config selects. Mainnet: execution version 0 below protocol 18, 1 from 18, 2 from 31,
//! 3 from 38, 4 (latest) from 119. Execution version 3 runs the static PTB executor when
//! `enable_ptb_execution_v2` is on (mainnet protocol 104 to 118), the dynamic one before.
const std = @import("std");
const protocol = @import("protocol");
const move_vm = @import("move_vm");

pub const latest: u64 = 4;

/// Which PTB executor a cut runs.
pub const Executor = enum {
    /// `static_programmable_transactions` (exec-move's `ptb/`).
    static,
    /// `programmable_transactions` (the dynamic executor of v0 to v3).
    dynamic,
};

/// The cut a protocol config selects, as the exec-history slice name.
pub const Cut = enum {
    v0,
    v1,
    v2,
    v3_dynamic,
    v3_static,
    v4,

    /// Words, not digits: exec-replay's skip tally folds digits.
    pub fn label(c: Cut) []const u8 {
        return switch (c) {
            .v0 => "zero",
            .v1 => "one",
            .v2 => "two",
            .v3_dynamic => "three (dynamic PTB executor)",
            .v3_static => "three (static PTB executor)",
            .v4 => "four",
        };
    }
};

pub fn executionVersion(cfg: *const protocol.ProtocolConfig) u64 {
    return cfg.execution_version orelse 0;
}

pub fn cutOf(cfg: *const protocol.ProtocolConfig) Cut {
    return switch (executionVersion(cfg)) {
        0 => .v0,
        1 => .v1,
        2 => .v2,
        3 => if (cfg.feature_flags.enable_ptb_execution_v2) .v3_static else .v3_dynamic,
        else => .v4,
    };
}

pub fn executorOf(cfg: *const protocol.ProtocolConfig) Executor {
    return switch (cutOf(cfg)) {
        .v3_static, .v4 => .static,
        else => .dynamic,
    };
}

/// The cuts whose Move-call PTBs deepwave runs. A cut joins this set once exec-replay reproduces
/// its whole slice with no failure.
pub fn moveSupported(cfg: *const protocol.ProtocolConfig) bool {
    return switch (cutOf(cfg)) {
        .v4, .v3_static, .v3_dynamic, .v2, .v1, .v0 => true,
    };
}

/// `charge_gas`: v3 and later bucketize computation with `Some(is_move_abort)`, v0..v2 with
/// `None` (no aborted-transaction price cap).
pub fn abortAwareBucketing(cfg: *const protocol.ProtocolConfig) bool {
    return executionVersion(cfg) >= 3;
}

/// The VM limits the cut's adapter passes to its Move VM (`new_move_vm` / `vm_config`). The
/// historical cuts read the same protocol fields as latest.
pub fn execConfig(cfg: *const protocol.ProtocolConfig) error{ProtocolConfigMissing}!move_vm.ExecConfig {
    return move_vm.ExecConfig.fromProtocolAnyCut(cfg); // exec-history-vm: limits plus the cut's VM rules
}

test "cuts by mainnet protocol version" {
    const expect = std.testing.expectEqual;
    try expect(Cut.v0, cutOf(try protocol.get(17, .mainnet)));
    try expect(Cut.v1, cutOf(try protocol.get(18, .mainnet)));
    try expect(Cut.v2, cutOf(try protocol.get(31, .mainnet)));
    try expect(Cut.v3_dynamic, cutOf(try protocol.get(38, .mainnet)));
    try expect(Cut.v3_dynamic, cutOf(try protocol.get(103, .mainnet)));
    try expect(Cut.v3_static, cutOf(try protocol.get(104, .mainnet)));
    try expect(Cut.v3_static, cutOf(try protocol.get(118, .mainnet)));
    try expect(Cut.v4, cutOf(try protocol.get(119, .mainnet)));
}

/// The native table of a cut over the latest natives. Frameworks before execution version 4
/// declare `type_name::get` and `get_with_original_ids` native; the v0 to v3 natives bind them
/// to what the latest natives call `with_defining_ids` and `with_original_ids`.
pub fn nativeTable(arena: std.mem.Allocator, cfg: *const protocol.ProtocolConfig, latest_table: move_vm.NativeTable) std.mem.Allocator.Error!*const move_vm.NativeTable {
    const t = try arena.create(move_vm.NativeTable);
    if (executionVersion(cfg) >= latest) {
        t.* = latest_table;
        return t;
    }
    const inner = try arena.create(move_vm.NativeTable);
    inner.* = latest_table;
    t.* = .{ .ctx = inner, .lookupFn = legacyLookup };
    return t;
}

fn legacyLookup(ctx: ?*const anyopaque, address: *const [32]u8, module: []const u8, func: []const u8) ?move_vm.Native {
    const inner: *const move_vm.NativeTable = @ptrCast(@alignCast(ctx.?));
    const one: [32]u8 = @as([31]u8, @splat(0)) ++ [1]u8{1};
    if (std.mem.eql(u8, address, &one) and std.mem.eql(u8, module, "type_name")) {
        if (std.mem.eql(u8, func, "get")) return inner.lookup(address, module, "with_defining_ids");
        if (std.mem.eql(u8, func, "get_with_original_ids")) return inner.lookup(address, module, "with_original_ids");
    }
    return inner.lookup(address, module, func);
}
