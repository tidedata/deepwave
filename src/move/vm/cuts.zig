//! exec-history-vm (CONTRACTS 6.6b.2): the Move VM rules that differ by execution cut.
//!
//! Mysten keeps one Move VM per execution version (`external-crates/move/historical-versions/
//! v0..v3`, run by `sui-execution/historical-versions/vN`). deepwave keeps one VM and selects the old
//! behaviour with the flags below. Gas-model differences (sizes, instruction costs, native
//! threshold) follow the gas model version in `gas.zig` and need no flag here; protocol feature
//! flags that only some cuts read are folded in by `of`.
const std = @import("std");
const protocol = @import("protocol");

pub const LATEST: u64 = 4;

pub const Rules = struct {
    /// The cut's execution version (mainnet: 0 below protocol 18, 1 from 18, 2 from 31, 3 from
    /// 38, 4 from 119).
    execution_version: u64 = LATEST,
    /// Type layouts count nodes the old way (v0..v2, v3 before `variant_nodes`, protocol 72):
    /// `host.Limits.legacy`.
    legacy_layout_count: bool = false,

    pub const latest: Rules = .{};

    pub fn of(cfg: *const protocol.ProtocolConfig) Rules {
        const ev = cfg.execution_version orelse 0;
        return .{
            .execution_version = ev,
            .legacy_layout_count = ev < LATEST and (ev < 3 or !cfg.feature_flags.variant_nodes),
        };
    }

    /// The VM of execution versions 0 to 3 (`move-vm-runtime-vN`, the old loader/interpreter).
    pub fn legacyVm(r: Rules) bool {
        return r.execution_version < LATEST;
    }
};

test "rules by protocol version" {
    try std.testing.expect((Rules.of(try protocol.get(118, .mainnet))).legacyVm());
    try std.testing.expect(!(Rules.of(try protocol.get(119, .mainnet))).legacyVm());
}
