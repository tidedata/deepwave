//! consensus: Mysticeti consensus core for the deepwave validator, equal to Mysten's consensus-core
//! at mainnet-v1.83.1 (docs/VALIDATOR-DESIGN.md). Sans-I/O: types, verification, DAG state,
//! commit rule, linearizer, fast-path finalization, storage. The network and threads live in
//! the `consensus_net` module. Owner lane: val-consensus-core. Built only behind the validator
//! build wiring; deepwave never imports it.
const std = @import("std");

pub const types = @import("types.zig");
pub const committee = @import("committee.zig");
pub const config = @import("config.zig");
pub const iface = @import("iface.zig");
pub const errors = @import("error.zig");
pub const digest = @import("digest.zig");
pub const context = @import("context.zig");
pub const verifier = @import("verifier.zig");
pub const store = @import("store.zig");
pub const rand = @import("rand.zig");
pub const leader_scoring = @import("leader_scoring.zig");
pub const dag_state = @import("dag_state.zig");
pub const block_manager = @import("block_manager.zig");
pub const threshold_clock = @import("threshold_clock.zig");
pub const leader_schedule = @import("leader_schedule.zig");
pub const committer = @import("committer.zig");
pub const linearizer = @import("linearizer.zig");
pub const transaction_vote_tracker = @import("transaction_vote_tracker.zig");
pub const commit_finalizer = @import("commit_finalizer.zig");
pub const ancestor = @import("ancestor.zig");
pub const core = @import("core.zig");
pub const test_dag = @import("test_dag.zig");
pub const sim = @import("sim.zig");
pub const conformance = @import("conformance.zig");

pub const Block = types.Block;
pub const SignedBlock = types.SignedBlock;
pub const VerifiedBlock = types.VerifiedBlock;
pub const BlockRef = types.BlockRef;
pub const Commit = types.Commit;
pub const CommittedSubDag = types.CommittedSubDag;
pub const Committee = committee.Committee;
pub const Context = context.Context;
pub const Core = core.Core;

test {
    // Unit tests of every file (a file's `test` blocks run only when the file is referenced here).
    inline for (.{ "types", "committee", "config", "iface", "digest", "verifier", "store", "rand", "leader_scoring", "dag_state", "block_manager", "threshold_clock", "leader_schedule", "committer", "linearizer", "transaction_vote_tracker", "commit_finalizer", "ancestor", "core", "test_dag", "sim", "conformance" }) |name| {
        _ = @field(@This(), name);
        std.testing.refAllDecls(@field(@This(), name));
    }
    std.testing.refAllDecls(@This());
    refDeep(@This(), 4, &.{});
}

/// Skeleton check: references every pub declaration, recursing into nested container types, so
/// the compiler analyzes every stub body (std.testing.refAllDecls stops at the first level).
fn refDeep(comptime T: type, comptime depth: u32, comptime skip: []const []const u8) void {
    inline for (comptime std.meta.declarations(T)) |name| {
        comptime var skipped = false;
        inline for (skip) |s| {
            if (comptime std.mem.eql(u8, s, name)) skipped = true;
        }
        if (skipped) continue;
        const F = @TypeOf(@field(T, name));
        if (F == type) {
            const V = @field(T, name);
            switch (@typeInfo(V)) {
                .@"struct", .@"union", .@"enum", .@"opaque" => if (depth > 0) refDeep(V, depth - 1, skip),
                else => {},
            }
        } else {
            _ = &@field(T, name);
        }
    }
}

