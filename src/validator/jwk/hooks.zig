//! `iface.JwkHooks` over the `Aggregator`: what the consensus handler (val-authority) calls for
//! each sequenced NewJWKFetched. The handler has already checked that the transaction's authority
//! equals the block author and `check_total_jwk_size` (`SequencedConsensusTransaction` checks); `vote`
//! applies `record_jwk_vote` and tells the handler whether the JWK just became active (it then
//! schedules the AuthenticatorStateUpdate one commit later via `state_update.forCommit`).
//! The adapter holds the commit's `Batch`; `takeBatch` hands it to the epoch store.
const std = @import("std");
const types = @import("types");
const iface = @import("../iface.zig");
const aggregator = @import("aggregator.zig");
const log = std.log.scoped(.jwk);

pub const Adapter = struct {
    gpa: std.mem.Allocator,
    agg: *aggregator.Aggregator,
    batch: aggregator.Batch,

    pub fn init(gpa: std.mem.Allocator, agg: *aggregator.Aggregator) Adapter {
        return .{ .gpa = gpa, .agg = agg, .batch = aggregator.Batch.init(gpa) };
    }

    pub fn deinit(a: *Adapter) void {
        a.batch.deinit();
    }

    pub fn hooks(a: *Adapter) iface.JwkHooks {
        return .{ .ctx = a, .vtable = &vtable };
    }

    pub fn takeBatch(a: *Adapter) aggregator.Batch {
        const b = a.batch;
        a.batch = aggregator.Batch.init(a.gpa);
        return b;
    }

    fn vote(ctx: *anyopaque, from: *const iface.AuthorityName, id: *const types.JwkId, jwk: *const types.JWK, round: u64) bool {
        const a: *Adapter = @ptrCast(@alignCast(ctx));
        if (!aggregator.checkTotalJwkSize(id.*, jwk.*)) return false;
        const out = a.agg.recordVote(&a.batch, round, &from.@"0", id.*, jwk.*) catch |e| {
            log.err("jwk vote failed: {s}", .{@errorName(e)});
            return false;
        };
        return out == .became_active;
    }

    const vtable: iface.JwkHooks.VTable = .{ .vote = vote };
};
