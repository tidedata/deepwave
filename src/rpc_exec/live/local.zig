//! Answers for transactions this node already has (sui-node `get_executed_effects` +
//! `build_response_from_local_effects`): effects and events from the store, input objects at
//! `modified_at_versions`, output objects at `all_changed_objects` (sui-types
//! `storage::get_transaction_{input,output}_objects`).
//!
//! Where sui-node answers TransactionDriverInternalError for an object its store lacks, deepwave falls
//! back to driving the transaction (the validators return the same effects), because deepwave's store
//! can lack an object version sui-node keeps (CONTRACTS 6.8 windows, a snapshot-started store).
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const drv = @import("../driver/driver.zig");
const handler = @import("../driver/handler.zig");

/// One object version, BCS `Object` (allocated in `arena` or valid for the request).
pub const ObjectSource = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, arena: Allocator, id: *const [32]u8, version: u64) ?[]const u8,
};

/// The orchestrator's local lookup. Null: not executed here (or not answerable): drive it.
pub const LocalEffects = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, arena: Allocator, req: *const handler.ExecuteRequest) ?drv.QuorumResponse,
};

/// `QuorumTransactionResponse` from stored effects. Null when an object is missing.
pub fn quorumFromEffects(arena: Allocator, effects_bcs: []const u8, events_bcs: ?[]const u8, req: *const handler.ExecuteRequest, objects: ObjectSource) Allocator.Error!?drv.QuorumResponse {
    const eff = bcs.decode(types.TransactionEffects, arena, effects_bcs) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    const v2 = switch (eff) {
        .V2 => |v| v,
        else => return null, // pre-V2 effects are years old; never re-submitted
    };
    var q: drv.QuorumResponse = .{
        .effects_digest = types.digest.effectsDigest(effects_bcs),
        .effects = effects_bcs,
        .events = if (req.include_events and v2.events_digest != null) events_bcs orelse return null else null,
        .input_objects = null,
        .output_objects = null,
        .source = 0,
    };
    if (req.include_input_objects) {
        var ins: std.ArrayList([]const u8) = .empty;
        for (v2.changed_objects) |c| switch (c.@"1".input_state) {
            .Exist => |x| try ins.append(arena, objects.get(objects.ctx, arena, &c.@"0".@"0".@"0", x.@"0".@"0".@"0") orelse return null),
            .NotExist => {},
        };
        q.input_objects = ins.items;
    }
    if (req.include_output_objects) {
        var outs: std.ArrayList([]const u8) = .empty;
        for (v2.changed_objects) |c| {
            const version: u64 = switch (c.@"1".output_state) {
                .ObjectWrite => v2.lamport_version.@"0",
                .PackageWrite => |p| p.@"0".@"0",
                else => continue,
            };
            try outs.append(arena, objects.get(objects.ctx, arena, &c.@"0".@"0".@"0", version) orelse return null);
        }
        q.output_objects = outs.items;
    }
    return q;
}

/// LocalEffects over the node's store (committed checkpoints only, like sui-node's executed set
/// on a fullnode: a transaction is "executed" once its checkpoint is).
pub const StoreLocal = struct {
    st: *store.Store,

    pub fn localEffects(self: *StoreLocal) LocalEffects {
        return .{ .ctx = self, .get = get };
    }

    fn get(ctx: *anyopaque, arena: Allocator, req: *const handler.ExecuteRequest) ?drv.QuorumResponse {
        const self: *StoreLocal = @ptrCast(@alignCast(ctx));
        var snap = self.st.snapshot();
        defer snap.release();
        const rec = snap.transaction(&req.digest) orelse return null;
        const effects = arena.dupe(u8, rec.effects) catch return null;
        const events = if (rec.events) |e| arena.dupe(u8, e) catch return null else null;
        const Src = struct {
            fn obj(c: *anyopaque, a: Allocator, id: *const [32]u8, version: u64) ?[]const u8 {
                const s: *store.Snapshot = @ptrCast(@alignCast(c));
                const b = s.objectAt(id, version) orelse return null;
                return a.dupe(u8, b) catch null;
            }
        };
        return quorumFromEffects(arena, effects, events, req, .{ .ctx = &snap, .get = Src.obj }) catch null;
    }
};
