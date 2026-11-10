//! The store-backed default Backend: answers ObjectInfo, TransactionInfo, Checkpoint(V2) and
//! GetSystemStateObject from the node's store exactly as `AuthorityState` answers them from its
//! stores (authority.rs `handle_object_info_request`, `handle_transaction_info_request`,
//! `handle_checkpoint_request(_v2)`, `get_sui_system_state_object_unsafe`), and forwards
//! SubmitTransaction and WaitForEffects to val-authority's `Authority`.
//!
//! Deliberate differences:
//!   - ObjectInfo with `LayoutGenerationOption::Generate` for a Move object answers
//!     UnsupportedFeatureError (no type layout resolver is wired into the validator yet);
//!   - CheckpointV2 with `certified = false` answers `checkpoint: None` unless a `PendingSource`
//!     (val-checkpoints' locally computed summaries) is attached.
const std = @import("std");
const store = @import("store");
const serve = @import("serve");
const types = @import("types");
const sysstate = serve.sysstate;
const rpcindex = serve.rpcindex;
const backend = @import("backend.zig");
const wire = @import("wire.zig");
const signer_mod = @import("../signer.zig");
const Result = backend.Result;

/// val-checkpoints' locally computed (not yet certified) checkpoint summaries.
pub const PendingSource = struct {
    ctx: *anyopaque,
    /// BCS CheckpointSummary of `seq` (null: the latest) and BCS CheckpointContents.
    get: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, seq: ?u64) ?struct { summary: []const u8, contents: ?[]const u8 },
};

pub const NodeBackend = struct {
    /// The node store; null serves the validator API without read data (every read answers UnsupportedFeatureError).
    store: ?*store.Store = null,
    authority: ?backend.Authority = null,
    signer: ?*signer_mod.Signer = null,
    pending: ?PendingSource = null,
    /// Current epoch (the epoch of the effects signatures), kept by the epoch manager.
    epoch: *const std.atomic.Value(u64),

    pub fn asBackend(n: *NodeBackend) backend.Backend {
        return .{ .ctx = n, .vt = &vtable };
    }

    fn self(ctx: *anyopaque) *NodeBackend {
        return @ptrCast(@alignCast(ctx));
    }

    fn submit(ctx: *anyopaque, arena: std.mem.Allocator, req: backend.SubmitRequest) Result([]const wire.driver_wire.RawSubmitResult) {
        const n = self(ctx);
        const a = n.authority orelse return .{ .err = backend.unsupported("validator authority is not attached") };
        return a.submit(a.ctx, arena, req);
    }

    fn waitForEffects(ctx: *anyopaque, arena: std.mem.Allocator, req: backend.WaitRequest) Result(wire.driver_wire.RawWaitResponse) {
        const n = self(ctx);
        const a = n.authority orelse return .{ .err = backend.unsupported("validator authority is not attached") };
        return a.wait_for_effects(a.ctx, arena, req);
    }

    fn objectInfo(ctx: *anyopaque, arena: std.mem.Allocator, req: wire.ObjectInfoRequest) Result([]const u8) {
        const n = self(ctx);
        const st = n.store orelse return .{ .err = backend.unsupported("no node store attached to this validator") };
        var snap = st.snapshot();
        defer snap.release();
        const version: u64 = req.version orelse blk: {
            const l = snap.latest(&req.object_id) catch return .{ .err = backend.storageError("object store read failed") };
            const lo = l orelse return .{ .err = backend.objectNotFound(&req.object_id, null) };
            break :blk switch (lo) {
                .live => |o| o.version,
                .removed => |r| r.version,
            };
        };
        const bytes = snap.objectAt(&req.object_id, version) orelse return .{ .err = backend.objectNotFound(&req.object_id, version) };
        if (req.generate_layout and sysstate.moveContents(bytes) != null) {
            return .{ .err = backend.unsupported("object layout generation is not available on this validator") };
        }
        const body = wire.objectInfoResponse(arena, bytes) catch return .{ .err = backend.storageError("out of memory") };
        return .{ .ok = body };
    }

    fn transactionInfo(ctx: *anyopaque, arena: std.mem.Allocator, digest: *const [32]u8) Result([]const u8) {
        const n = self(ctx);
        const missing: backend.SuiErrorKind = .{ .TransactionNotFound = .{ .digest = .{ .@"0" = .{ .@"0" = digest.* } } } };
        const st = n.store orelse return .{ .err = backend.unsupported("no node store attached to this validator") };
        var snap = st.snapshot();
        defer snap.release();
        const rec = snap.transaction(digest) orelse return .{ .err = missing };
        const sg = n.signer orelse return .{ .err = backend.unsupported("validator signer is not attached") };
        const epoch = n.epoch.load(.acquire);
        const sig = sg.signEffects(epoch, rec.effects, arena) catch return .{ .err = backend.storageError("effects signing failed") };
        const keys = sg.publicKeys() catch return .{ .err = backend.storageError("signer keys unavailable") };
        const body = wire.transactionInfoExecuted(arena, rec.tx, rec.effects, epoch, &keys.authority, &sig, rec.events) catch return .{ .err = backend.storageError("out of memory") };
        return .{ .ok = body };
    }

    fn checkpoint(ctx: *anyopaque, arena: std.mem.Allocator, q: backend.CheckpointQuery, v2: bool) Result([]const u8) {
        const n = self(ctx);
        const oom = backend.storageError("out of memory");
        if (v2 and !q.certified) {
            const p = n.pending orelse return .{ .ok = wire.checkpointResponseV2(arena, null, null) catch return .{ .err = oom } };
            const got = p.get(p.ctx, arena, q.sequence_number) orelse return .{ .ok = wire.checkpointResponseV2(arena, null, null) catch return .{ .err = oom } };
            const body = wire.checkpointResponseV2(arena, .{ .kind = .pending, .bcs = got.summary }, if (q.request_content) got.contents else got.contents) catch return .{ .err = oom };
            return .{ .ok = body };
        }
        const st = n.store orelse return .{ .err = backend.unsupported("no node store attached to this validator") };
        var snap = st.snapshot();
        defer snap.release();
        const seq: u64 = q.sequence_number orelse (snap.highestCommitted() orelse {
            return .{ .ok = (if (v2) wire.checkpointResponseV2(arena, null, null) else wire.checkpointResponse(arena, null, null)) catch return .{ .err = oom } };
        });
        const rec = snap.checkpoint(seq) orelse {
            return .{ .ok = (if (v2) wire.checkpointResponseV2(arena, null, null) else wire.checkpointResponse(arena, null, null)) catch return .{ .err = oom } };
        };
        // Rust returns the contents whenever the summary exists (the request flag is not read by
        // handle_checkpoint_request).
        const body = (if (v2)
            wire.checkpointResponseV2(arena, .{ .kind = .certified, .bcs = rec.summary_cert }, rec.contents)
        else
            wire.checkpointResponse(arena, rec.summary_cert, rec.contents)) catch return .{ .err = oom };
        return .{ .ok = body };
    }

    fn systemState(ctx: *anyopaque, arena: std.mem.Allocator) Result([]const u8) {
        const n = self(ctx);
        const store_ptr = n.store orelse return .{ .err = backend.unsupported("no node store attached to this validator") };
        var snap = store_ptr.snapshot();
        defer snap.release();
        const st = rpcindex.liveState(&snap) orelse return .{ .err = backend.storageError("system state object not found") };
        const body = wire.systemStateResponse(arena, st.version, st.inner) catch return .{ .err = backend.storageError("unsupported system state version") };
        return .{ .ok = body };
    }

    fn health(ctx: *anyopaque) wire.Health {
        const n = self(ctx);
        var h: wire.Health = if (n.authority) |a| a.health(a.ctx) else .{};
        if (h.checkpoint_sequence == 0 and n.store != null) {
            var snap = n.store.?.snapshot();
            defer snap.release();
            h.checkpoint_sequence = snap.highestCommitted() orelse 0;
        }
        return h;
    }

    const vtable: backend.Backend.VTable = .{
        .submit = submit,
        .wait_for_effects = waitForEffects,
        .object_info = objectInfo,
        .transaction_info = transactionInfo,
        .checkpoint = checkpoint,
        .system_state = systemState,
        .health = health,
    };
};
