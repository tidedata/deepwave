//! The real executor for `exec_bridge.Bridge`: runs a consensus-ordered user transaction with
//! deepwave's PTB engine (`rpc_exec.simulate.run`, the engine the node simulates with) against an
//! object store, reading every shared input at the version consensus assigned, and commits the
//! written objects back. A transaction cancelled by consensus (congestion, DKG failure) and
//! system transactions are not run here yet (`error.Unsupported`:
//! they go through exec.ccp / exec.system and the node's
//! effects-for-cancelled-transactions path once wired).
//!
//! `ObjectStore` is the seam to the node store: reads at exact versions and the latest, and
//! `commit` of what an execution wrote. `MemObjectStore` serves the local committee harness and
//! the tests.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const exec = @import("exec");
const rpc_exec = @import("rpc_exec");
const exec_bridge = @import("exec_bridge.zig");
const versions = @import("versions.zig");

const Allocator = std.mem.Allocator;
pub const Id = [32]u8;
const ObjectView = exec.objects.ObjectView;

pub const ObjectStore = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        at: *const fn (ctx: *anyopaque, id: *const Id, version: u64) ?[]const u8,
        latest: *const fn (ctx: *anyopaque, id: *const Id) ?[]const u8,
        /// Makes an execution's written objects visible (raw BCS Objects, new versions).
        commit: *const fn (ctx: *anyopaque, written: []const exec.coin_ptb.Written) Allocator.Error!void,
    };
};

/// Objects keyed by (id, version) plus the latest version per id.
pub const MemObjectStore = struct {
    gpa: Allocator,
    by_version: std.AutoHashMapUnmanaged([40]u8, []const u8) = .empty,
    latest_v: std.AutoHashMapUnmanaged(Id, u64) = .empty,

    pub fn deinit(m: *MemObjectStore) void {
        var it = m.by_version.valueIterator();
        while (it.next()) |v| m.gpa.free(v.*);
        m.by_version.deinit(m.gpa);
        m.latest_v.deinit(m.gpa);
    }

    fn key(id: Id, v: u64) [40]u8 {
        var k: [40]u8 = undefined;
        k[0..32].* = id;
        std.mem.writeInt(u64, k[32..40], v, .little);
        return k;
    }

    /// Adds a raw BCS Object.
    pub fn put(m: *MemObjectStore, raw: []const u8) !void {
        const v = try ObjectView.parse(raw);
        const copy = try m.gpa.dupe(u8, raw);
        errdefer m.gpa.free(copy);
        const gop = try m.by_version.getOrPut(m.gpa, key(v.id, v.version));
        if (gop.found_existing) m.gpa.free(gop.value_ptr.*);
        gop.value_ptr.* = copy;
        const lv = try m.latest_v.getOrPut(m.gpa, v.id);
        if (!lv.found_existing or lv.value_ptr.* < v.version) lv.value_ptr.* = v.version;
    }

    fn at(ctx: *anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const m: *MemObjectStore = @ptrCast(@alignCast(ctx));
        return m.by_version.get(key(id.*, version));
    }
    fn latest(ctx: *anyopaque, id: *const Id) ?[]const u8 {
        const m: *MemObjectStore = @ptrCast(@alignCast(ctx));
        const v = m.latest_v.get(id.*) orelse return null;
        return m.by_version.get(key(id.*, v));
    }
    fn commit(ctx: *anyopaque, written: []const exec.coin_ptb.Written) Allocator.Error!void {
        const m: *MemObjectStore = @ptrCast(@alignCast(ctx));
        for (written) |w| m.put(w.bytes) catch return error.OutOfMemory;
    }
    const vt: ObjectStore.VTable = .{ .at = at, .latest = latest, .commit = commit };
    pub fn store(m: *MemObjectStore) ObjectStore {
        return .{ .ctx = m, .vtable = &vt };
    }
};

/// A `rpc_exec.State` that answers shared inputs at their assigned versions and everything else
/// from the store's latest.
const AssignedState = struct {
    store: ObjectStore,
    shared: []const versions.SharedVersion,

    fn assignedFor(s: *const AssignedState, id: *const Id) ?u64 {
        for (s.shared) |x| if (std.mem.eql(u8, &x.id, id) and !versions.isCancelled(x.version)) return x.version;
        return null;
    }
    fn latestFn(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
        const s: *const AssignedState = @ptrCast(@alignCast(ctx));
        if (s.assignedFor(id)) |v| return s.store.vtable.at(s.store.ctx, id, v);
        return s.store.vtable.latest(s.store.ctx, id);
    }
    fn atFn(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const s: *const AssignedState = @ptrCast(@alignCast(ctx));
        return s.store.vtable.at(s.store.ctx, id, version);
    }
    fn childFn(ctx: *const anyopaque, id: *const Id, upper: u64) ?[]const u8 {
        const s: *const AssignedState = @ptrCast(@alignCast(ctx));
        const raw = s.store.vtable.latest(s.store.ctx, id) orelse return null;
        const v = ObjectView.parse(raw) catch return null;
        return if (v.version <= upper) raw else null;
    }
    const vt: rpc_exec.state.State.VTable = .{ .latest = latestFn, .at = atFn, .child_at_most = childFn };
    fn state(s: *const AssignedState) rpc_exec.State {
        return .{ .ctx = s, .vtable = &vt };
    }
};

pub const SimRunner = struct {
    gpa: Allocator,
    engine: *const rpc_exec.simulate.Engine,
    env: *const rpc_exec.EpochEnv,
    store: ObjectStore,
    executed: u64 = 0,
    failed: u64 = 0,
    /// The last execution failure (`simulate` reported `fail`/`unimplemented`), for diagnostics.
    last_error: [160]u8 = undefined,
    last_error_len: usize = 0,

    fn cast(ctx: *anyopaque) *SimRunner {
        return @ptrCast(@alignCast(ctx));
    }

    fn ready(ctx: *anyopaque, item: *const exec_bridge.Item) bool {
        const r = cast(ctx);
        for (item.owned) |o| if (r.store.vtable.at(r.store.ctx, &o.id, o.version) == null) return false;
        for (item.shared) |s| {
            if (versions.isCancelled(s.version)) continue;
            if (r.store.vtable.at(r.store.ctx, &s.id, s.version) == null) {
                // a shared object nobody created yet at its initial version is not ready either
                return false;
            }
        }
        return true;
    }

    fn run(ctx: *anyopaque, arena: Allocator, item: *const exec_bridge.Item) exec_bridge.RunError!exec_bridge.Outcome {
        const r = cast(ctx);
        if (item.kind != .user) return error.Unsupported;
        for (item.shared) |s| if (versions.isCancelled(s.version)) return error.Unsupported;
        const td_bcs = item.td_bcs orelse return error.Failed;
        const td_all = bcs.decode(types.TransactionData, arena, td_bcs) catch return error.Failed;
        const td = switch (td_all) {
            .V1 => |v| v,
        };
        const st: AssignedState = .{ .store = r.store, .shared = item.shared };
        const res = rpc_exec.simulate.run(r.engine, arena, r.env, st.state(), td_bcs, td, false, false) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                r.noteError(@errorName(e));
                return error.Failed;
            },
        };
        switch (res) {
            .ok => |sim| {
                r.store.vtable.commit(r.store.ctx, sim.written) catch return error.OutOfMemory;
                r.executed += 1;
                return .{
                    .effects_digest = hash.blake2b256(&.{ "TransactionEffects::", sim.effects }),
                    .effects_bcs = sim.effects,
                };
            },
            .fail => |f| {
                r.noteError(f.message);
                r.failed += 1;
                return error.Failed;
            },
            .unimplemented => |why| {
                r.noteError(why);
                return error.Unsupported;
            },
        }
    }

    fn noteError(r: *SimRunner, msg: []const u8) void {
        const n = @min(msg.len, r.last_error.len);
        @memcpy(r.last_error[0..n], msg[0..n]);
        r.last_error_len = n;
    }

    pub fn lastError(r: *const SimRunner) []const u8 {
        return r.last_error[0..r.last_error_len];
    }

    const vt: exec_bridge.Runner.VTable = .{ .ready = ready, .run = run };

    pub fn runner(r: *SimRunner) exec_bridge.Runner {
        return .{ .ctx = r, .vtable = &vt };
    }
};

test "mem object store answers by version and latest" {
    // an object with a trivial layout cannot be fabricated without a real Object BCS; cover the
    // key function and the empty store path only (full execution is covered by the conformance suite).
    var m: MemObjectStore = .{ .gpa = std.testing.allocator };
    defer m.deinit();
    const id: Id = @splat(3);
    try std.testing.expect(MemObjectStore.at(&m, &id, 1) == null);
    try std.testing.expect(MemObjectStore.latest(&m, &id) == null);
    try std.testing.expect(!std.mem.eql(u8, &MemObjectStore.key(id, 1), &MemObjectStore.key(id, 2)));
}
