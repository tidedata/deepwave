//! The execution side of the validator (docs/VALIDATOR-DESIGN 5.3 `exec_bridge`): receives what
//! the consensus handler schedules (a transaction or system transaction plus its assigned shared
//! versions), runs it with deepwave's executor once its inputs exist, and remembers the effects digest
//! so `WaitForEffects` can answer. Execution order follows input availability, not arrival order,
//! as sui-core's execution scheduler does: a transaction waits until every owned input version
//! and every assigned shared version is in the object store; independent transactions overtake it.
//!
//! The executor itself is a `Runner` vtable. `SimRunner` is the real implementation over
//! `rpc_exec.simulate.run` (the same PTB engine the node simulates with) reading shared inputs at
//! the versions consensus assigned; system transactions (consensus commit prologue, authenticator
//! update, randomness, settlement) go through `exec.ccp`/`exec.system`, wired by the integration
//! (the runner reports `error.Unsupported` for them until then).
const std = @import("std");
const iface = @import("../iface.zig");
const types = @import("types");
const versions = @import("versions.zig");
const tx_mod = @import("tx.zig");
const Spin = @import("sync.zig").Spin;

const Allocator = std.mem.Allocator;
pub const Id = tx_mod.Id;
pub const Key = versions.Assignable.Key;

pub const ItemKind = enum { user, consensus_commit_prologue, authenticator_state_update, randomness_state_update, accumulator_settlement };

pub const Item = struct {
    key: Key,
    kind: ItemKind,
    /// BCS TransactionData (null for randomness and settlement: built at execution time from
    /// the round / checkpoint height, as Rust's scheduler does).
    td_bcs: ?[]const u8,
    /// Transaction digest when known.
    digest: ?Id,
    shared: []const versions.SharedVersion,
    system: []const versions.SystemVersion,
    /// Non-shared inputs (owned and receiving) that must exist at exactly this version.
    owned: []const tx_mod.ObjRef = &.{},
};

pub const Outcome = struct {
    effects_digest: Id,
    /// BCS TransactionEffects (kept for serving WaitForEffects full effects; may be empty).
    effects_bcs: []const u8 = &.{},
};

pub const RunError = error{ Unsupported, Failed, OutOfMemory };

pub const Runner = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        /// True when every input of `item` exists at the required version.
        ready: *const fn (ctx: *anyopaque, item: *const Item) bool,
        run: *const fn (ctx: *anyopaque, arena: Allocator, item: *const Item) RunError!Outcome,
    };
};

const Owned = struct { arena: std.heap.ArenaAllocator, item: Item };

pub const Bridge = struct {
    gpa: Allocator,
    runner: Runner,
    queue: std.ArrayList(*Owned) = .empty,
    /// Guards `done` (API threads read it while the handler thread executes).
    done_lock: Spin = .{},
    done: std.AutoHashMapUnmanaged(Id, Id) = .empty,
    /// Called on the executing thread after an item ran (the handler records an ack for it).
    on_done: ?struct { ctx: *anyopaque, f: *const fn (ctx: *anyopaque, key: Key) void } = null,
    /// Items the runner could not execute (reported; kept out of the queue).
    unsupported: u64 = 0,
    executed: u64 = 0,
    max_queue: usize = 1 << 20,

    pub fn init(gpa: Allocator, runner: Runner) Bridge {
        return .{ .gpa = gpa, .runner = runner };
    }

    pub fn deinit(b: *Bridge) void {
        for (b.queue.items) |o| {
            o.arena.deinit();
            b.gpa.destroy(o);
        }
        b.queue.deinit(b.gpa);
        b.done.deinit(b.gpa);
    }

    /// Copies `item` into the queue.
    pub fn enqueue(b: *Bridge, item: Item) error{ Full, OutOfMemory }!void {
        if (b.queue.items.len >= b.max_queue) return error.Full;
        const o = try b.gpa.create(Owned);
        errdefer b.gpa.destroy(o);
        o.arena = .init(b.gpa);
        errdefer o.arena.deinit();
        const a = o.arena.allocator();
        o.item = .{
            .key = item.key,
            .kind = item.kind,
            .td_bcs = if (item.td_bcs) |t| try a.dupe(u8, t) else null,
            .digest = item.digest,
            .shared = try a.dupe(versions.SharedVersion, item.shared),
            .system = try a.dupe(versions.SystemVersion, item.system),
            .owned = try a.dupe(tx_mod.ObjRef, item.owned),
        };
        try b.queue.append(b.gpa, o);
    }

    /// Runs every ready item once, in queue order; returns how many executed. A transaction that
    /// became ready because an earlier one in this pass wrote its input runs in the same pass.
    pub fn pump(b: *Bridge, scratch: Allocator) Allocator.Error!usize {
        var ran: usize = 0;
        var progress = true;
        while (progress) {
            progress = false;
            var i: usize = 0;
            while (i < b.queue.items.len) {
                const o = b.queue.items[i];
                if (!b.runner.vtable.ready(b.runner.ctx, &o.item)) {
                    i += 1;
                    continue;
                }
                const outcome = b.runner.vtable.run(b.runner.ctx, scratch, &o.item) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.Unsupported, error.Failed => {
                        b.unsupported += 1;
                        _ = b.queue.orderedRemove(i);
                        o.arena.deinit();
                        b.gpa.destroy(o);
                        continue;
                    },
                };
                if (o.item.digest) |d| try b.markDone(d, outcome.effects_digest);
                if (b.on_done) |cb| cb.f(cb.ctx, o.item.key);
                _ = b.queue.orderedRemove(i);
                o.arena.deinit();
                b.gpa.destroy(o);
                ran += 1;
                b.executed += 1;
                progress = true;
            }
        }
        return ran;
    }

    pub fn markDone(b: *Bridge, digest: Id, effects: Id) Allocator.Error!void {
        b.done_lock.lock();
        defer b.done_lock.unlock();
        try b.done.put(b.gpa, digest, effects);
    }

    pub fn effectsDigest(b: *Bridge, digest: *const Id) ?Id {
        b.done_lock.lock();
        defer b.done_lock.unlock();
        return b.done.get(digest.*);
    }

    pub fn pending(b: *const Bridge) usize {
        return b.queue.items.len;
    }

    // ---- adapter to iface.TxExecutor (tx_bcs = BCS TransactionData)

    fn ifaceEnqueue(ctx: *anyopaque, tx_bcs: []const u8, shared: []const iface.TxExecutor.SharedVersion) error{ Full, Unimplemented }!void {
        const b: *Bridge = @ptrCast(@alignCast(ctx));
        const hash = @import("hash");
        var sv: std.ArrayList(versions.SharedVersion) = .empty;
        defer sv.deinit(b.gpa);
        for (shared) |s| sv.append(b.gpa, .{ .id = s.id.@"0".@"0", .isv = s.initial_shared_version.@"0", .version = s.assigned.@"0" }) catch return error.Full;
        const digest = hash.blake2b256(&.{ "TransactionData::", tx_bcs });
        b.enqueue(.{ .key = .{ .digest = digest }, .kind = .user, .td_bcs = tx_bcs, .digest = digest, .shared = sv.items, .system = &.{} }) catch return error.Full;
    }
    fn ifaceDigest(ctx: *anyopaque, digest: *const types.TransactionDigest) ?types.Digest {
        const b: *Bridge = @ptrCast(@alignCast(ctx));
        const d = b.effectsDigest(&digest.@"0".@"0") orelse return null;
        return .{ .@"0" = d };
    }
    const iface_vt: iface.TxExecutor.VTable = .{ .enqueue = ifaceEnqueue, .effects_digest = ifaceDigest };

    pub fn txExecutor(b: *Bridge) iface.TxExecutor {
        return .{ .ctx = b, .vtable = &iface_vt };
    }
};

// ------------------------------------------------------------------------ test runner

/// A runner over an in-memory set of existing (id, version) pairs: tests and the simulator.
pub const MemRunner = struct {
    have: std.AutoHashMapUnmanaged([40]u8, void) = .empty,
    gpa: Allocator,
    ran: std.ArrayList(Key) = .empty,

    pub fn deinit(m: *MemRunner) void {
        m.have.deinit(m.gpa);
        m.ran.deinit(m.gpa);
    }
    pub fn put(m: *MemRunner, id: Id, version: u64) !void {
        try m.have.put(m.gpa, objKey(id, version), {});
    }
    fn objKey(id: Id, v: u64) [40]u8 {
        var k: [40]u8 = undefined;
        k[0..32].* = id;
        std.mem.writeInt(u64, k[32..40], v, .little);
        return k;
    }
    fn ready(ctx: *anyopaque, item: *const Item) bool {
        const m: *MemRunner = @ptrCast(@alignCast(ctx));
        for (item.owned) |o| if (!m.have.contains(objKey(o.id, o.version))) return false;
        for (item.shared) |s| if (!versions.isCancelled(s.version) and !m.have.contains(objKey(s.id, s.version))) return false;
        return true;
    }
    fn run(ctx: *anyopaque, arena: Allocator, item: *const Item) RunError!Outcome {
        _ = arena;
        const m: *MemRunner = @ptrCast(@alignCast(ctx));
        m.ran.append(m.gpa, item.key) catch return error.OutOfMemory;
        // execution writes the new version of every exclusively accessed shared input: model it
        for (item.shared) |s| if (!versions.isCancelled(s.version)) m.put(s.id, s.version + 1) catch return error.OutOfMemory;
        return .{ .effects_digest = item.digest orelse @splat(0) };
    }
    const vt: Runner.VTable = .{ .ready = ready, .run = run };
    pub fn runner(m: *MemRunner) Runner {
        return .{ .ctx = m, .vtable = &vt };
    }
};

test "bridge waits for inputs and runs in dependency order" {
    const gpa = std.testing.allocator;
    var mr: MemRunner = .{ .gpa = gpa };
    defer mr.deinit();
    var b = Bridge.init(gpa, mr.runner());
    defer b.deinit();
    const obj: Id = @splat(5);
    // second transaction needs version 4 of obj, which the first (reading 3) will write as 4
    try b.enqueue(.{ .key = .{ .digest = @splat(2) }, .kind = .user, .td_bcs = "b", .digest = @splat(2), .shared = &.{.{ .id = obj, .isv = 1, .version = 4 }}, .system = &.{} });
    try b.enqueue(.{ .key = .{ .digest = @splat(1) }, .kind = .user, .td_bcs = "a", .digest = @splat(1), .shared = &.{.{ .id = obj, .isv = 1, .version = 3 }}, .system = &.{} });
    try std.testing.expectEqual(@as(usize, 0), try b.pump(gpa));
    try mr.put(obj, 3);
    try std.testing.expectEqual(@as(usize, 2), try b.pump(gpa));
    try std.testing.expect(mr.ran.items[0].digest[0] == 1 and mr.ran.items[1].digest[0] == 2);
    try std.testing.expect(b.effectsDigest(&@as(Id, @splat(2))) != null);
    try std.testing.expectEqual(@as(usize, 0), b.pending());
}
