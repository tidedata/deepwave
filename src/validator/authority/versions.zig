//! Shared-object version assignment for consensus-ordered transactions: a port of
//! `shared_object_version_manager.rs` (mainnet-v1.83.1) `assign_versions_from_consensus` and
//! `assign_versions_for_certificate`, with the epoch store's `get_or_init_next_object_versions`.
//!
//! Rules, in Rust's order. Every shared input of every schedulable in the commit (plus the
//! implicitly read system objects) gets a next version: the epoch store's value, or on first use
//! in the epoch the object's current version in the object store (the initial shared version when
//! the object is absent or has another start version). Schedulables are then walked in order. A
//! transaction cancelled for congestion or a failed DKG gets the sentinel versions (CONGESTED,
//! CANCELLED_READ, RANDOMNESS_UNAVAILABLE) and bumps nothing. Any other transaction reads each
//! shared input at its next version and every exclusively accessed input moves to the lamport
//! version: max(non-shared input versions, assigned shared versions) + 1.
const std = @import("std");
const tx_mod = @import("tx.zig");

const Allocator = std.mem.Allocator;
pub const Id = tx_mod.Id;
pub const SharedInput = tx_mod.SharedInput;

/// `SequenceNumber::MAX` and the sentinels above it.
pub const max_version: u64 = 0x7fff_ffff_ffff_ffff;
pub const cancelled_read: u64 = max_version + 1;
pub const congested: u64 = max_version + 2;
pub const randomness_unavailable: u64 = max_version + 3;

pub fn isCancelled(v: u64) bool {
    return v == cancelled_read or v == congested or v == randomness_unavailable;
}
pub fn isValid(v: u64) bool {
    return v < max_version;
}

/// `SequenceNumber::lamport_increment`: max of the inputs, plus one (inputs may be empty: 1).
pub fn lamportIncrement(inputs: []const u64) u64 {
    var m: u64 = 0;
    for (inputs) |v| m = @max(m, v);
    return m + 1;
}

pub const ObjKey = struct {
    id: Id,
    isv: u64,
    pub fn lessThan(_: void, a: ObjKey, b: ObjKey) bool {
        const o = std.mem.order(u8, &a.id, &b.id);
        if (o != .eq) return o == .lt;
        return a.isv < b.isv;
    }
    pub fn eql(a: ObjKey, b: ObjKey) bool {
        return a.isv == b.isv and std.mem.eql(u8, &a.id, &b.id);
    }
};

pub const NextVersions = std.AutoArrayHashMapUnmanaged(ObjKey, u64);

/// What the epoch start configuration says about the implicitly read system objects
/// (`implicitly_read_system_objects`): accumulator root when accumulators are enabled, and the
/// forwarding address registry when forwarding addresses are enabled and the registry exists.
pub const Implicit = struct {
    accumulator_root: ?u64 = null,
    forwarding_registry: ?u64 = null,

    pub const acc_id: Id = blk: {
        var a: Id = @splat(0);
        a[30] = 0x0a;
        a[31] = 0xcc;
        break :blk a;
    };
    pub const fwd_id: Id = blk: {
        var a: Id = @splat(0);
        a[31] = 0xfa;
        break :blk a;
    };

    /// In Rust's order (accumulator first).
    pub fn list(i: Implicit, out: *[2]ObjKey) []const ObjKey {
        var n: usize = 0;
        if (i.accumulator_root) |isv| {
            out[n] = .{ .id = acc_id, .isv = isv };
            n += 1;
        }
        if (i.forwarding_registry) |isv| {
            out[n] = .{ .id = fwd_id, .isv = isv };
            n += 1;
        }
        return out[0..n];
    }
};

/// The object store as version assignment sees it: the current version of an object and its
/// start version (`Owner::start_version()`), null when the object does not exist.
pub const ObjectReader = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const Current = struct { version: u64, start_version: ?u64 };
    pub const VTable = struct {
        current: *const fn (ctx: *anyopaque, id: *const Id) ?Current,
    };
    pub fn current(r: ObjectReader, id: *const Id) ?Current {
        return r.vtable.current(r.ctx, id);
    }
};

pub const CancelReason = union(enum) {
    congestion_on_objects: []const Id,
    dkg_failed,
};

pub const Cancelled = std.AutoArrayHashMapUnmanaged(Id, CancelReason);

/// One thing to schedule, reduced to what version assignment needs.
pub const Assignable = struct {
    key: Key,
    shared: []const SharedInput,
    /// Versions of the non-shared inputs: ImmOrOwned (PTB inputs and gas) and receiving objects.
    non_shared_versions: []const u64 = &.{},

    pub const Key = union(enum) {
        digest: Id,
        randomness_round: struct { epoch: u64, round: u64 },
        accumulator_settlement: struct { epoch: u64, height: u64 },
        consensus_commit_prologue: struct { epoch: u64, round: u64, sub_dag_index: u32 },

        pub fn asDigest(k: Key) ?Id {
            return switch (k) {
                .digest => |d| d,
                else => null,
            };
        }
        pub fn eql(a: Key, b: Key) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
            return switch (a) {
                .digest => |x| std.mem.eql(u8, &x, &b.digest),
                .randomness_round => |x| x.epoch == b.randomness_round.epoch and x.round == b.randomness_round.round,
                .accumulator_settlement => |x| x.epoch == b.accumulator_settlement.epoch and x.height == b.accumulator_settlement.height,
                .consensus_commit_prologue => |x| x.epoch == b.consensus_commit_prologue.epoch and x.round == b.consensus_commit_prologue.round and x.sub_dag_index == b.consensus_commit_prologue.sub_dag_index,
            };
        }
    };
};

pub const SharedVersion = struct { id: Id, isv: u64, version: u64 };
pub const SystemVersion = struct { id: Id, isv: u64, version: u64 };

pub const Assigned = struct {
    key: Assignable.Key,
    shared: []const SharedVersion,
    system: []const SystemVersion,

    pub fn accumulatorVersion(a: *const Assigned) ?u64 {
        for (a.system) |s| if (std.mem.eql(u8, &s.id, &Implicit.acc_id)) return s.version;
        return null;
    }
    pub fn anyCancelled(a: *const Assigned) bool {
        for (a.shared) |s| if (isCancelled(s.version)) return true;
        return false;
    }
};

pub const Result = struct {
    /// The next versions for every object touched, to be written with the commit.
    next_versions: NextVersions,
    assigned: []Assigned,
};

/// The epoch store's persisted next versions (read only here; the commit writes `Result.next_versions`).
pub const EpochVersions = struct {
    ctx: *const anyopaque,
    get: *const fn (ctx: *const anyopaque, key: ObjKey) ?u64,
};

pub const Env = struct {
    implicit: Implicit,
    epoch_versions: EpochVersions,
    reader: ObjectReader,
};

/// `get_or_init_next_object_versions` for `keys` (already sorted and deduplicated).
fn getOrInit(arena: Allocator, env: *const Env, keys: []const ObjKey, out: *NextVersions) Allocator.Error!void {
    for (keys) |k| {
        if (env.epoch_versions.get(env.epoch_versions.ctx, k)) |v| {
            try out.put(arena, k, v);
            continue;
        }
        const init_v: u64 = if (env.reader.current(&k.id)) |cur| blk: {
            if (cur.start_version != null and cur.start_version.? == k.isv) break :blk cur.version;
            break :blk k.isv;
        } else k.isv;
        try out.put(arena, k, init_v);
    }
}

/// `assign_versions_from_consensus`. `assignables` are in schedule order.
pub fn assignFromConsensus(arena: Allocator, env: *const Env, assignables: []const Assignable, cancelled: *const Cancelled) Allocator.Error!Result {
    var keys: std.ArrayList(ObjKey) = .empty;
    for (assignables) |a| for (a.shared) |s| try keys.append(arena, .{ .id = s.id, .isv = s.isv });
    var imp_buf: [2]ObjKey = undefined;
    const imp = env.implicit.list(&imp_buf);
    try keys.appendSlice(arena, imp);
    std.mem.sort(ObjKey, keys.items, {}, ObjKey.lessThan);
    // dedup
    var n: usize = 0;
    for (keys.items) |k| {
        if (n > 0 and keys.items[n - 1].eql(k)) continue;
        keys.items[n] = k;
        n += 1;
    }
    var next: NextVersions = .empty;
    try getOrInit(arena, env, keys.items[0..n], &next);

    const out = try arena.alloc(Assigned, assignables.len);
    for (assignables, out) |a, *o| o.* = try assignForCertificate(arena, env, a, &next, cancelled);
    return .{ .next_versions = next, .assigned = out };
}

/// `assign_versions_for_certificate`: asserts (as Rust) that every key is in `next`.
pub fn assignForCertificate(arena: Allocator, env: *const Env, a: Assignable, next: *NextVersions, cancelled: *const Cancelled) Allocator.Error!Assigned {
    var imp_buf: [2]ObjKey = undefined;
    const imp = env.implicit.list(&imp_buf);
    const system = try arena.alloc(SystemVersion, imp.len);
    for (imp, system) |k, *s| {
        const v = next.get(k) orelse std.debug.panic("implicitly read system object missing from next versions", .{});
        s.* = .{ .id = k.id, .isv = k.isv, .version = v };
    }
    if (a.shared.len == 0) return .{ .key = a.key, .shared = &.{}, .system = system };

    const reason: ?CancelReason = if (a.key.asDigest()) |d| cancelled.get(d) else null;
    const shared_out = try arena.alloc(SharedVersion, a.shared.len);
    if (reason) |r| {
        for (a.shared, shared_out) |s, *o| {
            const v: u64 = switch (r) {
                .congestion_on_objects => |ids| blk: {
                    for (ids) |c| if (std.mem.eql(u8, &c, &s.id)) break :blk congested;
                    break :blk cancelled_read;
                },
                .dkg_failed => if (std.mem.eql(u8, &s.id, &tx_mod.randomness_object_id)) randomness_unavailable else cancelled_read,
            };
            o.* = .{ .id = s.id, .isv = s.isv, .version = v };
        }
        return .{ .key = a.key, .shared = shared_out, .system = system };
    }

    var inputs: std.ArrayList(u64) = .empty;
    try inputs.appendSlice(arena, a.non_shared_versions);
    for (a.shared, shared_out) |s, *o| {
        const v = next.get(.{ .id = s.id, .isv = s.isv }) orelse std.debug.panic("shared input missing from next versions", .{});
        o.* = .{ .id = s.id, .isv = s.isv, .version = v };
        try inputs.append(arena, v);
    }
    const lamport = lamportIncrement(inputs.items);
    std.debug.assert(isValid(lamport));
    for (a.shared) |s| if (s.exclusive()) {
        try next.put(arena, .{ .id = s.id, .isv = s.isv }, lamport);
    };
    return .{ .key = a.key, .shared = shared_out, .system = system };
}

// ---------------------------------------------------------------------------------- tests

const TestStore = struct {
    map: std.AutoHashMapUnmanaged(ObjKey, u64) = .empty,
    cur: std.AutoHashMapUnmanaged(Id, ObjectReader.Current) = .empty,
    fn getV(ctx: *const anyopaque, k: ObjKey) ?u64 {
        const s: *const TestStore = @ptrCast(@alignCast(ctx));
        return s.map.get(k);
    }
    fn curV(ctx: *anyopaque, id: *const Id) ?ObjectReader.Current {
        const s: *TestStore = @ptrCast(@alignCast(ctx));
        return s.cur.get(id.*);
    }
};

fn id1(b: u8) Id {
    var a: Id = @splat(0);
    a[31] = b;
    return a;
}

test "assign versions: lamport and read-only" {
    var ts: TestStore = .{};
    defer ts.map.deinit(std.testing.allocator);
    defer ts.cur.deinit(std.testing.allocator);
    const obj = id1(0x42);
    try ts.cur.put(std.testing.allocator, obj, .{ .version = 7, .start_version = 3 });
    const vt: ObjectReader.VTable = .{ .current = TestStore.curV };
    const env: Env = .{
        .implicit = .{},
        .epoch_versions = .{ .ctx = &ts, .get = TestStore.getV },
        .reader = .{ .ctx = &ts, .vtable = &vt },
    };
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const mut: SharedInput = .{ .id = obj, .isv = 3, .mutability = .mutable };
    const ro: SharedInput = .{ .id = obj, .isv = 3, .mutability = .immutable };
    const a = [_]Assignable{
        .{ .key = .{ .digest = id1(1) }, .shared = &.{mut}, .non_shared_versions = &.{3} },
        .{ .key = .{ .digest = id1(2) }, .shared = &.{ro}, .non_shared_versions = &.{5} },
        .{ .key = .{ .digest = id1(3) }, .shared = &.{mut}, .non_shared_versions = &.{9} },
    };
    var c: Cancelled = .empty;
    const r = try assignFromConsensus(arena, &env, &a, &c);
    // first tx reads 7, lamport = max(3,7)+1 = 8
    try std.testing.expectEqual(@as(u64, 7), r.assigned[0].shared[0].version);
    // read only tx reads 8 and does not bump
    try std.testing.expectEqual(@as(u64, 8), r.assigned[1].shared[0].version);
    // third reads 8, lamport = max(9, 8)+1 = 10
    try std.testing.expectEqual(@as(u64, 8), r.assigned[2].shared[0].version);
    try std.testing.expectEqual(@as(u64, 10), r.next_versions.get(.{ .id = obj, .isv = 3 }).?);
}

test "cancelled gets sentinels and does not bump" {
    var ts: TestStore = .{};
    defer ts.map.deinit(std.testing.allocator);
    defer ts.cur.deinit(std.testing.allocator);
    const o1 = id1(0x10);
    const o2 = id1(0x11);
    const vt: ObjectReader.VTable = .{ .current = TestStore.curV };
    const env: Env = .{
        .implicit = .{},
        .epoch_versions = .{ .ctx = &ts, .get = TestStore.getV },
        .reader = .{ .ctx = &ts, .vtable = &vt },
    };
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const s1: SharedInput = .{ .id = o1, .isv = 1, .mutability = .mutable };
    const s2: SharedInput = .{ .id = o2, .isv = 1, .mutability = .mutable };
    const a = [_]Assignable{.{ .key = .{ .digest = id1(9) }, .shared = &.{ s1, s2 } }};
    var c: Cancelled = .empty;
    try c.put(arena, id1(9), .{ .congestion_on_objects = &.{o1} });
    const r = try assignFromConsensus(arena, &env, &a, &c);
    try std.testing.expectEqual(congested, r.assigned[0].shared[0].version);
    try std.testing.expectEqual(cancelled_read, r.assigned[0].shared[1].version);
    // absent objects start at their initial shared version and stay there
    try std.testing.expectEqual(@as(u64, 1), r.next_versions.get(.{ .id = o1, .isv = 1 }).?);
    try std.testing.expect(isCancelled(congested) and !isValid(cancelled_read));
}
