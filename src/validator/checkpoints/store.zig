//! What the checkpoint builder and aggregator persist (the checkpoint tables of
//! `CheckpointStore` and the builder summaries of the epoch store in sui-core). The real
//! implementation lives in the epoch store (val-epoch-api-keys) and the node store; this file
//! declares the seam (`Store`) and ships `MemStore`, an in-memory implementation used by the
//! tests and by a localnet run that does not need restarts.
//!
//! Rules every implementation must keep:
//!  - `putBuilt` stores the summary and contents (atomically, both or neither). It does NOT move
//!    `last_built`: the builder calls `setLastBuilt` only after the output (our signature)
//!    succeeded, so a failed output is retried instead of skipped.
//!  - `last_built` returns `height = null` for a checkpoint of a previous epoch (heights restart
//!    every epoch); the builder additionally compares epochs.
//!  - A built summary is never overwritten with a different digest (the builder checks first).
//!  - `highestCertified` only grows.
const std = @import("std");
const create = @import("create.zig");

pub const SpinLock = struct {
    flag: std.atomic.Value(u32) = .init(0),
    pub fn lock(l: *SpinLock) void {
        while (l.flag.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    pub fn unlock(l: *SpinLock) void {
        l.flag.store(0, .release);
    }
};

pub const Error = error{ Io, OutOfMemory };

pub const RunningRootRecord = struct { root: [32]u8, seq: u64 };

pub const Store = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// The checkpoint built last: this epoch's, else the previous epoch's last certified one.
        last_built: *const fn (ctx: *anyopaque) ?create.LastBuilt,
        /// Digest of the locally computed checkpoint `seq` (fork detection).
        locally_computed_digest: *const fn (ctx: *anyopaque, seq: u64) ?[32]u8,
        /// Stores a built checkpoint (copies the slices). Does not move `last_built`.
        put_built: *const fn (ctx: *anyopaque, seq: u64, height: u64, last: create.LastBuilt, summary_bcs: []const u8, contents_bcs: []const u8) Error!void,
        /// Moves `last_built` to a checkpoint stored with `put_built`.
        set_last_built: *const fn (ctx: *anyopaque, last: create.LastBuilt) Error!void,
        /// BCS(CheckpointSummary) built locally for `seq`, copied into `arena`.
        built_summary: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, seq: u64) Error!?[]const u8,
        built_contents: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, seq: u64) Error!?[]const u8,
        /// Highest certified (or state-synced and verified) checkpoint.
        highest_certified: *const fn (ctx: *anyopaque) ?u64,
        /// Digest of the certified checkpoint `seq`, if known.
        certified_digest: *const fn (ctx: *anyopaque, seq: u64) ?[32]u8,
        put_certified: *const fn (ctx: *anyopaque, seq: u64, digest: [32]u8, certified_summary_bcs: []const u8) Error!void,
        running_root: *const fn (ctx: *anyopaque) ?RunningRootRecord,
        put_running_root: *const fn (ctx: *anyopaque, rec: RunningRootRecord) Error!void,
        /// A fork was found at `seq` (local digest vs the digest the network certified, or null).
        record_fork: *const fn (ctx: *anyopaque, seq: u64, local: [32]u8, certified: ?[32]u8) void,
    };

    pub fn lastBuilt(s: Store) ?create.LastBuilt {
        return s.vtable.last_built(s.ctx);
    }
    pub fn locallyComputedDigest(s: Store, seq: u64) ?[32]u8 {
        return s.vtable.locally_computed_digest(s.ctx, seq);
    }
    pub fn putBuilt(s: Store, seq: u64, height: u64, last: create.LastBuilt, summary_bcs: []const u8, contents_bcs: []const u8) Error!void {
        return s.vtable.put_built(s.ctx, seq, height, last, summary_bcs, contents_bcs);
    }
    pub fn setLastBuilt(s: Store, last: create.LastBuilt) Error!void {
        return s.vtable.set_last_built(s.ctx, last);
    }
    pub fn builtSummary(s: Store, arena: std.mem.Allocator, seq: u64) Error!?[]const u8 {
        return s.vtable.built_summary(s.ctx, arena, seq);
    }
    pub fn builtContents(s: Store, arena: std.mem.Allocator, seq: u64) Error!?[]const u8 {
        return s.vtable.built_contents(s.ctx, arena, seq);
    }
    pub fn highestCertified(s: Store) ?u64 {
        return s.vtable.highest_certified(s.ctx);
    }
    pub fn certifiedDigest(s: Store, seq: u64) ?[32]u8 {
        return s.vtable.certified_digest(s.ctx, seq);
    }
    pub fn putCertified(s: Store, seq: u64, digest: [32]u8, bytes: []const u8) Error!void {
        return s.vtable.put_certified(s.ctx, seq, digest, bytes);
    }
    pub fn runningRoot(s: Store) ?RunningRootRecord {
        return s.vtable.running_root(s.ctx);
    }
    pub fn putRunningRoot(s: Store, rec: RunningRootRecord) Error!void {
        return s.vtable.put_running_root(s.ctx, rec);
    }
    pub fn recordFork(s: Store, seq: u64, local: [32]u8, certified: ?[32]u8) void {
        s.vtable.record_fork(s.ctx, seq, local, certified);
    }
    /// `next_checkpoint_to_certify`: one past the highest certified checkpoint, 0 when none.
    pub fn nextToCertify(s: Store) u64 {
        return if (s.highestCertified()) |h| h + 1 else 0;
    }
};

pub const MemStore = struct {
    gpa: std.mem.Allocator,
    lock: SpinLock = .{},
    built: std.AutoArrayHashMapUnmanaged(u64, Built) = .empty,
    certified: std.AutoArrayHashMapUnmanaged(u64, Certified) = .empty,
    last: ?create.LastBuilt = null,
    highest: ?u64 = null,
    root: ?RunningRootRecord = null,
    forks: u32 = 0,

    const Built = struct { digest: [32]u8, summary: []u8, contents: []u8 };
    const Certified = struct { digest: [32]u8, bytes: []u8 };

    pub fn init(gpa: std.mem.Allocator) MemStore {
        return .{ .gpa = gpa };
    }

    pub fn deinit(m: *MemStore) void {
        for (m.built.values()) |b| {
            m.gpa.free(b.summary);
            m.gpa.free(b.contents);
        }
        m.built.deinit(m.gpa);
        for (m.certified.values()) |c| m.gpa.free(c.bytes);
        m.certified.deinit(m.gpa);
    }

    /// Seeds the store with the last checkpoint of a previous epoch (or genesis).
    pub fn seedCertified(m: *MemStore, last: create.LastBuilt) void {
        m.last = last;
        m.highest = last.seq;
    }

    /// Seeds the running state root (what a validator joining at checkpoint `seq` must have).
    pub fn seedRoot(m: *MemStore, root: [32]u8, seq: u64) void {
        m.root = .{ .root = root, .seq = seq };
    }

    pub fn store(m: *MemStore) Store {
        return .{ .ctx = m, .vtable = &vtable };
    }

    const vtable: Store.VTable = .{
        .last_built = lastBuilt,
        .locally_computed_digest = locallyComputed,
        .put_built = putBuilt,
        .set_last_built = setLastBuilt,
        .built_summary = builtSummary,
        .built_contents = builtContents,
        .highest_certified = highestCertified,
        .certified_digest = certifiedDigest,
        .put_certified = putCertified,
        .running_root = runningRoot,
        .put_running_root = putRunningRoot,
        .record_fork = recordFork,
    };

    fn self(ctx: *anyopaque) *MemStore {
        return @ptrCast(@alignCast(ctx));
    }
    fn lastBuilt(ctx: *anyopaque) ?create.LastBuilt {
        const m = self(ctx);
        m.lock.lock();
        defer m.lock.unlock();
        return m.last;
    }
    fn locallyComputed(ctx: *anyopaque, seq: u64) ?[32]u8 {
        const m = self(ctx);
        m.lock.lock();
        defer m.lock.unlock();
        return if (m.built.get(seq)) |b| b.digest else null;
    }
    fn putBuilt(ctx: *anyopaque, seq: u64, height: u64, last: create.LastBuilt, summary_bcs: []const u8, contents_bcs: []const u8) Error!void {
        _ = height;
        const m = self(ctx);
        const s = try m.gpa.dupe(u8, summary_bcs);
        errdefer m.gpa.free(s);
        const c = try m.gpa.dupe(u8, contents_bcs);
        errdefer m.gpa.free(c);
        m.lock.lock();
        defer m.lock.unlock();
        const gop = try m.built.getOrPut(m.gpa, seq);
        if (gop.found_existing) {
            m.gpa.free(gop.value_ptr.summary);
            m.gpa.free(gop.value_ptr.contents);
        }
        gop.value_ptr.* = .{ .digest = last.digest, .summary = s, .contents = c };
    }
    fn setLastBuilt(ctx: *anyopaque, last: create.LastBuilt) Error!void {
        const m = self(ctx);
        m.lock.lock();
        defer m.lock.unlock();
        m.last = last;
    }
    fn builtSummary(ctx: *anyopaque, arena: std.mem.Allocator, seq: u64) Error!?[]const u8 {
        const m = self(ctx);
        m.lock.lock();
        defer m.lock.unlock();
        const b = m.built.get(seq) orelse return null;
        return try arena.dupe(u8, b.summary);
    }
    fn builtContents(ctx: *anyopaque, arena: std.mem.Allocator, seq: u64) Error!?[]const u8 {
        const m = self(ctx);
        m.lock.lock();
        defer m.lock.unlock();
        const b = m.built.get(seq) orelse return null;
        return try arena.dupe(u8, b.contents);
    }
    fn highestCertified(ctx: *anyopaque) ?u64 {
        const m = self(ctx);
        m.lock.lock();
        defer m.lock.unlock();
        return m.highest;
    }
    fn certifiedDigest(ctx: *anyopaque, seq: u64) ?[32]u8 {
        const m = self(ctx);
        m.lock.lock();
        defer m.lock.unlock();
        return if (m.certified.get(seq)) |c| c.digest else null;
    }
    fn putCertified(ctx: *anyopaque, seq: u64, digest: [32]u8, bytes: []const u8) Error!void {
        const m = self(ctx);
        const b = try m.gpa.dupe(u8, bytes);
        errdefer m.gpa.free(b);
        m.lock.lock();
        defer m.lock.unlock();
        const gop = try m.certified.getOrPut(m.gpa, seq);
        if (gop.found_existing) m.gpa.free(gop.value_ptr.bytes);
        gop.value_ptr.* = .{ .digest = digest, .bytes = b };
        if (m.highest == null or seq > m.highest.?) m.highest = seq;
    }
    fn runningRoot(ctx: *anyopaque) ?RunningRootRecord {
        const m = self(ctx);
        m.lock.lock();
        defer m.lock.unlock();
        return m.root;
    }
    fn putRunningRoot(ctx: *anyopaque, rec: RunningRootRecord) Error!void {
        const m = self(ctx);
        m.lock.lock();
        defer m.lock.unlock();
        m.root = rec;
    }
    fn recordFork(ctx: *anyopaque, seq: u64, local: [32]u8, certified: ?[32]u8) void {
        _ = .{ seq, local, certified };
        const m = self(ctx);
        m.lock.lock();
        defer m.lock.unlock();
        m.forks += 1;
    }
};

test "mem store keeps what it is given" {
    var m = MemStore.init(std.testing.allocator);
    defer m.deinit();
    const s = m.store();
    try std.testing.expectEqual(@as(u64, 0), s.nextToCertify());
    const last: create.LastBuilt = .{ .seq = 3, .epoch = 1, .timestamp_ms = 5, .network_total_transactions = 9, .rolling_gas = .{}, .digest = @splat(4) };
    try s.putBuilt(3, 11, last, "abc", "def");
    try std.testing.expectEqual(@as(?create.LastBuilt, null), s.lastBuilt());
    try s.setLastBuilt(last);
    try std.testing.expectEqual(@as(u64, 3), s.lastBuilt().?.seq);
    try std.testing.expectEqual(@as(u8, 4), s.locallyComputedDigest(3).?[0]);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("abc", (try s.builtSummary(arena.allocator(), 3)).?);
    try s.putCertified(3, @splat(4), "cert");
    try std.testing.expectEqual(@as(u64, 4), s.nextToCertify());
}
