//! `consensus_tx_status_cache.rs` (mainnet-v1.83.1): what the consensus handler decided for a
//! transaction position, so `WaitForEffects` can answer a client that submitted a transaction
//! that was rejected by the fast-path vote, dropped (lock conflict, epoch end, end of publish) or
//! finalized. Positions are (block ref, index in block). Bounded: the oldest positions fall out.
const std = @import("std");
const Spin = @import("sync.zig").Spin;

const Allocator = std.mem.Allocator;

pub const Position = struct {
    round: u32,
    author: u32,
    digest: [32]u8,
    index: u16,
};

pub const Status = enum { finalized, rejected, dropped };

pub const StatusCache = struct {
    gpa: Allocator,
    /// Guards every field: the handler thread writes, API threads poll.
    lock: Spin = .{},
    cap: usize = 1 << 20,
    map: std.AutoHashMapUnmanaged(Position, Status) = .empty,
    order: std.ArrayList(Position) = .empty,
    /// Entries before this index in `order` are already gone (compacted lazily).
    head: usize = 0,
    /// Highest leader round whose commit was processed (positions at or below it that are not in
    /// the map were garbage collected or never committed).
    last_committed_round: u64 = 0,
    expiry_round: u64 = 0,
    have_round: bool = false,
    /// The watch value exists (set from the second update on).
    have_expiry: bool = false,

    /// The published last committed leader round (the watch value), for the lagging response.
    pub fn lastCommitted(c: *StatusCache) u64 {
        c.lock.lock();
        defer c.lock.unlock();
        return c.expiry_round;
    }

    pub fn deinit(c: *StatusCache) void {
        c.map.deinit(c.gpa);
        c.order.deinit(c.gpa);
    }

    pub fn set(c: *StatusCache, p: Position, s: Status) Allocator.Error!void {
        c.lock.lock();
        defer c.lock.unlock();
        const gop = try c.map.getOrPut(c.gpa, p);
        gop.value_ptr.* = s;
        if (gop.found_existing) return;
        try c.order.append(c.gpa, p);
        // amortised FIFO eviction
        if (c.order.items.len - c.head > c.cap + c.cap / 4) {
            const drop = c.order.items.len - c.head - c.cap;
            for (c.order.items[c.head .. c.head + drop]) |old| _ = c.map.remove(old);
            c.head += drop;
            c.compact();
        }
    }

    fn compact(c: *StatusCache) void {
        if (c.head == 0 or c.head < c.order.items.len / 2) return;
        const live = c.order.items.len - c.head;
        std.mem.copyForwards(Position, c.order.items[0..live], c.order.items[c.head..]);
        c.order.shrinkRetainingCapacity(live);
        c.head = 0;
    }

    pub fn get(c: *StatusCache, p: Position) ?Status {
        c.lock.lock();
        defer c.lock.unlock();
        return c.map.get(p);
    }

    /// `update_last_committed_leader_round`: the first update records only; later ones expire
    /// statuses older than the PREVIOUS committed round (the current commit's own statuses must
    /// not expire in the same step) and publish that previous round as the expiry horizon.
    pub fn updateLastCommitted(c: *StatusCache, round: u64) void {
        c.lock.lock();
        defer c.lock.unlock();
        const prev = c.last_committed_round;
        c.last_committed_round = round;
        if (!c.have_round) {
            c.have_round = true;
            return;
        }
        c.expiry_round = prev;
        c.have_expiry = true;
        // positions arrive in commit order, so rounds are non-decreasing up to a small
        // reordering: drop the expired prefix in one pass instead of scanning everything
        while (c.head < c.order.items.len) {
            const p = c.order.items[c.head];
            if (@as(u64, p.round) + retention_rounds > prev) break;
            _ = c.map.remove(p);
            c.head += 1;
        }
        c.compact();
    }

    /// `check_position_too_ahead`: the position's block round is beyond what this validator has
    /// committed plus the retention window (ValidatorConsensusLagging).
    pub fn tooAhead(c: *StatusCache, p: Position) bool {
        c.lock.lock();
        defer c.lock.unlock();
        return c.have_expiry and @as(u64, p.round) > c.expiry_round + retention_rounds;
    }

    pub const Poll = union(enum) {
        status: Status,
        /// The position is older than the retention window and has no status: the leader round.
        expired: u64,
        pending,
    };

    /// One non-blocking step of `notify_read_transaction_status`.
    pub fn poll(c: *StatusCache, p: Position) Poll {
        c.lock.lock();
        defer c.lock.unlock();
        if (c.map.get(p)) |s| return .{ .status = s };
        if (c.have_expiry and @as(u64, p.round) + retention_rounds <= c.expiry_round) return .{ .expired = c.expiry_round };
        return .pending;
    }
};

/// `CONSENSUS_STATUS_RETENTION_ROUNDS`.
pub const retention_rounds: u64 = 400;

test "status cache evicts oldest" {
    var c: StatusCache = .{ .gpa = std.testing.allocator, .cap = 4 };
    defer c.deinit();
    var i: u32 = 0;
    while (i < 10) : (i += 1) try c.set(.{ .round = i, .author = 0, .digest = @splat(0), .index = 0 }, .finalized);
    try std.testing.expect(c.get(.{ .round = 0, .author = 0, .digest = @splat(0), .index = 0 }) == null);
    try std.testing.expect(c.get(.{ .round = 9, .author = 0, .digest = @splat(0), .index = 0 }) == .finalized);
}

test "status cache is safe to poll while the handler writes" {
    const gpa = std.testing.allocator;
    var c: StatusCache = .{ .gpa = gpa, .cap = 64 };
    defer c.deinit();
    const Reader = struct {
        fn run(cc: *StatusCache, stop: *std.atomic.Value(bool)) void {
            var i: u32 = 0;
            while (!stop.load(.acquire)) : (i +%= 1) {
                _ = cc.poll(.{ .round = i % 5000, .author = 0, .digest = @splat(0), .index = 0 });
                _ = cc.tooAhead(.{ .round = i % 5000, .author = 0, .digest = @splat(0), .index = 0 });
            }
        }
    };
    var stop: std.atomic.Value(bool) = .init(false);
    const th = try std.Thread.spawn(.{}, Reader.run, .{ &c, &stop });
    var i: u32 = 0;
    while (i < 5000) : (i += 1) {
        try c.set(.{ .round = i, .author = 0, .digest = @splat(0), .index = 0 }, .finalized);
        c.updateLastCommitted(i);
    }
    stop.store(true, .release);
    th.join();
    try std.testing.expect(c.map.count() <= 64 + 16);
}
