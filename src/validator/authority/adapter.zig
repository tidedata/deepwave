//! The consensus adapter (consensus_adapter.rs, mysticeti_adapter.rs, mainnet-v1.83.1): the queue
//! between everything that wants a ConsensusTransaction in this validator's next block and the
//! consensus core's proposal. Implements `iface.ConsensusSubmit` (producers: the submit path,
//! the checkpoint builder, randomness, JWK, epoch) and `consensus.iface.TransactionSource`
//! (consumer: the core's `tryPropose`).
//!
//! Rules:
//!   - system messages (checkpoint signatures, DKG, JWK, EndOfPublish, capabilities) are never
//!     shed under load and go into a block before user transactions;
//!   - user transactions are shed (`error.Overloaded`) when `max_pending_user` are queued;
//!   - a soft bundle (`.soft_bundle`) travels together: all in one block or none, as Rust's
//!     `submit_soft_bundle`;
//!   - a transaction larger than `consensus_max_transaction_size_bytes` is refused;
//!   - `next` honours `consensus_max_num_transactions_in_block` and
//!     `consensus_max_transactions_in_block_bytes` (the `out` length and `max_bytes`);
//!   - what was handed to a proposal waits for `ack(block)` and then stays tracked until the
//!     handler reports it sequenced (`onSequenced`); `resubmitOlderThan` puts what was proposed
//!     but never sequenced (a dropped block) back in the queue, and `resubmitAll` does so at an
//!     epoch change for the new epoch's consensus (`reopenForEpoch`);
//!   - after `closeForEpochEnd` user transactions get `error.EpochEnding`; system ones still go.
const std = @import("std");
const consensus = @import("consensus");
const hash = @import("hash");
const iface = @import("../iface.zig");

const Allocator = std.mem.Allocator;
pub const Priority = iface.ConsensusSubmit.Priority;

/// A short critical-section lock (no I/O inside).
pub const Spin = @import("sync.zig").Spin;

pub const Limits = struct {
    max_tx_bytes: usize = 262144,
    max_pending_user: usize = 100_000,
    max_pending_user_bytes: usize = 256 << 20,
};

const Entry = struct {
    data: []u8,
    key: [32]u8,
    /// Bundle id: entries with the same non-zero id move together (0 = none).
    bundle: u64,
    priority: Priority,
    /// Non-zero: the submitter waits for this transaction's consensus position.
    ticket: u64 = 0,
    /// The consensus transaction key of a user transaction (digest keyed), when known.
    ckey: ?[32]u8 = null,
    /// Sequenced elsewhere while in flight to the core: do not track or resubmit after the ack.
    dead: bool = false,
    /// Index in the proposed block (set by `next`).
    index: u16 = 0,
};

pub const Position = struct { block: consensus.types.BlockRef, index: u16 };

const Proposed = struct { entry: Entry, block: consensus.types.BlockRef, at_tick: u64 };

pub const Stats = struct {
    submitted: u64 = 0,
    shed: u64 = 0,
    proposed: u64 = 0,
    sequenced: u64 = 0,
    resubmitted: u64 = 0,
};

pub const Adapter = struct {
    gpa: Allocator,
    limits: Limits,
    lock: Spin = .{},
    system: std.ArrayList(Entry) = .empty,
    user: std.ArrayList(Entry) = .empty,
    user_bytes: usize = 0,
    /// Given to the core by `next`, not yet acked.
    handed: std.ArrayList(Entry) = .empty,
    /// Proposed, not yet seen sequenced, by the raw hash of the entry bytes.
    proposed: std.AutoHashMapUnmanaged([32]u8, Proposed) = .empty,
    /// consensus key -> raw hash, for proposed entries that carry one.
    by_ckey: std.AutoHashMapUnmanaged([32]u8, [32]u8) = .empty,
    /// Consensus keys of user entries waiting in `user`.
    queued_ckeys: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
    next_bundle: u64 = 1,
    next_ticket: u64 = 1,
    positions: std.AutoHashMapUnmanaged(u64, Position) = .empty,
    position_order: std.ArrayList(u64) = .empty,
    position_cap: usize = 1 << 16,
    tick: u64 = 0,
    closed_for_users: bool = false,
    stats: Stats = .{},
    /// Backing storage for the slices `next` returns (stay valid until `ack`).
    scratch_valid: bool = false,

    pub fn init(gpa: Allocator, limits: Limits) Adapter {
        return .{ .gpa = gpa, .limits = limits };
    }

    pub fn deinit(a: *Adapter) void {
        for ([_]*std.ArrayList(Entry){ &a.system, &a.user, &a.handed }) |l| {
            for (l.items) |e| a.gpa.free(e.data);
            l.deinit(a.gpa);
        }
        var pit = a.proposed.valueIterator();
        while (pit.next()) |p| a.gpa.free(p.entry.data);
        a.proposed.deinit(a.gpa);
        a.by_ckey.deinit(a.gpa);
        a.queued_ckeys.deinit(a.gpa);
        a.positions.deinit(a.gpa);
        a.position_order.deinit(a.gpa);
    }

    pub fn pendingUser(a: *Adapter) usize {
        a.lock.lock();
        defer a.lock.unlock();
        return a.user.items.len;
    }

    pub fn closeForEpochEnd(a: *Adapter) void {
        a.lock.lock();
        defer a.lock.unlock();
        a.closed_for_users = true;
    }

    // ---- ConsensusSubmit

    pub fn submit(a: *Adapter, txs: []const []const u8, priority: Priority) iface.ConsensusSubmit.Error!void {
        return a.submitTracked(txs, priority, null, null);
    }

    /// Like `submit`; with `tickets` (one slot per transaction) each transaction gets a ticket
    /// whose consensus position `positionOf` returns once a proposal carried it.
    pub fn submitTracked(a: *Adapter, txs: []const []const u8, priority: Priority, tickets: ?[]u64, ckeys: ?[]const [32]u8) iface.ConsensusSubmit.Error!void {
        if (txs.len == 0) return;
        for (txs) |t| if (t.len > a.limits.max_tx_bytes) return error.Overloaded;
        a.lock.lock();
        defer a.lock.unlock();
        const is_user = priority != .system;
        if (is_user) {
            if (a.closed_for_users) return error.EpochEnding;
            var add_bytes: usize = 0;
            for (txs) |t| add_bytes += t.len;
            if (a.user.items.len + txs.len > a.limits.max_pending_user or a.user_bytes + add_bytes > a.limits.max_pending_user_bytes) {
                a.stats.shed += txs.len;
                return error.Overloaded;
            }
        }
        const bundle: u64 = if (priority == .soft_bundle and txs.len > 1) blk: {
            defer a.next_bundle += 1;
            break :blk a.next_bundle;
        } else 0;
        const list = if (is_user) &a.user else &a.system;
        const start = list.items.len;
        errdefer {
            for (list.items[start..]) |e| {
                if (e.ckey) |k| _ = a.queued_ckeys.remove(k);
                a.gpa.free(e.data);
            }
            list.shrinkRetainingCapacity(start);
        }
        for (txs, 0..) |t, i| {
            const data = a.gpa.dupe(u8, t) catch return error.Overloaded;
            errdefer a.gpa.free(data);
            var ticket: u64 = 0;
            if (tickets) |ts| {
                ticket = a.next_ticket;
                a.next_ticket += 1;
                ts[i] = ticket;
            }
            const ck: ?[32]u8 = if (ckeys) |ks| ks[i] else null;
            list.append(a.gpa, .{ .data = data, .key = hash.blake2b256(&.{t}), .bundle = bundle, .priority = priority, .ticket = ticket, .ckey = ck }) catch return error.Overloaded;
            if (ck) |k| a.queued_ckeys.put(a.gpa, k, {}) catch {
                _ = list.pop();
                return error.Overloaded;
            };
            if (is_user) a.user_bytes += t.len;
        }
        a.stats.submitted += txs.len;
    }

    fn vtSubmit(ctx: *anyopaque, txs: []const []const u8, priority: Priority) iface.ConsensusSubmit.Error!void {
        const a: *Adapter = @ptrCast(@alignCast(ctx));
        return a.submit(txs, priority);
    }
    const submit_vt: iface.ConsensusSubmit.VTable = .{ .submit = vtSubmit };

    pub fn submitter(a: *Adapter) iface.ConsensusSubmit {
        return .{ .ctx = a, .vtable = &submit_vt };
    }

    // ---- TransactionSource

    /// Moves handed-but-unacked entries back to the front of their queues (a proposal that never
    /// happened), so nothing is lost when `next` is called twice without an `ack`.
    fn returnHandedLocked(a: *Adapter) void {
        // original order is preserved per queue: system entries first, then user
        var sys: usize = 0;
        var usr: usize = 0;
        for (a.handed.items) |e| {
            if (e.dead) {
                a.gpa.free(e.data);
                continue;
            }
            if (e.priority == .system) {
                a.system.insert(a.gpa, sys, e) catch {
                    a.gpa.free(e.data);
                    continue;
                };
                sys += 1;
            } else {
                a.user.insert(a.gpa, usr, e) catch {
                    a.gpa.free(e.data);
                    continue;
                };
                if (e.ckey) |k| a.queued_ckeys.put(a.gpa, k, {}) catch {};
                a.user_bytes += e.data.len;
                usr += 1;
            }
        }
        a.handed.clearRetainingCapacity();
    }

    pub fn next(a: *Adapter, out: []consensus.types.Transaction, max_bytes: u64) usize {
        a.lock.lock();
        defer a.lock.unlock();
        if (a.handed.items.len != 0) a.returnHandedLocked();
        var n: usize = 0;
        var bytes: u64 = 0;
        for ([_]*std.ArrayList(Entry){ &a.system, &a.user }) |list| {
            const i: usize = 0;
            while (i < list.items.len and n < out.len) {
                const e = list.items[i];
                // the whole bundle, or none of it
                var count: usize = 1;
                var size: u64 = e.data.len;
                if (e.bundle != 0) {
                    var j = i + 1;
                    while (j < list.items.len and list.items[j].bundle == e.bundle) : (j += 1) {
                        count += 1;
                        size += list.items[j].data.len;
                    }
                }
                if (n + count > out.len or bytes + size > max_bytes) break;
                // reserve first: an entry that is removed from its queue must always be tracked
                a.handed.ensureUnusedCapacity(a.gpa, count) catch break;
                var k: usize = 0;
                while (k < count) : (k += 1) {
                    var en = list.orderedRemove(i);
                    if (list == &a.user) {
                        a.user_bytes -= en.data.len;
                        if (en.ckey) |ck| _ = a.queued_ckeys.remove(ck);
                    }
                    en.index = @intCast(n);
                    out[n] = .{ .data = en.data };
                    n += 1;
                    a.handed.appendAssumeCapacity(en);
                }
                bytes += size;
            }
        }
        return n;
    }

    pub fn ack(a: *Adapter, block: consensus.types.BlockRef) void {
        a.lock.lock();
        defer a.lock.unlock();
        for (a.handed.items) |e| {
            if (e.ticket != 0) a.recordPositionLocked(e.ticket, .{ .block = block, .index = e.index });
            if (e.dead) a.gpa.free(e.data) else a.trackProposedLocked(e, block);
            a.stats.proposed += 1;
        }
        a.handed.clearRetainingCapacity();
    }

    fn trackProposedLocked(a: *Adapter, e: Entry, block: consensus.types.BlockRef) void {
        const gop = a.proposed.getOrPut(a.gpa, e.key) catch {
            a.gpa.free(e.data);
            return;
        };
        if (gop.found_existing) {
            // identical bytes already tracked: keep one copy
            a.gpa.free(e.data);
            return;
        }
        gop.value_ptr.* = .{ .entry = e, .block = block, .at_tick = a.tick };
        if (e.ckey) |k| a.by_ckey.put(a.gpa, k, e.key) catch {};
    }

    fn recordPositionLocked(a: *Adapter, ticket: u64, p: Position) void {
        if (a.positions.count() >= a.position_cap and a.position_order.items.len > 0) {
            const old = a.position_order.orderedRemove(0);
            _ = a.positions.remove(old);
        }
        a.positions.put(a.gpa, ticket, p) catch return;
        a.position_order.append(a.gpa, ticket) catch {};
    }

    /// The consensus position of a ticketed transaction, once proposed (the latest proposal if
    /// it was resubmitted).
    pub fn positionOf(a: *Adapter, ticket: u64) ?Position {
        a.lock.lock();
        defer a.lock.unlock();
        return a.positions.get(ticket);
    }

    fn vtNext(ctx: *anyopaque, out: []consensus.types.Transaction, max_bytes: u64) usize {
        const a: *Adapter = @ptrCast(@alignCast(ctx));
        return a.next(out, max_bytes);
    }
    fn vtAck(ctx: *anyopaque, block: consensus.types.BlockRef) void {
        const a: *Adapter = @ptrCast(@alignCast(ctx));
        a.ack(block);
    }
    const source_vt: consensus.iface.TransactionSource.VTable = .{ .next = vtNext, .ack = vtAck };

    pub fn source(a: *Adapter) consensus.iface.TransactionSource {
        return .{ .ctx = a, .vtable = &source_vt };
    }

    // ---- tracking after proposal

    fn dropProposedLocked(a: *Adapter, raw: *const [32]u8) void {
        if (a.proposed.fetchRemove(raw.*)) |kv| {
            if (kv.value.entry.ckey) |k| _ = a.by_ckey.remove(k);
            a.gpa.free(kv.value.entry.data);
            a.stats.sequenced += 1;
        }
    }

    /// The handler saw the consensus transaction whose raw bytes hash to `key` (sequenced,
    /// duplicate, dropped or rejected: any appearance ends our tracking of that exact copy).
    pub fn onSequenced(a: *Adapter, key: *const [32]u8) void {
        a.lock.lock();
        defer a.lock.unlock();
        a.dropProposedLocked(key);
    }

    /// The handler saw a user transaction with this consensus key (any copy, ours or another
    /// validator's): our own copy, proposed or still queued, is no longer needed.
    pub fn onConsensusKey(a: *Adapter, ckey: *const [32]u8) void {
        a.lock.lock();
        defer a.lock.unlock();
        if (a.by_ckey.get(ckey.*)) |raw| a.dropProposedLocked(&raw);
        if (a.queued_ckeys.remove(ckey.*)) {
            var i: usize = 0;
            while (i < a.user.items.len) {
                if (a.user.items[i].ckey) |k| if (std.mem.eql(u8, &k, ckey)) {
                    const e = a.user.orderedRemove(i);
                    a.user_bytes -= e.data.len;
                    a.gpa.free(e.data);
                    continue;
                };
                i += 1;
            }
        }
        // a copy between `next` and `ack`
        for (a.handed.items) |*e| if (e.ckey) |k| if (std.mem.eql(u8, &k, ckey)) {
            e.dead = true;
        };
    }

    pub fn advanceTick(a: *Adapter) void {
        a.lock.lock();
        defer a.lock.unlock();
        a.tick += 1;
    }

    /// Re-queues proposed transactions still unsequenced after `age` ticks (a block that never
    /// committed). System messages go first. Returns how many.
    pub fn resubmitOlderThan(a: *Adapter, age: u64) usize {
        a.lock.lock();
        defer a.lock.unlock();
        return a.requeueLocked(age);
    }

    /// Epoch change: everything proposed but unsequenced is submitted again to the new epoch's
    /// consensus; user transactions only if the new epoch accepts them.
    pub fn reopenForEpoch(a: *Adapter) usize {
        a.lock.lock();
        defer a.lock.unlock();
        a.closed_for_users = false;
        return a.requeueLocked(0);
    }

    fn requeueLocked(a: *Adapter, age: u64) usize {
        var n: usize = 0;
        var due: std.ArrayList([32]u8) = .empty;
        defer due.deinit(a.gpa);
        var it = a.proposed.iterator();
        while (it.next()) |kv| if (a.tick -| kv.value_ptr.at_tick >= age) due.append(a.gpa, kv.key_ptr.*) catch break;
        for (due.items) |k| {
            const p = a.proposed.fetchRemove(k).?.value;
            if (p.entry.ckey) |ck| _ = a.by_ckey.remove(ck);
            const list = if (p.entry.priority == .system) &a.system else &a.user;
            list.append(a.gpa, p.entry) catch {
                a.gpa.free(p.entry.data);
                continue;
            };
            if (p.entry.priority != .system) a.user_bytes += p.entry.data.len;
            if (p.entry.ckey) |ck| a.queued_ckeys.put(a.gpa, ck, {}) catch {};
            a.stats.resubmitted += 1;
            n += 1;
        }
        return n;
    }
};

// ------------------------------------------------------------------------ tests

test "system first, limits, bundle atomicity" {
    const gpa = std.testing.allocator;
    var a = Adapter.init(gpa, .{ .max_pending_user = 4 });
    defer a.deinit();
    try a.submit(&.{"user-1"}, .user);
    try a.submit(&.{"sys-1"}, .system);
    try a.submit(&.{ "bundle-a", "bundle-b" }, .soft_bundle);
    var out: [8]consensus.types.Transaction = undefined;
    // room for 2 only: sys-1 then user-1; the bundle (2) does not fit after those
    const n = a.next(out[0..2], 1 << 20);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("sys-1", out[0].data);
    try std.testing.expectEqualStrings("user-1", out[1].data);
    a.ack(.{ .round = 1, .author = 0, .digest = @splat(0) });
    // now the bundle goes whole
    const m = a.next(out[0..8], 1 << 20);
    try std.testing.expectEqual(@as(usize, 2), m);
    try std.testing.expectEqualStrings("bundle-a", out[0].data);
    a.ack(.{ .round = 2, .author = 0, .digest = @splat(0) });
    try std.testing.expectEqual(@as(usize, 4), a.proposed.count());
}

test "overload sheds users not system; epoch end" {
    const gpa = std.testing.allocator;
    var a = Adapter.init(gpa, .{ .max_pending_user = 2 });
    defer a.deinit();
    try a.submit(&.{ "a", "b" }, .user);
    try std.testing.expectError(error.Overloaded, a.submit(&.{"c"}, .user));
    try a.submit(&.{"sys"}, .system);
    a.closeForEpochEnd();
    try std.testing.expectError(error.EpochEnding, a.submit(&.{"d"}, .user));
    try a.submit(&.{"sys2"}, .system);
    try std.testing.expectEqual(@as(u64, 1), a.stats.shed);
}

test "unacked handed return, sequenced removal, resubmit" {
    const gpa = std.testing.allocator;
    var a = Adapter.init(gpa, .{});
    defer a.deinit();
    try a.submit(&.{"x"}, .user);
    var out: [4]consensus.types.Transaction = undefined;
    try std.testing.expectEqual(@as(usize, 1), a.next(&out, 100));
    // no ack: next again gets it back
    try std.testing.expectEqual(@as(usize, 1), a.next(&out, 100));
    a.ack(.{ .round = 3, .author = 1, .digest = @splat(1) });
    try std.testing.expectEqual(@as(usize, 0), a.next(&out, 100));
    a.advanceTick();
    a.advanceTick();
    try std.testing.expectEqual(@as(usize, 1), a.resubmitOlderThan(2));
    try std.testing.expectEqual(@as(usize, 1), a.next(&out, 100));
    a.ack(.{ .round = 4, .author = 1, .digest = @splat(1) });
    const key = hash.blake2b256(&.{"x"});
    a.onSequenced(&key);
    try std.testing.expectEqual(@as(usize, 0), a.proposed.count());
}

test "tickets resolve to block position after ack" {
    const gpa = std.testing.allocator;
    var a = Adapter.init(gpa, .{});
    defer a.deinit();
    var t: [2]u64 = undefined;
    try a.submitTracked(&.{ "p", "q" }, .user, &t, null);
    try std.testing.expect(a.positionOf(t[0]) == null);
    var out: [4]consensus.types.Transaction = undefined;
    try std.testing.expectEqual(@as(usize, 2), a.next(&out, 100));
    const b: consensus.types.BlockRef = .{ .round = 7, .author = 2, .digest = @splat(9) };
    a.ack(b);
    const p0 = a.positionOf(t[0]).?;
    const p1 = a.positionOf(t[1]).?;
    try std.testing.expectEqual(@as(u16, 0), p0.index);
    try std.testing.expectEqual(@as(u16, 1), p1.index);
    try std.testing.expectEqual(@as(u32, 7), p1.block.round);
}

test "any appearance of a user transaction ends tracking of our copy" {
    const gpa = std.testing.allocator;
    var a = Adapter.init(gpa, .{});
    defer a.deinit();
    const ck1: [32]u8 = @splat(1);
    const ck2: [32]u8 = @splat(2);
    var t: [2]u64 = undefined;
    try a.submitTracked(&.{ "u1", "u2" }, .user, &t, &.{ ck1, ck2 });
    // u2 sequenced by another validator while still queued
    a.onConsensusKey(&ck2);
    try std.testing.expectEqual(@as(usize, 1), a.pendingUser());
    var out: [4]consensus.types.Transaction = undefined;
    try std.testing.expectEqual(@as(usize, 1), a.next(&out, 100));
    // u1 sequenced elsewhere between next and ack: not tracked afterwards
    a.onConsensusKey(&ck1);
    a.ack(.{ .round = 1, .author = 0, .digest = @splat(0) });
    try std.testing.expectEqual(@as(usize, 0), a.proposed.count());
    try std.testing.expectEqual(@as(usize, 0), a.resubmitOlderThan(0));
}
