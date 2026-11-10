//! Candidate pool for outbound p2p dials: every peer learned from discovery (GetKnownPeersV2 of
//! any connected peer, every `query_interval_ms` like sui-node's discovery tick), the dial order,
//! and a backoff by why the last dial failed.
//!
//! Why (mainnet probe, 2026-11-08, `deepwave p2p-probe`): of 719 distinct peers in 8 seeds' known
//! peers, 60 accepted a connection. 541 never sent a single datagram back (firewalled or gone; UDP
//! gives no error), 95 finished TLS and then closed with code 0 (anemo's connection limit, or
//! PeerAffinity::Never), 15 answered with another key (PeerIdMismatch). Fixed slots on the first
//! 32 discovered peers, retried with a 0.5-30 s backoff, made 268 failed connects in 30 min for 13
//! good ones. Here a slot moves on to the next candidate at once, and a peer that failed is not
//! tried again until its class's backoff ends (sui-node: peer_failure_cooldown 1 h).
//!
//! Pure logic, no I/O (unit-tested below); the caller holds no lock (one mutex inside).
const std = @import("std");
const discovery = @import("discovery.zig");
const SpinLock = @import("peer_score.zig").SpinLock;

pub const max_candidates = 4096;
pub const max_addrs = 4;
pub const max_addr_len = 96;
/// sui-node's ONE_DAY_MILLISECONDS: signed infos older than this are not used.
pub const one_day_ms: u64 = 24 * 3600 * 1000;

pub const Outcome = enum {
    /// Connected; the session has ended (peer closed, idle, or dropped for failing).
    ended,
    /// No datagram came back.
    silent,
    /// The peer closed after the handshake (connection limit) or the handshake stalled.
    refused,
    /// The address answered with another key, or the peer is on another chain.
    wrong_peer,
    /// Local socket or DNS error.
    local,
};

pub const Config = struct {
    /// Backoff before trying a peer again, by outcome (ms). A peer that worked comes back fast.
    ended_ms: u64 = 2_000,
    silent_ms: u64 = 3_600_000,
    refused_ms: u64 = 600_000,
    wrong_peer_ms: u64 = 3_600_000,
    local_ms: u64 = 300_000,
};

pub const Candidate = struct {
    id: [32]u8,
    addrs: [max_addrs][max_addr_len]u8 = undefined,
    addr_lens: [max_addrs]u8 = @splat(0),
    n_addrs: u8 = 0,
    ts_ms: u64 = 0,
    next_ms: u64 = 0,
    tries: u32 = 0,
    oks: u32 = 0,
    in_slot: bool = false,
    last: ?Outcome = null,

    pub fn addr(c: *const Candidate, i: usize) []const u8 {
        return c.addrs[i][0..c.addr_lens[i]];
    }
};

pub const Stats = struct {
    added: u64 = 0,
    updated: u64 = 0,
    skipped: u64 = 0,
    taken: u64 = 0,
    ended: u64 = 0,
    silent: u64 = 0,
    refused: u64 = 0,
    wrong_peer: u64 = 0,
    local: u64 = 0,
    /// Infos skipped by the freshness rule, and candidates culled after a day without a newer one.
    stale: u64 = 0,
    culled: u64 = 0,
};

/// Same addresses in the same order (bytes past each length are not compared: `addrs` is not
/// zeroed).
fn sameAddrs(a: *const Candidate, b: *const Candidate) bool {
    if (a.n_addrs != b.n_addrs) return false;
    for (0..a.n_addrs) |i| if (!std.mem.eql(u8, a.addr(i), b.addr(i))) return false;
    return true;
}

/// Addresses set through the admin port (`POST /update-endpoint?endpoint_type=p2p`, sui-node's
/// `AddressSource::Admin`, the highest-priority source): in memory only, as sui-node keeps them.
/// A peer with an override is dialled at those addresses instead of the ones it signed, before
/// any other candidate, and a peer the pool has not learned yet is added for it (sui-node puts it
/// in anemo's known peers with high affinity). An empty address list removes the override. Only
/// addresses `Multiaddr::to_anemo_address` takes are kept (the caller filters), at most
/// `max_addrs` of them. A connection already open to the peer is not dropped (sui-node
/// disconnects it and dials the new address; here the next dial uses it).
pub const Overrides = struct {
    mu: SpinLock = .{},
    list: std.ArrayList(Entry) = .empty,
    /// Bumped by every change; a pool lifts the backoff of overridden peers when it moves.
    gen: std.atomic.Value(u64) = .init(0),

    pub const Entry = struct {
        id: [32]u8,
        addrs: [max_addrs][max_addr_len]u8 = undefined,
        addr_lens: [max_addrs]u8 = @splat(0),
        n_addrs: u8 = 0,

        pub fn addr(e: *const Entry, i: usize) []const u8 {
            return e.addrs[i][0..e.addr_lens[i]];
        }
    };

    const gpa = std.heap.page_allocator;

    /// Sets (or with no address, removes) the override of `id`. Addresses longer than
    /// `max_addr_len` and any past the first `max_addrs` are dropped.
    pub fn set(o: *Overrides, id: *const [32]u8, addrs: []const []const u8) std.mem.Allocator.Error!void {
        var e: Entry = .{ .id = id.* };
        for (addrs) |t| {
            if (e.n_addrs == max_addrs) break;
            if (t.len > max_addr_len) continue;
            @memcpy(e.addrs[e.n_addrs][0..t.len], t);
            e.addr_lens[e.n_addrs] = @intCast(t.len);
            e.n_addrs += 1;
        }
        o.mu.lock();
        defer o.mu.unlock();
        defer _ = o.gen.fetchAdd(1, .release);
        for (o.list.items, 0..) |*have, i| if (std.mem.eql(u8, &have.id, id)) {
            if (e.n_addrs == 0) _ = o.list.swapRemove(i) else have.* = e;
            return;
        };
        if (e.n_addrs > 0) try o.list.append(gpa, e);
    }

    /// The override of `id`, copied into `out`.
    pub fn get(o: *Overrides, id: *const [32]u8, out: *Entry) bool {
        o.mu.lock();
        defer o.mu.unlock();
        for (o.list.items) |*have| if (std.mem.eql(u8, &have.id, id)) {
            out.* = have.*;
            return true;
        };
        return false;
    }

    pub fn count(o: *Overrides) usize {
        o.mu.lock();
        defer o.mu.unlock();
        return o.list.items.len;
    }

    /// Drops every override (tests).
    pub fn clear(o: *Overrides) void {
        o.mu.lock();
        defer o.mu.unlock();
        o.list.clearAndFree(gpa);
        _ = o.gen.fetchAdd(1, .release);
    }
};

/// The process's admin overrides (one p2p stack per process).
pub var admin_overrides: Overrides = .{};

pub const Pool = struct {
    gpa: std.mem.Allocator,
    cfg: Config = .{},
    /// Admin address overrides consulted at every `take`.
    overrides: *Overrides = &admin_overrides,
    /// `overrides.gen` when this pool last merged them.
    ovr_seen: u64 = 0,
    own_id: [32]u8 = @splat(0),
    /// Peers held elsewhere (the seeds' own threads): never handed to a slot. A second
    /// connection from the same PeerId makes the remote's anemo close one of the two
    /// (simultaneous-dial tie-break, code 0 "connection closed" about 1 s after the handshake):
    /// that loop was 2,292 sessions ending in 30 min.
    held: [64][32]u8 = undefined,
    n_held: usize = 0,
    n_freed: usize = 0,
    mu: SpinLock = .{},
    list: std.ArrayList(Candidate) = .empty,
    stats: Stats = .{},
    /// sui-node's `is_trusted_peer` (seeds with an id, `allowlisted-peers`): their Private and
    /// Trusted infos are dialable; every other peer's only when Public.
    trusted: []const [32]u8 = &.{},

    pub fn isTrusted(p: *const Pool, id: *const [32]u8) bool {
        for (p.trusted) |*t| if (std.mem.eql(u8, t, id)) return true;
        return false;
    }

    /// `add` behind sui-node's freshness rule (`update_known_peers`): an info signed more than
    /// 30 s in the future or more than a day ago is skipped.
    pub fn addFresh(p: *Pool, info: *const discovery.SignedInfo, now_ms: u64) bool {
        if (info.timestamp_ms > now_ms +| 30_000 or now_ms -| info.timestamp_ms > one_day_ms) {
            p.mu.lock();
            p.stats.stale += 1;
            p.mu.unlock();
            return false;
        }
        return p.add(info);
    }

    /// Discovery's daily cull (`handle_tick`): candidates whose newest signed info is more than a
    /// day old are dropped, unless a slot holds them now. Returns how many went.
    pub fn cull(p: *Pool, now_ms: u64) usize {
        p.mu.lock();
        defer p.mu.unlock();
        var kept: usize = 0;
        for (p.list.items) |c| {
            if (c.in_slot or now_ms -| c.ts_ms <= one_day_ms) {
                p.list.items[kept] = c;
                kept += 1;
            }
        }
        const gone = p.list.items.len - kept;
        p.list.shrinkRetainingCapacity(kept);
        p.stats.culled += gone;
        return gone;
    }

    /// Frees the list but keeps its size for `count` (node.zig prints it after p2p stops).
    pub fn deinit(p: *Pool) void {
        p.mu.lock();
        defer p.mu.unlock();
        p.n_freed = p.list.items.len;
        p.list.deinit(p.gpa);
        p.list = .empty;
    }

    /// Marks `id` as connected outside the pool (see `held`); idempotent.
    pub fn hold(p: *Pool, id: *const [32]u8) void {
        p.mu.lock();
        defer p.mu.unlock();
        for (p.held[0..p.n_held]) |*h| if (std.mem.eql(u8, h, id)) return;
        if (p.n_held < p.held.len) {
            p.held[p.n_held] = id.*;
            p.n_held += 1;
        }
    }

    fn isHeld(p: *const Pool, id: *const [32]u8) bool {
        for (p.held[0..p.n_held]) |*h| if (std.mem.eql(u8, h, id)) return true;
        return false;
    }

    pub fn count(p: *Pool) usize {
        p.mu.lock();
        defer p.mu.unlock();
        return p.list.items.len + p.n_freed;
    }

    /// Adds or refreshes a verified peer with at least one dialable address: Public, or any
    /// access type from a trusted peer (sui-node: a restricted peer is ignored unless trusted).
    /// Returns true when the peer is new.
    pub fn add(p: *Pool, info: *const discovery.SignedInfo) bool {
        if ((info.access_type != .public and !p.isTrusted(&info.peer_id)) or std.mem.eql(u8, &info.peer_id, &p.own_id)) {
            p.mu.lock();
            p.stats.skipped += 1;
            p.mu.unlock();
            return false;
        }
        var c: Candidate = .{ .id = info.peer_id, .ts_ms = info.timestamp_ms };
        for (info.addresses) |t| {
            if (c.n_addrs == max_addrs) break;
            if (t.len > max_addr_len or discovery.parseAddress(t) == null) continue;
            @memcpy(c.addrs[c.n_addrs][0..t.len], t);
            c.addr_lens[c.n_addrs] = @intCast(t.len);
            c.n_addrs += 1;
        }
        p.mu.lock();
        defer p.mu.unlock();
        if (c.n_addrs == 0) {
            p.stats.skipped += 1;
            return false;
        }
        for (p.list.items) |*have| if (std.mem.eql(u8, &have.id, &c.id)) {
            if (c.ts_ms > have.ts_ms) {
                // A newer signed info: new addresses; a peer that was silent, answered with
                // another key or failed locally gets another chance at them. Not one that
                // refused us or replaced our connection (`refused`): it answered at its address,
                // so the 10 min wait holds whatever it re-signs (sui-node re-signs every tick).
                const changed = !sameAddrs(have, &c);
                have.addrs = c.addrs;
                have.addr_lens = c.addr_lens;
                have.n_addrs = c.n_addrs;
                have.ts_ms = c.ts_ms;
                if (changed and have.last != null and have.last.? != .ended and have.last.? != .refused) have.next_ms = 0;
                p.stats.updated += 1;
            }
            return false;
        };
        if (p.list.items.len >= max_candidates) {
            p.stats.skipped += 1;
            return false;
        }
        p.list.append(p.gpa, c) catch return false;
        p.stats.added += 1;
        return true;
    }

    /// The next peer to dial, copied out (`in_slot` set until `release`): peers that worked
    /// before first, then never-tried peers with the freshest signed info, then the rest whose
    /// backoff is over. Null when none is due.
    pub fn take(p: *Pool, now_ms: u64, out: *Candidate) bool {
        p.mu.lock();
        defer p.mu.unlock();
        p.mergeOverrides();
        var best: ?usize = null;
        var best_key: u128 = 0;
        var ovr: Overrides.Entry = undefined;
        for (p.list.items, 0..) |*c, i| {
            if (c.in_slot or c.next_ms > now_ms or p.isHeld(&c.id)) continue;
            const has_ovr = p.overrides.count() > 0 and p.overrides.get(&c.id, &ovr);
            if (c.n_addrs == 0 and !has_ovr) continue;
            // class (3: admin override, 2: worked before, 1: never tried, 0: failed before),
            // then freshness
            const class: u128 = if (has_ovr) 3 else if (c.oks > 0) 2 else if (c.tries == 0) 1 else 0;
            const key = (class << 64) | c.ts_ms;
            if (best == null or key > best_key) {
                best = i;
                best_key = key;
            }
        }
        const i = best orelse return false;
        const c = &p.list.items[i];
        c.in_slot = true;
        c.tries += 1;
        p.stats.taken += 1;
        out.* = c.*;
        if (p.overrides.get(&c.id, &ovr)) {
            out.addrs = ovr.addrs;
            out.addr_lens = ovr.addr_lens;
            out.n_addrs = ovr.n_addrs;
        }
        return true;
    }

    /// After an override change (under `mu`): a peer the pool does not know yet becomes a
    /// candidate, and every overridden peer may be dialled at once.
    fn mergeOverrides(p: *Pool) void {
        const g = p.overrides.gen.load(.acquire);
        if (g == p.ovr_seen) return;
        p.ovr_seen = g;
        const o = p.overrides;
        o.mu.lock();
        defer o.mu.unlock();
        for (o.list.items) |*e| {
            if (std.mem.eql(u8, &e.id, &p.own_id)) continue;
            const have = for (p.list.items) |*c| {
                if (std.mem.eql(u8, &c.id, &e.id)) break c;
            } else null;
            if (have) |c| {
                if (!c.in_slot) c.next_ms = 0;
            } else if (p.list.items.len < max_candidates) {
                p.list.append(p.gpa, .{ .id = e.id }) catch return;
            }
        }
    }

    pub fn release(p: *Pool, id: *const [32]u8, outcome: Outcome, connected: bool, now_ms: u64) void {
        p.mu.lock();
        defer p.mu.unlock();
        switch (outcome) {
            inline else => |o| @field(p.stats, @tagName(o)) += 1,
        }
        for (p.list.items) |*c| if (std.mem.eql(u8, &c.id, id)) {
            c.in_slot = false;
            c.last = outcome;
            if (connected) c.oks += 1;
            c.next_ms = now_ms + switch (outcome) {
                .ended => p.cfg.ended_ms,
                .silent => p.cfg.silent_ms,
                .refused => p.cfg.refused_ms,
                .wrong_peer => p.cfg.wrong_peer_ms,
                .local => p.cfg.local_ms,
            };
            return;
        };
    }

    /// Candidates whose backoff is over and that are not in a slot.
    pub fn due(p: *Pool, now_ms: u64) usize {
        p.mu.lock();
        defer p.mu.unlock();
        var n: usize = 0;
        p.mergeOverrides();
        var ovr: Overrides.Entry = undefined;
        for (p.list.items) |c| n += @intFromBool(!c.in_slot and c.next_ms <= now_ms and !p.isHeld(&c.id) and
            (c.n_addrs > 0 or (p.overrides.count() > 0 and p.overrides.get(&c.id, &ovr))));
        return n;
    }
};

fn testInfo(id: u8, ts: u64, addr: []const u8, access: discovery.AccessType) discovery.SignedInfo {
    const S = struct {
        var a: [8][]const u8 = undefined;
    };
    S.a[id % 8] = addr;
    return .{ .peer_id = @splat(id), .addresses = S.a[id % 8 ..][0..1], .timestamp_ms = ts, .access_type = access, .version = 1, .signed_bytes = "", .signature = @splat(0) };
}

test "pool: dial order, backoff by outcome, refresh" {
    var p: Pool = .{ .gpa = std.testing.allocator };
    defer p.deinit();
    try std.testing.expect(p.add(&testInfo(1, 100, "/ip4/1.1.1.1/udp/8084", .public)));
    try std.testing.expect(p.add(&testInfo(2, 300, "/dns/a.example/udp/8084", .public)));
    try std.testing.expect(p.add(&testInfo(3, 200, "/ip4/3.3.3.3/udp/8084", .public)));
    try std.testing.expect(!p.add(&testInfo(4, 200, "/ip4/4.4.4.4/udp/8084", .private)));
    try std.testing.expect(!p.add(&testInfo(5, 200, "/ip4/5.5.5.5/tcp/80", .public)));
    try std.testing.expectEqual(@as(usize, 3), p.count());
    var c: Candidate = undefined;
    // freshest never-tried first
    try std.testing.expect(p.take(1000, &c));
    try std.testing.expectEqual(@as(u8, 2), c.id[0]);
    try std.testing.expect(p.take(1000, &c));
    try std.testing.expectEqual(@as(u8, 3), c.id[0]);
    p.release(&@as([32]u8, @splat(2)), .silent, false, 1000);
    p.release(&@as([32]u8, @splat(3)), .ended, true, 1000);
    try std.testing.expect(p.take(1000, &c));
    try std.testing.expectEqual(@as(u8, 1), c.id[0]);
    try std.testing.expect(!p.take(1000, &c)); // 3 in its 2 s backoff, 2 in the silent hour
    try std.testing.expect(p.take(3000, &c)); // a peer that worked comes back first
    try std.testing.expectEqual(@as(u8, 3), c.id[0]);
    try std.testing.expect(!p.take(3000, &c));
    // a newer signed info with a new address lifts the silent backoff
    try std.testing.expect(!p.add(&testInfo(2, 400, "/ip4/2.2.2.2/udp/8084", .public)));
    try std.testing.expect(p.take(3000, &c));
    try std.testing.expectEqual(@as(u8, 2), c.id[0]);
    try std.testing.expectEqualStrings("/ip4/2.2.2.2/udp/8084", c.addr(0));
    try std.testing.expectEqual(@as(u64, 1), p.stats.silent);
}

test "pool: peers held elsewhere (seeds) are never handed to a slot" {
    var p: Pool = .{ .gpa = std.testing.allocator };
    defer p.deinit();
    _ = p.add(&testInfo(1, 100, "/ip4/1.1.1.1/udp/8084", .public));
    _ = p.add(&testInfo(2, 50, "/ip4/2.2.2.2/udp/8084", .public));
    p.hold(&@as([32]u8, @splat(1)));
    p.hold(&@as([32]u8, @splat(1)));
    try std.testing.expectEqual(@as(usize, 1), p.n_held);
    var c: Candidate = undefined;
    try std.testing.expect(p.take(1000, &c));
    try std.testing.expectEqual(@as(u8, 2), c.id[0]);
    try std.testing.expect(!p.take(1000, &c));
    try std.testing.expectEqual(@as(usize, 0), p.due(1000));
    p.deinit();
    try std.testing.expectEqual(@as(usize, 2), p.count());
}

test "pool: a refused or replaced peer keeps its 10 min backoff through re-signed infos" {
    var p: Pool = .{ .gpa = std.testing.allocator };
    defer p.deinit();
    _ = p.add(&testInfo(1, 100, "/ip4/1.1.1.1/udp/8084", .public));
    var c: Candidate = undefined;
    try std.testing.expect(p.take(1_000, &c));
    // connected, then the peer closed with code 0 within seconds (anemo replaced the connection)
    p.release(&c.id, .refused, true, 1_000);
    try std.testing.expect(!p.take(1_000 + 599_999, &c));
    // the peer re-signs its info (same address, then a new one): the wait holds
    try std.testing.expect(!p.add(&testInfo(1, 200, "/ip4/1.1.1.1/udp/8084", .public)));
    try std.testing.expect(!p.take(2_000, &c));
    try std.testing.expect(!p.add(&testInfo(1, 300, "/ip4/9.9.9.9/udp/8084", .public)));
    try std.testing.expect(!p.take(2_000, &c));
    try std.testing.expectEqual(@as(usize, 0), p.due(2_000));
    // over after 10 min, at the new address
    try std.testing.expect(p.take(1_000 + 600_000, &c));
    try std.testing.expectEqualStrings("/ip4/9.9.9.9/udp/8084", c.addr(0));
    try std.testing.expectEqual(@as(u64, 1), p.stats.refused);
}

test "pool: a silent peer's backoff lifts with a new address, not with a re-signed same address" {
    var p: Pool = .{ .gpa = std.testing.allocator };
    defer p.deinit();
    _ = p.add(&testInfo(3, 100, "/ip4/3.3.3.3/udp/8084", .public));
    var c: Candidate = undefined;
    try std.testing.expect(p.take(1_000, &c));
    p.release(&c.id, .silent, false, 1_000);
    try std.testing.expect(!p.add(&testInfo(3, 200, "/ip4/3.3.3.3/udp/8084", .public)));
    try std.testing.expect(!p.take(2_000, &c));
    try std.testing.expect(!p.add(&testInfo(3, 300, "/ip4/3.3.3.4/udp/8084", .public)));
    try std.testing.expect(p.take(2_000, &c));
}

test "pool: a seed held after a slot took it is not handed out again once released" {
    var p: Pool = .{ .gpa = std.testing.allocator };
    defer p.deinit();
    _ = p.add(&testInfo(5, 100, "/ip4/5.5.5.5/udp/8084", .public));
    var c: Candidate = undefined;
    try std.testing.expect(p.take(1_000, &c));
    // the slot found a seed's address and held the id instead of dialling (p2p.zig slotLoop)
    p.hold(&c.id);
    p.release(&c.id, .local, false, 1_000);
    try std.testing.expect(!p.take(1_000 + 3_600_000 * 24, &c));
}

test "pool: freshness, daily cull, and restricted peers only when trusted" {
    var p: Pool = .{ .gpa = std.testing.allocator, .trusted = &.{@as([32]u8, @splat(4))} };
    defer p.deinit();
    const day = one_day_ms;
    const now = 10 * day;
    // a day old or 30 s ahead: skipped
    try std.testing.expect(!p.addFresh(&testInfo(1, now - day - 1, "/ip4/1.1.1.1/udp/8084", .public), now));
    try std.testing.expect(!p.addFresh(&testInfo(1, now + 30_001, "/ip4/1.1.1.1/udp/8084", .public), now));
    try std.testing.expectEqual(@as(u64, 2), p.stats.stale);
    try std.testing.expect(p.addFresh(&testInfo(1, now - 1000, "/ip4/1.1.1.1/udp/8084", .public), now));
    // Private: only a trusted (allowlisted or seed) peer is dialable
    try std.testing.expect(p.addFresh(&testInfo(4, now, "/ip4/4.4.4.4/udp/8084", .private), now));
    try std.testing.expect(!p.addFresh(&testInfo(5, now, "/ip4/5.5.5.5/udp/8084", .trusted), now));
    try std.testing.expectEqual(@as(usize, 2), p.count());
    // a day later peer 1 goes, peer 4 (in a slot) stays
    var c: Candidate = undefined;
    try std.testing.expect(p.take(now, &c));
    try std.testing.expectEqual(@as(u8, 4), c.id[0]);
    try std.testing.expectEqual(@as(usize, 1), p.cull(now + day + 1));
    try std.testing.expectEqual(@as(usize, 1), p.count());
    p.release(&c.id, .ended, true, now + day + 1);
    try std.testing.expectEqual(@as(usize, 1), p.cull(now + 2 * day + 1));
    try std.testing.expectEqual(@as(usize, 0), p.count());
}

test "pool: admin overrides win, add unknown peers, lift backoff, clear" {
    var o: Overrides = .{};
    defer o.clear();
    var p: Pool = .{ .gpa = std.testing.allocator, .overrides = &o };
    defer p.deinit();
    _ = p.add(&testInfo(1, 100, "/ip4/1.1.1.1/udp/8084", .public));
    _ = p.add(&testInfo(2, 300, "/ip4/2.2.2.2/udp/8084", .public));
    var c: Candidate = undefined;
    try std.testing.expect(p.take(1_000, &c));
    try std.testing.expectEqual(@as(u8, 2), c.id[0]);
    p.release(&c.id, .silent, false, 1_000);
    // override peer 2 (in its silent hour) and add an unknown peer 9
    try o.set(&@as([32]u8, @splat(2)), &.{"/ip4/7.7.7.7/udp/1"});
    try o.set(&@as([32]u8, @splat(9)), &.{ "/dns/n.example/udp/2", "/ip4/9.9.9.9/udp/3" });
    // both overridden peers come first (fresher signed info first; 9 has none), at the
    // override addresses
    try std.testing.expect(p.take(2_000, &c));
    try std.testing.expectEqual(@as(u8, 2), c.id[0]);
    try std.testing.expectEqual(@as(u8, 1), c.n_addrs);
    try std.testing.expectEqualStrings("/ip4/7.7.7.7/udp/1", c.addr(0));
    try std.testing.expect(p.take(2_000, &c));
    try std.testing.expectEqual(@as(u8, 9), c.id[0]);
    try std.testing.expectEqual(@as(u8, 2), c.n_addrs);
    try std.testing.expectEqualStrings("/ip4/9.9.9.9/udp/3", c.addr(1));
    try std.testing.expect(p.take(2_000, &c));
    try std.testing.expectEqual(@as(u8, 1), c.id[0]);
    // an empty list removes the override: peer 9 has no address of its own and is never taken
    try o.set(&@as([32]u8, @splat(9)), &.{});
    try std.testing.expectEqual(@as(usize, 1), o.count());
    p.release(&@as([32]u8, @splat(9)), .ended, true, 2_000);
    try std.testing.expect(!p.take(10_000, &c));
    try std.testing.expectEqual(@as(usize, 0), p.due(10_000));
}
