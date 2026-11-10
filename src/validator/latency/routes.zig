//! DoubleZero / colocation as configuration (docs/VALIDATOR-DESIGN.md 10.7): alternate addresses
//! for consensus traffic. A peer keeps its committee address (the primary path) and may list up
//! to `max_alts` more, for example its DoubleZero overlay address or a colocated private
//! address. The dialer asks `Routes.pick` which address to use for a peer and reports the
//! outcome with `record`. Nothing here opens a socket, and nothing changes with an empty
//! config: every peer then has exactly its committee address.
//!
//! Identity is unchanged: every path to a peer reaches the same Ed25519 network key, so the
//! committee-pinned TLS check of consensus_net applies to every alternate unchanged.
//! Safety gate: every address a validator would dial must go through `gate.decide`, alternates
//! included. `allAddresses` returns the complete list for that request.
//!
//! Config text, one directive per line, `#` comments:
//!   mode primary_only | prefer_alt | alt_only | auto      (default primary_only)
//!   alt <authority index> <address>                        (multiaddr or host:port; repeatable)
//!   fail_backoff_ms <n>                                    (default 2000)
//! Modes: primary_only ignores alternates; prefer_alt tries alternates first, falling back to
//! the primary on failure; alt_only never uses the primary; auto measures each path (EWMA of
//! the connect round trip) and picks the fastest, probing the others now and then.
const std = @import("std");
const consensus = @import("consensus");

pub const max_alts = 4;
pub const max_paths = 1 + max_alts;

pub const Mode = enum { primary_only, prefer_alt, alt_only, auto };

pub const ParseError = error{ BadDirective, BadIndex, BadMode, TooManyAlts, EmptyAddress, OutOfMemory };

const Path = struct {
    addr: []const u8 = "",
    /// EWMA of the dial round trip in us (0 = never measured).
    ewma_us: u64 = 0,
    fails: u32 = 0,
    retry_after_ns: u64 = 0,
    uses: u64 = 0,
};

const Peer = struct {
    paths: [max_paths]Path = @splat(.{}),
    n: u8 = 1,
    dials: u64 = 0,
};

pub const Routes = struct {
    arena: std.heap.ArenaAllocator,
    peers: []Peer,
    mode: Mode = .primary_only,
    fail_backoff_ns: u64 = 2000 * std.time.ns_per_ms,
    /// auto mode explores a non-best path every this many dials.
    explore_every: u64 = 32,

    pub fn init(gpa: std.mem.Allocator, committee: *const consensus.committee.Committee) std.mem.Allocator.Error!Routes {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const peers = try arena.allocator().alloc(Peer, committee.size());
        for (peers, committee.authorities) |*p, a| {
            p.* = .{};
            p.paths[0].addr = try arena.allocator().dupe(u8, a.address);
        }
        return .{ .arena = arena, .peers = peers };
    }

    pub fn deinit(r: *Routes) void {
        r.arena.deinit();
    }

    pub fn addAlt(r: *Routes, authority: usize, addr: []const u8) ParseError!void {
        if (authority >= r.peers.len) return error.BadIndex;
        if (addr.len == 0) return error.EmptyAddress;
        const p = &r.peers[authority];
        if (p.n >= max_paths) return error.TooManyAlts;
        p.paths[p.n].addr = try r.arena.allocator().dupe(u8, addr);
        p.n += 1;
    }

    pub fn parse(r: *Routes, text: []const u8) ParseError!void {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, if (std.mem.indexOfScalar(u8, raw, '#')) |i| raw[0..i] else raw, " \t\r");
            if (line.len == 0) continue;
            var it = std.mem.tokenizeAny(u8, line, " \t");
            const dir = it.next().?;
            if (std.mem.eql(u8, dir, "mode")) {
                const m = it.next() orelse return error.BadMode;
                r.mode = std.meta.stringToEnum(Mode, m) orelse return error.BadMode;
            } else if (std.mem.eql(u8, dir, "alt")) {
                const idx = std.fmt.parseInt(usize, it.next() orelse return error.BadIndex, 10) catch return error.BadIndex;
                try r.addAlt(idx, it.next() orelse return error.EmptyAddress);
            } else if (std.mem.eql(u8, dir, "fail_backoff_ms")) {
                const ms = std.fmt.parseInt(u64, it.next() orelse return error.BadDirective, 10) catch return error.BadDirective;
                r.fail_backoff_ns = std.math.mul(u64, ms, std.time.ns_per_ms) catch return error.BadDirective;
            } else return error.BadDirective;
            if (it.next() != null) return error.BadDirective;
        }
    }

    /// Every address this validator might dial (primaries and alternates), for `gate.decide`.
    /// Caller owns the slice (strings are borrowed from the Routes).
    pub fn allAddresses(r: *const Routes, gpa: std.mem.Allocator) std.mem.Allocator.Error![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        errdefer out.deinit(gpa);
        for (r.peers) |*p| {
            for (p.paths[0..p.n], 0..) |*pa, i| {
                if (i != 0 and r.mode == .primary_only) continue;
                try out.append(gpa, pa.addr);
            }
        }
        return out.toOwnedSlice(gpa);
    }

    pub const Pick = struct { path: u8, addr: []const u8 };

    /// The address to dial for `authority` now. null only for alt_only with no alternate, or a
    /// bad index.
    pub fn pick(r: *Routes, authority: usize, now_ns: u64) ?Pick {
        if (authority >= r.peers.len) return null;
        const p = &r.peers[authority];
        p.dials += 1;
        const first: u8 = if (r.mode == .alt_only) 1 else 0;
        if (first >= p.n) return null;
        const chosen: u8 = switch (r.mode) {
            .primary_only => 0,
            .prefer_alt, .alt_only => blk: {
                // preference order: alternates first (prefer_alt), the primary last. The first
                // path not backing off wins; else the one that retries soonest.
                const last: u8 = p.n; // exclusive
                const start: u8 = if (r.mode == .prefer_alt and p.n > 1) 1 else first;
                var best: u8 = start;
                var k: u8 = 0;
                const total: u8 = last - first;
                while (k < total) : (k += 1) {
                    // rotate through [start..last) then wrap to [first..start)
                    var i: u8 = start + k;
                    if (i >= last) i = first + (i - last);
                    if (p.paths[i].retry_after_ns <= now_ns) {
                        best = i;
                        break;
                    }
                    if (p.paths[i].retry_after_ns < p.paths[best].retry_after_ns) best = i;
                }
                break :blk best;
            },
            .auto => blk: {
                var best: ?u8 = null;
                for (p.paths[0..p.n], 0..) |*pa, i| {
                    if (pa.retry_after_ns > now_ns) continue;
                    const idx: u8 = @intCast(i);
                    if (best == null) {
                        best = idx;
                        continue;
                    }
                    const b = &p.paths[best.?];
                    // unmeasured paths are tried before measured ones
                    if (pa.ewma_us == 0 and b.ewma_us != 0) {
                        best = idx;
                    } else if (pa.ewma_us != 0 and b.ewma_us != 0 and pa.ewma_us < b.ewma_us) {
                        best = idx;
                    }
                }
                var c = best orelse 0;
                if (p.n > 1 and p.dials % @max(r.explore_every, 1) == 0) c = @intCast((c + 1) % p.n);
                break :blk c;
            },
        };
        p.paths[chosen].uses += 1;
        return .{ .path = chosen, .addr = p.paths[chosen].addr };
    }

    /// Dial outcome: `rtt_us` on success (a failure passes null).
    pub fn record(r: *Routes, authority: usize, path: u8, rtt_us: ?u64, now_ns: u64) void {
        if (authority >= r.peers.len) return;
        const p = &r.peers[authority];
        if (path >= p.n) return;
        const pa = &p.paths[path];
        if (rtt_us) |v| {
            pa.fails = 0;
            pa.retry_after_ns = 0;
            pa.ewma_us = if (pa.ewma_us == 0) @max(v, 1) else (pa.ewma_us * 7 + v) / 8;
        } else {
            pa.fails +|= 1;
            const shift: u6 = @intCast(@min(pa.fails - 1, 5));
            pa.retry_after_ns = now_ns +| (std.math.shlExact(u64, r.fail_backoff_ns, shift) catch std.math.maxInt(u64));
        }
    }
};

fn testCommittee(auths: []consensus.committee.Authority) !consensus.committee.Committee {
    for (auths) |*a| {
        a.* = .{ .stake = 1, .address = "/ip4/10.0.0.1/tcp/8080", .hostname = "", .authority_name = "", .protocol_key = @as([32]u8, @splat(0)), .network_key = @as([32]u8, @splat(0)) };
    }
    return consensus.committee.Committee.init(0, auths);
}

test "empty config: primary only" {
    var auths: [4]consensus.committee.Authority = undefined;
    const c = try testCommittee(&auths);
    var r = try Routes.init(std.testing.allocator, &c);
    defer r.deinit();
    const p = r.pick(2, 0).?;
    try std.testing.expectEqual(@as(u8, 0), p.path);
    try std.testing.expectEqualStrings("/ip4/10.0.0.1/tcp/8080", p.addr);
    try std.testing.expect(r.pick(9, 0) == null);
}

test "parse, prefer_alt with failover and backoff" {
    var auths: [4]consensus.committee.Authority = undefined;
    const c = try testCommittee(&auths);
    var r = try Routes.init(std.testing.allocator, &c);
    defer r.deinit();
    try r.parse("# doublezero\nmode prefer_alt\nalt 1 /ip4/10.9.0.2/tcp/8080\nfail_backoff_ms 100\n");
    try std.testing.expectEqual(Mode.prefer_alt, r.mode);
    const p = r.pick(1, 0).?;
    try std.testing.expectEqual(@as(u8, 1), p.path);
    r.record(1, 1, null, 1_000);
    // alt backing off: falls to the primary
    try std.testing.expectEqual(@as(u8, 0), r.pick(1, 2_000).?.path);
    // after the backoff the alt is back
    try std.testing.expectEqual(@as(u8, 1), r.pick(1, 1_000 + 100 * std.time.ns_per_ms + 1).?.path);
    // peers without alts use the primary
    try std.testing.expectEqual(@as(u8, 0), r.pick(0, 0).?.path);
    const all = try r.allAddresses(std.testing.allocator);
    defer std.testing.allocator.free(all);
    try std.testing.expectEqual(@as(usize, 5), all.len);
    try std.testing.expectError(error.BadDirective, r.parse("frob 1"));
    try std.testing.expectError(error.BadIndex, r.parse("alt 9 x"));
    try std.testing.expectError(error.BadMode, r.parse("mode sideways"));
}

test "alt_only and auto" {
    var auths: [4]consensus.committee.Authority = undefined;
    const c = try testCommittee(&auths);
    var r = try Routes.init(std.testing.allocator, &c);
    defer r.deinit();
    try r.addAlt(0, "10.9.0.1:8080");
    r.mode = .alt_only;
    try std.testing.expectEqual(@as(u8, 1), r.pick(0, 0).?.path);
    try std.testing.expect(r.pick(3, 0) == null); // no alternate
    r.mode = .auto;
    r.explore_every = 1000;
    r.peers[0].dials = 1; // avoid the exploration slot
    r.record(0, 0, 400, 0);
    r.record(0, 1, 150, 0);
    try std.testing.expectEqual(@as(u8, 1), r.pick(0, 0).?.path);
    r.record(0, 1, null, 10);
    try std.testing.expectEqual(@as(u8, 0), r.pick(0, 11).?.path);
}
