//! Lease and fencing protocol for hot standby (docs/STANDBY.md). Pure state machines: no sockets,
//! no clocks, no files. Time comes in as monotonic nanoseconds, the wall clock only as a
//! replay-window input. Everything here is unit-tested and simulated in sim_test.zig.
//!
//! Model. N acceptors (odd, normally 3: primary box, standby box, a witness) each keep one lease
//! register (term, holder) and a local expiry. A node leads for as long as a MAJORITY of acceptors
//! granted it a lease. The term is the fencing token: it only ever grows, each term belongs to
//! exactly one holder, and every action that must not be duplicated (serving a client, signing)
//! carries the term so a stale holder is refused downstream.
//!
//! Safety (no two leaders at the same instant, as long as clock RATES differ by less than
//! margin/lease):
//!   * an acceptor grants term T to holder H only if T is above its term and its current lease has
//!     expired by ITS clock, or T equals its term and H is the holder (a renewal);
//!   * a holder counts a lease from the instant it SENT the request, so it always ends before the
//!     acceptor's copy (which starts at receipt), minus `margin_ms` for rate drift and for the
//!     time the on-lose hook needs;
//!   * two majorities share an acceptor, which cannot hold two leases at once.
//! An acceptor that restarts assumes a full lease is outstanding for `max_lease_ms` (it only
//! persists term, holder and the lease length, never a clock), so a reboot can only delay a takeover.
//! Liveness is best effort: split votes retry with a random delay, a minority partition leads
//! nothing, a lost holder is replaced `lease_ms` after its last renewal.
const std = @import("std");

pub const max_acceptors = 7;
const ms = std.time.ns_per_ms;

pub const Kind = enum(u8) { acquire = 1, release = 2, query = 3, reply = 0x80 };

/// One datagram body, request and reply alike (`ok`, `remaining_ms` and `acceptor` are reply-only).
pub const Msg = struct {
    kind: Kind,
    ok: bool = false,
    /// Requester's nonce, echoed in the reply. Strictly increasing per holder.
    seq: u64,
    /// Requester's wall clock (unix ms): bounds how old a replayed request can be.
    wall_ms: u64 = 0,
    /// Request: the term asked for. Reply: the acceptor's current term.
    term: u64,
    /// Request: who asks. Reply: the acceptor's current holder (0 none).
    holder: u64,
    lease_ms: u32 = 0,
    /// Reply: how much of the current lease is left on the acceptor's clock.
    remaining_ms: u32 = 0,
    acceptor: u64 = 0,

    pub const body_len = 56;
    pub const tag_len = 32;
    pub const wire_len = body_len + tag_len;
    const magic: u32 = 0x31534c5a; // "ZLS1"
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

    pub fn encode(m: Msg, key: *const [32]u8, out: *[wire_len]u8) void {
        std.mem.writeInt(u32, out[0..4], magic, .little);
        out[4] = @intFromEnum(m.kind);
        out[5] = @intFromBool(m.ok);
        std.mem.writeInt(u16, out[6..8], 0, .little);
        std.mem.writeInt(u64, out[8..16], m.seq, .little);
        std.mem.writeInt(u64, out[16..24], m.wall_ms, .little);
        std.mem.writeInt(u64, out[24..32], m.term, .little);
        std.mem.writeInt(u64, out[32..40], m.holder, .little);
        std.mem.writeInt(u32, out[40..44], m.lease_ms, .little);
        std.mem.writeInt(u32, out[44..48], m.remaining_ms, .little);
        std.mem.writeInt(u64, out[48..56], m.acceptor, .little);
        Hmac.create(out[body_len..][0..tag_len], out[0..body_len], key);
    }

    pub const DecodeError = error{ BadLength, BadMagic, BadKind, BadTag };

    pub fn decode(bytes: []const u8, key: *const [32]u8) DecodeError!Msg {
        if (bytes.len != wire_len) return error.BadLength;
        if (std.mem.readInt(u32, bytes[0..4], .little) != magic) return error.BadMagic;
        var want: [tag_len]u8 = undefined;
        Hmac.create(&want, bytes[0..body_len], key);
        if (!std.crypto.timing_safe.eql([tag_len]u8, want, bytes[body_len..][0..tag_len].*)) return error.BadTag;
        const kind = std.enums.fromInt(Kind, bytes[4]) orelse return error.BadKind;
        return .{
            .kind = kind,
            .ok = bytes[5] != 0,
            .seq = std.mem.readInt(u64, bytes[8..16], .little),
            .wall_ms = std.mem.readInt(u64, bytes[16..24], .little),
            .term = std.mem.readInt(u64, bytes[24..32], .little),
            .holder = std.mem.readInt(u64, bytes[32..40], .little),
            .lease_ms = std.mem.readInt(u32, bytes[40..44], .little),
            .remaining_ms = std.mem.readInt(u32, bytes[44..48], .little),
            .acceptor = std.mem.readInt(u64, bytes[48..56], .little),
        };
    }
};

/// A holder's name on the wire: the first 8 bytes of SHA-256 of the name, never 0.
pub fn holderId(name: []const u8) u64 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &h, .{});
    const v = std.mem.readInt(u64, h[0..8], .little);
    return if (v == 0) 1 else v;
}

// ------------------------------------------------------------------------------------ acceptor

/// What an acceptor must keep across restarts (and nothing else).
pub const State = struct {
    term: u64 = 0,
    holder: u64 = 0,
    /// Length of the last lease granted: after a restart that much is assumed outstanding.
    lease_ms: u32 = 0,

    pub const file_len = 8 + 8 + 4 + 4;
    /// `term holder lease_ms crc32`, little endian.
    pub fn encode(s: State, out: *[file_len]u8) void {
        std.mem.writeInt(u64, out[0..8], s.term, .little);
        std.mem.writeInt(u64, out[8..16], s.holder, .little);
        std.mem.writeInt(u32, out[16..20], s.lease_ms, .little);
        std.mem.writeInt(u32, out[20..24], std.hash.Crc32.hash(out[0..20]), .little);
    }
    pub fn decode(b: []const u8) ?State {
        if (b.len != file_len) return null;
        if (std.mem.readInt(u32, b[20..24], .little) != std.hash.Crc32.hash(b[0..20])) return null;
        return .{ .term = std.mem.readInt(u64, b[0..8], .little), .holder = std.mem.readInt(u64, b[8..16], .little), .lease_ms = std.mem.readInt(u32, b[16..20], .little) };
    }
};

pub const AcceptorConfig = struct {
    id: u64,
    /// Longest lease an acceptor grants; also what it assumes is outstanding after a restart.
    max_lease_ms: u32 = 60_000,
    /// Replay window for `wall_ms`.
    max_skew_ms: u64 = 5_000,
};

pub const Acceptor = struct {
    cfg: AcceptorConfig,
    st: State,
    /// The last state known to be on disk. A grant is only announced after `st` equals this, so
    /// a failed write is retried by the next request instead of being announced unpersisted.
    persisted: State,
    /// Monotonic ns at which the current lease ends on this acceptor's clock.
    until_ns: u64,
    seqs: [16]struct { holder: u64 = 0, seq: u64 = 0 } = @splat(.{}),

    pub fn init(cfg: AcceptorConfig, st: State, now_ns: u64) Acceptor {
        return .{ .cfg = cfg, .st = st, .persisted = st, .until_ns = if (st.holder != 0) now_ns + @as(u64, if (st.lease_ms == 0) cfg.max_lease_ms else @min(st.lease_ms, cfg.max_lease_ms)) * ms else now_ns };
    }

    pub const Outcome = struct {
        reply: Msg,
        /// Non-null: write this state durably BEFORE sending `reply` (a grant that was not
        /// persisted must not be announced; the in-memory lease then only delays others).
        persist: ?State = null,
    };

    fn remaining(a: *const Acceptor, now_ns: u64) u32 {
        if (a.st.holder == 0 or now_ns >= a.until_ns) return 0;
        return @intCast(@min((a.until_ns - now_ns + ms - 1) / ms, std.math.maxInt(u32)));
    }

    fn reply(a: *const Acceptor, req: Msg, ok: bool, now_ns: u64) Msg {
        return .{ .kind = .reply, .ok = ok, .seq = req.seq, .term = a.st.term, .holder = if (a.remaining(now_ns) == 0) 0 else a.st.holder, .remaining_ms = a.remaining(now_ns), .acceptor = a.cfg.id };
    }

    /// False for a nonce not above the last one from this holder (a replay or a reorder).
    fn freshSeq(a: *Acceptor, holder: u64, seq: u64) bool {
        var free: ?usize = null;
        for (&a.seqs, 0..) |*e, i| {
            if (e.holder == holder) {
                if (seq <= e.seq) return false;
                e.seq = seq;
                return true;
            }
            if (e.holder == 0 and free == null) free = i;
        }
        const i = free orelse @as(usize, @intCast(holder % a.seqs.len)); // table full: evict a slot
        a.seqs[i] = .{ .holder = holder, .seq = seq };
        return true;
    }

    /// Replies, and anything without a sender, get no answer at all (an answer to a reply would
    /// let two acceptors ping-pong forever off one spoofed packet).
    pub fn answers(req: Msg) bool {
        return req.kind != .reply and req.holder != 0;
    }

    /// The caller reports a successful durable write of `persist`.
    pub fn markPersisted(a: *Acceptor, st: State) void {
        a.persisted = st;
    }

    pub fn handle(a: *Acceptor, now_ns: u64, wall_ms: u64, req: Msg) Outcome {
        if (!answers(req)) return .{ .reply = a.reply(req, false, now_ns) };
        // Queries are read-only: no replay window, no nonce.
        if (req.kind == .query) return .{ .reply = a.reply(req, true, now_ns) };
        const skew = if (wall_ms > req.wall_ms) wall_ms - req.wall_ms else req.wall_ms - wall_ms;
        if (skew > a.cfg.max_skew_ms or !a.freshSeq(req.holder, req.seq)) return .{ .reply = a.reply(req, false, now_ns) };
        switch (req.kind) {
            .release => {
                // Only the holder of exactly this term gives a lease back early.
                if (a.st.holder == req.holder and a.st.term == req.term) a.until_ns = now_ns;
                return .{ .reply = a.reply(req, true, now_ns) };
            },
            .acquire => {
                if (req.lease_ms == 0 or req.lease_ms > a.cfg.max_lease_ms) return .{ .reply = a.reply(req, false, now_ns) };
                const live = a.remaining(now_ns) != 0;
                const renew = req.term == a.st.term and req.holder == a.st.holder;
                const take = req.term > a.st.term and (!live or req.holder == a.st.holder);
                if (!renew and !take) return .{ .reply = a.reply(req, false, now_ns) };
                a.st = .{ .term = req.term, .holder = req.holder, .lease_ms = req.lease_ms };
                a.until_ns = now_ns + @as(u64, req.lease_ms) * ms;
                const changed = !std.meta.eql(a.st, a.persisted);
                return .{ .reply = a.reply(req, true, now_ns), .persist = if (changed) a.st else null };
            },
            else => unreachable,
        }
    }
};

// ------------------------------------------------------------------------------------- agent

pub const Params = struct {
    /// Lease length asked of the acceptors.
    lease_ms: u32 = 6000,
    /// Round cadence (renewals as leader, attempts as follower).
    renew_ms: u32 = 1500,
    /// Leader stops this long before the lease ends on its own clock: clock-rate drift plus the
    /// time the on-lose hook may take. Must stay below lease_ms - 2 * renew_ms.
    margin_ms: u32 = 1500,
    /// A round without a majority after this long is over.
    round_timeout_ms: u32 = 700,
    /// A follower waits this long after it saw the lease free before it tries (the preferred
    /// box uses 0, the other box a few seconds, so the preferred box wins a race).
    priority_delay_ms: u32 = 0,

    pub const Error = error{ BadParams };
    pub fn check(p: Params) Error!void {
        if (p.renew_ms == 0 or p.round_timeout_ms == 0 or p.lease_ms == 0) return error.BadParams;
        if (p.round_timeout_ms >= p.renew_ms) return error.BadParams;
        if (@as(u64, p.margin_ms) + 2 * @as(u64, p.renew_ms) >= p.lease_ms) return error.BadParams;
    }
};

pub const Event = enum { none, acquired, renewed, lost };

pub const Agent = struct {
    p: Params,
    id: u64,
    n: u8,
    rng: std.Random.DefaultPrng,

    /// Highest term seen in any reply (or held).
    max_term: u64 = 0,
    /// The term held, or asked for in the open round.
    term: u64 = 0,
    leader: bool = false,
    /// Wanted: false makes a leader step down and a follower stay passive (the local deepwave is unhealthy).
    healthy: bool = true,
    /// Monotonic ns up to which the lease holds on OUR clock, margin already taken off.
    valid_until_ns: u64 = 0,

    round_open: bool = false,
    round_kind: Kind = .query,
    round_seq: u64 = 0,
    round_sent_ns: u64 = 0,
    round_term: u64 = 0,
    replied: u8 = 0, // bit per acceptor that answered this round
    grants: u8 = 0,
    free_votes: u8 = 0,
    higher_term_seen: bool = false,
    next_round_ns: u64 = 0,
    free_since_ns: ?u64 = null,
    seq_counter: u64 = 0,
    /// Term whose partial grants should be released (consumed by `takeRelease`).
    pending_release: u64 = 0,

    pub fn init(p: Params, id: u64, n_acceptors: u8, seed: u64) Params.Error!Agent {
        try p.check();
        std.debug.assert(n_acceptors >= 1 and n_acceptors <= max_acceptors and id != 0);
        return .{ .p = p, .id = id, .n = n_acceptors, .rng = std.Random.DefaultPrng.init(seed) };
    }

    fn majority(a: *const Agent) u8 {
        return a.n / 2 + 1;
    }

    /// Leading right now: a majority lease that has not ended on our clock.
    pub fn isLeader(a: *const Agent, now_ns: u64) bool {
        return a.leader and now_ns < a.valid_until_ns;
    }

    /// The fencing token to stamp on actions: the held term, or 0 when not leading.
    pub fn fence(a: *const Agent, now_ns: u64) u64 {
        return if (a.isLeader(now_ns)) a.term else 0;
    }

    /// Call often (every few ms is fine). Returns an event for a lease that just ran out, and the
    /// request to broadcast to every acceptor when a round starts now.
    pub const Step = struct { event: Event = .none, send: ?Msg = null };

    pub fn poll(a: *Agent, now_ns: u64, wall_ms: u64) Step {
        var st: Step = .{};
        if (a.leader and now_ns >= a.valid_until_ns) {
            a.leader = false;
            st.event = .lost;
        }
        if (a.round_open and now_ns >= a.round_sent_ns + @as(u64, a.p.round_timeout_ms) * ms) {
            const e = a.finishRound(now_ns, false);
            if (e != .none) st.event = e;
        }
        if (a.round_open or now_ns < a.next_round_ns) return st;
        // A leader that is unhealthy gives the lease up; a follower that is unhealthy stays out.
        if (!a.healthy) {
            if (a.leader) {
                a.leader = false;
                st.event = .lost;
                st.send = a.openRound(now_ns, wall_ms, .release, a.term);
                return st;
            }
            a.next_round_ns = now_ns + @as(u64, a.p.renew_ms) * ms;
            return st;
        }
        var kind: Kind = .acquire;
        var term = a.term;
        if (!a.leader) {
            term = a.max_term + 1;
            if (a.p.priority_delay_ms > 0) {
                const free = a.free_since_ns orelse 0;
                if (a.free_since_ns == null or now_ns < free + @as(u64, a.p.priority_delay_ms) * ms) kind = .query;
            }
        }
        st.send = a.openRound(now_ns, wall_ms, kind, term);
        return st;
    }

    fn openRound(a: *Agent, now_ns: u64, wall_ms: u64, kind: Kind, term: u64) Msg {
        a.seq_counter += 1;
        // Wall ns in the high bits keeps nonces rising across restarts; the counter breaks ties.
        a.round_seq = (wall_ms << 20) + (a.seq_counter & 0xfffff);
        a.round_open = true;
        a.round_kind = kind;
        a.round_sent_ns = now_ns;
        a.round_term = term;
        a.replied = 0;
        a.grants = 0;
        a.free_votes = 0;
        a.higher_term_seen = false;
        return .{ .kind = kind, .seq = a.round_seq, .wall_ms = wall_ms, .term = term, .holder = a.id, .lease_ms = if (kind == .acquire) a.p.lease_ms else 0 };
    }

    /// One reply from acceptor `idx`. Returns the event the reply completed, if any.
    pub fn onReply(a: *Agent, now_ns: u64, idx: u8, r: Msg) Event {
        if (!a.round_open or idx >= a.n or r.kind != .reply or r.seq != a.round_seq) return .none;
        const bit = @as(u8, 1) << @intCast(idx);
        if (a.replied & bit != 0) return .none;
        a.replied |= bit;
        a.max_term = @max(a.max_term, r.term);
        if (r.ok and a.round_kind == .acquire) a.grants |= bit;
        if (r.term > a.round_term) a.higher_term_seen = true;
        if (r.remaining_ms == 0 or r.holder == a.id) a.free_votes += 1;
        if (@popCount(a.grants) >= a.majority()) return a.finishRound(now_ns, true);
        // Everyone answered: no need to wait for the timeout.
        if (@popCount(a.replied) == a.n) return a.finishRound(now_ns, false);
        return .none;
    }

    fn finishRound(a: *Agent, now_ns: u64, won: bool) Event {
        a.round_open = false;
        const renew_ns = @as(u64, a.p.renew_ms) * ms;
        var ev: Event = .none;
        if (a.round_kind == .release) {
            a.next_round_ns = now_ns + renew_ns;
            return .none;
        }
        // Whether the lease looks free to a majority (used for the priority delay).
        if (a.free_votes >= a.majority()) {
            if (a.free_since_ns == null) a.free_since_ns = now_ns;
        } else a.free_since_ns = null;
        if (won) {
            const end = a.round_sent_ns + (@as(u64, a.p.lease_ms) - a.p.margin_ms) * ms;
            if (end > now_ns) {
                const was = a.leader;
                a.leader = true;
                a.term = a.round_term;
                a.max_term = @max(a.max_term, a.term);
                a.valid_until_ns = @max(a.valid_until_ns, end);
                ev = if (was) .renewed else .acquired;
            }
            // Next renewal is counted from the round start, so a slow round does not stretch the cadence.
            a.next_round_ns = a.round_sent_ns + renew_ns;
            return ev;
        }
        // Lost round. Hand partial grants back at once so a split vote does not block everyone
        // for a lease length; the caller sends the release from `poll` (below) via `pending`.
        if (a.grants != 0 and !a.leader) a.pending_release = a.round_term;
        if (a.leader and a.higher_term_seen) {
            // Someone else holds a newer term: we are out whatever our clock says.
            a.leader = false;
            ev = .lost;
        }
        // Random delay after a failed attempt breaks symmetric split votes.
        const jitter = a.rng.random().uintLessThan(u64, @max(1, renew_ns / ms)) * ms;
        a.next_round_ns = if (a.leader) a.round_sent_ns + renew_ns else now_ns + renew_ns / 2 + jitter;
        return ev;
    }

    pub fn takeRelease(a: *Agent, now_ns: u64, wall_ms: u64) ?Msg {
        if (a.pending_release == 0 or a.round_open) return null;
        const t = a.pending_release;
        a.pending_release = 0;
        return a.openRound(now_ns, wall_ms, .release, t);
    }

    /// Orderly stop (shutdown, planned switchover): not leading from now on; the returned release
    /// frees the lease on the acceptors so the other box takes over at once.
    pub fn stepDown(a: *Agent, now_ns: u64, wall_ms: u64) ?Msg {
        const was = a.leader;
        a.leader = false;
        a.healthy = false;
        a.round_open = false;
        if (!was) return null;
        return a.openRound(now_ns, wall_ms, .release, a.term);
    }
};

test "acceptor: grant, renew, refuse a live lease, take over after expiry" {
    var a = Acceptor.init(.{ .id = 7, .max_skew_ms = 1 << 40 }, .{}, 0);
    const base: Msg = .{ .kind = .acquire, .seq = 1, .wall_ms = 1000, .term = 1, .holder = 11, .lease_ms = 6000 };
    var o = a.handle(0, 1000, base);
    try std.testing.expect(o.reply.ok);
    try std.testing.expectEqual(State{ .term = 1, .holder = 11, .lease_ms = 6000 }, o.persist.?);
    a.markPersisted(o.persist.?);
    // renewal does not need a persist
    var r = base;
    r.seq = 2;
    o = a.handle(2000 * ms, 3000, r);
    try std.testing.expect(o.reply.ok and o.persist == null);
    // another holder, higher term, lease live: refused
    var b = base;
    b.holder = 22;
    b.term = 2;
    b.seq = 1;
    o = a.handle(3000 * ms, 4000, b);
    try std.testing.expect(!o.reply.ok);
    try std.testing.expectEqual(@as(u64, 11), o.reply.holder);
    // same term, other holder: refused even after expiry
    b.term = 1;
    b.seq = 2;
    o = a.handle(20_000 * ms, 21000, b);
    try std.testing.expect(!o.reply.ok);
    // after expiry a higher term wins
    b.term = 2;
    b.seq = 3;
    o = a.handle(20_000 * ms, 21000, b);
    try std.testing.expect(o.reply.ok);
    // the old holder cannot renew term 1 any more
    r.seq = 3;
    o = a.handle(21_000 * ms, 22000, r);
    try std.testing.expect(!o.reply.ok);
    // replay of an older nonce, and a stale wall clock, are dropped
    b.seq = 3;
    try std.testing.expect(!a.handle(21_000 * ms, 22000, b).reply.ok);
    b.seq = 9;
    b.wall_ms = 1;
    a.cfg.max_skew_ms = 5000;
    try std.testing.expect(!a.handle(21_000 * ms, 22000, b).reply.ok);
}

test "acceptor: restart assumes an outstanding lease; release frees it" {
    var a = Acceptor.init(.{ .id = 1, .max_lease_ms = 10_000 }, .{ .term = 4, .holder = 9 }, 100 * ms);
    var q: Msg = .{ .kind = .acquire, .seq = 1, .wall_ms = 5, .term = 5, .holder = 3, .lease_ms = 5000 };
    try std.testing.expect(!a.handle(105 * ms, 5, q).reply.ok);
    q.seq = 2;
    try std.testing.expect(a.handle(10_200 * ms, 5, q).reply.ok);
    var a2 = Acceptor.init(.{ .id = 1 }, .{ .term = 4, .holder = 9 }, 0);
    const rel: Msg = .{ .kind = .release, .seq = 1, .wall_ms = 5, .term = 4, .holder = 9 };
    try std.testing.expect(a2.handle(1, 5, rel).reply.ok);
    q.seq = 1;
    try std.testing.expect(a2.handle(2, 5, q).reply.ok);
}

test "acceptor: a failed write is retried by the next renewal, replies get no answer" {
    var a = Acceptor.init(.{ .id = 7, .max_skew_ms = 1 << 40 }, .{}, 0);
    const base: Msg = .{ .kind = .acquire, .seq = 1, .wall_ms = 1000, .term = 1, .holder = 11, .lease_ms = 6000 };
    var o = a.handle(0, 1000, base);
    try std.testing.expect(o.persist != null); // write "fails": markPersisted is not called
    var r = base;
    r.seq = 2;
    o = a.handle(1000 * ms, 2000, r);
    try std.testing.expect(o.persist != null); // still has to reach the disk before it is announced
    a.markPersisted(o.persist.?);
    r.seq = 3;
    try std.testing.expect(a.handle(2000 * ms, 3000, r).persist == null);
    try std.testing.expect(!Acceptor.answers(.{ .kind = .reply, .seq = 1, .term = 1, .holder = 5 }));
    try std.testing.expect(!Acceptor.answers(.{ .kind = .query, .seq = 1, .term = 1, .holder = 0 }));
}

test "wire: roundtrip, tamper and wrong key are refused" {
    const key: [32]u8 = @splat(7);
    const m: Msg = .{ .kind = .acquire, .seq = 0x1122334455, .wall_ms = 99, .term = 5, .holder = 77, .lease_ms = 6000 };
    var buf: [Msg.wire_len]u8 = undefined;
    m.encode(&key, &buf);
    try std.testing.expectEqual(m, try Msg.decode(&buf, &key));
    buf[9] ^= 1;
    try std.testing.expectError(error.BadTag, Msg.decode(&buf, &key));
    buf[9] ^= 1;
    const other: [32]u8 = @splat(8);
    try std.testing.expectError(error.BadTag, Msg.decode(&buf, &other));
    try std.testing.expectError(error.BadLength, Msg.decode(buf[0..40], &key));
}

test "state file: crc" {
    var b: [State.file_len]u8 = undefined;
    (State{ .term = 3, .holder = 4, .lease_ms = 6000 }).encode(&b);
    try std.testing.expectEqual(State{ .term = 3, .holder = 4, .lease_ms = 6000 }, State.decode(&b).?);
    b[2] ^= 1;
    try std.testing.expect(State.decode(&b) == null);
}

test "state file survives and agent params are checked" {
    try (Params{}).check();
    try std.testing.expectError(error.BadParams, (Params{ .lease_ms = 3000, .margin_ms = 1500 }).check());
}
