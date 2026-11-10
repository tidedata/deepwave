//! JWK vote aggregation (sui-core `authority_per_epoch_store.rs` `record_jwk_vote`,
//! `get_new_jwks`, `jwk_active_in_current_epoch`; `stake_aggregator.rs`
//! `GenericMultiStakeAggregator<(JwkId, JWK), true>`). A JWK becomes active for the epoch when
//! authorities holding a STRONG quorum (2f+1, 6667 of 10000: STRENGTH = true) voted for exactly
//! that (id, jwk); one validator may cast at most `max_jwk_votes_per_validator_per_epoch` (240)
//! distinct votes per epoch. The consensus handler asks, once per commit, for the JWKs that became
//! active in the PREVIOUS commit round and schedules one AuthenticatorStateUpdate for them (the
//! one round delay is deliberate: nothing in the previous round could have used them).
//!
//! Sans-I/O: the records Rust writes into the commit output go to a `Batch`, `load*` rebuilds the
//! state at epoch store open.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");

pub const Member = struct { name: [96]u8, stake: u64 };

/// MAX_TOTAL_JWK_SIZE (messages_consensus.rs).
pub const max_total_jwk_size = 4096;
/// protocol 141 `max_jwk_votes_per_validator_per_epoch`.
pub const default_max_votes_per_validator = 240;
/// QUORUM_THRESHOLD for TOTAL_VOTING_POWER 10000.
pub const default_quorum_threshold: u64 = 6667;

/// `check_total_jwk_size`.
pub fn checkTotalJwkSize(id: types.JwkId, jwk: types.JWK) bool {
    return id.iss.@"0".len + id.kid.@"0".len + jwk.kty.@"0".len + jwk.alg.@"0".len + jwk.e.@"0".len + jwk.n.@"0".len <= max_total_jwk_size;
}

/// `max_jwk_votes_per_validator_per_epoch` of the epoch's protocol config (Aggregator.Params).
pub fn maxVotesFromConfig(cfg: *const protocol.ProtocolConfig) u64 {
    return cfg.max_jwk_votes_per_validator_per_epoch orelse default_max_votes_per_validator;
}

test "jwk vote budget from the 141 protocol config" {
    try std.testing.expectEqual(@as(u64, 240), maxVotesFromConfig(try protocol.get(141, .mainnet)));
    try std.testing.expectEqual(@as(u64, 240), maxVotesFromConfig(try protocol.get(141, .testnet)));
}

pub const Outcome = enum {
    /// authenticator state object does not exist yet (created at the end of this epoch).
    ignored_disabled,
    /// the validator reached its vote limit for the epoch.
    ignored_limit,
    /// a vote from a name that is not in the committee (cannot happen for sequenced authors).
    ignored_unknown,
    recorded,
    /// this vote made the (id, jwk) reach quorum: it becomes active at this commit round.
    became_active,
};

pub const Batch = struct {
    gpa: std.mem.Allocator,
    /// BCS(AuthorityName, JwkId, JWK) of `pending_jwks` inserts.
    pending: std.ArrayList([]u8) = .empty,
    /// (round, BCS(JwkId, JWK)) of `active_jwks` inserts.
    active: std.ArrayList(Active) = .empty,

    pub const Active = struct { round: u64, key: []u8 };

    pub fn init(gpa: std.mem.Allocator) Batch {
        return .{ .gpa = gpa };
    }
    pub fn deinit(b: *Batch) void {
        for (b.pending.items) |p| b.gpa.free(p);
        b.pending.deinit(b.gpa);
        for (b.active.items) |a| b.gpa.free(a.key);
        b.active.deinit(b.gpa);
        b.* = init(b.gpa);
    }
};

/// A `pending_jwks` row: (AuthorityName, JwkId, JWK).
const PendingRec = struct { types.AuthorityPublicKeyBytes, types.JwkId, types.JWK };

const Entry = struct {
    id: types.JwkId,
    jwk: types.JWK,
    voters: []bool,
    total: u64 = 0,
};

/// ActiveJwk ordering (`jwk_ord`): iss, kid, kty, e, n, alg; each compared length first, then
/// bytewise (`string_bytes_ord`).
fn stringBytesOrd(a: []const u8, b: []const u8) std.math.Order {
    if (a.len < b.len) return .lt;
    if (a.len > b.len) return .gt;
    return std.mem.order(u8, a, b);
}

pub fn activeJwkOrder(a: types.ActiveJwk, b: types.ActiveJwk) std.math.Order {
    const pairs = [_][2][]const u8{
        .{ a.jwk_id.iss.@"0", b.jwk_id.iss.@"0" },
        .{ a.jwk_id.kid.@"0", b.jwk_id.kid.@"0" },
        .{ a.jwk.kty.@"0", b.jwk.kty.@"0" },
        .{ a.jwk.e.@"0", b.jwk.e.@"0" },
        .{ a.jwk.n.@"0", b.jwk.n.@"0" },
        .{ a.jwk.alg.@"0", b.jwk.alg.@"0" },
    };
    for (pairs) |p| {
        if (!std.mem.eql(u8, p[0], p[1])) return stringBytesOrd(p[0], p[1]);
    }
    return .eq;
}

fn activeLess(_: void, a: types.ActiveJwk, b: types.ActiveJwk) bool {
    return activeJwkOrder(a, b) == .lt;
}

pub const Aggregator = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator, // entry strings and structs
    epoch: u64,
    members: []Member,
    quorum_threshold: u64,
    max_votes: u64,
    /// `epoch_store.authenticator_state_enabled()`.
    enabled: bool,
    entries: std.StringHashMapUnmanaged(*Entry) = .empty,
    votes_per_authority: []u64,
    /// consensus round -> entries that became active at that round
    active_by_round: std.AutoArrayHashMapUnmanaged(u64, std.ArrayList(*Entry)) = .empty,

    pub const Params = struct {
        epoch: u64,
        members: []const Member,
        quorum_threshold: u64 = default_quorum_threshold,
        max_votes_per_validator: u64 = default_max_votes_per_validator,
        enabled: bool = true,
    };

    pub fn init(gpa: std.mem.Allocator, p: Params) !Aggregator {
        const votes = try gpa.alloc(u64, p.members.len);
        errdefer gpa.free(votes);
        @memset(votes, 0);
        return .{
            .gpa = gpa,
            .arena = std.heap.ArenaAllocator.init(gpa),
            .epoch = p.epoch,
            .members = try gpa.dupe(Member, p.members),
            .quorum_threshold = p.quorum_threshold,
            .max_votes = p.max_votes_per_validator,
            .enabled = p.enabled,
            .votes_per_authority = votes,
        };
    }

    pub fn deinit(a: *Aggregator) void {
        for (a.active_by_round.values()) |*l| l.deinit(a.gpa);
        a.active_by_round.deinit(a.gpa);
        a.entries.deinit(a.gpa);
        a.gpa.free(a.members);
        a.gpa.free(a.votes_per_authority);
        a.arena.deinit();
    }

    fn authorityIndex(a: *const Aggregator, name: *const [96]u8) ?usize {
        for (a.members, 0..) |m, i| if (std.mem.eql(u8, &m.name, name)) return i;
        return null;
    }

    fn keyBytes(a: std.mem.Allocator, id: types.JwkId, jwk: types.JWK) ![]u8 {
        const k1 = try bcs.encodeAlloc(types.JwkId, a, &id);
        defer a.free(k1);
        const k2 = try bcs.encodeAlloc(types.JWK, a, &jwk);
        defer a.free(k2);
        return std.mem.concat(a, u8, &.{ k1, k2 });
    }

    fn getOrCreate(a: *Aggregator, id: types.JwkId, jwk: types.JWK) !*Entry {
        const kb = try keyBytes(a.gpa, id, jwk);
        defer a.gpa.free(kb);
        if (a.entries.get(kb)) |e| return e;
        const al = a.arena.allocator();
        const e = try al.create(Entry);
        e.* = .{
            .id = .{ .iss = .{ .@"0" = try al.dupe(u8, id.iss.@"0") }, .kid = .{ .@"0" = try al.dupe(u8, id.kid.@"0") } },
            .jwk = .{ .kty = .{ .@"0" = try al.dupe(u8, jwk.kty.@"0") }, .e = .{ .@"0" = try al.dupe(u8, jwk.e.@"0") }, .n = .{ .@"0" = try al.dupe(u8, jwk.n.@"0") }, .alg = .{ .@"0" = try al.dupe(u8, jwk.alg.@"0") } },
            .voters = try al.alloc(bool, a.members.len),
        };
        @memset(e.voters, false);
        try a.entries.put(a.gpa, try al.dupe(u8, kb), e);
        return e;
    }

    fn hasQuorum(a: *const Aggregator, e: *const Entry) bool {
        return e.total >= a.quorum_threshold;
    }

    /// `record_jwk_vote` for a sequenced NewJWKFetched at consensus `round`.
    pub fn recordVote(a: *Aggregator, batch: *Batch, round: u64, authority: *const [96]u8, id: types.JwkId, jwk: types.JWK) !Outcome {
        if (!a.enabled) return .ignored_disabled;
        const idx = a.authorityIndex(authority) orelse return .ignored_unknown;
        if (a.votes_per_authority[idx] >= a.max_votes) return .ignored_limit;

        // output.insert_pending_jwk(authority, id, jwk)
        const auth: types.AuthorityPublicKeyBytes = .{ .@"0" = authority.* };
        const rec: PendingRec = .{ auth, id, jwk };
        const pend = try bcs.encodeAlloc(PendingRec, a.gpa, &rec);
        errdefer a.gpa.free(pend);
        try batch.pending.append(a.gpa, pend);

        const e = try a.getOrCreate(id, jwk);
        const previously_active = a.hasQuorum(e);
        // GenericMultiStakeAggregator::insert: a first vote of this authority for the key counts
        // toward its vote budget; StakeAggregator::insert_generic then adds the stake
        if (!e.voters[idx]) {
            a.votes_per_authority[idx] += 1;
            e.voters[idx] = true;
            const w = a.members[idx].stake;
            if (w > 0) e.total += w;
            if (!previously_active and w > 0 and a.hasQuorum(e)) {
                const key = try keyBytes(a.gpa, id, jwk);
                errdefer a.gpa.free(key);
                try batch.active.append(a.gpa, .{ .round = round, .key = key });
                try a.addActive(round, e);
                return .became_active;
            }
        }
        return .recorded;
    }

    fn addActive(a: *Aggregator, round: u64, e: *Entry) !void {
        const gop = try a.active_by_round.getOrPut(a.gpa, round);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(a.gpa, e);
    }

    /// `jwk_active_in_current_epoch`.
    pub fn isActive(a: *Aggregator, id: types.JwkId, jwk: types.JWK) bool {
        const kb = keyBytes(a.gpa, id, jwk) catch return false;
        defer a.gpa.free(kb);
        const e = a.entries.get(kb) orelse return false;
        return a.hasQuorum(e);
    }

    /// `get_new_jwks(round)`: the JWKs that became active at exactly `round`, in insertion order
    /// (callers sort with `activeJwkOrder`, as `authenticator_state_update_transaction` does).
    /// Strings are borrowed from the aggregator; the slice is in `out_arena`.
    pub fn newJwks(a: *Aggregator, out_arena: std.mem.Allocator, round: u64) ![]types.ActiveJwk {
        const list = a.active_by_round.get(round) orelse return &.{};
        const out = try out_arena.alloc(types.ActiveJwk, list.items.len);
        for (list.items, out) |e, *o| o.* = .{ .jwk_id = e.id, .jwk = e.jwk, .epoch = a.epoch };
        return out;
    }

    // ------------------------------------------------------------------------- restore

    /// Replays a persisted `pending_jwks` row (no effect on the active table).
    pub fn loadPending(a: *Aggregator, bytes: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        defer arena.deinit();
        const v = try bcs.decode(PendingRec, arena.allocator(), bytes);
        const idx = a.authorityIndex(&v[0].@"0") orelse return;
        const e = try a.getOrCreate(v[1], v[2]);
        if (!e.voters[idx]) {
            a.votes_per_authority[idx] += 1;
            e.voters[idx] = true;
            e.total += a.members[idx].stake;
        }
    }

    /// Replays a persisted `active_jwks` row.
    pub fn loadActive(a: *Aggregator, round: u64, key_bytes: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        defer arena.deinit();
        var r = bcs.Reader.init(key_bytes);
        const id = try bcs.decodeFrom(types.JwkId, arena.allocator(), &r);
        const jwk = try bcs.decodeFrom(types.JWK, arena.allocator(), &r);
        try r.finish();
        const e = try a.getOrCreate(id, jwk);
        try a.addActive(round, e);
    }
};

// ---------------------------------------------------------------------------------------------

fn testMembers(n: usize, stake: u64) [8]Member {
    var m: [8]Member = undefined;
    for (0..n) |i| m[i] = .{ .name = @splat(@intCast(i + 1)), .stake = stake };
    return m;
}

test "quorum activation, one round delay, vote limits" {
    const gpa = std.testing.allocator;
    const members = testMembers(4, 2500);
    var agg = try Aggregator.init(gpa, .{ .epoch = 5, .members = members[0..4], .max_votes_per_validator = 2 });
    defer agg.deinit();
    var batch = Batch.init(gpa);
    defer batch.deinit();
    const id: types.JwkId = .{ .iss = .{ .@"0" = "https://accounts.google.com" }, .kid = .{ .@"0" = "k1" } };
    const jwk: types.JWK = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = "nn" }, .alg = .{ .@"0" = "RS256" } };

    try std.testing.expectEqual(Outcome.recorded, try agg.recordVote(&batch, 10, &members[0].name, id, jwk));
    try std.testing.expectEqual(Outcome.recorded, try agg.recordVote(&batch, 10, &members[1].name, id, jwk));
    // a repeated vote does not add stake
    try std.testing.expectEqual(Outcome.recorded, try agg.recordVote(&batch, 10, &members[1].name, id, jwk));
    try std.testing.expect(!agg.isActive(id, jwk));
    // 3 x 2500 = 7500 >= 6667
    try std.testing.expectEqual(Outcome.became_active, try agg.recordVote(&batch, 11, &members[2].name, id, jwk));
    try std.testing.expect(agg.isActive(id, jwk));
    // a fourth vote after activation is recorded but does not re-activate
    try std.testing.expectEqual(Outcome.recorded, try agg.recordVote(&batch, 12, &members[3].name, id, jwk));
    try std.testing.expectEqual(@as(usize, 1), batch.active.items.len);

    var out_arena = std.heap.ArenaAllocator.init(gpa);
    defer out_arena.deinit();
    try std.testing.expectEqual(@as(usize, 0), (try agg.newJwks(out_arena.allocator(), 10)).len);
    const nj = try agg.newJwks(out_arena.allocator(), 11);
    try std.testing.expectEqual(@as(usize, 1), nj.len);
    try std.testing.expectEqual(@as(u64, 5), nj[0].epoch);

    // vote limit: validator 0 already voted once; a second distinct jwk is its last, a third is ignored
    const jwk2: types.JWK = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = "n2" }, .alg = .{ .@"0" = "RS256" } };
    const jwk3: types.JWK = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = "n3" }, .alg = .{ .@"0" = "RS256" } };
    try std.testing.expectEqual(Outcome.recorded, try agg.recordVote(&batch, 13, &members[0].name, id, jwk2));
    try std.testing.expectEqual(Outcome.ignored_limit, try agg.recordVote(&batch, 13, &members[0].name, id, jwk3));

    // disabled and unknown
    var off = try Aggregator.init(gpa, .{ .epoch = 5, .members = members[0..4], .enabled = false });
    defer off.deinit();
    try std.testing.expectEqual(Outcome.ignored_disabled, try off.recordVote(&batch, 1, &members[0].name, id, jwk));
    const stranger: [96]u8 = @splat(0xee);
    try std.testing.expectEqual(Outcome.ignored_unknown, try agg.recordVote(&batch, 1, &stranger, id, jwk));
}

test "restore from persisted rows" {
    const gpa = std.testing.allocator;
    const members = testMembers(4, 2500);
    var agg = try Aggregator.init(gpa, .{ .epoch = 1, .members = members[0..4] });
    defer agg.deinit();
    var batch = Batch.init(gpa);
    defer batch.deinit();
    const id: types.JwkId = .{ .iss = .{ .@"0" = "i" }, .kid = .{ .@"0" = "k" } };
    const jwk: types.JWK = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = "n" }, .alg = .{ .@"0" = "RS256" } };
    for (0..3) |i| _ = try agg.recordVote(&batch, 7, &members[i].name, id, jwk);

    var fresh = try Aggregator.init(gpa, .{ .epoch = 1, .members = members[0..4] });
    defer fresh.deinit();
    for (batch.pending.items) |p| try fresh.loadPending(p);
    for (batch.active.items) |act| try fresh.loadActive(act.round, act.key);
    try std.testing.expect(fresh.isActive(id, jwk));
    var out_arena = std.heap.ArenaAllocator.init(gpa);
    defer out_arena.deinit();
    try std.testing.expectEqual(@as(usize, 1), (try fresh.newJwks(out_arena.allocator(), 7)).len);
}

test "active jwk ordering is length first" {
    const a: types.ActiveJwk = .{ .jwk_id = .{ .iss = .{ .@"0" = "bb" }, .kid = .{ .@"0" = "x" } }, .jwk = .{ .kty = .{ .@"0" = "" }, .e = .{ .@"0" = "" }, .n = .{ .@"0" = "" }, .alg = .{ .@"0" = "" } }, .epoch = 0 };
    const b: types.ActiveJwk = .{ .jwk_id = .{ .iss = .{ .@"0" = "a" }, .kid = .{ .@"0" = "x" } }, .jwk = .{ .kty = .{ .@"0" = "" }, .e = .{ .@"0" = "" }, .n = .{ .@"0" = "" }, .alg = .{ .@"0" = "" } }, .epoch = 0 };
    // "a" (len 1) sorts before "bb" (len 2) even though "bb" > "a" bytewise
    try std.testing.expectEqual(std.math.Order.gt, activeJwkOrder(a, b));
    var arr = [_]types.ActiveJwk{ a, b };
    std.mem.sort(types.ActiveJwk, &arr, {}, activeLess);
    try std.testing.expectEqualStrings("a", arr[0].jwk_id.iss.@"0");
}
