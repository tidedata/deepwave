//! The JWK updater of sui-node (`start_jwk_updater`): for each provider of the chain, every
//! `jwk_fetch_interval_seconds` (3600) fetch the provider's JWK document, drop what is not valid
//! (`validate_jwk`: the key's issuer must parse back to this provider, total size within
//! MAX_TOTAL_JWK_SIZE), drop what is already active this epoch or was already offered by this
//! provider's loop (`seen`), keep at most MAX_JWK_KEYS_PER_FETCH (100) and submit one
//! NewJWKFetched per key through consensus. After a failed fetch the provider is retried in 30 s.
//!
//! Sans-I/O: `Updater.poll(now_ms)` runs every provider that is due. The HTTPS fetch is a
//! `Transport` (cold path; the real one is `https.zig`, local test committees use `Fixtures`),
//! the submission a callback. Nothing here sleeps or spawns.
const std = @import("std");
const types = @import("types");
const providers = @import("providers.zig");
const parse = @import("parse.zig");
const aggregator = @import("aggregator.zig");

pub const max_jwk_keys_per_fetch = 100;
pub const default_fetch_interval_ms: u64 = 3600 * 1000;
pub const retry_after_error_ms: u64 = 30 * 1000;

pub const Transport = struct {
    ctx: *anyopaque,
    /// GET `url`; returns the body allocated from `arena`.
    get: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, url: []const u8) anyerror![]const u8,
};

/// `Fixtures`: URL to body, for a local test committee (no network).
pub const Fixtures = struct {
    map: std.StringHashMapUnmanaged([]const u8) = .empty,
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator) Fixtures {
        return .{ .gpa = gpa };
    }
    pub fn deinit(f: *Fixtures) void {
        var it = f.map.iterator();
        while (it.next()) |e| {
            f.gpa.free(e.key_ptr.*);
            f.gpa.free(e.value_ptr.*);
        }
        f.map.deinit(f.gpa);
    }
    pub fn put(f: *Fixtures, url: []const u8, body: []const u8) !void {
        const v = try f.gpa.dupe(u8, body);
        errdefer f.gpa.free(v);
        if (f.map.getPtr(url)) |slot| {
            f.gpa.free(slot.*);
            slot.* = v;
            return;
        }
        const k = try f.gpa.dupe(u8, url);
        errdefer f.gpa.free(k);
        try f.map.put(f.gpa, k, v);
    }
    fn get(ctx: *anyopaque, arena: std.mem.Allocator, url: []const u8) anyerror![]const u8 {
        const f: *Fixtures = @ptrCast(@alignCast(ctx));
        const v = f.map.get(url) orelse return error.FixtureMissing;
        return arena.dupe(u8, v);
    }
    pub fn transport(f: *Fixtures) Transport {
        return .{ .ctx = f, .get = get };
    }
};

pub const Submit = struct {
    ctx: *anyopaque,
    /// One NewJWKFetched vote (id, jwk) to put into consensus under this validator's name.
    vote: *const fn (ctx: *anyopaque, id: types.JwkId, jwk: types.JWK) anyerror!void,
};

const ProviderState = struct {
    provider: providers.Provider,
    next_due_ms: u64 = 0,
    seen: std.StringHashMapUnmanaged(void) = .empty, // key: BCS-ish id+jwk bytes
};

pub const Updater = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator, // provider names
    seen_arena: std.heap.ArenaAllocator, // seen keys, reset every epoch
    states: []ProviderState,
    fetch_interval_ms: u64,
    stats: Stats = .{},

    pub const Stats = struct { requests: u64 = 0, errors: u64 = 0, invalid_jwks: u64 = 0, submitted: u64 = 0 };

    /// `names` as in `zklogin_oauth_providers` for the chain; an unparsable name is an error
    /// (Rust: `expect("Invalid provider string")`).
    pub fn init(gpa: std.mem.Allocator, names: []const []const u8, fetch_interval_ms: u64) !Updater {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const al = arena.allocator();
        const states = try al.alloc(ProviderState, names.len);
        for (names, states) |n, *s| {
            const owned = try al.dupe(u8, n);
            const p = providers.Provider.fromName(owned) orelse return error.InvalidProvider;
            s.* = .{ .provider = p };
        }
        return .{ .gpa = gpa, .arena = arena, .seen_arena = std.heap.ArenaAllocator.init(gpa), .states = states, .fetch_interval_ms = fetch_interval_ms };
    }

    pub fn deinit(u: *Updater) void {
        for (u.states) |*s| s.seen.deinit(u.gpa);
        u.arena.deinit();
        u.seen_arena.deinit();
    }

    /// Epoch boundary. Rust respawns the updater tasks every epoch with a fresh `seen`, so every
    /// validator re-votes each current key at the start of an epoch (that re-activates keys
    /// before max_age_of_jwk_in_epochs and re-commits keys that went active in the last round).
    /// The shell calls this when it installs a new epoch, together with a fresh Aggregator.
    pub fn resetEpoch(u: *Updater) void {
        for (u.states) |*s| {
            s.seen.clearRetainingCapacity();
            s.next_due_ms = 0;
        }
        _ = u.seen_arena.reset(.retain_capacity);
    }

    /// `validate_jwk`.
    pub fn validJwk(provider: providers.Provider, id: types.JwkId, jwk: types.JWK) bool {
        const iss_provider = providers.Provider.fromIss(id.iss.@"0") orelse return false;
        if (!iss_provider.eql(provider)) return false;
        return aggregator.checkTotalJwkSize(id, jwk);
    }

    /// Runs every due provider once. Returns the earliest time something is due next.
    pub fn poll(u: *Updater, now_ms: u64, transport: Transport, agg: *aggregator.Aggregator, submit: Submit) !u64 {
        var next: u64 = std.math.maxInt(u64);
        for (u.states) |*s| {
            if (now_ms >= s.next_due_ms) {
                const ok = u.runProvider(s, transport, agg, submit);
                s.next_due_ms = now_ms + (if (ok) u.fetch_interval_ms else retry_after_error_ms);
            }
            next = @min(next, s.next_due_ms);
        }
        return next;
    }

    /// One iteration of the provider loop; false when the fetch failed.
    fn runProvider(u: *Updater, s: *ProviderState, transport: Transport, agg: *aggregator.Aggregator, submit: Submit) bool {
        var arena = std.heap.ArenaAllocator.init(u.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        u.stats.requests += 1;
        var cfg_buf: [512]u8 = undefined;
        const cfg = s.provider.config(&cfg_buf) catch {
            u.stats.errors += 1;
            return false;
        };
        const body = transport.get(transport.ctx, a, cfg.jwk_endpoint) catch {
            u.stats.errors += 1;
            return false;
        };
        const keys = parse.parseJwks(a, body, s.provider) catch {
            u.stats.errors += 1;
            return false;
        };
        // keys.retain(valid && !active && seen.insert(..)): every retained key is marked seen
        // even when the truncation below drops it
        var fresh: std.ArrayList(parse.Entry) = .empty;
        defer fresh.deinit(u.gpa);
        for (keys) |k| {
            if (!validJwk(s.provider, k.id, k.jwk)) {
                u.stats.invalid_jwks += 1;
                continue;
            }
            if (agg.isActive(k.id, k.jwk)) continue;
            const sk = seenKey(a, k.id, k.jwk) catch continue;
            if (s.seen.contains(sk)) continue;
            const owned = u.seen_arena.allocator().dupe(u8, sk) catch continue;
            s.seen.put(u.gpa, owned, {}) catch continue;
            fresh.append(u.gpa, k) catch continue;
        }
        if (fresh.items.len > max_jwk_keys_per_fetch) fresh.shrinkRetainingCapacity(max_jwk_keys_per_fetch);
        for (fresh.items) |k| {
            submit.vote(submit.ctx, k.id, k.jwk) catch continue; // Rust logs and goes on
            u.stats.submitted += 1;
        }
        return true;
    }

    fn seenKey(a: std.mem.Allocator, id: types.JwkId, jwk: types.JWK) ![]u8 {
        return std.mem.concat(a, u8, &.{ id.iss.@"0", "\x00", id.kid.@"0", "\x00", jwk.kty.@"0", "\x00", jwk.e.@"0", "\x00", jwk.n.@"0", "\x00", jwk.alg.@"0" });
    }
};

// ---------------------------------------------------------------------------------------------

const TestSink = struct {
    votes: std.ArrayList([]const u8) = .empty,
    gpa: std.mem.Allocator,
    fn vote(ctx: *anyopaque, id: types.JwkId, jwk: types.JWK) anyerror!void {
        const s: *TestSink = @ptrCast(@alignCast(ctx));
        _ = jwk;
        try s.votes.append(s.gpa, try s.gpa.dupe(u8, id.kid.@"0"));
    }
    fn deinit(s: *TestSink) void {
        for (s.votes.items) |v| s.gpa.free(v);
        s.votes.deinit(s.gpa);
    }
};

test "updater fetches, filters seen and active, retries after errors" {
    const gpa = std.testing.allocator;
    var fx = Fixtures.init(gpa);
    defer fx.deinit();
    const body =
        \\{"keys":[{"kty":"RSA","kid":"a","n":"n1","e":"AQAB"},{"kty":"RSA","kid":"b","n":"n2","e":"AQAB"}]}
    ;
    try fx.put("https://www.googleapis.com/oauth2/v2/certs", body);
    var upd = try Updater.init(gpa, &.{ "Google", "Twitch" }, 1000);
    defer upd.deinit();

    var members: [4]aggregator.Member = undefined;
    for (&members, 0..) |*m, i| m.* = .{ .name = @splat(@intCast(i + 1)), .stake = 2500 };
    var agg = try aggregator.Aggregator.init(gpa, .{ .epoch = 1, .members = &members });
    defer agg.deinit();
    var sink: TestSink = .{ .gpa = gpa };
    defer sink.deinit();
    const submit: Submit = .{ .ctx = &sink, .vote = TestSink.vote };

    // Twitch has no fixture: error, retry in 30 s; Google submits both keys
    const next = try upd.poll(0, fx.transport(), &agg, submit);
    try std.testing.expectEqual(@as(usize, 2), sink.votes.items.len);
    try std.testing.expectEqual(@as(u64, 1), upd.stats.errors);
    try std.testing.expectEqual(@as(u64, 1000), next);

    // within the interval nothing runs; after it, key "a" is seen and "b" became active
    var batch = aggregator.Batch.init(gpa);
    defer batch.deinit();
    const id_b: types.JwkId = .{ .iss = .{ .@"0" = "https://accounts.google.com" }, .kid = .{ .@"0" = "b" } };
    const jwk_b: types.JWK = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = "n2" }, .alg = .{ .@"0" = "RS256" } };
    for (0..3) |i| _ = try agg.recordVote(&batch, 1, &members[i].name, id_b, jwk_b);
    _ = try upd.poll(500, fx.transport(), &agg, submit);
    try std.testing.expectEqual(@as(usize, 2), sink.votes.items.len);
    _ = try upd.poll(1000, fx.transport(), &agg, submit);
    try std.testing.expectEqual(@as(usize, 2), sink.votes.items.len); // a: seen, b: active

    // a rotated key is new
    try fx.put("https://www.googleapis.com/oauth2/v2/certs",
        \\{"keys":[{"kty":"RSA","kid":"c","n":"n3","e":"AQAB"}]}
    );
    _ = try upd.poll(2000, fx.transport(), &agg, submit);
    try std.testing.expectEqual(@as(usize, 3), sink.votes.items.len);
    try std.testing.expectEqualStrings("c", sink.votes.items[2]);

    try std.testing.expect(Updater.validJwk(providers.Provider.fromName("Google").?, id_b, jwk_b));
    try std.testing.expect(!Updater.validJwk(providers.Provider.fromName("Twitch").?, id_b, jwk_b));
}
