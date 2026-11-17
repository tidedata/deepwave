//! The zkLogin side of the validator's `SignatureVerifier` (sui-core signature_verifier.rs and
//! authority_per_epoch_store.rs, mainnet-v1.83.1):
//!
//!   - `JwkMap`: `SignatureVerifier.jwks`, keyed by `JwkId` (iss, kid) exactly as stored. An
//!     insert never replaces an existing id (`insert_jwk`), nothing is removed inside an epoch.
//!   - At epoch start (`AuthorityPerEpochStore::new`, when the authenticator state exists and
//!     `enable_jwk_consensus_updates` is on): every `active_jwks` entry of the AuthenticatorState
//!     (0x7 and its `Field<u64, AuthenticatorStateInner>`) in the live store, in stored order.
//!   - After each executed AuthenticatorStateUpdate (`update_authenticator_state`, called by
//!     `process_certificate` whatever the execution status): its `new_active_jwks`, in order.
//!   - `env`: `ZkLoginEnv::Prod` on mainnet and testnet (by genesis checkpoint digest), `Test`
//!     elsewhere; the circuit mode from `zklogin_circuit_mode`; the prepared verifying keys.
//!
//! Lookups come from the vote, submit and pre-verification threads, inserts from the executor
//! thread. Entries are never freed while the map lives, so a returned modulus stays valid.
const std = @import("std");
const types = @import("types");
const zk = @import("zk");
const serve = @import("serve");
const rpc_exec = @import("rpc_exec");
const protocol = @import("protocol");
const Spin = @import("../authority/sync.zig").Spin;
const store_mod = @import("exec_store.zig");

const Allocator = std.mem.Allocator;
const verifysig = serve.verifysig;

pub const JwkMap = struct {
    gpa: Allocator,
    lock: Spin = .{},
    arena: std.heap.ArenaAllocator,
    /// `writeKey(iss, kid)` -> JWK (strings in `arena`).
    map: std.StringHashMapUnmanaged(verifysig.Jwk) = .empty,

    pub fn init(gpa: Allocator) JwkMap {
        return .{ .gpa = gpa, .arena = .init(gpa) };
    }

    pub fn deinit(m: *JwkMap) void {
        m.map.deinit(m.gpa);
        m.arena.deinit();
    }

    /// `insert_jwk`: a JwkId already present keeps its JWK. Returns whether it was inserted.
    pub fn insert(m: *JwkMap, j: verifysig.Jwk) Allocator.Error!bool {
        m.lock.lock();
        defer m.lock.unlock();
        const a = m.arena.allocator();
        const key = try a.alloc(u8, keyLen(j.iss, j.kid));
        writeKey(key, j.iss, j.kid);
        if (m.map.contains(key)) return false;
        const owned: verifysig.Jwk = .{
            .iss = try a.dupe(u8, j.iss),
            .kid = try a.dupe(u8, j.kid),
            .kty = try a.dupe(u8, j.kty),
            .e = try a.dupe(u8, j.e),
            .n = try a.dupe(u8, j.n),
            .alg = try a.dupe(u8, j.alg),
        };
        try m.map.put(m.gpa, key, owned);
        return true;
    }

    pub fn insertActive(m: *JwkMap, list: []const types.ActiveJwk) Allocator.Error!void {
        for (list) |aj| _ = try m.insert(.{
            .iss = aj.jwk_id.iss.@"0",
            .kid = aj.jwk_id.kid.@"0",
            .kty = aj.jwk.kty.@"0",
            .e = aj.jwk.e.@"0",
            .n = aj.jwk.n.@"0",
            .alg = aj.jwk.alg.@"0",
        });
    }

    pub fn count(m: *JwkMap) usize {
        m.lock.lock();
        defer m.lock.unlock();
        return m.map.count();
    }

    /// The JWK of (iss, kid); `iss` as `JwkId::new` gives it (the caller normalizes).
    pub fn get(m: *JwkMap, iss: []const u8, kid: []const u8) ?verifysig.Jwk {
        var kb: [512]u8 = undefined;
        var heap: ?[]u8 = null;
        defer if (heap) |h| m.gpa.free(h);
        const n = keyLen(iss, kid);
        const key: []u8 = if (n <= kb.len) kb[0..n] else blk: {
            heap = m.gpa.alloc(u8, n) catch return null;
            break :blk heap.?;
        };
        writeKey(key, iss, kid);
        m.lock.lock();
        defer m.lock.unlock();
        return m.map.get(key);
    }

    fn lookupFn(ctx: *const anyopaque, iss: []const u8, kid: []const u8) ?[]const u8 {
        const m: *JwkMap = @ptrCast(@alignCast(@constCast(ctx)));
        return if (m.get(iss, kid)) |j| j.n else null;
    }

    pub fn jwks(m: *JwkMap) zk.zklogin.Jwks {
        return .{ .ctx = m, .lookupFn = lookupFn };
    }
};

/// Map key: u32 iss length, iss, kid (unambiguous for any strings).
fn keyLen(iss: []const u8, kid: []const u8) usize {
    return 4 + iss.len + kid.len;
}
fn writeKey(out: []u8, iss: []const u8, kid: []const u8) void {
    std.mem.writeInt(u32, out[0..4], @intCast(iss.len), .little);
    @memcpy(out[4..][0..iss.len], iss);
    @memcpy(out[4 + iss.len ..][0..kid.len], kid);
}

/// The epoch-start load: the AuthenticatorState's `active_jwks` in the live store, in stored
/// order. Returns how many JWKs the state holds (0 when it does not exist).
pub fn loadEpochStart(m: *JwkMap, store: *store_mod.ExecStore) Allocator.Error!usize {
    var scratch = std.heap.ArenaAllocator.init(m.gpa);
    defer scratch.deinit();
    const venv: verifysig.Env = .{ .ctx = store, .liveObject = liveObject };
    const set = try verifysig.chainJwks(scratch.allocator(), &venv);
    for (set) |j| _ = try m.insert(j);
    return set.len;
}

fn liveObject(ctx: *anyopaque, id: *const [32]u8) ?[]const u8 {
    const s: *store_mod.ExecStore = @ptrCast(@alignCast(ctx));
    return s.latest(id);
}

/// `ZkLoginEnv` and circuit mode of the epoch over `m`.
pub fn env(m: *JwkMap, chain_id: *const [32]u8, cfg: *const protocol.ProtocolConfig) zk.zklogin.Env {
    return rpc_exec.live.usersig.zkLoginEnv(chain_id, cfg, m.jwks());
}

test "jwk map: first insertion wins, lookups by (iss, kid)" {
    const gpa = std.testing.allocator;
    var m = JwkMap.init(gpa);
    defer m.deinit();
    const a: verifysig.Jwk = .{ .iss = "https://accounts.google.com", .kid = "k1", .kty = "RSA", .e = "AQAB", .n = "n-first", .alg = "RS256" };
    var b = a;
    b.n = "n-second";
    try std.testing.expect(try m.insert(a));
    try std.testing.expect(!try m.insert(b));
    try std.testing.expectEqualStrings("n-first", m.get("https://accounts.google.com", "k1").?.n);
    try std.testing.expect(m.get("https://accounts.google.com", "k2") == null);
    // the map's iss is matched exactly (JwkId::new normalizes only the query side)
    try std.testing.expect(m.get("https://accounts.google.com/", "k1") == null);
    const j = m.jwks();
    try std.testing.expectEqualStrings("n-first", j.lookup("https://accounts.google.com", "k1").?);
    try std.testing.expectEqual(@as(usize, 1), m.count());
}
