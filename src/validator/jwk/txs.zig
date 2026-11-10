//! ConsensusTransaction::NewJWKFetched builder (`new_jwk_fetched`). The tracking id is the
//! SipHash-1-3 (zero keys) of `JwkId` as the derived `Hash` feeds it: each `String` writes its
//! bytes then 0xff.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const messages = @import("../messages.zig");

pub const Error = error{OutOfMemory} || bcs.EncodeError;

pub fn trackingId(id: types.JwkId) [8]u8 {
    const SipHash = std.crypto.auth.siphash.SipHash64(1, 3);
    const key: [16]u8 = @splat(0);
    var h = SipHash.init(&key);
    h.update(id.iss.@"0");
    h.update(&.{0xff});
    h.update(id.kid.@"0");
    h.update(&.{0xff});
    var out: [8]u8 = undefined;
    h.final(&out);
    return out;
}

/// BCS(ConsensusTransaction::NewJWKFetched(authority, id, jwk)).
pub fn newJwkFetchedTx(gpa: std.mem.Allocator, authority: *const [96]u8, id: types.JwkId, jwk: types.JWK) Error![]u8 {
    const tx: messages.ConsensusTransaction = .{
        .tracking_id = trackingId(id),
        .kind = .{ .NewJWKFetched = .{ .{ .@"0" = authority.* }, id, jwk } },
    };
    return bcs.encodeAlloc(messages.ConsensusTransaction, gpa, &tx);
}

test "jwk transaction roundtrip" {
    const gpa = std.testing.allocator;
    const auth: [96]u8 = @splat(3);
    const id: types.JwkId = .{ .iss = .{ .@"0" = "https://accounts.google.com" }, .kid = .{ .@"0" = "abc" } };
    const jwk: types.JWK = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = "nn" }, .alg = .{ .@"0" = "RS256" } };
    const b = try newJwkFetchedTx(gpa, &auth, id, jwk);
    defer gpa.free(b);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const tx = try bcs.decode(messages.ConsensusTransaction, arena.allocator(), b);
    try std.testing.expect(tx.kind == .NewJWKFetched);
    try std.testing.expectEqualStrings("abc", tx.kind.NewJWKFetched[1].kid.@"0");
    try std.testing.expectEqualSlices(u8, &trackingId(id), &tx.tracking_id);
}
