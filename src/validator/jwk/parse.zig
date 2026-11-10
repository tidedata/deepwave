//! JWK document parsing (fastcrypto-zkp `parse_jwks` with `skip_on_invalid_jwk = true`, the way
//! sui-node `fetch_jwks` calls it): a JSON object with a `keys` array; every entry must be an RSA
//! key with exponent AQAB (alg RS256 when present); invalid entries are skipped, and a document
//! without any valid key is an error. Ids use the provider's configured issuer.
const std = @import("std");
const types = @import("types");
const providers = @import("providers.zig");

pub const Error = error{ InvalidJwkResponse, NoValidJwks, OutOfMemory, NoSpaceLeft };

pub const Entry = struct { id: types.JwkId, jwk: types.JWK };

/// `String::from_utf8_lossy`: every maximal invalid subpart becomes one U+FFFD.
fn lossy(arena: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]const u8 {
    if (std.unicode.utf8ValidateSlice(bytes)) return bytes;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < bytes.len) {
        const b0 = bytes[i];
        if (b0 < 0x80) {
            try out.append(arena, b0);
            i += 1;
            continue;
        }
        // (length, valid range of the second byte) per the Unicode well-formed table
        var need: usize = 0;
        var lo: u8 = 0x80;
        var hi: u8 = 0xBF;
        switch (b0) {
            0xC2...0xDF => need = 2,
            0xE0 => {
                need = 3;
                lo = 0xA0;
            },
            0xE1...0xEC, 0xEE...0xEF => need = 3,
            0xED => {
                need = 3;
                hi = 0x9F;
            },
            0xF0 => {
                need = 4;
                lo = 0x90;
            },
            0xF1...0xF3 => need = 4,
            0xF4 => {
                need = 4;
                hi = 0x8F;
            },
            else => {},
        }
        if (need == 0) {
            try out.appendSlice(arena, "\u{FFFD}");
            i += 1;
            continue;
        }
        var j: usize = 1;
        while (j < need) : (j += 1) {
            if (i + j >= bytes.len) break;
            const b = bytes[i + j];
            const l: u8 = if (j == 1) lo else 0x80;
            const h: u8 = if (j == 1) hi else 0xBF;
            if (b < l or b > h) break;
        }
        if (j == need) {
            try out.appendSlice(arena, bytes[i .. i + need]);
        } else {
            try out.appendSlice(arena, "\u{FFFD}");
        }
        i += j;
    }
    return out.items;
}

fn trimEq(s: []const u8) []const u8 {
    return std.mem.trimEnd(u8, s, "=");
}

fn str(v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

/// Optional string field: absent or null is None, any other non string type is invalid.
fn optStr(obj: std.json.ObjectMap, key: []const u8) error{Invalid}!?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .null => null,
        .string => |s| s,
        else => error.Invalid,
    };
}

fn optStrArray(obj: std.json.ObjectMap, key: []const u8) error{Invalid}!void {
    const v = obj.get(key) orelse return;
    switch (v) {
        .null => {},
        .array => |a| for (a.items) |x| if (x != .string) return error.Invalid,
        else => return error.Invalid,
    }
}

/// JWKReader deserialization then `JWK::from_reader`; null when either fails.
fn readKey(arena: std.mem.Allocator, iss: []const u8, v: std.json.Value) std.mem.Allocator.Error!?Entry {
    const obj = switch (v) {
        .object => |o| o,
        else => return null,
    };
    const e = str(obj.get("e") orelse return null) orelse return null;
    const n = str(obj.get("n") orelse return null) orelse return null;
    const kid = str(obj.get("kid") orelse return null) orelse return null;
    const kty = str(obj.get("kty") orelse return null) orelse return null;
    _ = optStr(obj, "use") catch return null;
    const alg = optStr(obj, "alg") catch return null;
    optStrArray(obj, "x5c") catch return null;
    _ = optStr(obj, "x5t") catch return null;
    _ = optStr(obj, "issuer") catch return null;
    const trimmed_e = trimEq(e);
    if (alg) |a| if (!std.mem.eql(u8, a, "RS256")) return null;
    if (!std.mem.eql(u8, kty, "RSA") or !std.mem.eql(u8, trimmed_e, "AQAB")) return null;
    return .{
        .id = .{ .iss = .{ .@"0" = try arena.dupe(u8, iss) }, .kid = .{ .@"0" = try arena.dupe(u8, kid) } },
        .jwk = .{
            .kty = .{ .@"0" = try arena.dupe(u8, kty) },
            .e = .{ .@"0" = try arena.dupe(u8, trimmed_e) },
            .n = .{ .@"0" = try arena.dupe(u8, trimEq(n)) },
            .alg = .{ .@"0" = try arena.dupe(u8, "RS256") },
        },
    };
}

/// All strings live in `arena`.
pub fn parseJwks(arena: std.mem.Allocator, json_bytes: []const u8, provider: providers.Provider) Error![]Entry {
    var cfg_buf: [512]u8 = undefined;
    const cfg = try provider.config(&cfg_buf);
    const text = try lossy(arena, json_bytes);
    const doc = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{ .duplicate_field_behavior = .use_last }) catch return error.InvalidJwkResponse;
    const root = switch (doc) {
        .object => |o| o,
        else => return error.InvalidJwkResponse,
    };
    const keys = switch (root.get("keys") orelse return error.InvalidJwkResponse) {
        .array => |a| a,
        else => return error.InvalidJwkResponse,
    };
    var out: std.ArrayList(Entry) = .empty;
    for (keys.items) |k| {
        if (try readKey(arena, cfg.iss, k)) |entry| try out.append(arena, entry);
    }
    if (out.items.len == 0) return error.NoValidJwks;
    return out.items;
}

test "parse a google style document, skipping bad keys" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const doc =
        \\{"keys":[
        \\ {"kty":"RSA","alg":"RS256","use":"sig","kid":"k1","n":"abcd==","e":"AQAB"},
        \\ {"kty":"RSA","alg":"RS512","kid":"k2","n":"x","e":"AQAB"},
        \\ {"kty":"EC","kid":"k3","n":"x","e":"AQAB"},
        \\ {"kty":"RSA","kid":"k4","n":"yy","e":"AQAB"},
        \\ {"kty":"RSA","kid":"k5","n":"zz","e":"AQAC"},
        \\ {"kid":"k6"}
        \\]}
    ;
    const p = providers.Provider.fromName("Google").?;
    const got = try parseJwks(a, doc, p);
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqualStrings("https://accounts.google.com", got[0].id.iss.@"0");
    try std.testing.expectEqualStrings("k1", got[0].id.kid.@"0");
    try std.testing.expectEqualStrings("abcd", got[0].jwk.n.@"0");
    try std.testing.expectEqualStrings("RS256", got[1].jwk.alg.@"0");
    try std.testing.expectError(error.NoValidJwks, parseJwks(a, "{\"keys\":[{\"kid\":\"x\"}]}", p));
    try std.testing.expectError(error.InvalidJwkResponse, parseJwks(a, "[1]", p));
    try std.testing.expectError(error.InvalidJwkResponse, parseJwks(a, "not json", p));
}

test "lossy matches from_utf8_lossy maximal subparts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // truncated 3-byte sequence is one replacement; lone continuation bytes one each
    try std.testing.expectEqualStrings("a\u{FFFD}b", try lossy(a, "a\xE2\x82b"));
    try std.testing.expectEqualStrings("\u{FFFD}\u{FFFD}", try lossy(a, "\x80\x80"));
    try std.testing.expectEqualStrings("\u{FFFD}", try lossy(a, "\xF0\x9F\x98"));
    try std.testing.expectEqualStrings("\u{FFFD}\u{FFFD}\u{FFFD}", try lossy(a, "\xED\xA0\x80"));
}

test "duplicate object keys: last wins" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), "{\"a\":1,\"a\":2}", .{ .duplicate_field_behavior = .use_last });
    try std.testing.expectEqual(@as(i64, 2), v.object.get("a").?.integer);
}
