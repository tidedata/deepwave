//! `UserSignature` rendering for ExecuteTransaction. The handler renders the request's signatures
//! as parsed by sui-sdk-types (`UserSignature::from_bytes`), not through sui-types like
//! GetTransaction: a zkLogin authenticator therefore renders in full (proof points, claim,
//! header, public identifier, JWK id) where serve's renderer has the sui-types fallback. Every
//! other scheme renders the same way, through serve.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const serve = @import("serve");
const proto = serve.proto;
const Mask = serve.mask.Mask;

pub const Error = serve.render_sig.Error || Allocator.Error || error{InvalidValue};

/// A zkLogin authenticator as sui-sdk-types holds it after `ZkLoginInputs::new`.
pub const ZkLogin = struct {
    auth: types.hand.ZkLoginAuthenticator,
    iss: []const u8,
    kid: []const u8,
};

/// `ZkLoginAuthenticator::from_serialized_bytes` (flag 0x05 first): the error text, or the value.
pub fn parseZkLogin(arena: Allocator, b: []const u8) Allocator.Error!union(enum) { ok: ZkLogin, err: []const u8 } {
    const auth = bcs.decode(types.hand.ZkLoginAuthenticator, arena, b[1..]) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .err = @import("sui_error.zig").bcsErrorText(e) },
    };
    const p = auth.inputs.proofPoints;
    if (p.a.len != 3 or p.c.len != 3) return .{ .err = "expected array of length 3" };
    if (p.b.len != 3) return .{ .err = "expected array of length 3" };
    for (p.b) |x| if (x.len != 2) return .{ .err = "expected array of length 2" };
    const claim = auth.inputs.issBase64Details;
    const iss = switch (try extendedClaim(arena, claim.value.@"0", claim.indexMod4, "iss")) {
        .ok => |s| s,
        .err => |e| return .{ .err = e },
    };
    if (iss.len > 255) return .{ .err = "invalid zklogin claim: invalid iss: too long" };
    const kid = switch (try headerKid(arena, auth.inputs.headerBase64.@"0")) {
        .ok => |s| s,
        .err => |e| return .{ .err = e },
    };
    return .{ .ok = .{ .auth = auth, .iss = iss, .kid = kid } };
}

const Text = union(enum) { ok: []const u8, err: []const u8 };

fn claimErr(arena: Allocator, why: []const u8) Allocator.Error!Text {
    return .{ .err = try std.fmt.allocPrint(arena, "invalid zklogin claim: {s}", .{why}) };
}

/// `ZkLoginClaim::verify_extended_claim`: base64url bits at the claim's offset, then the value of
/// `key` in `{<claim without its last character>}`.
fn extendedClaim(arena: Allocator, s: []const u8, index_mod_4: u8, key: []const u8) Allocator.Error!Text {
    if (s.len < 2) return claimErr(arena, "Base64 string smaller than 2");
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    var bits: std.ArrayList(u1) = try .initCapacity(arena, s.len * 6);
    for (s) |c| {
        const idx = std.mem.indexOfScalar(u8, charset, c) orelse return claimErr(arena, "base64_to_bitarry invalid input");
        var i: u3 = 6;
        while (i > 0) {
            i -= 1;
            bits.appendAssumeCapacity(@truncate(idx >> i));
        }
    }
    var lo: usize = 0;
    switch (index_mod_4) {
        0 => {},
        1 => lo = 2,
        2 => lo = 4,
        else => return claimErr(arena, "Invalid first_char_offset"),
    }
    var hi = bits.items.len;
    switch ((@as(usize, index_mod_4) + s.len - 1) % 4) {
        3 => {},
        2 => hi -= 2,
        1 => hi -= 4,
        else => return claimErr(arena, "Invalid last_char_offset"),
    }
    const b = bits.items[lo..hi];
    if (b.len % 8 != 0) return claimErr(arena, "Invalid bits length");
    const out = try arena.alloc(u8, b.len / 8);
    for (out, 0..) |*o, k| {
        var byte: u8 = 0;
        for (b[k * 8 ..][0..8]) |bit| byte = (byte << 1) | bit;
        o.* = byte;
    }
    if (!std.unicode.utf8ValidateSlice(out)) return claimErr(arena, "Invalid UTF8 string");
    if (out.len == 0 or !(out[out.len - 1] == '}' or out[out.len - 1] == ',')) return claimErr(arena, "Invalid extended claim");
    const json = try std.fmt.allocPrint(arena, "{{{s}}}", .{out[0 .. out.len - 1]});
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{ .duplicate_field_behavior = .use_last }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return claimErr(arena, "invalid json"),
    };
    if (v != .object) return claimErr(arena, "invalid extended claim");
    const x = v.object.get(key) orelse return claimErr(arena, "invalid extended claim");
    if (x != .string) return claimErr(arena, "invalid extended claim");
    return .{ .ok = x.string };
}

/// `JwtHeader::from_base64`: the `kid` of a base64url (unpadded) JSON header with `alg` RS256.
fn headerKid(arena: Allocator, s: []const u8) Allocator.Error!Text {
    const dec = std.base64.url_safe_no_pad.Decoder;
    const n = dec.calcSizeForSlice(s) catch return claimErr(arena, "invalid base64");
    const raw = try arena.alloc(u8, n);
    dec.decode(raw, s) catch return claimErr(arena, "invalid base64");
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, raw, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return claimErr(arena, "invalid json"),
    };
    if (v != .object) return claimErr(arena, "invalid json");
    const alg = v.object.get("alg") orelse return claimErr(arena, "invalid json: missing field `alg`");
    const kid = v.object.get("kid") orelse return claimErr(arena, "invalid json: missing field `kid`");
    if (alg != .string or kid != .string) return claimErr(arena, "invalid json");
    if (v.object.get("typ")) |t| if (t != .string and t != .null) return claimErr(arena, "invalid json");
    if (!std.mem.eql(u8, alg.string, "RS256")) return claimErr(arena, "jwt alg must be RS256");
    return .{ .ok = kid.string };
}

/// `UserSignature::merge_from(sdk signature, mask)` at `field`.
pub fn writeUserSignature(w: *proto.Writer, field: u32, arena: Allocator, m: Mask, b: []const u8) Error!void {
    if (b.len == 0 or b[0] != 5) return serve.render_sig.writeUserSignature(w, field, arena, m, b);
    const z = switch (try parseZkLogin(arena, b)) {
        .ok => |z| z,
        .err => return error.InvalidValue,
    };
    const mm = try w.begin(field, b.len + 64);
    if (m.contains("bcs")) {
        const bm = try w.begin(1, b.len + 32);
        try w.string(1, "UserSignatureBytes");
        try w.bytes(2, b);
        try w.end(bm);
    }
    if (m.contains("scheme")) try w.uint(2, 5);
    if (m.contains("zklogin")) try writeZkLogin(w, 5, z);
    try w.end(mm);
}

fn writeZkLogin(w: *proto.Writer, field: u32, z: ZkLogin) Error!void {
    const in = z.auth.inputs;
    const m = try w.begin(field, 1024);
    {
        const im = try w.begin(1, 900);
        {
            const pm = try w.begin(1, 800);
            try g1(w, 1, in.proofPoints.a);
            {
                const bm = try w.begin(2, 400);
                var f: u32 = 1;
                for (in.proofPoints.b) |pair| for (pair) |e| {
                    try w.string(f, e.@"0");
                    f += 1;
                };
                try w.end(bm);
            }
            try g1(w, 3, in.proofPoints.c);
            try w.end(pm);
        }
        {
            const cm = try w.begin(2, in.issBase64Details.value.@"0".len + 8);
            try w.string(1, in.issBase64Details.value.@"0");
            try w.uint(2, in.issBase64Details.indexMod4);
            try w.end(cm);
        }
        try w.string(3, in.headerBase64.@"0");
        try w.string(4, in.addressSeed.@"0");
        try w.end(im);
    }
    try w.uint(2, z.auth.maxEpoch);
    {
        const sig = z.auth.userSignature.@"0";
        const sig_len: usize = switch (sig[0]) {
            0, 1, 2 => 64,
            else => return error.InvalidValue,
        };
        if (sig.len < 1 + sig_len) return error.InvalidValue;
        const sm = try w.begin(3, sig.len + 12);
        try w.uint(1, sig[0]);
        try w.bytes(2, sig[1..][0..sig_len]);
        try w.bytes(3, sig[1 + sig_len ..]);
        try w.end(sm);
    }
    {
        const pm = try w.begin(4, z.iss.len + 90);
        try w.string(1, z.iss);
        try w.string(2, in.addressSeed.@"0");
        try w.end(pm);
    }
    {
        const jm = try w.begin(5, z.iss.len + z.kid.len + 8);
        try w.string(1, z.iss);
        try w.string(2, z.kid);
        try w.end(jm);
    }
    try w.end(m);
}

fn g1(w: *proto.Writer, field: u32, es: anytype) Error!void {
    const m = try w.begin(field, 240);
    for (es, 1..) |e, f| try w.string(@intCast(f), e.@"0");
    try w.end(m);
}
