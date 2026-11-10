//! sui.rpc.v2 SignatureVerificationService.VerifySignature, as sui-node 1.83.1 answers it.
//!
//! sui-node does not use fastcrypto here: `sui-rpc-api` `signature_verification_service.rs` parses
//! the signature with sui-sdk-types (`UserSignature::try_from(proto)`), hashes the message as
//! sui-sdk-types `Transaction`/`PersonalMessage` signing digests and verifies with sui-crypto's
//! `UserSignatureVerifier` (sui-rust-sdk 8c356d6). The rules that differ from the consensus path
//! (`sig.user`) and that this file follows:
//! - Ed25519 is ed25519-dalek `verify_strict` (canonical s, no small-order A or R, R compared as
//!   bytes), not ZIP-215.
//! - secp256r1 accepts high-s (p256), secp256k1 rejects it (k256); every ECDSA failure reads
//!   "signature error".
//! - zkLogin: no epoch check (max_epoch is only a proof input), no provider list, JWK lookup by
//!   the exact (iss, kid), mainnet/testnet use only the v1 production key (circuit mode Both
//!   falls back to v1), the JWK set is the request's `jwks` or else the chain's authenticator
//!   state (0x7) at the read.
//! - Multisig: committee validity, bitmap and weight checks with sui-crypto's texts.
//! Every failure is `signature error: <source>` (signature::Error's Display), and the response is
//! `{ is_valid, reason, address_aliases_checked }`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const sig = @import("sig");
const zk = @import("zk");
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const h2 = @import("h2/root.zig");
const proto = @import("proto.zig");
const status = @import("status.zig");
const reqdecode = @import("reqdecode.zig");
const sdkjson = @import("sdkjson.zig");
const MlDsa = std.crypto.sign.mldsa.MLDSA65;
const Blake2b256 = std.crypto.hash.blake2.Blake2b256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Ed = std.crypto.ecc.Edwards25519;
const ed25519 = sig.ed25519;
const bn = zk.bn254;
const Fq = bn.Fq;
const Fr = bn.Fr;
const Fq2 = bn.Fq2;

pub const path = "/sui.rpc.v2.SignatureVerificationService/VerifySignature";
pub const prefix = "/sui.rpc.v2.SignatureVerificationService/";

/// One active JWK (`ActiveJwk` minus the epoch).
pub const Jwk = struct { iss: []const u8, kid: []const u8, kty: []const u8, e: []const u8, n: []const u8, alg: []const u8 };

/// Where the handler reads chain state: the AuthenticatorState JWK set and AddressAliases.
pub const Env = struct {
    /// "mainnet" and "testnet" use the production zkLogin key; anything else the dev keys.
    chain_name: []const u8 = "mainnet",
    /// Live object bytes (BCS `Object`) by id, or null.
    ctx: *anyopaque,
    liveObject: *const fn (ctx: *anyopaque, id: *const [32]u8) ?[]const u8,
};

pub const Reply = union(enum) {
    /// Encoded VerifySignatureResponse.
    ok: []const u8,
    /// INVALID_ARGUMENT with one BadRequest field violation.
    bad: struct { field: []const u8, description: []const u8, reason: status.Reason },
    /// Another gRPC code with a plain message (RpcError: details carry google.rpc.Status).
    err: struct { code: h2.Status, message: []const u8 },
    /// prost rejected the request: tonic's INTERNAL with the DecodeError text and no details.
    decode: []const u8,
};

/// Writes `r` the way sui-node's tonic stack answers it.
pub fn respond(arena: Allocator, r: Reply, rs: *h2.ResponseStream) h2.Status {
    switch (r) {
        .ok => |body| {
            rs.message(body) catch {
                rs.setMessage("internal error");
                return .internal;
            };
            return .ok;
        },
        .bad => |b| {
            const bin = status.badRequest(arena, @intFromEnum(h2.Status.invalid_argument), b.field, b.description, b.reason) catch {
                rs.setMessage("internal error");
                return .internal;
            };
            rs.setMessage(b.description);
            rs.details(bin);
            return .invalid_argument;
        },
        .err => |e| {
            rs.setMessage(e.message);
            if (status.plain(arena, @intFromEnum(e.code), e.message)) |bin| rs.details(bin) else |_| {}
            return e.code;
        },
        .decode => |text| {
            rs.setMessage(text);
            return .internal;
        },
    }
}

/// The SignatureVerificationService entry for `service.zig`: path check, decode, handle, respond.
pub fn call(arena: Allocator, env: *const Env, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    if (!std.mem.eql(u8, req.path, path)) return .unimplemented;
    const r = handle(arena, env, req.body) catch {
        rs.setMessage("internal error");
        return .internal;
    };
    return respond(arena, r, rs);
}

const E = error{OutOfMemory};

// ------------------------------------------------------------------------------------------------
// Request

const Request = struct {
    msg_present: bool = false,
    msg_name: []const u8 = "",
    msg_value: []const u8 = "",
    sig_present: bool = false,
    sig_bcs_present: bool = false,
    sig_bcs: []const u8 = "",
    scheme: ?u64 = null,
    /// The oneof member (field number 3..6) and its bytes, last one wins.
    oneof_field: u32 = 0,
    oneof: std.ArrayList([]const u8) = .empty,
    address: ?[]const u8 = null,
    jwks: std.ArrayList([]const u8) = .empty,
    check_aliases: ?bool = null,
};

/// prost's decode of VerifySignatureRequest: scalars last-wins, message fields merge.
fn parseRequest(arena: Allocator, body: []const u8) (E || error{Malformed})!Request {
    var q: Request = .{};
    var r = proto.Reader.init(body);
    while (try r.next()) |f| switch (f.number) {
        1 => {
            q.msg_present = true;
            var m = proto.Reader.init(try proto.Reader.bytesOf(f));
            while (try m.next()) |g| switch (g.number) {
                1 => q.msg_name = try proto.Reader.stringOf(g),
                2 => q.msg_value = try proto.Reader.bytesOf(g),
                else => {},
            };
        },
        2 => {
            q.sig_present = true;
            var m = proto.Reader.init(try proto.Reader.bytesOf(f));
            while (try m.next()) |g| switch (g.number) {
                1 => {
                    q.sig_bcs_present = true;
                    var b = proto.Reader.init(try proto.Reader.bytesOf(g));
                    while (try b.next()) |h| switch (h.number) {
                        1 => _ = try proto.Reader.stringOf(h),
                        2 => q.sig_bcs = try proto.Reader.bytesOf(h),
                        else => {},
                    };
                },
                2 => q.scheme = try proto.Reader.varintOf(g),
                3, 4, 5, 6 => {
                    if (q.oneof_field != g.number) q.oneof.clearRetainingCapacity();
                    q.oneof_field = g.number;
                    try q.oneof.append(arena, try proto.Reader.bytesOf(g));
                },
                else => {},
            };
        },
        3 => q.address = try proto.Reader.stringOf(f),
        4 => try q.jwks.append(arena, try proto.Reader.bytesOf(f)),
        6 => q.check_aliases = (try proto.Reader.varintOf(f)) != 0,
        else => {},
    };
    return q;
}

// ------------------------------------------------------------------------------------------------
// Handler

pub fn handle(arena: Allocator, env: *const Env, body: []const u8) E!Reply {
    if (reqdecode.check(arena, &reqdecode.verify_signature_request, body)) |text| return .{ .decode = text };
    const q = parseRequest(arena, body) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Malformed => return .{ .err = .{ .code = .internal, .message = "failed to decode Protobuf message" } },
    };

    // signature
    if (!q.sig_present) return .{ .bad = .{ .field = "signature", .description = "", .reason = .field_missing } };
    var p: Parser = .{ .arena = arena };
    const user = (try protoSignature(&p, &q)) orelse {
        const d = try std.fmt.allocPrint(arena, "invalid signature: {s}", .{p.err});
        return .{ .bad = .{ .field = "signature", .description = d, .reason = .field_invalid } };
    };

    // message
    if (!q.msg_present) return .{ .bad = .{ .field = "message", .description = "", .reason = .field_missing } };
    var digest: [32]u8 = undefined;
    if (std.mem.eql(u8, q.msg_name, "TransactionData")) {
        if (txError(arena, q.msg_value)) |text| return .{ .err = .{ .code = .internal, .message = text } };
        digest = intentDigest(.{ 0, 0, 0 }, q.msg_value);
    } else if (std.mem.eql(u8, q.msg_name, "PersonalMessage")) {
        if (personalError(arena, q.msg_value)) |text| return .{ .err = .{ .code = .internal, .message = text } };
        digest = intentDigest(.{ 3, 0, 0 }, q.msg_value);
    } else if (personalError(arena, q.msg_value) == null) {
        digest = intentDigest(.{ 3, 0, 0 }, q.msg_value);
    } else if (txError(arena, q.msg_value) == null) {
        digest = intentDigest(.{ 0, 0, 0 }, q.msg_value);
    } else return .{ .bad = .{ .field = "message", .description = "invalid message", .reason = .field_invalid } };

    const check_aliases = q.check_aliases orelse false;
    if (check_aliases and q.address == null)
        return .{ .bad = .{ .field = "address", .description = "address is required when check_address_aliases is set", .reason = .field_missing } };

    var resp: Response = .{ .aliases_checked = check_aliases };

    if (q.address) |text| {
        const address = parseAddress(text) orelse
            return .{ .bad = .{ .field = "address", .description = "invalid address: Unable to parse Address (must be hex string of length 32)", .reason = .field_invalid } };
        var derived: [2]?[32]u8 = .{ null, null };
        switch (user) {
            .simple => |s| {
                if (s.scheme == 7) derived[0] = simpleAddress(s.scheme, s.pk) else derived[0] = simpleAddress(s.scheme, s.pk);
            },
            .multisig => |m| derived[0] = m.address(),
            .zklogin => |z| {
                derived[0] = zkAddress(z.iss, &z.seed, true);
                derived[1] = zkAddress(z.iss, &z.seed, false);
            },
            .passkey => |pk| derived[0] = simpleAddress(6, &pk.pk),
        }
        const authorized = if (check_aliases) try aliasesOf(arena, env, &address) else try arena.dupe([32]u8, &.{address});
        var found = false;
        for (derived) |d| if (d) |a| for (authorized) |x| {
            if (std.mem.eql(u8, &a, &x)) found = true;
        };
        if (!found) {
            const first = hexAddr(derived[0].?);
            const given = hexAddr(address);
            resp.valid = false;
            resp.reason = if (check_aliases)
                try std.fmt.allocPrint(arena, "derived address `{s}` is not an alias of `{s}`", .{ &first, &given })
            else
                try std.fmt.allocPrint(arena, "provided address `{s}` does not match derived address `{s}`", .{ &given, &first });
            return .{ .ok = try resp.encode(arena) };
        }
    }

    var v: Verifier = .{ .arena = arena, .env = env };
    if (mayContainZkLogin(user)) {
        if (try v.loadJwks(q.jwks.items)) |bad| return bad;
    }
    if (try v.verifyUser(&digest, user)) |reason| {
        resp.valid = false;
        // signature::Error's Display: "signature error" and, when there is a source, ": <source>"
        resp.reason = if (reason.len == 0) "signature error" else try std.fmt.allocPrint(arena, "signature error: {s}", .{reason});
    } else resp.valid = true;
    return .{ .ok = try resp.encode(arena) };
}

const Response = struct {
    valid: bool = false,
    reason: ?[]const u8 = null,
    aliases_checked: bool,

    fn encode(r: Response, arena: Allocator) E![]const u8 {
        const reason = r.reason orelse "";
        const buf = try arena.alloc(u8, reason.len + 16);
        var w = proto.Writer.init(buf);
        w.uint(1, @intFromBool(r.valid)) catch unreachable;
        if (r.reason) |t| w.bytes(2, t) catch unreachable;
        if (r.aliases_checked) w.uint(3, 1) catch unreachable;
        return w.bytesWritten();
    }
};

/// Blake2b256(intent || value): sui-sdk-types `signing_digest` (the value re-serializes to itself).
fn intentDigest(intent: [3]u8, value: []const u8) [32]u8 {
    var h = Blake2b256.init(.{});
    h.update(&intent);
    h.update(value);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// `bcs::from_bytes::<&[u8]>`: ULEB128 length, the bytes, nothing after.
fn personalError(arena: Allocator, value: []const u8) ?[]const u8 {
    var r: Rd = .{ .b = value };
    const n = r.len() catch |e| return bcsMsg(arena, e);
    _ = r.take(n) catch |e| return bcsMsg(arena, e);
    if (r.i != value.len) return "remaining input";
    return null;
}

/// `bcs::from_bytes::<sui_sdk_types::Transaction>` (TransactionData V1).
fn txError(arena: Allocator, value: []const u8) ?[]const u8 {
    {
        // TransactionData is an enum with one variant: bcs reads the ULEB128 variant index first
        var r: Rd = .{ .b = value };
        const tag = r.uleb() catch |e| return bcsMsg(arena, e);
        if (tag != 0) return std.fmt.allocPrint(arena, "invalid value: integer `{d}`, expected variant index 0 <= i < 1", .{tag}) catch "out of memory";
    }
    const tx = bcs.decode(types.TransactionData, arena, value) catch |e| return switch (e) {
        error.EndOfInput => "unexpected end of input",
        error.TrailingBytes => "remaining input",
        error.InvalidUleb => "ULEB128 encoding was not minimal in size",
        error.InvalidBool => "expected boolean",
        error.InvalidUtf8 => "malformed utf8",
        error.OutOfMemory => "out of memory",
        else => "invalid transaction",
    };
    return sdkLimits(arena, &tx);
}

// sui-sdk-types decodes `Transaction` with stricter Move names than sui-types: an `Identifier`
// (MoveCall module/function, StructTag module/name) must be a valid identifier of at most 128
// bytes (`unable to parse type "<s>"`), and each TypeTag has its own node budget (256) and
// nesting limit (128) (type_tag/serialization.rs). deepwave decodes with sui-types' layout, so the sdk
// limits are checked on the decoded value in byte order.

const max_ident = 128;
const max_tt_depth = 128;
const max_tt_nodes = 256;

fn sdkIdentValid(s: []const u8) bool {
    if (s.len == 0 or s.len > max_ident) return false;
    const rest = switch (s[0]) {
        'a'...'z', 'A'...'Z' => s[1..],
        '_' => if (s.len > 1) s[1..] else return false,
        else => return false,
    };
    for (rest) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_')) return false;
    return true;
}

fn identErr(arena: Allocator, s: []const u8) ?[]const u8 {
    if (sdkIdentValid(s)) return null;
    return std.fmt.allocPrint(arena, "unable to parse type \"{s}\"", .{s}) catch "out of memory";
}

fn ttCheck(arena: Allocator, t: anytype, depth: usize, nodes: *u64) ?[]const u8 {
    nodes.* += 1;
    if (nodes.* > max_tt_nodes) return "type tag exceeds max node count of 256";
    if (depth >= max_tt_depth) return "type tag exceeds max nesting depth of 128";
    switch (t.*) {
        .vector => |inner| return ttCheck(arena, inner, depth + 1, nodes),
        .@"struct" => |st| {
            if (identErr(arena, nameOf(st.module))) |e| return e;
            if (identErr(arena, nameOf(st.name))) |e| return e;
            for (st.type_args) |*a| if (ttCheck(arena, a, depth + 1, nodes)) |e| return e;
            return null;
        },
        else => return null,
    }
}

fn nameOf(x: anytype) []const u8 {
    const T = @TypeOf(x);
    if (T == []const u8) return x;
    if (@hasField(T, "@\"0\"")) return x.@"0";
    return x.str();
}

fn sdkLimits(arena: Allocator, tx: *const types.TransactionData) ?[]const u8 {
    const v1 = switch (tx.*) {
        .V1 => |*v| v,
    };
    const pt = switch (v1.kind) {
        .ProgrammableTransaction => |*pt| pt,
        else => return null,
    };
    for (pt.inputs) |*in| switch (in.*) {
        .FundsWithdrawal => |*fw| switch (fw.type_arg) {
            .Balance => |*t| {
                var nodes: u64 = 0;
                if (ttCheck(arena, t, 0, &nodes)) |e| return e;
            },
        },
        else => {},
    };
    for (pt.commands) |*c| switch (c.*) {
        .MoveCall => |*mc| {
            if (identErr(arena, nameOf(mc.module))) |e| return e;
            if (identErr(arena, nameOf(mc.function))) |e| return e;
            for (mc.type_arguments) |*t| {
                var nodes: u64 = 0;
                if (ttCheck(arena, t, 0, &nodes)) |e| return e;
            }
        },
        .MakeMoveVec => |*mv| if (mv.@"0") |*t| {
            var nodes: u64 = 0;
            if (ttCheck(arena, t, 0, &nodes)) |e| return e;
        },
        else => {},
    };
    return null;
}

fn parseAddress(text: []const u8) ?[32]u8 {
    if (text.len == 0) return null;
    const hex = if (text.len >= 2 and text[0] == '0' and text[1] == 'x') text[2..] else text;
    if (hex.len == 0 or hex.len > 64) return null;
    var out: [32]u8 = @splat(0);
    var i = hex.len;
    var j: usize = 32;
    while (i >= 2) : (i -= 2) {
        const lo = std.fmt.charToDigit(hex[i - 1], 16) catch return null;
        const hi = std.fmt.charToDigit(hex[i - 2], 16) catch return null;
        j -= 1;
        out[j] = @intCast(hi * 16 + lo);
    }
    if (i == 1) {
        out[j - 1] = std.fmt.charToDigit(hex[0], 16) catch return null;
    }
    return out;
}

fn hexAddr(a: [32]u8) [66]u8 {
    var out: [66]u8 = undefined;
    out[0] = '0';
    out[1] = 'x';
    _ = std.fmt.bufPrint(out[2..], "{x}", .{&a}) catch unreachable;
    return out;
}

fn simpleAddress(flag: u8, pk: []const u8) [32]u8 {
    var h = Blake2b256.init(.{});
    h.update(&.{flag});
    h.update(pk);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn zkAddress(iss: []const u8, seed: *const [32]u8, padded: bool) [32]u8 {
    var h = Blake2b256.init(.{});
    h.update(&.{ 5, @truncate(iss.len) });
    h.update(iss);
    if (padded) h.update(seed) else {
        var i: usize = 0;
        while (i < 31 and seed[i] == 0) i += 1;
        h.update(seed[i..]);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

// ------------------------------------------------------------------------------------------------
// Chain state reads

fn moveContents(arena: Allocator, raw: []const u8) ?[]const u8 {
    const obj = bcs.decode(types.Object, arena, raw) catch return null;
    return switch (obj.data) {
        .Move => |m| m.contents,
        else => null,
    };
}

/// Dynamic field id: Blake2b256(0xf0 || parent || len(key) u64 || key || BCS(key type)).
fn dynamicFieldId(parent: *const [32]u8, key: []const u8, type_tag: []const u8) [32]u8 {
    var h = Blake2b256.init(.{});
    h.update(&.{0xf0});
    h.update(parent);
    var l: [8]u8 = undefined;
    std.mem.writeInt(u64, &l, key.len, .little);
    h.update(&l);
    h.update(key);
    h.update(type_tag);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

const sui_framework: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 2;
    break :blk a;
};

fn objectId(last: u8) [32]u8 {
    var a: [32]u8 = @splat(0);
    a[31] = last;
    return a;
}

/// sui-types `address_aliases_object_id`: a derived object under 0xa keyed by
/// `DerivedObjectKey<address_alias::AliasKey>(address)`.
pub fn aliasesObjectId(address: *const [32]u8) [32]u8 {
    var tag: [128]u8 = undefined;
    var n: usize = 0;
    const put = struct {
        fn f(buf: []u8, at: *usize, b: []const u8) void {
            @memcpy(buf[at.*..][0..b.len], b);
            at.* += b.len;
        }
    }.f;
    put(&tag, &n, &.{7});
    put(&tag, &n, &sui_framework);
    put(&tag, &n, &.{"derived_object".len});
    put(&tag, &n, "derived_object");
    put(&tag, &n, &.{"DerivedObjectKey".len});
    put(&tag, &n, "DerivedObjectKey");
    put(&tag, &n, &.{ 1, 7 });
    put(&tag, &n, &sui_framework);
    put(&tag, &n, &.{"address_alias".len});
    put(&tag, &n, "address_alias");
    put(&tag, &n, &.{"AliasKey".len});
    put(&tag, &n, "AliasKey");
    put(&tag, &n, &.{0});
    return dynamicFieldId(&objectId(0xa), address, tag[0..n]);
}

/// `address_aliases(service, address)`: the AddressAliases set when the object exists.
fn aliasesOf(arena: Allocator, env: *const Env, address: *const [32]u8) E![]const [32]u8 {
    const id = aliasesObjectId(address);
    const raw = env.liveObject(env.ctx, &id) orelse return try arena.dupe([32]u8, &.{address.*});
    const c = moveContents(arena, raw) orelse return try arena.dupe([32]u8, &.{address.*});
    var r: Rd = .{ .b = c };
    _ = r.take(32) catch return try arena.dupe([32]u8, &.{address.*});
    const n = r.len() catch return try arena.dupe([32]u8, &.{address.*});
    const out = try arena.alloc([32]u8, n);
    for (out) |*a| a.* = (r.take(32) catch return try arena.dupe([32]u8, &.{address.*}))[0..32].*;
    return out;
}

/// `get_authenticator_state`: 0x7's AuthenticatorState { id, version }, then the dynamic field
/// `Field<u64, AuthenticatorStateInner>` holding `active_jwks`. Empty when absent.
pub fn chainJwks(arena: Allocator, env: *const Env) E![]const Jwk {
    const raw = env.liveObject(env.ctx, &objectId(7)) orelse return &.{};
    const c = moveContents(arena, raw) orelse return &.{};
    if (c.len < 40) return &.{};
    var key: [8]u8 = c[32..40].*;
    const fid = dynamicFieldId(&objectId(7), &key, &.{2});
    const fraw = env.liveObject(env.ctx, &fid) orelse return &.{};
    const fc = moveContents(arena, fraw) orelse return &.{};
    return parseInner(arena, fc[@min(fc.len, 40)..]) catch &.{};
}

/// AuthenticatorStateInner { version: u64, active_jwks: vector<ActiveJwk> } (after the Field's id and name).
pub fn parseInner(arena: Allocator, b: []const u8) (E || error{Bad})![]const Jwk {
    var r: Rd = .{ .b = b };
    _ = r.take(8) catch return error.Bad;
    const n = r.len() catch return error.Bad;
    if (n > b.len) return error.Bad;
    const out = try arena.alloc(Jwk, n);
    for (out) |*j| {
        j.iss = r.bytesV() catch return error.Bad;
        j.kid = r.bytesV() catch return error.Bad;
        j.kty = r.bytesV() catch return error.Bad;
        j.e = r.bytesV() catch return error.Bad;
        j.n = r.bytesV() catch return error.Bad;
        j.alg = r.bytesV() catch return error.Bad;
        _ = r.take(8) catch return error.Bad;
    }
    return out;
}

// ------------------------------------------------------------------------------------------------
// BCS reading with bcs 0.1.6's errors

const BcsErr = error{ Eof, NonCanonical, Overflow, MaxLen, Utf8, Remaining, Custom };

/// The length bcs rejected last (`ExceededMaxLen(len)`), per thread.
threadlocal var max_len_seen: usize = 0;

fn bcsMsg(arena: Allocator, e: BcsErr) []const u8 {
    if (e == error.MaxLen) return std.fmt.allocPrint(arena, "exceeded max sequence length: {d}", .{max_len_seen}) catch "out of memory";
    return bcsText(e);
}

fn bcsText(e: BcsErr) []const u8 {
    return switch (e) {
        error.Eof => "unexpected end of input",
        error.NonCanonical => "ULEB128 encoding was not minimal in size",
        error.Overflow => "ULEB128-encoded integer did not fit in the target size",
        error.MaxLen => "exceeded max sequence length",
        error.Utf8 => "malformed utf8",
        error.Remaining => "remaining input",
        error.Custom => "custom",
    };
}

const Rd = struct {
    b: []const u8,
    i: usize = 0,

    fn byte(r: *Rd) BcsErr!u8 {
        if (r.i >= r.b.len) return error.Eof;
        defer r.i += 1;
        return r.b[r.i];
    }
    fn take(r: *Rd, n: usize) BcsErr![]const u8 {
        if (r.b.len - r.i < n) return error.Eof;
        defer r.i += n;
        return r.b[r.i..][0..n];
    }
    fn uleb(r: *Rd) BcsErr!u32 {
        var v: u64 = 0;
        var shift: u6 = 0;
        while (shift < 32) : (shift += 7) {
            const b = try r.byte();
            const d = b & 0x7f;
            v |= @as(u64, d) << shift;
            if (d == b) {
                if (shift > 0 and d == 0) return error.NonCanonical;
                if (v > std.math.maxInt(u32)) return error.Overflow;
                return @intCast(v);
            }
        }
        return error.Overflow;
    }
    fn len(r: *Rd) BcsErr!usize {
        const n = try r.uleb();
        if (n > std.math.maxInt(i32)) {
            max_len_seen = n;
            return error.MaxLen;
        }
        return n;
    }
    fn bytesV(r: *Rd) BcsErr![]const u8 {
        return r.take(try r.len());
    }
    fn str(r: *Rd) BcsErr![]const u8 {
        const s = try r.bytesV();
        if (!std.unicode.utf8ValidateSlice(s)) return error.Utf8;
        return s;
    }
    fn u16le(r: *Rd) BcsErr!u16 {
        return std.mem.readInt(u16, (try r.take(2))[0..2], .little);
    }
    fn u64le(r: *Rd) BcsErr!u64 {
        return std.mem.readInt(u64, (try r.take(8))[0..8], .little);
    }
};

// ------------------------------------------------------------------------------------------------
// sui-sdk-types UserSignature

const Simple = struct { scheme: u8, sig: []const u8, pk: []const u8 };

const ZkAuth = struct {
    a: [3][32]u8,
    b: [3][2][32]u8,
    c: [3][32]u8,
    iss_value: []const u8,
    index_mod_4: u8,
    header: []const u8,
    seed: [32]u8,
    max_epoch: u64,
    simple: Simple,
    iss: []const u8,
    kid: []const u8,
};

const Passkey = struct {
    auth_data: []const u8,
    client_data_json: []const u8,
    sig: [64]u8,
    pk: [33]u8,
    challenge: []const u8,
};

const MemberPk = union(enum) {
    ed25519: []const u8,
    secp256k1: []const u8,
    secp256r1: []const u8,
    zklogin: struct { iss: []const u8, seed: [32]u8 },
    passkey: []const u8,
    mldsa65: []const u8,

    fn eql(a: MemberPk, b: MemberPk) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .zklogin => |z| std.mem.eql(u8, z.iss, b.zklogin.iss) and std.mem.eql(u8, &z.seed, &b.zklogin.seed),
            inline else => |x, t| std.mem.eql(u8, x, @field(b, @tagName(t))),
        };
    }
};

const MemberSig = union(enum) {
    ed25519: []const u8,
    secp256k1: []const u8,
    secp256r1: []const u8,
    zklogin: *ZkAuth,
    passkey: *Passkey,
    mldsa65: []const u8,
};

const Member = struct { pk: MemberPk, weight: u8 };

const Multisig = struct {
    sigs: []const MemberSig,
    bitmap: u16,
    members: []const Member,
    threshold: u16,

    fn address(m: *const Multisig) [32]u8 {
        var h = Blake2b256.init(.{});
        h.update(&.{3});
        var t: [2]u8 = undefined;
        std.mem.writeInt(u16, &t, m.threshold, .little);
        h.update(&t);
        for (m.members) |mem| {
            switch (mem.pk) {
                .ed25519 => |k| {
                    h.update(&.{0});
                    h.update(k);
                },
                .secp256k1 => |k| {
                    h.update(&.{1});
                    h.update(k);
                },
                .secp256r1 => |k| {
                    h.update(&.{2});
                    h.update(k);
                },
                .zklogin => |z| {
                    h.update(&.{ 5, @truncate(z.iss.len) });
                    h.update(z.iss);
                    h.update(&z.seed);
                },
                .passkey => |k| {
                    h.update(&.{6});
                    h.update(k);
                },
                .mldsa65 => |k| {
                    h.update(&.{7});
                    h.update(k);
                },
            }
            h.update(&.{mem.weight});
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
};

const UserSig = union(enum) {
    simple: Simple,
    multisig: Multisig,
    zklogin: *ZkAuth,
    passkey: *Passkey,
};

fn mayContainZkLogin(u: UserSig) bool {
    return switch (u) {
        .zklogin => true,
        .multisig => |m| for (m.members) |mem| {
            if (mem.pk == .zklogin) break true;
        } else false,
        else => false,
    };
}

const mldsa65_sig_len = 3309;
const mldsa65_pk_len = 1952;

/// Parse failures carry the text sui-sdk-types / bcs would give.
/// `UserSignature::from_serialized_bytes` (sui-sdk-types) for ExecuteTransaction's request
/// decoder (rpc_exec handler): null when the bytes form a signature, else the error text.
pub fn serializedUserSigError(arena: Allocator, bytes: []const u8) Allocator.Error!?[]const u8 {
    var p: Parser = .{ .arena = arena };
    _ = p.userSig(bytes) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Parse => return p.err,
    };
    return null;
}

const Parser = struct {
    arena: Allocator,
    err: []const u8 = "",

    fn fail(p: *Parser, text: []const u8) error{Parse} {
        p.err = text;
        return error.Parse;
    }
    fn failf(p: *Parser, comptime f: []const u8, args: anytype) error{Parse} {
        p.err = std.fmt.allocPrint(p.arena, f, args) catch "out of memory";
        return error.Parse;
    }
    fn bcsFail(p: *Parser, e: BcsErr) error{Parse} {
        return switch (e) {
            error.Custom => error.Parse, // text already set
            error.MaxLen => p.failf("exceeded max sequence length: {d}", .{max_len_seen}),
            else => p.fail(bcsText(e)),
        };
    }

    /// `SignatureScheme::from_byte` text for an unknown flag.
    fn flagOf(p: *Parser, bytes: []const u8) error{Parse}!u8 {
        if (bytes.len == 0) return p.fail("missing signature scheme flag");
        if (bytes[0] > 7) return p.failf("invalid signature scheme: {x:0>2}", .{bytes[0]});
        return bytes[0];
    }

    /// `UserSignature::from_serialized_bytes`.
    fn userSig(p: *Parser, bytes: []const u8) error{ Parse, OutOfMemory }!UserSig {
        const flag = try p.flagOf(bytes);
        return switch (flag) {
            0, 1, 2, 7 => .{ .simple = try p.simple(bytes) },
            3 => .{ .multisig = try p.multisig(bytes) },
            4 => p.fail("bls not supported for user signatures"),
            5 => .{ .zklogin = try p.zklogin(bytes) },
            6 => .{ .passkey = try p.passkey(bytes) },
            else => unreachable,
        };
    }

    /// `SimpleSignature::from_serialized_bytes`.
    fn simple(p: *Parser, bytes: []const u8) error{Parse}!Simple {
        const flag = try p.flagOf(bytes);
        const lens: struct { s: usize, k: usize, text: []const u8 } = switch (flag) {
            0 => .{ .s = 64, .k = 32, .text = "invalid ed25519 signature" },
            1 => .{ .s = 64, .k = 33, .text = "invalid secp25k1 signature" },
            2 => .{ .s = 64, .k = 33, .text = "invalid secp25r1 signature" },
            7 => .{ .s = mldsa65_sig_len, .k = mldsa65_pk_len, .text = "invalid mldsa65 signature" },
            else => return p.fail("invalid signature scheme"),
        };
        if (bytes.len != 1 + lens.s + lens.k) return p.fail(lens.text);
        return .{ .scheme = flag, .sig = bytes[1..][0..lens.s], .pk = bytes[1 + lens.s ..] };
    }

    fn multisig(p: *Parser, bytes: []const u8) error{ Parse, OutOfMemory }!Multisig {
        const body = bytes[1..];
        if (p.multisigNew(body)) |m| return m else |e| if (e == error.OutOfMemory) return error.OutOfMemory;
        if (p.multisigLegacy(body)) |m| return m else |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            // the legacy struct parsed but an index is >= 10: roaring_bitmap_to_u16's text
            error.HighIndex => return p.fail("invalid bitmap"),
            error.Parse => {},
        }
        return p.fail("invalid multisig");
    }

    fn memberSigs(p: *Parser, r: *Rd) error{ Parse, OutOfMemory }![]const MemberSig {
        const n = r.len() catch |e| return p.bcsFail(e);
        if (n > r.b.len) return p.bcsFail(error.Eof);
        const out = try p.arena.alloc(MemberSig, n);
        for (out) |*s| {
            const tag = r.uleb() catch |e| return p.bcsFail(e);
            s.* = switch (tag) {
                0 => .{ .ed25519 = r.take(64) catch |e| return p.bcsFail(e) },
                1 => .{ .secp256k1 = r.take(64) catch |e| return p.bcsFail(e) },
                2 => .{ .secp256r1 = r.take(64) catch |e| return p.bcsFail(e) },
                3 => .{ .zklogin = try p.zklogin(r.bytesV() catch |e| return p.bcsFail(e)) },
                4 => .{ .passkey = try p.passkey(r.bytesV() catch |e| return p.bcsFail(e)) },
                5 => .{ .mldsa65 = r.take(mldsa65_sig_len) catch |e| return p.bcsFail(e) },
                else => return p.failf("invalid value: integer `{d}`, expected variant index 0 <= i < 6", .{tag}),
            };
        }
        return out;
    }

    fn multisigNew(p: *Parser, body: []const u8) error{ Parse, OutOfMemory }!Multisig {
        var r: Rd = .{ .b = body };
        const sigs = try p.memberSigs(&r);
        const bitmap = r.u16le() catch |e| return p.bcsFail(e);
        const n = r.len() catch |e| return p.bcsFail(e);
        if (n > body.len) return p.bcsFail(error.Eof);
        const members = try p.arena.alloc(Member, n);
        for (members) |*m| {
            const tag = r.uleb() catch |e| return p.bcsFail(e);
            m.pk = switch (tag) {
                0 => .{ .ed25519 = r.take(32) catch |e| return p.bcsFail(e) },
                1 => .{ .secp256k1 = r.take(33) catch |e| return p.bcsFail(e) },
                2 => .{ .secp256r1 = r.take(33) catch |e| return p.bcsFail(e) },
                3 => blk: {
                    const b = r.bytesV() catch |e| return p.bcsFail(e);
                    if (b.len < 1) return p.fail("invalid zklogin public identifier");
                    const il = b[0];
                    if (b.len < 1 + @as(usize, il)) return p.fail("invalid zklogin public identifier");
                    const iss = b[1..][0..il];
                    if (!std.unicode.utf8ValidateSlice(iss)) return p.fail("invalid utf-8 sequence");
                    const rest = b[1 + @as(usize, il) ..];
                    if (rest.len != 32) return p.fail("could not convert slice to array");
                    break :blk .{ .zklogin = .{ .iss = iss, .seed = rest[0..32].* } };
                },
                4 => .{ .passkey = r.take(33) catch |e| return p.bcsFail(e) },
                5 => .{ .mldsa65 = r.take(mldsa65_pk_len) catch |e| return p.bcsFail(e) },
                else => return p.failf("invalid value: integer `{d}`, expected variant index 0 <= i < 6", .{tag}),
            };
            m.weight = r.byte() catch |e| return p.bcsFail(e);
        }
        const threshold = r.u16le() catch |e| return p.bcsFail(e);
        if (r.i != body.len) return p.bcsFail(error.Remaining);
        return .{ .sigs = sigs, .bitmap = bitmap, .members = members, .threshold = threshold };
    }

    fn multisigLegacy(p: *Parser, body: []const u8) error{ Parse, OutOfMemory, HighIndex }!Multisig {
        var r: Rd = .{ .b = body };
        const sigs = try p.memberSigs(&r);
        const bm = r.bytesV() catch |e| return p.bcsFail(e);
        // sui-sdk-types `deserialize_canonical_bitmap`: roaring, then no bytes left
        const rb = switch (roaringRead(p.arena, bm)) {
            .ok => |x| x,
            .err => |t| return p.fail(t),
        };
        if (rb.used != bm.len) return p.fail("trailing bytes after roaring bitmap encoding");
        const n = r.len() catch |e| return p.bcsFail(e);
        if (n > body.len) return p.bcsFail(error.Eof);
        const members = try p.arena.alloc(Member, n);
        for (members) |*m| {
            const s = r.str() catch |e| return p.bcsFail(e);
            m.pk = try p.legacyKey(s);
            m.weight = r.byte() catch |e| return p.bcsFail(e);
        }
        const threshold = r.u16le() catch |e| return p.bcsFail(e);
        if (r.i != body.len) return p.bcsFail(error.Remaining);
        if (rb.high) return error.HighIndex;
        return .{ .sigs = sigs, .bitmap = rb.bits, .members = members, .threshold = threshold };
    }

    /// `Base64MultisigMemberPublicKey`: standard base64 of flag || key (ed25519/k1/r1 only).
    fn legacyKey(p: *Parser, s: []const u8) error{ Parse, OutOfMemory }!MemberPk {
        const dec = std.base64.standard.Decoder;
        const n = dec.calcSizeForSlice(s) catch return p.fail("invalid Base64 encoding");
        const buf = try p.arena.alloc(u8, n);
        dec.decode(buf, s) catch return p.fail("invalid Base64 encoding");
        if (buf.len == 0) return p.fail("missing signature scheme flag");
        const k = buf[1..];
        return switch (buf[0]) {
            0 => if (k.len == 32) .{ .ed25519 = k } else p.fail("invalid ed25519 public key length"),
            1 => if (k.len == 33) .{ .secp256k1 = k } else p.fail("invalid secp256k1 public key length"),
            2 => if (k.len == 33) .{ .secp256r1 = k } else p.fail("invalid secp256r1 public key length"),
            3...7 => p.fail("invalid public key type"),
            else => p.failf("invalid signature scheme: {x:0>2}", .{buf[0]}),
        };
    }

    /// Bn254FieldElement's BCS form: a radix-10 string, `FromStr` (bnum) then the canonical check.
    fn bn254(p: *Parser, r: *Rd) error{Parse}![32]u8 {
        const s = r.str() catch |e| return p.bcsFail(e);
        const v = switch (bnumParse(s)) {
            .ok => |v| v,
            .err => |e| return p.fail(bnText(e)),
        };
        var canon: [80]u8 = undefined;
        const c = std.fmt.bufPrint(&canon, "{d}", .{v}) catch unreachable;
        if (!std.mem.eql(u8, c, s)) return p.fail("non-canonical Bn254FieldElement encoding");
        var out: [32]u8 = undefined;
        std.mem.writeInt(u256, &out, v, .big);
        return out;
    }

    /// CircomG1: the whole `Vec<Bn254FieldElement>` first, then the length.
    fn g1(p: *Parser, r: *Rd) error{Parse}![3][32]u8 {
        const n = r.len() catch |e| return p.bcsFail(e);
        var out: [3][32]u8 = undefined;
        for (0..n) |i| {
            const x = try p.bn254(r);
            if (i < 3) out[i] = x;
        }
        if (n != 3) return p.fail("expected array of length 3");
        return out;
    }

    /// CircomG2: `Vec<Vec<Bn254FieldElement>>` decoded whole, then the shape.
    fn g2(p: *Parser, r: *Rd) error{Parse}![3][2][32]u8 {
        const n = r.len() catch |e| return p.bcsFail(e);
        var out: [3][2][32]u8 = undefined;
        var shape_ok = n == 3;
        for (0..n) |i| {
            const m = r.len() catch |e| return p.bcsFail(e);
            if (m != 2) shape_ok = false;
            for (0..m) |j| {
                const x = try p.bn254(r);
                if (i < 3 and j < 2) out[i][j] = x;
            }
        }
        if (!shape_ok) return p.fail("vector of three vectors each being a vector of two strings");
        return out;
    }

    fn zklogin(p: *Parser, bytes: []const u8) error{ Parse, OutOfMemory }!*ZkAuth {
        const flag = try p.flagOf(bytes);
        if (flag != 5) return p.fail("invalid zklogin flag");
        var r: Rd = .{ .b = bytes[1..] };
        const z = try p.arena.create(ZkAuth);
        z.a = try p.g1(&r);
        z.b = try p.g2(&r);
        z.c = try p.g1(&r);
        z.iss_value = r.str() catch |e| return p.bcsFail(e);
        z.index_mod_4 = r.byte() catch |e| return p.bcsFail(e);
        z.header = r.str() catch |e| return p.bcsFail(e);
        z.seed = try p.bn254(&r);
        try p.zkInputs(z);
        z.max_epoch = r.u64le() catch |e| return p.bcsFail(e);
        const s = r.bytesV() catch |e| return p.bcsFail(e);
        z.simple = try p.simple(s);
        if (r.i != r.b.len) return p.bcsFail(error.Remaining);
        return z;
    }

    /// `ZkLoginInputs::new` (InvalidZkLoginAuthenticatorError: "invalid zklogin claim: <msg>").
    fn zkInputs(p: *Parser, z: *ZkAuth) error{ Parse, OutOfMemory }!void {
        if (try zkInputsMsg(p.arena, z)) |m| return p.failf("invalid zklogin claim: {s}", .{m});
    }

    /// `SimpleSignature::try_from(&proto)`.
    fn simpleProto(p: *Parser, data: []const u8) ProtoParse!Simple {
        const pf = try Pf.of(p.arena, data);
        const sc_raw = pf.v[1] orelse return ParserProto.missing(p, "scheme");
        // prost decodes the enum as i32 (truncating); values outside 0..=7: UnknownEnumValue
        const sc_i: i32 = @bitCast(@as(u32, @truncate(sc_raw)));
        if (sc_i < 0 or sc_i > 7) return p.failf("error converting from protobuf: field: scheme reason: FIELD_INVALID description: unknown enumeration value {d}", .{sc_i});
        const sc: u8 = @intCast(sc_i);
        const sv = pf.d[2] orelse return ParserProto.missing(p, "signature");
        const kv = pf.d[3] orelse return ParserProto.missing(p, "public_key");
        switch (sc) {
            0, 1, 2, 7 => {},
            else => return ParserProto.invalid(p, "scheme", "invalid or unknown signature scheme"),
        }
        if (!mldsaOrLen(sv.len, sc, true)) return ParserProto.invalid(p, "signature", slice_err);
        if (!mldsaOrLen(kv.len, sc, false)) return ParserProto.invalid(p, "public_key", slice_err);
        return .{ .scheme = sc, .sig = sv, .pk = kv };
    }

    /// `ZkLoginAuthenticator::try_from(&proto)`.
    fn zkProto(p: *Parser, data: []const u8) ProtoParse!*ZkAuth {
        const a = p.arena;
        const pf = try Pf.of(a, data);
        const z = try a.create(ZkAuth);
        const inputs = try pf.msg(a, 1) orelse return ParserProto.missing(p, "inputs");
        const ip = try Pf.of(a, inputs);
        const proof = try ip.msg(a, 1) orelse return ParserProto.missing(p, "proof_points");
        const pp = try Pf.of(a, proof);
        z.a = try g1Proto(p, try pp.msg(a, 1) orelse return ParserProto.missing(p, "a"));
        z.b = try g2Proto(p, try pp.msg(a, 2) orelse return ParserProto.missing(p, "b"));
        z.c = try g1Proto(p, try pp.msg(a, 3) orelse return ParserProto.missing(p, "c"));
        const claim = try ip.msg(a, 2) orelse return ParserProto.missing(p, "iss_base64_details");
        const cp = try Pf.of(a, claim);
        z.iss_value = cp.d[1] orelse return ParserProto.missing(p, "value");
        const idx: u32 = @truncate(cp.v[2] orelse return ParserProto.missing(p, "index_mod_4"));
        if (idx > 255) return ParserProto.invalid(p, "index_mod_4", tfi);
        z.index_mod_4 = @intCast(idx);
        z.header = ip.d[3] orelse return ParserProto.missing(p, "header_base64");
        z.seed = try bnFromStr(p, "address_seed", ip.d[4] orelse return ParserProto.missing(p, "address_seed"));
        if (try zkInputsMsg(a, z)) |m| return p.failf("error converting from protobuf: field: inputs reason: FIELD_INVALID description: invalid zklogin claim: {s}", .{m});
        z.max_epoch = pf.v[2] orelse return ParserProto.missing(p, "max_epoch");
        z.simple = try p.simpleProto(try pf.msg(a, 3) orelse return ParserProto.missing(p, "signature"));
        return z;
    }

    /// `PasskeyAuthenticator::try_from(&proto)`: any `PasskeyAuthenticator::new` failure is
    /// "invalid passkey" on client_data_json.
    fn passkeyProto(p: *Parser, data: []const u8) ProtoParse!*Passkey {
        const a = p.arena;
        const pf = try Pf.of(a, data);
        const ad = pf.d[1] orelse return ParserProto.missing(p, "authenticator_data");
        const cdj = pf.d[2] orelse return ParserProto.missing(p, "client_data_json");
        const s = try p.simpleProto(try pf.msg(a, 3) orelse return ParserProto.missing(p, "signature"));
        const bad = "invalid passkey";
        if (s.scheme != 2) return ParserProto.invalid(p, "client_data_json", bad);
        const challenge = switch (try sdkjson.clientData(a, cdj)) {
            .ok => |c| c,
            .err => return ParserProto.invalid(p, "client_data_json", bad),
        };
        const out = try a.alloc(u8, challenge.len + 4);
        const ch = zk.b64.decodeUrlUnpadded(challenge, out) orelse return ParserProto.invalid(p, "client_data_json", bad);
        const pk = try a.create(Passkey);
        pk.* = .{ .auth_data = ad, .client_data_json = cdj, .sig = s.sig[0..64].*, .pk = s.pk[0..33].*, .challenge = ch };
        return pk;
    }

    fn memberPkProto(p: *Parser, data: []const u8) ProtoParse!MemberPk {
        const pf = try Pf.of(p.arena, data);
        const k = pf.d[2] orelse "";
        const pkf = "public_key";
        return switch (pf.scheme()) {
            0 => if (k.len == 32) .{ .ed25519 = k } else ParserProto.invalid(p, pkf, slice_err),
            1 => if (k.len == 33) .{ .secp256k1 = k } else ParserProto.invalid(p, pkf, slice_err),
            2 => if (k.len == 33) .{ .secp256r1 = k } else ParserProto.invalid(p, pkf, slice_err),
            5 => blk: {
                const zd = try pf.msg(p.arena, 3) orelse return ParserProto.missing(p, "zklogin");
                const zp = try Pf.of(p.arena, zd);
                const iss = zp.d[1] orelse return ParserProto.missing(p, "iss");
                const seed = try bnFromStr(p, "address_seed", zp.d[2] orelse return ParserProto.missing(p, "address_seed"));
                if (iss.len > 255) return ParserProto.invalid(p, "iss", "invalid iss");
                break :blk .{ .zklogin = .{ .iss = iss, .seed = seed } };
            },
            6 => if (k.len == 33) .{ .passkey = k } else ParserProto.invalid(p, pkf, slice_err),
            7 => if (k.len == mldsa65_pk_len) .{ .mldsa65 = k } else ParserProto.invalid(p, pkf, slice_err),
            else => ParserProto.invalid(p, "scheme", "invalid MultisigMemberPublicKey scheme"),
        };
    }

    fn memberSigProto(p: *Parser, data: []const u8) ProtoParse!MemberSig {
        const pf = try Pf.of(p.arena, data);
        const k = pf.d[2] orelse "";
        const sf = "signature";
        return switch (pf.scheme()) {
            0 => if (k.len == 64) .{ .ed25519 = k } else ParserProto.invalid(p, sf, slice_err),
            1 => if (k.len == 64) .{ .secp256k1 = k } else ParserProto.invalid(p, sf, slice_err),
            2 => if (k.len == 64) .{ .secp256r1 = k } else ParserProto.invalid(p, sf, slice_err),
            5 => .{ .zklogin = try p.zkProto(try pf.msg(p.arena, 3) orelse return ParserProto.missing(p, "zklogin")) },
            6 => .{ .passkey = try p.passkeyProto(try pf.msg(p.arena, 4) orelse return ParserProto.missing(p, "passkey")) },
            7 => if (k.len == mldsa65_sig_len) .{ .mldsa65 = k } else ParserProto.invalid(p, sf, slice_err),
            else => ParserProto.invalid(p, "scheme", "invalid MultisigMemberSignature scheme"),
        };
    }

    /// `MultisigAggregatedSignature::try_from(&proto)` with `try_with_legacy_bitmap`.
    fn multisigProto(p: *Parser, data: []const u8) ProtoParse!Multisig {
        const a = p.arena;
        const pf = try Pf.of(a, data);
        const sigs = try a.alloc(MemberSig, pf.all[1].items.len);
        for (pf.all[1].items, sigs) |d, *x| x.* = try p.memberSigProto(d);
        const bm32: u32 = @truncate(pf.v[2] orelse return ParserProto.missing(p, "bitmap"));
        if (bm32 > 0xffff) return ParserProto.invalid(p, "bitmap", tfi);
        const cd = try pf.msg(a, 4) orelse return ParserProto.missing(p, "committee");
        const cp = try Pf.of(a, cd);
        const members = try a.alloc(Member, cp.all[1].items.len);
        for (cp.all[1].items, members) |d, *m| {
            const mp = try Pf.of(a, d);
            m.pk = try p.memberPkProto(try mp.msg(a, 1) orelse return ParserProto.missing(p, "public_key"));
            const w: u32 = @truncate(mp.v[2] orelse return ParserProto.missing(p, "weight"));
            if (w > 255) return ParserProto.invalid(p, "weight", tfi);
            m.weight = @intCast(w);
        }
        const th: u32 = @truncate(cp.v[2] orelse return ParserProto.missing(p, "threshold"));
        if (th > 0xffff) return ParserProto.invalid(p, "threshold", tfi);
        const m: Multisig = .{ .sigs = sigs, .bitmap = @intCast(bm32), .members = members, .threshold = @intCast(th) };
        if (pf.d[3]) |lb| {
            const lf = "legacy_bitmap";
            const rb = switch (roaringRead(a, lb)) {
                .ok => |x| x,
                .err => |t| return ParserProto.invalid(p, lf, t),
            };
            if (rb.high) return ParserProto.invalid(p, lf, "invalid bitmap");
            if (rb.bits != m.bitmap) return ParserProto.invalid(p, lf, "bitmap does not match legacy_bitmap");
            for (members) |mem| switch (mem.pk) {
                .zklogin => return ParserProto.invalid(p, lf, "zklogin member is not representable in legacy multisig"),
                .passkey => return ParserProto.invalid(p, lf, "passkey member is not representable in legacy multisig"),
                .mldsa65 => return ParserProto.invalid(p, lf, "mldsa65 member is not representable in legacy multisig"),
                else => {},
            };
        }
        return m;
    }

    fn passkey(p: *Parser, bytes: []const u8) error{ Parse, OutOfMemory }!*Passkey {
        const flag = try p.flagOf(bytes);
        if (flag != 6) return p.fail("invalid passkey flag");
        var r: Rd = .{ .b = bytes[1..] };
        const auth_data = r.bytesV() catch |e| return p.bcsFail(e);
        const cdj = r.str() catch |e| return p.bcsFail(e);
        const s = try p.simple(r.bytesV() catch |e| return p.bcsFail(e));
        if (r.i != r.b.len) return p.bcsFail(error.Remaining);
        if (s.scheme != 2) return p.fail("expected passkey with secp256r1 signature");
        const challenge = switch (try sdkjson.clientData(p.arena, cdj)) {
            .ok => |c| c,
            .err => |t| return p.fail(t),
        };
        const out = try p.arena.alloc(u8, challenge.len + 4);
        const ch = zk.b64.decodeUrlUnpadded(challenge, out) orelse
            return p.fail("unable to decode base64urlunpadded into 3-byte intent and 32-byte digest: invalid Base64 encoding");
        const pk = try p.arena.create(Passkey);
        pk.* = .{ .auth_data = auth_data, .client_data_json = cdj, .sig = s.sig[0..64].*, .pk = s.pk[0..33].*, .challenge = ch };
        return pk;
    }
};

/// `roaring::RoaringBitmap::deserialize_from` (0.11.4) over a byte slice, with its io::Error texts:
/// the indices < 10 as bits, whether any index is >= 10, and the bytes read (trailing bytes are left).
const Roaring = struct { bits: u16, high: bool, used: usize };

fn roaringRead(arena: Allocator, b: []const u8) union(enum) { ok: Roaring, err: []const u8 } {
    const eof = "failed to fill whole buffer";
    var r: Rd = .{ .b = b };
    const Rr = struct {
        fn u32le(rd: *Rd) ?u32 {
            const x = rd.take(4) catch return null;
            return std.mem.readInt(u32, x[0..4], .little);
        }
    };
    const cookie = Rr.u32le(&r) orelse return .{ .err = eof };
    var size: usize = undefined;
    var has_offsets: bool = undefined;
    var has_runs = false;
    if (cookie == 12346) {
        size = Rr.u32le(&r) orelse return .{ .err = eof };
        has_offsets = true;
    } else if (@as(u16, @truncate(cookie)) == 12347) {
        size = (cookie >> 16) + 1;
        has_offsets = size >= 4;
        has_runs = true;
    } else return .{ .err = "unknown cookie value" };
    var run_bm: []const u8 = &.{};
    if (has_runs) run_bm = r.take((size + 7) / 8) catch return .{ .err = eof };
    if (size > 65536) return .{ .err = "size is greater than supported" };
    const desc = r.take(size * 4) catch return .{ .err = eof };
    if (has_offsets) _ = r.take(size * 4) catch return .{ .err = eof };
    var out: u16 = 0;
    var high = false;
    var last_key: ?u16 = null;
    for (0..size) |i| {
        const key = std.mem.readInt(u16, desc[i * 4 ..][0..2], .little);
        if (last_key) |lk| if (key <= lk) return .{ .err = "container keys are not sorted" };
        last_key = key;
        const card = @as(u64, std.mem.readInt(u16, desc[i * 4 + 2 ..][0..2], .little)) + 1;
        const is_run = has_runs and (run_bm[i / 8] & (@as(u8, 1) << @intCast(i % 8))) != 0;
        if (is_run) {
            const runs = r.u16le() catch return .{ .err = eof };
            if (runs == 0) return .{ .err = "run container with zero runs" };
            const iv = r.take(@as(usize, runs) * 4) catch return .{ .err = eof };
            var last_end: ?u16 = null;
            for (0..runs) |k| {
                const st = std.mem.readInt(u16, iv[k * 4 ..][0..2], .little);
                const l = std.mem.readInt(u16, iv[k * 4 + 2 ..][0..2], .little);
                const e = std.math.add(u16, st, l) catch return .{ .err = "invalid data" };
                if (last_end) |le| if (st <= le +| 1) return .{ .err = "invalid data" };
                last_end = e;
                if (key != 0 or e >= 10) high = true;
                if (key == 0) {
                    var v: u32 = st;
                    while (v <= e and v < 10) : (v += 1) out |= @as(u16, 1) << @intCast(v);
                }
            }
        } else if (card <= 4096) {
            const vals = r.take(@as(usize, @intCast(card)) * 2) catch return .{ .err = eof };
            var prev: u16 = 0;
            for (0..@intCast(card)) |k| {
                const v = std.mem.readInt(u16, vals[k * 2 ..][0..2], .little);
                if (k > 0) {
                    if (v < prev) return .{ .err = std.fmt.allocPrint(arena, "An element was out of order at index: {d}", .{k}) catch "out of memory" };
                    if (v == prev) return .{ .err = std.fmt.allocPrint(arena, "Duplicate element found at index: {d}", .{k}) catch "out of memory" };
                }
                prev = v;
                if (key == 0 and v < 10) out |= @as(u16, 1) << @intCast(v) else high = true;
            }
        } else {
            const words = r.take(1024 * 8) catch return .{ .err = eof };
            var pop: u64 = 0;
            for (0..1024) |k| {
                const w = std.mem.readInt(u64, words[k * 8 ..][0..8], .little);
                pop += @popCount(w);
                if (w != 0) {
                    if (key != 0 or k != 0 or w >= (1 << 10)) high = true;
                    if (key == 0 and k == 0) out |= @intCast(w & 0x3ff);
                }
            }
            if (pop != card) return .{ .err = std.fmt.allocPrint(arena, "Expected cardinality was {d} but was {d}", .{ card, pop }) catch "out of memory" };
        }
    }
    return .{ .ok = .{ .bits = out, .high = high, .used = r.i } };
}

/// `UserSignature::try_from(&proto::UserSignature)`.
fn protoSignature(p: *Parser, q: *const Request) E!?UserSig {
    if (q.sig_bcs_present) {
        if (p.userSig(q.sig_bcs)) |u| return u else |e| if (e == error.OutOfMemory) return error.OutOfMemory;
        // `bcs.deserialize::<UserSignature>()`: a BCS byte vector holding the serialized signature
        var r: Rd = .{ .b = q.sig_bcs };
        const text: []const u8 = blk: {
            const inner = r.bytesV() catch |e| break :blk bcsMsg(p.arena, e);
            if (p.userSig(inner)) |_| {
                if (r.i != q.sig_bcs.len) break :blk "remaining input";
                break :blk "";
            } else |e| {
                if (e == error.OutOfMemory) return error.OutOfMemory;
                break :blk p.err;
            }
        };
        if (text.len == 0) {
            // the wrapped form parsed: that is the signature
            var r2: Rd = .{ .b = q.sig_bcs };
            const inner = r2.bytesV() catch unreachable;
            return p.userSig(inner) catch unreachable;
        }
        p.err = try std.fmt.allocPrint(p.arena, "error converting from protobuf: field: bcs reason: FIELD_INVALID description: {s}", .{text});
        return null;
    }
    if (q.scheme == null) {
        p.err = "error converting from protobuf: field: scheme reason: FIELD_MISSING";
        return null;
    }
    if (q.oneof_field == 0) {
        p.err = "error converting from protobuf: field: signature reason: FIELD_INVALID description: invalid or unknown signature scheme";
        return null;
    }
    // the oneof member's occurrences merge (prost): their encodings concatenated
    const data = try std.mem.concat(p.arena, u8, q.oneof.items);
    const r: error{ Parse, OutOfMemory }!UserSig = switch (q.oneof_field) {
        3 => if (p.simpleProto(data)) |x| .{ .simple = x } else |e| e,
        4 => if (p.multisigProto(data)) |x| .{ .multisig = x } else |e| e,
        5 => if (p.zkProto(data)) |x| .{ .zklogin = x } else |e| e,
        else => if (p.passkeyProto(data)) |x| .{ .passkey = x } else |e| e,
    };
    return r catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Parse => null,
    };
}

// ------------------------------------------------------------------------------------------------
// Structured (non-bcs) UserSignature members: sui-rpc signatures.rs TryFrom impls.

/// One proto message's fields 1..7: the last varint, the last length-delimited value, and every
/// length-delimited occurrence (a singular message field merges them; a repeated one lists them).
const Pf = struct {
    v: [8]?u64 = @splat(null),
    d: [8]?[]const u8 = @splat(null),
    all: [8]std.ArrayList([]const u8) = @splat(.empty),

    fn of(arena: Allocator, data: []const u8) E!Pf {
        var pf: Pf = .{};
        var r = proto.Reader.init(data);
        while (r.next() catch null) |f| if (f.number < 8) {
            if (f.wire == 2) {
                pf.d[f.number] = f.data;
                try pf.all[f.number].append(arena, f.data);
            } else pf.v[f.number] = f.varint;
        };
        return pf;
    }
    fn msg(pf: *const Pf, arena: Allocator, n: usize) E!?[]const u8 {
        if (pf.all[n].items.len == 0) return null;
        return try std.mem.concat(arena, u8, pf.all[n].items);
    }
    /// prost's enum getter: unknown or absent values read as the default (Ed25519).
    fn scheme(pf: *const Pf) u8 {
        const v: i32 = @bitCast(@as(u32, @truncate(pf.v[1] orelse 0)));
        return if (v >= 0 and v <= 7) @intCast(v) else 0;
    }
};

const tfi = "out of range integral type conversion attempted";
const slice_err = "could not convert slice to array";

const BnErr = enum { empty, invalid, overflow };

/// bnum 0.13 `BUintD8::<32>::from_str_radix(s, 10)` (u8 digits: a leading run of 1 or 2 digits,
/// then pairs), with its error kinds.
fn bnumParse(s: []const u8) union(enum) { ok: u256, err: BnErr } {
    if (s.len == 0) return .{ .err = .empty };
    const lead: usize = @intFromBool(s[0] == '+');
    if (lead == 1 and s.len == 1) return .{ .err = .invalid };
    const n = s.len - lead;
    const split: usize = if (n % 2 == 0) 2 else 1;
    var i = lead;
    var first: u8 = 0;
    while (i < split + lead) : (i += 1) {
        if (!std.ascii.isDigit(s[i])) return .{ .err = .invalid };
        first = first * 10 + (s[i] - '0');
    }
    var out: u256 = first;
    var start = i;
    while (start < s.len) {
        const end = start + 2;
        const wide = @as(u512, out) * 100;
        if (wide >> 256 != 0) {
            while (start < s.len and start < end) : (start += 1) if (!std.ascii.isDigit(s[start])) return .{ .err = .invalid };
            return .{ .err = .overflow };
        }
        out = @truncate(wide);
        var nn: u8 = 0;
        var j = start;
        while (j < end and j < s.len) : (j += 1) {
            if (!std.ascii.isDigit(s[j])) return .{ .err = .invalid };
            nn = nn * 10 + (s[j] - '0');
        }
        out = std.math.add(u256, out, nn) catch return .{ .err = .overflow };
        start = end;
    }
    return .{ .ok = out };
}

/// `Bn254FieldElementParseError` Display.
fn bnText(e: BnErr) []const u8 {
    return switch (e) {
        .empty => "unable to parse radix10 encoded value unable to parse U256: (bnum) attempt to parse integer from empty string",
        .invalid => "unable to parse radix10 encoded value unable to parse U256: (bnum) attempt to parse integer from string containing invalid digit",
        .overflow => "unable to parse radix10 encoded value unable to parse U256: (bnum) attempt to parse integer too large to be represented by the target type",
    };
}

/// `ZkLoginInputs::new`'s checks, or null; sets `iss` and `kid`.
fn zkInputsMsg(arena: Allocator, z: *ZkAuth) E!?[]const u8 {
    if (z.iss_value.len < 2) return "Base64 string smaller than 2";
    const buf = try arena.alloc(u8, z.iss_value.len + 8);
    var f: zk.errors.Fail = .none;
    const ext = zk.b64.decodeBase64UrlBits(z.iss_value, z.index_mod_4, buf, &f) orelse return switch (f) {
        .general => |m| m,
        else => "base64_to_bitarry invalid input",
    };
    if (!std.unicode.utf8ValidateSlice(ext)) return "Invalid UTF8 string";
    if (ext.len == 0 or (ext[ext.len - 1] != '}' and ext[ext.len - 1] != ',')) return "Invalid extended claim";
    const text = try std.mem.concat(arena, u8, &.{ "{", ext[0 .. ext.len - 1], "}" });
    const iss = switch (try sdkjson.claim(arena, text, "iss")) {
        .err => |t| return t,
        .ok => |v| v orelse return "invalid extended claim",
    };
    if (iss.len > 255) return "invalid iss: too long";
    z.iss = iss;
    const hdr = try arena.alloc(u8, z.header.len + 8);
    const hj = zk.b64.decodeUrlUnpadded(z.header, hdr) orelse return "invalid base64: invalid Base64 encoding";
    const h = switch (try sdkjson.jwtHeader(arena, hj)) {
        .err => |t| return try std.fmt.allocPrint(arena, "invalid json: {s}", .{t}),
        .ok => |h| h,
    };
    if (!std.mem.eql(u8, h.alg, "RS256")) return "jwt alg must be RS256";
    z.kid = h.kid;
    return null;
}

const ProtoParse = error{ Parse, OutOfMemory };

const ParserProto = struct {
    fn missing(p: *Parser, name: []const u8) error{Parse} {
        return p.failf("error converting from protobuf: field: {s} reason: FIELD_MISSING", .{name});
    }
    fn invalid(p: *Parser, name: []const u8, desc: []const u8) error{Parse} {
        return p.failf("error converting from protobuf: field: {s} reason: FIELD_INVALID description: {s}", .{ name, desc });
    }
};

fn bnFromStr(p: *Parser, field: []const u8, s: []const u8) error{Parse}![32]u8 {
    const v = switch (bnumParse(s)) {
        .ok => |v| v,
        .err => |e| return ParserProto.invalid(p, field, bnText(e)),
    };
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, v, .big);
    return out;
}

fn g1Proto(p: *Parser, data: []const u8) ProtoParse![3][32]u8 {
    const pf = try Pf.of(p.arena, data);
    var out: [3][32]u8 = undefined;
    const names = [_][]const u8{ "e0", "e1", "e2" };
    for (&out, names, 1..) |*x, n, k| x.* = try bnFromStr(p, n, pf.d[k] orelse return ParserProto.missing(p, n));
    return out;
}

fn g2Proto(p: *Parser, data: []const u8) ProtoParse![3][2][32]u8 {
    const pf = try Pf.of(p.arena, data);
    var out: [3][2][32]u8 = undefined;
    const names = [_][]const u8{ "e00", "e01", "e10", "e11", "e20", "e21" };
    for (names, 0..) |n, k| out[k / 2][k % 2] = try bnFromStr(p, n, pf.d[k + 1] orelse return ParserProto.missing(p, n));
    return out;
}

fn mldsaOrLen(len: usize, scheme: u8, sig_side: bool) bool {
    return switch (scheme) {
        0 => len == @as(usize, if (sig_side) 64 else 32),
        1, 2 => len == @as(usize, if (sig_side) 64 else 33),
        7 => len == @as(usize, if (sig_side) mldsa65_sig_len else mldsa65_pk_len),
        else => false,
    };
}

// ------------------------------------------------------------------------------------------------
// sui-crypto verification. Each function returns null on success or the error source text.

const Verifier = struct {
    arena: Allocator,
    env: *const Env,
    jwks: []const Jwk = &.{},
    have_zk: bool = false,

    /// `build_zklogin_verifier`: the request's JWKs, or the chain's when the request has none.
    fn loadJwks(v: *Verifier, raw: []const []const u8) E!?Reply {
        v.have_zk = true;
        if (raw.len == 0) {
            v.jwks = try chainJwks(v.arena, v.env);
            return null;
        }
        const out = try v.arena.alloc(Jwk, raw.len);
        for (raw, out, 0..) |data, *j, i| {
            if (activeJwk(data, j)) |missing| {
                const field = try std.fmt.allocPrint(v.arena, "jwks[{d}]", .{i});
                const d = try std.fmt.allocPrint(v.arena, "error converting from protobuf: field: {s} reason: FIELD_MISSING", .{missing});
                return .{ .bad = .{ .field = field, .description = d, .reason = .field_invalid } };
            }
        }
        v.jwks = out;
        return null;
    }

    fn findJwk(v: *const Verifier, iss: []const u8, kid: []const u8) ?*const Jwk {
        // a HashMap built in order: the last entry for a key wins
        var i = v.jwks.len;
        while (i > 0) {
            i -= 1;
            const j = &v.jwks[i];
            if (std.mem.eql(u8, j.iss, iss) and std.mem.eql(u8, j.kid, kid)) return j;
        }
        return null;
    }

    fn verifyUser(v: *Verifier, msg: *const [32]u8, u: UserSig) E!?[]const u8 {
        return switch (u) {
            .simple => |s| v.verifySimple(msg, s),
            .multisig => |m| v.verifyMultisig(msg, &m),
            .zklogin => |z| v.verifyZk(msg, z),
            .passkey => |pk| v.verifyPasskey(msg, pk),
        };
    }

    fn verifySimple(v: *Verifier, msg: []const u8, s: Simple) ?[]const u8 {
        _ = v;
        return switch (s.scheme) {
            0 => verifyEd25519(s.pk[0..32], msg, s.sig[0..64]),
            1 => verifyK1(s.pk[0..33], msg, s.sig[0..64]),
            2 => verifyR1(s.pk[0..33], msg, s.sig[0..64]),
            else => verifyMlDsa(s.pk, msg, s.sig),
        };
    }

    fn verifyMultisig(v: *Verifier, msg: *const [32]u8, m: *const Multisig) E!?[]const u8 {
        if (!committeeValid(m)) return "invalid MultisigCommittee";
        if (m.sigs.len != @popCount(m.bitmap)) return "number of signatures does not match bitmap";
        if (m.sigs.len > m.members.len) return "more signatures than committee members";
        var weight: u16 = 0;
        var k: usize = 0;
        var bit: u5 = 0;
        while (bit < 16) : (bit += 1) {
            if (m.bitmap & (@as(u16, 1) << @intCast(bit)) == 0) continue;
            if (k >= m.sigs.len) break;
            if (bit >= m.members.len) return "invalid bitmap";
            const mem = m.members[bit];
            if (try v.verifyMember(msg, mem.pk, m.sigs[k])) |e| return e;
            weight +%= mem.weight;
            k += 1;
        }
        if (weight >= m.threshold) return null;
        return "signature weight does not exceed threshold";
    }

    fn verifyMember(v: *Verifier, msg: *const [32]u8, pk: MemberPk, s: MemberSig) E!?[]const u8 {
        switch (pk) {
            .ed25519 => |k| if (s == .ed25519) return verifyEd25519(k[0..32], msg, s.ed25519[0..64]),
            .secp256k1 => |k| if (s == .secp256k1) return verifyK1(k[0..33], msg, s.secp256k1[0..64]),
            .secp256r1 => |k| if (s == .secp256r1) return verifyR1(k[0..33], msg, s.secp256r1[0..64]),
            .zklogin => |z| if (s == .zklogin) {
                if (!v.have_zk) return "no zklogin verifier provided";
                const a = s.zklogin;
                if (!std.mem.eql(u8, z.iss, a.iss) or !std.mem.eql(u8, &z.seed, &a.seed)) return "member zklogin identifier does not match signature";
                return v.verifyZk(msg, a);
            },
            .passkey => |k| if (s == .passkey) {
                if (!std.mem.eql(u8, k, &s.passkey.pk)) return "member passkey public_key does not match authenticator";
                return v.verifyPasskey(msg, s.passkey);
            },
            .mldsa65 => |k| if (s == .mldsa65) return verifyMlDsa(k, msg, s.mldsa65),
        }
        return "member and signature scheme do not match";
    }

    fn verifyPasskey(v: *Verifier, msg: *const [32]u8, pk: *const Passkey) ?[]const u8 {
        _ = v;
        if (!std.mem.eql(u8, msg, pk.challenge)) return "passkey challenge does not match expected message";
        var h = Sha256.init(.{});
        h.update(pk.client_data_json);
        var cdh: [32]u8 = undefined;
        h.final(&cdh);
        var m = Sha256.init(.{});
        m.update(pk.auth_data);
        m.update(&cdh);
        var d: [32]u8 = undefined;
        m.final(&d);
        return verifyR1Digest(&pk.pk, &d, &pk.sig);
    }

    fn verifyZk(v: *Verifier, msg: *const [32]u8, z: *const ZkAuth) E!?[]const u8 {
        if (!v.have_zk) return "no zklogin verifier provided";
        const jwk = v.findJwk(z.iss, z.kid) orelse {
            var aw: std.Io.Writer.Allocating = .init(v.arena);
            const w = &aw.writer;
            w.writeAll("unable to find corrisponding jwk with id 'JwkId { iss: \"") catch return error.OutOfMemory;
            zk.errors.escapeDebug(w, z.iss) catch return error.OutOfMemory;
            w.writeAll("\", kid: \"") catch return error.OutOfMemory;
            zk.errors.escapeDebug(w, z.kid) catch return error.OutOfMemory;
            w.writeAll("\" }' for provided authenticator") catch return error.OutOfMemory;
            return aw.written();
        };
        if (v.verifySimple(msg, z.simple)) |e| return e;
        const dev = !(std.mem.eql(u8, v.env.chain_name, "mainnet") or std.mem.eql(u8, v.env.chain_name, "testnet"));
        if (dev) {
            if (try zkProof(v.arena, jwk, z, .v2, true) == null) return null;
        }
        return zkProof(v.arena, jwk, z, .v1, dev);
    }
};

/// ActiveJwk { id: JwkId { iss = 1, kid = 2 } = 1, jwk: Jwk { kty = 1, e = 2, n = 3, alg = 4 } = 2, epoch = 3 }.
/// Returns the first missing field name (TryFrom<&ActiveJwk>), or null.
fn activeJwk(data: []const u8, j: *Jwk) ?[]const u8 {
    var id: ?[]const u8 = null;
    var jw: ?[]const u8 = null;
    var epoch = false;
    var r = proto.Reader.init(data);
    while (r.next() catch null) |f| switch (f.number) {
        1 => id = f.data,
        2 => jw = f.data,
        3 => epoch = true,
        else => {},
    };
    const idb = id orelse return "id";
    var iss: ?[]const u8 = null;
    var kid: ?[]const u8 = null;
    var ri = proto.Reader.init(idb);
    while (ri.next() catch null) |f| switch (f.number) {
        1 => iss = f.data,
        2 => kid = f.data,
        else => {},
    };
    j.iss = iss orelse return "iss";
    j.kid = kid orelse return "kid";
    const jb = jw orelse return "jwk";
    var fs: [4]?[]const u8 = .{ null, null, null, null };
    var rj = proto.Reader.init(jb);
    while (rj.next() catch null) |f| if (f.number >= 1 and f.number <= 4) {
        fs[f.number - 1] = f.data;
    };
    j.kty = fs[0] orelse return "kty";
    j.e = fs[1] orelse return "e";
    j.n = fs[2] orelse return "n";
    j.alg = fs[3] orelse return "alg";
    if (!epoch) return "epoch";
    return null;
}

fn committeeValid(m: *const Multisig) bool {
    if (m.threshold == 0 or m.members.len == 0 or m.members.len > 10) return false;
    var sum: u32 = 0;
    for (m.members) |mem| {
        if (mem.weight == 0) return false;
        sum += mem.weight;
    }
    if (sum < m.threshold) return false;
    for (m.members, 0..) |a, i| for (m.members[i + 1 ..]) |b| if (a.pk.eql(b.pk)) return false;
    return true;
}

/// ed25519-dalek `VerifyingKey::from_bytes` + `verify_strict`.
fn verifyEd25519(pk: *const [32]u8, msg: []const u8, s: *const [64]u8) ?[]const u8 {
    const a = ed25519.decompress(pk) orelse return "Cannot decompress Edwards point";
    if (!ed25519.isCanonicalScalar(s[32..64])) return "Cannot use scalar with high-bit set";
    const r = ed25519.decompress(s[0..32]) orelse return "Verification equation was not satisfied";
    if (r.mulByCofactor().isIdentity() or a.mulByCofactor().isIdentity()) return "Verification equation was not satisfied";
    var h = Sha512.init(.{});
    h.update(s[0..32]);
    h.update(pk);
    h.update(msg);
    var d: [64]u8 = undefined;
    h.final(&d);
    const k = Ed.scalar.reduce64(d);
    const neg_k = Ed.scalar.neg(k);
    // R' = [s]B - [k]A
    const rp = ed25519.doubleScalarMulBase(&neg_k, a, s[32..64]);
    const enc = rp.toBytes();
    if (!std.mem.eql(u8, &enc, s[0..32])) return "Verification equation was not satisfied";
    return null;
}

/// sui-crypto `MlDsa65VerifyingKey`: FIPS 204 ML-DSA-65, pure, empty context, over the 32-byte
/// signing digest (mysten_mldsa_native_rs). Every failure is `SignatureError::new()` (no source).
fn verifyMlDsa(pk: []const u8, msg: []const u8, s: []const u8) ?[]const u8 {
    if (pk.len != MlDsa.PublicKey.encoded_length or s.len != MlDsa.Signature.encoded_length) return "";
    const key = MlDsa.PublicKey.fromBytes(pk[0..MlDsa.PublicKey.encoded_length].*) catch return "";
    const sg = MlDsa.Signature.fromBytes(s[0..MlDsa.Signature.encoded_length].*) catch return "";
    sg.verify(msg, key) catch return "";
    return null;
}

fn sha256(msg: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(msg, &out, .{});
    return out;
}

/// k256 `VerifyingKey::try_from(sec1)` + `Signature::from_bytes` + verify (SHA-256, low s).
fn verifyK1(pk: *const [33]u8, msg: []const u8, s: *const [64]u8) ?[]const u8 {
    if (pk[0] != 2 and pk[0] != 3) return "";
    const q = sig.secp256k1.parsePublicKey(pk) orelse return "";
    const d = sha256(msg);
    return switch (sig.secp256k1.verifyDigestParsed(q, &d, s)) {
        .valid => null,
        .invalid => "",
    };
}

const r1_n: u256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

/// p256 verify: SHA-256 of the message, any s in [1, n).
fn verifyR1(pk: *const [33]u8, msg: []const u8, s: *const [64]u8) ?[]const u8 {
    const d = sha256(msg);
    return verifyR1Digest(pk, &d, s);
}

fn verifyR1Digest(pk: *const [33]u8, d: *const [32]u8, s: *const [64]u8) ?[]const u8 {
    if (pk[0] != 2 and pk[0] != 3) return "";
    const q = sig.secp256r1.parsePublicKey(pk) orelse return "";
    const r = std.mem.readInt(u256, s[0..32], .big);
    var sv = std.mem.readInt(u256, s[32..64], .big);
    if (r == 0 or sv == 0 or r >= r1_n or sv >= r1_n) return "";
    if (sv > r1_n / 2) sv = r1_n - sv;
    var low: [64]u8 = s.*;
    std.mem.writeInt(u256, low[32..64], sv, .big);
    return switch (sig.secp256r1.verifyDigestParsed(q, d, &low)) {
        .valid => null,
        .invalid => "",
    };
}

// ---- zkLogin proof (sui-crypto zklogin/verify.rs) ----

const pack_bytes = 31;

/// `hash_ascii_str_to_field(s, max)`: bytes (not characters) padded to `max`, packed in 248-bit
/// chunks from the right, poseidon.
fn hashAsciiStr(s: []const u8, max: usize) ?Fr {
    if (s.len > max) return null;
    var buf: [512]u8 = @splat(0);
    @memcpy(buf[0..s.len], s);
    return packAndHash(buf[0..max]);
}

fn packAndHash(bytes: []const u8) ?Fr {
    const n = (bytes.len + pack_bytes - 1) / pack_bytes;
    var frs: [zk.poseidon.zklogin_max_inputs]Fr = undefined;
    if (n == 0 or n > frs.len) return null;
    var end = bytes.len;
    var i = n;
    while (i > 0) {
        i -= 1;
        const start = end -| pack_bytes;
        frs[i] = Fr.fromBytesBeModOrder(bytes[start..end]);
        end = start;
    }
    var fail: zk.errors.Fail = .none;
    return zk.poseidon.zkLogin(frs[0..n], &fail);
}

fn g1Of(c: [3][32]u8) ?bn.G1 {
    const x = Fq.fromBytesBeModOrder(&c[0]);
    const y = Fq.fromBytesBeModOrder(&c[1]);
    const z = Fq.fromBytesBeModOrder(&c[2]);
    const p: bn.G1 = if (z.isZero()) bn.G1.identity else blk: {
        const zi = z.inverse();
        const zi2 = zi.sq();
        break :blk .{ .x = x.mul(zi2), .y = y.mul(zi2.mul(zi)), .infinity = false };
    };
    if (!p.isOnCurve()) return null;
    return p;
}

fn g2Of(c: [3][2][32]u8) ?bn.G2 {
    const x: Fq2 = .{ .c0 = Fq.fromBytesBeModOrder(&c[0][0]), .c1 = Fq.fromBytesBeModOrder(&c[0][1]) };
    const y: Fq2 = .{ .c0 = Fq.fromBytesBeModOrder(&c[1][0]), .c1 = Fq.fromBytesBeModOrder(&c[1][1]) };
    const z: Fq2 = .{ .c0 = Fq.fromBytesBeModOrder(&c[2][0]), .c1 = Fq.fromBytesBeModOrder(&c[2][1]) };
    const p: bn.G2 = if (z.isZero()) bn.G2.identity else blk: {
        const zi = z.inverse();
        const zi2 = zi.sq();
        break :blk .{ .x = x.mul(zi2), .y = y.mul(zi2.mul(zi)), .infinity = false };
    };
    if (!p.isOnCurve()) return null;
    if (!p.infinity and !bn.curve.g2InSubgroup(p)) return null;
    return p;
}

var keys_state: std.atomic.Value(u8) = .init(0); // 0 none, 1 initializing, 2 ready
var keys: zk.zklogin.Keys = undefined;

fn zkKeys() *const zk.zklogin.Keys {
    while (true) {
        switch (keys_state.load(.acquire)) {
            2 => return &keys,
            0 => if (keys_state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) {
                keys.init();
                keys_state.store(2, .release);
                return &keys;
            },
            else => std.atomic.spinLoopHint(),
        }
    }
}

/// `VerifyingKey::verify_zklogin` for one circuit version: modulus, proof points, inputs hash, Groth16.
fn zkProof(arena: Allocator, jwk: *const Jwk, z: *const ZkAuth, v: zk.zklogin.Version, dev: bool) E!?[]const u8 {
    const mod_buf = try arena.alloc(u8, jwk.n.len + 4);
    const modulus_raw = zk.b64.decodeUrlUnpadded(jwk.n, mod_buf) orelse return "invalid Base64 encoding";
    var lead: usize = 0;
    while (lead < modulus_raw.len and modulus_raw[lead] == 0) lead += 1;
    const modulus = modulus_raw[lead..];
    const pa = g1Of(z.a) orelse return "invalid G1 input";
    const pb = g2Of(z.b) orelse return "invalid G2 input";
    const pc = g1Of(z.c) orelse return "invalid G1 input";
    const cfg = zk.zklogin.config(v);
    if (z.header.len > cfg.max_header_len_b64) return "header too long";
    // public_key_to_frs: flag || pk split 16 bytes from the end
    var eph: [34]u8 = undefined;
    eph[0] = z.simple.scheme;
    if (z.simple.scheme == 7) return "unknown signature scheme";
    @memcpy(eph[1..][0..z.simple.pk.len], z.simple.pk);
    const el = 1 + z.simple.pk.len;
    const e0 = Fr.fromBytesBeModOrder(eph[0 .. el - 16]);
    const e1 = Fr.fromBytesBeModOrder(eph[el - 16 .. el]);
    const seed = Fr.fromBytesBeModOrder(&z.seed);
    const max_epoch = Fr.fromU64(z.max_epoch);
    const header_f = hashAsciiStr(z.header, cfg.max_header_len_b64) orelse return "in_arr too long";
    if (modulus.len > 1024) return "JWK modulus too large for U8192";
    const bits: usize = if (modulus.len == 0) 1 else (modulus.len - 1) * 8 + (8 - @as(usize, @clz(modulus[0])));
    if (bits > cfg.max_rsa_bits) return "invalid input";
    var mb: [1024]u8 = @splat(0);
    const nb = cfg.max_rsa_bits / 8;
    @memcpy(mb[nb - modulus.len .. nb], modulus);
    const modulus_f = packAndHash(mb[0..nb]) orelse return "invalid input";
    var fail: zk.errors.Fail = .none;
    const h = switch (v) {
        .v1 => blk: {
            const iss_f = hashAsciiStr(z.iss_value, cfg.max_iss_len) orelse return "in_arr too long";
            break :blk zk.poseidon.zkLogin(&.{ e0, e1, seed, max_epoch, iss_f, Fr.fromU64(z.index_mod_4), header_f, modulus_f }, &fail);
        },
        .v2 => blk: {
            const buf = try arena.alloc(u8, z.iss_value.len + 8);
            const ext = zk.b64.decodeBase64UrlBits(z.iss_value, z.index_mod_4, buf, &fail) orelse return "invalid extended claim";
            const iss_f = hashAsciiStr(ext, cfg.max_iss_len) orelse return "in_arr too long";
            break :blk zk.poseidon.zkLogin(&.{ e0, e1, seed, max_epoch, iss_f, header_f, modulus_f, Fr.fromU64(bits) }, &fail);
        },
    } orelse return "invalid input";
    const k = zkKeys();
    const vk = k.get(if (dev) .test_ else .prod, v);
    if (!vk.verify(h, .{ .a = pa, .b = pb, .c = pc })) return "Groth16 proof verify failed";
    return null;
}

// ------------------------------------------------------------------------------------------------
// Tests

test "address parsing follows sui-sdk-types from_hex" {
    const a = parseAddress("0x2").?;
    try std.testing.expectEqual(@as(u8, 2), a[31]);
    try std.testing.expect(parseAddress("") == null);
    try std.testing.expect(parseAddress("0x") == null);
    try std.testing.expect(parseAddress("0xzz") == null);
    try std.testing.expectEqual(@as(u8, 0xab), parseAddress("AB").?[31]);
}

test "ed25519 strict verify on a std signature" {
    const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(7)) catch unreachable;
    const s = kp.sign("hello", null) catch unreachable;
    const sb = s.toBytes();
    const pk = kp.public_key.toBytes();
    try std.testing.expect(verifyEd25519(&pk, "hello", &sb) == null);
    try std.testing.expectEqualStrings("Verification equation was not satisfied", verifyEd25519(&pk, "hellp", &sb).?);
}

test "handle compiles and rejects an empty request" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const Ctx = struct {
        fn none(_: *anyopaque, _: *const [32]u8) ?[]const u8 {
            return null;
        }
    };
    var dummy: u8 = 0;
    const env: Env = .{ .ctx = &dummy, .liveObject = Ctx.none };
    const r = try handle(arena_state.allocator(), &env, "");
    try std.testing.expect(r == .bad);
    try std.testing.expectEqualStrings("signature", r.bad.field);
}

test "MaxLen carries the decoded length (bcs ExceededMaxLen Display)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try std.testing.expectEqualStrings("exceeded max sequence length: 2147483648", personalError(a, &.{ 0x80, 0x80, 0x80, 0x80, 0x08 }).?);
    try std.testing.expectEqualStrings("ULEB128-encoded integer did not fit in the target size", personalError(a, &.{ 0x80, 0x80, 0x80, 0x80, 0x10 }).?);
}

test "bnum radix-10 parse and Bn254 texts" {
    try std.testing.expectEqual(@as(u256, 5), bnumParse("+5").ok);
    try std.testing.expectEqual(@as(u256, 7), bnumParse("007").ok);
    try std.testing.expectEqual(BnErr.empty, bnumParse("").err);
    try std.testing.expectEqual(BnErr.invalid, bnumParse("+").err);
    try std.testing.expectEqual(BnErr.invalid, bnumParse("12a").err);
    const max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    try std.testing.expectEqual(std.math.maxInt(u256), bnumParse(max).ok);
    try std.testing.expectEqual(BnErr.overflow, bnumParse("115792089237316195423570985008687907853269984665640564039457584007913129639936").err);
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var p: Parser = .{ .arena = arena_state.allocator() };
    var buf: [8]u8 = undefined;
    buf[0] = 2;
    @memcpy(buf[1..3], "+5");
    var r: Rd = .{ .b = buf[0..3] };
    try std.testing.expectError(error.Parse, p.bn254(&r));
    try std.testing.expectEqualStrings("non-canonical Bn254FieldElement encoding", p.err);
    buf[0] = 1;
    buf[1] = 'x';
    r = .{ .b = buf[0..2] };
    try std.testing.expectError(error.Parse, p.bn254(&r));
    try std.testing.expectEqualStrings(bnText(.invalid), p.err);
}

test "legacy multisig: canonical roaring and the index limit" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var p: Parser = .{ .arena = arena_state.allocator() };
    const key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // flag 0 + 32 zero bytes (44 chars)
    const Build = struct {
        fn ms(buf: []u8, roaring: []const u8) []const u8 {
            var n: usize = 0;
            const put = struct {
                fn f(b: []u8, at: *usize, x: []const u8) void {
                    @memcpy(b[at.*..][0..x.len], x);
                    at.* += x.len;
                }
            }.f;
            put(buf, &n, &.{ 3, 0 }); // flag, no signatures
            put(buf, &n, &.{@intCast(roaring.len)});
            put(buf, &n, roaring);
            put(buf, &n, &.{ 1, 44 });
            put(buf, &n, key_b64);
            put(buf, &n, &.{ 1, 1, 0 }); // weight 1, threshold 1
            return buf[0..n];
        }
    };
    // cookie 12346, 1 container, key 0, card 1, offset 16, value 0
    const rb = [_]u8{ 0x3a, 0x30, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0 };
    var buf: [256]u8 = undefined;
    const ok = try p.userSig(Build.ms(&buf, &rb));
    try std.testing.expectEqual(@as(u16, 1), ok.multisig.bitmap);
    // one trailing byte after the roaring encoding: sdk deserialize_canonical_bitmap rejects it
    const trailing = rb ++ [_]u8{0};
    try std.testing.expectError(error.Parse, p.userSig(Build.ms(&buf, &trailing)));
    try std.testing.expectEqualStrings("invalid multisig", p.err);
    // index 12: the legacy struct parses, then roaring_bitmap_to_u16 says "invalid bitmap"
    var high = rb;
    high[16] = 12;
    try std.testing.expectError(error.Parse, p.userSig(Build.ms(&buf, &high)));
    try std.testing.expectEqualStrings("invalid bitmap", p.err);
}

test "ML-DSA-65 verifies over the signing digest with an empty context" {
    const kp = try MlDsa.KeyPair.generateDeterministic(@splat(2));
    const digest = intentDigest(.{ 3, 0, 0 }, &.{ 5, 'h', 'e', 'l', 'l', 'o' });
    const sg = try kp.sign(&digest, null);
    const sb = sg.toBytes();
    const pk = kp.public_key.toBytes();
    try std.testing.expect(verifyMlDsa(&pk, &digest, &sb) == null);
    var other = digest;
    other[0] ^= 1;
    try std.testing.expectEqualStrings("", verifyMlDsa(&pk, &other, &sb).?);
}

test "sdk identifier rules" {
    try std.testing.expect(sdkIdentValid("coin"));
    try std.testing.expect(sdkIdentValid("_x"));
    try std.testing.expect(!sdkIdentValid("_"));
    try std.testing.expect(!sdkIdentValid("9a"));
    try std.testing.expect(!sdkIdentValid("a-b"));
    try std.testing.expect(sdkIdentValid(&@as([128]u8, @splat('a'))));
    try std.testing.expect(!sdkIdentValid(&@as([129]u8, @splat('a'))));
}

test "structured multisig member converts like sui-rpc" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var p: Parser = .{ .arena = a };
    // MultisigAggregatedSignature { bitmap = 1, committee = { members = [{ public_key = { scheme 0, public_key 32B }, weight 1 }], threshold 1 } }
    var pk: [2 + 2 + 32]u8 = undefined;
    @memcpy(pk[0..4], &[_]u8{ 0x08, 0x00, 0x12, 32 });
    @memset(pk[4..], 0);
    var member: [2 + pk.len + 2]u8 = undefined;
    member[0] = 0x0a;
    member[1] = pk.len;
    @memcpy(member[2..][0..pk.len], &pk);
    @memcpy(member[2 + pk.len ..], &[_]u8{ 0x10, 1 });
    var committee: [2 + member.len + 2]u8 = undefined;
    committee[0] = 0x0a;
    committee[1] = member.len;
    @memcpy(committee[2..][0..member.len], &member);
    @memcpy(committee[2 + member.len ..], &[_]u8{ 0x10, 1 });
    var msg: [2 + 2 + committee.len]u8 = undefined;
    @memcpy(msg[0..2], &[_]u8{ 0x10, 1 });
    msg[2] = 0x22;
    msg[3] = committee.len;
    @memcpy(msg[4..], &committee);
    const m = try p.multisigProto(&msg);
    try std.testing.expectEqual(@as(usize, 1), m.members.len);
    try std.testing.expectEqual(@as(u16, 1), m.threshold);
    // no committee
    try std.testing.expectError(error.Parse, p.multisigProto(msg[0..2]));
    try std.testing.expectEqualStrings("error converting from protobuf: field: committee reason: FIELD_MISSING", p.err);
    // bitmap 70000 does not fit u16
    const big = [_]u8{ 0x10, 0xf0, 0xa2, 0x04 };
    try std.testing.expectError(error.Parse, p.multisigProto(&big));
    try std.testing.expectEqualStrings("error converting from protobuf: field: bitmap reason: FIELD_INVALID description: out of range integral type conversion attempted", p.err);
}
