//! `nitro_attestation::load_nitro_attestation_internal(&vector<u8>, u64)` (sui-move-natives
//! crypto/nitro_attestation.rs over sui_types::nitro_attestation, mainnet from protocol 83/84).
//!
//! Outcome mapping (all after the charges shown):
//!   flag off                                   abort 0 (NOT_SUPPORTED), cost 0
//!   parse charge, then COSE/payload rejected   abort 1 (PARSE_ERROR)
//!   + verify charge (counts the cabundle), then signature/chain rejected   abort 2 (VERIFY_ERROR)
//!   legacy PCR list not 6 long                 abort 3 (INVALID_PCRS)
//!   ok                                         NitroAttestationDocument
const std = @import("std");
const abi = @import("abi.zig");
const cbor = @import("cbor.zig");
const x509 = @import("x509.zig");

const Ctx = abi.Ctx;
const Value = abi.Value;
const TyArg = abi.TyArg;
const Outcome = abi.Outcome;
const Error = abi.Error;
const Allocator = std.mem.Allocator;

const NOT_SUPPORTED: u64 = 0;
const PARSE_ERROR: u64 = 1;
const VERIFY_ERROR: u64 = 2;
const INVALID_PCRS: u64 = 3;

const max_cert_chain = 10;
const max_user_data = 512;
const max_pk = 1024;
const max_pcrs = 32;
const max_cert = 1024;

/// The AWS Nitro Enclaves root (sui-types nitro_root_certificate.pem).
pub const root_der = blk: {
    const b64 = "MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y=";
    @setEvalBranchQuota(100_000);
    const n = std.base64.standard.Decoder.calcSizeForSlice(b64) catch unreachable;
    var out: [n]u8 = undefined;
    std.base64.standard.Decoder.decode(&out, b64) catch unreachable;
    const final = out;
    break :blk final;
};

const Cose = struct { protected: []const u8, payload: []const u8, sig: []const u8 };

/// `CoseSign1::parse_and_validate`.
fn parseCose(a: Allocator, bytes: []const u8) cbor.Error!Cose {
    var v = try cbor.decode(a, bytes);
    if (v == .tag) {
        if (v.tag.tag != 18) return error.Invalid;
        v = v.tag.v.*;
    }
    // into_writer, then from_reader::<CoseSign1>: deserialize_any must see an array (a tag here
    // is visit_enum, which the visitor rejects; a bignum tag became an integer)
    if (v != .array) return error.Invalid;
    const items = v.array;
    if (items.len < 4) return error.Invalid;
    const p = try cbor.roundTrip(a, &items[0]);
    if (p != .bytes) return error.Invalid;
    // unprotected: HeaderMap via deserialize_map (tags skipped), no duplicate keys
    var u = try cbor.roundTrip(a, &items[1]);
    while (u == .tag) u = u.tag.v.*;
    if (u != .map) return error.Invalid;
    try noDuplicateKeys(u.map);
    const pl = try cbor.roundTrip(a, &items[2]);
    if (pl != .bytes) return error.Invalid;
    const s = try cbor.roundTrip(a, &items[3]);
    if (s != .bytes) return error.Invalid;
    // the protected header as a HeaderMap
    var d = cbor.Decoder.init(a, p.bytes);
    try noDuplicateKeys(try d.mapSkippingTags());
    // validate_header
    if (!validProtected(a, p.bytes)) return error.Invalid;
    if (pl.bytes.len < 1 or pl.bytes.len >= 16384 or s.bytes.len != 96) return error.Invalid;
    return .{ .protected = p.bytes, .payload = pl.bytes, .sig = s.bytes };
}

fn noDuplicateKeys(entries: []const cbor.Pair) cbor.Error!void {
    for (entries, 0..) |*e, i| {
        for (entries[0..i]) |*f| if (cbor.Value.eql(&e.k, &f.k)) return error.Invalid;
    }
}

/// `is_valid_protected_header`: exactly `{1: -35}` (ECDSA 384).
fn validProtected(a: Allocator, bytes: []const u8) bool {
    const v = cbor.decode(a, bytes) catch return false;
    if (v != .map or v.map.len != 1) return false;
    const e = v.map[0];
    return e.k == .int and e.k.int == 1 and e.v == .int and e.v.int == -35;
}

const Doc = struct {
    module_id: []const u8,
    timestamp: u64,
    digest: []const u8,
    pcr_vec: []const []const u8,
    /// index -> value for upgraded parsing (sorted by index)
    pcr_map: [256]?[]const u8,
    certificate: []const u8,
    cabundle: []const []const u8,
    public_key: ?[]const u8,
    user_data: ?[]const u8,
    nonce: ?[]const u8,
};

const Flags = struct { upgraded: bool, all_nonzero: bool, always_required: bool };

fn lookup(m: []const cbor.Pair, key: []const u8) ?*const cbor.Value {
    // BTreeMap built from the pairs in order: the last of equal keys wins
    var found: ?*const cbor.Value = null;
    for (m) |*e| if (std.mem.eql(u8, e.k.text, key)) {
        found = &e.v;
    };
    return found;
}

fn asU64(v: i128) ?u64 {
    if (v < 0 or v > std.math.maxInt(u64)) return null;
    return @intCast(v);
}

/// `AttestationDocument::parse_payload`.
fn parseDoc(a: Allocator, payload: []const u8, f: Flags, out: *Doc) cbor.Error!void {
    const v = try cbor.decode(a, payload);
    if (v != .map) return error.Invalid;
    const m = v.map;
    for (m) |e| if (e.k != .text) return error.Invalid;
    if (f.upgraded) try noDuplicateTextKeys(m);

    const module_id = lookup(m, "module_id") orelse return error.Invalid;
    if (module_id.* != .text or module_id.text.len == 0) return error.Invalid;
    out.module_id = module_id.text;

    const digest = lookup(m, "digest") orelse return error.Invalid;
    if (digest.* != .text or !std.mem.eql(u8, digest.text, "SHA384")) return error.Invalid;
    out.digest = digest.text;

    const cert = lookup(m, "certificate") orelse return error.Invalid;
    if (cert.* != .bytes or cert.bytes.len == 0 or cert.bytes.len > max_cert) return error.Invalid;
    out.certificate = cert.bytes;

    const ts = lookup(m, "timestamp") orelse return error.Invalid;
    if (ts.* != .int) return error.Invalid;
    out.timestamp = asU64(ts.int) orelse return error.Invalid;

    out.public_key = optBytes(m, "public_key");
    if (out.public_key) |pk| {
        if (f.upgraded) {
            if (pk.len > max_pk) return error.Invalid;
        } else if (pk.len == 0 or pk.len > max_pk) return error.Invalid;
    }
    out.user_data = optBytes(m, "user_data");
    if (out.user_data) |x| if (x.len > max_user_data) return error.Invalid;
    out.nonce = optBytes(m, "nonce");
    if (out.nonce) |x| if (x.len > max_user_data) return error.Invalid;

    const pcrs = lookup(m, "pcrs") orelse return error.Invalid;
    if (pcrs.* != .map) return error.Invalid;
    if (pcrs.map.len > max_pcrs) return error.Invalid;
    var vec: std.ArrayList([]const u8) = .empty;
    out.pcr_map = @splat(null);
    for (pcrs.map) |e| {
        if (e.k != .int) return error.Invalid;
        if (e.v != .bytes) return error.Invalid;
        const val = e.v.bytes;
        if (val.len != 32 and val.len != 48 and val.len != 64) return error.Invalid;
        const k64 = asU64(e.k.int) orelse return error.Invalid;
        if (isRequired(k64)) try vec.append(a, val);
        if (f.upgraded) {
            if (k64 > 255) return error.Invalid;
            const k: u8 = @intCast(k64);
            if (out.pcr_map[k] != null) return error.Invalid;
            if (f.all_nonzero) {
                const nonzero = for (val) |b| {
                    if (b != 0) break true;
                } else false;
                if (k <= 31 and (nonzero or (isRequired(k) and f.always_required))) out.pcr_map[k] = val;
            } else if (isRequired(k)) out.pcr_map[k] = val;
        }
    }
    out.pcr_vec = vec.items;

    const cab = lookup(m, "cabundle") orelse return error.Invalid;
    if (cab.* != .array) return error.Invalid;
    if (cab.array.len == 0 or cab.array.len > max_cert_chain) return error.Invalid;
    const certs = try a.alloc([]const u8, cab.array.len);
    for (cab.array, certs) |c, *o| {
        if (c != .bytes or c.bytes.len == 0 or c.bytes.len > max_cert) return error.Invalid;
        o.* = c.bytes;
    }
    out.cabundle = certs;
}

fn isRequired(k: u64) bool {
    return switch (k) {
        0, 1, 2, 3, 4, 8 => true,
        else => false,
    };
}

fn optBytes(m: []const cbor.Pair, key: []const u8) ?[]const u8 {
    const v = lookup(m, key) orelse return null;
    return if (v.* == .bytes) v.bytes else null;
}

fn noDuplicateTextKeys(m: []const cbor.Pair) cbor.Error!void {
    for (m, 0..) |e, i| for (m[0..i]) |f| if (std.mem.eql(u8, e.k.text, f.k.text)) return error.Invalid;
}

/// `to_signed_message`: the COSE Sig_structure ["Signature1", protected, h'', payload].
fn signedMessage(a: Allocator, c: *const Cose) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = try .initCapacity(a, c.protected.len + c.payload.len + 32);
    try out.append(a, 0x84);
    try out.appendSlice(a, &[_]u8{0x6a} ++ "Signature1");
    try cbor.writeHead(&out, a, 2, c.protected.len);
    try out.appendSlice(a, c.protected);
    try out.append(a, 0x40);
    try cbor.writeHead(&out, a, 2, c.payload.len);
    try out.appendSlice(a, c.payload);
    return out.items;
}

const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

/// `verify_nitro_attestation`.
fn verify(a: Allocator, sig: []const u8, msg: []const u8, doc: *const Doc, now_ms: u64) Allocator.Error!bool {
    const s = P384.Signature.fromBytes(sig[0..96].*);
    const leaf = x509.parse(doc.certificate) catch return false;
    if (!std.mem.eql(u8, leaf.spki.alg.oid, &x509.oid_ec_public_key)) return false;
    const pk = P384.PublicKey.fromSec1(leaf.spki.key) catch return false;
    s.verify(msg, pk) catch return false;

    // chain: leaf, then the cabundle from the end back to the root
    const n = 1 + doc.cabundle.len;
    const chain = try a.alloc([]const u8, n);
    chain[0] = doc.certificate;
    for (doc.cabundle, 0..) |c, i| chain[n - 1 - i] = c;
    const root = x509.parse(&root_der) catch return false;
    // ASN1Time::from_timestamp((now_ms as i64) / 1000): anything before 1970 is outside every
    // certificate's validity, as is a timestamp the time crate cannot represent
    const now: i64 = @divTrunc(@as(i64, @bitCast(now_ms)), 1000);
    var cert = leaf;
    for (0..n) |i| {
        if (i > 0) cert = x509.parse(chain[i]) catch return false;
        const ku = cert.key_usage orelse return false;
        if (i == 0) {
            if (ku & 1 == 0) return false; // digitalSignature
        } else if ((ku >> 5) & 1 == 0) return false; // keyCertSign
        if (i != 0) {
            if (cert.basic_dup) return false;
            const bc = cert.basic orelse return false;
            if (!bc.critical or !bc.ca) return false;
            if (bc.path_len) |pl| if (i - 1 > pl) return false;
        } else if (!cert.basic_dup) {
            if (cert.basic) |bc| if (bc.path_len != null or bc.ca) return false;
        }
        if (!(now >= cert.not_before and now <= cert.not_after)) return false;
        const issuer = if (i < n - 1) (x509.parse(chain[i + 1]) catch return false) else root;
        if (!std.mem.eql(u8, cert.issuer, issuer.subject)) return false;
        if (!x509.verifySignedBy(&cert, &issuer.spki)) return false;
    }
    return true;
}

pub fn load_nitro_attestation_internal(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.flag("enable_nitro_attestation")) return c.abort(NOT_SUPPORTED);
    const now = args[1].u64;
    const bytes = try abi.bytesOf(c.arena, args[0]);

    const pb = c.popt("nitro_attestation_parse_base_cost") orelse return Ctx.invariant();
    const pp = c.popt("nitro_attestation_parse_cost_per_byte") orelse return Ctx.invariant();
    if (!c.charge(pb +| pp *| bytes.len)) return c.oog();

    const flags: Flags = .{
        .upgraded = c.flag("enable_nitro_attestation_upgraded_parsing"),
        .all_nonzero = c.flag("enable_nitro_attestation_all_nonzero_pcrs_parsing"),
        .always_required = c.flag("enable_nitro_attestation_always_include_required_pcrs_parsing"),
    };
    const cose = parseCose(c.arena, bytes) catch |e| switch (e) {
        error.Invalid => return c.abort(PARSE_ERROR),
        else => |x| return x,
    };
    var doc: Doc = undefined;
    parseDoc(c.arena, cose.payload, flags, &doc) catch |e| switch (e) {
        error.Invalid => return c.abort(PARSE_ERROR),
        else => |x| return x,
    };
    const msg = try signedMessage(c.arena, &cose);

    const vb = c.popt("nitro_attestation_verify_base_cost") orelse return Ctx.invariant();
    const vc = c.popt("nitro_attestation_verify_cost_per_cert") orelse return Ctx.invariant();
    if (!c.charge(vb +| vc *| doc.cabundle.len)) return c.oog();

    if (!try verify(c.arena, cose.sig, msg, &doc, now)) return c.abort(VERIFY_ERROR);

    const pcrs = if (flags.upgraded) try pcrEntriesMap(c, &doc) else blk: {
        if (doc.pcr_vec.len != 6) return c.abort(INVALID_PCRS);
        const idx = [_]u8{ 0, 1, 2, 3, 4, 8 };
        const out = try c.arena.alloc(Value, 6);
        for (out, doc.pcr_vec, idx) |*o, v, i| o.* = try pcrEntry(c, i, v);
        break :blk out;
    };
    const fields = try c.arena.alloc(Value, 7);
    fields[0] = try c.bytesValue(doc.module_id);
    fields[1] = .{ .u64 = doc.timestamp };
    fields[2] = try c.bytesValue(doc.digest);
    fields[3] = .{ .vector = pcrs };
    fields[4] = try option(c, doc.public_key);
    fields[5] = try option(c, doc.user_data);
    fields[6] = try option(c, doc.nonce);
    return c.ok1(.{ .@"struct" = fields });
}

fn pcrEntry(c: *Ctx, index: u8, v: []const u8) Error!Value {
    const f = try c.arena.alloc(Value, 2);
    f[0] = .{ .u8 = index };
    f[1] = try c.bytesValue(v);
    return .{ .@"struct" = f };
}

fn pcrEntriesMap(c: *Ctx, doc: *const Doc) Error![]Value {
    var n: usize = 0;
    for (doc.pcr_map) |e| {
        if (e != null) n += 1;
    }
    const out = try c.arena.alloc(Value, n);
    var j: usize = 0;
    for (doc.pcr_map, 0..) |e, i| if (e) |v| {
        out[j] = try pcrEntry(c, @intCast(i), v);
        j += 1;
    };
    return out;
}

fn option(c: *Ctx, v: ?[]const u8) Error!Value {
    const f = try c.arena.alloc(Value, 1);
    if (v) |b| {
        const inner = try c.arena.alloc(Value, 1);
        inner[0] = try c.bytesValue(b);
        f[0] = .{ .vector = inner };
    } else f[0] = .{ .vector = &.{} };
    return .{ .@"struct" = f };
}
