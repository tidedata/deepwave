//! The X.509 subset `sui_types::nitro_attestation::verify_nitro_attestation` uses, as
//! x509-parser 0.17 (DER via asn1-rs 0.7) and ring 0.17 see it: certificate structure, validity,
//! issuer/subject names, the subject public key, keyUsage and basicConstraints, and
//! ECDSA (P-256/P-384 with SHA-256/SHA-384) signatures by the issuer.
//!
//! Every certificate a successful nitro verification reaches sits inside the signed attestation
//! payload, so only genuine AWS-issued DER gets this far on the success path; the parser is
//! strict DER all the same and fails closed on anything it does not model.
const std = @import("std");
const ecdsa = std.crypto.sign.ecdsa;

pub const Error = error{Invalid};

const Tlv = struct {
    id: u8,
    content: []const u8,
    raw: []const u8,
    rest: []const u8,
};

/// asn1-rs `Header::from_der`: single-byte tags only (all the X.509 we read), definite lengths,
/// long form with up to 8 significant bytes (non-minimal long forms are accepted, as asn1-rs does).
fn tlv(in: []const u8) Error!Tlv {
    if (in.len < 2) return error.Invalid;
    const id = in[0];
    if (id & 0x1f == 0x1f) return error.Invalid;
    var i: usize = 1;
    const l0 = in[i];
    i += 1;
    var len: u64 = 0;
    if (l0 < 0x80) {
        len = l0;
    } else {
        const n = l0 & 0x7f;
        if (n == 0 or n == 0x7f) return error.Invalid;
        if (in.len - i < n) return error.Invalid;
        for (in[i..][0..n]) |b| {
            if (len >= (1 << 56)) return error.Invalid;
            len = (len << 8) | b;
        }
        i += n;
    }
    if (len > in.len - i) return error.Invalid;
    const end = i + @as(usize, @intCast(len));
    return .{ .id = id, .content = in[i..end], .raw = in[0..end], .rest = in[end..] };
}

fn expect(in: []const u8, id: u8) Error!Tlv {
    const t = try tlv(in);
    if (t.id != id) return error.Invalid;
    return t;
}

const SEQ: u8 = 0x30;
const INT: u8 = 0x02;
const BITS: u8 = 0x03;
const OCTETS: u8 = 0x04;
const OID: u8 = 0x06;
const BOOL: u8 = 0x01;

pub const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
pub const oid_p384 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
pub const oid_p256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
pub const oid_ecdsa_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
pub const oid_ecdsa_sha384 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
const oid_key_usage = [_]u8{ 0x55, 0x1d, 0x0f };
const oid_basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 };

pub const AlgId = struct { oid: []const u8, params_oid: ?[]const u8 };

fn algId(in: []const u8) Error!struct { AlgId, []const u8 } {
    const s = try expect(in, SEQ);
    const o = try expect(s.content, OID);
    var params: ?[]const u8 = null;
    if (o.rest.len > 0) {
        const p = try tlv(o.rest);
        if (p.id == OID) params = p.content;
    }
    return .{ .{ .oid = o.content, .params_oid = params }, s.rest };
}

pub const Spki = struct { alg: AlgId, key: []const u8 };

pub const BasicConstraints = struct { critical: bool, ca: bool, path_len: ?u32 };

pub const Cert = struct {
    tbs: []const u8,
    issuer: []const u8,
    subject: []const u8,
    not_before: i64,
    not_after: i64,
    spki: Spki,
    sig_alg: AlgId,
    sig: []const u8,
    /// keyUsage bits (bit 0 = digitalSignature), null when the extension is absent or repeated
    key_usage: ?u16,
    basic: ?BasicConstraints,
    basic_dup: bool,
};

/// `X509Certificate::from_der` (bytes after the certificate are ignored, as `from_der` returns
/// them as the remainder).
pub fn parse(der: []const u8) Error!Cert {
    const outer = try expect(der, SEQ);
    const tbs = try expect(outer.content, SEQ);
    const alg, const after_alg = try algId(tbs.rest);
    const sv = try expect(after_alg, BITS);
    if (sv.content.len == 0 or sv.content[0] != 0) return error.Invalid;

    var c: Cert = undefined;
    c.tbs = tbs.raw;
    c.sig_alg = alg;
    c.sig = sv.content[1..];
    c.key_usage = null;
    c.basic = null;
    c.basic_dup = false;

    var r = tbs.content;
    if (r.len > 0 and r[0] == 0xa0) {
        const v = try tlv(r);
        const vi = try expect(v.content, INT);
        if (vi.rest.len != 0) return error.Invalid;
        r = v.rest;
    }
    const serial = try expect(r, INT);
    _, r = try algId(serial.rest);
    const issuer = try expect(r, SEQ);
    c.issuer = issuer.raw;
    const validity = try expect(issuer.rest, SEQ);
    const nb = try time(validity.content);
    const na = try time(nb.rest);
    c.not_before = nb.secs;
    c.not_after = na.secs;
    const subject = try expect(validity.rest, SEQ);
    c.subject = subject.raw;
    const spki = try expect(subject.rest, SEQ);
    const kalg, const kbits_in = try algId(spki.content);
    const kbits = try expect(kbits_in, BITS);
    if (kbits.content.len == 0 or kbits.content[0] != 0) return error.Invalid;
    c.spki = .{ .alg = kalg, .key = kbits.content[1..] };
    r = spki.rest;
    if (r.len > 0 and r[0] == 0x81) r = (try tlv(r)).rest;
    if (r.len > 0 and r[0] == 0x82) r = (try tlv(r)).rest;
    var ku_seen: u8 = 0;
    if (r.len > 0 and r[0] == 0xa3) {
        const x = try tlv(r);
        const list = try expect(x.content, SEQ);
        var e = list.content;
        while (e.len > 0) {
            const ext = try expect(e, SEQ);
            e = ext.rest;
            const oid = try expect(ext.content, OID);
            var critical = false;
            var rest = oid.rest;
            if (rest.len > 0 and rest[0] == BOOL) {
                const b = try tlv(rest);
                if (b.content.len != 1) return error.Invalid;
                critical = b.content[0] != 0;
                rest = b.rest;
            }
            const val = try expect(rest, OCTETS);
            if (std.mem.eql(u8, oid.content, &oid_key_usage)) {
                ku_seen += 1;
                const bits = try expect(val.content, BITS);
                if (bits.content.len == 0) return error.Invalid;
                var flags: u16 = 0;
                const data = bits.content[1..];
                var k: usize = data.len;
                while (k > 0) {
                    k -= 1;
                    flags = (flags << 8) | @bitReverse(data[k]);
                }
                c.key_usage = flags;
            } else if (std.mem.eql(u8, oid.content, &oid_basic_constraints)) {
                if (c.basic != null) c.basic_dup = true;
                const s = try expect(val.content, SEQ);
                var ca = false;
                var pl: ?u32 = null;
                var q = s.content;
                if (q.len > 0 and q[0] == BOOL) {
                    const b = try tlv(q);
                    if (b.content.len != 1) return error.Invalid;
                    ca = b.content[0] != 0;
                    q = b.rest;
                }
                if (q.len > 0) {
                    const n = try expect(q, INT);
                    if (n.content.len == 0 or n.content.len > 5 or n.content[0] & 0x80 != 0) return error.Invalid;
                    var v: u64 = 0;
                    for (n.content) |b| v = (v << 8) | b;
                    if (v > std.math.maxInt(u32)) return error.Invalid;
                    pl = @intCast(v);
                }
                c.basic = .{ .critical = critical, .ca = ca, .path_len = pl };
            }
        }
    }
    if (ku_seen > 1) c.key_usage = null;
    return c;
}

const Time = struct { secs: i64, rest: []const u8 };

/// UTCTime (YYMMDDHHMMSSZ, 19YY when YY >= 50) or GeneralizedTime (YYYYMMDDHHMMSSZ).
fn time(in: []const u8) Error!Time {
    const t = try tlv(in);
    const s = t.content;
    var year: i64 = undefined;
    var off: usize = undefined;
    switch (t.id) {
        0x17 => {
            if (s.len != 13) return error.Invalid;
            const yy = try dig2(s[0..2]);
            year = if (yy >= 50) 1900 + yy else 2000 + yy;
            off = 2;
        },
        0x18 => {
            if (s.len != 15) return error.Invalid;
            year = (try dig2(s[0..2])) * 100 + try dig2(s[2..4]);
            off = 4;
        },
        else => return error.Invalid,
    }
    if (s[s.len - 1] != 'Z') return error.Invalid;
    const mo = try dig2(s[off..][0..2]);
    const d = try dig2(s[off + 2 ..][0..2]);
    const h = try dig2(s[off + 4 ..][0..2]);
    const mi = try dig2(s[off + 6 ..][0..2]);
    const se = try dig2(s[off + 8 ..][0..2]);
    if (mo < 1 or mo > 12 or d < 1 or d > daysIn(year, mo) or h > 23 or mi > 59 or se > 59) return error.Invalid;
    return .{ .secs = daysFromCivil(year, mo, d) * 86400 + h * 3600 + mi * 60 + se, .rest = t.rest };
}

fn dig2(s: []const u8) Error!i64 {
    if (s[0] < '0' or s[0] > '9' or s[1] < '0' or s[1] > '9') return error.Invalid;
    return @as(i64, s[0] - '0') * 10 + (s[1] - '0');
}

fn daysIn(y: i64, m: i64) i64 {
    return switch (m) {
        2 => if (@mod(y, 4) == 0 and (@mod(y, 100) != 0 or @mod(y, 400) == 0)) 29 else 28,
        4, 6, 9, 11 => 30,
        else => 31,
    };
}

/// Days since 1970-01-01 (Howard Hinnant's days_from_civil).
fn daysFromCivil(y0: i64, m: i64, d: i64) i64 {
    const y = if (m <= 2) y0 - 1 else y0;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// ring's ECDSA_*_ASN1 signature: DER SEQUENCE of two positive, minimally encoded INTEGERs
/// of at most the scalar size, and nothing after it.
fn derSig(comptime n: usize, der: []const u8) Error![2 * n]u8 {
    const s = try expect(der, SEQ);
    if (s.rest.len != 0) return error.Invalid;
    var out: [2 * n]u8 = @splat(0);
    var r = s.content;
    inline for (0..2) |k| {
        const x = try expect(r, INT);
        r = x.rest;
        var v = x.content;
        if (v.len == 0 or v[0] & 0x80 != 0) return error.Invalid;
        if (v[0] == 0) {
            if (v.len == 1 or v[1] & 0x80 == 0) return error.Invalid;
            v = v[1..];
        }
        if (v.len > n) return error.Invalid;
        @memcpy(out[k * n + n - v.len ..][0..v.len], v);
    }
    if (r.len != 0) return error.Invalid;
    return out;
}

fn verifyWith(comptime E: type, key: []const u8, msg: []const u8, sig_der: []const u8) bool {
    const n = E.Signature.encoded_length / 2;
    // ring takes only uncompressed points
    if (key.len != 1 + 2 * n or key[0] != 0x04) return false;
    const pk = E.PublicKey.fromSec1(key) catch return false;
    const raw = derSig(n, sig_der) catch return false;
    const sig = E.Signature.fromBytes(raw);
    sig.verify(msg, pk) catch return false;
    return true;
}

/// `X509Certificate::verify_signature(Some(issuer_spki))` (x509-parser's `verify` feature).
pub fn verifySignedBy(c: *const Cert, issuer: *const Spki) bool {
    const curve = issuer.alg.params_oid orelse return false;
    const sha384 = std.mem.eql(u8, c.sig_alg.oid, &oid_ecdsa_sha384);
    const sha256 = std.mem.eql(u8, c.sig_alg.oid, &oid_ecdsa_sha256);
    if (!sha384 and !sha256) return false;
    if (std.mem.eql(u8, curve, &oid_p384)) {
        if (sha384) return verifyWith(ecdsa.Ecdsa(std.crypto.ecc.P384, std.crypto.hash.sha2.Sha384), issuer.key, c.tbs, c.sig);
        return verifyWith(ecdsa.Ecdsa(std.crypto.ecc.P384, std.crypto.hash.sha2.Sha256), issuer.key, c.tbs, c.sig);
    }
    if (std.mem.eql(u8, curve, &oid_p256)) {
        if (sha384) return verifyWith(ecdsa.Ecdsa(std.crypto.ecc.P256, std.crypto.hash.sha2.Sha384), issuer.key, c.tbs, c.sig);
        return verifyWith(ecdsa.Ecdsa(std.crypto.ecc.P256, std.crypto.hash.sha2.Sha256), issuer.key, c.tbs, c.sig);
    }
    return false;
}

test "time" {
    try std.testing.expectEqual(@as(i64, 0), daysFromCivil(1970, 1, 1));
    const t = try time(&([_]u8{ 0x17, 13 } ++ "191028132805Z".*));
    try std.testing.expectEqual(@as(i64, 1572269285), t.secs);
}
