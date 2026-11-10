//! Minimal X.509 for anemo's self-signed Ed25519 certificates: build ours (what `rcgen` makes:
//! one DNS name SAN, validity 1975..4096) and verify a peer's the way `rustls-webpki` is used in
//! anemo `crypto.rs`: self-signed, Ed25519 only, valid now, subject name matches the network's
//! server name, usable for the role. The peer id is the SPKI Ed25519 key.
const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const zsig = @import("sig");

pub const Error = error{
    BadDer,
    UnsupportedAlgorithm,
    BadSignature,
    NotYetValid,
    Expired,
    NameMismatch,
    BadUsage,
};

const oid_eku_server = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
const oid_eku_client = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };
/// AlgorithmIdentifier content for Ed25519 (RFC 8410: no parameters).
const alg_ed25519 = [_]u8{ 0x06, 0x03, 0x2b, 0x65, 0x70 };

// ------------------------------------------------------------------ DER reading

const Tlv = struct { tag: u8, content: []const u8, rest: []const u8, full: []const u8 };

fn readTlv(buf: []const u8) Error!Tlv {
    if (buf.len < 2) return error.BadDer;
    const tag = buf[0];
    if (tag & 0x1f == 0x1f) return error.BadDer; // high tag numbers unsupported
    var len: usize = buf[1];
    var p: usize = 2;
    if (len & 0x80 != 0) {
        const n = len & 0x7f;
        if (n == 0 or n > 3 or buf.len < p + n) return error.BadDer;
        len = 0;
        for (buf[p..][0..n]) |b| len = (len << 8) | b;
        p += n;
        if (len < 128 or buf[2] == 0) return error.BadDer; // not minimal
    }
    if (buf.len - p < len) return error.BadDer;
    return .{ .tag = tag, .content = buf[p..][0..len], .rest = buf[p + len ..], .full = buf[0 .. p + len] };
}

fn expect(buf: []const u8, tag: u8) Error!Tlv {
    const t = try readTlv(buf);
    if (t.tag != tag) return error.BadDer;
    return t;
}

fn daysFromCivil(y_in: i64, m: i64, d: i64) i64 {
    const y = if (m <= 2) y_in - 1 else y_in;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp = @mod(m + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

fn parseTime(t: Tlv) Error!i64 {
    const s = t.content;
    var year: i64 = undefined;
    var rest: []const u8 = undefined;
    if (t.tag == 0x17) {
        if (s.len != 13) return error.BadDer;
        const yy = try digits(s[0..2]);
        year = if (yy >= 50) 1900 + yy else 2000 + yy;
        rest = s[2..];
    } else if (t.tag == 0x18) {
        if (s.len != 15) return error.BadDer;
        year = try digits(s[0..4]);
        rest = s[4..];
    } else return error.BadDer;
    if (rest[10] != 'Z') return error.BadDer;
    const mo = try digits(rest[0..2]);
    const da = try digits(rest[2..4]);
    const hh = try digits(rest[4..6]);
    const mi = try digits(rest[6..8]);
    const ss = try digits(rest[8..10]);
    if (mo < 1 or mo > 12 or da < 1 or da > 31 or hh > 23 or mi > 59 or ss > 60) return error.BadDer;
    return daysFromCivil(year, mo, da) * 86400 + hh * 3600 + mi * 60 + ss;
}

fn digits(s: []const u8) Error!i64 {
    var v: i64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return error.BadDer;
        v = v * 10 + (c - '0');
    }
    return v;
}

pub const Role = enum { server, client };

pub const Parsed = struct {
    /// Ed25519 public key = anemo PeerId.
    public_key: [32]u8,
};

/// Verifies `der` as an anemo peer certificate. `now` is unix seconds. `name` must be one of the
/// certificate's dNSName SAN entries. Mirrors what anemo's `CertVerifier` gets from
/// rustls-webpki 0.103 (`verify_for_usage` with the certificate as its own trust anchor, then
/// `verify_is_valid_for_subject_name`): v3 only, issuer equal to subject, Ed25519 with no
/// parameters, notBefore <= now <= notAfter, no unknown critical extension, no repeated known
/// extension, not a CA, and an EKU (if present) naming the role's purpose (anyExtendedKeyUsage is
/// not honoured).
pub fn verifyPeerCert(der: []const u8, name: []const u8, role: Role, now: i64) Error!Parsed {
    const cert = try expect(der, 0x30);
    if (cert.rest.len != 0) return error.BadDer;
    const tbs = try expect(cert.content, 0x30);
    const sig_alg = try expect(tbs.rest, 0x30);
    const sig_val = try expect(sig_alg.rest, 0x03);
    if (sig_val.rest.len != 0) return error.BadDer;
    if (!std.mem.eql(u8, sig_alg.content, &alg_ed25519)) return error.UnsupportedAlgorithm;
    if (sig_val.content.len != 65 or sig_val.content[0] != 0) return error.BadDer;

    // TBSCertificate
    var p = tbs.content;
    const version = try expect(p, 0xa0);
    if (!std.mem.eql(u8, version.content, &.{ 0x02, 0x01, 0x02 })) return error.BadDer; // v3 only
    p = version.rest;
    const serial = try expect(p, 0x02);
    p = serial.rest;
    const inner_alg = try expect(p, 0x30);
    if (!std.mem.eql(u8, inner_alg.content, sig_alg.content)) return error.UnsupportedAlgorithm;
    p = inner_alg.rest;
    const issuer = try expect(p, 0x30);
    p = issuer.rest;
    const validity = try expect(p, 0x30);
    p = validity.rest;
    const nb = try readTlv(validity.content);
    const na = try readTlv(nb.rest);
    if (na.rest.len != 0) return error.BadDer;
    const not_before = try parseTime(nb);
    const not_after = try parseTime(na);
    if (not_before > not_after) return error.BadDer;
    if (now < not_before) return error.NotYetValid;
    if (now > not_after) return error.Expired;
    const subject = try expect(p, 0x30);
    p = subject.rest;
    // The certificate is its own trust anchor: path building needs issuer == subject.
    if (!std.mem.eql(u8, issuer.content, subject.content)) return error.BadSignature;
    const spki = try expect(p, 0x30);
    p = spki.rest;
    const spki_alg = try expect(spki.content, 0x30);
    if (!std.mem.eql(u8, spki_alg.content, &alg_ed25519)) return error.UnsupportedAlgorithm;
    const spki_key = try expect(spki_alg.rest, 0x03);
    if (spki_key.rest.len != 0) return error.BadDer;
    if (spki_key.content.len != 33 or spki_key.content[0] != 0) return error.BadDer;
    const pk: [32]u8 = spki_key.content[1..33].*;

    // Self-signed: the certificate's own key signs the TBS.
    if (zsig.ed25519.verify(&pk, tbs.full, sig_val.content[1..65]) != .valid) return error.BadSignature;

    // Extensions: optional [3] EXPLICIT SEQUENCE OF Extension, and nothing else (webpki rejects
    // issuerUniqueID / subjectUniqueID).
    var san: ?[]const u8 = null;
    var eku: ?[]const u8 = null;
    var basic: ?[]const u8 = null;
    var seen: [256]bool = @splat(false);
    if (p.len > 0) {
        const e = try expect(p, 0xa3);
        if (e.rest.len != 0) return error.BadDer;
        const exts = try expect(e.content, 0x30);
        if (exts.rest.len != 0) return error.BadDer;
        var ep = exts.content;
        while (ep.len > 0) {
            const ext = try expect(ep, 0x30);
            ep = ext.rest;
            const oid = try expect(ext.content, 0x06);
            var vp = oid.rest;
            var v = try readTlv(vp);
            var critical = false;
            if (v.tag == 0x01) { // critical BOOLEAN
                if (v.content.len != 1) return error.BadDer;
                critical = switch (v.content[0]) {
                    0xff => true,
                    0x00 => false,
                    else => return error.BadDer,
                };
                vp = v.rest;
                v = try readTlv(vp);
            }
            if (v.tag != 0x04 or v.rest.len != 0) return error.BadDer;
            const known = oid.content.len == 3 and oid.content[0] == 0x55 and oid.content[1] == 0x1d and switch (oid.content[2]) {
                15, 17, 19, 30, 31, 37 => true,
                else => false,
            };
            if (!known) {
                if (critical) return error.BadUsage; // UnsupportedCriticalExtension
                continue;
            }
            const id = oid.content[2];
            if (seen[id]) return error.BadDer; // ExtensionValueInvalid: repeated extension
            seen[id] = true;
            if (id == 15) continue; // keyUsage: ignored by webpki for end entities
            const inner = try expect(v.content, 0x30);
            if (inner.rest.len != 0) return error.BadDer;
            switch (id) {
                17 => san = inner.content,
                19 => basic = inner.content,
                37 => eku = inner.content,
                else => {}, // name constraints, CRL distribution points: not used for this check
            }
        }
    }
    // basicConstraints: cA must be absent or false for an end entity.
    if (basic) |b| if (b.len > 0) {
        const t = try readTlv(b);
        if (t.tag == 0x01) {
            if (t.content.len != 1) return error.BadDer;
            if (t.content[0] == 0xff) return error.BadUsage; // CaUsedAsEndEntity
            if (t.content[0] != 0x00) return error.BadDer;
        }
    };
    // extendedKeyUsage: when present it must be non-empty and name the role's purpose.
    if (eku) |u_all| {
        if (u_all.len == 0) return error.BadUsage;
        const want = if (role == .server) &oid_eku_server else &oid_eku_client;
        var up = u_all;
        var ok = false;
        while (up.len > 0) {
            const u = try expect(up, 0x06);
            up = u.rest;
            if (std.mem.eql(u8, u.content, want)) ok = true;
        }
        if (!ok) return error.BadUsage;
    }
    // subject name: a dNSName SAN entry equal to `name` (ASCII case-insensitive).
    var name_ok = false;
    if (san) |names| {
        var np = names;
        while (np.len > 0) {
            const n = try readTlv(np);
            np = n.rest;
            if (n.tag == 0x82 and std.ascii.eqlIgnoreCase(n.content, name)) name_ok = true;
        }
    }
    if (!name_ok) return error.NameMismatch;
    return .{ .public_key = pk };
}

// ------------------------------------------------------------------ DER writing

const Writer = struct {
    buf: []u8,
    len: usize = 0,

    fn put(w: *Writer, bytes: []const u8) void {
        @memcpy(w.buf[w.len..][0..bytes.len], bytes);
        w.len += bytes.len;
    }
    /// Starts a constructed element; returns the position to finish with `end`.
    fn begin(w: *Writer, tag: u8) usize {
        w.buf[w.len] = tag;
        w.len += 3; // reserve: tag + 0x82 hi lo; compacted in end()
        return w.len - 3;
    }
    fn end(w: *Writer, start: usize) void {
        const content_len = w.len - (start + 3);
        var hdr: [4]u8 = undefined;
        var hl: usize = 0;
        if (content_len < 128) {
            hdr[0] = @intCast(content_len);
            hl = 1;
        } else if (content_len < 256) {
            hdr[0] = 0x81;
            hdr[1] = @intCast(content_len);
            hl = 2;
        } else {
            hdr[0] = 0x82;
            hdr[1] = @intCast(content_len >> 8);
            hdr[2] = @intCast(content_len & 0xff);
            hl = 3;
        }
        // content currently starts at start+3; move to start+1+hl
        std.mem.copyForwards(u8, w.buf[start + 1 + hl ..][0..content_len], w.buf[start + 3 ..][0..content_len]);
        @memcpy(w.buf[start + 1 ..][0..hl], hdr[0..hl]);
        w.len = start + 1 + hl + content_len;
    }
};

pub const max_cert_len = 512;

/// A self-signed Ed25519 certificate for `name`, shaped like rcgen's: v3, CN subject = issuer,
/// 1975-01-01 .. 4096-01-01, SAN dNSName = `name`. Writes DER into `out`, returns its length.
pub fn generateSelfSigned(out: *[max_cert_len]u8, kp: Ed25519.KeyPair, serial: [20]u8, name: []const u8) usize {
    std.debug.assert(name.len < 100);
    var w: Writer = .{ .buf = out };
    const cert = w.begin(0x30);
    const tbs_start = w.len;
    const tbs = w.begin(0x30);
    w.put(&.{ 0xa0, 0x03, 0x02, 0x01, 0x02 }); // version v3
    w.put(&.{ 0x02, 0x14 }); // serial: 20 bytes, positive
    var s = serial;
    s[0] = (s[0] & 0x7f) | 0x01;
    w.put(&s);
    const alg: [7]u8 = .{ 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };
    w.put(&alg);
    const subject = [_]u8{ 0x30, 0x0a, 0x31, 0x08, 0x30, 0x06, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x00 };
    // Name = SEQUENCE { SET { SEQUENCE { OID cn, UTF8String "deepwave" } } }
    var nm: [16]u8 = undefined;
    const cn = "zui";
    nm[0] = 0x30;
    nm[1] = 2 + 2 + 5 + 2 + cn.len; // set(2) + seq(2) + oid(5) + str(2+len)
    nm[2] = 0x31;
    nm[3] = 2 + 5 + 2 + cn.len;
    nm[4] = 0x30;
    nm[5] = 5 + 2 + cn.len;
    nm[6] = 0x06;
    nm[7] = 0x03;
    nm[8] = 0x55;
    nm[9] = 0x04;
    nm[10] = 0x03;
    nm[11] = 0x0c;
    nm[12] = cn.len;
    @memcpy(nm[13..][0..cn.len], cn);
    _ = subject;
    const name_der = nm[0 .. 13 + cn.len];
    w.put(name_der); // issuer
    w.put(&.{ 0x30, 0x20, 0x17, 0x0d }); // validity
    w.put("750101000000Z");
    w.put(&.{ 0x18, 0x0f });
    w.put("40960101000000Z");
    w.put(name_der); // subject
    w.put(&.{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 }); // SPKI
    w.put(&kp.public_key.toBytes());
    // extensions [3] { SEQUENCE { SEQUENCE { OID san, OCTET STRING { SEQUENCE { [2] name } } } } }
    const e3 = w.begin(0xa3);
    const e_seq = w.begin(0x30);
    const e_one = w.begin(0x30);
    w.put(&.{ 0x06, 0x03, 0x55, 0x1d, 0x11 });
    const oct = w.begin(0x04);
    const names = w.begin(0x30);
    w.put(&.{ 0x82, @as(u8, @intCast(name.len)) });
    w.put(name);
    w.end(names);
    w.end(oct);
    w.end(e_one);
    w.end(e_seq);
    w.end(e3);
    w.end(tbs);
    const tbs_der = w.buf[tbs_start..w.len];
    const sig = kp.sign(tbs_der, null) catch unreachable;
    w.put(&alg);
    w.put(&.{ 0x03, 0x41, 0x00 });
    w.put(&sig.toBytes());
    w.end(cert);
    return w.len;
}

test "generate then verify" {
    const kp = Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(7))) catch unreachable;
    var buf: [max_cert_len]u8 = undefined;
    const n = generateSelfSigned(&buf, kp, @as([20]u8, @splat(0x42)), "sui-35834a8a");
    const parsed = try verifyPeerCert(buf[0..n], "sui-35834a8a", .client, 1_800_000_000);
    try std.testing.expectEqualSlices(u8, &kp.public_key.toBytes(), &parsed.public_key);
    try std.testing.expectError(error.NameMismatch, verifyPeerCert(buf[0..n], "sui-other", .server, 1_800_000_000));
    buf[n - 3] ^= 1;
    try std.testing.expectError(error.BadSignature, verifyPeerCert(buf[0..n], "sui-35834a8a", .server, 1_800_000_000));
}

/// Test-only certificate builder: like `generateSelfSigned`, with the knobs webpki checks.
const TestCert = struct {
    v3: bool = true,
    issuer_cn: []const u8 = "zui",
    not_before: []const u8 = "750101000000Z",
    san: bool = true,
    /// Extra Extension DER (each a full SEQUENCE) appended after the SAN.
    extra: []const u8 = "",

    fn build(t: TestCert, out: []u8, kp: Ed25519.KeyPair) []const u8 {
        var w: Writer = .{ .buf = out };
        const cert = w.begin(0x30);
        const tbs_start = w.len;
        const tbs = w.begin(0x30);
        if (t.v3) w.put(&.{ 0xa0, 0x03, 0x02, 0x01, 0x02 });
        w.put(&.{ 0x02, 0x01, 0x01 });
        const alg: [7]u8 = .{ 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };
        w.put(&alg);
        writeName(&w, t.issuer_cn);
        const v = w.begin(0x30);
        w.put(&.{ 0x17, @intCast(t.not_before.len) });
        w.put(t.not_before);
        w.put(&.{ 0x18, 0x0f });
        w.put("40960101000000Z");
        w.end(v);
        writeName(&w, "zui");
        w.put(&.{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 });
        w.put(&kp.public_key.toBytes());
        const e3 = w.begin(0xa3);
        const e_seq = w.begin(0x30);
        if (t.san) {
            const e_one = w.begin(0x30);
            w.put(&.{ 0x06, 0x03, 0x55, 0x1d, 0x11 });
            const oct = w.begin(0x04);
            const names = w.begin(0x30);
            w.put(&.{ 0x82, 12 });
            w.put("sui-35834a8a");
            w.end(names);
            w.end(oct);
            w.end(e_one);
        }
        w.put(t.extra);
        w.end(e_seq);
        w.end(e3);
        w.end(tbs);
        const sig = kp.sign(w.buf[tbs_start..w.len], null) catch unreachable;
        w.put(&alg);
        w.put(&.{ 0x03, 0x41, 0x00 });
        w.put(&sig.toBytes());
        w.end(cert);
        return w.buf[0..w.len];
    }

    fn writeName(w: *Writer, cn: []const u8) void {
        const n = w.begin(0x30);
        const set = w.begin(0x31);
        const atv = w.begin(0x30);
        w.put(&.{ 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, @intCast(cn.len) });
        w.put(cn);
        w.end(atv);
        w.end(set);
        w.end(n);
    }
};

test "webpki parity: certificates rustls-webpki rejects are rejected" {
    const kp = Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(9))) catch unreachable;
    const now: i64 = 1_800_000_000;
    const nm = "sui-35834a8a";
    var buf: [1024]u8 = undefined;
    // baseline accepted (both roles)
    _ = try verifyPeerCert((TestCert{}).build(&buf, kp), nm, .server, now);
    _ = try verifyPeerCert((TestCert{}).build(&buf, kp), nm, .client, now);
    // unknown non-critical extension (1.2.3.4) and keyUsage: accepted
    const unknown_noncrit = [_]u8{ 0x30, 0x0a, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x04, 0x03, 0x30, 0x01, 0x00 };
    _ = try verifyPeerCert((TestCert{ .extra = &unknown_noncrit }).build(&buf, kp), nm, .server, now);
    const ku = [_]u8{ 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80 };
    _ = try verifyPeerCert((TestCert{ .extra = &ku }).build(&buf, kp), nm, .server, now);
    // basicConstraints cA=false: accepted; cA=true: CaUsedAsEndEntity
    const bc_false = [_]u8{ 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x00 };
    _ = try verifyPeerCert((TestCert{ .extra = &bc_false }).build(&buf, kp), nm, .server, now);
    const bc_ca = [_]u8{ 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff };
    try std.testing.expectError(error.BadUsage, verifyPeerCert((TestCert{ .extra = &bc_ca }).build(&buf, kp), nm, .server, now));
    // EKU: serverAuth accepted for a server, rejected for a client; anyExtendedKeyUsage and an
    // empty EKU are rejected
    const eku_server = [_]u8{ 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
    _ = try verifyPeerCert((TestCert{ .extra = &eku_server }).build(&buf, kp), nm, .server, now);
    try std.testing.expectError(error.BadUsage, verifyPeerCert((TestCert{ .extra = &eku_server }).build(&buf, kp), nm, .client, now));
    const eku_any = [_]u8{ 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x08, 0x30, 0x06, 0x06, 0x04, 0x55, 0x1d, 0x25, 0x00 };
    try std.testing.expectError(error.BadUsage, verifyPeerCert((TestCert{ .extra = &eku_any }).build(&buf, kp), nm, .server, now));
    const eku_empty = [_]u8{ 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x02, 0x30, 0x00 };
    try std.testing.expectError(error.BadUsage, verifyPeerCert((TestCert{ .extra = &eku_empty }).build(&buf, kp), nm, .server, now));
    // the EKU extension's own OID as a "purpose" is not anyExtendedKeyUsage
    const eku_bogus = [_]u8{ 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55, 0x1d, 0x25 };
    try std.testing.expectError(error.BadUsage, verifyPeerCert((TestCert{ .extra = &eku_bogus }).build(&buf, kp), nm, .server, now));
    // unknown critical extension: UnsupportedCriticalExtension
    const unknown_crit = [_]u8{ 0x30, 0x0d, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x01, 0x01, 0xff, 0x04, 0x03, 0x30, 0x01, 0x00 };
    try std.testing.expectError(error.BadUsage, verifyPeerCert((TestCert{ .extra = &unknown_crit }).build(&buf, kp), nm, .server, now));
    // a second SAN: ExtensionValueInvalid
    const san2 = [_]u8{ 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x04, 0x30, 0x02, 0x82, 0x00 };
    try std.testing.expectError(error.BadDer, verifyPeerCert((TestCert{ .extra = &san2 }).build(&buf, kp), nm, .server, now));
    // v1 certificate: UnsupportedCertVersion
    try std.testing.expectError(error.BadDer, verifyPeerCert((TestCert{ .v3 = false }).build(&buf, kp), nm, .server, now));
    // issuer differs from subject: no path to the self anchor
    try std.testing.expectError(error.BadSignature, verifyPeerCert((TestCert{ .issuer_cn = "zux" }).build(&buf, kp), nm, .server, now));
    // notBefore after notAfter (UTCTime 2049 > GeneralizedTime 4096 is fine; use a 4096+ start via
    // UTCTime is impossible, so check the not-yet-valid path instead)
    try std.testing.expectError(error.NotYetValid, verifyPeerCert((TestCert{ .not_before = "491231235959Z" }).build(&buf, kp), nm, .server, now));
    // no SAN: no subject name to match
    try std.testing.expectError(error.NameMismatch, verifyPeerCert((TestCert{ .san = false }).build(&buf, kp), nm, .server, now));
}
