//! Self-signed ECDSA P-256 certificate for WebTransport `serverCertificateHashes` (Chrome: X.509v3,
//! ECDSA P-256, validity at most 14 days). NATIVE-PROTOCOL.md 1.3. The SHA-256 of the DER is what a
//! page passes as the certificate hash.
const std = @import("std");
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const max_len = 640;

pub const Cert = struct {
    der: [max_len]u8 = undefined,
    len: usize = 0,
    key: P256.KeyPair,

    pub fn bytes(c: *const Cert) []const u8 {
        return c.der[0..c.len];
    }
    pub fn sha256(c: *const Cert) [32]u8 {
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(c.bytes(), &h, .{});
        return h;
    }
};

const Writer = struct {
    buf: []u8,
    len: usize = 0,
    fn put(w: *Writer, b: []const u8) void {
        @memcpy(w.buf[w.len..][0..b.len], b);
        w.len += b.len;
    }
    /// Opens a TLV with a 2-byte long-form length (0x82 hi lo), patched by `end`.
    fn begin(w: *Writer, tag: u8) usize {
        w.put(&.{ tag, 0x82, 0, 0 });
        return w.len;
    }
    /// Patches the length with DER's minimal form (shifting the content down when shorter).
    fn end(w: *Writer, at: usize) void {
        const n = w.len - at;
        if (n >= 256) {
            w.buf[at - 2] = @intCast(n >> 8);
            w.buf[at - 1] = @intCast(n & 0xff);
            return;
        }
        const hdr: usize = if (n < 128) 1 else 2; // length bytes needed
        const drop = 3 - hdr;
        const len_at = at - 3;
        if (hdr == 1) w.buf[len_at] = @intCast(n) else {
            w.buf[len_at] = 0x81;
            w.buf[len_at + 1] = @intCast(n);
        }
        std.mem.copyForwards(u8, w.buf[len_at + hdr ..][0..n], w.buf[at..][0..n]);
        w.len -= drop;
    }
};

fn utcTime(out: *[13]u8, unix: i64) void {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(unix) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    _ = std.fmt.bufPrint(out, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
        yd.year % 100,              md.month.numeric(),           md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

const oid_ecdsa_sha256 = [_]u8{ 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };

/// A certificate valid from `now_unix - 1 h` for `days` (at most 14) for `name` (DNS SAN) and
/// 127.0.0.1 / ::1 (IP SANs).
pub fn generate(key: P256.KeyPair, serial: [16]u8, now_unix: i64, days: u32, name: []const u8) Cert {
    std.debug.assert(days <= 14 and name.len < 64);
    var c: Cert = .{ .key = key };
    var w: Writer = .{ .buf = &c.der };
    const cert = w.begin(0x30);
    const tbs_start = w.len;
    const tbs = w.begin(0x30);
    w.put(&.{ 0xa0, 0x03, 0x02, 0x01, 0x02 }); // v3
    var s = serial;
    s[0] = (s[0] & 0x7f) | 0x01;
    w.put(&.{ 0x02, 16 });
    w.put(&s);
    w.put(&oid_ecdsa_sha256);
    // Name: CN=deepwave
    const name_der = [_]u8{ 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 'z', 'u', 'i' };
    w.put(&name_der);
    var nb: [13]u8 = undefined;
    var na: [13]u8 = undefined;
    utcTime(&nb, now_unix - 3600);
    utcTime(&na, now_unix - 3600 + @as(i64, days) * 86400 - 1);
    w.put(&.{ 0x30, 0x1e, 0x17, 0x0d });
    w.put(&nb);
    w.put(&.{ 0x17, 0x0d });
    w.put(&na);
    w.put(&name_der);
    // SPKI: id-ecPublicKey, prime256v1, uncompressed point
    w.put(&.{ 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00 });
    w.put(&key.public_key.toUncompressedSec1());
    // extensions: subjectAltName
    const e3 = w.begin(0xa3);
    const eseq = w.begin(0x30);
    const san = w.begin(0x30);
    w.put(&.{ 0x06, 0x03, 0x55, 0x1d, 0x11 });
    const oct = w.begin(0x04);
    const names = w.begin(0x30);
    w.put(&.{ 0x82, @intCast(name.len) });
    w.put(name);
    w.put(&.{ 0x87, 4, 127, 0, 0, 1 });
    w.put(&.{ 0x87, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    w.end(names);
    w.end(oct);
    w.end(san);
    w.end(eseq);
    w.end(e3);
    w.end(tbs);
    const sig = key.sign(c.der[tbs_start..w.len], null) catch unreachable;
    var der_buf: [P256.Signature.der_encoded_length_max]u8 = undefined;
    const sder = sig.toDer(&der_buf);
    w.put(&oid_ecdsa_sha256);
    w.put(&.{ 0x03, @intCast(sder.len + 1), 0x00 }); // sder is at most 72 bytes
    w.put(sder);
    w.end(cert);
    c.len = w.len;
    return c;
}

/// What `issue` puts in a certificate.
pub const Issue = struct {
    /// The key the certificate is for, and the key that signs it (the same one: self-signed).
    subject: P256.PublicKey,
    signer: P256.KeyPair,
    subject_cn: []const u8,
    issuer_cn: []const u8,
    serial: [16]u8,
    not_before: i64,
    not_after: i64,
    /// DNS subjectAltName (none when empty).
    dns: []const u8 = "",
    /// basicConstraints CA:TRUE.
    ca: bool = false,
};

fn putName(w: *Writer, cn: []const u8) void {
    const name = w.begin(0x30);
    const set = w.begin(0x31);
    const atv = w.begin(0x30);
    w.put(&.{ 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, @intCast(cn.len) });
    w.put(cn);
    w.end(atv);
    w.end(set);
    w.end(name);
}

/// Test support for `--native-cert` (a local CA and its leaves; the node itself only ever makes
/// `generate`'s self-signed certificate): an X.509v3 ECDSA P-256 certificate into `buf`.
pub fn issue(buf: *[max_len]u8, o: Issue) []const u8 {
    std.debug.assert(o.subject_cn.len < 64 and o.issuer_cn.len < 64 and o.dns.len < 64);
    var w: Writer = .{ .buf = buf };
    const cert = w.begin(0x30);
    const tbs_start = w.len;
    const tbs = w.begin(0x30);
    w.put(&.{ 0xa0, 0x03, 0x02, 0x01, 0x02 }); // v3
    var s = o.serial;
    s[0] = (s[0] & 0x7f) | 0x01;
    w.put(&.{ 0x02, 16 });
    w.put(&s);
    w.put(&oid_ecdsa_sha256);
    putName(&w, o.issuer_cn);
    var nb: [13]u8 = undefined;
    var na: [13]u8 = undefined;
    utcTime(&nb, o.not_before);
    utcTime(&na, o.not_after);
    w.put(&.{ 0x30, 0x1e, 0x17, 0x0d });
    w.put(&nb);
    w.put(&.{ 0x17, 0x0d });
    w.put(&na);
    putName(&w, o.subject_cn);
    w.put(&.{ 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00 });
    w.put(&o.subject.toUncompressedSec1());
    if (o.dns.len > 0 or o.ca) {
        const e3 = w.begin(0xa3);
        const eseq = w.begin(0x30);
        if (o.ca) w.put(&.{ 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff });
        if (o.dns.len > 0) {
            const san = w.begin(0x30);
            w.put(&.{ 0x06, 0x03, 0x55, 0x1d, 0x11 });
            const oct = w.begin(0x04);
            const names = w.begin(0x30);
            w.put(&.{ 0x82, @intCast(o.dns.len) });
            w.put(o.dns);
            w.end(names);
            w.end(oct);
            w.end(san);
        }
        w.end(eseq);
        w.end(e3);
    }
    w.end(tbs);
    const sig = o.signer.sign(buf[tbs_start..w.len], null) catch unreachable;
    var der_buf: [P256.Signature.der_encoded_length_max]u8 = undefined;
    const sder = sig.toDer(&der_buf);
    w.put(&oid_ecdsa_sha256);
    w.put(&.{ 0x03, @intCast(sder.len + 1), 0x00 });
    w.put(sder);
    w.end(cert);
    return buf[0..w.len];
}

fn tlv(d: []const u8, at: usize) struct { hdr: usize, len: usize } {
    const l = d[at + 1];
    if (l < 0x80) return .{ .hdr = 2, .len = l };
    if (l == 0x81) return .{ .hdr = 3, .len = d[at + 2] };
    return .{ .hdr = 4, .len = @as(usize, d[at + 2]) << 8 | d[at + 3] };
}

test "p256 certificate signs and parses as DER" {
    const kp = P256.KeyPair.generateDeterministic(@splat(3)) catch unreachable;
    const c = generate(kp, @splat(9), 1_800_000_000, 13, "localhost");
    const d = c.bytes();
    const outer = tlv(d, 0);
    try std.testing.expectEqual(d.len, outer.hdr + outer.len);
    const t = tlv(d, outer.hdr);
    const tbs = d[outer.hdr..][0 .. t.hdr + t.len];
    const rest = d[outer.hdr + tbs.len ..];
    try std.testing.expectEqualSlices(u8, &oid_ecdsa_sha256, rest[0..oid_ecdsa_sha256.len]);
    const sig_der = rest[oid_ecdsa_sha256.len + 3 ..];
    const sig = try P256.Signature.fromDer(sig_der);
    try sig.verify(tbs, kp.public_key);
}

test "issue: a CA and a leaf it signed verify with std.crypto.Certificate" {
    const ca_key = P256.KeyPair.generateDeterministic(@splat(1)) catch unreachable;
    const leaf_key = P256.KeyPair.generateDeterministic(@splat(2)) catch unreachable;
    var cb: [max_len]u8 = undefined;
    var lb: [max_len]u8 = undefined;
    const now: i64 = 1_800_000_000;
    const ca = issue(&cb, .{ .subject = ca_key.public_key, .signer = ca_key, .subject_cn = "zui test CA", .issuer_cn = "zui test CA", .serial = @splat(3), .not_before = now - 86400, .not_after = now + 86400, .ca = true });
    const leaf = issue(&lb, .{ .subject = leaf_key.public_key, .signer = ca_key, .subject_cn = "node.test", .issuer_cn = "zui test CA", .serial = @splat(4), .not_before = now - 3600, .not_after = now + 3600, .dns = "node.test" });
    const C = std.crypto.Certificate;
    const pca = try (C{ .buffer = ca, .index = 0 }).parse();
    const pleaf = try (C{ .buffer = leaf, .index = 0 }).parse();
    try pleaf.verify(pca, now);
    try pca.verify(pca, now);
    try pleaf.verifyHostName("node.test");
    try std.testing.expectError(error.CertificateHostMismatch, pleaf.verifyHostName("other.test"));
    try std.testing.expectError(error.CertificateExpired, pleaf.verify(pca, now + 7200));
    try std.testing.expectEqualSlices(u8, &leaf_key.public_key.toUncompressedSec1(), pleaf.pubKey());
    // not signed by itself
    try std.testing.expectError(error.CertificateIssuerMismatch, pleaf.verify(pleaf, now));
}
