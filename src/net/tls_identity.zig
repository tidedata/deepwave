//! A TLS server identity loaded from PEM files: sui-node's `rpc.tls` (`cert`: a PEM certificate
//! chain, `key`: a PEM private key; sui-node lib.rs `https_rustls_config`, rustls with ring). The
//! chain is sent as is (leaf first, as the file lists it); CertificateVerify is signed with the
//! key in the scheme TLS 1.3 assigns to it:
//! - ECDSA P-256 -> ecdsa_secp256r1_sha256 (0x0403), P-384 -> ecdsa_secp384r1_sha384 (0x0503);
//! - Ed25519 -> ed25519 (0x0807);
//! - RSA (2048..4096 bits) -> rsa_pss_rsae_sha256 (0x0804), salt length 32 (RFC 8446 4.2.3).
//! Key files: PKCS#8 `PRIVATE KEY` (EC, Ed25519, RSA), SEC1 `EC PRIVATE KEY`, PKCS#1
//! `RSA PRIVATE KEY`, as rustls' `PrivateKeyDer::from_pem_file` reads them. Encrypted keys are
//! refused (rustls refuses them too).
const std = @import("std");
const Allocator = std.mem.Allocator;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Scheme = enum(u16) {
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ed25519 = 0x0807,
    rsa_pss_rsae_sha256 = 0x0804,
};

const rsa_max_bits = 4096;
const Modulus = std.crypto.ff.Modulus(rsa_max_bits);

pub const Rsa = struct {
    n: Modulus,
    /// Modulus length in bytes (the signature length).
    k: usize,
    /// Private and public exponents, big-endian, as the key file encodes them.
    d: []const u8,
    e: []const u8,
};

pub const Key = union(enum) {
    p256: EcdsaP256.KeyPair,
    p384: EcdsaP384.KeyPair,
    ed25519: Ed25519.KeyPair,
    rsa: Rsa,

    pub fn scheme(k: *const Key) Scheme {
        return switch (k.*) {
            .p256 => .ecdsa_secp256r1_sha256,
            .p384 => .ecdsa_secp384r1_sha384,
            .ed25519 => .ed25519,
            .rsa => .rsa_pss_rsae_sha256,
        };
    }
};

/// What a TLS server presents: the DER certificates (leaf first) and the leaf's private key.
pub const Identity = struct {
    certs: []const []const u8,
    key: Key,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(id: *Identity) void {
        id.arena.deinit();
    }

    /// The CertificateVerify signature over `msg` (the 130-byte TLS 1.3 content) into `out`.
    /// `random`: 32 bytes of fresh randomness (the RSA-PSS salt; ignored otherwise).
    pub fn sign(id: *const Identity, msg: []const u8, random: [32]u8, out: []u8) ![]const u8 {
        switch (id.key) {
            .p256 => |kp| {
                const sig = try kp.sign(msg, null);
                var b: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
                const der = sig.toDer(&b);
                @memcpy(out[0..der.len], der);
                return out[0..der.len];
            },
            .p384 => |kp| {
                const sig = try kp.sign(msg, null);
                var b: [EcdsaP384.Signature.der_encoded_length_max]u8 = undefined;
                const der = sig.toDer(&b);
                @memcpy(out[0..der.len], der);
                return out[0..der.len];
            },
            .ed25519 => |kp| {
                const sig = try kp.sign(msg, null);
                out[0..64].* = sig.toBytes();
                return out[0..64];
            },
            .rsa => |*r| return rsaPssSign(r, msg, random, out),
        }
    }
};

/// Longest CertificateVerify signature `sign` writes (RSA-4096).
pub const max_signature_len = rsa_max_bits / 8;

pub const LoadError = error{
    NoCertificate,
    BadPem,
    NoPrivateKey,
    EncryptedKey,
    UnsupportedKey,
    BadKey,
    RsaKeyTooSmall,
    RsaKeyTooLarge,
} || Allocator.Error;

/// Loads `cert_pem` (one or more CERTIFICATE blocks) and `key_pem` (the first private key block).
pub fn load(gpa: Allocator, cert_pem: []const u8, key_pem: []const u8) LoadError!Identity {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    var certs: std.ArrayList([]const u8) = .empty;
    var it: PemIter = .{ .text = cert_pem };
    while (try it.next(a)) |blk| {
        if (std.mem.eql(u8, blk.label, "CERTIFICATE")) try certs.append(a, blk.der);
    }
    if (certs.items.len == 0) return error.NoCertificate;
    const key = try loadKey(a, key_pem);
    return .{ .certs = certs.items, .key = key, .arena = arena };
}

fn loadKey(a: Allocator, key_pem: []const u8) LoadError!Key {
    var it: PemIter = .{ .text = key_pem };
    while (try it.next(a)) |blk| {
        if (std.mem.eql(u8, blk.label, "PRIVATE KEY")) return pkcs8(a, blk.der);
        if (std.mem.eql(u8, blk.label, "EC PRIVATE KEY")) return sec1(blk.der, null);
        if (std.mem.eql(u8, blk.label, "RSA PRIVATE KEY")) return pkcs1(a, blk.der);
        if (std.mem.eql(u8, blk.label, "ENCRYPTED PRIVATE KEY")) return error.EncryptedKey;
    }
    return error.NoPrivateKey;
}

// ------------------------------------------------------------------ PEM

const Block = struct { label: []const u8, der: []const u8 };

const PemIter = struct {
    text: []const u8,
    pos: usize = 0,

    fn next(p: *PemIter, a: Allocator) LoadError!?Block {
        const begin = "-----BEGIN ";
        const start = std.mem.indexOfPos(u8, p.text, p.pos, begin) orelse return null;
        const label_start = start + begin.len;
        const label_end = std.mem.indexOfPos(u8, p.text, label_start, "-----") orelse return error.BadPem;
        const label = p.text[label_start..label_end];
        const body_start = label_end + 5;
        const end_marker = try std.fmt.allocPrint(a, "-----END {s}-----", .{label});
        const body_end = std.mem.indexOfPos(u8, p.text, body_start, end_marker) orelse return error.BadPem;
        p.pos = body_end + end_marker.len;
        const body = p.text[body_start..body_end];
        // strip whitespace, then base64
        var clean = try a.alloc(u8, body.len);
        var n: usize = 0;
        for (body) |c| {
            if (c == ' ' or c == '\t' or c == '\r' or c == '\n') continue;
            clean[n] = c;
            n += 1;
        }
        const dec = std.base64.standard.Decoder;
        const len = dec.calcSizeForSlice(clean[0..n]) catch return error.BadPem;
        const der = try a.alloc(u8, len);
        dec.decode(der, clean[0..n]) catch return error.BadPem;
        return .{ .label = label, .der = der };
    }
};

// ------------------------------------------------------------------ DER (bounds-checked)

const Der = struct {
    b: []const u8,
    i: usize = 0,

    const Tlv = struct { tag: u8, v: []const u8 };

    fn done(d: *const Der) bool {
        return d.i >= d.b.len;
    }

    fn any(d: *Der) LoadError!Tlv {
        if (d.b.len - d.i < 2) return error.BadKey;
        const tag = d.b[d.i];
        var len: usize = d.b[d.i + 1];
        d.i += 2;
        if (len & 0x80 != 0) {
            const nb = len & 0x7f;
            if (nb == 0 or nb > 4 or d.b.len - d.i < nb) return error.BadKey;
            len = 0;
            for (d.b[d.i..][0..nb]) |x| len = (len << 8) | x;
            d.i += nb;
        }
        if (d.b.len - d.i < len) return error.BadKey;
        const v = d.b[d.i..][0..len];
        d.i += len;
        return .{ .tag = tag, .v = v };
    }

    fn want(d: *Der, tag: u8) LoadError![]const u8 {
        const t = try d.any();
        if (t.tag != tag) return error.BadKey;
        return t.v;
    }

    /// An unsigned INTEGER's magnitude (leading zero bytes dropped).
    fn uint(d: *Der) LoadError![]const u8 {
        var v = try d.want(0x02);
        while (v.len > 1 and v[0] == 0) v = v[1..];
        return v;
    }
};

const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_p256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_p384 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };
const oid_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

const Curve = enum { p256, p384 };

fn curveOf(oid: []const u8) ?Curve {
    if (std.mem.eql(u8, oid, &oid_p256)) return .p256;
    if (std.mem.eql(u8, oid, &oid_p384)) return .p384;
    return null;
}

/// PKCS#8 PrivateKeyInfo: SEQ { INTEGER version, SEQ { OID alg, params }, OCTET STRING key, ... }.
fn pkcs8(a: Allocator, der: []const u8) LoadError!Key {
    var outer: Der = .{ .b = der };
    var d: Der = .{ .b = try outer.want(0x30) };
    _ = try d.uint();
    var alg: Der = .{ .b = try d.want(0x30) };
    const oid = try alg.want(0x06);
    const key = try d.want(0x04);
    if (std.mem.eql(u8, oid, &oid_ec_public_key)) {
        const curve = curveOf(try alg.want(0x06)) orelse return error.UnsupportedKey;
        return sec1(key, curve);
    }
    if (std.mem.eql(u8, oid, &oid_ed25519)) {
        var k: Der = .{ .b = key };
        const seed = try k.want(0x04);
        if (seed.len != 32) return error.BadKey;
        return .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(seed[0..32].*) catch return error.BadKey };
    }
    if (std.mem.eql(u8, oid, &oid_rsa)) return pkcs1(a, key);
    return error.UnsupportedKey;
}

/// SEC1 ECPrivateKey: SEQ { INTEGER 1, OCTET STRING d, [0] OID curve OPTIONAL, [1] pub OPTIONAL }.
fn sec1(der: []const u8, from_pkcs8: ?Curve) LoadError!Key {
    var outer: Der = .{ .b = der };
    var d: Der = .{ .b = try outer.want(0x30) };
    _ = try d.uint();
    const priv = try d.want(0x04);
    var curve = from_pkcs8;
    while (!d.done()) {
        const t = try d.any();
        if (t.tag == 0xa0) {
            var p: Der = .{ .b = t.v };
            curve = curveOf(try p.want(0x06)) orelse return error.UnsupportedKey;
        }
    }
    switch (curve orelse return error.UnsupportedKey) {
        .p256 => {
            var b: [32]u8 = @splat(0);
            if (priv.len > 32) return error.BadKey;
            @memcpy(b[32 - priv.len ..], priv);
            const sk = EcdsaP256.SecretKey.fromBytes(b) catch return error.BadKey;
            return .{ .p256 = EcdsaP256.KeyPair.fromSecretKey(sk) catch return error.BadKey };
        },
        .p384 => {
            var b: [48]u8 = @splat(0);
            if (priv.len > 48) return error.BadKey;
            @memcpy(b[48 - priv.len ..], priv);
            const sk = EcdsaP384.SecretKey.fromBytes(b) catch return error.BadKey;
            return .{ .p384 = EcdsaP384.KeyPair.fromSecretKey(sk) catch return error.BadKey };
        },
    }
}

/// PKCS#1 RSAPrivateKey: SEQ { version, n, e, d, p, q, dp, dq, qinv }. rustls/ring take
/// 2048..8192-bit moduli; deepwave signs up to 4096 bits (std.crypto.ff's bound here).
fn pkcs1(a: Allocator, der: []const u8) LoadError!Key {
    var outer: Der = .{ .b = der };
    var d: Der = .{ .b = try outer.want(0x30) };
    _ = try d.uint();
    const n = try d.uint();
    const e = try d.uint();
    const priv = try d.uint();
    if (n.len * 8 < 2048 - 7) return error.RsaKeyTooSmall;
    if (n.len > rsa_max_bits / 8) return error.RsaKeyTooLarge;
    const m = Modulus.fromBytes(n, .big) catch return error.BadKey;
    if (m.bits() < 2048) return error.RsaKeyTooSmall;
    return .{ .rsa = .{ .n = m, .k = n.len, .d = try a.dupe(u8, priv), .e = try a.dupe(u8, e) } };
}

// ------------------------------------------------------------------ RSASSA-PSS (RFC 8017 8.1.1)

fn mgf1Xor(out: []u8, seed: []const u8) void {
    var counter: u32 = 0;
    var off: usize = 0;
    while (off < out.len) : (counter += 1) {
        var h = Sha256.init(.{});
        h.update(seed);
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, counter, .big);
        h.update(&c);
        var block: [32]u8 = undefined;
        h.final(&block);
        const n = @min(32, out.len - off);
        for (out[off..][0..n], block[0..n]) |*o, b| o.* ^= b;
        off += n;
    }
}

fn rsaPssSign(r: *const Rsa, msg: []const u8, salt: [32]u8, out: []u8) ![]const u8 {
    const mod_bits = r.n.bits();
    const em_bits = mod_bits - 1;
    const em_len = (em_bits + 7) / 8;
    const h_len = 32;
    if (em_len < h_len + salt.len + 2 or out.len < r.k) return error.BadKey;
    var mhash: [32]u8 = undefined;
    Sha256.hash(msg, &mhash, .{});
    var hh: [32]u8 = undefined;
    {
        var h = Sha256.init(.{});
        h.update(&@as([8]u8, @splat(0)));
        h.update(&mhash);
        h.update(&salt);
        h.final(&hh);
    }
    // EM = maskedDB || H || 0xbc, placed right-aligned in a k-byte buffer
    var em_buf: [rsa_max_bits / 8]u8 = @splat(0);
    const em = em_buf[r.k - em_len .. r.k];
    const db_len = em_len - h_len - 1;
    const db = em[0..db_len];
    @memset(db, 0);
    db[db_len - salt.len - 1] = 0x01;
    @memcpy(db[db_len - salt.len ..], &salt);
    mgf1Xor(db, &hh);
    db[0] &= @as(u8, 0xff) >> @intCast(8 * em_len - em_bits);
    @memcpy(em[db_len..][0..h_len], &hh);
    em[em_len - 1] = 0xbc;
    const m = Modulus.Fe.fromBytes(r.n, em_buf[0..r.k], .big) catch return error.BadKey;
    const s = r.n.powWithEncodedExponent(m, r.d, .big) catch return error.BadKey;
    // check the signature before it leaves (a fault would leak the key)
    const back = r.n.powWithEncodedPublicExponent(s, r.e, .big) catch return error.BadKey;
    if (!back.eql(m)) return error.BadKey;
    s.toBytes(out[0..r.k], .big) catch return error.BadKey;
    return out[0..r.k];
}

// ------------------------------------------------------------------ tests

test "tls_identity: the rpc-surface capture's cert and PKCS#8 P-256 key" {
    const gpa = std.testing.allocator;
    var id = try load(gpa, @embedFile("testdata/tls-cert.pem"), @embedFile("testdata/tls-key.pem"));
    defer id.deinit();
    try std.testing.expectEqual(@as(usize, 1), id.certs.len);
    try std.testing.expect(id.key == .p256);
    // the key matches the certificate's public key
    const parsed = try (std.crypto.Certificate{ .buffer = id.certs[0], .index = 0 }).parse();
    const pk = parsed.pubKey();
    try std.testing.expectEqualSlices(u8, &id.key.p256.public_key.toUncompressedSec1(), pk);
    var out: [max_signature_len]u8 = undefined;
    const msg = "TLS 1.3, server CertificateVerify";
    const sig = try id.sign(msg, @splat(1), &out);
    const s = try EcdsaP256.Signature.fromDer(sig);
    try s.verify(msg, id.key.p256.public_key);
}

test "tls_identity: SEC1, Ed25519 PKCS#8, chains and refusals" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    // SEC1 P-384 (openssl ecparam -name secp384r1 -genkey -noout); its public point from openssl ec -pubout
    const k384 = try loadKey(arena.allocator(), @embedFile("testdata/tls-ec384.pem"));
    try std.testing.expect(k384 == .p384);
    var want384: [97]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want384, "04820963144013142107c7512da07d4a358fce3a91d7a48191e019766be5e412653c78b99460c025ece5c7c08e912fe1033b8161e40ed7c205dbfed13cad2a0cd8a538d9c1da058b9b0a543511d215b40a89d873da2ddec7e980f602273a32d4c7");
    try std.testing.expectEqualSlices(u8, &want384, &k384.p384.public_key.toUncompressedSec1());
    // Ed25519 (RFC 8410 section 10.3 example)
    const ed =
        \\-----BEGIN PRIVATE KEY-----
        \\MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
        \\-----END PRIVATE KEY-----
    ;
    const k = try loadKey(arena.allocator(), ed);
    try std.testing.expect(k == .ed25519);
    // RFC 8410 10.3: the matching public key
    var want_pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_pk, "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
    try std.testing.expectEqualSlices(u8, &want_pk, &k.ed25519.public_key.toBytes());
    try std.testing.expectError(error.EncryptedKey, loadKey(arena.allocator(), "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"));
    try std.testing.expectError(error.NoPrivateKey, loadKey(arena.allocator(), "nothing here"));
    try std.testing.expectError(error.NoCertificate, load(gpa, "", ed));
    try std.testing.expectError(error.BadPem, load(gpa, "-----BEGIN CERTIFICATE-----\nAAAA\n", ed));
    // two certificates: both kept, in order
    const one = @embedFile("testdata/tls-cert.pem");
    const two = try std.mem.concat(gpa, u8, &.{ one, one });
    defer gpa.free(two);
    var id = try load(gpa, two, ed);
    defer id.deinit();
    try std.testing.expectEqual(@as(usize, 2), id.certs.len);
}

test "tls_identity: RSA-PSS signatures verify with std's RSASSA-PSS" {
    // A 2048-bit key generated for this test (openssl genrsa 2048 | openssl rsa -traditional).
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const k = try loadKey(arena.allocator(), @embedFile("testdata/tls-rsa2048.pem"));
    try std.testing.expect(k == .rsa);
    // the same key as PKCS#8
    const k8 = try loadKey(arena.allocator(), @embedFile("testdata/tls-rsa2048-pkcs8.pem"));
    try std.testing.expectEqualSlices(u8, k.rsa.d, k8.rsa.d);
    var out: [max_signature_len]u8 = undefined;
    const id: Identity = .{ .certs = &.{}, .key = k, .arena = undefined };
    const msg = "TLS 1.3, server CertificateVerify\x00 transcript";
    const sig = try id.sign(msg, @splat(7), &out);
    try std.testing.expectEqual(@as(usize, 256), sig.len);
    var n_bytes: [256]u8 = undefined;
    try k.rsa.n.toBytes(&n_bytes, .big);
    const rsa = std.crypto.Certificate.rsa;
    const pk = try rsa.PublicKey.fromBytes(k.rsa.e, &n_bytes);
    try rsa.PSSSignature.verify(256, sig[0..256], msg, pk, Sha256);
    try std.testing.expectError(error.InvalidSignature, rsa.PSSSignature.verify(256, sig[0..256], "other", pk, Sha256));
}

/// Test keys and certificates (never for production): the rpc-surface capture's P-256 pair and a
/// self-signed RSA-2048 pair, for other modules' tests.
pub const testdata = struct {
    pub const p256_cert = @embedFile("testdata/tls-cert.pem");
    pub const p256_key = @embedFile("testdata/tls-key.pem");
    pub const rsa_cert = @embedFile("testdata/tls-rsa-cert.pem");
    pub const rsa_key = @embedFile("testdata/tls-rsa2048.pem");
};
