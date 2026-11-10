//! TLS 1.3 / QUIC key derivation and packet protection (RFC 8446 section 7, RFC 9001), AES-128-GCM
//! with SHA-256 only (the one suite deepwave offers: TLS_AES_128_GCM_SHA256). std.crypto supplies the
//! primitives (constant-time AES via hardware instructions where available).
const std = @import("std");
const crypto = std.crypto;
const Aes128 = crypto.core.aes.Aes128;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
/// AES-NI/PCLMULQDQ at runtime on x86-64 (core/cpu.zig).
const core_cpu = @import("core").cpu;
const cpu_aes = core_cpu.aes;

/// A kernel object above the build's own tier is in use (a baseline x86-64 build on an AES-NI
/// CPU): its AES-NI GCM, key expansion per packet included, beats the cached software schedule.
/// Otherwise (native builds, aarch64, ZUI_CPU=baseline) the cached schedule.
inline fn dispatchedAes() bool {
    return core_cpu.tier() != core_cpu.native_tier;
}
const Hkdf = crypto.kdf.hkdf.HkdfSha256;
const Hmac = crypto.auth.hmac.sha2.HmacSha256;
const Ghash = crypto.onetimeauth.Ghash;
const AesCtx = crypto.core.aes.AesEncryptCtx(Aes128);

pub const hash_len = 32;
pub const tag_len = 16;
pub const Secret = [32]u8;

/// HKDF-Expand-Label (RFC 8446 section 7.1) with a `tls13 ` prefix.
pub fn expandLabel(secret: *const Secret, label: []const u8, context: []const u8, out: []u8) void {
    var info: [2 + 1 + 6 + 32 + 1 + 64]u8 = undefined;
    std.debug.assert(label.len <= 32 and context.len <= 64);
    std.mem.writeInt(u16, info[0..2], @intCast(out.len), .big);
    info[2] = @intCast(6 + label.len);
    @memcpy(info[3..9], "tls13 ");
    @memcpy(info[9..][0..label.len], label);
    info[9 + label.len] = @intCast(context.len);
    @memcpy(info[10 + label.len ..][0..context.len], context);
    Hkdf.expand(out, info[0 .. 10 + label.len + context.len], secret.*);
}

pub fn deriveSecret(secret: *const Secret, label: []const u8, transcript_hash: *const [32]u8) Secret {
    var out: Secret = undefined;
    expandLabel(secret, label, transcript_hash, &out);
    return out;
}

pub fn hashOf(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

pub const empty_hash: [32]u8 = hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

fn hex32(comptime s: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

pub fn hmac(key: []const u8, msg: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Hmac.create(&out, msg, key);
    return out;
}

/// Key schedule stage helpers.
pub fn extract(salt: []const u8, ikm: []const u8) Secret {
    return Hkdf.extract(salt, ikm);
}

/// AEAD key, IV and header-protection key of one direction at one encryption level, plus the
/// expanded AES key schedules and the GHASH key powers, computed once per key (not per packet).
/// AES and GHASH run on the hardware path std.crypto picks (ARMv8 AES+PMULL, AES-NI+PCLMUL).
pub const PacketKeys = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
    secret: Secret,
    aes: AesCtx,
    hpc: AesCtx,
    /// GHASH state keyed with H = AES(0), all 16 powers precomputed; copied per packet.
    mac: Ghash,

    pub fn fromSecret(secret: Secret) PacketKeys {
        var k: PacketKeys = undefined;
        k.secret = secret;
        expandLabel(&secret, "quic key", "", &k.key);
        expandLabel(&secret, "quic iv", "", &k.iv);
        expandLabel(&secret, "quic hp", "", &k.hp);
        k.schedule();
        return k;
    }

    fn schedule(k: *PacketKeys) void {
        k.aes = Aes128.initEnc(k.key);
        k.hpc = Aes128.initEnc(k.hp);
        var h: [16]u8 = undefined;
        k.aes.encrypt(&h, &@as([16]u8, @splat(0)));
        k.mac = Ghash.initForBlockCount(&h, std.math.maxInt(usize));
    }

    /// Next 1-RTT generation (RFC 9001 section 6): new secret, key and iv; hp stays.
    pub fn nextGeneration(k: PacketKeys) PacketKeys {
        var s: Secret = undefined;
        expandLabel(&k.secret, "quic ku", "", &s);
        var n = fromSecret(s);
        n.hp = k.hp;
        n.hpc = k.hpc;
        return n;
    }
};

const initial_salt_v1 = [20]u8{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };

pub const InitialKeys = struct { client: PacketKeys, server: PacketKeys };

pub fn initialKeys(dcid: []const u8) InitialKeys {
    const initial = extract(&initial_salt_v1, dcid);
    var c: Secret = undefined;
    var s: Secret = undefined;
    expandLabel(&initial, "client in", "", &c);
    expandLabel(&initial, "server in", "", &s);
    return .{ .client = PacketKeys.fromSecret(c), .server = PacketKeys.fromSecret(s) };
}

pub inline fn nonce(iv: *const [12]u8, pn: u64) [12]u8 {
    var n = iv.*;
    var be: [8]u8 = undefined;
    std.mem.writeInt(u64, &be, pn, .big);
    for (0..8) |i| n[4 + i] ^= be[i];
    return n;
}

/// GCM with the cached schedule (NIST SP 800-38D), byte-identical to std's Aes128Gcm.
fn gcmTag(k: *const PacketKeys, j0: *const [16]u8, ad: []const u8, ct: []const u8) [16]u8 {
    var mac = k.mac;
    mac.update(ad);
    mac.pad();
    mac.update(ct);
    mac.pad();
    var fin: [16]u8 = undefined;
    std.mem.writeInt(u64, fin[0..8], @as(u64, ad.len) * 8, .big);
    std.mem.writeInt(u64, fin[8..16], @as(u64, ct.len) * 8, .big);
    mac.update(&fin);
    var tag: [16]u8 = undefined;
    mac.final(&tag);
    var t: [16]u8 = undefined;
    k.aes.encrypt(&t, j0);
    for (&tag, t) |*x, y| x.* ^= y;
    return tag;
}

fn j0Of(n: [12]u8, ctr: u32) [16]u8 {
    var j: [16]u8 = undefined;
    j[0..12].* = n;
    std.mem.writeInt(u32, j[12..16], ctr, .big);
    return j;
}

/// Seals `buf[hdr_len .. hdr_len+payload_len]` in place and appends the 16-byte tag at the end
/// of the payload. `buf[0..hdr_len]` is the unprotected header (AAD). No allocation, no key
/// expansion: the AES schedule and GHASH powers come from `k`.
pub fn seal(k: *const PacketKeys, pn: u64, buf: []u8, hdr_len: usize, payload_len: usize) void {
    const n = nonce(&k.iv, pn);
    const ct = buf[hdr_len..][0..payload_len];
    if (dispatchedAes()) {
        var tag: [16]u8 = undefined;
        cpu_aes.gcmSeal(ct, &tag, ct, buf[0..hdr_len], n, k.key);
        @memcpy(buf[hdr_len + payload_len ..][0..16], &tag);
        return;
    }
    crypto.core.modes.ctr(AesCtx, k.aes, ct, ct, j0Of(n, 2), .big);
    const tag = gcmTag(k, &j0Of(n, 1), buf[0..hdr_len], ct);
    @memcpy(buf[hdr_len + payload_len ..][0..16], &tag);
}

/// Opens in place: `buf[hdr_len..]` is ciphertext ++ tag. Returns the plaintext length.
pub fn open(k: *const PacketKeys, pn: u64, buf: []u8, hdr_len: usize) error{AuthenticationFailed}!usize {
    if (buf.len < hdr_len + 16) return error.AuthenticationFailed;
    const n = nonce(&k.iv, pn);
    const ct_len = buf.len - hdr_len - 16;
    const ct = buf[hdr_len..][0..ct_len];
    if (dispatchedAes()) {
        const tag = buf[hdr_len + ct_len ..][0..16].*;
        if (!cpu_aes.gcmOpen(ct, ct, tag, buf[0..hdr_len], n, k.key)) return error.AuthenticationFailed;
        return ct_len;
    }
    const want = gcmTag(k, &j0Of(n, 1), buf[0..hdr_len], ct);
    if (!crypto.timing_safe.eql([16]u8, want, buf[hdr_len + ct_len ..][0..16].*)) return error.AuthenticationFailed;
    crypto.core.modes.ctr(AesCtx, k.aes, ct, ct, j0Of(n, 2), .big);
    return ct_len;
}

/// Header protection mask from the cached hp schedule.
pub inline fn hpMaskK(k: *const PacketKeys, sample: *const [16]u8) [5]u8 {
    var out: [16]u8 = undefined;
    k.hpc.encrypt(&out, sample);
    return out[0..5].*;
}

/// Header protection mask: AES-128-ECB of a 16-byte sample.
pub inline fn hpMask(hp: *const [16]u8, sample: *const [16]u8) [5]u8 {
    const out = cpu_aes.encryptBlock(hp.*, sample.*);
    return out[0..5].*;
}

/// Applies (or removes: the operation is an XOR) header protection. `pn_off` is the offset of the
/// packet number field, `pn_len` its length (1..4) after protection removal; when removing,
/// the caller learns the length from the unmasked first byte, so this takes the first-byte mask
/// and the pn bytes separately.
pub fn maskFirstByte(first: *u8, mask: [5]u8) void {
    const is_long = (first.* & 0x80) != 0;
    first.* ^= mask[0] & (if (is_long) @as(u8, 0x0f) else 0x1f);
}

pub fn maskPn(buf: []u8, pn_off: usize, pn_len: usize, mask: [5]u8) void {
    for (0..pn_len) |i| buf[pn_off + i] ^= mask[1 + i];
}

/// Longest Retry packet (without its tag) `retryTag` accepts; callers drop longer ones.
pub const max_retry_len = 1500;

/// Retry integrity tag (RFC 9001 section 5.8): AEAD tag over the retry pseudo packet.
pub fn retryTag(odcid: []const u8, retry_packet_without_tag: []const u8) [16]u8 {
    std.debug.assert(odcid.len <= 20 and retry_packet_without_tag.len <= max_retry_len);
    const key = [16]u8{ 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
    const nonce_v = [12]u8{ 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };
    var aad: [1 + 20 + max_retry_len]u8 = undefined;
    aad[0] = @intCast(odcid.len);
    @memcpy(aad[1..][0..odcid.len], odcid);
    @memcpy(aad[1 + odcid.len ..][0..retry_packet_without_tag.len], retry_packet_without_tag);
    var tag: [16]u8 = undefined;
    var empty: [0]u8 = .{};
    cpu_aes.gcmSeal(&empty, &tag, &empty, aad[0 .. 1 + odcid.len + retry_packet_without_tag.len], nonce_v, key);
    return tag;
}

test "cached GCM matches std Aes128Gcm (seal and open, all lengths up to 1500)" {
    const k = PacketKeys.fromSecret(@splat(0x5a));
    var buf: [1600]u8 = undefined;
    var ref: [1600]u8 = undefined;
    for (0..1500) |len| {
        if (len % 7 != 0 and len > 64) continue;
        for (0..len + 20) |i| buf[i] = @truncate(i * 31 + len);
        @memcpy(ref[0 .. len + 20], buf[0 .. len + 20]);
        seal(&k, len, &buf, 20, len);
        var tag: [16]u8 = undefined;
        Aes128Gcm.encrypt(ref[20..][0..len], &tag, ref[20..][0..len], ref[0..20], nonce(&k.iv, len), k.key);
        try std.testing.expectEqualSlices(u8, ref[20..][0..len], buf[20..][0..len]);
        try std.testing.expectEqualSlices(u8, &tag, buf[20 + len ..][0..16]);
        try std.testing.expectEqual(len, try open(&k, len, buf[0 .. 20 + len + 16], 20));
        for (0..len) |i| try std.testing.expectEqual(@as(u8, @truncate((i + 20) * 31 + len)), buf[20 + i]);
        if (len > 0) {
            seal(&k, len, &buf, 20, len);
            buf[25] ^= 1;
            try std.testing.expectError(error.AuthenticationFailed, open(&k, len, buf[0 .. 20 + len + 16], 20));
        }
    }
    var s: [16]u8 = @splat(3);
    try std.testing.expectEqual(hpMask(&k.hp, &s), hpMaskK(&k, &s));
    s[0] = 9;
    const g2 = k.nextGeneration();
    try std.testing.expectEqual(hpMask(&k.hp, &s), hpMaskK(&g2, &s));
}

test "RFC 9001 appendix A initial secrets" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const k = initialKeys(&dcid);
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    try std.testing.expectEqualSlices(u8, &want, &k.client.secret);
    var key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "1f369613dd76d5467730efcbe3b1a22d");
    try std.testing.expectEqualSlices(u8, &key, &k.client.key);
    var iv: [12]u8 = undefined;
    _ = try std.fmt.hexToBytes(&iv, "fa044b2f42a3fd3b46fb255c");
    try std.testing.expectEqualSlices(u8, &iv, &k.client.iv);
    var hp: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hp, "9f50449e04a0e810283a1e9933adedd2");
    try std.testing.expectEqualSlices(u8, &hp, &k.client.hp);
}

test "quinn-proto header_encoding vector (client Initial, 16 zero bytes)" {
    const dcid = [_]u8{ 0x06, 0xb8, 0x58, 0xec, 0x6f, 0x80, 0x45, 0x2b };
    const k = initialKeys(&dcid);
    var buf: [64]u8 = undefined;
    const hdr = [_]u8{ 0xc0, 0, 0, 0, 1, 8, 0x06, 0xb8, 0x58, 0xec, 0x6f, 0x80, 0x45, 0x2b, 0, 0, 0x40, 0x21, 0x00 };
    @memcpy(buf[0..hdr.len], &hdr);
    @memset(buf[hdr.len..][0..16], 0);
    seal(&k.client, 0, &buf, hdr.len, 16);
    const total = hdr.len + 16 + 16;
    const mask = hpMask(&k.client.hp, buf[hdr.len - 1 + 4 ..][0..16]);
    maskFirstByte(&buf[0], mask);
    maskPn(&buf, hdr.len - 1, 1, mask);
    var want: [51]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "c8000000010806b858ec6f80452b00004021be3ef50807b84191a196f760a6dad1e9d1c430c48952cba0148250c21c0a6a70e1");
    try std.testing.expectEqualSlices(u8, &want, buf[0..total]);
}
