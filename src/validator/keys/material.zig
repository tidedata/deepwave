//! Key material of one validator: the BLS12-381 authority (protocol) key, the Ed25519 worker key
//! (the consensus protocol key that signs blocks), the Ed25519 network key (TLS identity) and the
//! Ed25519 account key (rewards address), in sui's file formats:
//!   authority key file   base64(32-byte BLS secret, big endian)  (sui-keys write_authority_keypair_to_file)
//!   other key files      base64(flag || 32-byte secret)         (flag 0 = Ed25519), or bech32 `suiprivkey1...`
//! The same base64 texts are the in-place `value:` of validator.yaml key pairs (KeyPairWithPath,
//! AuthorityKeyPairWithPath). Readers trim surrounding whitespace, as read_*_from_file does.
//! Pinned against sui-keys/sui-types 1.83.1 output in testdata/keys.jsonl (vectors from
//! tools/truth/validator-keys).
//! Generated keys (local test committees) derive from one seed and never touch a file.
const std = @import("std");
const bls = @import("bls");
const hash = @import("hash");
const Ed25519 = std.crypto.sign.Ed25519;

pub const Error = error{ BadKey, Io, OutOfMemory };

pub const flag_ed25519: u8 = 0;
pub const flag_secp256k1: u8 = 1;
pub const flag_secp256r1: u8 = 2;
pub const flag_mldsa65: u8 = 7;

pub const KeySet = struct {
    authority: bls.SecretKey,
    authority_pk: [96]u8,
    /// Consensus protocol key (validator.yaml `worker-key-pair`).
    worker: Ed25519.KeyPair,
    network: Ed25519.KeyPair,
    /// The rewards address key. sui-node never reads it on a validator (KeyPairWithPath loads
    /// lazily and nothing asks), so a key set loaded from validator.yaml leaves it null.
    account: ?Ed25519.KeyPair,

    pub fn wipe(k: *KeySet) void {
        std.crypto.secureZero(u8, std.mem.asBytes(k));
    }
};

pub const Role = enum { authority, worker, network, account };

fn h256(parts: []const []const u8) [32]u8 {
    var h = hash.Blake2b256.init();
    for (parts) |x| h.update(x);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn derive32(seed: *const [32]u8, index: u32, role: Role) [32]u8 {
    var idx: [4]u8 = undefined;
    std.mem.writeInt(u32, &idx, index, .little);
    return h256(&.{ "zui-localnet-key-v1", seed, &idx, @tagName(role) });
}

/// The key set of authority `index` of the committee generated from `seed`.
pub fn generate(seed: *const [32]u8, index: u32) KeySet {
    var ctr: u32 = 0;
    const sk = while (true) : (ctr += 1) {
        var raw = derive32(seed, index, .authority);
        if (ctr != 0) raw = h256(&.{ &raw, std.mem.asBytes(&ctr) });
        // clear the top bits so the scalar is below r with overwhelming probability, then check
        raw[0] &= 0x3f;
        if (bls.SecretKey.fromBytes(&raw)) |s| break s;
    };
    return .{
        .authority = sk,
        .authority_pk = sk.publicKey().toBytes(),
        .worker = Ed25519.KeyPair.generateDeterministic(derive32(seed, index, .worker)) catch unreachable,
        .network = Ed25519.KeyPair.generateDeterministic(derive32(seed, index, .network)) catch unreachable,
        .account = Ed25519.KeyPair.generateDeterministic(derive32(seed, index, .account)) catch unreachable,
    };
}

/// Whether `text` is a key sui-types `SuiKeyPair::decode_base64` (or the bech32 `suiprivkey`
/// form) accepts: 33 bytes `flag || 32-byte secret` with flag Ed25519, Secp256k1, Secp256r1 or
/// ML-DSA-65 (seed form), ECDSA secrets in 1..n-1. Returns the flag. For the account key, which
/// may be any of those schemes and which a validator never uses.
pub fn checkSuiKeyText(text: []const u8) Error!u8 {
    const t = std.mem.trim(u8, text, " \t\r\n");
    var raw: [33]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw);
    try rawSuiKey(t, &raw);
    switch (raw[0]) {
        flag_ed25519, flag_mldsa65 => {},
        flag_secp256k1 => _ = std.crypto.ecc.Secp256k1.scalar.Scalar.fromBytes(raw[1..33].*, .big) catch return error.BadKey,
        flag_secp256r1 => _ = std.crypto.ecc.P256.scalar.Scalar.fromBytes(raw[1..33].*, .big) catch return error.BadKey,
        else => return error.BadKey,
    }
    if (raw[0] == flag_secp256k1 or raw[0] == flag_secp256r1) {
        if (std.mem.allEqual(u8, raw[1..33], 0)) return error.BadKey;
    }
    return raw[0];
}

fn rawSuiKey(t: []const u8, raw: *[33]u8) Error!void {
    if (std.mem.startsWith(u8, t, "suiprivkey1")) {
        const n = bech32Decode("suiprivkey", t, raw) catch return error.BadKey;
        if (n != 33) return error.BadKey;
    } else {
        const n = b64.Decoder.calcSizeForSlice(t) catch return error.BadKey;
        if (n != 33) return error.BadKey;
        b64.Decoder.decode(raw, t) catch return error.BadKey;
    }
}

/// `SuiAddress::from(&Ed25519PublicKey)`: Blake2b256(flag 0 || public key).
pub fn ed25519Address(pk: *const [32]u8) [32]u8 {
    return h256(&.{ &.{flag_ed25519}, pk });
}

/// sui-types `generate_proof_of_possession(keypair, address)`: the BLS signature
/// `AuthoritySignature::new_secure(IntentMessage(Intent::sui_app(ProofOfPossession), pk || address), epoch 0)`,
/// i.e. min-sig BLS over BCS(intent [5,0,0], Vec<u8>(pk ++ address)) ++ 0u64 LE. Genesis and
/// `sui validator make-validator-info` carry it; `verify_proof_of_possession` checks it.
pub fn proofOfPossession(sk: *const bls.SecretKey, address: *const [32]u8) [48]u8 {
    const pk = sk.publicKey().toBytes();
    var msg: [3 + 2 + 96 + 32 + 8]u8 = undefined;
    msg[0..3].* = .{ 5, 0, 0 }; // IntentScope::ProofOfPossession, IntentVersion::V0, AppId::Sui
    msg[3..5].* = .{ 0x80, 0x01 }; // ULEB128(128)
    msg[5..101].* = pk;
    msg[101..133].* = address.*;
    msg[133..141].* = @splat(0); // DEFAULT_EPOCH_ID
    return sk.sign(&msg).toBytes();
}

// ------------------------------------------------------------------ key files

const b64 = std.base64.standard;

pub fn encodeAuthorityFile(sk: *const bls.SecretKey, out: *[44]u8) []const u8 {
    const raw = sk.toBytes();
    return b64.Encoder.encode(out, &raw);
}

pub fn encodeEd25519File(kp: *const Ed25519.KeyPair, out: *[44 + 4]u8) []const u8 {
    var raw: [33]u8 = undefined;
    raw[0] = flag_ed25519;
    raw[1..].* = kp.secret_key.seed();
    return b64.Encoder.encode(out, &raw);
}

pub fn decodeAuthorityFile(text: []const u8) Error!bls.SecretKey {
    const t = std.mem.trim(u8, text, " \t\r\n");
    var raw: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw);
    const n = b64.Decoder.calcSizeForSlice(t) catch return error.BadKey;
    if (n != 32) return error.BadKey;
    b64.Decoder.decode(&raw, t) catch return error.BadKey;
    return bls.SecretKey.fromBytes(&raw) orelse error.BadKey;
}

/// An Ed25519 keypair from `flag || seed` in base64 or a `suiprivkey1` bech32 string.
pub fn decodeEd25519File(text: []const u8) Error!Ed25519.KeyPair {
    const t = std.mem.trim(u8, text, " \t\r\n");
    var raw: [33]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw);
    try rawSuiKey(t, &raw);
    if (raw[0] != flag_ed25519) return error.BadKey;
    return Ed25519.KeyPair.generateDeterministic(raw[1..33].*) catch error.BadKey;
}

// ------------------------------------------------------------------ bech32 (BIP-173, as sui's `suiprivkey`)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: []const u8) u32 {
    const gen = [5]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    var chk: u32 = 1;
    for (values) |v| {
        const b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (0..5) |i| {
            if ((b >> @intCast(i)) & 1 == 1) chk ^= gen[i];
        }
    }
    return chk;
}

pub const Bech32Error = error{ BadChar, BadChecksum, BadHrp, Short, Long };

/// Decodes `hrp1data` into bytes (8-bit regrouping without padding bits), returns the byte count.
pub fn bech32Decode(hrp: []const u8, s: []const u8, out: []u8) Bech32Error!usize {
    if (s.len < hrp.len + 7 or s.len > 90) return error.Short;
    const sep = std.mem.lastIndexOfScalar(u8, s, '1') orelse return error.BadHrp;
    if (!std.mem.eql(u8, s[0..sep], hrp)) return error.BadHrp;
    var vals: [128]u8 = undefined;
    var n: usize = 0;
    for (hrp) |c| {
        vals[n] = c >> 5;
        n += 1;
    }
    vals[n] = 0;
    n += 1;
    for (hrp) |c| {
        vals[n] = c & 31;
        n += 1;
    }
    const data = s[sep + 1 ..];
    if (data.len < 6) return error.Short;
    for (data) |c| {
        const lc = std.ascii.toLower(c);
        const i = std.mem.indexOfScalar(u8, charset, lc) orelse return error.BadChar;
        vals[n] = @intCast(i);
        n += 1;
    }
    if (polymod(vals[0..n]) != 1) return error.BadChecksum;
    // regroup 5 -> 8 bits over the data part without the checksum
    var acc: u32 = 0;
    var bits: u5 = 0;
    var o: usize = 0;
    for (vals[hrp.len * 2 + 1 .. n - 6]) |v| {
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (o >= out.len) return error.Long;
            out[o] = @intCast((acc >> bits) & 0xff);
            o += 1;
        }
    }
    return o;
}

test "generated keys are deterministic and distinct per index" {
    const seed: [32]u8 = @splat(7);
    const a = generate(&seed, 0);
    const b = generate(&seed, 0);
    const c = generate(&seed, 1);
    try std.testing.expectEqualSlices(u8, &a.authority_pk, &b.authority_pk);
    try std.testing.expect(!std.mem.eql(u8, &a.authority_pk, &c.authority_pk));
    try std.testing.expectEqualSlices(u8, &a.worker.public_key.toBytes(), &b.worker.public_key.toBytes());
    try std.testing.expect(!std.mem.eql(u8, &a.network.public_key.toBytes(), &c.network.public_key.toBytes()));
}

test "key files round trip" {
    const seed: [32]u8 = @splat(9);
    const k = generate(&seed, 2);
    var buf: [44]u8 = undefined;
    const text = encodeAuthorityFile(&k.authority, &buf);
    const sk = try decodeAuthorityFile(text);
    try std.testing.expectEqualSlices(u8, &k.authority.toBytes(), &sk.toBytes());
    var buf2: [48]u8 = undefined;
    const t2 = encodeEd25519File(&k.network, &buf2);
    const kp = try decodeEd25519File(t2);
    try std.testing.expectEqualSlices(u8, &k.network.public_key.toBytes(), &kp.public_key.toBytes());
    try std.testing.expectError(error.BadKey, decodeEd25519File("AAAA"));
}

// Rust truth (tools/truth/validator-keys, sui-keys + sui-types 1.83.1): key files written by
// write_authority_keypair_to_file / write_keypair_to_file for 8 seeds, their public keys, the
// bech32 export, the Ed25519 account address and generate_proof_of_possession.
const KeyVector = struct {
    seed: u32,
    authority_file: []const u8,
    authority_pk: []const u8,
    ed25519_file: []const u8,
    ed25519_pk: []const u8,
    ed25519_bech32: []const u8,
    secp256k1_file: []const u8,
    account_pk: []const u8,
    account_address: []const u8,
    pop: []const u8,
};

fn unhexAlloc(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

test "key files, addresses and proofs of possession match sui-keys/sui-types (8 seeds)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var lines = std.mem.tokenizeScalar(u8, @embedFile("testdata/keys.jsonl"), '\n');
    var n: usize = 0;
    while (lines.next()) |line| : (n += 1) {
        const v = try std.json.parseFromSliceLeaky(KeyVector, a, line, .{});
        // BLS authority key: Rust's file decodes to the same public key and re-encodes byte for byte
        const sk = try decodeAuthorityFile(v.authority_file);
        try std.testing.expectEqualSlices(u8, try unhexAlloc(a, v.authority_pk), &sk.publicKey().toBytes());
        var ab: [44]u8 = undefined;
        try std.testing.expectEqualStrings(v.authority_file, encodeAuthorityFile(&sk, &ab));
        // Ed25519 `flag || seed` file and its bech32 export
        const kp = try decodeEd25519File(v.ed25519_file);
        try std.testing.expectEqualSlices(u8, try unhexAlloc(a, v.ed25519_pk), &kp.public_key.toBytes());
        var eb: [48]u8 = undefined;
        try std.testing.expectEqualStrings(v.ed25519_file, encodeEd25519File(&kp, &eb));
        const kp2 = try decodeEd25519File(v.ed25519_bech32);
        try std.testing.expectEqualSlices(u8, &kp.public_key.toBytes(), &kp2.public_key.toBytes());
        // a Secp256k1 SuiKeyPair is a valid account key but never a network/worker key
        try std.testing.expectEqual(flag_secp256k1, try checkSuiKeyText(v.secp256k1_file));
        try std.testing.expectError(error.BadKey, decodeEd25519File(v.secp256k1_file));
        try std.testing.expectEqual(flag_ed25519, try checkSuiKeyText(v.ed25519_file));
        // SuiAddress of the Ed25519 account key, and the proof of possession over (pk, address)
        const apk = try unhexAlloc(a, v.account_pk);
        const addr = ed25519Address(apk[0..32]);
        try std.testing.expectEqualSlices(u8, try unhexAlloc(a, v.account_address), &addr);
        try std.testing.expectEqualSlices(u8, try unhexAlloc(a, v.pop), &proofOfPossession(&sk, &addr));
    }
    try std.testing.expectEqual(@as(usize, 8), n);
}

test "key texts Rust's readers reject are rejected, and the accepted ones accepted" {
    const Case = struct { name: []const u8, text: []const u8, authority_ok: bool, suikeypair_ok: bool, network_ok: bool };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var lines = std.mem.tokenizeScalar(u8, @embedFile("testdata/bad-keys.jsonl"), '\n');
    var n: usize = 0;
    while (lines.next()) |line| : (n += 1) {
        const c = try std.json.parseFromSliceLeaky(Case, arena_state.allocator(), line, .{});
        const got_auth = if (decodeAuthorityFile(c.text)) |_| true else |_| false;
        const got_sui = if (checkSuiKeyText(c.text)) |_| true else |_| false;
        const got_net = if (decodeEd25519File(c.text)) |_| true else |_| false;
        if (got_auth != c.authority_ok or got_sui != c.suikeypair_ok or got_net != c.network_ok) {
            std.debug.print("case {s}: authority {} sui {} network {}\n", .{ c.name, got_auth, got_sui, got_net });
            return error.TestUnexpectedResult;
        }
    }
    try std.testing.expectEqual(@as(usize, 7), n);
}
