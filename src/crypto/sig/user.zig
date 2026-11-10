//! User signatures: GenericSignature parsing, address derivation and verification exactly as
//! sui-types mainnet-v1.83.1 does them (`GenericSignature::from_bytes`, `SuiAddress::try_from`,
//! `verify_authenticator`, `verify_sender_signed_data_message_signatures`).
//!
//! Every function reads the signature bytes in place and allocates nothing.
//!
//! Supported here: Ed25519, Secp256k1, Secp256r1 (plain), MultiSig, MultiSigLegacy (including the
//! roaring bitmap and base64 key forms), PasskeyAuthenticator (WebAuthn), zkLogin (single and as a
//! multisig member; the authenticator parse, Groth16 proof and addresses come from the zk
//! module), and MLDSA65 up to the point the protocol rejects it (the flag is off on mainnet).
//! A zkLogin signature returns error.Unsupported only when the caller gave no zkLogin environment
//! (JWKs and verifying keys).
//!
//! zkLogin parsing decodes the JWT header and iss claim; the decoded strings live in caller
//! scratch (`scratchLen` bytes per signature). Nothing allocates.
const std = @import("std");
const verdict = @import("verdict.zig");
const ed25519 = @import("ed25519.zig");
const ecdsa = @import("ecdsa.zig");
const fast = @import("fast.zig");
const json = @import("json.zig");
const Verdict = verdict.Verdict;
const Reason = verdict.Reason;
const hash = @import("hash");
const bcs = @import("bcs");
const types = @import("types");
const zk = @import("zk");
const zkl = zk.zklogin;
const Blake2b256 = hash.Blake2b256;

pub const Address = [32]u8;

pub const Error = error{
    /// A zkLogin signature with no zkLogin environment in the UserSigEnv, or ML-DSA-65
    /// verification with the flag on (no ML-DSA verifier in sig yet).
    Unsupported,
};

/// `OIDCProvider` variants that `zklogin_supported_providers` can name and `OIDCProvider::from_iss`
/// can return without data. (`AwsTenant` carries a region and tenant; no protocol version lists
/// one, so a provider set here cannot hold it and an AWS iss is never "supported" by a set.)
pub const OidcProvider = enum {
    google,
    twitch,
    facebook,
    kakao,
    apple,
    slack,
    test_issuer,
    test_issuer_key8192,
    microsoft,
    karrier_one,
    credenza3,
    playtron,
    threedos,
    onefc,
    fan_tv,
    arden,
    eve_frontier,
    test_eve_frontier,

    /// `OIDCProvider::from_iss` for the data-free variants (null: AwsTenant or unknown).
    pub fn fromIss(iss: []const u8) ?OidcProvider {
        const map = [_]struct { []const u8, OidcProvider }{
            .{ "https://accounts.google.com", .google },
            .{ "https://id.twitch.tv/oauth2", .twitch },
            .{ "https://www.facebook.com", .facebook },
            .{ "https://kauth.kakao.com", .kakao },
            .{ "https://appleid.apple.com", .apple },
            .{ "https://slack.com", .slack },
            .{ "https://oauth.sui.io", .test_issuer },
            .{ "https://jwt-tester.mystenlabs.com", .test_issuer_key8192 },
            .{ "https://accounts.karrier.one/", .karrier_one },
            .{ "https://accounts.credenza3.com", .credenza3 },
            .{ "https://oauth2.playtron.one", .playtron },
            .{ "https://auth.3dos.io", .threedos },
            .{ "https://login.onepassport.onefc.com/de3ee5c1-5644-4113-922d-e8336569a462/v2.0/", .onefc },
            .{ "https://accounts.fantv.world", .fan_tv },
            .{ "https://oidc.arden.cc", .arden },
            .{ "auth.evefrontier.com", .eve_frontier },
            .{ "test.auth.evefrontier.com", .test_eve_frontier },
        };
        for (map) |m| if (std.mem.eql(u8, iss, m[0])) return m[1];
        if (std.mem.startsWith(u8, iss, "https://login.microsoftonline.com/") and std.mem.endsWith(u8, iss, "/v2.0")) return .microsoft;
        return null;
    }

    /// `OIDCProvider::from_str` of the protocol config's provider names (Debug names).
    pub fn fromName(name: []const u8) ?OidcProvider {
        const names = [_]struct { []const u8, OidcProvider }{
            .{ "Google", .google },                 .{ "Twitch", .twitch },           .{ "Facebook", .facebook },
            .{ "Kakao", .kakao },                   .{ "Apple", .apple },             .{ "Slack", .slack },
            .{ "TestIssuer", .test_issuer },        .{ "TestIssuerKey8192", .test_issuer_key8192 },
            .{ "Microsoft", .microsoft },           .{ "KarrierOne", .karrier_one },  .{ "Credenza3", .credenza3 },
            .{ "Playtron", .playtron },             .{ "Threedos", .threedos },       .{ "Onefc", .onefc },
            .{ "FanTV", .fan_tv },                  .{ "Arden", .arden },             .{ "EveFrontier", .eve_frontier },
            .{ "TestEveFrontier", .test_eve_frontier },
        };
        for (names) |n| if (std.mem.eql(u8, name, n[0])) return n[1];
        return null;
    }
};

pub const ProviderSet = std.EnumSet(OidcProvider);

/// VerifyParams fields that come from the protocol config (sui-core SignatureVerifier).
pub const Flags = struct {
    accept_zklogin_in_multisig: bool = false,
    accept_passkey_in_multisig: bool = false,
    accept_mldsa65_in_multisig: bool = false,
    additional_multisig_checks: bool = false,
    validate_zklogin_public_identifier: bool = false,
    verify_legacy_zklogin_address: bool = false,
    zklogin_max_epoch_upper_bound_delta: ?u64 = null,
    /// `zklogin_supported_providers` (mainnet protocol versions 25 to 29: Google, Facebook,
    /// Twitch). Empty: no provider check, the JWK map alone decides.
    zklogin_supported_providers: ProviderSet = .empty,
};

/// Values the caller takes from the protocol config and epoch state.
pub const UserSigEnv = struct {
    epoch: u64,
    flags: Flags = .{},
    /// The SignatureVerifier's zkLogin side: prepared verifying keys, the JWK map at this point
    /// of the epoch, `ZkLoginEnv` and the circuit mode (`zklogin_circuit_mode`). Null: zkLogin
    /// signatures are error.Unsupported (fail closed).
    zklogin: ?zkl.Env = null,
};

/// One required signer's allowed addresses (sui-core `verify_tx_with_current_aliases`: the
/// AddressAliases object's `aliases` for the signer, in order). A signer with no entry is its
/// own only alias; an empty list also means the signer itself (sui-core's fallback).
pub const AliasSet = struct {
    signer: Address,
    aliases: []const Address,
};

/// Scratch bytes one signature of `sig_len` bytes may need (zkLogin JWT decoding, top level or
/// a multisig member); 16 for anything shorter than a zkLogin authenticator can be.
pub fn scratchLen(sig_len: usize) usize {
    return zkl.scratchLen(sig_len);
}

/// Scratch for `verifyTransaction` / `verifyTransactionSignatures` over these signatures.
pub fn txScratchLen(sigs: []const []const u8) usize {
    var n: usize = 0;
    for (sigs) |s| n += scratchLen(s.len);
    return n;
}

pub const Scheme = enum(u8) {
    ed25519 = 0,
    secp256k1 = 1,
    secp256r1 = 2,
    multisig = 3,
    bls12381 = 4,
    zklogin = 5,
    passkey = 6,
    mldsa65 = 7,
};

const ed_sig_len = 1 + 64 + 32;
const ecdsa_sig_len = 1 + 64 + 33;
const mldsa65_sig_bytes = 3309;
const mldsa65_pk_bytes = 1952;
const mldsa65_len = 1 + mldsa65_sig_bytes + mldsa65_pk_bytes;
const max_signers = 10;

// ---------------------------------------------------------------------------------------------
// BCS reading (bcs 0.1.6 rules, the version sui-types resolves: canonical ULEB128 up to u32, lengths <= 2^31 - 1)

/// The bcs module's reader; every decode error is one `error.Bcs` here (each one maps to the
/// same Sui verdict).
const Rd = struct {
    r: bcs.Reader,

    const E = error{Bcs};

    fn of(b: []const u8) Rd {
        return .{ .r = bcs.Reader.init(b) };
    }

    fn byte(r: *Rd) E!u8 {
        return r.r.int(u8) catch error.Bcs;
    }

    fn take(r: *Rd, n: usize) E![]const u8 {
        return r.r.bytes(n) catch error.Bcs;
    }

    fn uleb(r: *Rd) E!u32 {
        return r.r.uleb32() catch error.Bcs;
    }

    fn len(r: *Rd) E!usize {
        return r.r.length() catch error.Bcs;
    }

    fn bytes(r: *Rd) E![]const u8 {
        return r.take(try r.len());
    }

    fn u16le(r: *Rd) E!u16 {
        return r.r.int(u16) catch error.Bcs;
    }

    fn end(r: *Rd) E!void {
        if (r.r.remaining() != 0) return error.Bcs;
    }
};

// ---------------------------------------------------------------------------------------------
// Public keys as they sit in a MultiSigPublicKey (`PublicKey` enum, AsBytes variants)

pub const PkKind = enum(u8) { ed25519 = 0, secp256k1 = 1, secp256r1 = 2, zklogin = 3, passkey = 4, mldsa65 = 5 };

pub const Pk = struct {
    kind: PkKind,
    bytes: []const u8,
    /// A MultiSigLegacy ML-DSA-65 key kept as its (canonical) base64 text: flag byte included.
    base64: bool = false,

    /// `PublicKey::flag()` (the signature scheme flag).
    pub fn flag(pk: Pk) u8 {
        return switch (pk.kind) {
            .ed25519 => 0,
            .secp256k1 => 1,
            .secp256r1 => 2,
            .zklogin => 5,
            .passkey => 6,
            .mldsa65 => 7,
        };
    }

    fn eql(a: Pk, b: Pk) bool {
        return a.kind == b.kind and a.base64 == b.base64 and std.mem.eql(u8, a.bytes, b.bytes);
    }
};

pub const CsKind = enum(u8) { ed25519 = 0, secp256k1 = 1, secp256r1 = 2, zklogin = 3, passkey = 4, mldsa65 = 5 };

/// One `CompressedSignature`.
pub const Cs = struct {
    kind: CsKind,
    bytes: []const u8,
};

pub const MultiSig = struct {
    sigs: [max_signers]Cs = undefined,
    n_sigs: usize = 0,
    bitmap: u16 = 0,
    pks: [max_signers]Pk = undefined,
    weights: [max_signers]u8 = undefined,
    n_pks: usize = 0,
    threshold: u16 = 0,
    legacy: bool = false,
    /// Legacy keys are base64-decoded (and secp keys re-compressed) into here.
    key_store: [max_signers][33]u8 = undefined,

    fn pkSlice(m: *const MultiSig) []const Pk {
        return m.pks[0..m.n_pks];
    }

    /// MultiSigPublicKey::validate
    fn validPk(m: *const MultiSig) bool {
        if (m.threshold == 0 or m.n_pks == 0 or m.n_pks > max_signers) return false;
        var sum: u32 = 0;
        for (m.weights[0..m.n_pks]) |w| {
            if (w == 0) return false;
            sum += w;
        }
        // the Rust sum is a u16; ten u8 weights cannot overflow it
        if (sum < m.threshold) return false;
        for (0..m.n_pks) |i| for (i + 1..m.n_pks) |j| if (m.pks[i].eql(m.pks[j])) return false;
        return true;
    }

    /// MultiSig::init_and_validate (after the bitmap is a u16)
    fn initAndValidate(m: *const MultiSig) bool {
        if (m.n_sigs > m.n_pks or m.n_sigs == 0 or m.bitmap > 0b1111111111) return false;
        return m.validPk();
    }

    /// SuiAddress::from(&MultiSigPublicKey)
    pub fn address(m: *const MultiSig) Address {
        var h = Blake2b256.init();
        h.update(&.{@backingInt(Scheme.multisig)});
        var t: [2]u8 = undefined;
        std.mem.writeInt(u16, &t, m.threshold, .little);
        h.update(&t);
        for (m.pks[0..m.n_pks], m.weights[0..m.n_pks]) |pk, w| {
            if (pk.base64) {
                // decoded text is flag || key: hash it 4 characters (3 bytes) at a time
                var i: usize = 0;
                while (i < pk.bytes.len) : (i += 4) {
                    var chunk: [3]u8 = undefined;
                    const k = base64Decode(.standard, pk.bytes[i .. i + 4], &chunk) orelse unreachable;
                    h.update(chunk[0..k]);
                }
            } else {
                h.update(&.{pk.flag()});
                h.update(pk.bytes);
            }
            h.update(&.{w});
        }
        var out: Address = undefined;
        h.final(&out);
        return out;
    }

    fn hasZkLoginSigs(m: *const MultiSig) bool {
        for (m.sigs[0..m.n_sigs]) |s| if (s.kind == .zklogin) return true;
        return false;
    }

    fn hasPasskeySigs(m: *const MultiSig) bool {
        for (m.sigs[0..m.n_sigs]) |s| if (s.kind == .passkey) return true;
        return false;
    }

    fn hasMldsaMember(m: *const MultiSig) bool {
        for (m.pks[0..m.n_pks]) |p| if (p.kind == .mldsa65) return true;
        return false;
    }
};

fn readCs(r: *Rd) Rd.E!Cs {
    const tag = try r.uleb();
    return switch (tag) {
        0, 1, 2 => .{ .kind = @fromBackingInt(@intCast(tag)), .bytes = try r.take(64) },
        3, 4 => .{ .kind = @fromBackingInt(@intCast(tag)), .bytes = try r.bytes() },
        5 => .{ .kind = .mldsa65, .bytes = try r.take(mldsa65_sig_bytes) },
        else => error.Bcs,
    };
}

fn readPk(r: *Rd) Rd.E!Pk {
    const tag = try r.uleb();
    return switch (tag) {
        0 => .{ .kind = .ed25519, .bytes = try r.take(32) },
        1 => .{ .kind = .secp256k1, .bytes = try r.take(33) },
        2 => .{ .kind = .secp256r1, .bytes = try r.take(33) },
        3 => .{ .kind = .zklogin, .bytes = try r.bytes() },
        4 => .{ .kind = .passkey, .bytes = try r.take(33) },
        5 => .{ .kind = .mldsa65, .bytes = try r.take(mldsa65_pk_bytes) },
        else => error.Bcs,
    };
}

/// MultiSig::from_bytes (flag already checked): BCS, then init_and_validate.
fn parseMultiSig(payload: []const u8, m: *MultiSig) bool {
    parseMultiSigBcs(payload, m) catch return false;
    return m.initAndValidate();
}

fn parseMultiSigBcs(payload: []const u8, m: *MultiSig) Rd.E!void {
    var r = Rd.of(payload);
    const ns = try r.len();
    // More than ten signatures always fails validation; stop early (same outcome).
    if (ns > max_signers) return error.Bcs;
    m.n_sigs = ns;
    for (0..ns) |i| m.sigs[i] = try readCs(&r);
    m.bitmap = try r.u16le();
    const np = try r.len();
    if (np > max_signers) return error.Bcs;
    m.n_pks = np;
    for (0..np) |i| {
        m.pks[i] = try readPk(&r);
        m.weights[i] = try r.byte();
    }
    m.threshold = try r.u16le();
    try r.end();
}

/// MultiSigLegacy::from_bytes: BCS with a roaring-bitmap and base64 key strings, then validate.
fn parseLegacy(payload: []const u8, m: *MultiSig) bool {
    parseLegacyBcs(payload, m) catch return false;
    m.legacy = true;
    if (m.n_sigs > m.n_pks or m.n_sigs == 0) return false;
    return m.validPk();
}

fn parseLegacyBcs(payload: []const u8, m: *MultiSig) Rd.E!void {
    var r = Rd.of(payload);
    const ns = try r.len();
    if (ns > max_signers) return error.Bcs;
    m.n_sigs = ns;
    for (0..ns) |i| m.sigs[i] = try readCs(&r);
    const bm = try r.bytes();
    m.bitmap = roaringToU16(bm) orelse return error.Bcs;
    const np = try r.len();
    if (np > max_signers) return error.Bcs;
    m.n_pks = np;
    for (0..np) |i| {
        const s = try r.bytes();
        if (!std.unicode.utf8ValidateSlice(s)) return error.Bcs;
        m.pks[i] = decodeLegacyPk(s, &m.key_store[i]) orelse return error.Bcs;
        m.weights[i] = try r.byte();
    }
    m.threshold = try r.u16le();
    try r.end();
}

/// `<PublicKey as EncodeDecodeBase64>::decode_base64`: standard base64 (base64ct, canonical,
/// padded), flag byte, then the key parsed by fastcrypto. A secp256k1 key is re-encoded
/// compressed; a secp256r1 key only when it was given in 65-byte form.
fn decodeLegacyPk(s: []const u8, store: *[33]u8) ?Pk {
    const n = base64Decode(.standard, s, null) orelse return null;
    if (n == 0) return null;
    if (n > 66) {
        // Only an ML-DSA-65 key (flag 7 + 1952 bytes, length-checked only) is this long. It
        // stays base64 here; MultiSig.address decodes it while hashing.
        var head: [3]u8 = undefined;
        _ = base64Decode(.standard, s[0..4], &head) orelse return null;
        if (head[0] != 7 or n != 1 + mldsa65_pk_bytes) return null;
        return .{ .kind = .mldsa65, .bytes = s, .base64 = true };
    }
    var raw: [66]u8 = undefined;
    _ = base64Decode(.standard, s, &raw) orelse return null;
    const body = raw[1..n];
    switch (raw[0]) {
        0 => {
            if (body.len != 32) return null;
            _ = ed25519.decompress(body[0..32]) orelse return null;
            @memcpy(store[0..32], body);
            return .{ .kind = .ed25519, .bytes = store[0..32] };
        },
        1 => {
            const pt = ecdsa.secp256k1.parsePublicKey(body) orelse return null;
            store.* = pt.toCompressedSec1();
            return .{ .kind = .secp256k1, .bytes = store };
        },
        2, 6 => {
            // fastcrypto keeps 33 input bytes as the key's bytes (05 compact form included) and
            // re-encodes only the 65-byte form
            const pt = ecdsa.secp256r1.parsePublicKey(body) orelse return null;
            store.* = if (body.len == 33) body[0..33].* else pt.toCompressedSec1();
            return .{ .kind = if (raw[0] == 2) .secp256r1 else .passkey, .bytes = store };
        },
        else => return null,
    }
}

/// roaring 0.11.4 `RoaringBitmap::deserialize_from` + sui `deserialize_sui_bitmap` +
/// `bitmap_to_u16`. Trailing bytes after the bitmap are ignored, as the reader is not drained.
pub fn roaringToU16(b: []const u8) ?u16 {
    var r = Rd.of(b);
    const cookie = std.mem.readInt(u32, (r.take(4) catch return null)[0..4], .little);
    var size: usize = undefined;
    var has_offsets: bool = undefined;
    var has_runs: bool = undefined;
    if (cookie == 12346) {
        size = std.mem.readInt(u32, (r.take(4) catch return null)[0..4], .little);
        has_offsets = true;
        has_runs = false;
    } else if (@as(u16, @truncate(cookie)) == 12347) {
        size = (cookie >> 16) + 1;
        has_offsets = size >= 4;
        has_runs = true;
    } else return null;
    var run_bm: []const u8 = &.{};
    if (has_runs) run_bm = r.take((size + 7) / 8) catch return null;
    if (size > 65536) return null;
    const desc = r.take(size * 4) catch return null;
    if (has_offsets) _ = r.take(size * 4) catch return null;
    var out: u16 = 0;
    var card: u64 = 0;
    var last_key: ?u16 = null;
    for (0..size) |i| {
        const key = std.mem.readInt(u16, desc[i * 4 ..][0..2], .little);
        if (last_key) |lk| if (key <= lk) return null;
        last_key = key;
        const cardinality = @as(u64, std.mem.readInt(u16, desc[i * 4 + 2 ..][0..2], .little)) + 1;
        const is_run = has_runs and (run_bm[i / 8] & (@as(u8, 1) << @intCast(i % 8))) != 0;
        if (is_run) {
            const runs = r.u16le() catch return null;
            if (runs == 0) return null;
            const iv = r.take(@as(usize, runs) * 4) catch return null;
            var last_end: ?u16 = null;
            for (0..runs) |k| {
                const s = std.mem.readInt(u16, iv[k * 4 ..][0..2], .little);
                const l = std.mem.readInt(u16, iv[k * 4 + 2 ..][0..2], .little);
                const e = std.math.add(u16, s, l) catch return null;
                if (last_end) |le| if (s <= le +| 1) return null;
                last_end = e;
                card += @as(u64, l) + 1;
                if (key == 0) {
                    var v: u32 = s;
                    while (v <= e and v < 16) : (v += 1) out |= setBit(v);
                    if (e >= 10) out |= 0x8000; // a value >= 10: rejected below
                } else out |= 0x8000;
            }
        } else if (cardinality <= 4096) {
            const vals = r.take(@as(usize, @intCast(cardinality)) * 2) catch return null;
            var prev: ?u16 = null;
            for (0..@intCast(cardinality)) |k| {
                const v = std.mem.readInt(u16, vals[k * 2 ..][0..2], .little);
                if (prev) |pv| if (v <= pv) return null;
                prev = v;
                if (key == 0 and v < 10) out |= setBit(v) else out |= 0x8000;
            }
            card += cardinality;
        } else {
            const words = r.take(1024 * 8) catch return null;
            var pop: u64 = 0;
            for (0..1024) |k| {
                const w = std.mem.readInt(u64, words[k * 8 ..][0..8], .little);
                pop += @popCount(w);
                if (w != 0) {
                    if (key != 0 or k != 0 or w >= (1 << 10)) out |= 0x8000 else out |= @intCast(w);
                }
            }
            if (pop != cardinality) return null;
            card += cardinality;
        }
    }
    if (card > 150) return null; // MAX_VALIDATOR_COUNT
    if (out & 0x8000 != 0) return null; // bitmap_to_u16: an index >= 10
    return out;
}

fn setBit(v: u32) u16 {
    return if (v < 10) @as(u16, 1) << @intCast(v) else 0x8000;
}

// ---------------------------------------------------------------------------------------------
// base64 (base64ct 1.8: strict, canonical)

const Alphabet = enum { standard, url_unpadded };

fn b64val(a: Alphabet, c: u8) ?u6 {
    return switch (c) {
        'A'...'Z' => @intCast(c - 'A'),
        'a'...'z' => @intCast(c - 'a' + 26),
        '0'...'9' => @intCast(c - '0' + 52),
        '+' => if (a == .standard) 62 else null,
        '/' => if (a == .standard) 63 else null,
        '-' => if (a == .url_unpadded) 62 else null,
        '_' => if (a == .url_unpadded) 63 else null,
        else => null,
    };
}

/// Decodes into `out`; null unless the input is the canonical encoding of the result.
/// With `out` null it only validates and returns the decoded length.
pub fn base64Decode(a: Alphabet, s: []const u8, out: ?[]u8) ?usize {
    var body = s;
    if (a == .standard) {
        if (s.len % 4 != 0) return null;
        var pad: usize = 0;
        if (s.len >= 1 and s[s.len - 1] == '=') pad = 1;
        if (s.len >= 2 and s[s.len - 2] == '=' and pad == 1) pad = 2;
        body = s[0 .. s.len - pad];
    }
    if (body.len % 4 == 1) return null;
    const n = body.len / 4 * 3 + switch (body.len % 4) {
        2 => @as(usize, 1),
        3 => 2,
        else => 0,
    };
    if (out) |o| if (n > o.len) return null;
    var acc: u32 = 0;
    var bits: u5 = 0;
    var o: usize = 0;
    for (body) |c| {
        const v = b64val(a, c) orelse return null;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out) |ob| ob[o] = @truncate(acc >> bits);
            o += 1;
            acc &= (@as(u32, 1) << bits) - 1;
        }
    }
    if (acc != 0) return null; // non-canonical trailing bits
    if (a == .standard) {
        const want_pad: usize = switch (body.len % 4) {
            2 => 2,
            3 => 1,
            else => 0,
        };
        if (s.len - body.len != want_pad) return null;
    }
    return o;
}

// ---------------------------------------------------------------------------------------------
// Passkey (WebAuthn) authenticator

pub const Passkey = struct {
    authenticator_data: []const u8,
    client_data_json: []const u8,
    sig: *const [64]u8,
    pk: *const [33]u8,
    challenge: [32]u8,

    /// fastcrypto keeps a 33-byte secp256r1 key's input bytes as its `as_ref` (a 05 "compact"
    /// key included), so the address hashes the bytes as given.
    pub fn address(p: *const Passkey) Address {
        return addressOf(@backingInt(Scheme.passkey), p.pk);
    }
};

/// PasskeyAuthenticator::from_bytes payload (after the 0x06 flag): BCS RawPasskeyAuthenticator,
/// then the TryFrom checks. Any failure is the same error to the caller.
fn parsePasskey(payload: []const u8) ?Passkey {
    var r = Rd.of(payload);
    const ad = r.bytes() catch return null;
    const cdj = r.bytes() catch return null;
    if (!std.unicode.utf8ValidateSlice(cdj)) return null;
    const us = r.bytes() catch return null;
    r.end() catch return null;
    // user_signature: Signature::from_bytes (scheme flag + exact length)
    if (us.len == 0) return null;
    switch (us[0]) {
        0 => if (us.len != ed_sig_len) return null,
        1, 2 => if (us.len != ecdsa_sig_len) return null,
        7 => if (us.len != mldsa65_len) return null,
        else => return null,
    }
    var cbuf: [64]u8 = undefined;
    const cd = json.parse(cdj, &cbuf) orelse return null;
    if (cd.ty != .get) return null;
    if (cd.challenge_len > cbuf.len) return null;
    var challenge: [32]u8 = undefined;
    var tmp: [48]u8 = undefined;
    const n = base64Decode(.url_unpadded, cd.challenge, &tmp) orelse return null;
    if (n != 32) return null;
    @memcpy(&challenge, tmp[0..32]);
    if (us[0] != 2) return null;
    const pk = us[65..98];
    _ = fast.ecdsaDecodeKey(.r1, pk) orelse return null;
    const sig = us[1..65];
    const rr = std.mem.readInt(u256, sig[0..32], .big);
    const ss = std.mem.readInt(u256, sig[32..64], .big);
    const n_r1: u256 = std.crypto.ecc.P256.scalar.field_order;
    if (rr == 0 or ss == 0 or rr >= n_r1 or ss >= n_r1) return null;
    return .{ .authenticator_data = ad, .client_data_json = cdj, .sig = sig[0..64], .pk = pk[0..33], .challenge = challenge };
}

/// PasskeyAuthenticator::verify_claims. All failures are InvalidSignature.
fn verifyPasskey(p: *const Passkey, digest: *const [32]u8, author: *const Address) Verdict {
    const bad: Verdict = .{ .invalid = .InvalidSignature };
    if (!std.mem.eql(u8, author, &p.address())) return bad;
    if (!std.mem.eql(u8, &p.challenge, digest)) return bad;
    var h = hash.Sha256.init();
    var cdh: [32]u8 = undefined;
    hash.Sha256.hash(p.client_data_json, &cdh);
    h.update(p.authenticator_data);
    h.update(&cdh);
    var msg_hash: [32]u8 = undefined;
    h.final(&msg_hash);
    // pk.verify(message) hashes the message with SHA-256: hash in two parts, then verify the
    // prehashed digest.
    if (verifyR1Prehashed(p.pk, &msg_hash, p.sig) != .valid) return bad;
    return .valid;
}

fn verifyR1Prehashed(pk: *const [33]u8, z: *const [32]u8, sig: *const [64]u8) Verdict {
    return ecdsa.secp256r1.verifyDigest(pk, z, sig);
}

// ---------------------------------------------------------------------------------------------
// GenericSignature

pub const ZkLogin = struct {
    /// flag || BCS(ZkLoginAuthenticator)
    bytes: []const u8,
    /// Parsed (`ZkLoginAuthenticator::from_bytes`); kid and iss live in the parse scratch.
    auth: zkl.Authenticator,

    /// `SuiAddress::try_from_unpadded` (padded: `try_from_padded`, the legacy derivation).
    pub fn address(z: *const ZkLogin, padded: bool) Address {
        return zkl.address(z.auth.iss, &z.auth.seed, padded);
    }
};

pub const Parsed = union(enum) {
    /// Ed25519 / Secp256k1 / Secp256r1 / MLDSA65: flag || sig || pk
    single: struct { scheme: Scheme, sig: []const u8, pk: []const u8 },
    multisig: MultiSig,
    passkey: Passkey,
    zklogin: ZkLogin,
};

/// `FastCryptoError` from `ZkLoginAuthenticator::from_bytes` as a parse reason.
fn zkParseReason(f: zk.errors.Fail) Reason {
    return switch (f) {
        .invalid_input => .parse_invalid_input,
        .invalid_signature => .parse_invalid_signature,
        .invalid_proof => .parse_invalid_proof,
        .input_length_wrong => .parse_input_length_wrong,
        .input_too_short => .parse_input_too_short,
        .input_too_long => .parse_input_too_long,
        .general, .jwk_not_found => .parse_general_error,
        .none => unreachable,
    };
}

/// `ZkLoginAuthenticator::from_bytes(bytes)` (flag included). `scratch` holds the decoded
/// strings and must stay alive while `out` is used; it needs `scratchLen(bytes.len)` bytes.
fn parseZkLogin(bytes: []const u8, scratch: []u8, out: *ZkLogin) ?zk.errors.Fail {
    if (bytes.len == 0 or bytes[0] != zkl.flag) return .invalid_input;
    if (scratch.len < scratchLen(bytes.len)) @panic("sig.user: scratch smaller than scratchLen(signature length)");
    var fail: zk.errors.Fail = .none;
    out.bytes = bytes;
    if (!zkl.Authenticator.parse(bytes[1..], scratch, &out.auth, &fail)) return fail;
    return null;
}

/// GenericSignature::from_bytes. On failure, the parse reason (the FastCryptoError the Rust code
/// returns: InputTooShort, InvalidInput or InvalidSignature, and for zkLogin whatever
/// `ZkLoginInputs::init` returns). `scratch`: at least `scratchLen(bytes.len)` bytes, alive while
/// `out` is used (a zkLogin authenticator's decoded strings live there).
pub fn parse(bytes: []const u8, out: *Parsed, scratch: []u8) ?Reason {
    if (bytes.len == 0) return .parse_input_too_short;
    const flag = bytes[0];
    switch (flag) {
        0, 1, 2, 7 => {
            const want: usize = switch (flag) {
                0 => ed_sig_len,
                1, 2 => ecdsa_sig_len,
                else => mldsa65_len,
            };
            if (bytes.len != want) return .parse_invalid_signature;
            const sig_len: usize = if (flag == 7) mldsa65_sig_bytes else 64;
            out.* = .{ .single = .{ .scheme = @fromBackingInt(@intCast(flag)), .sig = bytes[1 .. 1 + sig_len], .pk = bytes[1 + sig_len ..] } };
            return null;
        },
        3 => {
            out.* = .{ .multisig = .{} };
            if (parseMultiSig(bytes[1..], &out.multisig)) return null;
            out.multisig = .{};
            if (parseLegacy(bytes[1..], &out.multisig)) return null;
            return .parse_invalid_input;
        },
        5 => {
            out.* = .{ .zklogin = undefined };
            if (parseZkLogin(bytes, scratch, &out.zklogin)) |f| return zkParseReason(f);
            return null;
        },
        6 => {
            out.* = .{ .passkey = parsePasskey(bytes[1..]) orelse return .parse_invalid_signature };
            return null;
        },
        else => return .parse_invalid_input,
    }
}

fn addressOf(flag: u8, pk: []const u8) Address {
    var h = Blake2b256.init();
    h.update(&.{flag});
    h.update(pk);
    var out: Address = undefined;
    h.final(&out);
    return out;
}

/// fastcrypto public key parsing for a plain signature's key (PublicKey::try_from_bytes).
fn pkValid(scheme: Scheme, pk: []const u8) bool {
    return switch (scheme) {
        .ed25519 => pk.len == 32 and ed25519.decompress(pk[0..32]) != null,
        .secp256k1 => fast.ecdsaDecodeKey(.k1, pk) != null,
        .secp256r1 => fast.ecdsaDecodeKey(.r1, pk) != null,
        .mldsa65 => pk.len == mldsa65_pk_bytes, // TODO(crypto-sig): fastcrypto-pq key checks
        else => false,
    };
}

pub const AddressResult = union(enum) {
    ok: Address,
    /// SuiAddress::try_from failed with this SuiErrorKind.
    err: Reason,
};

/// SuiAddress::try_from(&GenericSignature) (zkLogin: `try_from_unpadded`). Never
/// error.Unsupported now; the error set is kept for the contract.
pub fn address(p: *const Parsed) Error!AddressResult {
    switch (p.*) {
        .single => |s| {
            if (!pkValid(s.scheme, s.pk)) return .{ .err = .InvalidSignature };
            return .{ .ok = addressOf(@backingInt(s.scheme), s.pk) };
        },
        .multisig => |*m| return .{ .ok = m.address() },
        .passkey => |*pk| return .{ .ok = pk.address() },
        .zklogin => |*z| return .{ .ok = z.address(false) },
    }
}

/// verify_user_authenticator_epoch + verify_claims for a parsed signature, over the Blake2b256
/// digest of the intent message (every scheme signs that digest). `scratch`: what `parse` was
/// given for this signature (a multisig re-parses its zkLogin members there).
pub fn verifyParsed(env: *const UserSigEnv, p: *const Parsed, digest: *const [32]u8, author: *const Address, scratch: []u8) Error!Verdict {
    switch (p.*) {
        .single => |s| return verifySingle(env, s.scheme, s.sig, s.pk, digest, author, true),
        .multisig => |*m| return verifyMultiSig(env, m, digest, author, scratch),
        .passkey => |*pk| return verifyPasskey(pk, digest, author),
        .zklogin => |*z| {
            if (!zkl.checkEpoch(z.auth.max_epoch, env.epoch, env.flags.zklogin_max_epoch_upper_bound_delta))
                return .{ .invalid = .InvalidSignature };
            return verifyZkClaims(env, z, digest, author, null);
        },
    }
}

/// `ZkLoginAuthenticator::verify_claims`. `proof_ok`: the Groth16 side already verified for
/// these exact inputs (the transaction check verifies a legacy-address signature twice, as Rust
/// does; Rust's inputs cache skips the second proof, and so does this).
fn verifyZkClaims(env: *const UserSigEnv, z: *const ZkLogin, digest: *const [32]u8, author: *const Address, proof_ok: ?*bool) Error!Verdict {
    const bad: Verdict = .{ .invalid = .InvalidSignature };
    if (!std.mem.eql(u8, author, &z.address(false))) {
        if (!env.flags.verify_legacy_zklogin_address or !std.mem.eql(u8, author, &z.address(true)))
            return .{ .invalid = .InvalidAddress };
    }
    if (env.flags.zklogin_supported_providers.count() != 0) {
        const p = OidcProvider.fromIss(z.auth.iss) orelse return bad;
        if (!env.flags.zklogin_supported_providers.contains(p)) return bad;
    }
    const us = z.auth.user_signature;
    const scheme: Scheme = switch (us[0]) {
        0, 1, 2 => @fromBackingInt(us[0]),
        else => return bad, // a post-quantum ephemeral key adds nothing to zkLogin
    };
    const sig_len: usize = 64;
    // verify_secure with the zkLogin scheme: no address check against the ephemeral key
    const v = try verifySingle(env, scheme, us[1 .. 1 + sig_len], us[1 + sig_len ..], digest, author, false);
    if (v != .valid) return v;
    if (proof_ok) |po| if (po.*) return .valid;
    const zenv = env.zklogin orelse return error.Unsupported;
    if (fast.zkVerify(&zenv, &z.auth) != .none) return bad;
    if (proof_ok) |po| po.* = true;
    return .valid;
}

/// A and R of an Ed25519 signature: together when the key cache is off (their square roots
/// interleave), A from the cache and R alone when it is on. Same points either way.
fn decodeEdPair(pk: *const [32]u8, r: *const [32]u8) [2]?ed25519.Point {
    if (!fast.pkCacheOn()) return ed25519.decompress2(pk, r);
    if (fast.edGetKey(pk)) |a| return .{ a, ed25519.decompress(r) };
    const pts = ed25519.decompress2(pk, r);
    fast.edPutKey(pk, pts[0]);
    return pts;
}

/// Signature::verify_claims -> verify_secure. Each key is decoded once: Ed25519 decodes A and R
/// together, ECDSA keys are parsed once and verified with the parsed point. `check_author`
/// false: the zkLogin ephemeral signature (the scheme skips the key-address check).
fn verifySingle(env: *const UserSigEnv, scheme: Scheme, sig: []const u8, pk: []const u8, digest: *const [32]u8, author: *const Address, check_author: bool) Error!Verdict {
    if (scheme == .mldsa65 and !env.flags.accept_mldsa65_in_multisig) return .{ .invalid = .InvalidSignature };
    const bad_key: Verdict = .{ .invalid = .KeyConversionError };
    const bad_sig: Verdict = .{ .invalid = .InvalidSignature };
    const wrong_signer: Verdict = .{ .invalid = .IncorrectSigner };
    // get_verification_inputs: key first, then signature, then the author check
    switch (scheme) {
        .ed25519 => {
            if (pk.len != 32) return bad_key;
            // Verified cache (off by default): a hit means `ed25519.verify(pk, digest, sig)`
            // accepted this exact triple, so A decodes and the equation holds; only the author
            // check is left, in the order the plain path runs it.
            // A batch pass of the same call (sig.batch, `fast.setScope`) counts the same way.
            const vkey: ?[32]u8 = if (fast.edVerifiedOn() or fast.scopeOn()) fast.edVerifiedKey(pk[0..32], digest, sig[0..64]) else null;
            if (vkey) |*k| if (fast.scopeHas(k) or (fast.edVerifiedOn() and fast.edVerifiedGet(k))) {
                if (check_author and !std.mem.eql(u8, author, &addressOf(0, pk))) return wrong_signer;
                return .valid;
            };
            const pts = decodeEdPair(pk[0..32], sig[0..32]);
            const a = pts[0] orelse return bad_key;
            if (check_author and !std.mem.eql(u8, author, &addressOf(0, pk))) return wrong_signer;
            if (!ed25519.verifyDecoded(a, pts[1], pk[0..32], digest, sig[0..64])) return bad_sig;
            if (vkey) |*k| if (fast.edVerifiedOn()) fast.edVerifiedPut(k);
            return .valid;
        },
        .secp256k1 => {
            const q = fast.ecdsaDecodeKey(.k1, pk) orelse return bad_key;
            const r = std.mem.readInt(u256, sig[0..32], .big);
            const s = std.mem.readInt(u256, sig[32..64], .big);
            const n: u256 = std.crypto.ecc.Secp256k1.scalar.field_order;
            if (r >= n or s >= n) return bad_sig;
            if (check_author and !std.mem.eql(u8, author, &addressOf(1, pk))) return wrong_signer;
            const d = ecdsa.HashKind.sha256.digest(digest);
            return if (ecdsa.secp256k1.verifyDigestParsed(q, &d, sig) == .valid) .valid else bad_sig;
        },
        .secp256r1 => {
            const q = fast.ecdsaDecodeKey(.r1, pk) orelse return bad_key;
            const r = std.mem.readInt(u256, sig[0..32], .big);
            const s = std.mem.readInt(u256, sig[32..64], .big);
            const n: u256 = std.crypto.ecc.P256.scalar.field_order;
            if (r == 0 or s == 0 or r >= n or s >= n) return bad_sig;
            if (check_author and !std.mem.eql(u8, author, &addressOf(2, pk))) return wrong_signer;
            const d = ecdsa.HashKind.sha256.digest(digest);
            return if (ecdsa.secp256r1.verifyDigestParsed(q, &d, sig) == .valid) .valid else bad_sig;
        },
        .mldsa65 => {
            if (!pkValid(scheme, pk)) return bad_key;
            return error.Unsupported;
        },
        else => unreachable,
    }
}

/// ZkLoginPublicIdentifier::validate
fn zkLoginPkValid(b: []const u8) bool {
    if (b.len == 0) return false;
    const iss_len: usize = b[0];
    if (b.len < 1 + iss_len) return false;
    if (!std.unicode.utf8ValidateSlice(b[1 .. 1 + iss_len])) return false;
    return b.len - (1 + iss_len) <= 32;
}

/// True when every member signature is Ed25519, well formed for the member loop's checks, and the
/// whole set passes one batch verification. Never the reason for a verdict: false means "run the
/// single checks".
fn msEdBatch(env: *const UserSigEnv, m: *const MultiSig, digest: *const [32]u8) bool {
    const min = fast.multisigBatchMin();
    if (min == 0 or m.n_sigs < min) return false;
    var items: [10]ed25519.BatchItem = undefined;
    var n: usize = 0;
    var bit: u5 = 0;
    for (m.sigs[0..m.n_sigs]) |s| {
        while (bit < 10 and (m.bitmap >> @as(u4, @intCast(bit))) & 1 == 0) bit += 1;
        if (bit >= 10) return false;
        const idx: usize = bit;
        bit += 1;
        if (idx >= m.n_pks or n >= items.len) return false;
        const pk = m.pks[idx];
        if (s.kind != .ed25519 or pk.bytes.len != 32 or s.bytes.len != 64) return false;
        if (env.flags.additional_multisig_checks and pk.kind != .ed25519) return false;
        items[n] = .{ .pk = pk.bytes[0..32], .msg = digest, .sig = s.bytes[0..64] };
        n += 1;
    }
    if (n < 2) return false;
    return msBatchRun(items[0..n]);
}

/// Holds the ~32 KB batch scratch in its own frame, so only a call that reaches a batch pays it.
noinline fn msBatchRun(items: []const ed25519.BatchItem) bool {
    var buf: [fast.ms_scratch_len]u8 align(64) = undefined;
    return fast.batchAllValid(items, &buf);
}

/// MultiSig::verify_user_authenticator_epoch + verify_claims (legacy converts to MultiSig first).
fn verifyMultiSig(env: *const UserSigEnv, m: *const MultiSig, digest: *const [32]u8, author: *const Address, scratch: []u8) Error!Verdict {
    const bad: Verdict = .{ .invalid = .InvalidSignature };
    // epoch check (get_zklogin_sigs): every zkLogin member must parse, then each one's epoch
    for (m.sigs[0..m.n_sigs]) |s| if (s.kind == .zklogin) {
        var z: ZkLogin = undefined;
        if (parseZkLogin(s.bytes, scratch, &z) != null) return bad;
    };
    for (m.sigs[0..m.n_sigs]) |s| if (s.kind == .zklogin) {
        var z: ZkLogin = undefined;
        _ = parseZkLogin(s.bytes, scratch, &z);
        if (!zkl.checkEpoch(z.auth.max_epoch, env.epoch, env.flags.zklogin_max_epoch_upper_bound_delta)) return bad;
    };
    if (!m.validPk()) return bad;
    if (env.flags.validate_zklogin_public_identifier) {
        for (m.pks[0..m.n_pks]) |pk| if (pk.kind == .zklogin and !zkLoginPkValid(pk.bytes)) return bad;
    }
    if (!std.mem.eql(u8, author, &m.address())) return bad;
    if (m.hasZkLoginSigs() and !env.flags.accept_zklogin_in_multisig) return bad;
    if (m.hasPasskeySigs() and !env.flags.accept_passkey_in_multisig) return bad;
    if (m.hasMldsaMember() and !env.flags.accept_mldsa65_in_multisig) return bad;
    // Fast path (off by default): every Ed25519 member in one batch. Only a passing batch is
    // used, to skip the single checks below; anything else runs them and they decide.
    const ed_batched = msEdBatch(env, m, digest);
    var weight: u32 = 0;
    // zip(sigs, as_indices(bitmap)): the shorter one ends it
    var idx: usize = 0;
    var bit: u5 = 0;
    for (m.sigs[0..m.n_sigs]) |s| {
        while (bit < 10 and (m.bitmap >> @as(u4, @intCast(bit))) & 1 == 0) bit += 1;
        if (bit >= 10) break;
        idx = bit;
        bit += 1;
        if (idx >= m.n_pks) return bad;
        const pk = m.pks[idx];
        const strict = env.flags.additional_multisig_checks;
        const ok: bool = switch (s.kind) {
            .ed25519 => blk: {
                if (strict and pk.kind != .ed25519) return bad;
                if (pk.bytes.len != 32) return bad;
                if (ed_batched) break :blk true;
                // verified by this call's batch pass (sig.batch): A decodes and the equation holds
                if (fast.scopeOn() and s.bytes.len == 64 and fast.scopeHas(&fast.edVerifiedKey(pk.bytes[0..32], digest, s.bytes[0..64]))) break :blk true;
                const pts = decodeEdPair(pk.bytes[0..32], s.bytes[0..32]);
                const a = pts[0] orelse return bad;
                break :blk ed25519.verifyDecoded(a, pts[1], pk.bytes[0..32], digest, s.bytes[0..64]);
            },
            .secp256k1 => blk: {
                if (strict and pk.kind != .secp256k1) return bad;
                const q = fast.ecdsaDecodeKey(.k1, pk.bytes) orelse return bad;
                const r = std.mem.readInt(u256, s.bytes[0..32], .big);
                const sv = std.mem.readInt(u256, s.bytes[32..64], .big);
                const n: u256 = std.crypto.ecc.Secp256k1.scalar.field_order;
                if (r >= n or sv >= n) return bad;
                const d = ecdsa.HashKind.sha256.digest(digest);
                break :blk ecdsa.secp256k1.verifyDigestParsed(q, &d, s.bytes) == .valid;
            },
            .secp256r1 => blk: {
                if (strict and pk.kind != .secp256r1) return bad;
                const q = fast.ecdsaDecodeKey(.r1, pk.bytes) orelse return bad;
                const r = std.mem.readInt(u256, s.bytes[0..32], .big);
                const sv = std.mem.readInt(u256, s.bytes[32..64], .big);
                const n: u256 = std.crypto.ecc.P256.scalar.field_order;
                if (r == 0 or sv == 0 or r >= n or sv >= n) return bad;
                const d = ecdsa.HashKind.sha256.digest(digest);
                break :blk ecdsa.secp256r1.verifyDigestParsed(q, &d, s.bytes) == .valid;
            },
            .mldsa65 => {
                if (strict and pk.kind != .mldsa65) return bad;
                if (pk.bytes.len != mldsa65_pk_bytes) return bad;
                return error.Unsupported;
            },
            .zklogin => blk: {
                if (strict and pk.kind != .zklogin) return bad;
                var z: ZkLogin = undefined;
                if (parseZkLogin(s.bytes, scratch, &z) != null) return bad;
                const member = addressOf(pk.flag(), pk.bytes);
                break :blk try verifyZkClaims(env, &z, digest, &member, null) == .valid;
            },
            .passkey => blk: {
                if (s.bytes.len == 0 or s.bytes[0] != @backingInt(Scheme.passkey)) return bad;
                const pa = parsePasskey(s.bytes[1..]) orelse return bad;
                const member = addressOf(pk.flag(), pk.bytes);
                break :blk verifyPasskey(&pa, digest, &member) == .valid;
            },
        };
        if (!ok) return bad;
        weight += m.weights[idx];
    }
    if (weight >= m.threshold) return .valid;
    return bad;
}

/// Blake2b256 of the intent message bytes (`BCS(IntentMessage)`), the digest every scheme signs.
/// Who must sign a transaction, from its BCS `TransactionData` (sui-types
/// `TransactionDataV1::required_signers` and `TransactionKind::is_system_tx`): the sender, then
/// the gas owner when it differs; system kinds (everything but ProgrammableTransaction) need
/// no user signature. error.Bcs when the bytes are not one whole TransactionData.
pub const TxSigners = struct {
    signers: [2]Address,
    n: usize,
    is_system: bool,

    pub fn slice(t: *const TxSigners) []const Address {
        return t.signers[0..t.n];
    }
};

pub fn txSigners(tx_data: []const u8) error{Bcs}!TxSigners {
    const gen = types.gen;
    var r = bcs.Reader.init(tx_data);
    const ver = r.uleb32() catch return error.Bcs;
    if (ver != 0) return error.Bcs; // TransactionData::V1 only
    const kind_tag = r.uleb32() catch return error.Bcs;
    // re-read the kind as a whole value (validating it) and skip it
    r = bcs.Reader.init(tx_data);
    _ = r.uleb32() catch return error.Bcs;
    bcs.skip(gen.TransactionKind, &r) catch return error.Bcs;
    var out: TxSigners = undefined;
    out.signers[0] = (r.bytes(32) catch return error.Bcs)[0..32].*;
    bcs.skip(@FieldType(gen.GasData, "payment"), &r) catch return error.Bcs;
    const owner: Address = (r.bytes(32) catch return error.Bcs)[0..32].*;
    bcs.skip(u64, &r) catch return error.Bcs; // price
    bcs.skip(u64, &r) catch return error.Bcs; // budget
    bcs.skip(gen.TransactionExpiration, &r) catch return error.Bcs;
    if (r.remaining() != 0) return error.Bcs;
    out.n = 1;
    if (!std.mem.eql(u8, &owner, &out.signers[0])) {
        out.signers[1] = owner;
        out.n = 2;
    }
    out.is_system = kind_tag != @intFromEnum(std.meta.Tag(gen.TransactionKind).ProgrammableTransaction);
    return out;
}

/// `verifyTransactionSignatures` with the signers and the system flag derived from the intent
/// message (3 intent bytes, then the BCS TransactionData). Rust asserts the intent is
/// `Intent::sui_transaction()` (0, 0, 0); any other intent is error.Bcs here.
pub fn verifyTransaction(env: *const UserSigEnv, intent_msg: []const u8, sigs: []const []const u8, aliases: []const AliasSet, scratch: []u8) (Error || error{Bcs})!TxResult {
    if (intent_msg.len < 3 or intent_msg[0] != 0 or intent_msg[1] != 0 or intent_msg[2] != 0) return error.Bcs;
    const t = txSigners(intent_msg[3..]) catch return error.Bcs;
    const digest = intentDigest(intent_msg);
    return verifyTransactionSignatures(env, &digest, t.slice(), t.is_system, sigs, aliases, scratch);
}

pub fn intentDigest(intent_msg: []const u8) [32]u8 {
    var d: [32]u8 = undefined;
    Blake2b256.hash(intent_msg, &d);
    return d;
}

/// Verify one GenericSignature (flag byte + payload) for `sender` over the intent message:
/// `GenericSignature::from_bytes` then `verify_authenticator`. Allocation-free; `scratch` needs
/// `scratchLen(generic_sig.len)` bytes (used only by zkLogin).
pub fn verifyUserSignature(env: *const UserSigEnv, intent_msg: []const u8, sender: Address, generic_sig: []const u8, scratch: []u8) Error!Verdict {
    const d = intentDigest(intent_msg);
    return verifyUserSignatureDigest(env, &d, &sender, generic_sig, scratch);
}

pub fn verifyUserSignatureDigest(env: *const UserSigEnv, digest: *const [32]u8, sender: *const Address, generic_sig: []const u8, scratch: []u8) Error!Verdict {
    var p: Parsed = undefined;
    if (parse(generic_sig, &p, scratch)) |r| return .{ .invalid = r };
    return verifyParsed(env, &p, digest, sender, scratch);
}

// ---------------------------------------------------------------------------------------------
// Transaction level: verify_sender_signed_data_message_signatures

pub const TxResult = struct {
    verdict: Verdict,
    /// For each required signer, the index of its signature (valid when verdict is valid).
    indices: [8]u8 = undefined,
    n: usize = 0,
};

const max_tx_sigs = 8;

/// `required_signers`: sender, then the gas owner when it differs (TransactionData::required_signers).
/// `sigs`: the tx_signatures, each flag + payload. A signature that does not parse is reported
/// with its parse reason. `aliases`: the aliased_addresses argument (AliasSet). `scratch`:
/// `txScratchLen(sigs)` bytes.
pub fn verifyTransactionSignatures(env: *const UserSigEnv, digest: *const [32]u8, required_signers: []const Address, is_system: bool, sigs: []const []const u8, aliases: []const AliasSet, scratch: []u8) Error!TxResult {
    var res: TxResult = .{ .verdict = .valid };
    // 0. Every GenericSignature is decoded when the SenderSignedData is deserialized, before any
    // check below runs: a signature that does not decode fails first, whatever else is wrong.
    var parsed: [max_tx_sigs]Parsed = undefined;
    var regions: [max_tx_sigs][]u8 = undefined;
    var rest = scratch;
    for (sigs, 0..) |s, i| {
        const need = scratchLen(s.len);
        if (rest.len < need) @panic("sig.user: scratch smaller than txScratchLen(sigs)");
        const region = rest[0..need];
        rest = rest[need..];
        if (i < max_tx_sigs) {
            regions[i] = region;
            if (parse(s, &parsed[i], region)) |r| return .{ .verdict = .{ .invalid = r } };
        } else {
            var tmp: Parsed = undefined;
            if (parse(s, &tmp, region)) |r| return .{ .verdict = .{ .invalid = r } };
        }
    }
    // 1. one signature per signer
    if (sigs.len != required_signers.len) return .{ .verdict = .{ .invalid = .SignerSignatureNumberMismatch } };
    // TransactionData has at most two required signers; a caller passing more is not a Sui tx.
    if (sigs.len > max_tx_sigs) return error.Unsupported;
    // 2. system transactions use their dummy signatures
    if (is_system) {
        for (0..required_signers.len) |i| res.indices[i] = @intCast(i);
        res.n = required_signers.len;
        return res;
    }
    // get_signer_sig_mapping: address -> signature index (BTreeMap: a later insert of the same
    // address wins). A zkLogin signature under verify_legacy_zklogin_address is inserted under
    // its padded address, then its unpadded one. Parsed signatures live in `parsed[sig index]`.
    var addrs: [2 * max_tx_sigs]Address = undefined;
    var idxs: [2 * max_tx_sigs]u8 = undefined;
    var n: usize = 0;
    for (0..sigs.len) |i| {
        var keys: [2]Address = undefined;
        var nk: usize = 0;
        if (parsed[i] == .zklogin and env.flags.verify_legacy_zklogin_address) {
            keys[nk] = parsed[i].zklogin.address(true);
            nk += 1;
        }
        keys[nk] = switch (try address(&parsed[i])) {
            .ok => |a| a,
            .err => |r| return .{ .verdict = .{ .invalid = r } },
        };
        nk += 1;
        for (keys[0..nk]) |a| {
            var slot: ?usize = null;
            for (addrs[0..n], 0..) |x, k| if (std.mem.eql(u8, &x, &a)) {
                slot = k;
            };
            const k = slot orelse blk: {
                n += 1;
                break :blk n - 1;
            };
            addrs[k] = a;
            idxs[k] = @intCast(i);
        }
    }
    // 3. each signer is satisfied by the first of its aliases that has a signature
    for (required_signers, 0..) |signer, i| {
        var set: []const Address = required_signers[i..][0..1];
        for (aliases) |al| if (std.mem.eql(u8, &al.signer, &signer)) {
            if (al.aliases.len != 0) set = al.aliases;
            break;
        };
        var found: ?u8 = null;
        outer: for (set) |alias| {
            for (addrs[0..n], 0..) |x, k| if (std.mem.eql(u8, &x, &alias)) {
                found = idxs[k];
                break :outer;
            };
        }
        res.indices[i] = found orelse return .{ .verdict = .{ .invalid = .SignerSignatureAbsent } };
    }
    res.n = required_signers.len;
    // 4. every signature is valid, checked in address order (BTreeMap iteration)
    var order: [2 * max_tx_sigs]usize = undefined;
    for (0..n) |k| order[k] = k;
    std.mem.sort(usize, order[0..n], &addrs, struct {
        fn lt(a: *const [2 * max_tx_sigs]Address, x: usize, y: usize) bool {
            return std.mem.order(u8, &a[x], &a[y]) == .lt;
        }
    }.lt);
    var proof_ok: [max_tx_sigs]bool = @splat(false);
    for (order[0..n]) |k| {
        const si = idxs[k];
        const p = &parsed[si];
        const v = switch (p.*) {
            .zklogin => |*z| blk: {
                if (!zkl.checkEpoch(z.auth.max_epoch, env.epoch, env.flags.zklogin_max_epoch_upper_bound_delta))
                    break :blk Verdict{ .invalid = .InvalidSignature };
                break :blk try verifyZkClaims(env, z, digest, &addrs[k], &proof_ok[si]);
            },
            else => try verifyParsed(env, p, digest, &addrs[k], regions[si]),
        };
        if (v != .valid) return .{ .verdict = v };
    }
    return res;
}

test "roaring bitmap forms" {
    // RoaringBitmap {0, 2} serialized without run containers: cookie 12346, 1 container
    const b = [_]u8{ 0x3a, 0x30, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 2, 0 };
    try std.testing.expectEqual(@as(?u16, 0b101), roaringToU16(&b));
}

test "base64 canonical" {
    var out: [8]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, 1), base64Decode(.standard, "AA==", &out));
    try std.testing.expectEqual(@as(?usize, null), base64Decode(.standard, "AB==", &out));
    try std.testing.expectEqual(@as(?usize, null), base64Decode(.standard, "AA", &out));
    try std.testing.expectEqual(@as(?usize, 2), base64Decode(.url_unpadded, "AAA", &out));
    try std.testing.expectEqual(@as(?usize, null), base64Decode(.url_unpadded, "AAA=", &out));
}

fn testEdSig(seed: u8, digest: *const [32]u8) struct { sig: [ed_sig_len]u8, addr: Address } {
    const kp = ed25519.KeyPair.fromSeed(&@as([32]u8, @splat(seed)));
    var out: [ed_sig_len]u8 = undefined;
    out[0] = 0;
    out[1..65].* = kp.sign(digest);
    out[65..97].* = kp.pk;
    return .{ .sig = out, .addr = addressOf(0, &kp.pk) };
}

test "verifyTransaction: intent must be sui_transaction" {
    const env: UserSigEnv = .{ .epoch = 0 };
    var sc: [64]u8 = undefined;
    try std.testing.expectError(error.Bcs, verifyTransaction(&env, &.{ 1, 0, 0, 0 }, &.{}, &.{}, &sc));
    try std.testing.expectError(error.Bcs, verifyTransaction(&env, &.{ 0, 0 }, &.{}, &.{}, &sc));
}

test "address aliases: first alias with a signature, absent, both signed" {
    const env: UserSigEnv = .{ .epoch = 0 };
    const digest: [32]u8 = @splat(7);
    const a = testEdSig(1, &digest);
    const b = testEdSig(2, &digest);
    const signer: Address = @splat(0xaa); // keyless: only its aliases can sign
    var sc: [4096]u8 = undefined;
    const signers = [_]Address{signer};
    // no alias set: the signer itself must sign
    var r = try verifyTransactionSignatures(&env, &digest, &signers, false, &.{&a.sig}, &.{}, &sc);
    try std.testing.expectEqual(Reason.SignerSignatureAbsent, r.verdict.invalid);
    // aliased signer
    r = try verifyTransactionSignatures(&env, &digest, &signers, false, &.{&a.sig}, &.{.{ .signer = signer, .aliases = &.{ b.addr, a.addr } }}, &sc);
    try std.testing.expect(r.verdict == .valid);
    try std.testing.expectEqual(@as(u8, 0), r.indices[0]);
    // none of the aliases signed
    r = try verifyTransactionSignatures(&env, &digest, &signers, false, &.{&a.sig}, &.{.{ .signer = signer, .aliases = &.{b.addr} }}, &sc);
    try std.testing.expectEqual(Reason.SignerSignatureAbsent, r.verdict.invalid);
    // an empty alias list falls back to the signer itself
    r = try verifyTransactionSignatures(&env, &digest, &.{a.addr}, false, &.{&a.sig}, &.{.{ .signer = a.addr, .aliases = &.{} }}, &sc);
    try std.testing.expect(r.verdict == .valid);
    // sender and sponsor, the sponsor's set lists both: the first listed alias with a signature wins
    const two = [_]Address{ a.addr, signer };
    r = try verifyTransactionSignatures(&env, &digest, &two, false, &.{ &a.sig, &b.sig }, &.{.{ .signer = signer, .aliases = &.{ a.addr, b.addr } }}, &sc);
    try std.testing.expect(r.verdict == .valid);
    try std.testing.expectEqual(@as(u8, 0), r.indices[1]);
    r = try verifyTransactionSignatures(&env, &digest, &two, false, &.{ &a.sig, &b.sig }, &.{.{ .signer = signer, .aliases = &.{ b.addr, a.addr } }}, &sc);
    try std.testing.expectEqual(@as(u8, 1), r.indices[1]);
}

test "tx: every signature decodes before the count and system checks" {
    const env: UserSigEnv = .{ .epoch = 0 };
    const digest: [32]u8 = @splat(7);
    const a = testEdSig(1, &digest);
    var sc: [4096]u8 = undefined;
    const bad = [_]u8{ 0, 1, 2 }; // Ed25519 flag, wrong length
    // count mismatch and an undecodable signature: the decode error wins
    var r = try verifyTransactionSignatures(&env, &digest, &.{a.addr}, false, &.{ &a.sig, &bad }, &.{}, &sc);
    try std.testing.expectEqual(Reason.parse_invalid_signature, r.verdict.invalid);
    // a system transaction's signatures must decode too
    r = try verifyTransactionSignatures(&env, &digest, &.{a.addr}, true, &.{&bad}, &.{}, &sc);
    try std.testing.expectEqual(Reason.parse_invalid_signature, r.verdict.invalid);
    r = try verifyTransactionSignatures(&env, &digest, &.{a.addr}, true, &.{&a.sig}, &.{}, &sc);
    try std.testing.expect(r.verdict == .valid);
    // more signatures than any Sui transaction can carry, all decodable: count mismatch
    const many: [9][]const u8 = @splat(&a.sig);
    r = try verifyTransactionSignatures(&env, &digest, &.{a.addr}, false, &many, &.{}, &sc);
    try std.testing.expectEqual(Reason.SignerSignatureNumberMismatch, r.verdict.invalid);
}

test "zkLogin without an environment fails closed" {
    // a zkLogin signature that does not parse is a parse verdict, never Unsupported
    const env: UserSigEnv = .{ .epoch = 0 };
    var sc: [256]u8 = undefined;
    const v = try verifyUserSignatureDigest(&env, &@as([32]u8, @splat(0)), &@as(Address, @splat(0)), &.{ 5, 1, 2, 3 }, &sc);
    try std.testing.expect(v == .invalid);
}

test "ed25519 verified cache: verdicts unchanged, a hit only for the exact triple" {
    const env: UserSigEnv = .{ .epoch = 0 };
    fast.configure(.{});
    fast.clearCaches();
    defer fast.configure(.{});
    defer fast.clearCaches();
    var sc: [256]u8 = undefined;
    const digest: [32]u8 = @splat(9);
    const other: [32]u8 = @splat(10);
    const a = testEdSig(3, &digest);
    const b = testEdSig(4, &digest);
    // the plain verdict of every case first (cache off)
    const Case = struct { d: *const [32]u8, author: *const Address, sig: [ed_sig_len]u8 };
    var cases: [8]Case = undefined;
    cases[0] = .{ .d = &digest, .author = &a.addr, .sig = a.sig }; // valid
    cases[1] = .{ .d = &other, .author = &a.addr, .sig = a.sig }; // other message
    cases[2] = .{ .d = &digest, .author = &b.addr, .sig = a.sig }; // wrong signer
    cases[3] = .{ .d = &digest, .author = &a.addr, .sig = a.sig };
    cases[3].sig[1 + 40] ^= 1; // s changed
    cases[4] = .{ .d = &digest, .author = &a.addr, .sig = a.sig };
    cases[4].sig[1 + 3] ^= 1; // R changed
    cases[5] = .{ .d = &digest, .author = &a.addr, .sig = a.sig };
    cases[5].sig[66] ^= 1; // pk changed (address no longer matches either)
    cases[6] = .{ .d = &digest, .author = &b.addr, .sig = b.sig }; // valid, other key
    cases[7] = .{ .d = &digest, .author = &a.addr, .sig = b.sig }; // b's signature for a
    var want: [cases.len]Verdict = undefined;
    for (cases, &want) |c, *w| w.* = try verifyUserSignatureDigest(&env, c.d, c.author, &c.sig, &sc);
    try std.testing.expect(want[0] == .valid and want[6] == .valid);
    try std.testing.expect(want[1] != .valid and want[3] != .valid and want[4] != .valid and want[7] != .valid);
    try std.testing.expectEqual(Reason.IncorrectSigner, want[2].invalid);
    // cache on, twice over (the second round sees the entries the first one put)
    fast.configure(.{ .ed_verified_cache = true });
    for (0..2) |_| for (cases, want) |c, w| {
        const got = try verifyUserSignatureDigest(&env, c.d, c.author, &c.sig, &sc);
        try std.testing.expectEqual(w, got);
    };
    const st = fast.edVerifiedStats();
    // only the two accepted triples were ever stored; a's triple also hit under the wrong author
    try std.testing.expectEqual(@as(u64, 2), st.inserts);
    try std.testing.expect(fast.edVerifiedContains(&fast.edVerifiedKey(a.sig[65..97], &digest, a.sig[1..65])));
    try std.testing.expect(!fast.edVerifiedContains(&fast.edVerifiedKey(a.sig[65..97], &other, a.sig[1..65])));
    // a cached entry is never consulted while the switch is off
    fast.configure(.{});
    try std.testing.expectEqual(want[0], try verifyUserSignatureDigest(&env, &digest, &a.addr, &a.sig, &sc));
    try std.testing.expectEqual(st.hits, fast.edVerifiedStats().hits);
}
