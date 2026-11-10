//! User signature verification before submission: `TransactionOrchestrator`
//! `execute_transaction_with_effects_waiting` runs `verify_transaction_with_current_aliases` and
//! answers `TransactionSubmissionError::InvalidUserSignature` without contacting a validator.
//!
//! Source: sui-types mainnet-v1.83.1 `verify_sender_signed_data_message_signatures` (count, signer
//! mapping with address aliases, then each signature) and `SuiSignatureInner::verify_secure` /
//! `get_verification_inputs` (texts). The cryptography is crypto-sig's `sig.user` (fastcrypto
//! acceptance rules, checked against Rust truth by the sig suites).
//!
//! Policy: deepwave rejects locally only where it reproduces sui-node's reply exactly: Ed25519,
//! Secp256k1 and Secp256r1 signatures, multisig, passkey and zkLogin (with the chain's JWK set:
//! JWK lookup, proof points, Groth16 per the epoch's circuit mode). The verdict is crypto-sig's;
//! a valid verdict is never refused, and a failure whose text is not reproduced (or anything this
//! file cannot classify) goes to the validators unchanged. The signer-absent check needs the
//! address-alias lookup; without one it is left to the validators.
const std = @import("std");
const Allocator = std.mem.Allocator;
pub const sig = @import("sig");
const zk = @import("zk");
const hash = @import("hash");
const se = @import("../driver/sui_error.zig");
const errors = @import("../driver/errors.zig");
const handler = @import("../driver/handler.zig");

const Address = [32]u8;

/// `get_address_aliases_from_store`'s answer for one signer.
pub const Aliases = union(enum) {
    /// No AddressAliases object: the signer is its own only alias.
    none,
    /// The object's `aliases`, in order.
    set: []const Address,
    /// The lookup failed (store or upstream error): deepwave does not reject on it.
    unknown,
};

/// `get_address_aliases_from_store`. `fresh`: bypass any cache (asked again before a local
/// SignerSignatureAbsent rejection, so a changed alias set never makes deepwave refuse a transaction
/// sui-node, reading the live object, executes).
pub const AliasLookup = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, arena: Allocator, signer: *const Address, fresh: bool) Aliases,
};

pub const Env = struct {
    /// Null: the absent-signer check is skipped (validators decide).
    aliases: ?AliasLookup = null,
};

/// sui-types `address_aliases_object_id`: the derived object under 0xa keyed by
/// `DerivedObjectKey<address_alias::AliasKey>(address)` (same derivation as serve's VerifySignature,
/// lane verifysig).
pub fn aliasesObjectId(address: *const Address) Address {
    const fw = comptime blk: {
        var a: [32]u8 = @splat(0);
        a[31] = 2;
        break :blk a;
    };
    var tag: std.ArrayList(u8) = .empty;
    var buf: [160]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const a = fba.allocator();
    const put = struct {
        fn f(l: *std.ArrayList(u8), al: Allocator, b: []const u8) void {
            l.appendSlice(al, b) catch unreachable;
        }
    }.f;
    put(&tag, a, &.{7});
    put(&tag, a, &fw);
    put(&tag, a, &.{"derived_object".len});
    put(&tag, a, "derived_object");
    put(&tag, a, &.{"DerivedObjectKey".len});
    put(&tag, a, "DerivedObjectKey");
    put(&tag, a, &.{ 1, 7 });
    put(&tag, a, &fw);
    put(&tag, a, &.{"address_alias".len});
    put(&tag, a, "address_alias");
    put(&tag, a, &.{"AliasKey".len});
    put(&tag, a, "AliasKey");
    put(&tag, a, &.{0});
    var parent: Address = @splat(0);
    parent[31] = 0xa;
    var h = hash.Blake2b256.init();
    h.update(&.{0xf0});
    h.update(&parent);
    var l: [8]u8 = undefined;
    std.mem.writeInt(u64, &l, 32, .little);
    h.update(&l);
    h.update(address);
    h.update(tag.items);
    var out: Address = undefined;
    h.final(&out);
    return out;
}

/// AddressAliases Move contents: `{ id: UID, aliases: VecSet<address> }`.
pub fn parseAliases(arena: Allocator, contents: []const u8) ?[]const Address {
    if (contents.len < 33) return null;
    var p: usize = 32;
    var n: usize = 0;
    var shift: u6 = 0;
    while (true) {
        if (p >= contents.len or shift > 28) return null;
        const b = contents[p];
        p += 1;
        n |= @as(usize, b & 0x7f) << shift;
        if (b & 0x80 == 0) break;
        shift += 7;
    }
    if (contents.len < p + 32 * n) return null;
    const out = arena.alloc(Address, n) catch return null;
    for (out, 0..) |*o, i| o.* = contents[p + 32 * i ..][0..32].*;
    return out;
}

fn addressText(arena: Allocator, a: *const Address) Allocator.Error!se.Str {
    return .{ .@"0" = try std.fmt.allocPrint(arena, "0x{x}", .{a}) };
}

/// The epoch facts the check reads: the protocol config's signature flags and the epoch.
pub const EpochEnv = @import("../root.zig").EpochEnv;
const verifysig = @import("serve").verifysig;

/// The chain's AuthenticatorState JWKs from the node's latest objects (verifysig's reader).
/// sui-node's verifier map is the epoch-start active set plus every `AuthenticatorStateUpdate`
/// executed since, and the chain's active set only grows inside an epoch (expiry runs in the
/// end-of-epoch transaction): a (iss, kid) absent from the chain is absent from sui-node's map.
pub const LatestJwks = struct {
    ctx: *anyopaque,
    latest: *const fn (ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?[]const u8,
    arena: Allocator = undefined,
    loaded: ?[]const verifysig.Jwk = null,
    tried: bool = false,

    /// Null: no JWK set could be read (nothing is decided from it).
    fn get(self: *LatestJwks, arena: Allocator) ?[]const verifysig.Jwk {
        if (self.tried) return self.loaded;
        self.tried = true;
        self.arena = arena;
        const venv: verifysig.Env = .{ .ctx = self, .liveObject = live };
        const j = verifysig.chainJwks(arena, &venv) catch return null;
        if (j.len != 0) self.loaded = j;
        return self.loaded;
    }

    fn live(ctx: *anyopaque, id: *const [32]u8) ?[]const u8 {
        const self: *LatestJwks = @ptrCast(@alignCast(ctx));
        return self.latest(self.ctx, self.arena, id);
    }
};

/// `SignatureVerifier`'s `VerifyParams` from the protocol config (null: a provider name this
/// build does not know; the caller then leaves zkLogin to the validators).
pub fn flagsOf(cfg: anytype) ?sig.user.Flags {
    const ff = &cfg.feature_flags;
    var f: sig.user.Flags = .{
        .accept_zklogin_in_multisig = ff.accept_zklogin_in_multisig,
        .accept_passkey_in_multisig = ff.accept_passkey_in_multisig,
        .accept_mldsa65_in_multisig = ff.mldsa65_auth,
        .additional_multisig_checks = ff.additional_multisig_checks,
        .validate_zklogin_public_identifier = ff.validate_zklogin_public_identifier,
        .verify_legacy_zklogin_address = ff.verify_legacy_zklogin_address,
        .zklogin_max_epoch_upper_bound_delta = ff.zklogin_max_epoch_upper_bound_delta,
    };
    for (ff.zklogin_supported_providers) |name| f.zklogin_supported_providers.insert(sig.user.OidcProvider.fromName(name) orelse return null);
    return f;
}

/// Null: submit (valid, or left to the validators). Otherwise the orchestrator's error.
/// `ee`: the current epoch (protocol flags and epoch number). Without it only Ed25519,
/// Secp256k1 and Secp256r1 signatures are checked (they need no flag).
/// `jwks`: the chain's JWK set, for zkLogin's `verify_zk_login` (JWK lookup, proof points,
/// Groth16) and its texts (null: zkLogin past its ephemeral signature goes to the validators).
pub fn check(arena: Allocator, env: *const Env, req: *const handler.ExecuteRequest, ee: ?*const EpochEnv, jwks: ?*LatestJwks) Allocator.Error!?errors.SubmissionError {
    const signers = sig.user.txSigners(req.data_bcs) catch return null;
    // Every GenericSignature was decoded with the request (the decoder answers those that do
    // not decode); here a signature this file cannot parse is left to the validators.
    const n = req.signatures.len;
    const parsed = try arena.alloc(sig.user.Parsed, n);
    const scratch = try arena.alloc([]u8, n);
    var simple = true;
    for (req.signatures, parsed, scratch) |s, *p, *sc| {
        sc.* = try arena.alloc(u8, sig.user.scratchLen(s.len));
        if (sig.user.parse(s, p, sc.*) != null) return null;
        switch (p.*) {
            .single => |x| if (@backingInt(x.scheme) > 2) return null,
            else => simple = false,
        }
    }
    var ue: sig.user.UserSigEnv = .{ .epoch = 0 };
    var zj: ZkJwks = .{};
    if (!simple) {
        const e = ee orelse return null;
        ue = .{ .epoch = e.epoch, .flags = flagsOf(e.cfg) orelse return null };
        // the SignatureVerifier's zkLogin side (`verify_zk_login`): the chain's JWK set, the
        // production key on mainnet and testnet, the epoch's circuit mode. Without a JWK set
        // crypto-sig answers Unsupported for zkLogin and the validators decide.
        var any_zk = false;
        for (parsed) |*p| switch (p.*) {
            .zklogin => any_zk = true,
            .multisig => |*m| for (m.sigs[0..m.n_sigs]) |ms| {
                if (ms.kind == .zklogin) any_zk = true;
            },
            else => {},
        };
        if (any_zk) if (jwks) |jw| if (jw.get(arena)) |set| {
            zj.set = set;
            ue.zklogin = zkEnv(e, &zj);
        };
    }

    // 1. one signature per signer
    if (n != signers.n) return .{ .InvalidUserSignature = .{ .SignerSignatureNumberMismatch = .{
        .expected = signers.n,
        .actual = n,
    } } };
    // 2. system transactions are not user-submittable; the validators answer those
    if (signers.is_system) return null;

    // 3. get_signer_sig_mapping (BTreeMap: sorted by address, a later insert wins; with the
    // legacy zkLogin flag a zkLogin signature also maps its padded address, first)
    const Entry = struct { addr: Address, idx: usize };
    var map: std.ArrayList(Entry) = .empty;
    const put = struct {
        fn f(a: Allocator, m: *std.ArrayList(Entry), addr: Address, i: usize) Allocator.Error!void {
            for (m.items) |*e| if (std.mem.eql(u8, &e.addr, &addr)) {
                e.idx = i;
                return;
            };
            try m.append(a, .{ .addr = addr, .idx = i });
        }
    }.f;
    for (parsed, 0..) |*p, i| {
        if (ue.flags.verify_legacy_zklogin_address) if (p.* == .zklogin) try put(arena, &map, p.zklogin.address(true), i);
        const a = switch (sig.user.address(p) catch return null) {
            .ok => |x| x,
            .err => return null,
        };
        try put(arena, &map, a, i);
    }
    std.mem.sort(Entry, map.items, {}, struct {
        fn lt(_: void, x: Entry, y: Entry) bool {
            return std.mem.order(u8, &x.addr, &y.addr) == .lt;
        }
    }.lt);
    if (env.aliases) |al| {
        for (signers.slice()) |*signer| {
            const own: [1]Address = .{signer.*};
            var set: []const Address = &own;
            var found = false;
            var fresh = false;
            while (true) : (fresh = true) {
                set = switch (al.get(al.ctx, arena, signer, fresh)) {
                    .unknown => return null, // cannot tell: the validators decide
                    .none => &own,
                    .set => |x| x,
                };
                for (set) |*alias| {
                    for (map.items) |e| if (std.mem.eql(u8, &e.addr, alias)) {
                        found = true;
                    };
                }
                if (found or fresh) break;
            }
            if (found) continue;
            var expected: std.ArrayList(u8) = .empty;
            for (set, 0..) |*alias, k| {
                if (k > 0) try expected.appendSlice(arena, " or ");
                try expected.print(arena, "0x{x}", .{alias});
            }
            const actual = try arena.alloc(se.Str, map.items.len);
            for (map.items, actual) |*e, *t| t.* = try addressText(arena, &e.addr);
            return .{ .InvalidUserSignature = .{ .SignerSignatureAbsent = .{ .expected = .{ .@"0" = expected.items }, .actual = actual } } };
        }
    }

    // 4. every signature, in address order (verify_authenticator: epoch, then claims). The
    // verdict is crypto-sig's (fastcrypto and sui-types rules, checked against Rust truth); the
    // text layer below only names the failure. A valid verdict is never refused, and a failure
    // the text layer cannot name exactly goes to the validators.
    var hh = hash.Blake2b256.init();
    hh.update(&.{ 0, 0, 0 });
    hh.update(req.data_bcs);
    var digest: [32]u8 = undefined;
    hh.final(&digest);
    for (map.items) |e| {
        const p = &parsed[e.idx];
        const v: ?sig.Verdict = sig.user.verifyParsed(&ue, p, &digest, &e.addr, scratch[e.idx]) catch null;
        if (v) |x| if (x == .valid) continue;
        const t = try authenticatorText(arena, &ue, jwks, p, &digest, &e.addr, scratch[e.idx]);
        switch (t) {
            .reject => |k| return .{ .InvalidUserSignature = k },
            // crypto-sig says invalid but the text layer passes it (or cannot tell, or the
            // proof stage needs JWKs): the validators decide
            .ok, .unknown => return null,
        }
    }
    return null;
}

// ---------------------------------------------------------------------------------------------
// Text layer: the SuiErrorKind sui-types 1.83.1 raises, in its order of checks.

const Text = union(enum) {
    /// Every check this layer can run passed.
    ok,
    reject: se.SuiErrorKind,
    /// A failure (or a stage) whose text is not reproduced here.
    unknown,
};

fn invalidSig(arena: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!Text {
    return .{ .reject = .{ .InvalidSignature = .{ .@"error" = .{ .@"0" = try std.fmt.allocPrint(arena, fmt, args) } } } };
}

fn invalidLit(text: []const u8) Text {
    return .{ .reject = .{ .InvalidSignature = .{ .@"error" = .{ .@"0" = text } } } };
}

/// `GenericSignature::verify_authenticator`.
fn authenticatorText(arena: Allocator, ue: *const sig.user.UserSigEnv, jw: ?*LatestJwks, p: *const sig.user.Parsed, digest: *const [32]u8, author: *const Address, scratch: []u8) Allocator.Error!Text {
    switch (p.*) {
        .single => |s| return secureText(arena, @backingInt(s.scheme), s.sig, s.pk, digest, author, true),
        .passkey => |*pk| return passkeyText(pk, digest, author),
        .zklogin => |*z| {
            if (try zkEpochText(arena, ue, z.auth.max_epoch)) |t| return t;
            return zkClaimsText(arena, ue, jw, z, digest, author);
        },
        .multisig => |*m| return multisigText(arena, ue, jw, m, digest, author, scratch),
    }
}

/// `SuiSignature::verify_secure` (`get_verification_inputs`: key, then signature; then the
/// author check unless the scheme is zkLogin's; then verify).
fn secureText(arena: Allocator, flag: u8, sg: []const u8, pk: []const u8, digest: *const [32]u8, author: *const Address, check_author: bool) Allocator.Error!Text {
    const bad_key: Text = .{ .reject = .{ .KeyConversionError = .{ .@"0" = "Invalid public key" } } };
    if (!pkParses(flag, pk)) return bad_key;
    if (sg.len != 64) return .unknown;
    if (flag != 0 and !scalarsInRange(flag, sg)) return invalidLit("Fail to get pubkey and sig");
    if (check_author) {
        const a = addressOf(flag, pk);
        if (!std.mem.eql(u8, &a, author)) return .{ .reject = .{ .IncorrectSigner = .{ .@"error" = .{ .@"0" = try std.fmt.allocPrint(arena, "Incorrect signer, expected 0x{x}, got 0x{x}", .{ author, &a }) } } } };
    }
    if (!cryptoVerify(flag, pk, sg[0..64], digest)) return invalidLit("Fail to verify user sig Invalid signature was given to the function");
    return .ok;
}

fn pkParses(flag: u8, pk: []const u8) bool {
    return switch (flag) {
        0 => pk.len == 32 and sig.ed25519.decompress(pk[0..32]) != null,
        1 => sig.secp256k1.parsePublicKey(pk) != null,
        2 => sig.secp256r1.parsePublicKey(pk) != null,
        else => false,
    };
}

/// fastcrypto `VerifyingKey::verify` over the intent digest (key already parsed, signature
/// scalars in range).
fn cryptoVerify(flag: u8, pk: []const u8, sg: *const [64]u8, digest: *const [32]u8) bool {
    switch (flag) {
        0 => return sig.ed25519.verify(pk[0..32], digest, sg) == .valid,
        1, 2 => {
            const d = sig.HashKind.sha256.digest(digest);
            if (flag == 1) return sig.secp256k1.verifyDigestSlices(pk, &d, sg) == .valid;
            return sig.secp256r1.verifyDigestSlices(pk, &d, sg) == .valid;
        },
        else => return false,
    }
}

fn addressOf(flag: u8, pk: []const u8) Address {
    var h = hash.Blake2b256.init();
    h.update(&.{flag});
    h.update(pk);
    var out: Address = undefined;
    h.final(&out);
    return out;
}

/// `PasskeyAuthenticator::verify_claims`.
fn passkeyText(p: *const sig.user.Passkey, digest: *const [32]u8, author: *const Address) Text {
    if (!std.mem.eql(u8, author, &p.address())) return invalidLit("Invalid author");
    if (!std.mem.eql(u8, &p.challenge, digest)) return invalidLit("Invalid challenge");
    var cdh: [32]u8 = undefined;
    hash.Sha256.hash(p.client_data_json, &cdh);
    var h = hash.Sha256.init();
    h.update(p.authenticator_data);
    h.update(&cdh);
    var m: [32]u8 = undefined;
    h.final(&m);
    if (sig.secp256r1.verifyDigest(p.pk, &m, p.sig) != .valid) return invalidLit("Fails to verify");
    return .ok;
}

/// `ZkLoginAuthenticator::verify_user_authenticator_epoch` (null: in range).
fn zkEpochText(arena: Allocator, ue: *const sig.user.UserSigEnv, max_epoch: u64) Allocator.Error!?Text {
    if (ue.flags.zklogin_max_epoch_upper_bound_delta) |d| {
        const bound = ue.epoch +% d;
        if (max_epoch > bound) return try invalidSig(arena, "ZKLogin max epoch too large {d}, current epoch {d}, max accepted: {d}", .{ max_epoch, ue.epoch, bound });
    }
    if (ue.epoch > max_epoch) return try invalidSig(arena, "ZKLogin expired at epoch {d}, current epoch {d}", .{ max_epoch, ue.epoch });
    return null;
}

/// `ZkLoginAuthenticator::verify_claims` up to the proof (the proof needs the epoch's JWKs:
/// `unknown` there).
fn zkClaimsText(arena: Allocator, ue: *const sig.user.UserSigEnv, jw: ?*LatestJwks, z: *const sig.user.ZkLogin, digest: *const [32]u8, author: *const Address) Allocator.Error!Text {
    if (!std.mem.eql(u8, author, &z.address(false))) {
        if (!ue.flags.verify_legacy_zklogin_address or !std.mem.eql(u8, author, &z.address(true)))
            return .{ .reject = .InvalidAddress };
    }
    if (ue.flags.zklogin_supported_providers.count() != 0) {
        const pv = sig.user.OidcProvider.fromIss(z.auth.iss) orelse return .unknown;
        if (!ue.flags.zklogin_supported_providers.contains(pv)) return try invalidSig(arena, "OIDC provider not supported: {s}", .{z.auth.iss});
    }
    const us = z.auth.user_signature;
    // "zkLogin is classical (Groth16 over BN254); a PQ ephemeral key adds nothing"
    if (us.len > 0 and us[0] == 7) return invalidLit("zkLogin ephemeral signature scheme not supported: mldsa65");
    if (us.len == 0 or us[0] > 2) return .unknown;
    const t = try secureText(arena, us[0], us[1..65], us[65..], digest, author, false);
    if (t != .ok) return t;
    // verify_zk_login (fastcrypto-zkp zk_login_api.rs): the JWK for (iss, kid), its modulus,
    // the proof points, then the inputs hash and Groth16 per circuit mode. The text is
    // `InvalidSignature { error: SuiError::InvalidSignature { error: e.to_string() }.to_string() }`.
    const zenv = ue.zklogin orelse {
        // no zkLogin environment: only "JWK not found" is named here
        const set = (jw orelse return .unknown).get(arena) orelse return .unknown;
        for (set) |j| if (std.mem.eql(u8, zk.zklogin.normalizeIss(j.iss), zk.zklogin.normalizeIss(z.auth.iss)) and std.mem.eql(u8, j.kid, z.auth.kid)) return .unknown;
        return invalidSig(arena, "Signature is not valid: General cryptographic error: JWK not found ({s} - {s})", .{ z.auth.iss, z.auth.kid });
    };
    const f = zk.zklogin.verify(&zenv, &z.auth);
    if (f == .none) return .ok;
    var w: std.Io.Writer.Allocating = .init(arena);
    f.display(&w.writer) catch return error.OutOfMemory;
    return invalidSig(arena, "Signature is not valid: {s}", .{w.written()});
}

/// The chain's JWK set as `verify_zk_login`'s map (`JwkId::new` normalises a Microsoft tenant
/// iss on both sides).
const ZkJwks = struct {
    set: []const verifysig.Jwk = &.{},

    fn lookup(ctx: *const anyopaque, iss: []const u8, kid: []const u8) ?[]const u8 {
        const self: *const ZkJwks = @ptrCast(@alignCast(ctx));
        for (self.set) |j| if (std.mem.eql(u8, j.kid, kid) and std.mem.eql(u8, zk.zklogin.normalizeIss(j.iss), iss)) return j.n;
        return null;
    }
};

/// sui-types `get_mainnet_chain_identifier` / `get_testnet_chain_identifier` (genesis checkpoint
/// digests): `ZkLoginEnv::Prod` there, `Test` on any other chain (authority_per_epoch_store.rs).
const mainnet_chain_id = hexId("35834a8ac17ca48fb14ac8f99c17c98747e95dd07294ae41a46b382246a4499b");
const testnet_chain_id = hexId("4c78adacf2a2f5ad80f27ed7d54aa69d3a78f1ca67fdef9ecf5754f5b8bb77b0");

fn hexId(comptime h: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

/// `SignatureVerifier`'s zkLogin parameters for this epoch.
fn zkEnv(e: *const EpochEnv, jw: *const ZkJwks) zk.zklogin.Env {
    const prod = std.mem.eql(u8, &e.chain_id, &mainnet_chain_id) or std.mem.eql(u8, &e.chain_id, &testnet_chain_id);
    return .{
        .keys = zkKeys(),
        .jwks = .{ .ctx = jw, .lookupFn = ZkJwks.lookup },
        .usage = if (prod) .prod else .test_,
        // `zklogin_circuit_mode_from_flag`: 0 v1 only, 1 v2 then v1, 2 v2 only
        .mode = switch (e.cfg.feature_flags.zklogin_circuit_mode) {
            0 => .v1_only,
            1 => .both,
            else => .v2_only,
        },
    };
}

/// The prepared zkLogin verifying keys, built once per process (about 100 KiB).
var keys_state: std.atomic.Value(u8) = .init(0); // 0 none, 1 building, 2 ready
var keys: zk.zklogin.Keys = undefined;

fn zkKeys() *const zk.zklogin.Keys {
    while (true) switch (keys_state.load(.acquire)) {
        2 => return &keys,
        0 => if (keys_state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) {
            keys.init();
            keys_state.store(2, .release);
            return &keys;
        },
        else => std.atomic.spinLoopHint(),
    };
}

const PkCheck = union(enum) { text: Text, seed_len: usize };

/// `ZkLoginPublicIdentifier::validate` (null: valid; unknown for a UTF-8 error, whose Rust text
/// is not reproduced).
fn zkPkCheck(b: []const u8) ?PkCheck {
    if (b.len == 0) return .{ .text = invalidLit("Invalid zkLogin pk in multisig: Signature is not valid: invalid zklogin pk") };
    const il: usize = b[0];
    if (b.len < 1 + il) return .{ .text = invalidLit("Invalid zkLogin pk in multisig: Signature is not valid: invalid zklogin pk iss length") };
    if (!std.unicode.utf8ValidateSlice(b[1 .. 1 + il])) return .{ .text = .unknown };
    if (b.len - 1 - il > 32) return .{ .seed_len = b.len - 1 - il };
    return null;
}

fn pkBase64(arena: Allocator, pk: sig.user.Pk) Allocator.Error![]const u8 {
    const raw = try arena.alloc(u8, 1 + pk.bytes.len);
    raw[0] = pk.flag();
    @memcpy(raw[1..], pk.bytes);
    const enc = std.base64.standard.Encoder;
    const out = try arena.alloc(u8, enc.calcSize(raw.len));
    _ = enc.encode(out, raw);
    return out;
}

/// "Invalid sig for pk=<base64> address=<Debug> error=<tail>".
fn memberFail(arena: Allocator, pk: sig.user.Pk, tail: []const u8) Allocator.Error!Text {
    const a = addressOf(pk.flag(), pk.bytes);
    return invalidSig(arena, "Invalid sig for pk={s} address=0x{x} error={s}", .{ try pkBase64(arena, pk), &a, tail });
}

/// A member's failure as `error={:?}` of the FastCryptoError's text.
fn memberFailDebug(arena: Allocator, pk: sig.user.Pk, err_text: []const u8) Allocator.Error!Text {
    var w: std.Io.Writer.Allocating = .init(arena);
    se.writeDebugStr(&w.writer, err_text) catch return error.OutOfMemory;
    return memberFail(arena, pk, w.written());
}

/// A zkLogin or passkey member's `verify_claims` error, wrapped as
/// `FastCryptoError::GeneralError(e.to_string())`.
fn memberClaims(arena: Allocator, pk: sig.user.Pk, t: Text) Allocator.Error!?Text {
    switch (t) {
        .ok => return null,
        .unknown => return .unknown,
        .reject => |k| {
            const inner = try k.text(arena);
            return try memberFailDebug(arena, pk, try std.fmt.allocPrint(arena, "General cryptographic error: {s}", .{inner}));
        },
    }
}

/// `MultiSig::verify_user_authenticator_epoch` then `verify_claims` (a legacy multisig is
/// converted first, as `MultiSigLegacy` does; the parse already did that).
fn multisigText(arena: Allocator, ue: *const sig.user.UserSigEnv, jw: ?*LatestJwks, m: *const sig.user.MultiSig, digest: *const [32]u8, author: *const Address, scratch: []u8) Allocator.Error!Text {
    const sigs = m.sigs[0..m.n_sigs];
    const pks = m.pks[0..m.n_pks];
    for (pks) |pk| if (pk.base64) return .unknown;
    // get_zklogin_sigs: every zkLogin member parses, then each one's epoch
    for (sigs) |s| if (s.kind == .zklogin) {
        var zp: sig.user.Parsed = undefined;
        if (sig.user.parse(s.bytes, &zp, scratch) != null or zp != .zklogin) return invalidLit("Invalid zklogin authenticator bytes");
    };
    for (sigs) |s| if (s.kind == .zklogin) {
        var zp: sig.user.Parsed = undefined;
        _ = sig.user.parse(s.bytes, &zp, scratch);
        if (try zkEpochText(arena, ue, zp.zklogin.auth.max_epoch)) |t| return t;
    };
    // MultiSigPublicKey::validate
    {
        var ok = m.threshold != 0 and pks.len != 0;
        var sum: u32 = 0;
        for (m.weights[0..pks.len]) |w| {
            if (w == 0) ok = false;
            sum += w;
        }
        if (sum < m.threshold) ok = false;
        for (0..pks.len) |i| for (i + 1..pks.len) |j| {
            if (pks[i].kind == pks[j].kind and std.mem.eql(u8, pks[i].bytes, pks[j].bytes)) ok = false;
        };
        if (!ok) return invalidLit("Invalid multisig pubkey");
    }
    if (ue.flags.validate_zklogin_public_identifier) {
        for (pks) |pk| if (pk.kind == .zklogin) {
            if (zkPkCheck(pk.bytes)) |c| return switch (c) {
                .text => |t| t,
                .seed_len => |l| try invalidSig(arena, "Invalid zkLogin pk in multisig: Signature is not valid: address seed must be at most 32 bytes, got {d}", .{l}),
            };
        };
    }
    if (!std.mem.eql(u8, author, &m.address())) return invalidLit("Invalid address derived from pks");
    var has_zk = false;
    var has_pass = false;
    for (sigs) |s| {
        if (s.kind == .zklogin) has_zk = true;
        if (s.kind == .passkey) has_pass = true;
    }
    if (has_zk and !ue.flags.accept_zklogin_in_multisig) return invalidLit("zkLogin sig not supported inside multisig");
    if (has_pass and !ue.flags.accept_passkey_in_multisig) return invalidLit("Passkey sig not supported inside multisig");
    for (pks) |pk| if (pk.kind == .mldsa65) {
        if (!ue.flags.accept_mldsa65_in_multisig) return invalidLit("ML-DSA-65 member not supported inside multisig");
        return .unknown;
    };
    if (m.bitmap > 0b1111111111) return invalidLit("Invalid bitmap");
    var weight: u16 = 0;
    var bit: u5 = 0;
    for (sigs) |s| {
        while (bit < 10 and (m.bitmap >> @as(u4, @intCast(bit))) & 1 == 0) bit += 1;
        if (bit >= 10) break;
        const i: usize = bit;
        bit += 1;
        if (i >= pks.len) return invalidLit("Invalid public keys index");
        const pk = pks[i];
        const strict = ue.flags.additional_multisig_checks;
        const mismatch = "signature/pubkey type mismatch";
        switch (s.kind) {
            .ed25519, .secp256k1, .secp256r1 => {
                const flag: u8 = @backingInt(s.kind);
                if (strict and @backingInt(pk.kind) != flag) return memberFail(arena, pk, mismatch);
                if (!pkParses(flag, pk.bytes)) return invalidLit(switch (flag) {
                    0 => "Invalid ed25519 pk bytes",
                    1 => "Invalid k1 pk bytes",
                    else => "Invalid r1 pk bytes",
                });
                if (s.bytes.len != 64) return .unknown;
                if (flag != 0 and !scalarsInRange(flag, s.bytes)) return invalidLit(if (flag == 1) "Invalid k1 signature bytes" else "Invalid r1 signature bytes");
                if (!cryptoVerify(flag, pk.bytes, s.bytes[0..64], digest)) return memberFailDebug(arena, pk, "Invalid signature was given to the function");
            },
            .zklogin => {
                if (strict and pk.kind != .zklogin) return memberFail(arena, pk, mismatch);
                var zp: sig.user.Parsed = undefined;
                if (sig.user.parse(s.bytes, &zp, scratch) != null or zp != .zklogin) return invalidLit("Invalid zklogin authenticator bytes");
                const member = addressOf(pk.flag(), pk.bytes);
                if (try memberClaims(arena, pk, try zkClaimsText(arena, ue, jw, &zp.zklogin, digest, &member))) |t| return t;
            },
            .passkey => {
                var pp: sig.user.Parsed = undefined;
                if (s.bytes.len == 0 or s.bytes[0] != 6 or sig.user.parse(s.bytes, &pp, scratch) != null or pp != .passkey) return invalidLit("Invalid passkey authenticator bytes");
                const member = addressOf(pk.flag(), pk.bytes);
                if (try memberClaims(arena, pk, passkeyText(&pp.passkey, digest, &member))) |t| return t;
            },
            .mldsa65 => return .unknown,
        }
        weight += m.weights[i];
    }
    if (weight >= m.threshold) return .ok;
    return invalidSig(arena, "Insufficient weight={d} threshold={d}", .{ weight, m.threshold });
}

fn scalarsInRange(flag: u8, rs: []const u8) bool {
    const r = std.mem.readInt(u256, rs[0..32], .big);
    const s = std.mem.readInt(u256, rs[32..64], .big);
    if (flag == 1) {
        const n: u256 = std.crypto.ecc.Secp256k1.scalar.field_order;
        return r < n and s < n;
    }
    const n: u256 = std.crypto.ecc.P256.scalar.field_order;
    return r != 0 and s != 0 and r < n and s < n;
}

const testing = std.testing;

test "aliases object id is stable" {
    const a: Address = @splat(0x11);
    const x = aliasesObjectId(&a);
    const y = aliasesObjectId(&a);
    try testing.expectEqualSlices(u8, &x, &y);
}

test "parse aliases" {
    var c: [32 + 1 + 64]u8 = @splat(0);
    c[32] = 2;
    c[33] = 0xaa;
    c[65] = 0xbb;
    const out = parseAliases(testing.allocator, &c).?;
    defer testing.allocator.free(out);
    try testing.expectEqual(@as(usize, 2), out.len);
    try testing.expectEqual(@as(u8, 0xaa), out[0][0]);
    try testing.expectEqual(@as(u8, 0xbb), out[1][0]);
}

test "an alias set that changed is read again before a local SignerSignatureAbsent" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // a real signed testnet transaction (local vectors)
    const vectors = @embedFile("testdata/local_vectors.bin");
    if (vectors.len < 4) return error.SkipZigTest;
    const lr = std.mem.readInt(u32, vectors[0..4], .little);
    const Cap = struct {
        env: Env,
        verdict: ?errors.SubmissionError = null,
        fn run(ctx: *anyopaque, arena: Allocator, req: *const handler.ExecuteRequest) Allocator.Error!@import("../driver/driver.zig").Outcome {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            c.verdict = try check(arena, &c.env, req, null, null);
            return .{ .err = .TimeoutBeforeFinality };
        }
    };
    const L = struct {
        stale: Aliases,
        fresh: Aliases,
        calls: u32 = 0,
        fn get(ctx: *anyopaque, _: Allocator, _: *const Address, fresh: bool) Aliases {
            const l: *@This() = @ptrCast(@alignCast(ctx));
            l.calls += 1;
            return if (fresh) l.fresh else l.stale;
        }
    };
    const other = [_]Address{@splat(0xee)};
    const req = vectors[4..][0..lr];
    // cached: someone else's key only; live: no aliases object (the signer itself) -> valid
    var l1: L = .{ .stale = .{ .set = &other }, .fresh = .none };
    var c1: Cap = .{ .env = .{ .aliases = .{ .ctx = &l1, .get = L.get } } };
    _ = try handler.executeTransaction(a, .{ .ctx = &c1, .executeFn = Cap.run }, req);
    try testing.expect(c1.verdict == null);
    try testing.expectEqual(@as(u32, 2), l1.calls);
    // the fresh lookup fails: no local rejection (the validators decide)
    var l2: L = .{ .stale = .{ .set = &other }, .fresh = .unknown };
    var c2: Cap = .{ .env = .{ .aliases = .{ .ctx = &l2, .get = L.get } } };
    _ = try handler.executeTransaction(a, .{ .ctx = &c2, .executeFn = Cap.run }, req);
    try testing.expect(c2.verdict == null);
    // both say someone else: rejected locally, as sui-node does
    var l3: L = .{ .stale = .{ .set = &other }, .fresh = .{ .set = &other } };
    var c3: Cap = .{ .env = .{ .aliases = .{ .ctx = &l3, .get = L.get } } };
    _ = try handler.executeTransaction(a, .{ .ctx = &c3, .executeFn = Cap.run }, req);
    try testing.expect(c3.verdict != null and c3.verdict.? == .InvalidUserSignature);
    // the own key in the cached answer: one lookup only
    var l4: L = .{ .stale = .none, .fresh = .unknown };
    var c4: Cap = .{ .env = .{ .aliases = .{ .ctx = &l4, .get = L.get } } };
    _ = try handler.executeTransaction(a, .{ .ctx = &c4, .executeFn = Cap.run }, req);
    try testing.expect(c4.verdict == null);
    try testing.expectEqual(@as(u32, 1), l4.calls);
}

test "multisig, zkLogin and passkey texts equal the Mysten testnet fullnode's (sig_vectors.bin)" {
    // Recorded by `deepwave-execute sigcases` (testnet, sui-node 1.83.1): every case pays a gas price
    // above the maximum, so a valid signature passes this check and meets validity_check.
    const protocol = @import("protocol");
    const v = @embedFile("testdata/sig_vectors.bin");
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("ZSV1", v[0..4]);
    var off: usize = 4;
    const R = struct {
        fn u(b: []const u8, o: *usize) u64 {
            defer o.* += 8;
            return std.mem.readInt(u64, b[o.*..][0..8], .little);
        }
        fn s(b: []const u8, o: *usize) []const u8 {
            const l = std.mem.readInt(u32, b[o.*..][0..4], .little);
            defer o.* += 4 + l;
            return b[o.* + 4 ..][0..l];
        }
    };
    const epoch = R.u(v, &off);
    const pv = R.u(v, &off);
    const n = R.u(v, &off);
    const ee: EpochEnv = .{ .chain_id = testnet_chain_id, .epoch = epoch, .pv = pv, .cfg = try protocol.get(pv, .testnet), .rgp = 1000, .epoch_start_ms = 0, .committee_size = 100 };
    // an optional trailer after the cases: the live Google kid the proof-stage cases carry
    // (sigcases writes it; older recordings have none)
    const live_kid: []const u8 = blk: {
        var o = off;
        for (0..n) |_| {
            _ = R.s(v, &o);
            _ = R.s(v, &o);
            _ = R.u(v, &o);
            _ = R.s(v, &o);
            _ = R.s(v, &o);
        }
        break :blk if (o + 4 <= v.len) R.s(v, &o) else "";
    };
    // a Google JWK set without the synthetic cases' kid ("JWK not found"), plus the live kid
    // (its modulus does not matter: the synthetic proofs fail either way)
    const set = [_]verifysig.Jwk{
        .{ .iss = "https://accounts.google.com", .kid = "another-kid", .kty = "RSA", .e = "AQAB", .n = "", .alg = "RS256" },
        .{ .iss = "https://accounts.google.com", .kid = if (live_kid.len > 0) live_kid else "another-kid", .kty = "RSA", .e = "AQAB", .n = "AQAB", .alg = "RS256" },
    };
    const L = struct {
        fn get(_: *anyopaque, _: Allocator, _: *const Address, _: bool) Aliases {
            return .none;
        }
    };
    const Cap = struct {
        env: Env,
        ee: *const EpochEnv,
        jw: LatestJwks,
        fn run(ctx: *anyopaque, arena: Allocator, req: *const handler.ExecuteRequest) Allocator.Error!@import("../driver/driver.zig").Outcome {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            c.jw.tried = true;
            if (try check(arena, &c.env, req, c.ee, &c.jw)) |e| return .{ .err = e };
            return .{ .err = .TimeoutBeforeFinality }; // passed: "submitted"
        }
    };
    var local: u32 = 0;
    var passed: u32 = 0;
    for (0..n) |_| {
        const name = R.s(v, &off);
        const body = R.s(v, &off);
        const code = R.u(v, &off);
        const msg = R.s(v, &off);
        const details = R.s(v, &off);
        var c: Cap = .{ .env = .{ .aliases = .{ .ctx = undefined, .get = L.get } }, .ee = &ee, .jw = .{ .ctx = undefined, .latest = undefined, .loaded = &set } };
        const r = try handler.executeTransaction(a, .{ .ctx = &c, .executeFn = Cap.run }, body);
        errdefer std.debug.print("case {s}: reference {d} {s}\n", .{ name, code, msg });
        try testing.expect(code != 0); // every case is refused somewhere
        const e = r.err;
        if (std.mem.startsWith(u8, msg, "Invalid user signature") or std.mem.startsWith(u8, msg, "invalid signature")) {
            try testing.expectEqual(code, e.code);
            try testing.expectEqualStrings(msg, e.message);
            try testing.expectEqualStrings(details, e.details);
            local += 1;
        } else {
            // a valid signature: never refused here
            try testing.expect(!std.mem.startsWith(u8, e.message, "Invalid user signature"));
            passed += 1;
        }
    }
    try testing.expect(local >= 20 and passed >= 5);
}

test "zkLogin past a known JWK: the proof stage's texts (sig_vectors.bin cases, JWK set with their kid)" {
    // The recorded "JWK not found (https://accounts.google.com - zui-sigcases)" cases, replayed
    // with that kid in the JWK set: `verify_zk_login` goes on to the modulus and the proof points
    // (placeholders (1, 1, 1), not on the curve). Expected texts: fastcrypto-zkp zk_login_api.rs
    // (`Invalid Base64 encoded jwk modulus`; `as_arkworks` -> FastCryptoError::InvalidInput)
    // through the same wrapping as the recorded JWK text.
    const protocol = @import("protocol");
    const v = @embedFile("testdata/sig_vectors.bin");
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var off: usize = 4;
    const R = struct {
        fn u(b: []const u8, o: *usize) u64 {
            defer o.* += 8;
            return std.mem.readInt(u64, b[o.*..][0..8], .little);
        }
        fn s(b: []const u8, o: *usize) []const u8 {
            const l = std.mem.readInt(u32, b[o.*..][0..4], .little);
            defer o.* += 4 + l;
            return b[o.* + 4 ..][0..l];
        }
    };
    const epoch = R.u(v, &off);
    const pv = R.u(v, &off);
    const n = R.u(v, &off);
    const ee: EpochEnv = .{ .chain_id = testnet_chain_id, .epoch = epoch, .pv = pv, .cfg = try protocol.get(pv, .testnet), .rgp = 1000, .epoch_start_ms = 0, .committee_size = 100 };
    const jwk_text = "General cryptographic error: JWK not found (https://accounts.google.com - zui-sigcases)";
    const L = struct {
        fn get(_: *anyopaque, _: Allocator, _: *const Address, _: bool) Aliases {
            return .none;
        }
    };
    const Cap = struct {
        env: Env,
        ee: *const EpochEnv,
        jw: LatestJwks,
        fn run(ctx: *anyopaque, arena: Allocator, req: *const handler.ExecuteRequest) Allocator.Error!@import("../driver/driver.zig").Outcome {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            c.jw.tried = true;
            if (try check(arena, &c.env, req, c.ee, &c.jw)) |e| return .{ .err = e };
            return .{ .err = .TimeoutBeforeFinality };
        }
    };
    const variants = [_]struct { modulus: []const u8, text: []const u8 }{
        .{ .modulus = "AQAB", .text = "Invalid value was given to the function" },
        .{ .modulus = "A@B", .text = "General cryptographic error: Invalid Base64 encoded jwk modulus" },
    };
    var seen: u32 = 0;
    for (0..n) |_| {
        const name = R.s(v, &off);
        const body = R.s(v, &off);
        _ = R.u(v, &off);
        const msg = R.s(v, &off);
        _ = R.s(v, &off);
        if (std.mem.indexOf(u8, msg, jwk_text) == null) continue;
        seen += 1;
        for (variants) |var_| {
            const set = [_]verifysig.Jwk{.{ .iss = "https://accounts.google.com", .kid = "zui-sigcases", .kty = "RSA", .e = "AQAB", .n = var_.modulus, .alg = "RS256" }};
            var c: Cap = .{ .env = .{ .aliases = .{ .ctx = undefined, .get = L.get } }, .ee = &ee, .jw = .{ .ctx = undefined, .latest = undefined, .loaded = &set } };
            const r = try handler.executeTransaction(a, .{ .ctx = &c, .executeFn = Cap.run }, body);
            const want = try std.mem.replaceOwned(u8, a, msg, jwk_text, var_.text);
            errdefer std.debug.print("case {s}:\n  want {s}\n  got  {s}\n", .{ name, want, r.err.message });
            try testing.expectEqualStrings(want, r.err.message);
        }
    }
    try testing.expect(seen >= 2); // top level and multisig member
}

test "fastcrypto error display texts" {
    var buf: [128]u8 = undefined;
    const T = struct {
        fn of(b: []u8, f: zk.errors.Fail) []const u8 {
            var w: std.Io.Writer = .fixed(b);
            f.display(&w) catch unreachable;
            return w.buffered();
        }
    };
    try testing.expectEqualStrings("General cryptographic error: Groth16 proof verify failed", T.of(&buf, .{ .general = "Groth16 proof verify failed" }));
    try testing.expectEqualStrings("Invalid value was given to the function", T.of(&buf, .invalid_input));
    try testing.expectEqualStrings("Expected input of length at most 7", T.of(&buf, .{ .input_too_long = 7 }));
}
