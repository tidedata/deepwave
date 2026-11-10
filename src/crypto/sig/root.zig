//! sig: Ed25519 (ZIP-215), secp256k1, secp256r1, multisig, passkey, user-signature dispatch.
//! Owner lane: crypto-sig. Interface: CONTRACTS.md 5.4. Only the crypto-sig lane edits files in src/crypto/sig/.
//! Every acceptance rule comes from fastcrypto (da61cd4) and sui-types (mainnet-v1.83.1), and is
//! checked against Rust-made truth by the `sig-vectors` and `sig-corpus` suites.
const std = @import("std");

pub const verdict = @import("verdict.zig");
pub const Verdict = verdict.Verdict;
pub const Reason = verdict.Reason;
pub const ed25519 = @import("ed25519.zig");
pub const ed25519_ifma = @import("ed25519_ifma.zig");
pub const ecdsa = @import("ecdsa.zig");
pub const secp256k1 = ecdsa.secp256k1;
pub const secp256r1 = ecdsa.secp256r1;
pub const HashKind = ecdsa.HashKind;
pub const ristretto255 = @import("ristretto255.zig");
pub const Ecmh = ristretto255.Ecmh;
pub const ecvrf = @import("ecvrf.zig");
pub const lehmer = @import("lehmer.zig");
pub const dit = @import("dit.zig");
pub const secp256k1_arith = @import("secp256k1.zig");
pub const secp256r1_arith = @import("secp256r1.zig");
pub const user = @import("user.zig");
pub const json = @import("json.zig");
pub const UserSigEnv = user.UserSigEnv;
pub const verifyUserSignature = user.verifyUserSignature;
pub const verifyUserSignatureDigest = user.verifyUserSignatureDigest;

pub const conformance = @import("conformance.zig");

test {
    std.testing.refAllDecls(@This());
}
