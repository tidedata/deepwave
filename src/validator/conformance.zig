//! Conformance suites of the validator module. Each validator lane registers its suites from its
//! own directory and they are concatenated here (docs/VALIDATOR-DESIGN.md 9). Planned:
//! consensus-messages (BCS ConsensusTransactions from a Mysten localnet decode and re-encode
//! byte for byte), checkpoint-build (deepwave's builder over recorded checkpoints equals the Rust
//! ones: registered, src/validator/checkpoints/conformance.zig), dkg-vectors and jwk-vectors
//! (fastcrypto-tbls DKG messages, confirmations, outputs and partial signatures; JWK parsing and
//! AuthenticatorStateUpdate: registered, src/validator/{randomness,jwk}/conformance.zig), validator-api (sui.validator
//! messages against the Rust codecs).
//!
//! Run with `./zig build test-validator-conformance -Dsuite=<name>` (build.zig).
const harness = @import("harness");
const checkpoints_conformance = @import("checkpoints/conformance.zig");
const randomness_conformance = @import("randomness/conformance.zig");
const jwk_conformance = @import("jwk/conformance.zig");
const val_bench = @import("bench/root.zig");
const versions_conformance = @import("authority/versions_conformance.zig");
const messages_conformance = @import("consensus_messages_conformance.zig");
const sigs_conformance = @import("run/sigs_conformance.zig");
const funds_conformance = @import("run/funds_conformance.zig");

pub const suites = [_]harness.Suite{} ++ checkpoints_conformance.suites ++ randomness_conformance.suites ++ jwk_conformance.suites ++ versions_conformance.suites ++ messages_conformance.suites ++ sigs_conformance.suites ++ funds_conformance.suites ++ val_bench.suites;
