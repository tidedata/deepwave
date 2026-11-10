//! Conformance suites of consensus_net (val-consensus-net). Planned (docs/VALIDATOR-DESIGN.md
//! 9): consensus-proto (prost bytes of every ConsensusService message equal tonic's, from
//! recorded localnet traffic), consensus-interop (a deepwave authority in a Mysten localnet commits
//! with the Rust validators: run on a test machine, not a corpus suite).
const harness = @import("harness");

pub const suites = [_]harness.Suite{};
