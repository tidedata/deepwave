//! val-randomness-jwk, part 2: JWK consensus at mainnet-v1.83.1 (docs/VALIDATOR-DESIGN.md 5.5).
//! Sources: sui-node `lib.rs` start_jwk_updater (fetch every `jwk_fetch_interval_seconds` from
//! each provider in `zklogin_oauth_providers` for the chain, validate with
//! `check_total_jwk_size`, submit NewJWKFetched), sui-core `authority_per_epoch_store.rs` (JWK
//! vote aggregation by stake: a STRONG quorum, 2f+1; `max_jwk_votes_per_validator_per_epoch`),
//! consensus handler AuthenticatorStateUpdate scheduling (previous round's new JWKs, sorted),
//! `authority.rs` create_authenticator_state_tx (Create / Expire at epoch end),
//! fastcrypto-zkp `OIDCProvider` and `parse_jwks`.
//! HTTPS fetches are cold-path and never run in local test mode (fixtures instead).
//!
//! Layout: providers, parse, aggregator (votes and active set), updater (fetch loop logic),
//! txs (NewJWKFetched), state_update (AuthenticatorStateUpdate and end of epoch kinds), https
//! (the real Transport), hooks (the iface.JwkHooks adapter).
const std = @import("std");

pub const providers = @import("providers.zig");
pub const parse = @import("parse.zig");
pub const aggregator = @import("aggregator.zig");
pub const updater = @import("updater.zig");
pub const txs = @import("txs.zig");
pub const state_update = @import("state_update.zig");
pub const https = @import("https.zig");
pub const hooks = @import("hooks.zig");

pub const Aggregator = aggregator.Aggregator;
pub const Updater = updater.Updater;

test {
    std.testing.refAllDecls(@This());
}
