//! val-epoch-api-keys, part 3: validator.yaml and keys at mainnet-v1.83.1
//! (docs/VALIDATOR-DESIGN.md 5.6, 8). Sources: sui-config `node.rs` (NodeConfig validator fields:
//! protocol-key-pair (BLS12-381), worker-key-pair (Ed25519, used as the consensus protocol key),
//! account-key-pair, network-key-pair (Ed25519), consensus-config, jwk-fetch-interval-seconds,
//! authority-overload-config), sui-keys key file formats, and the localnet generator: a local test
//! committee of N validators whose keys derive from one seed (gate.KeySource.generated).
//! The signer's persistence (lock file, fsynced two-slot watermark file) is `signer_impl.zig`,
//! used by `signer.zig`.
pub const fsutil = @import("fsutil.zig");
pub const material = @import("material.zig");
pub const signer_impl = @import("signer_impl.zig");
pub const config = @import("config.zig");
pub const localnet = @import("localnet.zig");

pub const Error = error{ Io, BadConfig, OutOfMemory };
pub const ValidatorConfig = config.ValidatorConfig;
pub const Localnet = localnet.Localnet;

/// Reads validator.yaml (the same keys sui-node reads; unknown keys are tolerated and listed in
/// `unknown_keys`, as NodeConfig has no deny_unknown_fields).
pub const loadConfig = config.load;

test {
    @import("std").testing.refAllDecls(@This());
}
