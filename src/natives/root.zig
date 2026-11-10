//! natives: All Move native functions (std + sui) with costs; Sui framework system packages.
//! Owner lane: sui-natives. Interface: CONTRACTS.md section 6.3. Only the sui-natives lane edits
//! files in src/natives/.
const std = @import("std");

pub const abi = @import("abi.zig");
pub const table = @import("table.zig");
pub const stdlib = @import("stdlib.zig");
pub const sui = @import("sui.zig");
pub const crypto = @import("crypto.zig");
pub const objrt = @import("objrt.zig");
pub const objnatives = @import("objnatives.zig");
pub const groth16_bls = @import("groth16_bls.zig");
pub const framework = @import("framework.zig");
pub const cbor = @import("cbor.zig");
pub const x509 = @import("x509.zig");
pub const nitro = @import("nitro.zig");
pub const multiaddr = @import("multiaddr.zig");
pub const validator = @import("validator.zig");
pub const conformance = @import("conformance.zig");

pub const Ctx = abi.Ctx;
pub const NativeFn = abi.NativeFn;
pub const Outcome = abi.Outcome;
pub const TxContext = abi.TxContext;
pub const ObjectRuntime = abi.ObjectRuntime;
pub const lookup = table.lookup;

test {
    std.testing.refAllDecls(@This());
}
