//! exec: Transaction execution: input loading, PTB, gas charging, effects/events/object changes.
//! Owner lane: exec. Interface: CONTRACTS.md. Only the exec lane edits files in src/exec/.
const std = @import("std");

pub const conformance = @import("conformance.zig");
pub const classify = @import("classify.zig");
pub const replay = @import("replay.zig");
pub const objects = @import("objects.zig");
pub const state_hash = @import("state_hash.zig");
pub const StateHasher = state_hash;
pub const gas = @import("gas.zig");
pub const storage_check = @import("storage_check.zig");
pub const inputs = @import("inputs.zig");
pub const packages = @import("packages.zig");
pub const coin_ptb = @import("coin_ptb.zig");
pub const ccp = @import("ccp.zig");
pub const ptb = @import("ptb/root.zig");
pub const system = @import("system/root.zig");
pub const system_replay = @import("system/replay.zig");
pub const versions = @import("versions/root.zig");

test {
    std.testing.refAllDecls(@This());
}
