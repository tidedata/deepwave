//! rt: Tile runtime: pinned threads, SPSC/MPSC rings, io_uring/kqueue event loop.
//! Owner lane: net. Interface: CONTRACTS.md. Only the net lane edits files in src/rt/.
const std = @import("std");

pub const ring = @import("ring.zig");
pub const conformance = @import("conformance.zig");

test {
    std.testing.refAllDecls(@This());
}
