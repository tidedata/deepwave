//! edge: edge deepwave (docs/EDGE.md). A node kind that follows core nodes over the
//! native zui/1 protocol, verifies every checkpoint itself and keeps the live set plus recent
//! history. This module is the client side: the zui/1 connection, the core pool and the
//! profiles. The follower, store and serving stack are the full node's own.
const std = @import("std");

pub const conformance = @import("conformance.zig");
pub const client = @import("client.zig");
pub const fallback = @import("fallback.zig");
pub const certs = @import("certs.zig");
pub const inflight = @import("inflight.zig");
pub const profile = @import("profile.zig");
pub const route = @import("route.zig");
pub const forward = @import("forward.zig");
pub const raw = @import("raw.zig");
/// The access gate for a node that serves the public (docs/GATE.md); off without `--gate`.
pub const gate = @import("gate/root.zig");

test {
    std.testing.refAllDecls(@This());
}
