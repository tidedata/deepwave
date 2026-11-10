//! validator: the deepwave validator (docs/VALIDATOR-DESIGN.md). Composes consensus
//! (`consensus`, `consensus_net`) with the full node (`node`) and the validator-only parts:
//! transaction handling, checkpoint production, randomness, JWK, epochs, the Validator gRPC API,
//! keys, and the latency work. Unaudited: everything starts behind `gate.decide`, and deepwave
//! never imports this module. validator-base owns this file, gate.zig, signer.zig,
//! messages.zig, iface.zig and main.zig; lanes own their subdirectories.
const std = @import("std");

pub const gate = @import("gate.zig");
pub const signer = @import("signer.zig");
pub const messages = @import("messages.zig");
pub const iface = @import("iface.zig");
pub const authority = @import("authority/root.zig");
pub const checkpoints = @import("checkpoints/root.zig");
pub const randomness = @import("randomness/root.zig");
pub const jwk = @import("jwk/root.zig");
pub const epoch = @import("epoch/root.zig");
pub const api = @import("api/root.zig");
pub const keys = @import("keys/root.zig");
pub const latency = @import("latency/root.zig");
pub const conformance = @import("conformance.zig");
pub const node = @import("node.zig");
pub const seat = @import("seat.zig");

pub const consensus = @import("consensus");
pub const consensus_net = @import("consensus_net");

test {
    std.testing.refAllDecls(@This());
    refDeep(@This(), 4, &.{ "consensus", "consensus_net" });
}

/// Skeleton check: references every pub declaration, recursing into nested container types, so
/// the compiler analyzes every stub body (std.testing.refAllDecls stops at the first level).
fn refDeep(comptime T: type, comptime depth: u32, comptime skip: []const []const u8) void {
    inline for (comptime std.meta.declarations(T)) |name| {
        comptime var skipped = false;
        inline for (skip) |s| {
            if (comptime std.mem.eql(u8, s, name)) skipped = true;
        }
        if (skipped) continue;
        const F = @TypeOf(@field(T, name));
        if (F == type) {
            const V = @field(T, name);
            switch (@typeInfo(V)) {
                .@"struct", .@"union", .@"enum", .@"opaque" => if (depth > 0) refDeep(V, depth - 1, skip),
                else => {},
            }
        } else {
            _ = &@field(T, name);
        }
    }
}

