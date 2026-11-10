//! consensus_net: Mysticeti networking and threads for the deepwave validator, equal to Mysten's
//! consensus-core network layer at mainnet-v1.83.1 (tonic gRPC over TLS, ConsensusService),
//! plus the core thread, subscriber, synchronizer, commit syncer and round prober.
//! Owner lane: val-consensus-net. docs/VALIDATOR-DESIGN.md sections 5 and 7.
const std = @import("std");

pub const proto = @import("proto.zig");
pub const tls = @import("tls.zig");
pub const mon = @import("mon.zig");
pub const rounds = @import("rounds.zig");
pub const addr = @import("addr.zig");
pub const broadcast = @import("broadcast.zig");
pub const testkit = @import("testkit.zig");
pub const peers = @import("peers.zig");
pub const shared = @import("shared.zig");
pub const testcore = @import("testcore.zig");
pub const localnet = @import("localnet.zig");
pub const grpc = @import("grpc.zig");
pub const service = @import("service.zig");
pub const sync = @import("sync.zig");
pub const authority_node = @import("authority_node.zig");
pub const conformance = @import("conformance.zig");
pub const interop = @import("interop.zig");

pub const ConsensusAuthority = authority_node.ConsensusAuthority;

test {
    std.testing.refAllDecls(@This());
    refDeep(@This(), 4, &.{});
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

