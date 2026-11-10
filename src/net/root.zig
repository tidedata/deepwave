//! net: QUIC + TLS 1.3 + anemo framing, read-only state-sync peer.
//! Owner lane: net. Interface: CONTRACTS.md. Only the net lane edits files in src/net/.
const std = @import("std");

pub const conformance = @import("conformance.zig");
pub const crc32c = @import("crc32c.zig");
pub const snappy = @import("snappy.zig");
pub const wire = @import("wire.zig");
pub const state_sync = @import("state_sync.zig");
pub const qcrypto = @import("qcrypto.zig");
pub const x509 = @import("x509.zig");
pub const tls13 = @import("tls13.zig");
pub const tls13_server = @import("tls13_server.zig");
pub const tls_identity = @import("tls_identity.zig");
pub const buf = @import("buf.zig");
pub const conn = @import("conn.zig");
pub const udpio = @import("udpio.zig");
pub const anemo = @import("anemo.zig");
pub const live = @import("live.zig");
pub const envutil = @import("envutil.zig");
pub const discovery = @import("discovery.zig");
pub const peer_addr = @import("peer_addr.zig");
pub const peer_score = @import("peer_score.zig");
pub const server = @import("server.zig");
pub const retry = @import("retry.zig");
pub const peer_pool = @import("peer_pool.zig");
pub const peer_cache = @import("peer_cache.zig");
test {
    _ = @import("fuzz_test.zig");
}

test {
    std.testing.refAllDecls(@This());
}
