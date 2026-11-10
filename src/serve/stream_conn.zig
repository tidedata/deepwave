//! The deferred server-stream contract the stream lane introduced (`attach`, `Pump`, `Link`,
//! `streaming`, `serveBlocking`), now served by the transport runtime (h2/server.zig, h2/pump.zig):
//! the same calls work over h2c and over gRPC-web (HTTP/1.1) on one port.
const h2 = @import("h2/root.zig");

pub const Pump = h2.pump.Pump;
pub const Link = h2.pump.Link;
pub const attach = h2.pump.attach;
pub const streaming = h2.pump.streaming;
pub const serveBlocking = h2.server.serveBlocking;
