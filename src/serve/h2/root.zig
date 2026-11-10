//! HTTP/2 (h2c) + gRPC + gRPC-web server core. `Conn` is sans-IO; `server.zig` is the
//! thread-per-connection runtime on one port (h2c and HTTP/1.1 told apart by the preface),
//! `web.zig` the HTTP/1.1 gRPC-web connection, `pump.zig` the deferred server-stream contract.
const std = @import("std");

pub const hpack = @import("hpack.zig");
pub const conn = @import("conn.zig");
pub const codec = @import("codec.zig");
pub const zstd = @import("zstd.zig");
pub const meta = @import("meta.zig");
pub const sock = @import("sock.zig");
pub const web = @import("web.zig");
pub const pump = @import("pump.zig");
pub const server = @import("server.zig");
pub const pool = @import("pool.zig");
pub const obs = @import("obs.zig");
pub const Conn = conn.Conn;
pub const Status = conn.Status;
pub const Request = conn.Request;
pub const ResponseStream = conn.ResponseStream;
pub const Handler = conn.Handler;
pub const Options = conn.Options;
pub const ServerOptions = server.Options;
pub const Header = hpack.Header;
pub const Pump = pump.Pump;
pub const Link = pump.Link;
pub const attach = pump.attach;
pub const streaming = pump.streaming;

/// Serves one accepted stream until the peer closes it or the connection errors. Every h2c unary
/// call runs on the worker pool (pool.zig), so a slow one (ExecuteTransaction waiting for
/// validators) never holds up the other streams of its connection; this replaces the execute
/// lane's interim offload.zig.
pub const serveStream = server.serveStream;
/// Accepts connections until `stop` is set and serves each on a thread.
pub const serveBlocking = server.serveBlocking;

test {
    std.testing.refAllDecls(@This());
    _ = @import("test.zig");
    _ = @import("test_web.zig");
    _ = @import("test_limits.zig");
    _ = @import("test_drain.zig");
}
