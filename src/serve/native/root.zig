//! native: deepwave's native serving protocol `zui/1` (docs/NATIVE-PROTOCOL.md). Raw QUIC with ALPN
//! `zui/1` and WebTransport over HTTP/3 (ALPN `h3`), both on net/conn.zig's QUIC server role.
//! Owner lane: native-proto. Off by default; the node starts it with `--native-listen`.
const std = @import("std");

pub const conformance = @import("conformance.zig");
pub const qpack = @import("qpack.zig");
pub const h3 = @import("h3.zig");
pub const proto = @import("proto.zig");
pub const cert = @import("cert.zig");
pub const certs = @import("certs.zig");
pub const dispatch = @import("dispatch.zig");
pub const hello = @import("hello.zig");
pub const sub = @import("sub.zig");
pub const listener = @import("listener.zig");
pub const certhttp = @import("certhttp.zig");
pub const tcptls = @import("tcptls.zig");
pub const indexq = @import("indexq.zig");
pub const jobs = @import("jobs.zig");
pub const edgefeed = @import("edgefeed.zig");
pub const dicts = @import("dicts.zig");
pub const agentpass = @import("agentpass.zig");

test {
    _ = @import("certs_test.zig");
    _ = @import("hello_test.zig");
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(listener.Listener);
    std.testing.refAllDecls(dispatch.Dispatcher);
    std.testing.refAllDecls(dicts.Dicts);
    std.testing.refAllDecls(agentpass.Policy);
    std.testing.refAllDecls(agentpass.Pass);
}
