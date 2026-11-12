//! The access gate (docs/GATE.md): API keys, local rate limits and per-key usage metering for a
//! node that serves the public, with an external gate service as the source of truth. Nothing
//! here runs unless the node is started with `--gate`.
const std = @import("std");

pub const contract = @import("contract.zig");
pub const ident = @import("ident.zig");
pub const methods = @import("methods.zig");
pub const state = @import("state.zig");
pub const spool = @import("spool.zig");
pub const meter = @import("meter.zig");
pub const gate = @import("gate.zig");
pub const mock = @import("mock.zig");

pub const Gate = gate.Gate;
pub const Config = gate.Config;
pub const Call = gate.Call;
pub const Ticket = gate.Ticket;
pub const Decision = gate.Decision;
pub const Deny = gate.Deny;
pub const Transport = gate.Transport;
pub const HttpRequest = gate.HttpRequest;
pub const Methods = methods.Methods;
pub const Ip = ident.Ip;

test {
    std.testing.refAllDecls(@This());
    _ = @import("gate_test.zig");
    _ = @import("bench.zig");
}
