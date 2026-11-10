//! deepwave's simulation engine: execution without commit for agents and bots.
//! The interface is `api` (src/exec/simulate/api.zig).
const std = @import("std");

pub const api = @import("api.zig");
pub const overlay = @import("overlay.zig");
pub const conformance = @import("conformance.zig");

pub const Engine = api.Engine;
pub const Request = api.Request;
pub const Result = api.Result;

test {
    std.testing.refAllDecls(@This());
}
