//! Deterministic simulation testing of the whole node: seeded runs of
//! the follow pipeline on a virtual clock, simulated sources and a simulated disk, with the
//! production verification, admission rules, peer scoring and store engine, checked against
//! invariants (never accept a bad checkpoint, never lose a committed one, always converge).
const std = @import("std");

pub const chain = @import("chain.zig");
pub const run = @import("run.zig");

pub const Options = run.Options;
pub const Result = run.Result;
pub const Chain = chain.Chain;

test {
    std.testing.refAllDecls(@This());
}
