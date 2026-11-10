//! move_vm: the Move VM of Sui 1.83.1 (move-vm-runtime "latest" execution) in Zig: loader and
//! package cache, runtime types, values, the interpreter and the Sui gas meter.
//! Owner lane: move-vm. Interface: CONTRACTS.md section 6.2. Only the move-vm lane edits files in src/move/vm/.
const std = @import("std");

pub const conformance = @import("conformance.zig");
pub const gas = @import("gas.zig");
pub const value = @import("value.zig");
pub const loader = @import("loader.zig");
pub const types = @import("types.zig");
pub const interp = @import("interp.zig");
pub const trace = @import("trace.zig");
pub const host = @import("host.zig");
pub const cuts = @import("cuts.zig"); // exec-history-vm

pub const Runtime = loader.Runtime;
pub const Package = loader.Package;
pub const PackageInput = loader.PackageInput;
pub const Function = loader.Function;
pub const Type = loader.Type;
pub const Value = value.Value;
pub const Meter = gas.Meter;
pub const Session = interp.Session;
pub const LinkCtx = interp.LinkCtx;
pub const ExecConfig = interp.ExecConfig;
pub const VmError = interp.VmError;
pub const Outcome = interp.Outcome;
pub const Native = interp.Native;
pub const NativeFn = interp.NativeFn;
pub const NativeTable = interp.NativeTable;
pub const NativeContext = interp.NativeContext;
pub const NativeResult = interp.NativeResult;
pub const Tracer = trace.Tracer;
pub const Host = host.Host;
pub const TyArgCache = host.TyArgCache;

test {
    std.testing.refAllDecls(@This());
}
