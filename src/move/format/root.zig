//! move_format: Move binary format (CompiledModule) + bytecode verifier + verifier meter, Sui verifier passes.
//! Owner lane: move-format. Interface: CONTRACTS.md section 5.7. Only the move-format lane edits files in src/move/format/.
//!
//! Byte-exact with Mysten 1.83.1: `deserialize` mirrors `CompiledModule::deserialize_with_config`
//! (deserializer + bounds checker), `serialize` mirrors `serialize_with_version`.
const std = @import("std");

pub const conformance = @import("conformance.zig");
pub const file_format = @import("file_format.zig");
pub const deserializer = @import("deserializer.zig");
pub const serializer = @import("serializer.zig");
pub const check_bounds = @import("check_bounds.zig");
pub const verifier = @import("verifier/root.zig");

pub const StatusCode = file_format.StatusCode;
pub const PartialVmError = file_format.PartialVmError;
pub const VmError = file_format.VmError;
pub const Location = file_format.Location;
pub const IndexKind = file_format.IndexKind;
pub const CompiledModule = file_format.CompiledModule;
pub const BinaryConfig = deserializer.BinaryConfig;
pub const TableConfig = deserializer.TableConfig;
pub const DeserializeResult = deserializer.Result;

/// `CompiledModule::deserialize_with_config`. The module borrows `bytes` and lives in `arena`.
pub fn deserialize(arena: std.mem.Allocator, bytes: []const u8, cfg: *const BinaryConfig) std.mem.Allocator.Error!DeserializeResult {
    return deserializer.deserialize(arena, bytes, cfg);
}

/// `CompiledModule::serialize_with_version`, appending to `out`.
pub const serialize = serializer.serialize;
pub const serializeAlloc = serializer.serializeAlloc;

test {
    std.testing.refAllDecls(@This());
}
