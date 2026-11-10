//! Layout checks for every struct the store writes to disk byte for byte (`std.mem.asBytes`):
//! no padding, no undefined bits. A checksum over a struct with padding hashes whatever the
//! padding bytes held, so the same value could checksum two ways and write stack garbage to
//! disk. Adding a field that opens a gap fails the build here, not a recovery later.
//! (Meta, MetaFloors and JournalHeader are private to store.zig and not covered here yet.)
const std = @import("std");
const format = @import("format.zig");
const chunk = @import("chunk.zig");
const table = @import("table.zig");

pub fn assertNoPadding(comptime T: type) void {
    comptime {
        if (@typeInfo(T) != .@"struct" or @typeInfo(T).@"struct".layout != .@"extern")
            @compileError(@typeName(T) ++ " is written to disk: it must be an extern struct");
        if (!std.meta.hasUniqueRepresentation(T))
            @compileError(@typeName(T) ++ " has padding or non-unique bits: its bytes on disk are not defined");
    }
}

comptime {
    for (.{
        format.Header,          format.Short,      format.ObjectFixed, format.LinkFixed,
        format.XrefFixed,       format.RemoveFixed, format.TxFixed,    format.CheckpointFixed,
        format.CommitFixed,     format.SegmentFixed, chunk.FileHeader, chunk.Frame,
        chunk.Entry,            chunk.DirHeader,   table.LegacySlot,   table.Page,
        table.KeyEntry,         table.CpEntry,     table.RunHeader,    table.FilterHeader, table.LegacyPage,
    }) |T| assertNoPadding(T);
}
