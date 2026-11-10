//! bcs: BCS codec: zero-copy reader/views, writer, ULEB128, serde-equivalent rules, canonical tree text.
//! Owner lane: bcs-types. Interface: CONTRACTS.md. Only the bcs-types lane edits files in src/bcs/.
const std = @import("std");

pub const conformance = @import("conformance.zig");

const io = @import("io.zig");
const codec = @import("codec.zig");
const wire = @import("wire.zig");

pub const Error = io.Error;
pub const max_sequence_length = io.max_sequence_length;
pub const max_container_depth = io.max_container_depth;
pub const Reader = io.Reader;
pub const Writer = io.Writer;
pub const CountingWriter = io.CountingWriter;
pub const ulebLen = io.ulebLen;
pub const Bytes = wire.Bytes;
pub const String = wire.String;
pub const Map = wire.Map;

pub const DecodeError = codec.DecodeError;
pub const EncodeError = codec.EncodeError;
pub const decode = codec.decode;
pub const decodeFrom = codec.decodeFrom;
pub const skip = codec.skip;
pub const encode = codec.encode;
pub const encodedLen = codec.encodedLen;
pub const encodeAlloc = codec.encodeAlloc;
pub const minWire = codec.minWire;
pub const isNewtype = codec.isNewtype;
pub const hasHooks = codec.hasHooks;
pub const readStr = wire.readStr;
pub const tree = @import("tree.zig");
pub const view = @import("view.zig");
pub const View = view.View;

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
}
