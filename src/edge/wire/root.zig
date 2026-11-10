//! edgewire: the edge feed (one checkpoint's verify-and-apply material as a core sends it) and its
//! zstd dictionaries, pure bytes in and out (docs/EDGE.md). The zui/1 method that serves it
//! lives in src/serve/native/dispatch.zig, the client and node source in src/edge/.
const std = @import("std");

pub const conformance = @import("conformance.zig");
pub const feed = @import("feed.zig");
pub const dict = @import("dict.zig");

test {
    std.testing.refAllDecls(@This());
}
