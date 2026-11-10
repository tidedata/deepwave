//! zstd compressor for gRPC response messages: the store's encoder (src/store/zstd.zig, shared
//! with the store's compressed segment chunks).
const z = @import("store").zstd;
pub const compress = z.compress;
