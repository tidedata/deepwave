//! Lives in src/types/sigparse/b64.zig (shared with GenericSignature decode, PARITY.md G20).
const m = @import("types").sigparse.b64;
pub const decodedLen = m.decodedLen;
pub const encodedLen = m.encodedLen;
pub const decodeUrlUnpadded = m.decodeUrlUnpadded;
pub const encodeUrlUnpadded = m.encodeUrlUnpadded;
pub const decodeBase64UrlBits = m.decodeBase64UrlBits;
