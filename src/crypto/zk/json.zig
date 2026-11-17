//! Lives in src/types/sigparse/jwt.zig (shared with GenericSignature decode, PARITY.md G20).
const m = @import("types").sigparse.jwt;
pub const Error = m.Error;
pub const Header = m.Header;
pub const jwtHeader = m.jwtHeader;
pub const claimValue = m.claimValue;
