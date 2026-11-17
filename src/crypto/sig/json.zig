//! Lives in src/types/sigparse/clientdata.zig (shared with GenericSignature decode, PARITY.md
//! G20: passkey client data is checked when the signature is decoded).
const m = @import("types").sigparse.clientdata;
pub const ClientDataType = m.ClientDataType;
pub const ClientData = m.ClientData;
pub const parse = m.parse;
