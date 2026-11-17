//! Lives in src/types/sigparse/errors.zig: the types module runs `ZkLoginInputs::init` at
//! GenericSignature decode (PARITY.md G20) and cannot import zk.
const m = @import("types").sigparse.errors;
pub const Fail = m.Fail;
pub const escapeDebug = m.escapeDebug;
